use std::fmt;

use sanitization::{
    BoundedGuardedSecretVec, ForkProtectionRequest, ProtectedSecretFillError, ProtectionRequest,
    ProtectionState, Requirement,
};
use serde::{Deserialize, Serialize};

/// Hard ceiling for any one compact protected allocation.
pub const MAX_PROTECTED_BYTES: usize = 1024 * 1024;

/// Hard ceiling for an explicitly requested large protected allocation.
pub const MAX_LARGE_PROTECTED_BYTES: usize = 16 * 1024 * 1024;

/// Caller-selected runtime protection policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtectionPolicy {
    /// Every memory protection is mandatory.
    Strict,
    /// Guard pages and canaries remain mandatory; unavailable OS controls are
    /// exposed as degraded state rather than causing an ordinary heap fallback.
    EmergencyAllowDegraded,
}

/// Stable public state for one requested runtime control.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeControlStatus {
    Established,
    NotRequested,
    NotApplicable,
    Unsupported,
    Failed,
    CompatibilityOnly,
}

/// Serializable, value-free report retained beside protected memory.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ProtectionStatus {
    policy: ProtectionPolicy,
    mapping: RuntimeControlStatus,
    memory_lock: RuntimeControlStatus,
    dump_exclusion: RuntimeControlStatus,
    fork_exclusion: RuntimeControlStatus,
    guard_pages: RuntimeControlStatus,
    canary: RuntimeControlStatus,
    requested_bytes: usize,
    mapped_bytes: usize,
    locked_bytes: usize,
    page_granule: usize,
    core_dump_suppressed: bool,
}

impl ProtectionStatus {
    #[must_use]
    pub const fn policy(&self) -> ProtectionPolicy {
        self.policy
    }

    #[must_use]
    pub const fn mapping(&self) -> RuntimeControlStatus {
        self.mapping
    }

    #[must_use]
    pub const fn memory_lock(&self) -> RuntimeControlStatus {
        self.memory_lock
    }

    #[must_use]
    pub const fn dump_exclusion(&self) -> RuntimeControlStatus {
        self.dump_exclusion
    }

    #[must_use]
    pub const fn fork_exclusion(&self) -> RuntimeControlStatus {
        self.fork_exclusion
    }

    #[must_use]
    pub const fn guard_pages(&self) -> RuntimeControlStatus {
        self.guard_pages
    }

    #[must_use]
    pub const fn canary(&self) -> RuntimeControlStatus {
        self.canary
    }

    #[must_use]
    pub const fn requested_bytes(&self) -> usize {
        self.requested_bytes
    }

    #[must_use]
    pub const fn mapped_bytes(&self) -> usize {
        self.mapped_bytes
    }

    #[must_use]
    pub const fn locked_bytes(&self) -> usize {
        self.locked_bytes
    }

    #[must_use]
    pub const fn page_granule(&self) -> usize {
        self.page_granule
    }

    #[must_use]
    pub const fn core_dump_suppressed(&self) -> bool {
        self.core_dump_suppressed
    }

    #[must_use]
    pub const fn is_degraded(&self) -> bool {
        !matches!(self.mapping, RuntimeControlStatus::Established)
            || !matches!(self.memory_lock, RuntimeControlStatus::Established)
            || !matches!(self.dump_exclusion, RuntimeControlStatus::Established)
            || !matches!(self.fork_exclusion, RuntimeControlStatus::Established)
            || !matches!(self.guard_pages, RuntimeControlStatus::Established)
            || !matches!(self.canary, RuntimeControlStatus::Established)
            || !self.core_dump_suppressed
    }

    pub(crate) fn record_core_suppression(&mut self) {
        self.core_dump_suppressed = true;
    }
}

/// Stable construction or access failure class.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemoryErrorKind {
    Capacity,
    Protection,
    Initializer,
    InvalidLength,
    Integrity,
    UnsupportedPlatform,
}

/// Value-free protected-memory error.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct MemoryError {
    kind: MemoryErrorKind,
}

impl MemoryError {
    #[must_use]
    pub const fn kind(&self) -> MemoryErrorKind {
        self.kind
    }

    const fn new(kind: MemoryErrorKind) -> Self {
        Self { kind }
    }
}

impl fmt::Debug for MemoryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MemoryError")
            .field("kind", &self.kind)
            .finish()
    }
}

impl fmt::Display for MemoryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self.kind {
            MemoryErrorKind::Capacity => "protected memory capacity is outside supported bounds",
            MemoryErrorKind::Protection => "required protected memory controls are unavailable",
            MemoryErrorKind::Initializer => "protected memory initialization failed",
            MemoryErrorKind::InvalidLength => {
                "protected memory initializer returned an invalid length"
            }
            MemoryErrorKind::Integrity => "protected memory integrity verification failed",
            MemoryErrorKind::UnsupportedPlatform => {
                "protected memory is unsupported on this platform"
            }
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for MemoryError {}

/// Page-dedicated, permanently bounded secret bytes.
///
/// The provider type and raw mapping never cross this boundary. Bytes are
/// visible only during checked callbacks.
pub struct ProtectedMemory {
    inner: BoundedGuardedSecretVec<MAX_LARGE_PROTECTED_BYTES>,
    logical_capacity: usize,
    status: ProtectionStatus,
}

impl ProtectedMemory {
    /// Allocates protected pages and initializes them directly in place.
    pub fn initialize<E>(
        capacity: usize,
        policy: ProtectionPolicy,
        initializer: impl FnOnce(&mut [u8]) -> Result<usize, E>,
    ) -> Result<Self, MemoryError> {
        Self::initialize_bounded(capacity, MAX_PROTECTED_BYTES, policy, initializer)
    }

    /// Allocates a protected owner for an explicitly large bounded value.
    ///
    /// Compact callers continue to use [`Self::initialize`]. This constructor
    /// exists for authenticated formats whose selected public size bucket can
    /// exceed the compact 1 MiB ceiling.
    pub fn initialize_large<E>(
        capacity: usize,
        policy: ProtectionPolicy,
        initializer: impl FnOnce(&mut [u8]) -> Result<usize, E>,
    ) -> Result<Self, MemoryError> {
        Self::initialize_bounded(capacity, MAX_LARGE_PROTECTED_BYTES, policy, initializer)
    }

    fn initialize_bounded<E>(
        capacity: usize,
        maximum: usize,
        policy: ProtectionPolicy,
        initializer: impl FnOnce(&mut [u8]) -> Result<usize, E>,
    ) -> Result<Self, MemoryError> {
        if capacity == 0 || capacity > maximum {
            return Err(MemoryError::new(MemoryErrorKind::Capacity));
        }
        let request = request(policy);
        let inner = BoundedGuardedSecretVec::<MAX_LARGE_PROTECTED_BYTES>::try_from_capacity_with_protection(
            capacity,
            request,
            initializer,
        )
        .map_err(map_fill_error)?;
        let report = inner.protection_report();
        if policy == ProtectionPolicy::Strict && !report.satisfies(request) {
            return Err(MemoryError::new(MemoryErrorKind::Protection));
        }
        let status = ProtectionStatus {
            policy,
            mapping: state(report.mapping),
            memory_lock: state(report.memory_lock),
            dump_exclusion: state(report.dump_exclusion),
            fork_exclusion: state(report.fork.state),
            guard_pages: state(report.guard_pages),
            canary: state(report.canary),
            requested_bytes: report.requested_bytes,
            mapped_bytes: report.mapped_bytes,
            locked_bytes: report.locked_bytes,
            page_granule: report.page_granule,
            core_dump_suppressed: false,
        };
        Ok(Self {
            inner,
            logical_capacity: capacity,
            status,
        })
    }

    #[must_use]
    pub const fn len(&self) -> usize {
        self.inner.len()
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    #[must_use]
    pub const fn capacity(&self) -> usize {
        self.logical_capacity
    }

    #[must_use]
    pub const fn status(&self) -> &ProtectionStatus {
        &self.status
    }

    pub fn expose<R>(&self, inspect: impl FnOnce(&[u8]) -> R) -> Result<R, MemoryError> {
        self.inner
            .try_with_secret(inspect)
            .map_err(|_| MemoryError::new(MemoryErrorKind::Integrity))
    }

    pub fn expose_mut<R>(&mut self, edit: impl FnOnce(&mut [u8]) -> R) -> Result<R, MemoryError> {
        self.inner
            .try_with_secret_mut(edit)
            .map_err(|_| MemoryError::new(MemoryErrorKind::Integrity))
    }
}

impl fmt::Debug for ProtectedMemory {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProtectedMemory")
            .field("len", &self.len())
            .field("capacity", &self.logical_capacity)
            .field("status", &self.status)
            .field("contents", &"[REDACTED]")
            .finish()
    }
}

const fn request(policy: ProtectionPolicy) -> ProtectionRequest {
    let os_requirement = match policy {
        ProtectionPolicy::Strict => Requirement::Required,
        ProtectionPolicy::EmergencyAllowDegraded => Requirement::Preferred,
    };
    ProtectionRequest {
        memory_lock: os_requirement,
        dump_exclusion: os_requirement,
        fork: ForkProtectionRequest::exclude(os_requirement),
        guard_pages: Requirement::Required,
        canary: Requirement::Required,
        cache_policy: Requirement::NotRequested,
    }
}

const fn state(value: ProtectionState) -> RuntimeControlStatus {
    match value {
        ProtectionState::Established => RuntimeControlStatus::Established,
        ProtectionState::NotRequested => RuntimeControlStatus::NotRequested,
        ProtectionState::NotApplicable => RuntimeControlStatus::NotApplicable,
        ProtectionState::Unsupported => RuntimeControlStatus::Unsupported,
        ProtectionState::Failed { .. } => RuntimeControlStatus::Failed,
        ProtectionState::CompatibilityOnly => RuntimeControlStatus::CompatibilityOnly,
    }
}

fn map_fill_error<E>(error: ProtectedSecretFillError<E>) -> MemoryError {
    let kind = match error {
        ProtectedSecretFillError::CapacityLimit { .. } => MemoryErrorKind::Capacity,
        ProtectedSecretFillError::Protection(_) => MemoryErrorKind::Protection,
        ProtectedSecretFillError::Fill(_) => MemoryErrorKind::Initializer,
        ProtectedSecretFillError::Integrity(_) => MemoryErrorKind::Integrity,
        ProtectedSecretFillError::Length(_) => MemoryErrorKind::InvalidLength,
    };
    MemoryError::new(kind)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_memory_is_guarded_locked_dump_excluded_and_fork_excluded() -> Result<(), MemoryError>
    {
        let memory = ProtectedMemory::initialize(31, ProtectionPolicy::Strict, |bytes| {
            bytes.fill(0xa5);
            Ok::<usize, ()>(bytes.len())
        })?;
        let status = memory.status();
        assert_eq!(memory.capacity(), 31);
        assert_eq!(memory.len(), 31);
        assert!(status.mapped_bytes() >= 31);
        assert!(status.page_granule() > 0);
        assert_eq!(status.memory_lock(), RuntimeControlStatus::Established);
        assert_eq!(status.dump_exclusion(), RuntimeControlStatus::Established);
        assert_eq!(status.fork_exclusion(), RuntimeControlStatus::Established);
        assert_eq!(status.guard_pages(), RuntimeControlStatus::Established);
        assert_eq!(status.canary(), RuntimeControlStatus::Established);
        Ok(())
    }

    #[test]
    fn initializer_writes_directly_and_invalid_lengths_return_no_owner() {
        let error = ProtectedMemory::initialize(8, ProtectionPolicy::Strict, |bytes| {
            bytes.fill(0x5a);
            Ok::<usize, ()>(bytes.len() + 1)
        });
        assert_eq!(
            error.map(|_| ()),
            Err(MemoryError::new(MemoryErrorKind::InvalidLength))
        );
    }

    #[test]
    fn large_allocations_require_the_explicit_bounded_constructor() -> Result<(), MemoryError> {
        let length = MAX_PROTECTED_BYTES + 1;
        let compact = ProtectedMemory::initialize(
            length,
            ProtectionPolicy::EmergencyAllowDegraded,
            |bytes| Ok::<usize, ()>(bytes.len()),
        );
        assert!(matches!(compact, Err(error) if error.kind() == MemoryErrorKind::Capacity));

        let large = ProtectedMemory::initialize_large(
            length,
            ProtectionPolicy::EmergencyAllowDegraded,
            |bytes| {
                bytes.fill(0xa5);
                Ok::<usize, ()>(bytes.len())
            },
        )?;
        assert_eq!(large.len(), length);
        assert_eq!(large.capacity(), length);
        Ok(())
    }

    #[test]
    fn debug_and_json_are_value_free() -> Result<(), Box<dyn std::error::Error>> {
        let memory = ProtectedMemory::initialize(16, ProtectionPolicy::Strict, |bytes| {
            bytes.copy_from_slice(b"ExampleSecret123");
            Ok::<usize, ()>(bytes.len())
        })?;
        let debug = format!("{memory:?}");
        let json = serde_json::to_string(memory.status())?;
        assert!(!debug.contains("ExampleSecret123"));
        assert!(!json.contains("ExampleSecret123"));
        assert!(debug.contains("[REDACTED]"));
        Ok(())
    }
}
