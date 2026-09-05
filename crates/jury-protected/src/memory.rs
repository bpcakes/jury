use std::fmt;

use sanitization::{
    BoundedGuardedSecretVec, ForkPolicy, ForkProtectionRequest, ProtectedSecretFillError,
    ProtectionRequest, ProtectionState, Requirement,
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
        !self.memory_controls_established() || !self.core_dump_suppressed
    }

    // Linux retains mandatory per-mapping dump exclusion. macOS has no such
    // mechanism: only Unsupported paired with verified process suppression
    // satisfies its bounded ordinary-core contract.
    const fn memory_controls_established(&self) -> bool {
        let dump_protected = if cfg!(target_os = "macos") {
            matches!(self.dump_exclusion, RuntimeControlStatus::Unsupported)
                && self.core_dump_suppressed
        } else {
            matches!(self.dump_exclusion, RuntimeControlStatus::Established)
        };
        matches!(self.mapping, RuntimeControlStatus::Established)
            && matches!(self.memory_lock, RuntimeControlStatus::Established)
            && dump_protected
            && matches!(self.fork_exclusion, RuntimeControlStatus::Established)
            && matches!(self.guard_pages, RuntimeControlStatus::Established)
            && matches!(self.canary, RuntimeControlStatus::Established)
            && self.requested_bytes > 0
            && self.page_granule > 0
            && self.locked_bytes >= self.requested_bytes
            && self.locked_bytes.is_multiple_of(self.page_granule)
            && self.mapped_bytes >= self.locked_bytes
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
    ///
    /// On macOS, after capacity validation, strict mode sets both process
    /// `RLIMIT_CORE` limits to zero and verifies them before provider entry.
    /// This suppresses ordinary core dumps for the whole process irreversibly;
    /// once applied, it remains in effect even if allocation or initialization
    /// subsequently fails. Linux construction retains its per-mapping contract;
    /// process suppression is performed separately by the capture boundary.
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
    /// It has the same irreversible macOS strict core-suppression side effect
    /// as [`Self::initialize`], including after subsequent allocation failure.
    pub fn initialize_large<E>(
        capacity: usize,
        policy: ProtectionPolicy,
        initializer: impl FnOnce(&mut [u8]) -> Result<usize, E>,
    ) -> Result<Self, MemoryError> {
        Self::initialize_bounded(capacity, MAX_LARGE_PROTECTED_BYTES, policy, initializer)
    }

    /// Allocates any supported compact or large protected value.
    ///
    /// The compact ceiling remains available through [`Self::initialize`] for
    /// callers whose own contract must reject larger values.
    /// It has the same irreversible macOS strict core-suppression side effect
    /// as [`Self::initialize`], including after subsequent allocation failure.
    pub fn initialize_supported<E>(
        capacity: usize,
        policy: ProtectionPolicy,
        initializer: impl FnOnce(&mut [u8]) -> Result<usize, E>,
    ) -> Result<Self, MemoryError> {
        if capacity > MAX_PROTECTED_BYTES {
            Self::initialize_large(capacity, policy, initializer)
        } else {
            Self::initialize(capacity, policy, initializer)
        }
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
        #[cfg(target_os = "macos")]
        if policy == ProtectionPolicy::Strict {
            crate::process_protection::suppress_core_dumps()
                .map_err(|_| MemoryError::new(MemoryErrorKind::Protection))?;
        }
        let request = request(policy);
        #[cfg(test)]
        tests::record_provider_entry();
        let inner = BoundedGuardedSecretVec::<MAX_LARGE_PROTECTED_BYTES>::try_from_capacity_with_protection(
            capacity,
            request,
            initializer,
        )
        .map_err(map_fill_error)?;
        let report = inner.protection_report();
        // Provider-contract assertion, not an establishment check: the pinned
        // provider retains the requested policy even when preferred establishment
        // fails. The strict predicate below checks the separate runtime state.
        if report.fork.policy != ForkPolicy::Exclude {
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
            core_dump_suppressed: crate::process_protection::core_dump_suppressed(),
        };
        if policy == ProtectionPolicy::Strict && !status.memory_controls_established() {
            return Err(MemoryError::new(MemoryErrorKind::Protection));
        }
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
        dump_exclusion: if cfg!(target_os = "macos") {
            Requirement::Preferred
        } else {
            os_requirement
        },
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
#[path = "memory_tests.rs"]
pub(crate) mod tests;
