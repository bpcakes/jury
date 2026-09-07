use core::fmt;

/// Error returned when a mapped secret's integrity canaries are corrupted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CanaryCorruptedError;

impl fmt::Display for CanaryCorruptedError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("mapped secret canary corrupted")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for CanaryCorruptedError {}

/// Result alias for mapped operations that can fail only because integrity
/// canaries were corrupted.
pub type IntegrityResult<T> = Result<T, CanaryCorruptedError>;

/// Error returned by an operation that checks mapped-secret integrity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecretIntegrityError<E> {
    /// Prefix or suffix canary verification failed.
    Canary(CanaryCorruptedError),
    /// The requested operation failed for a non-integrity reason.
    Operation(E),
}

/// Result alias for mapped operations that distinguish integrity corruption
/// from an operation-specific failure.
pub type MappedResult<T, E> = Result<T, SecretIntegrityError<E>>;

/// Descriptive compatibility alias for [`MappedResult`].
pub type SecretIntegrityResult<T, E> = MappedResult<T, E>;

/// Error returned by a permanently bounded mapped-secret mutation.
///
/// Unlike the one-shot bounded constructors, containers using this error
/// preserve their const-generic maximum across every safe growth and
/// replacement operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BoundedMappedSecretError<E> {
    /// The resulting initialized length would exceed the type-level maximum.
    CapacityLimit {
        /// Largest permitted initialized length.
        maximum: usize,
        /// Length requested by the operation.
        actual: usize,
    },
    /// Computing the resulting initialized length overflowed `usize`.
    CapacityOverflow {
        /// Largest permitted initialized length.
        maximum: usize,
    },
    /// Prefix or suffix canary verification failed.
    Integrity(CanaryCorruptedError),
    /// The underlying mapped operation failed.
    Operation(E),
}

impl<E> From<SecretIntegrityError<E>> for BoundedMappedSecretError<E> {
    #[inline]
    fn from(error: SecretIntegrityError<E>) -> Self {
        match error {
            SecretIntegrityError::Canary(error) => Self::Integrity(error),
            SecretIntegrityError::Operation(error) => Self::Operation(error),
        }
    }
}

impl<E: fmt::Display> fmt::Display for BoundedMappedSecretError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CapacityLimit { maximum, actual } => write!(
                formatter,
                "mapped secret length {actual} exceeds permanent maximum {maximum}"
            ),
            Self::CapacityOverflow { maximum } => write!(
                formatter,
                "mapped secret length overflowed its permanent maximum {maximum}"
            ),
            Self::Integrity(error) => error.fmt(formatter),
            Self::Operation(error) => error.fmt(formatter),
        }
    }
}

#[cfg(feature = "std")]
impl<E> std::error::Error for BoundedMappedSecretError<E>
where
    E: std::error::Error + 'static,
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::CapacityLimit { .. } | Self::CapacityOverflow { .. } => None,
            Self::Integrity(error) => Some(error),
            Self::Operation(error) => Some(error),
        }
    }
}

impl<E> SecretIntegrityError<E> {
    /// Returns `true` when integrity-canary verification failed.
    #[must_use]
    pub const fn is_canary(&self) -> bool {
        matches!(self, Self::Canary(_))
    }

    /// Returns `true` when the requested operation failed after integrity
    /// verification succeeded.
    #[must_use]
    pub const fn is_operation(&self) -> bool {
        matches!(self, Self::Operation(_))
    }

    /// Borrows the operation-specific error, when present.
    #[must_use]
    pub const fn operation(&self) -> Option<&E> {
        match self {
            Self::Canary(_) => None,
            Self::Operation(error) => Some(error),
        }
    }

    /// Maps only the operation-specific error while preserving integrity
    /// corruption as a separate variant.
    pub fn map_operation<O>(self, map: impl FnOnce(E) -> O) -> SecretIntegrityError<O> {
        match self {
            Self::Canary(error) => SecretIntegrityError::Canary(error),
            Self::Operation(error) => SecretIntegrityError::Operation(map(error)),
        }
    }
}

/// Flattens a fallible mapped-secret exposure closure without losing the
/// distinction between integrity corruption and the closure's own error.
///
/// Mapped byte exposure methods return `Result<R, CanaryCorruptedError>`. If
/// the closure itself returns `Result<T, E>`, importing this trait permits:
///
/// ```rust,no_run
/// # #[cfg(feature = "memory-lock")]
/// # fn example() -> sanitization::MappedResult<(), &'static str> {
/// use sanitization::{LockedSecretBytes, SecretIntegrityResultExt};
///
/// let key = LockedSecretBytes::<4>::from_array([1, 2, 3, 4])
///     .expect("test environment permits memory locking");
/// let parsed = key
///     .try_expose_secret(|bytes| bytes.first().copied().ok_or("empty key"))
///     .flatten_secret_integrity()?;
/// assert_eq!(parsed, 1);
/// # Ok(())
/// # }
/// ```
pub trait SecretIntegrityResultExt<T, E> {
    /// Converts the outer canary error to [`SecretIntegrityError::Canary`] and
    /// the closure error to [`SecretIntegrityError::Operation`].
    fn flatten_secret_integrity(self) -> MappedResult<T, E>;
}

impl<T, E> SecretIntegrityResultExt<T, E> for Result<Result<T, E>, CanaryCorruptedError> {
    #[inline]
    fn flatten_secret_integrity(self) -> MappedResult<T, E> {
        match self {
            Ok(Ok(value)) => Ok(value),
            Ok(Err(error)) => Err(SecretIntegrityError::Operation(error)),
            Err(error) => Err(SecretIntegrityError::Canary(error)),
        }
    }
}

impl<E: fmt::Display> fmt::Display for SecretIntegrityError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Canary(error) => error.fmt(formatter),
            Self::Operation(error) => error.fmt(formatter),
        }
    }
}

#[cfg(feature = "std")]
impl<E> std::error::Error for SecretIntegrityError<E>
where
    E: std::error::Error + 'static,
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Canary(error) => Some(error),
            Self::Operation(error) => Some(error),
        }
    }
}

impl<E> From<CanaryCorruptedError> for SecretIntegrityError<E> {
    #[inline]
    fn from(error: CanaryCorruptedError) -> Self {
        Self::Canary(error)
    }
}

impl From<crate::LengthError> for SecretIntegrityError<crate::LengthError> {
    #[inline]
    fn from(error: crate::LengthError) -> Self {
        Self::Operation(error)
    }
}

/// Stable identity of one live allocation from a fixed-size secret pool.
///
/// The slot index may be reused after a handle drops. The generation changes
/// on each successful claim, so retained identifiers can distinguish later
/// occupants of the same slot. This is diagnostic identity only; it does not
/// grant access to slot storage.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct SecretPoolSlotId {
    /// Slot index inside the parent pool.
    pub index: usize,
    /// Non-zero allocation generation assigned after the slot is claimed.
    pub generation: usize,
}

/// Point-in-time capacity and lock-efficiency report for a fixed-size pool.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SecretPoolReport {
    /// Secret payload bytes in one slot.
    pub slot_size: usize,
    /// Storage bytes reserved per slot, including integrity metadata.
    pub slot_stride: usize,
    /// Total fixed slot count.
    pub capacity_slots: usize,
    /// Slots with a live handle when the report was captured.
    pub live_slots: usize,
    /// Slots permanently withheld after an integrity failure.
    pub quarantined_slots: usize,
    /// Maximum secret payload bytes across all slots.
    pub payload_capacity_bytes: usize,
    /// Slot storage bytes before platform page rounding.
    pub reserved_bytes: usize,
    /// Bytes in the native mapping, or zero for compatibility storage.
    pub mapped_bytes: usize,
    /// Bytes successfully locked against ordinary paging.
    pub locked_bytes: usize,
    /// Mapping bytes beyond fixed slot storage, normally page-rounding waste.
    pub mapping_overhead_bytes: usize,
    /// Locked bytes beyond secret payload capacity, including canaries and
    /// page-rounding waste.
    pub locked_overhead_bytes: usize,
    /// Page granule used by the backend, or zero for compatibility storage.
    pub page_granule: usize,
    /// Whether the underlying protection report associated a failure with
    /// likely platform lock-quota pressure.
    pub lock_quota_likely: bool,
}

impl SecretPoolReport {
    /// Payload density inside the fixed slot storage, in basis points.
    ///
    /// `10_000` means every reserved byte is payload. Zero-sized pools return
    /// `None`.
    #[must_use]
    pub const fn storage_efficiency_basis_points(&self) -> Option<u16> {
        efficiency_basis_points(self.payload_capacity_bytes, self.reserved_bytes)
    }

    /// Payload density inside the native mapping, in basis points.
    ///
    /// Compatibility backends without a native mapping return `None`.
    #[must_use]
    pub const fn mapping_efficiency_basis_points(&self) -> Option<u16> {
        efficiency_basis_points(self.payload_capacity_bytes, self.mapped_bytes)
    }

    /// Payload density inside bytes locked against ordinary paging.
    ///
    /// Unlocked and compatibility backends return `None`.
    #[must_use]
    pub const fn lock_efficiency_basis_points(&self) -> Option<u16> {
        efficiency_basis_points(self.payload_capacity_bytes, self.locked_bytes)
    }
}

const fn efficiency_basis_points(payload: usize, total: usize) -> Option<u16> {
    if total == 0 {
        return None;
    }

    let value = ((payload as u128) * 10_000) / (total as u128);
    Some(if value > 10_000 { 10_000 } else { value as u16 })
}

/// Whether a runtime memory-protection control is mandatory.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Requirement {
    /// Construction must fail if the control cannot be established.
    Required,
    /// Construction may continue with an explicit reduced-protection report.
    Preferred,
    /// The control is not requested.
    NotRequested,
}

/// Desired treatment of secret mappings across process fork.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ForkPolicy {
    /// Allow the child process to inherit the mapping.
    Inherit,
    /// Exclude the mapping from the child process.
    Exclude,
    /// Replace the child process's inherited mapping contents with zeroes.
    WipeChild,
}

/// Fork behavior requested for a mapped secret allocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ForkProtectionRequest {
    /// Desired fork behavior.
    pub policy: ForkPolicy,
    /// Whether construction may continue when the behavior is unavailable.
    pub requirement: Requirement,
}

impl ForkProtectionRequest {
    /// Explicitly allow ordinary fork inheritance.
    #[must_use]
    pub const fn inherit() -> Self {
        Self {
            policy: ForkPolicy::Inherit,
            requirement: Requirement::NotRequested,
        }
    }

    /// Request exclusion from child processes.
    #[must_use]
    pub const fn exclude(requirement: Requirement) -> Self {
        Self {
            policy: ForkPolicy::Exclude,
            requirement,
        }
    }

    /// Request zero-filled contents in child processes.
    #[must_use]
    pub const fn wipe_child(requirement: Requirement) -> Self {
        Self {
            policy: ForkPolicy::WipeChild,
            requirement,
        }
    }
}

/// Runtime protections requested for a mapped secret allocation.
///
/// Cargo features determine which backends are compiled. They do not prove
/// that a requested operating-system control was established at runtime.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProtectionRequest {
    /// Pin secret-bearing pages against ordinary paging.
    pub memory_lock: Requirement,
    /// Request exclusion from supported process core dumps.
    pub dump_exclusion: Requirement,
    /// Requested process-fork behavior.
    pub fork: ForkProtectionRequest,
    /// Require inaccessible pages around writable secret storage.
    pub guard_pages: Requirement,
    /// Require integrity canaries around secret storage.
    pub canary: Requirement,
    /// Request a persistent cache-eviction policy.
    ///
    /// The current mapped containers expose checked explicit cache flushing,
    /// but do not install an automatic persistent policy. Requesting this as
    /// `Required` therefore fails closed.
    pub cache_policy: Requirement,
}

impl ProtectionRequest {
    /// Policy used by the existing locked-storage constructors.
    ///
    /// Memory locking is required. Dump and fork exclusion are preferred
    /// because not every supported native platform exposes those controls.
    #[must_use]
    pub const fn locked() -> Self {
        Self {
            memory_lock: Requirement::Required,
            dump_exclusion: Requirement::Preferred,
            fork: ForkProtectionRequest::exclude(compiled_fork_requirement()),
            guard_pages: Requirement::NotRequested,
            canary: compiled_canary_requirement(),
            cache_policy: Requirement::NotRequested,
        }
    }

    /// Policy used by guarded storage without page locking.
    #[must_use]
    pub const fn guarded() -> Self {
        Self {
            memory_lock: Requirement::NotRequested,
            dump_exclusion: Requirement::NotRequested,
            fork: ForkProtectionRequest::inherit(),
            guard_pages: Requirement::Required,
            canary: compiled_canary_requirement(),
            cache_policy: Requirement::NotRequested,
        }
    }

    /// Fail-closed policy used by default page-sealed storage.
    ///
    /// Linux must establish `MADV_WIPEONFORK` so a fork during an exposed
    /// access window cannot leave readable secret bytes in the child. Windows
    /// does not clone the process address space during process creation.
    /// Other targets currently report the required fork policy as unsupported,
    /// so callers must use an explicit policy only after reviewing that risk.
    #[cfg(feature = "page-seal")]
    #[must_use]
    pub const fn page_sealed() -> Self {
        Self {
            memory_lock: Requirement::NotRequested,
            dump_exclusion: Requirement::NotRequested,
            fork: page_sealed_fork_request(),
            guard_pages: Requirement::Required,
            canary: compiled_canary_requirement(),
            cache_policy: Requirement::NotRequested,
        }
    }

    /// Policy used by guarded and page-locked storage.
    #[must_use]
    pub const fn locked_guarded() -> Self {
        Self {
            memory_lock: Requirement::Required,
            dump_exclusion: Requirement::Preferred,
            fork: ForkProtectionRequest::exclude(compiled_fork_requirement()),
            guard_pages: Requirement::Required,
            canary: compiled_canary_requirement(),
            cache_policy: Requirement::NotRequested,
        }
    }

    /// Policy represented by the `profile-hardened-native` feature.
    ///
    /// Memory locking and random integrity canaries are required. Dump and
    /// fork exclusion remain preferred because the named profile spans native
    /// operating systems with different process-policy controls.
    #[cfg(feature = "profile-hardened-native")]
    #[must_use]
    pub const fn profile_hardened_native() -> Self {
        Self {
            memory_lock: Requirement::Required,
            dump_exclusion: Requirement::Preferred,
            fork: ForkProtectionRequest::exclude(Requirement::Preferred),
            guard_pages: Requirement::NotRequested,
            canary: Requirement::Required,
            cache_policy: Requirement::NotRequested,
        }
    }

    /// Policy represented by the `profile-guarded-native` feature.
    #[cfg(feature = "profile-guarded-native")]
    #[must_use]
    pub const fn profile_guarded_native() -> Self {
        Self {
            guard_pages: Requirement::Required,
            ..Self::profile_hardened_native()
        }
    }

    /// Policy represented by the Linux-specific hardened profile.
    ///
    /// Linux fork exclusion is required by this profile. Dump exclusion
    /// remains preferred because runtime kernel or sandbox policy can reject
    /// the request and callers must inspect the resulting report.
    #[cfg(feature = "profile-hardened-linux")]
    #[must_use]
    pub const fn profile_hardened_linux() -> Self {
        Self {
            fork: ForkProtectionRequest::exclude(Requirement::Required),
            ..Self::profile_hardened_native()
        }
    }

    /// Explicit reduced-guarantee policy for WASM compatibility storage.
    #[must_use]
    pub const fn wasm_compatibility() -> Self {
        Self {
            memory_lock: Requirement::Preferred,
            dump_exclusion: Requirement::Preferred,
            fork: ForkProtectionRequest::exclude(Requirement::Preferred),
            guard_pages: Requirement::NotRequested,
            canary: compiled_canary_requirement(),
            cache_policy: Requirement::NotRequested,
        }
    }
}

#[cfg(all(feature = "page-seal", target_os = "linux"))]
const fn page_sealed_fork_request() -> ForkProtectionRequest {
    ForkProtectionRequest::wipe_child(Requirement::Required)
}

#[cfg(all(feature = "page-seal", target_os = "windows"))]
const fn page_sealed_fork_request() -> ForkProtectionRequest {
    ForkProtectionRequest::inherit()
}

#[cfg(all(
    feature = "page-seal",
    not(any(target_os = "linux", target_os = "windows"))
))]
const fn page_sealed_fork_request() -> ForkProtectionRequest {
    ForkProtectionRequest::wipe_child(Requirement::Required)
}

#[cfg(feature = "canary-check")]
const fn compiled_canary_requirement() -> Requirement {
    Requirement::Required
}

#[cfg(not(feature = "canary-check"))]
const fn compiled_canary_requirement() -> Requirement {
    Requirement::NotRequested
}

#[cfg(feature = "require-fork-exclusion")]
const fn compiled_fork_requirement() -> Requirement {
    Requirement::Required
}

#[cfg(not(feature = "require-fork-exclusion"))]
const fn compiled_fork_requirement() -> Requirement {
    Requirement::Preferred
}

/// Actual outcome of one requested runtime protection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtectionState {
    /// The control was established for the current storage.
    Established,
    /// The control was not requested and was not attempted.
    NotRequested,
    /// The control does not apply, such as locking an empty mapping.
    NotApplicable,
    /// The target or compiled backend does not support the control.
    Unsupported,
    /// A preferred control was attempted but failed.
    Failed {
        /// Positive platform error code when available.
        code: i32,
    },
    /// The API is present only for compatibility and the native control is
    /// outside the module's authority, as on WASM.
    CompatibilityOnly,
}

impl ProtectionState {
    /// Returns whether this outcome fulfills a requested control.
    ///
    /// This state alone cannot prove that [`ProtectionState::NotApplicable`]
    /// refers to genuinely empty storage, so it does not fulfill a required or
    /// preferred control. [`ProtectionReport::satisfies`] applies that exception
    /// only when its requested byte count is zero. `NotRequested` requirements
    /// are always fulfilled and do not imply that a control was attempted.
    #[must_use]
    pub const fn satisfies(self, requirement: Requirement) -> bool {
        match requirement {
            Requirement::NotRequested => true,
            Requirement::Required | Requirement::Preferred => matches!(self, Self::Established),
        }
    }
}

/// Actual outcome of the requested process-fork behavior.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ForkProtectionReport {
    /// Fork behavior requested by the caller.
    pub policy: ForkPolicy,
    /// Whether that behavior was established.
    pub state: ProtectionState,
}

/// Runtime report retained by a mapped secret container.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProtectionReport {
    /// Private mapping or compatibility storage outcome.
    pub mapping: ProtectionState,
    /// Page-lock outcome.
    pub memory_lock: ProtectionState,
    /// Core-dump exclusion outcome.
    pub dump_exclusion: ProtectionState,
    /// Process-fork behavior outcome.
    pub fork: ForkProtectionReport,
    /// Guard-page outcome.
    pub guard_pages: ProtectionState,
    /// Canary integrity outcome.
    pub canary: ProtectionState,
    /// Persistent cache-policy outcome.
    pub cache_policy: ProtectionState,
    /// Secret payload bytes requested by the caller.
    pub requested_bytes: usize,
    /// Bytes in the owned platform mapping.
    pub mapped_bytes: usize,
    /// Bytes successfully locked against ordinary paging.
    pub locked_bytes: usize,
    /// Page granule used for mapping arithmetic, or zero for compatibility
    /// storage without host page control.
    pub page_granule: usize,
    /// Whether a lock failure code is commonly associated with a lock quota
    /// or working-set limit.
    pub lock_quota_likely: bool,
}

impl ProtectionReport {
    /// Returns whether the mapping is live and every requested control was
    /// established or did not apply to empty storage.
    ///
    /// This is stricter than construction success: a failed or unsupported
    /// [`Requirement::Preferred`] control returns `false`, even though
    /// construction may legitimately have returned a live reduced-protection
    /// container. Controls marked [`Requirement::NotRequested`] are ignored.
    #[must_use]
    pub const fn satisfies(&self, request: ProtectionRequest) -> bool {
        let empty = self.requested_bytes == 0;
        mapping_satisfies(self.mapping, empty)
            && state_satisfies_for_storage(self.memory_lock, request.memory_lock, empty)
            && state_satisfies_for_storage(self.dump_exclusion, request.dump_exclusion, empty)
            && fork_policies_match(self.fork.policy, request.fork.policy)
            && state_satisfies_for_storage(self.fork.state, request.fork.requirement, empty)
            && state_satisfies_for_storage(self.guard_pages, request.guard_pages, empty)
            && state_satisfies_for_storage(self.canary, request.canary, empty)
            && state_satisfies_for_storage(self.cache_policy, request.cache_policy, empty)
    }

    /// Returns whether every requested control was established or did not
    /// apply to empty storage.
    ///
    /// This compatibility spelling is equivalent to
    /// [`ProtectionReport::satisfies`].
    #[must_use]
    pub const fn all_requested_controls_established(&self, request: ProtectionRequest) -> bool {
        self.satisfies(request)
    }

    /// Returns whether this report records reduced or unusable protection.
    ///
    /// A failed, unsupported, or compatibility-only control is degraded.
    /// `NotApplicable` is accepted only when `requested_bytes` is zero; for
    /// nonempty storage it indicates a released or missing control and is
    /// degraded. Unrequested controls are ignored.
    #[must_use]
    pub const fn is_degraded(&self) -> bool {
        let empty = self.requested_bytes == 0;
        !mapping_satisfies(self.mapping, empty)
            || protection_state_is_degraded(self.memory_lock, empty)
            || protection_state_is_degraded(self.dump_exclusion, empty)
            || protection_state_is_degraded(self.fork.state, empty)
            || protection_state_is_degraded(self.guard_pages, empty)
            || protection_state_is_degraded(self.canary, empty)
            || protection_state_is_degraded(self.cache_policy, empty)
    }

    /// Returns whether the page-lock control was established.
    ///
    /// Empty storage reports `NotApplicable` and therefore returns `false`.
    #[must_use]
    pub const fn memory_is_locked(&self) -> bool {
        matches!(self.memory_lock, ProtectionState::Established)
    }

    /// Returns whether inaccessible guard pages were established.
    ///
    /// Empty storage reports `NotApplicable` and therefore returns `false`.
    #[must_use]
    pub const fn guard_pages_established(&self) -> bool {
        matches!(self.guard_pages, ProtectionState::Established)
    }

    /// Iterates over controls that failed, are unsupported, or are available
    /// only through a reduced-guarantee compatibility backend.
    ///
    /// The iterator allocates no memory and yields controls in stable report
    /// order: mapping, memory lock, dump exclusion, fork policy, guard pages,
    /// canary, and cache policy. `NotRequested` controls are omitted.
    /// `NotApplicable` is omitted only for genuinely empty storage and is
    /// reported as unavailable for nonempty storage.
    pub fn failed_or_unsupported_controls(&self) -> impl Iterator<Item = ProtectionControl> {
        let empty = self.requested_bytes == 0;
        [
            unavailable_control(ProtectionControl::Mapping, self.mapping, empty),
            unavailable_control(ProtectionControl::MemoryLock, self.memory_lock, empty),
            unavailable_control(ProtectionControl::DumpExclusion, self.dump_exclusion, empty),
            unavailable_control(ProtectionControl::ForkPolicy, self.fork.state, empty),
            unavailable_control(ProtectionControl::GuardPages, self.guard_pages, empty),
            unavailable_control(ProtectionControl::Canary, self.canary, empty),
            unavailable_control(ProtectionControl::CachePolicy, self.cache_policy, empty),
        ]
        .into_iter()
        .flatten()
    }

    #[allow(dead_code)]
    pub(crate) const fn pending(
        request: ProtectionRequest,
        requested_bytes: usize,
        page_granule: usize,
    ) -> Self {
        Self {
            mapping: ProtectionState::NotRequested,
            memory_lock: initial_state(request.memory_lock),
            dump_exclusion: initial_state(request.dump_exclusion),
            fork: ForkProtectionReport {
                policy: request.fork.policy,
                state: initial_fork_state(request.fork),
            },
            guard_pages: initial_state(request.guard_pages),
            canary: initial_state(request.canary),
            cache_policy: initial_state(request.cache_policy),
            requested_bytes,
            mapped_bytes: 0,
            locked_bytes: 0,
            page_granule,
            lock_quota_likely: false,
        }
    }
}

/// Derive the effective policy for replacement storage without permitting an
/// established preferred control to disappear during growth or replacement.
///
/// The returned request is used only while constructing the replacement. The
/// replacement owner retains the caller's original request after construction
/// so future operations can derive continuity from their then-current report.
#[cfg(any(feature = "memory-lock", feature = "guard-pages"))]
pub(crate) const fn replacement_request_preserving_established(
    mut request: ProtectionRequest,
    report: &ProtectionReport,
    next_bytes: usize,
) -> ProtectionRequest {
    preserve_control(&mut request.memory_lock, report.memory_lock, next_bytes);
    preserve_control(
        &mut request.dump_exclusion,
        report.dump_exclusion,
        next_bytes,
    );
    preserve_control(&mut request.fork.requirement, report.fork.state, next_bytes);
    preserve_control(&mut request.guard_pages, report.guard_pages, next_bytes);
    preserve_control(&mut request.canary, report.canary, next_bytes);
    preserve_control(&mut request.cache_policy, report.cache_policy, next_bytes);
    request
}

#[cfg(any(feature = "memory-lock", feature = "guard-pages"))]
const fn preserve_control(
    requirement: &mut Requirement,
    state: ProtectionState,
    next_bytes: usize,
) {
    if matches!(*requirement, Requirement::Preferred)
        && (matches!(state, ProtectionState::Established)
            || (next_bytes != 0 && matches!(state, ProtectionState::NotApplicable)))
    {
        *requirement = Requirement::Required;
    }
}

const fn mapping_satisfies(state: ProtectionState, empty: bool) -> bool {
    matches!(state, ProtectionState::Established)
        || (empty && matches!(state, ProtectionState::NotApplicable))
}

const fn state_satisfies_for_storage(
    state: ProtectionState,
    requirement: Requirement,
    empty: bool,
) -> bool {
    match requirement {
        Requirement::NotRequested => true,
        Requirement::Required | Requirement::Preferred => {
            matches!(state, ProtectionState::Established)
                || (empty && matches!(state, ProtectionState::NotApplicable))
        }
    }
}

const fn protection_state_is_degraded(state: ProtectionState, empty: bool) -> bool {
    matches!(
        state,
        ProtectionState::Unsupported
            | ProtectionState::Failed { .. }
            | ProtectionState::CompatibilityOnly
    ) || (!empty && matches!(state, ProtectionState::NotApplicable))
}

const fn fork_policies_match(left: ForkPolicy, right: ForkPolicy) -> bool {
    matches!(
        (left, right),
        (ForkPolicy::Inherit, ForkPolicy::Inherit)
            | (ForkPolicy::Exclude, ForkPolicy::Exclude)
            | (ForkPolicy::WipeChild, ForkPolicy::WipeChild)
    )
}

fn unavailable_control(
    control: ProtectionControl,
    state: ProtectionState,
    empty: bool,
) -> Option<ProtectionControl> {
    if protection_state_is_degraded(state, empty) {
        Some(control)
    } else {
        None
    }
}

#[cfg(all(test, any(feature = "memory-lock", feature = "guard-pages")))]
mod tests {
    use super::*;

    #[test]
    fn replacement_requires_previously_established_preferred_controls() {
        let request = ProtectionRequest {
            memory_lock: Requirement::Preferred,
            dump_exclusion: Requirement::Preferred,
            fork: ForkProtectionRequest::exclude(Requirement::Preferred),
            guard_pages: Requirement::Preferred,
            canary: Requirement::Preferred,
            cache_policy: Requirement::Preferred,
        };
        let mut report = ProtectionReport::pending(request, 32, 4096);
        report.mapping = ProtectionState::Established;
        report.memory_lock = ProtectionState::Established;
        report.dump_exclusion = ProtectionState::Established;
        report.fork.state = ProtectionState::Established;
        report.guard_pages = ProtectionState::Established;
        report.canary = ProtectionState::Established;
        report.cache_policy = ProtectionState::Established;

        let replacement = replacement_request_preserving_established(request, &report, 64);

        assert_eq!(replacement.memory_lock, Requirement::Required);
        assert_eq!(replacement.dump_exclusion, Requirement::Required);
        assert_eq!(replacement.fork.requirement, Requirement::Required);
        assert_eq!(replacement.guard_pages, Requirement::Required);
        assert_eq!(replacement.canary, Requirement::Required);
        assert_eq!(replacement.cache_policy, Requirement::Required);
    }

    #[test]
    fn replacement_does_not_upgrade_controls_that_were_already_degraded() {
        let request = ProtectionRequest::wasm_compatibility();
        let mut report = ProtectionReport::pending(request, 32, 0);
        report.mapping = ProtectionState::CompatibilityOnly;
        report.memory_lock = ProtectionState::CompatibilityOnly;
        report.dump_exclusion = ProtectionState::Unsupported;
        report.fork.state = ProtectionState::Unsupported;

        assert_eq!(
            replacement_request_preserving_established(request, &report, 64),
            request
        );
    }

    #[test]
    fn nonempty_replacement_requires_controls_accepted_for_empty_storage() {
        let request = ProtectionRequest::wasm_compatibility();
        let mut report = ProtectionReport::pending(request, 0, 0);
        report.mapping = ProtectionState::NotApplicable;
        report.memory_lock = ProtectionState::NotApplicable;
        report.dump_exclusion = ProtectionState::NotApplicable;
        report.fork.state = ProtectionState::NotApplicable;

        let replacement = replacement_request_preserving_established(request, &report, 1);

        assert_eq!(replacement.memory_lock, Requirement::Required);
        assert_eq!(replacement.dump_exclusion, Requirement::Required);
        assert_eq!(replacement.fork.requirement, Requirement::Required);
    }
}

#[allow(dead_code)]
const fn initial_state(requirement: Requirement) -> ProtectionState {
    match requirement {
        Requirement::NotRequested => ProtectionState::NotRequested,
        Requirement::Required | Requirement::Preferred => ProtectionState::Unsupported,
    }
}

#[allow(dead_code)]
const fn initial_fork_state(request: ForkProtectionRequest) -> ProtectionState {
    match request.policy {
        ForkPolicy::Inherit => ProtectionState::Established,
        ForkPolicy::Exclude | ForkPolicy::WipeChild => initial_state(request.requirement),
    }
}

/// Runtime control that failed during protected allocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtectionControl {
    /// Length or mapping setup.
    Mapping,
    /// Page locking.
    MemoryLock,
    /// Core-dump exclusion.
    DumpExclusion,
    /// Process-fork behavior.
    ForkPolicy,
    /// Guard-page establishment.
    GuardPages,
    /// Canary generation or establishment.
    Canary,
    /// Persistent cache policy.
    CachePolicy,
}

/// Non-secret description of a failed protection operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProtectionFailure {
    /// Control that failed.
    pub control: ProtectionControl,
    /// Positive platform error code when available.
    pub code: i32,
}

/// Result of one cleanup operation after failed construction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RollbackState {
    /// The cleanup operation was unnecessary.
    NotNeeded,
    /// Cleanup completed successfully.
    Completed,
    /// Cleanup failed and storage may remain live.
    Failed(ProtectionFailure),
}

/// Cleanup results after a required protection could not be established.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RollbackReport {
    /// Page-unlock outcome.
    pub unlock: RollbackState,
    /// Mapping-release outcome.
    pub unmap: RollbackState,
}

impl RollbackReport {
    #[allow(dead_code)]
    pub(crate) const fn not_needed() -> Self {
        Self {
            unlock: RollbackState::NotNeeded,
            unmap: RollbackState::NotNeeded,
        }
    }
}

/// Error returned when a required runtime protection cannot be established.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProtectionError {
    /// Original control failure.
    pub failure: ProtectionFailure,
    /// State reached before rollback began.
    pub partial_report: ProtectionReport,
    /// Explicit cleanup outcome.
    pub rollback: RollbackReport,
}

impl fmt::Display for ProtectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "required protection {:?} failed with code {}; rollback: {:?}",
            self.failure.control, self.failure.code, self.rollback
        )
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ProtectionError {}

/// Error returned when protected dynamic storage cannot be established and
/// filled in place.
///
/// This keeps protection setup, caller-provided filling, and initialized
/// length validation as separate failure classes. In particular,
/// [`ProtectedSecretFillError::Protection`] retains the partial protection and
/// rollback reports from [`ProtectionError`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtectedSecretFillError<E> {
    /// The requested public capacity exceeded the caller-supplied application
    /// maximum. No mapping was created and the fill closure was not invoked.
    CapacityLimit {
        /// Largest permitted capacity.
        maximum: usize,
        /// Capacity requested by the caller.
        actual: usize,
    },
    /// A required runtime protection could not be established before the fill
    /// closure was invoked.
    Protection(ProtectionError),
    /// The caller-provided fill closure returned an error.
    Fill(E),
    /// Integrity canaries were corrupted while the fill closure had access
    /// to the destination.
    Integrity(CanaryCorruptedError),
    /// The fill closure reported more initialized bytes than the mapping can
    /// hold.
    Length(crate::LengthError),
}

impl<E: fmt::Display> fmt::Display for ProtectedSecretFillError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CapacityLimit { maximum, actual } => write!(
                formatter,
                "protected secret capacity {actual} exceeds application maximum {maximum}"
            ),
            Self::Protection(error) => error.fmt(formatter),
            Self::Fill(error) => write!(formatter, "protected secret fill failed: {error}"),
            Self::Integrity(error) => error.fmt(formatter),
            Self::Length(error) => error.fmt(formatter),
        }
    }
}

#[cfg(feature = "std")]
impl<E> std::error::Error for ProtectedSecretFillError<E>
where
    E: std::error::Error + 'static,
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::CapacityLimit { .. } => None,
            Self::Protection(error) => Some(error),
            Self::Fill(error) => Some(error),
            Self::Integrity(error) => Some(error),
            Self::Length(error) => Some(error),
        }
    }
}

impl<E> From<ProtectionError> for ProtectedSecretFillError<E> {
    #[inline]
    fn from(error: ProtectionError) -> Self {
        Self::Protection(error)
    }
}

impl<E> From<crate::LengthError> for ProtectedSecretFillError<E> {
    #[inline]
    fn from(error: crate::LengthError) -> Self {
        Self::Length(error)
    }
}

#[allow(dead_code)]
pub(crate) const fn unavailable_state(requirement: Requirement) -> Result<ProtectionState, ()> {
    match requirement {
        Requirement::Required => Err(()),
        Requirement::Preferred => Ok(ProtectionState::Unsupported),
        Requirement::NotRequested => Ok(ProtectionState::NotRequested),
    }
}

#[cfg(kani)]
pub(crate) const fn failed_state(
    requirement: Requirement,
    code: i32,
) -> Result<ProtectionState, ()> {
    match requirement {
        Requirement::Required => Err(()),
        Requirement::Preferred => Ok(ProtectionState::Failed { code }),
        Requirement::NotRequested => Ok(ProtectionState::NotRequested),
    }
}

#[cfg(kani)]
mod verification {
    use super::*;

    #[kani::proof]
    fn required_unavailable_never_degrades_to_success() {
        assert!(unavailable_state(Requirement::Required).is_err());
    }

    #[kani::proof]
    fn preferred_failure_is_reported_as_failed() {
        let code: i32 = kani::any();
        assert_eq!(
            failed_state(Requirement::Preferred, code),
            Ok(ProtectionState::Failed { code })
        );
    }

    #[kani::proof]
    fn not_requested_is_never_reported_established() {
        assert_eq!(
            unavailable_state(Requirement::NotRequested),
            Ok(ProtectionState::NotRequested)
        );
        assert_eq!(
            failed_state(Requirement::NotRequested, 7),
            Ok(ProtectionState::NotRequested)
        );
    }

    #[kani::proof]
    fn inherit_policy_is_explicitly_established() {
        assert_eq!(
            initial_fork_state(ForkProtectionRequest::inherit()),
            ProtectionState::Established
        );
    }
}
