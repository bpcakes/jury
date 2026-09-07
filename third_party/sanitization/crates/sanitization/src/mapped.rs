#[cfg(feature = "alloc")]
#[allow(unused_imports)]
use alloc::string::String;
#[allow(unused_imports)]
use core::fmt;

#[cfg(feature = "alloc")]
#[allow(unused_imports)]
use crate::SecretString;
#[allow(unused_imports)]
use crate::{ct, SecureSanitize};

#[path = "mapped/protection.rs"]
mod protection;
pub use protection::{
    BoundedMappedSecretError, CanaryCorruptedError, ForkPolicy, ForkProtectionReport,
    ForkProtectionRequest, IntegrityResult, MappedResult, ProtectedSecretFillError,
    ProtectionControl, ProtectionError, ProtectionFailure, ProtectionReport, ProtectionRequest,
    ProtectionState, Requirement, RollbackReport, RollbackState, SecretIntegrityError,
    SecretIntegrityResult, SecretIntegrityResultExt, SecretPoolReport, SecretPoolSlotId,
};

#[cfg(all(
    feature = "memory-lock",
    feature = "wasm-compat",
    target_arch = "wasm32"
))]
#[allow(unsafe_code)]
#[path = "mapped/memory_lock_wasm.rs"]
mod memory_lock;

#[cfg(all(
    feature = "memory-lock",
    any(
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ),
        target_os = "macos",
        target_os = "ios",
        target_os = "android",
        target_os = "windows",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
    )
))]
#[allow(unsafe_code)]
#[cfg_attr(all(miri, test), allow(dead_code))]
#[path = "mapped/memory_lock_native.rs"]
mod memory_lock;

#[cfg(all(
    feature = "memory-lock",
    any(
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ),
        target_os = "macos",
        target_os = "ios",
        target_os = "android",
        target_os = "windows",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
        all(target_arch = "wasm32", feature = "wasm-compat"),
    )
))]
pub use memory_lock::{
    LockedSecretBytes, LockedSecretBytesError, LockedSecretBytesFillError,
    LockedSecretBytesGenerateError, LockedSecretInitError, LockedSecretInitializeError,
    MemoryLockError, MemoryLockOperation, PoolInitError, SecretPool, SecretPoolGenerateError,
    SecretPoolSlot,
};

#[cfg(all(
    feature = "memory-lock",
    any(
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ),
        target_os = "macos",
        target_os = "ios",
        target_os = "android",
        target_os = "windows",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
    )
))]
pub use memory_lock::{LockedSecretVec, LockedSecretVecFillError, LockedSecretVecGenerateError};

/// Compatibility name for fixed-size copy operations that check integrity.
pub type LockedSecretBytesCheckedCopyError = SecretIntegrityError<crate::LengthError>;

#[cfg(all(
    feature = "guard-pages",
    any(
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ),
        target_os = "macos",
        target_os = "ios",
        target_os = "android",
        target_os = "windows",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
    ),
    not(all(miri, test))
))]
#[allow(unsafe_code)]
#[path = "mapped/guard_pages.rs"]
mod guard_pages;

#[cfg(all(
    feature = "guard-pages",
    any(
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ),
        target_os = "macos",
        target_os = "ios",
        target_os = "android",
        target_os = "windows",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
    ),
    not(all(miri, test))
))]
pub use guard_pages::{
    GuardPageError, GuardPageOperation, GuardedSecretVec, GuardedSecretVecGenerateError,
};

#[cfg(any(
    all(
        feature = "memory-lock",
        any(
            all(
                target_os = "linux",
                any(target_arch = "x86_64", target_arch = "aarch64")
            ),
            target_os = "macos",
            target_os = "ios",
            target_os = "android",
            target_os = "windows",
            target_os = "freebsd",
            target_os = "openbsd",
            target_os = "netbsd",
            target_os = "dragonfly",
        )
    ),
    all(
        feature = "guard-pages",
        any(
            all(
                target_os = "linux",
                any(target_arch = "x86_64", target_arch = "aarch64")
            ),
            target_os = "macos",
            target_os = "ios",
            target_os = "android",
            target_os = "windows",
            target_os = "freebsd",
            target_os = "openbsd",
            target_os = "netbsd",
            target_os = "dragonfly",
        ),
        not(all(miri, test))
    )
))]
#[path = "mapped/bounded.rs"]
mod bounded;
#[cfg(any(
    all(
        feature = "memory-lock",
        any(
            all(
                target_os = "linux",
                any(target_arch = "x86_64", target_arch = "aarch64")
            ),
            target_os = "macos",
            target_os = "ios",
            target_os = "android",
            target_os = "windows",
            target_os = "freebsd",
            target_os = "openbsd",
            target_os = "netbsd",
            target_os = "dragonfly",
        )
    ),
    all(
        feature = "guard-pages",
        any(
            all(
                target_os = "linux",
                any(target_arch = "x86_64", target_arch = "aarch64")
            ),
            target_os = "macos",
            target_os = "ios",
            target_os = "android",
            target_os = "windows",
            target_os = "freebsd",
            target_os = "openbsd",
            target_os = "netbsd",
            target_os = "dragonfly",
        ),
        not(all(miri, test))
    )
))]
pub use bounded::*;

#[cfg(all(
    feature = "page-seal",
    any(
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ),
        target_os = "macos",
        target_os = "ios",
        target_os = "android",
        target_os = "windows",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
    ),
    not(all(miri, test))
))]
pub use guard_pages::{
    CleanupError, CleanupReport, CleanupState, SealedSecretAccessError, SealedSecretBytes,
};

/// Error returned when checked secret-text exposure detects corruption or
/// invalid UTF-8.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecretTextIntegrityError {
    /// Prefix or suffix canary verification failed.
    Canary(CanaryCorruptedError),
    /// The payload bytes were not valid UTF-8.
    Utf8(core::str::Utf8Error),
}

impl fmt::Display for SecretTextIntegrityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Canary(error) => error.fmt(formatter),
            Self::Utf8(error) => error.fmt(formatter),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for SecretTextIntegrityError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Canary(error) => Some(error),
            Self::Utf8(error) => Some(error),
        }
    }
}

/// Error returned when protected UTF-8 storage cannot be established, filled,
/// or validated.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtectedSecretTextFillError<E> {
    /// The requested public capacity exceeded the caller-supplied application
    /// maximum. No mapping was created and the fill closure was not invoked.
    CapacityLimit {
        /// Largest permitted UTF-8 byte capacity.
        maximum: usize,
        /// Capacity requested by the caller.
        actual: usize,
    },
    /// A required runtime protection could not be established before filling.
    Protection(ProtectionError),
    /// The caller-provided fill closure returned an error.
    Fill(E),
    /// Integrity canaries were corrupted while the fill closure had access.
    Integrity(CanaryCorruptedError),
    /// The fill closure reported more initialized bytes than requested.
    Length(crate::LengthError),
    /// The initialized bytes were not valid UTF-8 and were cleared.
    Utf8(core::str::Utf8Error),
}

impl<E> From<ProtectedSecretFillError<E>> for ProtectedSecretTextFillError<E> {
    #[inline]
    fn from(error: ProtectedSecretFillError<E>) -> Self {
        match error {
            ProtectedSecretFillError::CapacityLimit { maximum, actual } => {
                Self::CapacityLimit { maximum, actual }
            }
            ProtectedSecretFillError::Protection(error) => Self::Protection(error),
            ProtectedSecretFillError::Fill(error) => Self::Fill(error),
            ProtectedSecretFillError::Integrity(error) => Self::Integrity(error),
            ProtectedSecretFillError::Length(error) => Self::Length(error),
        }
    }
}

impl<E> From<SecretTextIntegrityError> for ProtectedSecretTextFillError<E> {
    #[inline]
    fn from(error: SecretTextIntegrityError) -> Self {
        match error {
            SecretTextIntegrityError::Canary(error) => Self::Integrity(error),
            SecretTextIntegrityError::Utf8(error) => Self::Utf8(error),
        }
    }
}

impl<E: fmt::Display> fmt::Display for ProtectedSecretTextFillError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CapacityLimit { maximum, actual } => write!(
                formatter,
                "protected secret text capacity {actual} exceeds application maximum {maximum}"
            ),
            Self::Protection(error) => error.fmt(formatter),
            Self::Fill(error) => write!(formatter, "protected secret text fill failed: {error}"),
            Self::Integrity(error) => error.fmt(formatter),
            Self::Length(error) => error.fmt(formatter),
            Self::Utf8(error) => error.fmt(formatter),
        }
    }
}

#[cfg(feature = "std")]
impl<E> std::error::Error for ProtectedSecretTextFillError<E>
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
            Self::Utf8(error) => Some(error),
        }
    }
}

/// UTF-8 text stored in a private platform mapping locked against paging.
///
/// This wrapper delegates allocation, locking, dump/fork exclusion, canary
/// handling, growth, clearing, unlocking, and unmapping to [`LockedSecretVec`].
/// It exposes only `str`/`mut str` access, so safe Rust cannot invalidate UTF-8.
#[cfg(all(
    feature = "memory-lock",
    any(
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ),
        target_os = "macos",
        target_os = "ios",
        target_os = "android",
        target_os = "windows",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
    )
))]
pub struct LockedSecretString {
    pub(crate) inner: LockedSecretVec,
}

#[cfg(all(
    feature = "memory-lock",
    any(
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ),
        target_os = "macos",
        target_os = "ios",
        target_os = "android",
        target_os = "windows",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
    )
))]
impl LockedSecretString {
    /// Allocate empty locked text storage with at least `capacity` UTF-8 bytes.
    #[inline]
    pub fn with_capacity(capacity: usize) -> Result<Self, MemoryLockError> {
        LockedSecretVec::with_capacity(capacity).map(|inner| Self { inner })
    }

    /// Allocate locked text with the `profile-hardened-native` policy.
    #[cfg(feature = "profile-hardened-native")]
    #[inline]
    pub fn with_capacity_hardened_native(capacity: usize) -> Result<Self, ProtectionError> {
        LockedSecretVec::with_capacity_hardened_native(capacity).map(|inner| Self { inner })
    }

    /// Allocate locked text with the `profile-hardened-linux` policy.
    #[cfg(feature = "profile-hardened-linux")]
    #[inline]
    pub fn with_capacity_hardened_linux(capacity: usize) -> Result<Self, ProtectionError> {
        LockedSecretVec::with_capacity_hardened_linux(capacity).map(|inner| Self { inner })
    }

    /// Allocate text storage under an explicit runtime protection policy.
    #[inline]
    pub fn with_capacity_with_protection(
        capacity: usize,
        request: ProtectionRequest,
    ) -> Result<Self, ProtectionError> {
        LockedSecretVec::with_capacity_with_protection(capacity, request)
            .map(|inner| Self { inner })
    }

    /// Fill a runtime-length UTF-8 payload only after all required controls
    /// have been established.
    ///
    /// The closure receives exactly `capacity` bytes and returns the number
    /// initialized. Invalid UTF-8, partial fill failures, excessive lengths,
    /// and canary corruption clear the mapping before returning an error.
    #[inline]
    pub fn try_from_capacity_with_protection<E>(
        capacity: usize,
        request: ProtectionRequest,
        fill: impl FnOnce(&mut [u8]) -> Result<usize, E>,
    ) -> Result<Self, ProtectedSecretTextFillError<E>> {
        let inner = LockedSecretVec::try_from_capacity_with_protection(capacity, request, fill)
            .map_err(ProtectedSecretTextFillError::from)?;
        Self::from_locked_secret_vec(inner).map_err(ProtectedSecretTextFillError::from)
    }

    /// Bounded policy-aware UTF-8 fill for untrusted capacities.
    ///
    /// A capacity above `maximum` is rejected before mapping or invoking
    /// `fill`.
    #[inline]
    pub fn try_from_capacity_bounded_with_protection<E>(
        capacity: usize,
        maximum: usize,
        request: ProtectionRequest,
        fill: impl FnOnce(&mut [u8]) -> Result<usize, E>,
    ) -> Result<Self, ProtectedSecretTextFillError<E>> {
        let inner = LockedSecretVec::try_from_capacity_bounded_with_protection(
            capacity, maximum, request, fill,
        )
        .map_err(ProtectedSecretTextFillError::from)?;
        Self::from_locked_secret_vec(inner).map_err(ProtectedSecretTextFillError::from)
    }

    /// Fill an exact-length UTF-8 payload after required controls succeed.
    #[inline]
    pub fn try_from_exact_len_with_protection<E>(
        len: usize,
        request: ProtectionRequest,
        fill: impl FnOnce(&mut [u8]) -> Result<(), E>,
    ) -> Result<Self, ProtectedSecretTextFillError<E>> {
        Self::try_from_capacity_with_protection(len, request, |output| {
            fill(output)?;
            Ok(len)
        })
    }

    /// Copy UTF-8 text directly into a locked platform mapping.
    #[inline]
    pub fn from_secret_str(text: &str) -> Result<Self, MemoryLockError> {
        LockedSecretVec::from_slice(text.as_bytes()).map(|inner| Self { inner })
    }

    /// Move an owned string through clear-on-drop staging into locked storage.
    ///
    /// The original string allocation is volatile-cleared whether mapping setup
    /// succeeds or fails. The locked mapping necessarily receives a copy
    /// because it does not use the Rust global allocator.
    #[cfg(feature = "alloc")]
    #[inline]
    pub fn from_string(text: String) -> Result<Self, MemoryLockError> {
        let source = SecretString::from_string(text);
        LockedSecretVec::from_slice(source.inner.as_slice()).map(|inner| Self { inner })
    }

    /// Wrap existing locked bytes without reallocating after UTF-8 validation.
    ///
    /// Invalid input is cleared before [`core::str::Utf8Error`] is returned.
    #[inline]
    pub fn from_locked_secret_vec(
        mut inner: LockedSecretVec,
    ) -> Result<Self, SecretTextIntegrityError> {
        let valid = inner
            .try_with_secret(|bytes| core::str::from_utf8(bytes).map(|_| ()))
            .map_err(SecretTextIntegrityError::Canary)?;
        if let Err(error) = valid {
            inner.clear_secret();
            return Err(SecretTextIntegrityError::Utf8(error));
        }
        Ok(Self { inner })
    }

    /// Number of initialized UTF-8 bytes.
    #[must_use]
    #[inline]
    pub const fn len(&self) -> usize {
        self.inner.len()
    }

    /// Returns true when no text is held.
    #[must_use]
    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Payload capacity in UTF-8 bytes.
    #[must_use]
    #[inline]
    pub const fn capacity(&self) -> usize {
        self.inner.capacity()
    }

    /// Length of the underlying locked mapping.
    #[must_use]
    #[inline]
    pub const fn locked_len(&self) -> usize {
        self.inner.locked_len()
    }

    /// Returns true when the underlying mapping is locked against ordinary paging.
    #[must_use]
    #[inline]
    pub const fn is_memory_locked(&self) -> bool {
        self.inner.is_memory_locked()
    }

    /// Actual runtime protections established for the underlying mapping.
    #[must_use]
    #[inline]
    pub const fn protection_report(&self) -> &ProtectionReport {
        self.inner.protection_report()
    }

    /// Runtime protection policy requested for the underlying mapping.
    #[must_use]
    #[inline]
    pub const fn protection_request(&self) -> ProtectionRequest {
        self.inner.protection_request()
    }

    /// Run a closure with read-only access to the locked secret text.
    #[inline]
    pub fn try_with_secret<R>(
        &self,
        inspect: impl FnOnce(&str) -> R,
    ) -> Result<R, SecretTextIntegrityError> {
        self.inner
            .try_with_secret(|bytes| core::str::from_utf8(bytes).map(inspect))
            .map_err(SecretTextIntegrityError::Canary)?
            .map_err(SecretTextIntegrityError::Utf8)
    }

    /// Run a closure with mutable access to the locked secret text.
    #[inline]
    pub fn try_with_secret_mut<R>(
        &mut self,
        edit: impl FnOnce(&mut str) -> R,
    ) -> Result<R, SecretTextIntegrityError> {
        self.inner
            .try_with_secret_mut(|bytes| core::str::from_utf8_mut(bytes).map(edit))
            .map_err(SecretTextIntegrityError::Canary)?
            .map_err(SecretTextIntegrityError::Utf8)
    }

    /// Run a closure with shared access, panicking on integrity or UTF-8 failure.
    #[inline]
    pub fn with_secret_or_panic<R>(&self, inspect: impl FnOnce(&str) -> R) -> R {
        self.try_with_secret(inspect)
            .unwrap_or_else(|_| panic!("locked secret text access failed"))
    }

    /// Run a closure with mutable access, panicking on integrity or UTF-8 failure.
    #[inline]
    pub fn with_secret_mut_or_panic<R>(&mut self, edit: impl FnOnce(&mut str) -> R) -> R {
        self.try_with_secret_mut(edit)
            .unwrap_or_else(|_| panic!("locked secret text mutation failed"))
    }

    /// Append UTF-8 text, preserving locked storage across growth.
    #[inline]
    pub fn try_push_str(
        &mut self,
        text: &str,
    ) -> Result<(), SecretIntegrityError<MemoryLockError>> {
        self.inner.try_extend_from_slice(text.as_bytes())
    }

    /// Replace all text while preserving locked-storage semantics.
    #[inline]
    pub fn try_replace_from_secret_str(
        &mut self,
        text: &str,
    ) -> Result<(), SecretIntegrityError<MemoryLockError>> {
        self.inner.try_replace_from_slice(text.as_bytes())
    }

    /// Replace all text from an owned string and clear the source allocation.
    #[cfg(feature = "alloc")]
    #[inline]
    pub fn try_replace_from_string(
        &mut self,
        text: String,
    ) -> Result<(), SecretIntegrityError<MemoryLockError>> {
        let source = SecretString::from_string(text);
        self.inner.try_replace_from_slice(source.inner.as_slice())
    }

    /// Clear the full locked mapping and reset the text length.
    #[inline(never)]
    pub fn clear_secret(&mut self) {
        self.inner.clear_secret();
    }

    /// Clear the locked mapping, then flush its cache lines.
    #[cfg(feature = "cache-flush")]
    #[inline(never)]
    pub fn try_clear_secret_and_flush(
        &mut self,
    ) -> Result<crate::cache_flush::CacheFlushReport, crate::cache_flush::CacheFlushError> {
        self.inner.try_clear_secret_and_flush()
    }

    /// Compare against UTF-8 text without early exit for equal-length inputs.
    #[inline]
    pub fn try_constant_time_eq(&self, other: &str) -> Result<bool, CanaryCorruptedError> {
        self.inner.try_constant_time_eq(other.as_bytes())
    }

    /// Compare after integrity verification, panicking on canary corruption.
    #[must_use]
    #[inline]
    pub fn constant_time_eq_or_panic(&self, other: &str) -> bool {
        self.try_constant_time_eq(other)
            .expect("locked secret canary corrupted")
    }

    /// Verify the underlying locked mapping canaries.
    #[inline]
    pub fn verify_integrity(&self) -> Result<(), CanaryCorruptedError> {
        self.inner.verify_integrity()
    }

    /// Return the locked byte container without reallocating.
    #[must_use]
    #[inline]
    pub fn into_locked_secret_vec(self) -> LockedSecretVec {
        self.inner
    }
}

#[cfg(all(
    feature = "memory-lock",
    any(
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ),
        target_os = "macos",
        target_os = "ios",
        target_os = "android",
        target_os = "windows",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
    )
))]
impl TryFrom<LockedSecretVec> for LockedSecretString {
    type Error = SecretTextIntegrityError;

    #[inline]
    fn try_from(secret: LockedSecretVec) -> Result<Self, Self::Error> {
        Self::from_locked_secret_vec(secret)
    }
}

#[cfg(all(
    feature = "memory-lock",
    any(
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ),
        target_os = "macos",
        target_os = "ios",
        target_os = "android",
        target_os = "windows",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
    )
))]
impl From<LockedSecretString> for LockedSecretVec {
    #[inline]
    fn from(secret: LockedSecretString) -> Self {
        secret.into_locked_secret_vec()
    }
}

#[cfg(all(
    feature = "memory-lock",
    any(
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ),
        target_os = "macos",
        target_os = "ios",
        target_os = "android",
        target_os = "windows",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
    )
))]
impl SecureSanitize for LockedSecretString {
    #[inline]
    fn secure_sanitize(&mut self) {
        self.clear_secret();
    }
}

#[cfg(all(
    feature = "memory-lock",
    any(
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ),
        target_os = "macos",
        target_os = "ios",
        target_os = "android",
        target_os = "windows",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
    )
))]
impl fmt::Debug for LockedSecretString {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LockedSecretString")
            .field("len", &self.len())
            .field("capacity", &self.capacity())
            .field("locked_len", &self.locked_len())
            .field("contents", &"<redacted>")
            .finish()
    }
}

/// UTF-8 text stored between inaccessible platform guard pages.
///
/// This wrapper delegates guarded mapping ownership, optional memory locking,
/// canary handling, growth, clearing, and unmapping to [`GuardedSecretVec`].
/// It exposes only `str`/`mut str` access.
#[cfg(all(
    feature = "guard-pages",
    any(
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ),
        target_os = "macos",
        target_os = "ios",
        target_os = "android",
        target_os = "windows",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
    ),
    not(all(miri, test))
))]
pub struct GuardedSecretString {
    pub(crate) inner: GuardedSecretVec,
}

#[cfg(all(
    feature = "guard-pages",
    any(
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ),
        target_os = "macos",
        target_os = "ios",
        target_os = "android",
        target_os = "windows",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
    ),
    not(all(miri, test))
))]
impl GuardedSecretString {
    /// Allocate empty guarded text storage with at least `capacity` UTF-8 bytes.
    #[inline]
    pub fn with_capacity(capacity: usize) -> Result<Self, GuardPageError> {
        GuardedSecretVec::with_capacity(capacity).map(|inner| Self { inner })
    }

    /// Allocate guarded text with the `profile-guarded-native` policy.
    #[cfg(feature = "profile-guarded-native")]
    #[inline]
    pub fn with_capacity_guarded_native(capacity: usize) -> Result<Self, ProtectionError> {
        GuardedSecretVec::with_capacity_guarded_native(capacity).map(|inner| Self { inner })
    }

    /// Allocate guarded text under an explicit runtime protection policy.
    #[inline]
    pub fn with_capacity_with_protection(
        capacity: usize,
        request: ProtectionRequest,
    ) -> Result<Self, ProtectionError> {
        GuardedSecretVec::with_capacity_with_protection(capacity, request)
            .map(|inner| Self { inner })
    }

    /// Fill a runtime-length UTF-8 payload only after all required controls
    /// have been established.
    ///
    /// The closure receives exactly `capacity` bytes and returns the number
    /// initialized. Invalid UTF-8, partial fill failures, excessive lengths,
    /// and canary corruption clear the mapping before returning an error.
    #[inline]
    pub fn try_from_capacity_with_protection<E>(
        capacity: usize,
        request: ProtectionRequest,
        fill: impl FnOnce(&mut [u8]) -> Result<usize, E>,
    ) -> Result<Self, ProtectedSecretTextFillError<E>> {
        let inner = GuardedSecretVec::try_from_capacity_with_protection(capacity, request, fill)
            .map_err(ProtectedSecretTextFillError::from)?;
        Self::from_guarded_secret_vec(inner).map_err(ProtectedSecretTextFillError::from)
    }

    /// Bounded policy-aware UTF-8 fill for untrusted capacities.
    ///
    /// A capacity above `maximum` is rejected before mapping or invoking
    /// `fill`.
    #[inline]
    pub fn try_from_capacity_bounded_with_protection<E>(
        capacity: usize,
        maximum: usize,
        request: ProtectionRequest,
        fill: impl FnOnce(&mut [u8]) -> Result<usize, E>,
    ) -> Result<Self, ProtectedSecretTextFillError<E>> {
        let inner = GuardedSecretVec::try_from_capacity_bounded_with_protection(
            capacity, maximum, request, fill,
        )
        .map_err(ProtectedSecretTextFillError::from)?;
        Self::from_guarded_secret_vec(inner).map_err(ProtectedSecretTextFillError::from)
    }

    /// Fill an exact-length UTF-8 payload after required controls succeed.
    #[inline]
    pub fn try_from_exact_len_with_protection<E>(
        len: usize,
        request: ProtectionRequest,
        fill: impl FnOnce(&mut [u8]) -> Result<(), E>,
    ) -> Result<Self, ProtectedSecretTextFillError<E>> {
        Self::try_from_capacity_with_protection(len, request, |output| {
            fill(output)?;
            Ok(len)
        })
    }

    /// Copy UTF-8 text directly into a guarded platform mapping.
    #[inline]
    pub fn from_secret_str(text: &str) -> Result<Self, GuardPageError> {
        GuardedSecretVec::from_slice(text.as_bytes()).map(|inner| Self { inner })
    }

    /// Move an owned string through clear-on-drop staging into guarded storage.
    #[cfg(feature = "alloc")]
    #[inline]
    pub fn from_string(text: String) -> Result<Self, GuardPageError> {
        let source = SecretString::from_string(text);
        GuardedSecretVec::from_slice(source.inner.as_slice()).map(|inner| Self { inner })
    }

    /// Copy UTF-8 text into a guarded and memory-locked mapping.
    #[cfg(feature = "memory-lock")]
    #[inline]
    pub fn locked_from_secret_str(text: &str) -> Result<Self, GuardPageError> {
        GuardedSecretVec::locked_from_slice(text.as_bytes()).map(|inner| Self { inner })
    }

    /// Move an owned string through clear-on-drop staging into a guarded and
    /// memory-locked mapping.
    #[cfg(all(feature = "alloc", feature = "memory-lock"))]
    #[inline]
    pub fn locked_from_string(text: String) -> Result<Self, GuardPageError> {
        let source = SecretString::from_string(text);
        GuardedSecretVec::locked_from_slice(source.inner.as_slice()).map(|inner| Self { inner })
    }

    /// Wrap existing guarded bytes without reallocating after UTF-8 validation.
    ///
    /// Invalid input is cleared before [`core::str::Utf8Error`] is returned.
    #[inline]
    pub fn from_guarded_secret_vec(
        mut inner: GuardedSecretVec,
    ) -> Result<Self, SecretTextIntegrityError> {
        let valid = inner
            .try_with_secret(|bytes| core::str::from_utf8(bytes).map(|_| ()))
            .map_err(SecretTextIntegrityError::Canary)?;
        if let Err(error) = valid {
            inner.clear_secret();
            return Err(SecretTextIntegrityError::Utf8(error));
        }
        Ok(Self { inner })
    }

    /// Number of initialized UTF-8 bytes.
    #[must_use]
    #[inline]
    pub const fn len(&self) -> usize {
        self.inner.len()
    }

    /// Returns true when no text is held.
    #[must_use]
    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Payload capacity in UTF-8 bytes.
    #[must_use]
    #[inline]
    pub const fn capacity(&self) -> usize {
        self.inner.capacity()
    }

    /// Returns true when the writable guarded pages are memory locked.
    #[must_use]
    #[inline]
    pub const fn is_memory_locked(&self) -> bool {
        self.inner.is_memory_locked()
    }

    /// Actual runtime protections established for the underlying mapping.
    #[must_use]
    #[inline]
    pub const fn protection_report(&self) -> &ProtectionReport {
        self.inner.protection_report()
    }

    /// Runtime protection policy requested for the underlying mapping.
    #[must_use]
    #[inline]
    pub const fn protection_request(&self) -> ProtectionRequest {
        self.inner.protection_request()
    }

    /// Run a closure with read-only access to the guarded secret text.
    #[inline]
    pub fn try_with_secret<R>(
        &self,
        inspect: impl FnOnce(&str) -> R,
    ) -> Result<R, SecretTextIntegrityError> {
        self.inner
            .try_with_secret(|bytes| core::str::from_utf8(bytes).map(inspect))
            .map_err(SecretTextIntegrityError::Canary)?
            .map_err(SecretTextIntegrityError::Utf8)
    }

    /// Run a closure with mutable access to the guarded secret text.
    #[inline]
    pub fn try_with_secret_mut<R>(
        &mut self,
        edit: impl FnOnce(&mut str) -> R,
    ) -> Result<R, SecretTextIntegrityError> {
        self.inner
            .try_with_secret_mut(|bytes| core::str::from_utf8_mut(bytes).map(edit))
            .map_err(SecretTextIntegrityError::Canary)?
            .map_err(SecretTextIntegrityError::Utf8)
    }

    /// Run a closure with shared access, panicking on integrity or UTF-8 failure.
    #[inline]
    pub fn with_secret_or_panic<R>(&self, inspect: impl FnOnce(&str) -> R) -> R {
        self.try_with_secret(inspect)
            .unwrap_or_else(|_| panic!("guarded secret text access failed"))
    }

    /// Run a closure with mutable access, panicking on integrity or UTF-8 failure.
    #[inline]
    pub fn with_secret_mut_or_panic<R>(&mut self, edit: impl FnOnce(&mut str) -> R) -> R {
        self.try_with_secret_mut(edit)
            .unwrap_or_else(|_| panic!("guarded secret text mutation failed"))
    }

    /// Append UTF-8 text, preserving guarded and lock-state semantics.
    #[inline]
    pub fn try_push_str(&mut self, text: &str) -> Result<(), SecretIntegrityError<GuardPageError>> {
        self.inner.try_extend_from_slice(text.as_bytes())
    }

    /// Replace all text while preserving guarded and lock-state semantics.
    #[inline]
    pub fn try_replace_from_secret_str(
        &mut self,
        text: &str,
    ) -> Result<(), SecretIntegrityError<GuardPageError>> {
        self.inner.try_replace_from_slice(text.as_bytes())
    }

    /// Replace all text from an owned string and clear the source allocation.
    #[cfg(feature = "alloc")]
    #[inline]
    pub fn try_replace_from_string(
        &mut self,
        text: String,
    ) -> Result<(), SecretIntegrityError<GuardPageError>> {
        let source = SecretString::from_string(text);
        self.inner.try_replace_from_slice(source.inner.as_slice())
    }

    /// Clear the full writable guarded region and reset the text length.
    #[inline(never)]
    pub fn clear_secret(&mut self) {
        self.inner.clear_secret();
    }

    /// Clear the writable guarded region, then flush its cache lines.
    #[cfg(feature = "cache-flush")]
    #[inline(never)]
    pub fn try_clear_secret_and_flush(
        &mut self,
    ) -> Result<crate::cache_flush::CacheFlushReport, crate::cache_flush::CacheFlushError> {
        self.inner.try_clear_secret_and_flush()
    }

    /// Compare against UTF-8 text without early exit for equal-length inputs.
    #[inline]
    pub fn try_constant_time_eq(&self, other: &str) -> Result<bool, CanaryCorruptedError> {
        self.inner.try_constant_time_eq(other.as_bytes())
    }

    /// Compare after integrity verification, panicking on canary corruption.
    #[must_use]
    #[inline]
    pub fn constant_time_eq_or_panic(&self, other: &str) -> bool {
        self.try_constant_time_eq(other)
            .expect("guarded secret canary corrupted")
    }

    /// Verify the guarded mapping canaries.
    #[inline]
    pub fn verify_integrity(&self) -> Result<(), CanaryCorruptedError> {
        self.inner.verify_integrity()
    }

    /// Return the guarded byte container without reallocating.
    #[must_use]
    #[inline]
    pub fn into_guarded_secret_vec(self) -> GuardedSecretVec {
        self.inner
    }
}

#[cfg(all(
    feature = "guard-pages",
    any(
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ),
        target_os = "macos",
        target_os = "ios",
        target_os = "android",
        target_os = "windows",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
    ),
    not(all(miri, test))
))]
impl TryFrom<GuardedSecretVec> for GuardedSecretString {
    type Error = SecretTextIntegrityError;

    #[inline]
    fn try_from(secret: GuardedSecretVec) -> Result<Self, Self::Error> {
        Self::from_guarded_secret_vec(secret)
    }
}

#[cfg(all(
    feature = "guard-pages",
    any(
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ),
        target_os = "macos",
        target_os = "ios",
        target_os = "android",
        target_os = "windows",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
    ),
    not(all(miri, test))
))]
impl From<GuardedSecretString> for GuardedSecretVec {
    #[inline]
    fn from(secret: GuardedSecretString) -> Self {
        secret.into_guarded_secret_vec()
    }
}

#[cfg(all(
    feature = "guard-pages",
    any(
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ),
        target_os = "macos",
        target_os = "ios",
        target_os = "android",
        target_os = "windows",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
    ),
    not(all(miri, test))
))]
impl SecureSanitize for GuardedSecretString {
    #[inline]
    fn secure_sanitize(&mut self) {
        self.clear_secret();
    }
}

#[cfg(all(
    feature = "guard-pages",
    any(
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ),
        target_os = "macos",
        target_os = "ios",
        target_os = "android",
        target_os = "windows",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
    ),
    not(all(miri, test))
))]
impl fmt::Debug for GuardedSecretString {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GuardedSecretString")
            .field("len", &self.len())
            .field("capacity", &self.capacity())
            .field("memory_locked", &self.is_memory_locked())
            .field("contents", &"<redacted>")
            .finish()
    }
}

#[cfg(all(
    feature = "memory-lock",
    any(
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ),
        target_os = "macos",
        target_os = "ios",
        target_os = "android",
        target_os = "windows",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
        all(target_arch = "wasm32", feature = "wasm-compat"),
    )
))]
mod native_ct_memory_lock_impls {
    use super::*;

    impl<const N: usize> ct::ConstantTimeEq for LockedSecretBytes<N> {
        #[inline]
        fn ct_eq(&self, other: &Self) -> ct::Choice {
            match self.try_expose_secret(|left| {
                other.try_expose_secret(|right| ct::eq_fixed(left, right))
            }) {
                Ok(Ok(choice)) => choice,
                Ok(Err(_)) | Err(_) => ct::Choice::FALSE,
            }
        }
    }

    impl<const N: usize> ct::ConstantTimeEq<[u8]> for LockedSecretBytes<N> {
        #[inline]
        fn ct_eq(&self, other: &[u8]) -> ct::Choice {
            self.try_expose_secret(|left| ct::eq_public_len(left, other))
                .unwrap_or(ct::Choice::FALSE)
        }
    }

    impl<'pool, const N: usize, const SLOTS: usize> ct::ConstantTimeEq
        for SecretPoolSlot<'pool, N, SLOTS>
    {
        #[inline]
        fn ct_eq(&self, other: &Self) -> ct::Choice {
            match self.try_expose_secret(|left| {
                other.try_expose_secret(|right| ct::eq_fixed(left, right))
            }) {
                Ok(Ok(choice)) => choice,
                Ok(Err(_)) | Err(_) => ct::Choice::FALSE,
            }
        }
    }

    impl<'pool, const N: usize, const SLOTS: usize> ct::ConstantTimeEq<[u8]>
        for SecretPoolSlot<'pool, N, SLOTS>
    {
        #[inline]
        fn ct_eq(&self, other: &[u8]) -> ct::Choice {
            self.try_expose_secret(|left| ct::eq_public_len(left, other))
                .unwrap_or(ct::Choice::FALSE)
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    impl ct::ConstantTimeEq for LockedSecretVec {
        #[inline]
        fn ct_eq(&self, other: &Self) -> ct::Choice {
            match self.try_with_secret(|left| {
                other.try_with_secret(|right| ct::eq_public_len(left, right))
            }) {
                Ok(Ok(choice)) => choice,
                Ok(Err(_)) | Err(_) => ct::Choice::FALSE,
            }
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    impl ct::ConstantTimeEq<[u8]> for LockedSecretVec {
        #[inline]
        fn ct_eq(&self, other: &[u8]) -> ct::Choice {
            self.try_with_secret(|left| ct::eq_public_len(left, other))
                .unwrap_or(ct::Choice::FALSE)
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    impl<const MAX: usize> ct::ConstantTimeEq for BoundedLockedSecretVec<MAX> {
        #[inline]
        fn ct_eq(&self, other: &Self) -> ct::Choice {
            match self.try_with_secret(|left| {
                other.try_with_secret(|right| ct::eq_public_len(left, right))
            }) {
                Ok(Ok(choice)) => choice,
                Ok(Err(_)) | Err(_) => ct::Choice::FALSE,
            }
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    impl<const MAX: usize> ct::ConstantTimeEq<[u8]> for BoundedLockedSecretVec<MAX> {
        #[inline]
        fn ct_eq(&self, other: &[u8]) -> ct::Choice {
            self.try_with_secret(|left| ct::eq_public_len(left, other))
                .unwrap_or(ct::Choice::FALSE)
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    impl ct::ConstantTimeEq for LockedSecretString {
        #[inline]
        fn ct_eq(&self, other: &Self) -> ct::Choice {
            self.inner.ct_eq(&other.inner)
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    impl ct::ConstantTimeEq<str> for LockedSecretString {
        #[inline]
        fn ct_eq(&self, other: &str) -> ct::Choice {
            self.inner.ct_eq(other.as_bytes())
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    impl<const MAX: usize> ct::ConstantTimeEq for BoundedLockedSecretString<MAX> {
        #[inline]
        fn ct_eq(&self, other: &Self) -> ct::Choice {
            match self.try_with_secret(|left| {
                other.try_with_secret(|right| ct::eq_public_len(left.as_bytes(), right.as_bytes()))
            }) {
                Ok(Ok(choice)) => choice,
                Ok(Err(_)) | Err(_) => ct::Choice::FALSE,
            }
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    impl<const MAX: usize> ct::ConstantTimeEq<str> for BoundedLockedSecretString<MAX> {
        #[inline]
        fn ct_eq(&self, other: &str) -> ct::Choice {
            self.try_with_secret(|left| ct::eq_public_len(left.as_bytes(), other.as_bytes()))
                .unwrap_or(ct::Choice::FALSE)
        }
    }
}

#[cfg(all(
    feature = "guard-pages",
    any(
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ),
        target_os = "macos",
        target_os = "ios",
        target_os = "android",
        target_os = "windows",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
    ),
    not(all(miri, test))
))]
mod native_ct_guard_page_impls {
    use super::*;

    impl ct::ConstantTimeEq for GuardedSecretVec {
        #[inline]
        fn ct_eq(&self, other: &Self) -> ct::Choice {
            match self.try_with_secret(|left| {
                other.try_with_secret(|right| ct::eq_public_len(left, right))
            }) {
                Ok(Ok(choice)) => choice,
                Ok(Err(_)) | Err(_) => ct::Choice::FALSE,
            }
        }
    }

    impl ct::ConstantTimeEq<[u8]> for GuardedSecretVec {
        #[inline]
        fn ct_eq(&self, other: &[u8]) -> ct::Choice {
            self.try_with_secret(|left| ct::eq_public_len(left, other))
                .unwrap_or(ct::Choice::FALSE)
        }
    }

    impl<const MAX: usize> ct::ConstantTimeEq for BoundedGuardedSecretVec<MAX> {
        #[inline]
        fn ct_eq(&self, other: &Self) -> ct::Choice {
            match self.try_with_secret(|left| {
                other.try_with_secret(|right| ct::eq_public_len(left, right))
            }) {
                Ok(Ok(choice)) => choice,
                Ok(Err(_)) | Err(_) => ct::Choice::FALSE,
            }
        }
    }

    impl<const MAX: usize> ct::ConstantTimeEq<[u8]> for BoundedGuardedSecretVec<MAX> {
        #[inline]
        fn ct_eq(&self, other: &[u8]) -> ct::Choice {
            self.try_with_secret(|left| ct::eq_public_len(left, other))
                .unwrap_or(ct::Choice::FALSE)
        }
    }

    impl ct::ConstantTimeEq for GuardedSecretString {
        #[inline]
        fn ct_eq(&self, other: &Self) -> ct::Choice {
            self.inner.ct_eq(&other.inner)
        }
    }

    impl ct::ConstantTimeEq<str> for GuardedSecretString {
        #[inline]
        fn ct_eq(&self, other: &str) -> ct::Choice {
            self.inner.ct_eq(other.as_bytes())
        }
    }

    impl<const MAX: usize> ct::ConstantTimeEq for BoundedGuardedSecretString<MAX> {
        #[inline]
        fn ct_eq(&self, other: &Self) -> ct::Choice {
            match self.try_with_secret(|left| {
                other.try_with_secret(|right| ct::eq_public_len(left.as_bytes(), right.as_bytes()))
            }) {
                Ok(Ok(choice)) => choice,
                Ok(Err(_)) | Err(_) => ct::Choice::FALSE,
            }
        }
    }

    impl<const MAX: usize> ct::ConstantTimeEq<str> for BoundedGuardedSecretString<MAX> {
        #[inline]
        fn ct_eq(&self, other: &str) -> ct::Choice {
            self.try_with_secret(|left| ct::eq_public_len(left.as_bytes(), other.as_bytes()))
                .unwrap_or(ct::Choice::FALSE)
        }
    }
}

#[cfg(all(
    test,
    feature = "std",
    feature = "profile-guarded-native",
    any(target_os = "macos", target_os = "linux"),
    not(miri)
))]
#[allow(unsafe_code)]
#[path = "mapped/native_tests.rs"]
mod native_tests;
