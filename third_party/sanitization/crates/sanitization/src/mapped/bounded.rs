use core::fmt;

use super::{
    BoundedMappedSecretError, CanaryCorruptedError, ProtectedSecretFillError,
    ProtectedSecretTextFillError, ProtectionReport, ProtectionRequest, SecretTextIntegrityError,
};
use crate::SecureSanitize;

macro_rules! enforce_replacement_bound {
    ($maximum:expr, $actual:expr) => {
        if $actual > $maximum {
            return Err(BoundedMappedSecretError::CapacityLimit {
                maximum: $maximum,
                actual: $actual,
            });
        }
    };
}

macro_rules! checked_extended_len {
    ($current:expr, $additional:expr, $maximum:expr) => {{
        let actual = $current
            .checked_add($additional)
            .ok_or(BoundedMappedSecretError::CapacityOverflow { maximum: $maximum })?;
        enforce_replacement_bound!($maximum, actual);
        actual
    }};
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
use super::{LockedSecretVec, LockedSecretVecGenerateError, MemoryLockError};

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
use super::{GuardPageError, GuardedSecretVec, GuardedSecretVecGenerateError};

/// Runtime-length locked bytes with a permanent type-level maximum.
///
/// The inner growable container is private and cannot be extracted. Every safe
/// constructor, append, and replacement rejects a resulting length above
/// `MAX` before allocation or caller-provided generation begins.
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
pub struct BoundedLockedSecretVec<const MAX: usize> {
    inner: LockedSecretVec,
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
impl<const MAX: usize> BoundedLockedSecretVec<MAX> {
    /// Maximum initialized length accepted for the lifetime of this value.
    #[must_use]
    pub const fn max_len() -> usize {
        MAX
    }

    /// Construct an empty bounded mapping after establishing requested controls.
    pub fn try_with_capacity_with_protection(
        capacity: usize,
        request: ProtectionRequest,
    ) -> Result<Self, ProtectedSecretFillError<core::convert::Infallible>> {
        Self::try_from_capacity_with_protection(capacity, request, |_| {
            Ok::<usize, core::convert::Infallible>(0)
        })
    }

    /// Fill bounded locked storage after all required controls succeed.
    pub fn try_from_capacity_with_protection<E>(
        capacity: usize,
        request: ProtectionRequest,
        fill: impl FnOnce(&mut [u8]) -> Result<usize, E>,
    ) -> Result<Self, ProtectedSecretFillError<E>> {
        LockedSecretVec::try_from_capacity_bounded_with_protection(capacity, MAX, request, fill)
            .map(|inner| Self { inner })
    }

    /// Fill an exact-length bounded locked value in place.
    pub fn try_from_exact_len_with_protection<E>(
        len: usize,
        request: ProtectionRequest,
        fill: impl FnOnce(&mut [u8]) -> Result<(), E>,
    ) -> Result<Self, ProtectedSecretFillError<E>> {
        Self::try_from_capacity_with_protection(len, request, |output| {
            fill(output)?;
            Ok(len)
        })
    }

    /// Copy a slice after required controls are established.
    pub fn from_slice_with_protection(
        bytes: &[u8],
        request: ProtectionRequest,
    ) -> Result<Self, ProtectedSecretFillError<core::convert::Infallible>> {
        Self::try_from_exact_len_with_protection(bytes.len(), request, |output| {
            output.copy_from_slice(bytes);
            Ok::<(), core::convert::Infallible>(())
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

    /// Current backing mapping capacity; safe mutation remains capped at `MAX`.
    #[must_use]
    pub const fn backing_capacity(&self) -> usize {
        self.inner.capacity()
    }

    #[must_use]
    pub const fn locked_len(&self) -> usize {
        self.inner.locked_len()
    }

    /// Returns true when the mapping is locked against ordinary paging.
    #[must_use]
    pub const fn is_memory_locked(&self) -> bool {
        self.inner.is_memory_locked()
    }

    #[must_use]
    pub const fn protection_report(&self) -> &ProtectionReport {
        self.inner.protection_report()
    }

    #[must_use]
    pub const fn protection_request(&self) -> ProtectionRequest {
        self.inner.protection_request()
    }

    pub fn try_with_secret<R>(
        &self,
        inspect: impl FnOnce(&[u8]) -> R,
    ) -> Result<R, CanaryCorruptedError> {
        self.inner.try_with_secret(inspect)
    }

    pub fn try_with_secret_mut<R>(
        &mut self,
        edit: impl FnOnce(&mut [u8]) -> R,
    ) -> Result<R, CanaryCorruptedError> {
        self.inner.try_with_secret_mut(edit)
    }

    pub fn try_extend_from_slice(
        &mut self,
        bytes: &[u8],
    ) -> Result<(), BoundedMappedSecretError<MemoryLockError>> {
        // Verify before the public bound check so corruption cannot be masked
        // by a capacity error. The inner operation re-verifies at its boundary.
        self.verify_integrity()
            .map_err(BoundedMappedSecretError::Integrity)?;
        let _ = checked_extended_len!(self.len(), bytes.len(), MAX);
        self.inner.try_extend_from_slice(bytes).map_err(Into::into)
    }

    pub fn try_replace_from_slice(
        &mut self,
        bytes: &[u8],
    ) -> Result<(), BoundedMappedSecretError<MemoryLockError>> {
        self.verify_integrity()
            .map_err(BoundedMappedSecretError::Integrity)?;
        enforce_replacement_bound!(MAX, bytes.len());
        self.inner.try_replace_from_slice(bytes).map_err(Into::into)
    }

    pub fn try_replace_from_fn(
        &mut self,
        len: usize,
        make_byte: impl FnMut(usize) -> u8,
    ) -> Result<(), BoundedMappedSecretError<MemoryLockError>> {
        self.verify_integrity()
            .map_err(BoundedMappedSecretError::Integrity)?;
        enforce_replacement_bound!(MAX, len);
        self.inner
            .try_replace_from_fn(len, make_byte)
            .map_err(Into::into)
    }

    pub fn try_replace_from_fallible_fn<E>(
        &mut self,
        len: usize,
        make_byte: impl FnMut(usize) -> Result<u8, E>,
    ) -> Result<(), BoundedMappedSecretError<LockedSecretVecGenerateError<E>>> {
        self.verify_integrity()
            .map_err(BoundedMappedSecretError::Integrity)?;
        enforce_replacement_bound!(MAX, len);
        self.inner
            .try_replace_from_fallible_fn(len, make_byte)
            .map_err(Into::into)
    }

    #[inline(never)]
    pub fn clear_secret(&mut self) {
        self.inner.clear_secret();
    }

    pub fn try_constant_time_eq(&self, other: &[u8]) -> Result<bool, CanaryCorruptedError> {
        self.inner.try_constant_time_eq(other)
    }

    pub fn verify_integrity(&self) -> Result<(), CanaryCorruptedError> {
        self.inner.verify_integrity()
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
impl<const MAX: usize> SecureSanitize for BoundedLockedSecretVec<MAX> {
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
impl<const MAX: usize> fmt::Debug for BoundedLockedSecretVec<MAX> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BoundedLockedSecretVec")
            .field("len", &self.len())
            .field("maximum", &MAX)
            .field("contents", &"<redacted>")
            .finish()
    }
}

/// Runtime-length guarded bytes with a permanent type-level maximum.
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
pub struct BoundedGuardedSecretVec<const MAX: usize> {
    inner: GuardedSecretVec,
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
impl<const MAX: usize> BoundedGuardedSecretVec<MAX> {
    #[must_use]
    pub const fn max_len() -> usize {
        MAX
    }

    pub fn try_with_capacity_with_protection(
        capacity: usize,
        request: ProtectionRequest,
    ) -> Result<Self, ProtectedSecretFillError<core::convert::Infallible>> {
        Self::try_from_capacity_with_protection(capacity, request, |_| {
            Ok::<usize, core::convert::Infallible>(0)
        })
    }

    pub fn try_from_capacity_with_protection<E>(
        capacity: usize,
        request: ProtectionRequest,
        fill: impl FnOnce(&mut [u8]) -> Result<usize, E>,
    ) -> Result<Self, ProtectedSecretFillError<E>> {
        GuardedSecretVec::try_from_capacity_bounded_with_protection(capacity, MAX, request, fill)
            .map(|inner| Self { inner })
    }

    pub fn try_from_exact_len_with_protection<E>(
        len: usize,
        request: ProtectionRequest,
        fill: impl FnOnce(&mut [u8]) -> Result<(), E>,
    ) -> Result<Self, ProtectedSecretFillError<E>> {
        Self::try_from_capacity_with_protection(len, request, |output| {
            fill(output)?;
            Ok(len)
        })
    }

    pub fn from_slice_with_protection(
        bytes: &[u8],
        request: ProtectionRequest,
    ) -> Result<Self, ProtectedSecretFillError<core::convert::Infallible>> {
        Self::try_from_exact_len_with_protection(bytes.len(), request, |output| {
            output.copy_from_slice(bytes);
            Ok::<(), core::convert::Infallible>(())
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
    pub const fn backing_capacity(&self) -> usize {
        self.inner.capacity()
    }

    #[must_use]
    pub const fn is_memory_locked(&self) -> bool {
        self.inner.is_memory_locked()
    }

    #[must_use]
    pub const fn protection_report(&self) -> &ProtectionReport {
        self.inner.protection_report()
    }

    #[must_use]
    pub const fn protection_request(&self) -> ProtectionRequest {
        self.inner.protection_request()
    }

    pub fn try_with_secret<R>(
        &self,
        inspect: impl FnOnce(&[u8]) -> R,
    ) -> Result<R, CanaryCorruptedError> {
        self.inner.try_with_secret(inspect)
    }

    pub fn try_with_secret_mut<R>(
        &mut self,
        edit: impl FnOnce(&mut [u8]) -> R,
    ) -> Result<R, CanaryCorruptedError> {
        self.inner.try_with_secret_mut(edit)
    }

    pub fn try_extend_from_slice(
        &mut self,
        bytes: &[u8],
    ) -> Result<(), BoundedMappedSecretError<GuardPageError>> {
        self.verify_integrity()
            .map_err(BoundedMappedSecretError::Integrity)?;
        let _ = checked_extended_len!(self.len(), bytes.len(), MAX);
        self.inner.try_extend_from_slice(bytes).map_err(Into::into)
    }

    pub fn try_replace_from_slice(
        &mut self,
        bytes: &[u8],
    ) -> Result<(), BoundedMappedSecretError<GuardPageError>> {
        self.verify_integrity()
            .map_err(BoundedMappedSecretError::Integrity)?;
        enforce_replacement_bound!(MAX, bytes.len());
        self.inner.try_replace_from_slice(bytes).map_err(Into::into)
    }

    pub fn try_replace_from_fn(
        &mut self,
        len: usize,
        make_byte: impl FnMut(usize) -> u8,
    ) -> Result<(), BoundedMappedSecretError<GuardPageError>> {
        self.verify_integrity()
            .map_err(BoundedMappedSecretError::Integrity)?;
        enforce_replacement_bound!(MAX, len);
        self.inner
            .try_replace_from_fn(len, make_byte)
            .map_err(Into::into)
    }

    pub fn try_replace_from_fallible_fn<E>(
        &mut self,
        len: usize,
        make_byte: impl FnMut(usize) -> Result<u8, E>,
    ) -> Result<(), BoundedMappedSecretError<GuardedSecretVecGenerateError<E>>> {
        self.verify_integrity()
            .map_err(BoundedMappedSecretError::Integrity)?;
        enforce_replacement_bound!(MAX, len);
        self.inner
            .try_replace_from_fallible_fn(len, make_byte)
            .map_err(Into::into)
    }

    #[inline(never)]
    pub fn clear_secret(&mut self) {
        self.inner.clear_secret();
    }

    pub fn try_constant_time_eq(&self, other: &[u8]) -> Result<bool, CanaryCorruptedError> {
        self.inner.try_constant_time_eq(other)
    }

    pub fn verify_integrity(&self) -> Result<(), CanaryCorruptedError> {
        self.inner.verify_integrity()
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
impl<const MAX: usize> SecureSanitize for BoundedGuardedSecretVec<MAX> {
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
impl<const MAX: usize> fmt::Debug for BoundedGuardedSecretVec<MAX> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BoundedGuardedSecretVec")
            .field("len", &self.len())
            .field("maximum", &MAX)
            .field("contents", &"<redacted>")
            .finish()
    }
}

/// Locked UTF-8 text with a permanent type-level byte maximum.
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
pub struct BoundedLockedSecretString<const MAX: usize> {
    inner: super::LockedSecretString,
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
impl<const MAX: usize> BoundedLockedSecretString<MAX> {
    #[must_use]
    pub const fn max_len() -> usize {
        MAX
    }

    /// Construct empty bounded UTF-8 storage after required controls succeed.
    pub fn try_with_capacity_with_protection(
        capacity: usize,
        request: ProtectionRequest,
    ) -> Result<Self, ProtectedSecretTextFillError<core::convert::Infallible>> {
        Self::try_from_capacity_with_protection(capacity, request, |_| {
            Ok::<usize, core::convert::Infallible>(0)
        })
    }

    /// Fill bounded locked UTF-8 storage after required controls succeed.
    pub fn try_from_capacity_with_protection<E>(
        capacity: usize,
        request: ProtectionRequest,
        fill: impl FnOnce(&mut [u8]) -> Result<usize, E>,
    ) -> Result<Self, ProtectedSecretTextFillError<E>> {
        super::LockedSecretString::try_from_capacity_bounded_with_protection(
            capacity, MAX, request, fill,
        )
        .map(|inner| Self { inner })
    }

    /// Fill an exact-length bounded locked UTF-8 value in place.
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

    /// Copy UTF-8 text after required controls are established.
    pub fn from_secret_str_with_protection(
        text: &str,
        request: ProtectionRequest,
    ) -> Result<Self, ProtectedSecretTextFillError<core::convert::Infallible>> {
        Self::try_from_capacity_with_protection(text.len(), request, |output| {
            output.copy_from_slice(text.as_bytes());
            Ok::<usize, core::convert::Infallible>(text.len())
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
    pub const fn backing_capacity(&self) -> usize {
        self.inner.capacity()
    }
    #[must_use]
    pub const fn locked_len(&self) -> usize {
        self.inner.locked_len()
    }
    /// Returns true when the mapping is locked against ordinary paging.
    #[must_use]
    pub const fn is_memory_locked(&self) -> bool {
        self.inner.is_memory_locked()
    }
    #[must_use]
    pub const fn protection_report(&self) -> &ProtectionReport {
        self.inner.protection_report()
    }
    #[must_use]
    pub const fn protection_request(&self) -> ProtectionRequest {
        self.inner.protection_request()
    }

    pub fn try_with_secret<R>(
        &self,
        inspect: impl FnOnce(&str) -> R,
    ) -> Result<R, SecretTextIntegrityError> {
        self.inner.try_with_secret(inspect)
    }

    pub fn try_with_secret_mut<R>(
        &mut self,
        edit: impl FnOnce(&mut str) -> R,
    ) -> Result<R, SecretTextIntegrityError> {
        self.inner.try_with_secret_mut(edit)
    }

    pub fn try_push_str(
        &mut self,
        text: &str,
    ) -> Result<(), BoundedMappedSecretError<MemoryLockError>> {
        // Verify before the public bound check so corruption cannot be masked
        // by a capacity error. The inner operation re-verifies at its boundary.
        self.verify_integrity()
            .map_err(BoundedMappedSecretError::Integrity)?;
        let _ = checked_extended_len!(self.len(), text.len(), MAX);
        self.inner.try_push_str(text).map_err(Into::into)
    }

    pub fn try_replace_from_secret_str(
        &mut self,
        text: &str,
    ) -> Result<(), BoundedMappedSecretError<MemoryLockError>> {
        self.verify_integrity()
            .map_err(BoundedMappedSecretError::Integrity)?;
        enforce_replacement_bound!(MAX, text.len());
        self.inner
            .try_replace_from_secret_str(text)
            .map_err(Into::into)
    }

    #[inline(never)]
    pub fn clear_secret(&mut self) {
        self.inner.clear_secret();
    }

    pub fn try_constant_time_eq(&self, other: &str) -> Result<bool, CanaryCorruptedError> {
        self.inner.try_constant_time_eq(other)
    }

    pub fn verify_integrity(&self) -> Result<(), CanaryCorruptedError> {
        self.inner.verify_integrity()
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
impl<const MAX: usize> SecureSanitize for BoundedLockedSecretString<MAX> {
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
impl<const MAX: usize> fmt::Debug for BoundedLockedSecretString<MAX> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BoundedLockedSecretString")
            .field("len", &self.len())
            .field("maximum", &MAX)
            .field("contents", &"<redacted>")
            .finish()
    }
}

/// Guarded UTF-8 text with a permanent type-level byte maximum.
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
pub struct BoundedGuardedSecretString<const MAX: usize> {
    inner: super::GuardedSecretString,
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
impl<const MAX: usize> BoundedGuardedSecretString<MAX> {
    #[must_use]
    pub const fn max_len() -> usize {
        MAX
    }

    /// Construct empty bounded UTF-8 storage after required controls succeed.
    pub fn try_with_capacity_with_protection(
        capacity: usize,
        request: ProtectionRequest,
    ) -> Result<Self, ProtectedSecretTextFillError<core::convert::Infallible>> {
        Self::try_from_capacity_with_protection(capacity, request, |_| {
            Ok::<usize, core::convert::Infallible>(0)
        })
    }

    /// Fill bounded guarded UTF-8 storage after required controls succeed.
    pub fn try_from_capacity_with_protection<E>(
        capacity: usize,
        request: ProtectionRequest,
        fill: impl FnOnce(&mut [u8]) -> Result<usize, E>,
    ) -> Result<Self, ProtectedSecretTextFillError<E>> {
        super::GuardedSecretString::try_from_capacity_bounded_with_protection(
            capacity, MAX, request, fill,
        )
        .map(|inner| Self { inner })
    }

    /// Fill an exact-length bounded guarded UTF-8 value in place.
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

    /// Copy UTF-8 text after required controls are established.
    pub fn from_secret_str_with_protection(
        text: &str,
        request: ProtectionRequest,
    ) -> Result<Self, ProtectedSecretTextFillError<core::convert::Infallible>> {
        Self::try_from_capacity_with_protection(text.len(), request, |output| {
            output.copy_from_slice(text.as_bytes());
            Ok::<usize, core::convert::Infallible>(text.len())
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
    pub const fn backing_capacity(&self) -> usize {
        self.inner.capacity()
    }
    #[must_use]
    pub const fn is_memory_locked(&self) -> bool {
        self.inner.is_memory_locked()
    }
    #[must_use]
    pub const fn protection_report(&self) -> &ProtectionReport {
        self.inner.protection_report()
    }
    #[must_use]
    pub const fn protection_request(&self) -> ProtectionRequest {
        self.inner.protection_request()
    }

    pub fn try_with_secret<R>(
        &self,
        inspect: impl FnOnce(&str) -> R,
    ) -> Result<R, SecretTextIntegrityError> {
        self.inner.try_with_secret(inspect)
    }

    pub fn try_with_secret_mut<R>(
        &mut self,
        edit: impl FnOnce(&mut str) -> R,
    ) -> Result<R, SecretTextIntegrityError> {
        self.inner.try_with_secret_mut(edit)
    }

    pub fn try_push_str(
        &mut self,
        text: &str,
    ) -> Result<(), BoundedMappedSecretError<GuardPageError>> {
        self.verify_integrity()
            .map_err(BoundedMappedSecretError::Integrity)?;
        let _ = checked_extended_len!(self.len(), text.len(), MAX);
        self.inner.try_push_str(text).map_err(Into::into)
    }

    pub fn try_replace_from_secret_str(
        &mut self,
        text: &str,
    ) -> Result<(), BoundedMappedSecretError<GuardPageError>> {
        self.verify_integrity()
            .map_err(BoundedMappedSecretError::Integrity)?;
        enforce_replacement_bound!(MAX, text.len());
        self.inner
            .try_replace_from_secret_str(text)
            .map_err(Into::into)
    }

    #[inline(never)]
    pub fn clear_secret(&mut self) {
        self.inner.clear_secret();
    }

    pub fn try_constant_time_eq(&self, other: &str) -> Result<bool, CanaryCorruptedError> {
        self.inner.try_constant_time_eq(other)
    }

    pub fn verify_integrity(&self) -> Result<(), CanaryCorruptedError> {
        self.inner.verify_integrity()
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
impl<const MAX: usize> SecureSanitize for BoundedGuardedSecretString<MAX> {
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
impl<const MAX: usize> fmt::Debug for BoundedGuardedSecretString<MAX> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BoundedGuardedSecretString")
            .field("len", &self.len())
            .field("maximum", &MAX)
            .field("contents", &"<redacted>")
            .finish()
    }
}
