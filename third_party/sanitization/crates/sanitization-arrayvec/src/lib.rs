#![no_std]
#![deny(unsafe_code)]
#![deny(unsafe_op_in_unsafe_fn)]

//! `arrayvec` integration wrappers for `sanitization`.
//!
//! This crate deliberately uses wrapper types instead of trait impls for
//! external types. Rust's orphan rules prevent implementing
//! `sanitization::SecureSanitize` directly for `arrayvec::ArrayVec` here.

use arrayvec::{ArrayVec, CapacityError};
use core::fmt;
use sanitization::SecureSanitize;

#[cfg(test)]
extern crate std;

mod backing_wipe {
    use arrayvec::ArrayVec;

    pub(super) fn wipe_spare<T, const CAP: usize>(inner: &mut ArrayVec<T, CAP>) {
        let spare = inner.spare_capacity_mut();
        sanitization::wipe::maybe_uninit(spare);
    }

    #[cfg(test)]
    #[allow(unsafe_code)]
    pub(super) unsafe fn spare_is_zero_after_wipe<T, const CAP: usize>(
        inner: &mut ArrayVec<T, CAP>,
    ) -> bool {
        let spare = inner.spare_capacity_mut();
        let byte_len = core::mem::size_of_val(spare);
        if byte_len == 0 {
            return true;
        }

        // SAFETY: The caller guarantees every spare byte was initialized by
        // `wipe_spare` after the most recent operation that changed the live
        // range. Reading those initialized bytes as `u8` is valid.
        let bytes = unsafe { core::slice::from_raw_parts(spare.as_ptr().cast::<u8>(), byte_len) };
        bytes.iter().all(|byte| *byte == 0)
    }
}

/// Error returned when [`SecretArrayVec::push_or_sanitize`] rejects and clears
/// an element because the vector is full.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SanitizedCapacityError;

impl fmt::Display for SanitizedCapacityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("secret array vector is full; rejected element was sanitized")
    }
}

impl core::error::Error for SanitizedCapacityError {}

/// Clear-on-drop wrapper around [`ArrayVec`].
///
/// Live elements are sanitized and dropped before the complete resulting
/// `MaybeUninit<T>` spare region is volatile-cleared. This covers inline bytes
/// left by earlier push, pop, truncate, clear, reuse, or wrapping operations
/// without raw-zeroing a live `T`.
pub struct SecretArrayVec<T: SecureSanitize, const CAP: usize> {
    inner: ArrayVec<T, CAP>,
}

impl<T: SecureSanitize, const CAP: usize> SecretArrayVec<T, CAP> {
    /// Create an empty secret array vector.
    #[must_use]
    #[inline]
    pub const fn new() -> Self {
        Self {
            inner: ArrayVec::new_const(),
        }
    }

    /// Wrap an existing [`ArrayVec`].
    ///
    /// Historical bytes in the incoming vector's current spare capacity are
    /// cleared immediately. Live elements remain unchanged.
    #[must_use]
    #[inline]
    pub fn from_arrayvec(inner: ArrayVec<T, CAP>) -> Self {
        let mut secret = Self { inner };
        secret.wipe_spare();
        secret
    }

    /// Number of initialized elements.
    #[must_use]
    #[inline]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Maximum number of elements.
    #[must_use]
    #[inline]
    pub const fn capacity(&self) -> usize {
        CAP
    }

    /// Returns true when there are no initialized elements.
    #[must_use]
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Push one sanitizable element.
    ///
    /// If the vector is full, [`CapacityError`] returns the original element
    /// unchanged, matching `arrayvec` semantics. Callers remain responsible for
    /// sanitizing or securely reusing that rejected value. Use
    /// [`SecretArrayVec::push_or_sanitize`] when rejection must consume and
    /// clear the element instead.
    #[inline]
    pub fn push(&mut self, value: T) -> Result<(), CapacityError<T>> {
        self.inner.try_push(value)
    }

    /// Push an element, consuming and sanitizing it if the vector is full.
    ///
    /// The error intentionally carries no `T`, preventing callers from
    /// mistaking a sanitized value for the original secret.
    #[inline]
    pub fn push_or_sanitize(&mut self, value: T) -> Result<(), SanitizedCapacityError> {
        match self.inner.try_push(value) {
            Ok(()) => Ok(()),
            Err(error) => {
                let mut rejected = error.element();
                rejected.secure_sanitize();
                Err(SanitizedCapacityError)
            }
        }
    }

    /// Remove and return the last element.
    ///
    /// The returned value remains secret-bearing and is the caller's
    /// responsibility. The stale inline slot left by the move is
    /// volatile-cleared before this method returns.
    #[inline]
    pub fn pop(&mut self) -> Option<T> {
        let value = self.inner.pop();
        self.wipe_spare();
        value
    }

    /// Shorten the vector to `new_len`.
    ///
    /// Removed elements are sanitized before their destructors run. The
    /// complete spare region, including historical bytes from earlier
    /// operations, is then volatile-cleared.
    #[inline]
    pub fn truncate(&mut self, new_len: usize) {
        let len = self.inner.len();
        if new_len < len {
            self.inner.as_mut_slice()[new_len..].secure_sanitize();
            self.inner.truncate(new_len);
        }
        self.wipe_spare();
    }

    /// Borrow initialized elements.
    #[must_use]
    #[inline]
    pub fn as_slice(&self) -> &[T] {
        self.inner.as_slice()
    }

    /// Mutably borrow initialized elements.
    #[must_use]
    #[inline]
    pub fn as_mut_slice(&mut self) -> &mut [T] {
        self.inner.as_mut_slice()
    }

    /// Run a closure with read-only access to initialized elements.
    #[inline]
    pub fn with_secret<R>(&self, inspect: impl FnOnce(&[T]) -> R) -> R {
        inspect(self.as_slice())
    }

    /// Run a closure with mutable access to initialized elements.
    #[inline]
    pub fn with_secret_mut<R>(&mut self, edit: impl FnOnce(&mut [T]) -> R) -> R {
        edit(self.as_mut_slice())
    }

    /// Sanitize and drop all live elements, then clear all inline backing bytes.
    #[inline]
    pub fn clear_secret(&mut self) {
        self.inner.as_mut_slice().secure_sanitize();
        self.inner.clear();
        self.wipe_spare();
    }

    /// Consume after first sanitizing all live elements.
    #[inline]
    pub fn into_cleared(mut self) {
        self.clear_secret();
    }

    #[inline]
    fn wipe_spare(&mut self) {
        backing_wipe::wipe_spare(&mut self.inner);
    }
}

impl<T: SecureSanitize, const CAP: usize> Default for SecretArrayVec<T, CAP> {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl<T: SecureSanitize, const CAP: usize> SecureSanitize for SecretArrayVec<T, CAP> {
    #[inline]
    fn secure_sanitize(&mut self) {
        self.clear_secret();
    }
}

impl<T: SecureSanitize, const CAP: usize> Drop for SecretArrayVec<T, CAP> {
    #[inline]
    fn drop(&mut self) {
        self.clear_secret();
    }
}

impl<T: SecureSanitize, const CAP: usize> fmt::Debug for SecretArrayVec<T, CAP> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretArrayVec")
            .field("len", &self.len())
            .field("capacity", &CAP)
            .field("contents", &"<redacted>")
            .finish()
    }
}

#[cfg(test)]
#[allow(unsafe_code)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use sanitization::SecretBytes;
    use std::sync::Arc;

    fn assert_backing_is_zero<T: SecureSanitize, const CAP: usize>(
        secrets: &mut SecretArrayVec<T, CAP>,
    ) {
        // SAFETY: Tests call this only immediately after a wrapper operation
        // that invokes `wipe_spare`, which initializes every byte in the
        // current spare region to zero.
        assert!(unsafe { backing_wipe::spare_is_zero_after_wipe(&mut secrets.inner) });
    }

    #[test]
    fn empty_arrayvec_wipes_never_initialized_spare() {
        let mut secrets = SecretArrayVec::<u8, 1>::new();

        secrets.clear_secret();

        assert_backing_is_zero(&mut secrets);
    }

    #[test]
    fn arrayvec_wrapper_clears_live_elements() {
        let mut secrets = SecretArrayVec::<SecretBytes<4>, 2>::new();

        secrets.push(SecretBytes::from_array([1, 2, 3, 4])).unwrap();
        secrets.push(SecretBytes::from_array([5, 6, 7, 8])).unwrap();

        assert_eq!(secrets.len(), 2);
        assert!(secrets.with_secret(|items| items[0].constant_time_eq(&[1, 2, 3, 4])));

        secrets.clear_secret();

        assert!(secrets.is_empty());
        assert_backing_is_zero(&mut secrets);
    }

    #[test]
    fn arrayvec_wrapper_debug_is_redacted() {
        let mut secrets = SecretArrayVec::<SecretBytes<4>, 2>::new();
        secrets.push(SecretBytes::from_array([1, 2, 3, 4])).unwrap();

        let rendered = std::format!("{secrets:?}");

        assert!(rendered.contains("redacted"));
        assert!(!rendered.contains("1, 2, 3, 4"));
    }

    #[test]
    fn arrayvec_wrapper_push_returns_original_rejected_element() {
        let mut secrets = SecretArrayVec::<[u8; 4], 0>::new();

        let error = secrets.push([1, 2, 3, 4]).unwrap_err();

        assert_eq!(error.element(), [1, 2, 3, 4]);
    }

    #[test]
    fn arrayvec_wrapper_can_sanitize_rejected_elements() {
        struct Probe(Arc<AtomicBool>);

        impl SecureSanitize for Probe {
            fn secure_sanitize(&mut self) {
                self.0.store(true, Ordering::Release);
            }
        }

        let sanitized = Arc::new(AtomicBool::new(false));
        let mut secrets = SecretArrayVec::<Probe, 0>::new();

        assert_eq!(
            secrets.push_or_sanitize(Probe(Arc::clone(&sanitized))),
            Err(SanitizedCapacityError)
        );
        assert!(sanitized.load(Ordering::Acquire));
    }

    #[test]
    fn arrayvec_wrapper_pop_clears_the_historical_slot() {
        let mut secrets = SecretArrayVec::<[u8; 4], 2>::new();
        secrets.push([0xA5; 4]).unwrap();

        let mut removed = secrets.pop().unwrap();

        assert_eq!(removed, [0xA5; 4]);
        assert!(secrets.is_empty());
        assert_backing_is_zero(&mut secrets);
        removed.secure_sanitize();
    }

    #[test]
    fn arrayvec_wrapper_truncate_sanitizes_before_drop_and_wipes_spare() {
        struct Probe {
            bytes: [u8; 4],
            sanitized: Arc<AtomicBool>,
            dropped_zeroed: Arc<AtomicBool>,
        }

        impl SecureSanitize for Probe {
            fn secure_sanitize(&mut self) {
                self.bytes.secure_sanitize();
                self.sanitized.store(true, Ordering::Release);
            }
        }

        impl Drop for Probe {
            fn drop(&mut self) {
                self.dropped_zeroed
                    .store(self.bytes == [0; 4], Ordering::Release);
            }
        }

        let sanitized = Arc::new(AtomicBool::new(false));
        let dropped_zeroed = Arc::new(AtomicBool::new(false));
        let mut secrets = SecretArrayVec::<Probe, 2>::new();
        secrets
            .push(Probe {
                bytes: [9; 4],
                sanitized: Arc::clone(&sanitized),
                dropped_zeroed: Arc::clone(&dropped_zeroed),
            })
            .unwrap();

        secrets.truncate(0);

        assert!(sanitized.load(Ordering::Acquire));
        assert!(dropped_zeroed.load(Ordering::Acquire));
        assert_backing_is_zero(&mut secrets);
    }

    #[test]
    fn arrayvec_wrapper_clears_historical_spare_when_wrapping() {
        let mut inner = ArrayVec::<[u8; 4], 2>::new();
        inner.push([0xC3; 4]);
        let mut removed = inner.pop().unwrap();

        let mut secrets = SecretArrayVec::from_arrayvec(inner);

        assert_backing_is_zero(&mut secrets);
        removed.secure_sanitize();
    }

    #[test]
    fn arrayvec_wrapper_clears_complete_backing_after_reuse() {
        let mut secrets = SecretArrayVec::<[u8; 4], 3>::new();
        secrets.push([1; 4]).unwrap();
        secrets.push([2; 4]).unwrap();
        let mut removed = secrets.pop().unwrap();
        secrets.push([3; 4]).unwrap();

        secrets.clear_secret();

        assert!(secrets.is_empty());
        assert_backing_is_zero(&mut secrets);
        removed.secure_sanitize();
    }

    #[test]
    fn arrayvec_wrapper_handles_zero_sized_drop_types() {
        struct ZeroSized;

        static SANITIZED: AtomicUsize = AtomicUsize::new(0);
        static DROPPED: AtomicUsize = AtomicUsize::new(0);

        impl SecureSanitize for ZeroSized {
            fn secure_sanitize(&mut self) {
                SANITIZED.fetch_add(1, Ordering::SeqCst);
            }
        }

        impl Drop for ZeroSized {
            fn drop(&mut self) {
                DROPPED.fetch_add(1, Ordering::SeqCst);
            }
        }

        SANITIZED.store(0, Ordering::SeqCst);
        DROPPED.store(0, Ordering::SeqCst);
        let mut secrets = SecretArrayVec::<ZeroSized, 4>::new();
        secrets.push(ZeroSized).unwrap();
        secrets.push(ZeroSized).unwrap();

        secrets.clear_secret();

        assert_eq!(SANITIZED.load(Ordering::SeqCst), 2);
        assert_eq!(DROPPED.load(Ordering::SeqCst), 2);
        assert_backing_is_zero(&mut secrets);
    }
}
