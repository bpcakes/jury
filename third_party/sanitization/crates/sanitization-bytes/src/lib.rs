#![no_std]
#![deny(unsafe_code)]

//! `bytes` integration wrappers for `sanitization`.
//!
//! This crate deliberately uses wrapper types instead of trait impls for
//! external types. Rust's orphan rules prevent implementing
//! `sanitization::SecureSanitize` directly for `bytes::BytesMut` here.

use bytes::BytesMut;
use core::fmt;
use sanitization::{wipe, SecureSanitize};

#[cfg(test)]
extern crate std;

/// Error returned when an append would exceed the fixed buffer capacity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CapacityError {
    /// Current reported buffer capacity.
    pub capacity: usize,
    /// Current initialized length.
    pub len: usize,
    /// Additional bytes requested by the caller.
    pub additional: usize,
}

impl fmt::Display for CapacityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "insufficient secret buffer capacity: capacity {}, len {}, additional {}",
            self.capacity, self.len, self.additional
        )
    }
}

/// Clear-on-drop wrapper around [`BytesMut`].
///
/// Clearing expands the buffer to its reported capacity, volatile-clears that
/// initialized view, then resets the length to zero. This covers the owned
/// capacity exposed by `BytesMut`; it does not make claims about allocator
/// internals outside that buffer.
///
/// # Security
///
/// This wrapper treats capacity as fixed after construction. Appending beyond
/// capacity would force `BytesMut` to reallocate and free the old allocation
/// while it still contains secret bytes. [`SecretBytesMut::extend_from_slice`]
/// therefore returns [`CapacityError`] instead of growing implicitly. Allocate
/// the maximum expected size up front with [`SecretBytesMut::with_capacity`].
pub struct SecretBytesMut {
    inner: BytesMut,
}

impl SecretBytesMut {
    /// Create an empty secret byte buffer.
    #[must_use]
    #[inline]
    pub fn new() -> Self {
        Self {
            inner: BytesMut::new(),
        }
    }

    /// Allocate secret byte storage with at least `capacity` bytes.
    #[must_use]
    #[inline]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            inner: BytesMut::with_capacity(capacity),
        }
    }

    /// Copy a slice into a new secret byte buffer.
    #[must_use]
    #[inline]
    pub fn from_slice(bytes: &[u8]) -> Self {
        let mut inner = BytesMut::with_capacity(bytes.len());
        inner.extend_from_slice(bytes);
        Self { inner }
    }

    /// Wrap an existing [`BytesMut`].
    ///
    /// Historical bytes in the incoming buffer's current spare capacity are
    /// volatile-cleared immediately. Initialized bytes and their length remain
    /// unchanged.
    #[must_use]
    #[inline]
    pub fn from_bytes_mut(inner: BytesMut) -> Self {
        let mut inner = inner;
        let len = inner.len();
        let capacity = inner.capacity();
        inner.resize(capacity, 0);
        wipe::bytes(&mut inner[len..]);
        inner.truncate(len);
        Self { inner }
    }

    /// Number of initialized bytes.
    #[must_use]
    #[inline]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Returns true when there are no initialized bytes.
    #[must_use]
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Reported capacity of the underlying [`BytesMut`].
    #[must_use]
    #[inline]
    pub fn capacity(&self) -> usize {
        self.inner.capacity()
    }

    /// Append bytes to the secret buffer without reallocating.
    ///
    /// Returns [`CapacityError`] if the append would exceed the current
    /// capacity. This avoids leaving secret bytes in a freed old allocation
    /// after an implicit `BytesMut` growth.
    #[inline]
    pub fn extend_from_slice(&mut self, bytes: &[u8]) -> Result<(), CapacityError> {
        let remaining = self.inner.capacity().saturating_sub(self.inner.len());
        if bytes.len() > remaining {
            return Err(CapacityError {
                capacity: self.inner.capacity(),
                len: self.inner.len(),
                additional: bytes.len(),
            });
        }

        self.inner.extend_from_slice(bytes);
        Ok(())
    }

    /// Borrow initialized bytes.
    #[must_use]
    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        self.inner.as_ref()
    }

    /// Run a closure with read-only access to initialized bytes.
    #[inline]
    pub fn with_secret<R>(&self, inspect: impl FnOnce(&[u8]) -> R) -> R {
        inspect(self.as_slice())
    }

    /// Run a closure with mutable access to initialized bytes.
    #[inline]
    pub fn with_secret_mut<R>(&mut self, edit: impl FnOnce(&mut [u8]) -> R) -> R {
        edit(self.inner.as_mut())
    }

    /// Sanitize the reported capacity and clear the buffer.
    #[inline]
    pub fn clear_secret(&mut self) {
        let capacity = self.inner.capacity();
        self.inner.resize(capacity, 0);
        wipe::bytes(self.inner.as_mut());
        self.inner.clear();
    }

    /// Consume after first sanitizing all accessible capacity.
    #[inline]
    pub fn into_cleared(mut self) {
        self.clear_secret();
    }
}

impl Default for SecretBytesMut {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl SecureSanitize for SecretBytesMut {
    #[inline]
    fn secure_sanitize(&mut self) {
        self.clear_secret();
    }
}

impl Drop for SecretBytesMut {
    #[inline]
    fn drop(&mut self) {
        self.clear_secret();
    }
}

impl fmt::Debug for SecretBytesMut {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretBytesMut")
            .field("len", &self.len())
            .field("capacity", &self.capacity())
            .field("contents", &"<redacted>")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_mut_wrapper_round_trip_and_clear() {
        let mut secret = SecretBytesMut::with_capacity(8);

        secret.extend_from_slice(b"token").unwrap();
        secret.extend_from_slice(b"-v2").unwrap();

        assert_eq!(secret.len(), 8);
        assert_eq!(secret.with_secret(|bytes| bytes[0]), b't');

        secret.with_secret_mut(|bytes| bytes[0] = b'T');
        assert_eq!(secret.with_secret(|bytes| bytes[0]), b'T');

        secret.clear_secret();
        assert!(secret.is_empty());
    }

    #[test]
    fn bytes_mut_wrapper_refuses_growth_past_capacity() {
        let mut secret = SecretBytesMut::with_capacity(5);

        secret.extend_from_slice(b"token").unwrap();

        assert_eq!(
            secret.extend_from_slice(b"-v2"),
            Err(CapacityError {
                capacity: 5,
                len: 5,
                additional: 3,
            })
        );
        assert!(secret.with_secret(|bytes| bytes == b"token"));
    }

    #[test]
    fn bytes_mut_wrapper_debug_is_redacted() {
        let secret = SecretBytesMut::from_slice(b"token");
        let rendered = std::format!("{secret:?}");

        assert!(rendered.contains("redacted"));
        assert!(!rendered.contains("token"));
    }

    #[test]
    #[allow(unsafe_code)]
    fn wrapping_clears_spare_capacity_and_preserves_live_bytes() {
        let mut incoming = BytesMut::with_capacity(16);
        incoming.extend_from_slice(b"historical-data");
        incoming.truncate(5);
        let capacity = incoming.capacity();

        let mut wrapped = SecretBytesMut::from_bytes_mut(incoming);

        assert_eq!(wrapped.as_slice(), b"histo");
        assert_eq!(wrapped.capacity(), capacity);

        let live_len = wrapped.len();
        // SAFETY: `from_bytes_mut` initializes every byte through `resize`
        // before truncating back to `live_len`, and `capacity` is the exact
        // initialized bound established by that operation.
        unsafe { wrapped.inner.set_len(capacity) };
        assert!(wrapped.inner[live_len..].iter().all(|byte| *byte == 0));
        // SAFETY: `live_len` was the valid initialized length on entry and is
        // no greater than the current length.
        unsafe { wrapped.inner.set_len(live_len) };
    }
}
