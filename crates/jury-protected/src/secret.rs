use std::fmt;

use zeroize::{Zeroize, Zeroizing};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SecretBytesCapacityError;

impl fmt::Display for SecretBytesCapacityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("secret byte extension would reallocate")
    }
}

impl std::error::Error for SecretBytesCapacityError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SecretBytesAllocationError;

impl fmt::Display for SecretBytesAllocationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("secret byte allocation failed")
    }
}

impl std::error::Error for SecretBytesAllocationError {}

pub struct SecretBytes {
    value: Zeroizing<Vec<u8>>,
}

impl SecretBytes {
    pub fn new(value: Vec<u8>) -> Self {
        Self {
            value: Zeroizing::new(value),
        }
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self::new(Vec::with_capacity(capacity))
    }

    /// Allocates one fixed-length zeroed sensitive buffer without a panic on
    /// recoverable allocator exhaustion.
    pub fn try_zeroed(length: usize) -> Result<Self, SecretBytesAllocationError> {
        let mut value = Vec::new();
        value
            .try_reserve_exact(length)
            .map_err(|_| SecretBytesAllocationError)?;
        value.resize(length, 0);
        Ok(Self::new(value))
    }

    pub fn len(&self) -> usize {
        self.value.len()
    }

    pub fn is_empty(&self) -> bool {
        self.value.is_empty()
    }

    pub fn as_slice(&self) -> &[u8] {
        self.value.as_slice()
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        self.value.as_mut_slice()
    }

    /// Appends bytes without allowing the backing allocation to grow.
    ///
    /// # Errors
    ///
    /// Returns [`SecretBytesCapacityError`] when the new length overflows or
    /// exceeds the existing allocation capacity.
    pub fn extend_from_slice(&mut self, bytes: &[u8]) -> Result<(), SecretBytesCapacityError> {
        let Some(new_len) = self.len().checked_add(bytes.len()) else {
            return Err(SecretBytesCapacityError);
        };
        if new_len > self.value.capacity() {
            return Err(SecretBytesCapacityError);
        }
        self.value.extend_from_slice(bytes);
        Ok(())
    }

    /// Removes bytes beyond `len`, overwriting the removed region first.
    ///
    /// This never changes the allocation capacity, so a protected editor can
    /// delete and subsequently append without reallocating secret material.
    pub fn truncate(&mut self, len: usize) {
        if len >= self.len() {
            return;
        }
        self.value[len..].zeroize();
        self.value.truncate(len);
    }

    /// Overwrites and removes every byte while retaining the allocation.
    pub fn clear(&mut self) {
        self.value.zeroize();
    }
}

impl AsRef<[u8]> for SecretBytes {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretBytes")
            .field("len", &self.len())
            .field("value", &"[REDACTED]")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::SecretBytes;

    #[test]
    fn fallible_zeroed_allocation_has_fixed_mutable_length()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut bytes = SecretBytes::try_zeroed(32)?;
        assert_eq!(bytes.len(), 32);
        assert!(bytes.as_slice().iter().all(|byte| *byte == 0));
        bytes.as_mut_slice()[31] = 0xa5;
        assert_eq!(bytes.as_slice()[31], 0xa5);
        Ok(())
    }

    #[test]
    fn truncate_and_clear_retain_the_preallocated_capacity()
    -> Result<(), super::SecretBytesCapacityError> {
        let mut bytes = SecretBytes::with_capacity(32);
        bytes.extend_from_slice(b"sensitive")?;
        bytes.truncate(4);
        assert_eq!(bytes.as_slice(), b"sens");
        bytes.clear();
        assert!(bytes.is_empty());
        bytes.extend_from_slice(b"replacement")?;
        assert_eq!(bytes.as_slice(), b"replacement");
        Ok(())
    }

    #[test]
    fn extension_refuses_allocation_growth_without_changing_contents()
    -> Result<(), super::SecretBytesCapacityError> {
        let mut bytes = SecretBytes::with_capacity(4);
        bytes.extend_from_slice(b"safe")?;
        assert_eq!(
            bytes.extend_from_slice(b"growth"),
            Err(super::SecretBytesCapacityError)
        );
        assert_eq!(bytes.as_slice(), b"safe");
        Ok(())
    }
}
