use std::fmt;

use crate::{MemoryError, ProtectedMemory, ProtectionPolicy};

/// Value-free entropy failure. Partial destination contents are never returned.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EntropyError;

impl fmt::Display for EntropyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("operating-system entropy was unavailable")
    }
}

impl std::error::Error for EntropyError {}

/// Fallible entropy source which fills caller-owned storage.
pub trait RandomSource {
    fn fill(&mut self, destination: &mut [u8]) -> Result<(), EntropyError>;
}

impl<T: RandomSource + ?Sized> RandomSource for &mut T {
    fn fill(&mut self, destination: &mut [u8]) -> Result<(), EntropyError> {
        (**self).fill(destination)
    }
}

/// Operating-system CSPRNG with no fallback source.
#[derive(Clone, Copy, Debug, Default)]
pub struct OsRandom;

impl RandomSource for OsRandom {
    fn fill(&mut self, destination: &mut [u8]) -> Result<(), EntropyError> {
        getrandom::fill(destination).map_err(|_| EntropyError)
    }
}

/// Allocates protected memory first, then fills it directly from `source`.
///
/// Any entropy failure causes the provider to wipe and unmap the partially
/// initialized owner before a value-free error is returned.
pub fn protected_random(
    len: usize,
    policy: ProtectionPolicy,
    source: &mut impl RandomSource,
) -> Result<ProtectedMemory, ProtectedRandomError> {
    ProtectedMemory::initialize(len, policy, |destination| {
        source.fill(destination)?;
        Ok::<usize, EntropyError>(destination.len())
    })
    .map_err(|error| match error.kind() {
        crate::MemoryErrorKind::Initializer => ProtectedRandomError::Entropy(EntropyError),
        _ => ProtectedRandomError::Memory(error),
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtectedRandomError {
    Memory(MemoryError),
    Entropy(EntropyError),
}

impl fmt::Display for ProtectedRandomError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Memory(error) => error.fmt(formatter),
            Self::Entropy(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for ProtectedRandomError {}

#[cfg(test)]
mod tests {
    use super::*;

    struct PartialFailure;

    impl RandomSource for PartialFailure {
        fn fill(&mut self, destination: &mut [u8]) -> Result<(), EntropyError> {
            let partial = destination.len().min(3);
            destination[..partial].fill(0xa5);
            Err(EntropyError)
        }
    }

    #[test]
    fn partial_entropy_failure_returns_no_memory_or_bytes() {
        if !crate::test_support::in_subprocess(concat!(
            module_path!(),
            "::partial_entropy_failure_returns_no_memory_or_bytes"
        )) {
            return;
        }

        let result = protected_random(32, ProtectionPolicy::Strict, &mut PartialFailure);
        assert!(matches!(
            result.as_ref(),
            Err(ProtectedRandomError::Entropy(EntropyError))
        ));
        assert_eq!(format!("{:?}", result.err()), "Some(Entropy(EntropyError))");
    }

    #[test]
    fn caller_supplied_source_fills_the_protected_mapping() -> Result<(), Box<dyn std::error::Error>>
    {
        if !crate::test_support::in_subprocess(concat!(
            module_path!(),
            "::caller_supplied_source_fills_the_protected_mapping"
        )) {
            return Ok(());
        }

        struct Fixed;
        impl RandomSource for Fixed {
            fn fill(&mut self, destination: &mut [u8]) -> Result<(), EntropyError> {
                destination.fill(0x5a);
                Ok(())
            }
        }

        let memory = protected_random(7, ProtectionPolicy::Strict, &mut Fixed)?;
        assert!(memory.expose(|bytes| bytes == [0x5a; 7])?);
        Ok(())
    }
}
