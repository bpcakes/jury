//! Narrow fallible entropy seam consumed by Jury domain constructors.

pub use jury_protected::{EntropyError, OsRandom, RandomSource};

/// Fills caller-owned bytes or returns one value-free failure without a
/// fallback source or partial-success result.
pub fn fill_random(
    source: &mut impl RandomSource,
    destination: &mut [u8],
) -> Result<(), EntropyError> {
    source.fill(destination)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct PartialFailure;

    impl RandomSource for PartialFailure {
        fn fill(&mut self, destination: &mut [u8]) -> Result<(), EntropyError> {
            destination[..2].fill(0xa5);
            Err(EntropyError)
        }
    }

    #[test]
    fn injected_failure_is_value_free_and_never_reports_partial_success() {
        let mut destination = [0_u8; 32];
        let error = fill_random(&mut PartialFailure, &mut destination);
        assert_eq!(error, Err(EntropyError));
        assert_eq!(format!("{:?}", error.err()), "Some(EntropyError)");
    }
}
