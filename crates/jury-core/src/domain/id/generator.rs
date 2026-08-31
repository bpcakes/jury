use std::fmt;

use crate::entropy::{EntropyError, OsRandom, RandomSource};

use super::{GeneratedIdentifier, IDENTIFIER_BYTES, ItemId, PrincipalId, VaultId};

/// Maximum number of full-width draws made while rejecting the zero sentinel.
pub const IDENTIFIER_ZERO_RETRY_ATTEMPTS: usize = 8;

/// Maximum number of generated candidates offered to a state-owner collision check.
pub const IDENTIFIER_COLLISION_RETRY_ATTEMPTS: usize = 8;

/// Value-free failure to generate a native identifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentifierGenerationError {
    /// The operating-system cryptographic random source failed.
    EntropyUnavailable,
    /// Every permitted full-width draw produced the reserved zero value.
    RetryExhausted,
}

impl fmt::Display for IdentifierGenerationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EntropyUnavailable => {
                formatter.write_str("operating-system entropy was unavailable")
            }
            Self::RetryExhausted => {
                formatter.write_str("native identifier generation exhausted its retry bound")
            }
        }
    }
}

impl std::error::Error for IdentifierGenerationError {}

impl From<EntropyError> for IdentifierGenerationError {
    fn from(_: EntropyError) -> Self {
        Self::EntropyUnavailable
    }
}

/// Shared generator for every Jury-native opaque identifier.
///
/// Ordinary callers can construct only the operating-system-backed form.
/// Domain-owner unit tests may inject the fallible J02 randomness seam without
/// exposing caller-selected identifiers in product APIs.
pub struct NativeIdGenerator<R = OsRandom> {
    source: R,
}

impl NativeIdGenerator<OsRandom> {
    /// Creates a generator backed by the operating-system CSPRNG.
    #[must_use]
    pub const fn new() -> Self {
        Self { source: OsRandom }
    }
}

impl Default for NativeIdGenerator<OsRandom> {
    fn default() -> Self {
        Self::new()
    }
}

impl<R: RandomSource> NativeIdGenerator<R> {
    #[cfg(test)]
    pub(crate) fn from_source(source: R) -> Self {
        Self { source }
    }

    /// Generates an independent nonzero vault identifier not known to the
    /// state owner.
    ///
    /// `identifier_is_known` must check every source and destination lineage
    /// visible to the operation. There is no global registry, so this does not
    /// claim worldwide uniqueness.
    pub fn generate_vault_id(
        &mut self,
        identifier_is_known: impl FnMut(&VaultId) -> bool,
    ) -> Result<VaultId, IdentifierGenerationError> {
        generate_identifier(&mut self.source, identifier_is_known)
    }

    /// Generates an independent nonzero principal identifier not present in
    /// the complete known lineage, including tombstones.
    pub fn generate_principal_id(
        &mut self,
        identifier_is_known: impl FnMut(&PrincipalId) -> bool,
    ) -> Result<PrincipalId, IdentifierGenerationError> {
        generate_identifier(&mut self.source, identifier_is_known)
    }

    /// Generates an independent nonzero item identifier not present in the
    /// complete known lineage, including tombstones.
    pub fn generate_item_id(
        &mut self,
        identifier_is_known: impl FnMut(&ItemId) -> bool,
    ) -> Result<ItemId, IdentifierGenerationError> {
        generate_identifier(&mut self.source, identifier_is_known)
    }
}

fn generate_identifier<I: GeneratedIdentifier>(
    source: &mut impl RandomSource,
    mut identifier_is_known: impl FnMut(&I) -> bool,
) -> Result<I, IdentifierGenerationError> {
    for _ in 0..IDENTIFIER_COLLISION_RETRY_ATTEMPTS {
        let candidate = generate_nonzero_identifier(source)?;
        if !identifier_is_known(&candidate) {
            return Ok(candidate);
        }
    }

    Err(IdentifierGenerationError::RetryExhausted)
}

fn generate_nonzero_identifier<I: GeneratedIdentifier>(
    source: &mut impl RandomSource,
) -> Result<I, IdentifierGenerationError> {
    for _ in 0..IDENTIFIER_ZERO_RETRY_ATTEMPTS {
        let mut bytes = [0_u8; IDENTIFIER_BYTES];
        source.fill(&mut bytes)?;
        if bytes.iter().any(|byte| *byte != 0) {
            return Ok(I::from_nonzero_bytes(bytes));
        }
    }

    Err(IdentifierGenerationError::RetryExhausted)
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use super::*;

    enum Draw {
        Bytes([u8; IDENTIFIER_BYTES]),
        PartialFailure,
    }

    struct ScriptedRandom {
        draws: VecDeque<Draw>,
        calls: usize,
    }

    impl ScriptedRandom {
        fn new(draws: impl IntoIterator<Item = Draw>) -> Self {
            Self {
                draws: draws.into_iter().collect(),
                calls: 0,
            }
        }
    }

    impl RandomSource for ScriptedRandom {
        fn fill(&mut self, destination: &mut [u8]) -> Result<(), EntropyError> {
            assert_eq!(destination.len(), IDENTIFIER_BYTES);
            self.calls += 1;
            let draw = self.draws.pop_front();
            assert!(draw.is_some(), "unexpected entropy request");
            match draw {
                Some(Draw::Bytes(bytes)) => {
                    destination.copy_from_slice(&bytes);
                    Ok(())
                }
                Some(Draw::PartialFailure) => {
                    destination[..3].fill(0xa5);
                    Err(EntropyError)
                }
                None => Err(EntropyError),
            }
        }
    }

    #[test]
    fn one_generator_creates_every_native_identifier_type() {
        let source = ScriptedRandom::new([
            Draw::Bytes([0x11; IDENTIFIER_BYTES]),
            Draw::Bytes([0x22; IDENTIFIER_BYTES]),
            Draw::Bytes([0x33; IDENTIFIER_BYTES]),
        ]);
        let mut generator = NativeIdGenerator::from_source(source);

        let vault = generator.generate_vault_id(|_| false);
        let principal = generator.generate_principal_id(|_| false);
        let item = generator.generate_item_id(|_| false);

        assert!(matches!(vault, Ok(id) if id.as_bytes() == &[0x11; IDENTIFIER_BYTES]));
        assert!(matches!(principal, Ok(id) if id.as_bytes() == &[0x22; IDENTIFIER_BYTES]));
        assert!(matches!(item, Ok(id) if id.as_bytes() == &[0x33; IDENTIFIER_BYTES]));
        assert_eq!(generator.source.calls, 3);
    }

    #[test]
    fn zero_draws_are_resampled_through_the_exact_bound() {
        let mut draws = (0..IDENTIFIER_ZERO_RETRY_ATTEMPTS - 1)
            .map(|_| Draw::Bytes([0; IDENTIFIER_BYTES]))
            .collect::<Vec<_>>();
        draws.push(Draw::Bytes([0x5a; IDENTIFIER_BYTES]));
        let mut generator = NativeIdGenerator::from_source(ScriptedRandom::new(draws));

        let generated = generator.generate_item_id(|_| false);

        assert!(matches!(generated, Ok(id) if id.as_bytes() == &[0x5a; IDENTIFIER_BYTES]));
        assert_eq!(generator.source.calls, IDENTIFIER_ZERO_RETRY_ATTEMPTS);
    }

    #[test]
    fn eight_zero_draws_return_only_retry_exhaustion() {
        let draws = (0..IDENTIFIER_ZERO_RETRY_ATTEMPTS).map(|_| Draw::Bytes([0; IDENTIFIER_BYTES]));
        let mut generator = NativeIdGenerator::from_source(ScriptedRandom::new(draws));

        let generated = generator.generate_vault_id(|_| false);

        assert_eq!(generated, Err(IdentifierGenerationError::RetryExhausted));
        assert_eq!(generator.source.calls, IDENTIFIER_ZERO_RETRY_ATTEMPTS);
        assert_eq!(format!("{:?}", generated.err()), "Some(RetryExhausted)");
    }

    #[test]
    fn known_lineage_collision_is_resampled_before_return() {
        let source = ScriptedRandom::new([
            Draw::Bytes([0x44; IDENTIFIER_BYTES]),
            Draw::Bytes([0x55; IDENTIFIER_BYTES]),
        ]);
        let mut generator = NativeIdGenerator::from_source(source);

        let generated = generator.generate_principal_id(|id| id.as_bytes() == &[0x44; 32]);

        assert!(matches!(generated, Ok(id) if id.as_bytes() == &[0x55; IDENTIFIER_BYTES]));
        assert_eq!(generator.source.calls, 2);
    }

    #[test]
    fn known_lineage_collision_retries_are_bounded() {
        let draws = (1..=IDENTIFIER_COLLISION_RETRY_ATTEMPTS)
            .map(|byte| Draw::Bytes([u8::try_from(byte).unwrap_or(0xff); IDENTIFIER_BYTES]));
        let mut generator = NativeIdGenerator::from_source(ScriptedRandom::new(draws));

        let generated = generator.generate_item_id(|_| true);

        assert_eq!(generated, Err(IdentifierGenerationError::RetryExhausted));
        assert_eq!(generator.source.calls, IDENTIFIER_COLLISION_RETRY_ATTEMPTS);
    }

    #[test]
    fn entropy_failure_returns_no_identifier_for_every_native_type() {
        let mut vault = NativeIdGenerator::from_source(ScriptedRandom::new([Draw::PartialFailure]));
        let mut principal =
            NativeIdGenerator::from_source(ScriptedRandom::new([Draw::PartialFailure]));
        let mut item = NativeIdGenerator::from_source(ScriptedRandom::new([Draw::PartialFailure]));

        assert_eq!(
            vault.generate_vault_id(|_| false),
            Err(IdentifierGenerationError::EntropyUnavailable)
        );
        assert_eq!(
            principal.generate_principal_id(|_| false),
            Err(IdentifierGenerationError::EntropyUnavailable)
        );
        assert_eq!(
            item.generate_item_id(|_| false),
            Err(IdentifierGenerationError::EntropyUnavailable)
        );
        assert_eq!(vault.source.calls, 1);
        assert_eq!(principal.source.calls, 1);
        assert_eq!(item.source.calls, 1);
    }
}
