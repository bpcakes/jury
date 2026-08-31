use std::collections::BTreeSet;

use jury_protected::RandomSource;
use jury_protocol::vault_v1::{Nonce12, RevisionSealId, SlotId};

use super::{ItemError, ItemErrorKind};

const RETRY_ATTEMPTS: usize = 8;

pub(super) fn draw_seal_id(
    source: &mut impl RandomSource,
    known: &mut BTreeSet<RevisionSealId>,
) -> Result<RevisionSealId, ItemError> {
    draw_unique_id(source, known, RevisionSealId::from_bytes)
}

pub(super) fn draw_slot_id(
    source: &mut impl RandomSource,
    known: &mut BTreeSet<SlotId>,
) -> Result<SlotId, ItemError> {
    draw_unique_id(source, known, SlotId::from_bytes)
}

fn draw_unique_id<T: Copy + Ord>(
    source: &mut impl RandomSource,
    known: &mut BTreeSet<T>,
    construct: impl Fn([u8; 32]) -> Result<T, jury_protocol::vault_v1::ByteStringError>,
) -> Result<T, ItemError> {
    for _ in 0..RETRY_ATTEMPTS {
        let mut bytes = [0; 32];
        source
            .fill(&mut bytes)
            .map_err(|_| ItemError::new(ItemErrorKind::EntropyUnavailable))?;
        if let Ok(candidate) = construct(bytes)
            && known.insert(candidate)
        {
            return Ok(candidate);
        }
    }
    Err(ItemError::new(ItemErrorKind::RetryExhausted))
}

pub(super) fn draw_nonce(
    source: &mut impl RandomSource,
    known: &mut BTreeSet<Nonce12>,
) -> Result<Nonce12, ItemError> {
    for _ in 0..RETRY_ATTEMPTS {
        let mut bytes = [0; 12];
        source
            .fill(&mut bytes)
            .map_err(|_| ItemError::new(ItemErrorKind::EntropyUnavailable))?;
        let nonce = Nonce12::new(bytes);
        if known.insert(nonce.clone()) {
            return Ok(nonce);
        }
    }
    Err(ItemError::new(ItemErrorKind::RetryExhausted))
}
