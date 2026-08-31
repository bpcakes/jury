use jury_protocol::vault_v1::{
    Digest32, FixedBytes, ItemDescriptorV1, ItemEnvelopeV1, ItemStateV1, PrincipalId,
    VerificationPublicKey32, item_body_aad, item_descriptor_aad,
};
use sha2::{Digest as _, Sha256};

use crate::crypto;
use crate::identity::ProtectedRevisionSecret;

use super::{ItemError, ItemErrorKind, map_crypto_error};

const ZERO_DIGEST: [u8; 32] = [0; 32];

pub(crate) fn open_descriptor(
    envelope: &ItemEnvelopeV1,
    secret: &ProtectedRevisionSecret,
) -> Result<ItemDescriptorV1, ItemError> {
    if sha256(envelope.descriptor_ciphertext.as_bytes()) != envelope.descriptor.ciphertext_digest {
        return Err(ItemError::new(ItemErrorKind::InvalidAncestry));
    }
    let aad = item_descriptor_aad(
        envelope.current_revision.vault_id.as_bytes(),
        envelope.item_id.as_bytes(),
        envelope.descriptor.key_epoch,
        envelope.descriptor.revision,
        envelope.descriptor.revision_seal_id.as_bytes(),
    );
    let plaintext = crypto::open(
        secret.memory(),
        &envelope.descriptor.nonce,
        &aad,
        envelope.descriptor_ciphertext.as_bytes(),
        256,
    )
    .map_err(map_crypto_error)?;
    plaintext
        .expose(ItemDescriptorV1::decode)
        .map_err(|_| ItemError::new(ItemErrorKind::ProtectionUnavailable))?
        .map_err(|_| ItemError::new(ItemErrorKind::InvalidInput))
}

pub(crate) fn open_body(
    envelope: &ItemEnvelopeV1,
    secret: &ProtectedRevisionSecret,
) -> Result<ItemStateV1, ItemError> {
    let revision = &envelope.current_revision;
    if sha256(envelope.body_ciphertext.as_bytes()) != revision.ciphertext_digest
        || usize::try_from(revision.ciphertext_length).ok() != Some(envelope.body_ciphertext.len())
    {
        return Err(ItemError::new(ItemErrorKind::InvalidAncestry));
    }
    let plaintext_length = envelope
        .body_ciphertext
        .len()
        .checked_sub(16)
        .ok_or_else(|| ItemError::new(ItemErrorKind::InvalidInput))?;
    let aad = item_body_aad(
        revision.vault_id.as_bytes(),
        envelope.item_id.as_bytes(),
        revision.key_epoch,
        revision.item_revision,
        revision.revision_seal_id.as_bytes(),
        revision.bucket_id,
    );
    let plaintext = crypto::open(
        secret.memory(),
        &revision.nonce,
        &aad,
        envelope.body_ciphertext.as_bytes(),
        plaintext_length,
    )
    .map_err(map_crypto_error)?;
    plaintext
        .expose(|bytes| ItemStateV1::parse_framed(revision.bucket_id, bytes))
        .map_err(|_| ItemError::new(ItemErrorKind::ProtectionUnavailable))?
        .map_err(|_| ItemError::new(ItemErrorKind::InvalidInput))
}

pub(crate) fn verify_item_ancestry(
    envelope: &ItemEnvelopeV1,
    mut verification_key: impl FnMut(PrincipalId) -> Option<VerificationPublicKey32>,
) -> Result<(), ItemError> {
    let mut previous_hash = FixedBytes::new(ZERO_DIGEST);
    let expected_vault = envelope.current_revision.vault_id;
    for (index, revision) in envelope
        .prior_revisions
        .iter()
        .chain(std::iter::once(&envelope.current_revision))
        .enumerate()
    {
        let expected_revision =
            u64::try_from(index).map_err(|_| ItemError::new(ItemErrorKind::CapacityExhausted))? + 1;
        if revision.vault_id != expected_vault
            || revision.item_id != envelope.item_id
            || revision.item_revision != expected_revision
            || revision.previous_item_revision_hash != previous_hash
            || revision.key_epoch == 0
            || revision.plaintext_schema != 1
        {
            return Err(ItemError::new(ItemErrorKind::InvalidAncestry));
        }
        let key = verification_key(revision.author_principal_id)
            .ok_or_else(|| ItemError::new(ItemErrorKind::Unauthorized))?;
        crypto::verify_bytes(&key, &revision.signature_preimage(), &revision.signature)
            .map_err(|_| ItemError::new(ItemErrorKind::AuthenticationFailed))?;
        previous_hash = revision
            .recomputed_hash()
            .map_err(|_| ItemError::new(ItemErrorKind::InvalidAncestry))?;
    }
    Ok(())
}

fn sha256(bytes: &[u8]) -> Digest32 {
    FixedBytes::new(Sha256::digest(bytes).into())
}
