use jury_protocol::{
    vault_v1::{Digest32, MAX_VAULT_BYTES, Signature64},
    witness_v1::{OwnerReviewLabelV1, owner_review_label_set_digest},
};
use sha2::{Digest as _, Sha256};

use crate::{canonical, policy::WitnessPolicy};

use super::{RolloverError, RolloverErrorKind};

fn invalid() -> RolloverError {
    RolloverError::new(RolloverErrorKind::InvalidDestination)
}

/// Encode a genesis-independent witnessed bootstrap intent. This checks shape,
/// scope and label-set completeness, but deliberately does not claim that
/// genesis or label owner signatures have been authenticated. The completed
/// bootstrap verifier must authenticate those unprojected objects separately.
pub fn witness_intent_preimage(
    policy: &WitnessPolicy,
    labels: &[OwnerReviewLabelV1],
) -> Result<Vec<u8>, RolloverError> {
    policy.validate().map_err(|_| invalid())?;
    if policy.revision != 1
        || policy.vault_policy_sequence != 1
        || policy.predecessor_policy_digest != Digest32::new([0; 32])
        || owner_review_label_set_digest(labels).map_err(|_| invalid())?
            != policy.review_label_set_digest
        || labels
            .windows(2)
            .any(|pair| pair[0].label_id >= pair[1].label_id)
        || labels.iter().any(|label| {
            label.vault_id != policy.vault_id
                || label.genesis_fingerprint != policy.genesis_fingerprint
                || label.vault_policy_sequence != 1
                || label.label_revision != 1
        })
    {
        return Err(invalid());
    }
    encode_projection(policy, labels)
}

/// Encoding only, for the private pre-genesis constructor after authenticating
/// its source templates. Final acceptance always calls the validating public
/// wrapper with the actual signed destination roles and labels.
pub(super) fn encode_projection(
    policy: &WitnessPolicy,
    labels: &[OwnerReviewLabelV1],
) -> Result<Vec<u8>, RolloverError> {
    let mut projected = policy.clone();
    projected.genesis_fingerprint = Digest32::new([0; 32]);
    projected.vault_policy_hash = Digest32::new([0; 32]);
    projected.review_label_set_digest = Digest32::new([0; 32]);
    for descriptor in &mut projected.approver_descriptors {
        descriptor.self_signature = Signature64::new([0; 64]);
    }
    for descriptor in &mut projected.witness_descriptors {
        descriptor.self_signature = Signature64::new([0; 64]);
    }
    let body = projected.canonical_body().map_err(|_| invalid())?;
    let mut output = canonical::jce_v1("jury-v1/rollover/witness-intent");
    canonical::bytes_field(&mut output, &body).map_err(|_| invalid())?;
    let mut label_preimages = Vec::with_capacity(labels.len());
    for label in labels {
        let mut projected = label.clone();
        projected.genesis_fingerprint = Digest32::new([0; 32]);
        label_preimages.push(projected.signature_preimage().map_err(|_| invalid())?);
    }
    canonical::list_bytes(&mut output, &label_preimages).map_err(|_| invalid())?;
    if output.len() > MAX_VAULT_BYTES {
        return Err(invalid());
    }
    Ok(output)
}

pub fn witness_intent_digest(
    policy: &WitnessPolicy,
    labels: &[OwnerReviewLabelV1],
) -> Result<Digest32, RolloverError> {
    Ok(Digest32::new(
        Sha256::digest(witness_intent_preimage(policy, labels)?).into(),
    ))
}
