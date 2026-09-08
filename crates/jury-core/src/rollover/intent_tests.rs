use jury_protocol::{
    vault_v1::{Digest32, ItemId, LabelId, PrincipalId, Signature64},
    witness_v1::{
        OwnerReviewLabelV1, PresentationSubjectV1, ReviewLabelBytes, owner_review_label_set_digest,
    },
};
use serde_json::Value;

use super::{witness_intent_digest, witness_intent_preimage};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn label(policy: &crate::policy::WitnessPolicy) -> TestResult<OwnerReviewLabelV1> {
    Ok(OwnerReviewLabelV1 {
        schema: 1,
        label_id: LabelId::from_bytes([0x71; 32])?,
        label_revision: 1,
        subject_kind: PresentationSubjectV1::Item,
        vault_id: policy.vault_id,
        genesis_fingerprint: policy.genesis_fingerprint.clone(),
        item_id: Some(ItemId::from_bytes([3; 32])?),
        field_id: None,
        subject_commitment: None,
        public_label: ReviewLabelBytes::new(b"ExampleItem".to_vec())?,
        vault_policy_sequence: 1,
        issued_at_ms: 1_699_999_999_000,
        expires_at_ms: None,
        issuer_owner_id: PrincipalId::from_bytes([9; 32])?,
        issuer_key_fingerprint: Digest32::from_slice(&hex::decode(
            "20367a13894f8ebbb319f692e58c68369ddd3d547ed886b08fcb05ef74f1932c",
        )?)?,
        issuer_key_epoch: 1,
        // Intent encoding deliberately does not authenticate this signature.
        signature: Signature64::new([0; 64]),
    })
}

#[test]
fn witness_bootstrap_intent_matches_independent_projection_vectors() -> TestResult {
    let corpus: Value = serde_json::from_str(include_str!(
        "../../../../conformance/rollover-v1/intent-vectors.json"
    ))?;
    let (mut policy, _, _) = crate::policy::witness_tests::frozen_policy()?;
    policy.vault_policy_sequence = 1;
    for vector in corpus["vectors"].as_array().ok_or("missing vectors")? {
        let labels = if vector["name"] == "owner_label" {
            vec![label(&policy)?]
        } else {
            Vec::new()
        };
        policy.review_label_set_digest = owner_review_label_set_digest(&labels)?;
        assert_eq!(
            witness_intent_preimage(&policy, &labels)?,
            hex::decode(vector["preimage_hex"].as_str().ok_or("missing bytes")?)?
        );
        assert_eq!(
            witness_intent_digest(&policy, &labels)?
                .as_bytes()
                .as_slice(),
            hex::decode(vector["digest_hex"].as_str().ok_or("missing digest")?)?
        );
    }
    Ok(())
}

#[test]
fn intent_ignores_only_genesis_dependencies_and_retains_authority_settings() -> TestResult {
    let (mut policy, _, _) = crate::policy::witness_tests::frozen_policy()?;
    policy.vault_policy_sequence = 1;
    let mut labels = vec![label(&policy)?];
    policy.review_label_set_digest = owner_review_label_set_digest(&labels)?;
    let initial = witness_intent_digest(&policy, &labels)?;
    policy.genesis_fingerprint = Digest32::new([0x45; 32]);
    policy.vault_policy_hash = Digest32::new([0x45; 32]);
    labels[0].genesis_fingerprint = policy.genesis_fingerprint.clone();
    labels[0].signature = Signature64::new([0x46; 64]);
    policy.review_label_set_digest = owner_review_label_set_digest(&labels)?;
    assert_eq!(witness_intent_digest(&policy, &labels)?, initial);
    policy.witness_threshold = 3;
    assert_ne!(witness_intent_digest(&policy, &labels)?, initial);
    policy.witness_threshold = 2;
    policy.operation_rules[0].approval_threshold = 1;
    assert_ne!(witness_intent_digest(&policy, &labels)?, initial);
    policy.operation_rules[0].approval_threshold = 2;
    labels[0].public_label = ReviewLabelBytes::new(b"ExampleOtherItem".to_vec())?;
    policy.review_label_set_digest = owner_review_label_set_digest(&labels)?;
    assert_ne!(witness_intent_digest(&policy, &labels)?, initial);
    assert!(witness_intent_digest(&policy, &[]).is_err());
    policy.vault_policy_sequence = 2;
    assert!(witness_intent_digest(&policy, &labels).is_err());
    policy.vault_policy_sequence = 1;
    policy.direct_fallback = true;
    assert!(witness_intent_digest(&policy, &labels).is_err());
    Ok(())
}

#[test]
fn unsigned_role_templates_predict_only_the_same_fresh_signed_roles() -> TestResult {
    let (mut policy, _, _) = crate::policy::witness_tests::frozen_policy()?;
    policy.vault_policy_sequence = 1;
    policy.review_label_set_digest = owner_review_label_set_digest(&[])?;
    let source_intent = witness_intent_preimage(&policy, &[])?;
    for descriptor in &mut policy.approver_descriptors {
        descriptor.created_at_ms += 1;
        descriptor.self_signature = Signature64::new([0; 64]);
    }
    for descriptor in &mut policy.witness_descriptors {
        descriptor.created_at_ms += 1;
        descriptor.self_signature = Signature64::new([0; 64]);
    }
    let predicted = super::intent::encode_projection(&policy, &[])?;
    assert_ne!(predicted, source_intent);
    assert!(witness_intent_preimage(&policy, &[]).is_err());
    // These are the public signing seeds in the frozen conformance corpus.
    for (index, descriptor) in policy.approver_descriptors.iter_mut().enumerate() {
        let seed = [0x21 + u8::try_from(index)?; 32];
        assert_eq!(
            crate::crypto::verification_public_key_bytes(&seed)?,
            descriptor.signing_public_key
        );
        descriptor.self_signature =
            crate::crypto::sign_bytes(&seed, &descriptor.self_signature_preimage()?)?;
    }
    for (index, descriptor) in policy.witness_descriptors.iter_mut().enumerate() {
        let seed = [0x31 + u8::try_from(index)?; 32];
        assert_eq!(
            crate::crypto::verification_public_key_bytes(&seed)?,
            descriptor.signing_public_key
        );
        descriptor.self_signature =
            crate::crypto::sign_bytes(&seed, &descriptor.self_signature_preimage()?)?;
    }
    assert_eq!(witness_intent_preimage(&policy, &[])?, predicted);
    policy.witness_descriptors[0].created_at_ms += 1;
    assert!(witness_intent_preimage(&policy, &[]).is_err());
    policy.witness_descriptors[0].self_signature = crate::crypto::sign_bytes(
        &[0x31; 32],
        &policy.witness_descriptors[0].self_signature_preimage()?,
    )?;
    assert_ne!(witness_intent_preimage(&policy, &[])?, predicted);
    Ok(())
}
