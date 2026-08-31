#![forbid(unsafe_code)]

use chacha20::ChaCha20Rng;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hmac::{Hmac, KeyInit, Mac};
use hpke::{
    Deserializable, Kem, OpModeR, OpModeS, Serializable, aead::ChaCha20Poly1305, kdf::HkdfSha256,
    kem::XWing, rand_core::SeedableRng, single_shot_open, single_shot_seal_with_rng,
};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fs, path::Path};
use vsss_rs::Gf256;

const SUITE: u16 = 1;
const WITNESS_THRESHOLD: usize = 2;
const WITNESS_COUNT: usize = 3;
const APPROVER_THRESHOLD: usize = 2;
const APPROVER_COUNT: usize = 2;

type AnyResult<T> = Result<T, String>;

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn hex_bytes(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

fn fixed(byte: u8, length: usize) -> Vec<u8> {
    vec![byte; length]
}

fn id(byte: u8) -> Vec<u8> {
    fixed(byte, 32)
}

fn u16be(value: u16) -> Vec<u8> {
    value.to_be_bytes().to_vec()
}

fn u32be(value: u32) -> Vec<u8> {
    value.to_be_bytes().to_vec()
}

fn u64be(value: u64) -> Vec<u8> {
    value.to_be_bytes().to_vec()
}

fn bytes_field(value: &[u8]) -> AnyResult<Vec<u8>> {
    let length = u32::try_from(value.len()).map_err(|_| "bytes field too large".to_owned())?;
    let mut encoded = u32be(length);
    encoded.extend_from_slice(value);
    Ok(encoded)
}

fn optional(value: Option<&[u8]>) -> Vec<u8> {
    match value {
        None => vec![0],
        Some(value) => {
            let mut encoded = vec![1];
            encoded.extend_from_slice(value);
            encoded
        }
    }
}

fn list_fixed(values: &[Vec<u8>]) -> AnyResult<Vec<u8>> {
    let count = u32::try_from(values.len()).map_err(|_| "list too large".to_owned())?;
    let mut encoded = u32be(count);
    for value in values {
        encoded.extend_from_slice(value);
    }
    Ok(encoded)
}

fn list_bytes(values: &[Vec<u8>]) -> AnyResult<Vec<u8>> {
    let count = u32::try_from(values.len()).map_err(|_| "list too large".to_owned())?;
    let mut encoded = u32be(count);
    for value in values {
        encoded.extend(bytes_field(value)?);
    }
    Ok(encoded)
}

fn jce(domain: &str, fields: &[Vec<u8>]) -> Vec<u8> {
    let mut encoded = domain.as_bytes().to_vec();
    encoded.push(0);
    encoded.extend(u16be(SUITE));
    for field in fields {
        encoded.extend_from_slice(field);
    }
    encoded
}

fn hash_preimage(domain: &str, fields: &[Vec<u8>]) -> [u8; 32] {
    sha256(&jce(domain, fields))
}

fn signing_key(seed_byte: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed_byte; 32])
}

fn signing_fingerprint(role: u8, subject_id: &[u8], epoch: u64, public: &[u8]) -> [u8; 32] {
    hash_preimage(
        "jury-witness-v1/signing-key/fingerprint",
        &[
            vec![role],
            subject_id.to_vec(),
            u64be(epoch),
            public.to_vec(),
        ],
    )
}

fn signed_vector(
    name: &str,
    signature_domain: &str,
    hash_domain: &str,
    fields: &[Vec<u8>],
    signer: &SigningKey,
) -> AnyResult<Value> {
    let preimage = jce(signature_domain, fields);
    let signature = signer.sign(&preimage).to_bytes();
    let digest = hash_preimage(hash_domain, &[bytes_field(&preimage)?, signature.to_vec()]);
    let field_bytes = fields.concat();
    let mut message = field_bytes.clone();
    message.extend_from_slice(&signature);
    Ok(json!({
        "name": name,
        "signature_domain": signature_domain,
        "hash_domain": hash_domain,
        "preimage_hex": hex_bytes(&preimage),
        "field_bytes_hex": hex_bytes(&field_bytes),
        "signature_hex": hex_bytes(&signature),
        "signing_public_key_hex": hex_bytes(&signer.verifying_key().to_bytes()),
        "message_hex": hex_bytes(&message),
        "digest_hex": hex_bytes(&digest),
        "expected": "accepted"
    }))
}

fn vector_bytes(vector: &Value, field: &str) -> AnyResult<Vec<u8>> {
    let encoded = vector[field]
        .as_str()
        .ok_or_else(|| format!("missing {field}"))?;
    hex::decode(encoded).map_err(|error| format!("decode {field}: {error}"))
}

fn digest_vector(name: &str, domain: &str, body: &[u8]) -> AnyResult<Value> {
    let preimage = jce(domain, &[bytes_field(body)?]);
    Ok(json!({
        "name": name,
        "domain": domain,
        "body_hex": hex_bytes(body),
        "preimage_hex": hex_bytes(&preimage),
        "digest_hex": hex_bytes(&sha256(&preimage)),
        "expected": "accepted"
    }))
}

fn descriptor_vector(
    name: &str,
    fingerprint_domain: &str,
    signature_domain: &str,
    fields: &[Vec<u8>],
    signer: &SigningKey,
) -> AnyResult<Value> {
    let body = fields.concat();
    let fingerprint_preimage = jce(fingerprint_domain, &[bytes_field(&body)?]);
    let signature_preimage = jce(signature_domain, &[bytes_field(&body)?]);
    let signature = signer.sign(&signature_preimage).to_bytes();
    let mut message = body.clone();
    message.extend_from_slice(&signature);
    Ok(json!({
        "name": name,
        "fingerprint_domain": fingerprint_domain,
        "signature_domain": signature_domain,
        "body_hex": hex_bytes(&body),
        "fingerprint_preimage_hex": hex_bytes(&fingerprint_preimage),
        "fingerprint_hex": hex_bytes(&sha256(&fingerprint_preimage)),
        "preimage_hex": hex_bytes(&signature_preimage),
        "signature_hex": hex_bytes(&signature),
        "signing_public_key_hex": hex_bytes(&signer.verifying_key().to_bytes()),
        "message_hex": hex_bytes(&message),
        "expected": "accepted"
    }))
}

fn xwing_keypair(seed_byte: u8) -> (Vec<u8>, Vec<u8>) {
    let mut rng = ChaCha20Rng::from_seed([seed_byte; 32]);
    let (private, public) = XWing::gen_keypair_with_rng(&mut rng);
    (private.to_bytes().to_vec(), public.to_bytes().to_vec())
}

fn hpke_open(
    private_seed: &[u8],
    enc: &[u8],
    ciphertext: &[u8],
    info: &[u8],
    aad: &[u8],
) -> AnyResult<Vec<u8>> {
    let private = <<XWing as Kem>::PrivateKey as Deserializable>::from_bytes(private_seed)
        .map_err(|error| format!("private key decode: {error:?}"))?;
    let encapsulation = <<XWing as Kem>::EncappedKey as Deserializable>::from_bytes(enc)
        .map_err(|error| format!("encapsulation decode: {error:?}"))?;
    single_shot_open::<ChaCha20Poly1305, HkdfSha256, XWing>(
        &OpModeR::Base,
        &private,
        &encapsulation,
        info,
        ciphertext,
        aad,
    )
    .map_err(|error| format!("HPKE open: {error:?}"))
}

fn hpke_seal(
    public_bytes: &[u8],
    plaintext: &[u8],
    info: &[u8],
    aad: &[u8],
    seed_byte: u8,
) -> AnyResult<(Vec<u8>, Vec<u8>)> {
    let public = <<XWing as Kem>::PublicKey as Deserializable>::from_bytes(public_bytes)
        .map_err(|error| format!("public key decode: {error:?}"))?;
    let mut rng = ChaCha20Rng::from_seed([seed_byte; 32]);
    let (enc, ciphertext) = single_shot_seal_with_rng::<ChaCha20Poly1305, HkdfSha256, XWing>(
        &OpModeS::Base,
        &public,
        info,
        plaintext,
        aad,
        &mut rng,
    )
    .map_err(|error| format!("HPKE seal: {error:?}"))?;
    Ok((enc.to_bytes().to_vec(), ciphertext))
}

fn make_scope(seed: &str) -> BTreeMap<String, String> {
    let mut scope = BTreeMap::new();
    for field in [
        "request_id",
        "vault_id",
        "genesis_fingerprint",
        "item_id",
        "key_epoch",
        "item_access_mode",
        "slot_id",
        "content_role",
        "revision",
        "revision_seal_id",
        "vault_policy_sequence",
        "vault_policy_hash",
        "witness_policy_id",
        "witness_policy_revision",
        "witness_policy_digest",
        "requester_principal_id",
        "requested_access_role",
        "operation",
        "approval_target_digest",
        "issued_at_ms",
        "not_before_ms",
        "expires_at_ms",
        "operation_context",
        "arguments",
        "working_directory_commitment",
        "environment_injections",
        "stdin_target",
        "stdin_mode",
        "output_sink",
        "output_sink_commitment",
        "platform_assurance",
        "timeout_ms",
        "output_limit_bytes",
    ] {
        scope.insert(field.to_owned(), format!("{seed}:{field}"));
    }
    scope
}

pub fn scope_result(
    request: &BTreeMap<String, String>,
    manifest: &BTreeMap<String, String>,
) -> &'static str {
    if request == manifest {
        "accepted"
    } else {
        "wrong-scope"
    }
}

pub fn presentation_result(case: &Value) -> &'static str {
    let human = case["human"].as_bool().unwrap_or(false);
    if !human {
        return if case["automatic_rule_match"].as_bool().unwrap_or(false)
            && case["empty_presentation"].as_bool().unwrap_or(false)
        {
            "accepted"
        } else {
            "policy-denied"
        };
    }
    let checks = [
        "complete",
        "digest_match",
        "lossless",
        "untruncated",
        "meaningful",
        "label_signature_valid",
        "label_current",
        "subject_binding_valid",
        "entitled",
    ];
    if checks
        .iter()
        .all(|name| case[*name].as_bool() == Some(true))
    {
        "accepted"
    } else {
        "wrong-scope"
    }
}

pub fn split_write_result(case: &Value) -> &'static str {
    let database = case["database"].as_str().unwrap_or("invalid");
    let external = case["external"].as_str().unwrap_or("invalid");
    let pending = case["pending"].as_str().unwrap_or("invalid");
    let output_escaped = case["output_escaped"].as_bool().unwrap_or(true);
    match (database, external, pending, output_escaped) {
        ("g", "g", "none", false) => "serve-base",
        ("g+1", "g", "exact-candidate", false) => "repeat-cas-readback",
        ("g+1", "candidate", "exact-candidate", false) => "mark-published",
        ("g+1", "candidate", "published", true) => "serve-stable-output",
        _ => "anchor-conflict",
    }
}

#[derive(Default)]
struct ModelCounts {
    states: u64,
    applicable_states: u64,
    earlier_reopens: u64,
    old_approval_replay_attempts: u64,
    old_response_replay_attempts: u64,
    prior_state_authorizations: u64,
    later_opens_with_fresh_quorum: u64,
    excluded_direct_or_mixed: u64,
    excluded_witness_threshold: u64,
    authorization_compromise: u64,
    counterexamples: u64,
}

fn run_model_counts() -> ModelCounts {
    let mut counts = ModelCounts::default();
    for mode in ["witnessed-only", "mixed", "direct-only"] {
        for compromised_witnesses in 0..=WITNESS_COUNT {
            for compromised_approvers in 0..=APPROVER_COUNT {
                for retain_earlier_secret in [false, true] {
                    for request in ["absent", "current", "wrong-seal"] {
                        for honest_approvals in 0..=APPROVER_COUNT {
                            for replay_old_approvals in [false, true] {
                                for requested_honest_contributions in 0..=WITNESS_COUNT {
                                    for replay_old_response in [false, true] {
                                        for attempt_direct in [false, true] {
                                            counts.states += 1;
                                            let request_current = request == "current";
                                            let accepted_approvals = if request_current {
                                                (honest_approvals + compromised_approvers)
                                                    .min(APPROVER_COUNT)
                                            } else {
                                                0
                                            };
                                            let fresh_quorum = request_current
                                                && accepted_approvals >= APPROVER_THRESHOLD;
                                            let honest_available =
                                                WITNESS_COUNT.saturating_sub(compromised_witnesses);
                                            let honest_contributions = if fresh_quorum {
                                                requested_honest_contributions.min(honest_available)
                                            } else {
                                                0
                                            };
                                            let current_shares =
                                                compromised_witnesses + honest_contributions;
                                            let witnessed_open =
                                                current_shares >= WITNESS_THRESHOLD;
                                            let direct_open =
                                                attempt_direct && mode != "witnessed-only";
                                            let later_open = witnessed_open || direct_open;
                                            let earlier_reopen = retain_earlier_secret;

                                            if replay_old_approvals {
                                                counts.old_approval_replay_attempts += 1;
                                            }
                                            if replay_old_response {
                                                counts.old_response_replay_attempts += 1;
                                            }
                                            if replay_old_approvals
                                                && !request_current
                                                && accepted_approvals >= APPROVER_THRESHOLD
                                            {
                                                counts.prior_state_authorizations += 1;
                                            }
                                            if earlier_reopen {
                                                counts.earlier_reopens += 1;
                                            }
                                            if later_open && fresh_quorum {
                                                counts.later_opens_with_fresh_quorum += 1;
                                            }
                                            if mode != "witnessed-only" {
                                                counts.excluded_direct_or_mixed += 1;
                                            } else if compromised_witnesses >= WITNESS_THRESHOLD {
                                                counts.excluded_witness_threshold += 1;
                                            } else {
                                                counts.applicable_states += 1;
                                                if compromised_approvers >= APPROVER_THRESHOLD
                                                    && fresh_quorum
                                                {
                                                    counts.authorization_compromise += 1;
                                                }
                                                if later_open && !fresh_quorum {
                                                    counts.counterexamples += 1;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    counts
}

fn build_protocol_vectors() -> AnyResult<(Map<String, Value>, Value)> {
    let vault_id = id(0x01);
    let genesis = id(0x02);
    let item_id = id(0x03);
    let slot_id = id(0x05);
    let seal_id = id(0x06);
    let request_id = id(0x07);
    let requester_id = id(0x08);
    let owner_id = id(0x09);
    let witness_policy_id = id(0x0a);
    let issued_at = 1_700_000_000_000_u64;
    let expires_at = issued_at + 300_000;

    let requester_key = signing_key(0x11);
    let owner_key = signing_key(0x12);
    let approver_keys = [signing_key(0x21), signing_key(0x22)];
    let witness_signing_keys = [signing_key(0x31), signing_key(0x32), signing_key(0x33)];
    let approver_ids = [id(0x41), id(0x42)];
    let witness_ids = [id(0x51), id(0x52), id(0x53)];
    let requester_public = requester_key.verifying_key().to_bytes();
    let requester_fingerprint = signing_fingerprint(1, &requester_id, 1, &requester_public);
    let owner_public = owner_key.verifying_key().to_bytes();
    let owner_fingerprint = signing_fingerprint(1, &owner_id, 1, &owner_public);

    let mut vectors = Map::new();
    let mut approver_descriptors = Vec::new();
    let mut approver_fingerprints = Vec::new();
    for index in 0..APPROVER_COUNT {
        let public = approver_keys[index].verifying_key().to_bytes();
        let fingerprint = signing_fingerprint(2, &approver_ids[index], 1, &public);
        approver_fingerprints.push(fingerprint);
        let fields = vec![
            u16be(1),
            approver_ids[index].clone(),
            public.to_vec(),
            fingerprint.to_vec(),
            u64be(1),
            vec![1],
            vec![1],
            list_fixed(&[vec![1]])?,
            u64be(issued_at - 10_000),
        ];
        let vector = descriptor_vector(
            &format!("approver_descriptor_{}", index + 1),
            "jury-witness-v1/approver-descriptor/fingerprint",
            "jury-witness-v1/approver-descriptor/self-signature",
            &fields,
            &approver_keys[index],
        )?;
        approver_descriptors.push(vector_bytes(&vector, "message_hex")?);
        vectors.insert(format!("approver_descriptor_{}", index + 1), vector);
    }

    let mut witness_descriptors = Vec::new();
    let mut witness_descriptor_fingerprints = Vec::new();
    let mut witness_signing_fingerprints = Vec::new();
    let mut contribution_private_keys = Vec::new();
    let mut contribution_public_keys = Vec::new();
    let mut contribution_fingerprints = Vec::new();
    for index in 0..WITNESS_COUNT {
        let (private, public) = xwing_keypair(0x61 + u8::try_from(index).map_err(|_| "index")?);
        let contribution_fingerprint = hash_preimage(
            "jury-v1/recipient-public-bundle/fingerprint",
            std::slice::from_ref(&public),
        );
        let signing_public = witness_signing_keys[index].verifying_key().to_bytes();
        let signing_fingerprint = signing_fingerprint(3, &witness_ids[index], 1, &signing_public);
        let fields = vec![
            u16be(1),
            witness_ids[index].clone(),
            vec![u8::try_from(index + 1).map_err(|_| "share index")?],
            signing_public.to_vec(),
            signing_fingerprint.to_vec(),
            u64be(1),
            public.clone(),
            contribution_fingerprint.to_vec(),
            u64be(1),
            vec![1],
            u64be(issued_at - 10_000),
        ];
        let vector = descriptor_vector(
            &format!("witness_descriptor_{}", index + 1),
            "jury-witness-v1/witness-descriptor/fingerprint",
            "jury-witness-v1/witness-descriptor/self-signature",
            &fields,
            &witness_signing_keys[index],
        )?;
        witness_descriptors.push(vector_bytes(&vector, "message_hex")?);
        witness_descriptor_fingerprints.push(vector_bytes(&vector, "fingerprint_hex")?);
        witness_signing_fingerprints.push(signing_fingerprint);
        contribution_private_keys.push(private);
        contribution_public_keys.push(public);
        contribution_fingerprints.push(contribution_fingerprint);
        vectors.insert(format!("witness_descriptor_{}", index + 1), vector);
    }

    let label_fields = vec![
        u16be(1),
        id(0x71),
        u64be(1),
        vec![1],
        vault_id.clone(),
        genesis.clone(),
        optional(Some(&item_id)),
        optional(None),
        optional(None),
        bytes_field(b"ExampleItem")?,
        u64be(7),
        u64be(issued_at - 1_000),
        optional(None),
        owner_id.clone(),
        owner_fingerprint.to_vec(),
        u64be(1),
    ];
    let review_label = signed_vector(
        "owner_review_label",
        "jury-witness-v1/review-label/signature",
        "jury-witness-v1/review-label/hash",
        &label_fields,
        &owner_key,
    )?;
    let review_label_bytes = vector_bytes(&review_label, "message_hex")?;
    let review_label_digest = vector_bytes(&review_label, "digest_hex")?;
    vectors.insert("owner_review_label".to_owned(), review_label);
    let review_label_set_digest = hash_preimage(
        "jury-witness-v1/review-label-set/hash",
        &[list_fixed(std::slice::from_ref(&review_label_digest))?],
    );

    let operation_rule = [
        vec![1],
        list_fixed(&approver_ids)?,
        vec![2],
        u64be(300_000),
        u64be(30_000),
        u32be(4_096),
        vec![1],
        vec![1],
        list_bytes(&[])?,
    ]
    .concat();
    let policy_body = [
        u16be(1),
        witness_policy_id.clone(),
        u64be(1),
        fixed(0, 32),
        vault_id.clone(),
        genesis.clone(),
        u64be(7),
        id(0x72),
        u16be(1),
        u16be(1),
        list_bytes(&approver_descriptors)?,
        list_bytes(&witness_descriptors)?,
        vec![2],
        list_bytes(&[operation_rule])?,
        review_label_set_digest.to_vec(),
        vec![0],
    ]
    .concat();
    let witness_policy = digest_vector(
        "witness_policy",
        "jury-witness-v1/policy/hash",
        &policy_body,
    )?;
    let witness_policy_digest = vector_bytes(&witness_policy, "digest_hex")?;
    vectors.insert("witness_policy".to_owned(), witness_policy);
    let policy_revision_fields = vec![
        vault_id.clone(),
        u64be(7),
        id(0x70),
        u64be(issued_at - 600),
        owner_id.clone(),
        list_bytes(&[[vec![0x0b], witness_policy_digest.clone()].concat()])?,
        id(0x72),
    ];
    let policy_revision = signed_vector(
        "owner_policy_revision",
        "jury-v1/policy-revision/signature",
        "jury-v1/policy-revision/hash",
        &policy_revision_fields,
        &owner_key,
    )?;
    let policy_material = [
        bytes_field(&vector_bytes(&policy_revision, "message_hex")?)?,
        bytes_field(&policy_body)?,
    ]
    .concat();
    vectors.insert("owner_policy_revision".to_owned(), policy_revision);

    let checkpoint_fields = vec![
        u16be(1),
        vault_id.clone(),
        genesis.clone(),
        u64be(7),
        id(0x72),
        witness_policy_id.clone(),
        u64be(1),
        witness_policy_digest.clone(),
        hash_preimage(
            "jury-witness-v1/witness-descriptor-set/hash",
            &[list_bytes(&witness_descriptors)?],
        )
        .to_vec(),
        hash_preimage(
            "jury-witness-v1/approver-descriptor-set/hash",
            &[list_bytes(&approver_descriptors)?],
        )
        .to_vec(),
        review_label_set_digest.to_vec(),
        fixed(0, 32),
        u64be(issued_at - 500),
        owner_id.clone(),
        owner_fingerprint.to_vec(),
        u64be(1),
    ];
    let checkpoint = signed_vector(
        "policy_checkpoint",
        "jury-witness-v1/checkpoint/signature",
        "jury-witness-v1/checkpoint/hash",
        &checkpoint_fields,
        &owner_key,
    )?;
    let checkpoint_bytes = vector_bytes(&checkpoint, "message_hex")?;
    let checkpoint_digest = vector_bytes(&checkpoint, "digest_hex")?;
    vectors.insert("policy_checkpoint".to_owned(), checkpoint);

    let presentation_entry = [
        vec![1],
        optional(Some(&item_id)),
        optional(None),
        optional(None),
        vec![2],
        bytes_field(b"ExampleItem")?,
        optional(Some(&u64be(4))),
        optional(Some(&seal_id)),
        optional(Some(&review_label_bytes)),
        id(0x73),
    ]
    .concat();
    let presentation_list = list_bytes(std::slice::from_ref(&presentation_entry))?;
    let presentation_digest = hash_preimage(
        "jury-witness-v1/approval-presentation/hash",
        std::slice::from_ref(&presentation_list),
    );
    let presentation_commitment = hash_preimage(
        "jury-witness-v1/approval-presentation/commitment",
        &[bytes_field(&presentation_entry)?],
    );
    vectors.insert(
        "approval_presentation".to_owned(),
        json!({
            "name": "approval_presentation",
            "entry_hex": hex_bytes(&presentation_entry),
            "entry_commitment_hex": hex_bytes(&presentation_commitment),
            "list_hex": hex_bytes(&presentation_list),
            "digest_hex": hex_bytes(&presentation_digest),
            "expected": "accepted"
        }),
    );

    let target_entry = [
        item_id.clone(),
        optional(None),
        presentation_commitment.to_vec(),
    ]
    .concat();
    let approval_target = [
        list_bytes(std::slice::from_ref(&target_entry))?,
        presentation_digest.to_vec(),
    ]
    .concat();
    let approval_target_digest = hash_preimage(
        "jury-witness-v1/approval-target/hash",
        &[bytes_field(&approval_target)?],
    );
    vectors.insert(
        "approval_target".to_owned(),
        json!({
            "name": "approval_target",
            "entry_hex": hex_bytes(&target_entry),
            "body_hex": hex_bytes(&approval_target),
            "digest_hex": hex_bytes(&approval_target_digest),
            "expected": "accepted"
        }),
    );

    let operation_context = jce("jury-witness-v1/operation-context/read-stdout", &[u16be(1)]);
    let workload_fields = vec![
        vec![1],
        bytes_field(&operation_context)?,
        optional(None),
        list_bytes(&[])?,
        optional(None),
        list_bytes(&[])?,
        optional(None),
        vec![1],
        vec![1],
        optional(None),
        vec![1],
        u64be(30_000),
        u32be(4_096),
    ];
    let workload_preimage = jce("jury-witness-v1/workload/hash", &workload_fields);
    let workload_digest = sha256(&workload_preimage);
    vectors.insert(
        "workload".to_owned(),
        json!({
            "name": "workload",
            "preimage_hex": hex_bytes(&workload_preimage),
            "digest_hex": hex_bytes(&workload_digest),
            "expected": "accepted"
        }),
    );

    let manifest_fields = vec![
        u16be(1),
        request_id.clone(),
        vault_id.clone(),
        genesis.clone(),
        item_id.clone(),
        u64be(3),
        vec![2],
        slot_id.clone(),
        vec![2],
        u64be(4),
        seal_id.clone(),
        u64be(7),
        id(0x72),
        witness_policy_id.clone(),
        u64be(1),
        witness_policy_digest.clone(),
        requester_id.clone(),
        vec![1],
        vec![1],
        bytes_field(&operation_context)?,
        bytes_field(&approval_target)?,
        approval_target_digest.to_vec(),
        optional(None),
        list_bytes(&[])?,
        optional(None),
        list_bytes(&[])?,
        optional(None),
        vec![1],
        vec![1],
        optional(None),
        vec![1],
        u64be(30_000),
        u32be(4_096),
        u64be(issued_at),
        optional(None),
        u64be(expires_at),
        presentation_digest.to_vec(),
    ];
    let manifest_body = manifest_fields.concat();
    let action_manifest = digest_vector(
        "action_manifest",
        "jury-witness-v1/action-manifest/hash",
        &manifest_body,
    )?;
    let action_manifest_digest = vector_bytes(&action_manifest, "digest_hex")?;
    vectors.insert("action_manifest".to_owned(), action_manifest);

    let (session_private, session_public) = xwing_keypair(0x74);
    let session_fingerprint = hash_preimage(
        "jury-v1/recipient-public-bundle/fingerprint",
        std::slice::from_ref(&session_public),
    );
    let intended_witness_entries: Vec<Vec<u8>> = (0..WITNESS_COUNT)
        .map(|index| {
            [
                witness_ids[index].clone(),
                vec![u8::try_from(index + 1).unwrap_or(0)],
                witness_signing_fingerprints[index].to_vec(),
                contribution_fingerprints[index].to_vec(),
            ]
            .concat()
        })
        .collect();
    let intended_witness_set = list_fixed(&intended_witness_entries)?;
    let intended_witness_set_digest = hash_preimage(
        "jury-witness-v1/intended-witness-set/hash",
        std::slice::from_ref(&intended_witness_set),
    );
    let request_fields = vec![
        u16be(1),
        u16be(1),
        u16be(1),
        request_id.clone(),
        id(0x75),
        vault_id.clone(),
        genesis.clone(),
        item_id.clone(),
        u64be(3),
        vec![2],
        slot_id.clone(),
        vec![2],
        u64be(4),
        seal_id.clone(),
        u64be(7),
        id(0x72),
        checkpoint_digest.clone(),
        witness_policy_id.clone(),
        u64be(1),
        witness_policy_digest.clone(),
        requester_id.clone(),
        requester_fingerprint.to_vec(),
        u64be(1),
        vec![1],
        vec![1],
        approval_target_digest.to_vec(),
        action_manifest_digest.clone(),
        workload_digest.to_vec(),
        u64be(issued_at),
        optional(None),
        u64be(expires_at),
        session_public.clone(),
        session_fingerprint.to_vec(),
        intended_witness_set.clone(),
    ];
    let request = signed_vector(
        "witness_request",
        "jury-witness-v1/request/signature",
        "jury-witness-v1/request/hash",
        &request_fields,
        &requester_key,
    )?;
    let request_message = vector_bytes(&request, "message_hex")?;
    let request_digest = vector_bytes(&request, "digest_hex")?;
    let request_signature_preimage = vector_bytes(&request, "preimage_hex")?;
    let client_signature = vector_bytes(&request, "signature_hex")?;
    vectors.insert("witness_request".to_owned(), request);

    let mut approval_messages = Vec::new();
    for index in 0..APPROVER_COUNT {
        let fields = vec![
            u16be(1),
            id(0x80 + u8::try_from(index).map_err(|_| "approval index")?),
            request_id.clone(),
            request_digest.clone(),
            action_manifest_digest.clone(),
            presentation_digest.to_vec(),
            witness_policy_id.clone(),
            u64be(1),
            witness_policy_digest.clone(),
            approver_ids[index].clone(),
            approver_fingerprints[index].to_vec(),
            u64be(1),
            vec![1],
            vec![1],
            vec![0],
            u64be(issued_at + 1_000),
            optional(None),
            u64be(expires_at),
            id(0x82 + u8::try_from(index).map_err(|_| "approval nonce")?),
            intended_witness_set_digest.to_vec(),
        ];
        let vector = signed_vector(
            &format!("approval_decision_{}", index + 1),
            "jury-witness-v1/approval-decision/signature",
            "jury-witness-v1/approval-decision/hash",
            &fields,
            &approver_keys[index],
        )?;
        approval_messages.push(vector_bytes(&vector, "message_hex")?);
        vectors.insert(format!("approval_decision_{}", index + 1), vector);
    }

    let revision_secret = fixed(0x91, 32);
    let mut share_rng = ChaCha20Rng::from_seed([0x92; 32]);
    let shares = Gf256::split_bytes(
        WITNESS_THRESHOLD,
        WITNESS_COUNT,
        &revision_secret,
        &mut share_rng,
    )
    .map_err(|error| format!("split shares: {error:?}"))?;
    let reconstructed = Gf256::combine_bytes(&shares[0..WITNESS_THRESHOLD])
        .map_err(|error| format!("combine shares: {error:?}"))?;
    if reconstructed != revision_secret {
        return Err("share reconstruction mismatch".to_owned());
    }
    let later_revision_secret = fixed(0x93, 32);
    let mut later_share_rng = ChaCha20Rng::from_seed([0x94; 32]);
    let later_shares = Gf256::split_bytes(
        WITNESS_THRESHOLD,
        WITNESS_COUNT,
        &later_revision_secret,
        &mut later_share_rng,
    )
    .map_err(|error| format!("split later shares: {error:?}"))?;
    let later_reconstructed = Gf256::combine_bytes(&later_shares[0..WITNESS_THRESHOLD])
        .map_err(|error| format!("combine later shares: {error:?}"))?;
    let cross_revision_result =
        Gf256::combine_bytes(vec![shares[0].clone(), later_shares[1].clone()])
            .map_err(|error| format!("combine cross-revision shares: {error:?}"))?;
    if later_reconstructed != later_revision_secret
        || cross_revision_result == later_revision_secret
        || cross_revision_result == revision_secret
    {
        return Err("later revision separation mismatch".to_owned());
    }

    let mut capsule_contexts = Vec::new();
    let mut share_commitments = Vec::new();
    let mut capsules = Vec::new();
    let mut capsule_json = Vec::new();
    for index in 0..WITNESS_COUNT {
        let context_fields = vec![
            u16be(1),
            u16be(1),
            u16be(1),
            vault_id.clone(),
            genesis.clone(),
            item_id.clone(),
            u64be(3),
            vec![2],
            slot_id.clone(),
            vec![2],
            u64be(4),
            seal_id.clone(),
            u64be(7),
            witness_policy_id.clone(),
            u64be(1),
            witness_policy_digest.clone(),
            vec![2],
            vec![3],
            witness_ids[index].clone(),
            contribution_fingerprints[index].to_vec(),
            vec![u8::try_from(index + 1).map_err(|_| "share index")?],
        ];
        let context_preimage = jce("jury-witness-v1/capsule/context", &context_fields);
        let context_digest = sha256(&context_preimage);
        let commitment = hash_preimage(
            "jury-witness-v1/share/commitment",
            &[context_digest.to_vec(), shares[index].clone()],
        );
        let info = jce(
            "jury-witness-v1/capsule/info",
            &[
                context_digest.to_vec(),
                witness_ids[index].clone(),
                contribution_fingerprints[index].to_vec(),
                vec![u8::try_from(index + 1).map_err(|_| "share index")?],
            ],
        );
        let aad = jce(
            "jury-witness-v1/capsule/aad",
            &[
                context_digest.to_vec(),
                commitment.to_vec(),
                witness_policy_digest.clone(),
                u64be(7),
            ],
        );
        let (enc, ciphertext) = hpke_seal(
            &contribution_public_keys[index],
            &shares[index],
            &info,
            &aad,
            0xa0 + u8::try_from(index).map_err(|_| "capsule seed")?,
        )?;
        let capsule = [
            context_fields.concat(),
            context_digest.to_vec(),
            commitment.to_vec(),
            enc.clone(),
            ciphertext.clone(),
        ]
        .concat();
        capsule_contexts.push(context_digest);
        share_commitments.push(commitment);
        capsules.push(capsule.clone());
        capsule_json.push(json!({
            "witness_id_hex": hex_bytes(&witness_ids[index]),
            "share_index": index + 1,
            "context_preimage_hex": hex_bytes(&context_preimage),
            "context_digest_hex": hex_bytes(&context_digest),
            "share_hex": hex_bytes(&shares[index]),
            "share_commitment_hex": hex_bytes(&commitment),
            "info_hex": hex_bytes(&info),
            "aad_hex": hex_bytes(&aad),
            "recipient_private_seed_hex": hex_bytes(&contribution_private_keys[index]),
            "recipient_public_key_hex": hex_bytes(&contribution_public_keys[index]),
            "enc_hex": hex_bytes(&enc),
            "ciphertext_hex": hex_bytes(&ciphertext),
            "capsule_hex": hex_bytes(&capsule)
        }));
    }
    let capsule_set_digest = hash_preimage(
        "jury-witness-v1/capsule-set/hash",
        &[list_bytes(&capsules)?],
    );
    let witnessed_slot = [
        vec![1],
        vec![2],
        u16be(1),
        u16be(1),
        u16be(1),
        vault_id.clone(),
        genesis.clone(),
        item_id.clone(),
        u64be(3),
        vec![2],
        slot_id.clone(),
        vec![2],
        u64be(4),
        seal_id.clone(),
        u64be(7),
        witness_policy_id.clone(),
        u64be(1),
        witness_policy_digest.clone(),
        vec![2],
        vec![3],
        list_bytes(&capsules)?,
        capsule_set_digest.to_vec(),
    ]
    .concat();
    let witnessed_slot_digest = hash_preimage(
        "jury-witness-v1/slot/hash",
        &[bytes_field(&witnessed_slot)?],
    );
    let witnessed_state_digest = hash_preimage(
        "jury-witness-v1/slot-set/hash",
        &[list_bytes(std::slice::from_ref(&witnessed_slot))?],
    );

    let mut contribution_envelopes = Vec::new();
    let mut contribution_json = Vec::new();
    let mut witness_messages = Vec::new();
    let mut witness_responses = Vec::new();
    for index in 0..WITNESS_THRESHOLD {
        let response_id = id(0xb0 + u8::try_from(index).map_err(|_| "response id")?);
        let info = jce(
            "jury-witness-v1/contribution/info",
            &[
                request_digest.clone(),
                action_manifest_digest.clone(),
                response_id.clone(),
                witness_ids[index].clone(),
                witness_policy_digest.clone(),
                checkpoint_digest.clone(),
                share_commitments[index].to_vec(),
                vec![u8::try_from(index + 1).map_err(|_| "share index")?],
            ],
        );
        let aad = jce(
            "jury-witness-v1/contribution/aad",
            &[
                capsule_set_digest.to_vec(),
                capsule_contexts[index].to_vec(),
                session_fingerprint.to_vec(),
                u64be(expires_at),
            ],
        );
        let (enc, ciphertext) = hpke_seal(
            &session_public,
            &shares[index],
            &info,
            &aad,
            0xc0 + u8::try_from(index).map_err(|_| "contribution seed")?,
        )?;
        let envelope = [
            u16be(1),
            response_id.clone(),
            vec![u8::try_from(index + 1).map_err(|_| "share index")?],
            share_commitments[index].to_vec(),
            capsule_contexts[index].to_vec(),
            capsule_set_digest.to_vec(),
            session_fingerprint.to_vec(),
            enc.clone(),
            ciphertext.clone(),
        ]
        .concat();
        let contribution_digest = hash_preimage(
            "jury-witness-v1/contribution/hash",
            &[bytes_field(&envelope)?],
        );
        contribution_envelopes.push(envelope.clone());
        contribution_json.push(json!({
            "witness_id_hex": hex_bytes(&witness_ids[index]),
            "response_id_hex": hex_bytes(&response_id),
            "share_index": index + 1,
            "info_hex": hex_bytes(&info),
            "aad_hex": hex_bytes(&aad),
            "request_session_private_seed_hex": hex_bytes(&session_private),
            "request_session_public_key_hex": hex_bytes(&session_public),
            "enc_hex": hex_bytes(&enc),
            "ciphertext_hex": hex_bytes(&ciphertext),
            "envelope_hex": hex_bytes(&envelope),
            "digest_hex": hex_bytes(&contribution_digest),
            "plaintext_share_hex": hex_bytes(&shares[index])
        }));

        let decision_fields = vec![
            u16be(1),
            response_id,
            request_id.clone(),
            request_digest.clone(),
            action_manifest_digest.clone(),
            witness_ids[index].clone(),
            witness_signing_fingerprints[index].to_vec(),
            u64be(1),
            witness_policy_id.clone(),
            u64be(1),
            witness_policy_digest.clone(),
            checkpoint_digest.clone(),
            u64be(2 + u64::try_from(index).map_err(|_| "state generation")?),
            vec![1],
            vec![0],
            u64be(issued_at + 2_000),
            u64be(expires_at),
            optional(Some(&contribution_digest)),
            optional(Some(&[u8::try_from(index + 1).map_err(|_| "share index")?])),
            optional(Some(&share_commitments[index])),
        ];
        let vector = signed_vector(
            &format!("witness_decision_{}", index + 1),
            "jury-witness-v1/decision/signature",
            "jury-witness-v1/decision/hash",
            &decision_fields,
            &witness_signing_keys[index],
        )?;
        let decision_message = vector_bytes(&vector, "message_hex")?;
        let response = [decision_message.clone(), envelope].concat();
        witness_messages.push(decision_message);
        witness_responses.push(response.clone());
        contribution_json[index]["response_hex"] = json!(hex_bytes(&response));
        vectors.insert(format!("witness_decision_{}", index + 1), vector);
    }
    let contribution_shares: Vec<Vec<u8>> = contribution_json
        .iter()
        .map(|entry| {
            let value = entry["plaintext_share_hex"].as_str().unwrap_or("");
            hex::decode(value).unwrap_or_default()
        })
        .collect();
    let assembled = Gf256::combine_bytes(contribution_shares)
        .map_err(|error| format!("assemble contributions: {error:?}"))?;
    if assembled != revision_secret {
        return Err("contribution assembly mismatch".to_owned());
    }
    let construction = json!({
        "construction": "jury-witness-v1-shamir-xwing-hpke",
        "suite": 1,
        "threshold": WITNESS_THRESHOLD,
        "member_count": WITNESS_COUNT,
        "revision_secret_hex": hex_bytes(&revision_secret),
        "share_rng_seed_hex": hex_bytes(&[0x92; 32]),
        "shares": shares.iter().map(|share| hex_bytes(share)).collect::<Vec<_>>(),
        "later_revision": {
            "revision_seal_id_hex": hex_bytes(&id(0x95)),
            "revision_secret_hex": hex_bytes(&later_revision_secret),
            "share_rng_seed_hex": hex_bytes(&[0x94; 32]),
            "shares": later_shares.iter().map(|share| hex_bytes(share)).collect::<Vec<_>>(),
            "reconstructed_revision_secret_hex": hex_bytes(&later_reconstructed),
            "cross_revision_share_result_hex": hex_bytes(&cross_revision_result),
            "prior_state_opens_later_revision": false
        },
        "capsule_set_digest_hex": hex_bytes(&capsule_set_digest),
        "witnessed_slot_hex": hex_bytes(&witnessed_slot),
        "witnessed_slot_digest_hex": hex_bytes(&witnessed_slot_digest),
        "witnessed_state_digest_hex": hex_bytes(&witnessed_state_digest),
        "capsules": capsule_json,
        "contributions": contribution_json,
        "selected_share_indexes": [1, 2],
        "reconstructed_revision_secret_hex": hex_bytes(&assembled),
        "reusable_contribution": false,
        "epoch_root": null
    });

    let cancellation_fields = vec![
        u16be(1),
        id(0xd0),
        bytes_field(&request_signature_preimage)?,
        client_signature.clone(),
        request_id.clone(),
        request_digest.clone(),
        requester_id.clone(),
        requester_fingerprint.to_vec(),
        u64be(1),
        vec![1],
        u64be(issued_at + 3_000),
        vec![0x0b],
        id(0xd1),
    ];
    let cancellation = signed_vector(
        "request_cancellation",
        "jury-witness-v1/cancellation/signature",
        "jury-witness-v1/cancellation/hash",
        &cancellation_fields,
        &requester_key,
    )?;
    vectors.insert("request_cancellation".to_owned(), cancellation);

    let registration_id = id(0xd2);
    let registration_challenge_plaintext = fixed(0xd3, 32);
    let registration_info = jce(
        "jury-witness-v1/registration/info",
        &[
            registration_id.clone(),
            vault_id.clone(),
            genesis.clone(),
            witness_descriptor_fingerprints[0].clone(),
            contribution_fingerprints[0].to_vec(),
            checkpoint_digest.clone(),
        ],
    );
    let registration_aad = jce(
        "jury-witness-v1/registration/aad",
        &[
            u64be(issued_at),
            u64be(expires_at),
            owner_id.clone(),
            owner_fingerprint.to_vec(),
            u64be(1),
            witness_ids[0].clone(),
        ],
    );
    let (registration_enc, registration_ciphertext) = hpke_seal(
        &contribution_public_keys[0],
        &registration_challenge_plaintext,
        &registration_info,
        &registration_aad,
        0xd4,
    )?;
    let registration_challenge_fields = vec![
        u16be(1),
        registration_id.clone(),
        vault_id.clone(),
        genesis.clone(),
        bytes_field(&witness_descriptors[0])?,
        witness_descriptor_fingerprints[0].clone(),
        bytes_field(&checkpoint_bytes)?,
        checkpoint_digest.clone(),
        u64be(issued_at),
        u64be(expires_at),
        owner_id.clone(),
        owner_fingerprint.to_vec(),
        u64be(1),
        registration_enc.clone(),
        registration_ciphertext.clone(),
    ];
    let registration_challenge = signed_vector(
        "registration_challenge",
        "jury-witness-v1/registration/challenge-signature",
        "jury-witness-v1/registration/challenge-hash",
        &registration_challenge_fields,
        &owner_key,
    )?;
    let registration_challenge_digest = vector_bytes(&registration_challenge, "digest_hex")?;
    let registration_challenge_message = vector_bytes(&registration_challenge, "message_hex")?;
    vectors.insert("registration_challenge".to_owned(), registration_challenge);
    let key_proof_data = jce(
        "jury-witness-v1/registration/key-proof",
        &[
            registration_id.clone(),
            vault_id.clone(),
            genesis.clone(),
            witness_descriptor_fingerprints[0].clone(),
            checkpoint_digest.clone(),
            registration_enc.clone(),
            registration_ciphertext.clone(),
        ],
    );
    let mut mac = Hmac::<Sha256>::new_from_slice(&registration_challenge_plaintext)
        .map_err(|error| format!("HMAC key: {error}"))?;
    mac.update(&key_proof_data);
    let key_proof = mac.finalize().into_bytes().to_vec();
    let registration_response_fields = vec![
        u16be(1),
        registration_id.clone(),
        registration_challenge_digest.clone(),
        witness_ids[0].clone(),
        witness_signing_fingerprints[0].to_vec(),
        u64be(1),
        contribution_fingerprints[0].to_vec(),
        u64be(1),
        key_proof.clone(),
        u64be(issued_at + 1_000),
    ];
    let registration_response = signed_vector(
        "registration_response",
        "jury-witness-v1/registration/response-signature",
        "jury-witness-v1/registration/response-hash",
        &registration_response_fields,
        &witness_signing_keys[0],
    )?;
    let registration_response_digest = vector_bytes(&registration_response, "digest_hex")?;
    let registration_response_message = vector_bytes(&registration_response, "message_hex")?;
    vectors.insert("registration_response".to_owned(), registration_response);
    let registration_acceptance_fields = vec![
        u16be(1),
        registration_id.clone(),
        registration_challenge_digest.clone(),
        registration_response_digest.clone(),
        witness_descriptor_fingerprints[0].clone(),
        checkpoint_digest.clone(),
        u64be(issued_at + 2_000),
        owner_id.clone(),
        owner_fingerprint.to_vec(),
        u64be(1),
    ];
    let registration_acceptance = signed_vector(
        "registration_acceptance",
        "jury-witness-v1/registration/acceptance-signature",
        "jury-witness-v1/registration/acceptance-hash",
        &registration_acceptance_fields,
        &owner_key,
    )?;
    let registration_acceptance_message = vector_bytes(&registration_acceptance, "message_hex")?;
    vectors.insert(
        "registration_acceptance".to_owned(),
        registration_acceptance,
    );
    let registration_body = [
        bytes_field(&registration_challenge_message)?,
        bytes_field(&registration_response_message)?,
        bytes_field(&registration_acceptance_message)?,
    ]
    .concat();
    vectors.insert(
        "witness_registration".to_owned(),
        digest_vector(
            "witness_registration",
            "jury-witness-v1/registration/hash",
            &registration_body,
        )?,
    );
    vectors.insert(
        "registration_key_proof".to_owned(),
        json!({
            "name": "registration_key_proof",
            "info_hex": hex_bytes(&registration_info),
            "aad_hex": hex_bytes(&registration_aad),
            "recipient_private_seed_hex": hex_bytes(&contribution_private_keys[0]),
            "enc_hex": hex_bytes(&registration_enc),
            "ciphertext_hex": hex_bytes(&registration_ciphertext),
            "plaintext_hex": hex_bytes(&registration_challenge_plaintext),
            "hmac_data_hex": hex_bytes(&key_proof_data),
            "hmac_hex": hex_bytes(&key_proof)
        }),
    );

    let replay_record = [
        u16be(1),
        vault_id.clone(),
        request_id.clone(),
        request_digest.clone(),
        bytes_field(&request_message)?,
        action_manifest_digest.clone(),
        vec![2],
        u64be(expires_at),
        u64be(expires_at + 86_400_000),
        list_bytes(&approval_messages)?,
        optional(None),
        optional(Some(&bytes_field(&witness_responses[0])?)),
    ]
    .concat();
    vectors.insert(
        "witness_replay_record".to_owned(),
        json!({
            "name": "witness_replay_record",
            "body_hex": hex_bytes(&replay_record),
            "expected": "accepted"
        }),
    );
    let database_state_body = [
        u16be(1),
        witness_ids[0].clone(),
        u64be(4),
        list_bytes(&[[
            u16be(1),
            vault_id.clone(),
            genesis.clone(),
            bytes_field(&registration_body)?,
            bytes_field(&checkpoint_bytes)?,
            bytes_field(&policy_material)?,
        ]
        .concat()])?,
        list_bytes(&[replay_record])?,
        u64be(issued_at + 2_000),
    ]
    .concat();
    let database_state_digest = hash_preimage(
        "jury-witness-v1/database-state/hash",
        &[bytes_field(&database_state_body)?],
    );
    vectors.insert(
        "witness_database_state".to_owned(),
        digest_vector(
            "witness_database_state",
            "jury-witness-v1/database-state/hash",
            &database_state_body,
        )?,
    );
    let high_watermark = [
        vault_id.clone(),
        genesis.clone(),
        u64be(7),
        checkpoint_digest.clone(),
        u64be(expires_at),
    ]
    .concat();
    let anchor_fields = vec![
        u16be(1),
        witness_ids[0].clone(),
        witness_signing_fingerprints[0].to_vec(),
        u64be(1),
        u64be(4),
        database_state_digest.to_vec(),
        list_fixed(&[high_watermark])?,
        u64be(expires_at + 86_400_000),
        u64be(issued_at + 2_000),
        id(0xd5),
        u64be(issued_at + 2_100),
    ];
    let state_anchor = signed_vector(
        "witness_state_anchor",
        "jury-witness-v1/state-anchor/signature",
        "jury-witness-v1/state-anchor/hash",
        &anchor_fields,
        &witness_signing_keys[0],
    )?;
    vectors.insert("witness_state_anchor".to_owned(), state_anchor);
    let refusal = [
        u16be(1),
        vec![0x11],
        optional(Some(&request_id)),
        optional(Some(&vault_id)),
        optional(Some(&witness_ids[0])),
    ]
    .concat();
    vectors.insert(
        "protocol_refusal".to_owned(),
        json!({
            "name": "protocol_refusal",
            "body_hex": hex_bytes(&refusal),
            "reason": "unsupported-version",
            "state_change": false,
            "counts_as_decision": false,
            "expected": "accepted"
        }),
    );

    let affected_item = [
        item_id.clone(),
        u64be(3),
        u64be(4),
        u64be(5),
        id(0xd6),
        id(0xd7),
        u64be(5),
        id(0xd8),
        id(0xd9),
    ]
    .concat();
    let rotation_fields = vec![
        u16be(1),
        id(0xda),
        vault_id.clone(),
        genesis.clone(),
        u64be(7),
        id(0x72),
        u64be(8),
        id(0xdb),
        witness_policy_id.clone(),
        u64be(1),
        witness_policy_digest.clone(),
        id(0xdc),
        u64be(2),
        id(0xdd),
        vec![8],
        list_bytes(&[affected_item])?,
        u64be(issued_at + 4_000),
        owner_id.clone(),
        owner_fingerprint.to_vec(),
        u64be(1),
    ];
    let rotation = signed_vector(
        "witness_policy_rotation",
        "jury-witness-v1/rotation/signature",
        "jury-witness-v1/rotation/hash",
        &rotation_fields,
        &owner_key,
    )?;
    let rotation_digest = vector_bytes(&rotation, "digest_hex")?;
    vectors.insert("witness_policy_rotation".to_owned(), rotation);
    let recovery_fields = vec![
        u16be(1),
        id(0xde),
        vault_id.clone(),
        genesis.clone(),
        optional(Some(&witness_ids[0])),
        bytes_field(&witness_descriptors[2])?,
        hash_preimage(
            "jury-witness-v1/registration/hash",
            &[bytes_field(&registration_body)?],
        )
        .to_vec(),
        checkpoint_digest.clone(),
        id(0xdf),
        rotation_digest.clone(),
        vec![1],
        u64be(issued_at + 5_000),
        owner_id.clone(),
        owner_fingerprint.to_vec(),
        u64be(1),
    ];
    let recovery = signed_vector(
        "witness_recovery",
        "jury-witness-v1/recovery/signature",
        "jury-witness-v1/recovery/hash",
        &recovery_fields,
        &owner_key,
    )?;
    vectors.insert("witness_recovery".to_owned(), recovery);

    let public_scope = [
        u16be(1),
        request_id.clone(),
        vault_id.clone(),
        genesis.clone(),
        item_id.clone(),
        u64be(3),
        vec![2],
        slot_id.clone(),
        vec![2],
        u64be(4),
        seal_id.clone(),
        u64be(7),
        id(0x72),
        witness_policy_id.clone(),
        u64be(1),
        witness_policy_digest.clone(),
        requester_id.clone(),
        vec![1],
        vec![1],
        approval_target_digest.to_vec(),
        action_manifest_digest.clone(),
        workload_digest.to_vec(),
        u64be(issued_at),
        optional(None),
        u64be(expires_at),
    ]
    .concat();
    let receipt_id = id(0xe0);
    let receipt_core_fields = vec![
        u16be(1),
        receipt_id.clone(),
        bytes_field(&request_signature_preimage)?,
        client_signature,
        request_digest.clone(),
        action_manifest_digest.clone(),
        presentation_digest.to_vec(),
        bytes_field(&public_scope)?,
        list_bytes(&approval_messages)?,
        list_bytes(&witness_messages)?,
        bytes_field(&checkpoint_bytes)?,
        bytes_field(&policy_material)?,
        vec![2],
        vec![2],
        list_fixed(&approver_ids)?,
        list_fixed(&witness_ids[0..WITNESS_THRESHOLD])?,
        vec![1],
        vec![0],
        u64be(issued_at + 3_000),
        u64be(expires_at),
    ];
    let receipt_core = receipt_core_fields.concat();
    let receipt_core_digest = hash_preimage(
        "jury-witness-v1/receipt/core-hash",
        &[bytes_field(&receipt_core)?],
    );
    let acknowledgement_fields = vec![
        u16be(1),
        receipt_id.clone(),
        receipt_core_digest.to_vec(),
        request_digest.clone(),
        requester_id.clone(),
        requester_fingerprint.to_vec(),
        u64be(1),
        u64be(issued_at + 1_500),
    ];
    let acknowledgement = signed_vector(
        "receipt_acknowledgement",
        "jury-witness-v1/receipt/acknowledgement",
        "jury-witness-v1/receipt/acknowledgement/hash",
        &acknowledgement_fields,
        &requester_key,
    )?;
    let acknowledgement_digest = vector_bytes(&acknowledgement, "digest_hex")?;
    let acknowledgement_message = vector_bytes(&acknowledgement, "message_hex")?;
    vectors.insert("receipt_acknowledgement".to_owned(), acknowledgement);
    let completion_fields = vec![
        u16be(1),
        receipt_id.clone(),
        receipt_core_digest.to_vec(),
        optional(Some(&acknowledgement_digest)),
        requester_id.clone(),
        requester_fingerprint.to_vec(),
        u64be(1),
        vec![1],
        vec![0],
        u64be(issued_at + 3_000),
    ];
    let completion = signed_vector(
        "receipt_completion",
        "jury-witness-v1/receipt/completion",
        "jury-witness-v1/receipt/completion/hash",
        &completion_fields,
        &requester_key,
    )?;
    let completion_message = vector_bytes(&completion, "message_hex")?;
    vectors.insert("receipt_completion".to_owned(), completion);
    let full_receipt = [
        receipt_core.clone(),
        optional(Some(&bytes_field(&acknowledgement_message)?)),
        optional(Some(&bytes_field(&completion_message)?)),
    ]
    .concat();
    let receipt = digest_vector(
        "witness_receipt",
        "jury-witness-v1/receipt/hash",
        &full_receipt,
    )?;
    vectors.insert(
        "receipt_core".to_owned(),
        json!({
            "name": "receipt_core",
            "body_hex": hex_bytes(&receipt_core),
            "digest_hex": hex_bytes(&receipt_core_digest),
            "expected": "accepted"
        }),
    );
    vectors.insert("witness_receipt".to_owned(), receipt);

    Ok((vectors, construction))
}

pub fn protocol_case_result(case: &Value) -> &'static str {
    if case["known_version"].as_bool() != Some(true)
        || case["known_suite"].as_bool() != Some(true)
        || case["known_construction"].as_bool() != Some(true)
    {
        "unsupported-version"
    } else if case["within_bounds"].as_bool() != Some(true)
        || case["canonical"].as_bool() != Some(true)
    {
        "invalid"
    } else if case["signature_valid"].as_bool() != Some(true)
        || case["domain_valid"].as_bool() != Some(true)
    {
        "invalid-signature"
    } else if case["scope_equal"].as_bool() != Some(true) {
        "wrong-scope"
    } else if case["policy_current"].as_bool() != Some(true) {
        "stale-policy"
    } else if case["revision_current"].as_bool() != Some(true) {
        "wrong-scope"
    } else if case["time_valid"].as_bool() != Some(true) {
        "expired"
    } else if case["replay_consistent"].as_bool() != Some(true) {
        "replay-conflict"
    } else if case["actors_unique"].as_bool() != Some(true) {
        "invalid"
    } else if case["quorum_reached"].as_bool() != Some(true) {
        "insufficient-quorum"
    } else if case["anchor_consistent"].as_bool() != Some(true) {
        "anchor-conflict"
    } else if case["restored_state_safe"].as_bool() != Some(true) {
        "restored-state-unsafe"
    } else if case["explicit_witnessed_path"].as_bool() != Some(true) {
        "direct-downgrade"
    } else {
        "accepted"
    }
}

fn protocol_case(name: &str, changed: Option<(&str, bool)>, expected: &str) -> Value {
    let mut case = json!({
        "name": name,
        "known_version": true,
        "known_suite": true,
        "known_construction": true,
        "within_bounds": true,
        "canonical": true,
        "signature_valid": true,
        "domain_valid": true,
        "scope_equal": true,
        "policy_current": true,
        "revision_current": true,
        "time_valid": true,
        "replay_consistent": true,
        "actors_unique": true,
        "quorum_reached": true,
        "anchor_consistent": true,
        "restored_state_safe": true,
        "explicit_witnessed_path": true,
        "expected": expected
    });
    if let Some((field, value)) = changed {
        case[field] = Value::Bool(value);
    }
    case
}

fn build_scope_cases() -> Value {
    let request = make_scope("base");
    let mut cases = vec![json!({
        "name": "exact-equality",
        "request": request,
        "manifest": make_scope("base"),
        "request_signature_valid": true,
        "manifest_digest_valid": true,
        "expected": "accepted"
    })];
    for field in make_scope("base").keys() {
        let request = make_scope("base");
        let mut manifest = make_scope("base");
        manifest.insert(field.clone(), format!("mutated:{field}"));
        cases.push(json!({
            "name": format!("mismatch-{field}"),
            "mutated_field": field,
            "request": request,
            "manifest": manifest,
            "request_signature_valid": true,
            "manifest_digest_valid": true,
            "expected": "wrong-scope"
        }));
    }
    Value::Array(cases)
}

fn build_presentation_cases() -> Value {
    let base = json!({
        "human": true,
        "automatic_rule_match": false,
        "empty_presentation": false,
        "complete": true,
        "digest_match": true,
        "lossless": true,
        "untruncated": true,
        "meaningful": true,
        "label_signature_valid": true,
        "label_current": true,
        "subject_binding_valid": true,
        "entitled": true
    });
    let mut cases = Vec::new();
    let mut positive = base.clone();
    positive["name"] = json!("human-complete");
    positive["expected"] = json!("accepted");
    cases.push(positive);
    for (name, field) in [
        ("missing", "complete"),
        ("digest-mismatched", "digest_match"),
        ("lossy", "lossless"),
        ("truncated", "untruncated"),
        ("opaque", "meaningful"),
        ("forged-label", "label_signature_valid"),
        ("stale-label", "label_current"),
        ("wrong-binding", "subject_binding_valid"),
        ("absent-entitlement", "entitled"),
    ] {
        let mut case = base.clone();
        case["name"] = json!(name);
        case[field] = Value::Bool(false);
        case["expected"] = json!("wrong-scope");
        cases.push(case);
    }
    cases.push(json!({
        "name": "automatic-exact-rule",
        "human": false,
        "automatic_rule_match": true,
        "empty_presentation": true,
        "expected": "accepted"
    }));
    cases.push(json!({
        "name": "automatic-rule-mismatch",
        "human": false,
        "automatic_rule_match": false,
        "empty_presentation": true,
        "expected": "policy-denied"
    }));
    Value::Array(cases)
}

fn build_protocol_cases() -> Value {
    Value::Array(vec![
        protocol_case("accepted", None, "accepted"),
        protocol_case("identical-replay-idempotent", None, "accepted"),
        protocol_case("identical-duplicate-actor-counts-once", None, "accepted"),
        protocol_case(
            "unknown-version",
            Some(("known_version", false)),
            "unsupported-version",
        ),
        protocol_case(
            "unknown-algorithm",
            Some(("known_suite", false)),
            "unsupported-version",
        ),
        protocol_case(
            "unknown-construction",
            Some(("known_construction", false)),
            "unsupported-version",
        ),
        protocol_case("malformed-bound", Some(("within_bounds", false)), "invalid"),
        protocol_case("noncanonical", Some(("canonical", false)), "invalid"),
        protocol_case(
            "one-bit-signature",
            Some(("signature_valid", false)),
            "invalid-signature",
        ),
        protocol_case(
            "wrong-domain",
            Some(("domain_valid", false)),
            "invalid-signature",
        ),
        protocol_case(
            "cross-vault-item-role-revision-seal-session",
            Some(("scope_equal", false)),
            "wrong-scope",
        ),
        protocol_case(
            "stale-policy",
            Some(("policy_current", false)),
            "stale-policy",
        ),
        protocol_case(
            "stale-revision",
            Some(("revision_current", false)),
            "wrong-scope",
        ),
        protocol_case("expired", Some(("time_valid", false)), "expired"),
        protocol_case(
            "replay-changed-bytes",
            Some(("replay_consistent", false)),
            "replay-conflict",
        ),
        protocol_case("duplicate-actor", Some(("actors_unique", false)), "invalid"),
        protocol_case(
            "quorum-substitution",
            Some(("quorum_reached", false)),
            "insufficient-quorum",
        ),
        protocol_case(
            "anchor-rollback",
            Some(("anchor_consistent", false)),
            "anchor-conflict",
        ),
        protocol_case(
            "restored-witness",
            Some(("restored_state_safe", false)),
            "restored-state-unsafe",
        ),
        protocol_case(
            "implicit-direct-downgrade",
            Some(("explicit_witnessed_path", false)),
            "direct-downgrade",
        ),
    ])
}

fn build_split_write_cases() -> Value {
    Value::Array(vec![
        json!({"name":"before-db-commit","database":"g","external":"g","pending":"none","output_escaped":false,"expected":"serve-base"}),
        json!({"name":"db-advanced-without-candidate","database":"g+1","external":"g","pending":"none","output_escaped":false,"expected":"anchor-conflict"}),
        json!({"name":"after-db-commit-before-cas","database":"g+1","external":"g","pending":"exact-candidate","output_escaped":false,"expected":"repeat-cas-readback"}),
        json!({"name":"after-cas-before-readback","database":"g+1","external":"candidate","pending":"exact-candidate","output_escaped":false,"expected":"mark-published"}),
        json!({"name":"after-readback-before-release","database":"g+1","external":"candidate","pending":"exact-candidate","output_escaped":false,"expected":"mark-published"}),
        json!({"name":"after-response-release","database":"g+1","external":"candidate","pending":"published","output_escaped":true,"expected":"serve-stable-output"}),
        json!({"name":"external-conflict","database":"g+1","external":"conflict","pending":"exact-candidate","output_escaped":false,"expected":"anchor-conflict"}),
        json!({"name":"multiple-candidates","database":"g+1","external":"g","pending":"multiple","output_escaped":false,"expected":"anchor-conflict"}),
        json!({"name":"output-before-anchor","database":"g+1","external":"g","pending":"exact-candidate","output_escaped":true,"expected":"anchor-conflict"}),
    ])
}

fn build_byte_mutations(vectors: &Map<String, Value>) -> AnyResult<Value> {
    let mut mutations = Vec::new();
    for (name, vector) in vectors {
        let Some(signature_hex) = vector["signature_hex"].as_str() else {
            continue;
        };
        let mut signature =
            hex::decode(signature_hex).map_err(|error| format!("signature decode: {error}"))?;
        let first = signature
            .first_mut()
            .ok_or_else(|| format!("empty signature for {name}"))?;
        *first ^= 1;
        mutations.push(json!({
            "name": format!("{name}-signature-bit-0"),
            "source": name,
            "mutation": "signature bit 0 xor 1",
            "mutated_signature_hex": hex_bytes(&signature),
            "expected": "invalid-signature"
        }));
        mutations.push(json!({
            "name": format!("{name}-wrong-domain"),
            "source": name,
            "mutation": "prepend wrong-domain byte to signed preimage",
            "expected": "invalid-signature"
        }));
    }
    mutations.push(json!({
        "name": "capsule-ciphertext-bit-0",
        "source": "construction.capsules[0]",
        "mutation": "ciphertext bit 0 xor 1",
        "expected": "invalid-contribution"
    }));
    mutations.push(json!({
        "name": "witnessed-slot-context-bit-0",
        "source": "construction.witnessed_slot",
        "mutation": "context bit 0 xor 1",
        "expected": "wrong-scope"
    }));
    mutations.push(json!({
        "name": "witnessed-slot-set-bit-0",
        "source": "construction.witnessed_state_digest",
        "mutation": "digest bit 0 xor 1",
        "expected": "wrong-scope"
    }));
    mutations.push(json!({
        "name": "contribution-ciphertext-bit-0",
        "source": "construction.contributions[0]",
        "mutation": "ciphertext bit 0 xor 1",
        "expected": "invalid-contribution"
    }));
    Ok(Value::Array(mutations))
}

pub fn build_corpus() -> AnyResult<Value> {
    let (vectors, construction) = build_protocol_vectors()?;
    let mutations = build_byte_mutations(&vectors)?;
    let counts = run_model_counts();
    Ok(json!({
        "schema": "jury-witness-v1-conformance-corpus",
        "schema_version": 1,
        "status": "pre-alpha-public-generic-fixtures-not-for-real-secrets",
        "construction": "jury-witness-v1-shamir-xwing-hpke",
        "suite": 1,
        "inputs": {
            "j01b_revision": "560897e90fa7a7dc840458285ec64eff53a0a284",
            "j19a_construction_sha256": "23ded2718d4b2bb305a6cd83da246b8cecdd03135b4a8529ecd3ced333b8feac",
            "j19a_threat_model_sha256": "3334eee2c86c07afd5799c1bbfadc4a0fed00eadec86a40f32811a21548ad275",
            "j19b_protocol_sha256": "1e1c23218f668638f8fe6f24e1193f92783c57f2ee8f175a4a1142a8ea934319",
            "j19b_state_machines_sha256": "7cbf65276bb60fbb1a2b72f9d1f12612ccba402de09eee3fb70a320bfdc5ca6f"
        },
        "normalization": {
            "unknown_version_suite_or_construction": "unsupported-version",
            "length_count_order_or_canonical_failure": "invalid",
            "wrong_domain_or_signature": "invalid-signature",
            "request_manifest_or_cross_context_mismatch": "wrong-scope",
            "duplicate_distinct_actor_bytes": "invalid",
            "provider_decapsulation_or_authentication_failure": "invalid-contribution",
            "provider_messages_exposed": false,
            "trailing_bytes_accepted": false
        },
        "vectors": vectors,
        "construction_vector": construction,
        "byte_mutations": mutations,
        "scope_cases": build_scope_cases(),
        "presentation_cases": build_presentation_cases(),
        "protocol_cases": build_protocol_cases(),
        "split_write_cases": build_split_write_cases(),
        "retention_model": {
            "construction_count": 1,
            "witness_count": WITNESS_COUNT,
            "witness_threshold": WITNESS_THRESHOLD,
            "approver_count": APPROVER_COUNT,
            "approver_threshold": APPROVER_THRESHOLD,
            "revision_seals": 2,
            "access_modes": ["witnessed-only", "mixed", "direct-only"],
            "compromised_witness_range": [0, 1, 2, 3],
            "compromised_approver_range": [0, 1, 2],
            "retained_endpoint_state": [
                "long-term requester signing key",
                "prior request session private key",
                "prior requests manifests approvals responses receipts",
                "prior encrypted and plaintext shares",
                "prior revision secret and plaintext",
                "all current and historical public storage"
            ],
            "actor_state": {
                "requester_endpoint": "long-term requester key, prior session keys, all prior public transcripts, opened shares, revision secrets, and plaintext",
                "approver": "separate signing key, current descriptor/policy, private meaningful presentation, and issued decisions",
                "witness": "separate signing and contribution keys, current capsules/checkpoint, replay records, encrypted responses, clock, and anchor candidate",
                "juryd": "the state of exactly its configured witness identity; co-hosted identities count as correlated compromise",
                "storage_and_network": "all public current/historical artifacts and messages, with arbitrary replay, mutation, fork, loss, and reordering"
            },
            "assumptions": [
                "independent per-seal revision secrets coefficients and sessions",
                "honest writer and plaintext boundary",
                "ideal frozen signature hash HPKE storage-AEAD and canonical checks",
                "fewer than the current witness threshold compromised",
                "no active direct slot in the property-bearing item"
            ],
            "excluded_compromises": [
                "threshold witness contribution keys or shares",
                "active direct or mixed access",
                "writer plaintext or target storage key",
                "cryptographic or entropy failure",
                "correlated roles reaching a threshold",
                "combined witness database and external-anchor rollback"
            ],
            "result": {
                "states": counts.states,
                "applicable_states": counts.applicable_states,
                "earlier_reopens": counts.earlier_reopens,
                "old_approval_replay_attempts": counts.old_approval_replay_attempts,
                "old_response_replay_attempts": counts.old_response_replay_attempts,
                "prior_state_authorizations": counts.prior_state_authorizations,
                "later_opens_with_fresh_quorum": counts.later_opens_with_fresh_quorum,
                "excluded_direct_or_mixed": counts.excluded_direct_or_mixed,
                "excluded_witness_threshold": counts.excluded_witness_threshold,
                "authorization_compromise": counts.authorization_compromise,
                "counterexamples": counts.counterexamples
            },
            "claim": "no retained revision-N endpoint state opens revision N+1 without a fresh accepted witness quorum inside the declared property boundary",
            "formal_proof": false,
            "external_review": false
        }
    }))
}

pub fn corpus_bytes() -> AnyResult<Vec<u8>> {
    let mut bytes = serde_json::to_vec_pretty(&build_corpus()?)
        .map_err(|error| format!("serialize corpus: {error}"))?;
    bytes.push(b'\n');
    Ok(bytes)
}

pub fn write_corpus(path: &Path) -> AnyResult<()> {
    fs::write(path, corpus_bytes()?).map_err(|error| format!("write {}: {error}", path.display()))
}

pub fn check_corpus(path: &Path) -> AnyResult<()> {
    let expected = corpus_bytes()?;
    let actual = fs::read(path).map_err(|error| format!("read {}: {error}", path.display()))?;
    if actual == expected {
        Ok(())
    } else {
        Err(format!(
            "{} differs from deterministic generation; inspect the mismatch before --write",
            path.display()
        ))
    }
}

fn string_field<'a>(value: &'a Value, field: &str) -> AnyResult<&'a str> {
    value[field]
        .as_str()
        .ok_or_else(|| format!("missing string field {field}"))
}

fn decode_field(value: &Value, field: &str) -> AnyResult<Vec<u8>> {
    hex::decode(string_field(value, field)?)
        .map_err(|error| format!("decode field {field}: {error}"))
}

pub fn consume_corpus(corpus: &Value) -> AnyResult<()> {
    if corpus["schema"] != "jury-witness-v1-conformance-corpus" || corpus["schema_version"] != 1 {
        return Err("unknown corpus schema".to_owned());
    }
    let vectors = corpus["vectors"]
        .as_object()
        .ok_or_else(|| "vectors must be an object".to_owned())?;
    for (name, vector) in vectors {
        if let Some(signature_hex) = vector["signature_hex"].as_str() {
            let signature_bytes =
                hex::decode(signature_hex).map_err(|error| format!("{name}: {error}"))?;
            let signature = Signature::from_slice(&signature_bytes)
                .map_err(|error| format!("{name}: signature: {error}"))?;
            let public_bytes = decode_field(vector, "signing_public_key_hex")?;
            let public_array: [u8; 32] = public_bytes
                .try_into()
                .map_err(|_| format!("{name}: public key length"))?;
            let public = VerifyingKey::from_bytes(&public_array)
                .map_err(|error| format!("{name}: public key: {error}"))?;
            let preimage = decode_field(vector, "preimage_hex")?;
            public
                .verify(&preimage, &signature)
                .map_err(|error| format!("{name}: signature verification: {error}"))?;
            if let Some(hash_domain) = vector["hash_domain"].as_str() {
                let expected =
                    hash_preimage(hash_domain, &[bytes_field(&preimage)?, signature_bytes]);
                if decode_field(vector, "digest_hex")? != expected {
                    return Err(format!("{name}: signed digest mismatch"));
                }
            }
        }
        if let (Some(_domain), Some(preimage_hex), Some(digest_hex)) = (
            vector["domain"].as_str(),
            vector["preimage_hex"].as_str(),
            vector["digest_hex"].as_str(),
        ) {
            let preimage = hex::decode(preimage_hex).map_err(|error| format!("{name}: {error}"))?;
            if hex_bytes(&sha256(&preimage)) != digest_hex {
                return Err(format!("{name}: digest mismatch"));
            }
        }
        if vector["fingerprint_domain"].is_string() {
            let fingerprint_preimage = decode_field(vector, "fingerprint_preimage_hex")?;
            if sha256(&fingerprint_preimage).as_slice() != decode_field(vector, "fingerprint_hex")?
            {
                return Err(format!("{name}: descriptor fingerprint mismatch"));
            }
        }
    }

    let mutations = corpus["byte_mutations"]
        .as_array()
        .ok_or_else(|| "byte_mutations must be an array".to_owned())?;
    for mutation in mutations {
        let Some(source) = mutation["source"].as_str() else {
            continue;
        };
        let Some(vector) = vectors.get(source) else {
            continue;
        };
        if let Some(mutated_hex) = mutation["mutated_signature_hex"].as_str() {
            let signature_bytes =
                hex::decode(mutated_hex).map_err(|error| format!("mutated signature: {error}"))?;
            let signature = Signature::from_slice(&signature_bytes)
                .map_err(|error| format!("mutated signature: {error}"))?;
            let public_bytes = decode_field(vector, "signing_public_key_hex")?;
            let public_array: [u8; 32] = public_bytes
                .try_into()
                .map_err(|_| "mutated public key length".to_owned())?;
            let public = VerifyingKey::from_bytes(&public_array)
                .map_err(|error| format!("mutated public key: {error}"))?;
            if public
                .verify(&decode_field(vector, "preimage_hex")?, &signature)
                .is_ok()
            {
                return Err(format!("{source}: mutated signature accepted"));
            }
        } else if mutation["mutation"] == "prepend wrong-domain byte to signed preimage" {
            let signature_bytes = decode_field(vector, "signature_hex")?;
            let signature = Signature::from_slice(&signature_bytes)
                .map_err(|error| format!("wrong-domain signature: {error}"))?;
            let public_bytes = decode_field(vector, "signing_public_key_hex")?;
            let public_array: [u8; 32] = public_bytes
                .try_into()
                .map_err(|_| "wrong-domain public key length".to_owned())?;
            let public = VerifyingKey::from_bytes(&public_array)
                .map_err(|error| format!("wrong-domain public key: {error}"))?;
            let mut wrong_preimage = vec![0xff];
            wrong_preimage.extend(decode_field(vector, "preimage_hex")?);
            if public.verify(&wrong_preimage, &signature).is_ok() {
                return Err(format!("{source}: wrong domain accepted"));
            }
        }
    }

    consume_construction(&corpus["construction_vector"])?;
    consume_registration(vectors)?;
    consume_cases(corpus)?;
    Ok(())
}

fn decode_string_array(value: &Value) -> AnyResult<Vec<Vec<u8>>> {
    value
        .as_array()
        .ok_or_else(|| "expected string array".to_owned())?
        .iter()
        .map(|entry| {
            let encoded = entry
                .as_str()
                .ok_or_else(|| "array entry must be a string".to_owned())?;
            hex::decode(encoded).map_err(|error| format!("array hex: {error}"))
        })
        .collect()
}

fn consume_construction(construction: &Value) -> AnyResult<()> {
    if construction["epoch_root"] != Value::Null || construction["reusable_contribution"] != false {
        return Err("construction exposes reusable material".to_owned());
    }
    let secret = decode_field(construction, "revision_secret_hex")?;
    let shares = decode_string_array(&construction["shares"])?;
    let reconstructed = Gf256::combine_bytes(&shares[0..WITNESS_THRESHOLD])
        .map_err(|error| format!("consumer combine: {error:?}"))?;
    if reconstructed != secret {
        return Err("consumer reconstruction mismatch".to_owned());
    }
    if let Ok(one_share) = Gf256::combine_bytes(std::slice::from_ref(&shares[0]))
        && one_share == secret
    {
        return Err("one share reconstructed threshold secret".to_owned());
    }

    let later = &construction["later_revision"];
    let later_secret = decode_field(later, "revision_secret_hex")?;
    let later_shares = decode_string_array(&later["shares"])?;
    let later_reconstructed = Gf256::combine_bytes(&later_shares[0..WITNESS_THRESHOLD])
        .map_err(|error| format!("consumer later combine: {error:?}"))?;
    if later_reconstructed != later_secret
        || decode_field(later, "cross_revision_share_result_hex")? == later_secret
    {
        return Err("later revision separation failed".to_owned());
    }

    let capsules = construction["capsules"]
        .as_array()
        .ok_or_else(|| "capsules must be an array".to_owned())?;
    for (index, capsule) in capsules.iter().enumerate() {
        let plaintext = hpke_open(
            &decode_field(capsule, "recipient_private_seed_hex")?,
            &decode_field(capsule, "enc_hex")?,
            &decode_field(capsule, "ciphertext_hex")?,
            &decode_field(capsule, "info_hex")?,
            &decode_field(capsule, "aad_hex")?,
        )?;
        if plaintext != shares[index] {
            return Err(format!("capsule {index}: wrong share"));
        }
        let expected_commitment = hash_preimage(
            "jury-witness-v1/share/commitment",
            &[
                decode_field(capsule, "context_digest_hex")?,
                plaintext.clone(),
            ],
        );
        if expected_commitment.as_slice() != decode_field(capsule, "share_commitment_hex")? {
            return Err(format!("capsule {index}: commitment mismatch"));
        }
        let mut ciphertext = decode_field(capsule, "ciphertext_hex")?;
        let first = ciphertext
            .first_mut()
            .ok_or_else(|| format!("capsule {index}: empty ciphertext"))?;
        *first ^= 1;
        if hpke_open(
            &decode_field(capsule, "recipient_private_seed_hex")?,
            &decode_field(capsule, "enc_hex")?,
            &ciphertext,
            &decode_field(capsule, "info_hex")?,
            &decode_field(capsule, "aad_hex")?,
        )
        .is_ok()
        {
            return Err(format!("capsule {index}: mutation opened"));
        }
    }
    let capsule_bytes = capsules
        .iter()
        .map(|capsule| decode_field(capsule, "capsule_hex"))
        .collect::<AnyResult<Vec<_>>>()?;
    let expected_capsule_set = hash_preimage(
        "jury-witness-v1/capsule-set/hash",
        &[list_bytes(&capsule_bytes)?],
    );
    if expected_capsule_set.as_slice() != decode_field(construction, "capsule_set_digest_hex")?
    {
        return Err("capsule-set digest mismatch".to_owned());
    }
    let witnessed_slot = decode_field(construction, "witnessed_slot_hex")?;
    let expected_slot_digest = hash_preimage(
        "jury-witness-v1/slot/hash",
        &[bytes_field(&witnessed_slot)?],
    );
    if expected_slot_digest.as_slice()
        != decode_field(construction, "witnessed_slot_digest_hex")?
    {
        return Err("witnessed-slot digest mismatch".to_owned());
    }
    let expected_state_digest = hash_preimage(
        "jury-witness-v1/slot-set/hash",
        &[list_bytes(std::slice::from_ref(&witnessed_slot))?],
    );
    if expected_state_digest.as_slice()
        != decode_field(construction, "witnessed_state_digest_hex")?
    {
        return Err("witnessed-state digest mismatch".to_owned());
    }

    let contributions = construction["contributions"]
        .as_array()
        .ok_or_else(|| "contributions must be an array".to_owned())?;
    let mut opened = Vec::new();
    for (index, contribution) in contributions.iter().enumerate() {
        let plaintext = hpke_open(
            &decode_field(contribution, "request_session_private_seed_hex")?,
            &decode_field(contribution, "enc_hex")?,
            &decode_field(contribution, "ciphertext_hex")?,
            &decode_field(contribution, "info_hex")?,
            &decode_field(contribution, "aad_hex")?,
        )?;
        if plaintext != decode_field(contribution, "plaintext_share_hex")? {
            return Err(format!("contribution {index}: wrong share"));
        }
        let envelope = decode_field(contribution, "envelope_hex")?;
        let digest = hash_preimage(
            "jury-witness-v1/contribution/hash",
            &[bytes_field(&envelope)?],
        );
        if digest.as_slice() != decode_field(contribution, "digest_hex")? {
            return Err(format!("contribution {index}: digest mismatch"));
        }
        opened.push(plaintext);
        let mut ciphertext = decode_field(contribution, "ciphertext_hex")?;
        let first = ciphertext
            .first_mut()
            .ok_or_else(|| format!("contribution {index}: empty ciphertext"))?;
        *first ^= 1;
        if hpke_open(
            &decode_field(contribution, "request_session_private_seed_hex")?,
            &decode_field(contribution, "enc_hex")?,
            &ciphertext,
            &decode_field(contribution, "info_hex")?,
            &decode_field(contribution, "aad_hex")?,
        )
        .is_ok()
        {
            return Err(format!("contribution {index}: mutation opened"));
        }
    }
    let assembled = Gf256::combine_bytes(opened)
        .map_err(|error| format!("consumer contribution assembly: {error:?}"))?;
    if assembled != secret {
        return Err("consumer contribution assembly mismatch".to_owned());
    }
    Ok(())
}

fn consume_registration(vectors: &Map<String, Value>) -> AnyResult<()> {
    let vector = vectors
        .get("registration_key_proof")
        .ok_or_else(|| "missing registration key proof".to_owned())?;
    let plaintext = hpke_open(
        &decode_field(vector, "recipient_private_seed_hex")?,
        &decode_field(vector, "enc_hex")?,
        &decode_field(vector, "ciphertext_hex")?,
        &decode_field(vector, "info_hex")?,
        &decode_field(vector, "aad_hex")?,
    )?;
    if plaintext != decode_field(vector, "plaintext_hex")? {
        return Err("registration challenge plaintext mismatch".to_owned());
    }
    let mut mac = Hmac::<Sha256>::new_from_slice(&plaintext)
        .map_err(|error| format!("registration HMAC key: {error}"))?;
    mac.update(&decode_field(vector, "hmac_data_hex")?);
    let expected = mac.finalize().into_bytes();
    if expected.as_slice() != decode_field(vector, "hmac_hex")? {
        return Err("registration HMAC mismatch".to_owned());
    }
    Ok(())
}

fn consume_cases(corpus: &Value) -> AnyResult<()> {
    let scope_cases = corpus["scope_cases"]
        .as_array()
        .ok_or_else(|| "scope cases must be an array".to_owned())?;
    for case in scope_cases {
        let request: BTreeMap<String, String> = serde_json::from_value(case["request"].clone())
            .map_err(|error| format!("scope request: {error}"))?;
        let manifest: BTreeMap<String, String> =
            serde_json::from_value(case["manifest"].clone())
                .map_err(|error| format!("scope manifest: {error}"))?;
        if scope_result(&request, &manifest) != string_field(case, "expected")? {
            return Err(format!(
                "scope case {} disagreed",
                string_field(case, "name")?
            ));
        }
    }
    for case in corpus["presentation_cases"]
        .as_array()
        .ok_or_else(|| "presentation cases must be an array".to_owned())?
    {
        if presentation_result(case) != string_field(case, "expected")? {
            return Err(format!(
                "presentation case {} disagreed",
                string_field(case, "name")?
            ));
        }
    }
    for case in corpus["protocol_cases"]
        .as_array()
        .ok_or_else(|| "protocol cases must be an array".to_owned())?
    {
        if protocol_case_result(case) != string_field(case, "expected")? {
            return Err(format!(
                "protocol case {} disagreed",
                string_field(case, "name")?
            ));
        }
    }
    for case in corpus["split_write_cases"]
        .as_array()
        .ok_or_else(|| "split-write cases must be an array".to_owned())?
    {
        if split_write_result(case) != string_field(case, "expected")? {
            return Err(format!(
                "split-write case {} disagreed",
                string_field(case, "name")?
            ));
        }
    }
    let counts = run_model_counts();
    let result = &corpus["retention_model"]["result"];
    for (name, actual) in [
        ("states", counts.states),
        ("applicable_states", counts.applicable_states),
        ("earlier_reopens", counts.earlier_reopens),
        (
            "old_approval_replay_attempts",
            counts.old_approval_replay_attempts,
        ),
        (
            "old_response_replay_attempts",
            counts.old_response_replay_attempts,
        ),
        (
            "prior_state_authorizations",
            counts.prior_state_authorizations,
        ),
        (
            "later_opens_with_fresh_quorum",
            counts.later_opens_with_fresh_quorum,
        ),
        ("excluded_direct_or_mixed", counts.excluded_direct_or_mixed),
        (
            "excluded_witness_threshold",
            counts.excluded_witness_threshold,
        ),
        ("authorization_compromise", counts.authorization_compromise),
        ("counterexamples", counts.counterexamples),
    ] {
        if result[name].as_u64() != Some(actual) {
            return Err(format!("model count {name} disagreed"));
        }
    }
    if counts.counterexamples != 0 || counts.prior_state_authorizations != 0 {
        return Err(format!(
            "retention model found {} decryption and {} authorization counterexamples",
            counts.counterexamples, counts.prior_state_authorizations
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checked_in_corpus_matches_generation_and_consumes() -> Result<(), String> {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("vectors.json");
        check_corpus(&path)?;
        let bytes = fs::read(&path).map_err(|error| format!("read corpus: {error}"))?;
        let corpus: Value =
            serde_json::from_slice(&bytes).map_err(|error| format!("parse corpus: {error}"))?;
        consume_corpus(&corpus)
    }
}
