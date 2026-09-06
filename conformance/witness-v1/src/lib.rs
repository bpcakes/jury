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

mod cases;
mod consumer;
mod vectors;

use cases::*;
use vectors::build_protocol_vectors;

pub use cases::protocol_case_result;
pub use consumer::consume_corpus;

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

fn active_policy_set_vector(name: &str, digests: &[Vec<u8>]) -> AnyResult<Value> {
    if digests.len() > 16_384
        || digests
            .iter()
            .any(|d| d.len() != 32 || d.iter().all(|b| *b == 0))
        || digests.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return Err("invalid active policy set".to_owned());
    }
    let mut body = u32be(u32::try_from(digests.len()).map_err(|_| "policy set count")?);
    body.extend(digests.concat());
    let domain = "jury-witness-v1/active-policy-set/hash";
    let preimage = jce(domain, std::slice::from_ref(&body));
    Ok(
        json!({"name": name, "kind": "active-policy-set", "domain": domain,
        "policy_digests_hex": digests.iter().map(|d| hex_bytes(d)).collect::<Vec<_>>(),
        "body_hex": hex_bytes(&body), "preimage_hex": hex_bytes(&preimage),
        "digest_hex": hex_bytes(&sha256(&preimage)), "expected": "accepted"}),
    )
}

fn owner_change_context_vector(
    name: &str,
    change: u8,
    target: &[u8],
    sequence: u64,
) -> AnyResult<Value> {
    if !matches!(change, 1 | 2)
        || target.len() != 32
        || target.iter().all(|b| *b == 0)
        || sequence == 0
    {
        return Err("invalid owner-change context".to_owned());
    }
    let body = [u16be(1), vec![change], target.to_vec(), u64be(sequence)].concat();
    let domain = "jury-witness-v1/operation-context/owner-change";
    let preimage = jce(domain, std::slice::from_ref(&body));
    Ok(
        json!({"name": name, "kind": "owner-change-context", "domain": domain,
        "change": change, "target_principal_id_hex": hex_bytes(target), "next_sequence": sequence,
        "body_hex": hex_bytes(&body), "preimage_hex": hex_bytes(&preimage),
        "digest_hex": hex_bytes(&sha256(&preimage)), "expected": "accepted"}),
    )
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

fn automatic_targets_match(case: &Value) -> bool {
    let Some(allowed) = case["automatic_targets"].as_array() else {
        return false;
    };
    let Some(requested) = case["manifest_targets"].as_array() else {
        return false;
    };
    if allowed.is_empty() || requested.is_empty() {
        return false;
    }
    let valid = |target: &Value| {
        target["item_id"].as_str().is_some_and(|id| !id.is_empty())
            && match target["content_role"].as_str() {
                Some("descriptor") => target.get("field_id").is_some_and(Value::is_null),
                Some("body") => target["field_id"].as_str().is_some_and(|id| !id.is_empty()),
                _ => false,
            }
    };
    allowed.iter().all(valid)
        && requested
            .iter()
            .all(|target| valid(target) && allowed.contains(target))
}

pub fn presentation_result(case: &Value) -> &'static str {
    let human = case["human"].as_bool().unwrap_or(false);
    if !human {
        return if automatic_targets_match(case)
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
            "j19b_protocol_sha256": "7672a3d4449835955c037e9477f195c93a2ab47ef1647afeb92d68cb2794838c",
            "j19b_state_machines_sha256": "ddf06ee1a6ad2268c8cb4cd480f9e0daae6009720ba6da38cd23761635bbf6fc"
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
