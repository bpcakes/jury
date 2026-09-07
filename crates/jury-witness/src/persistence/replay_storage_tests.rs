use jury_core::witness_engine::WitnessReplayEntry;
use jury_protocol::{
    vault_v1::{RequestId, Signature64},
    witness_v1::{REPLAY_RETENTION_MS, WitnessRequestV1, WitnessStateAnchorV1},
};

use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn request() -> Result<WitnessRequestV1, Box<dyn std::error::Error>> {
    // Reuse a frozen public protocol vector, not a private identity fixture.
    let corpus: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../conformance/witness-v1/vectors.json"
    ))?;
    let vector = &corpus["vectors"]["witness_request"];
    let decode = |key: &str| -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let text = vector[key].as_str().ok_or("missing vector bytes")?;
        (0..text.len())
            .step_by(2)
            .map(|offset| Ok(u8::from_str_radix(&text[offset..offset + 2], 16)?))
            .collect()
    };
    Ok(WitnessRequestV1::from_signature_preimage(
        &decode("preimage_hex")?,
        Signature64::new(
            decode("signature_hex")?
                .try_into()
                .map_err(|_| "signature length")?,
        ),
    )?)
}

fn populated_state() -> Result<PersistedWitnessState, Box<dyn std::error::Error>> {
    let request = request()?;
    let witness_id = request.intended_witness_set[0].witness_id;
    let mut state = PersistedWitnessState::empty(witness_id);
    state.logical.state_generation = 1;
    state.logical.last_accepted_wall_time_ms = request.issued_at_ms;
    let retained = request.expires_at_ms + REPLAY_RETENTION_MS;
    state.logical.replay.insert(
        (request.vault_id, request.request_id),
        WitnessReplayEntry {
            action_manifest_digest: request.action_manifest_digest.clone(),
            request,
            state: ReplayStateV1::Reserved,
            retain_through_ms: retained,
            approvals: vec![],
            cancellation: None,
            response: None,
        },
    );
    // This test exercises storage, not signature verification. Actual signed
    // service behavior is checked by the Linux witness lifecycle test.
    state.pending_anchor = Some(WitnessStateAnchorV1 {
        schema: 1,
        witness_id,
        witness_signing_key_fingerprint: Digest32::new([2; 32]),
        witness_signing_key_epoch: 1,
        state_generation: 1,
        database_state_digest: Digest32::new([3; 32]),
        vault_high_watermarks: vec![],
        replay_retain_through_ms: retained,
        last_accepted_wall_time_ms: state.logical.last_accepted_wall_time_ms,
        predecessor_anchor_digest: Digest32::new([0; 32]),
        issued_at_ms: state.logical.last_accepted_wall_time_ms,
        signature: Signature64::new([4; 64]),
    });
    Ok(state)
}

#[test]
fn nonempty_replay_survives_sqlite_reopen_backup_and_restore() -> TestResult {
    let directory = tempfile::tempdir()?;
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
    let source = directory.path().join("ExampleWitness.sqlite3");
    let backup = directory.path().join("ExampleBackup.sqlite3");
    let restored = directory.path().join("ExampleRestored.sqlite3");
    let expected = populated_state()?;
    let witness_id = expected.logical.witness_id;
    SqliteWitnessStore::initialize(&source, witness_id)?;
    let mut store = SqliteWitnessStore::open(&source, witness_id)?;
    store
        .commit(0, expected.clone())
        .map_err(|_| "replay commit failed")?;
    drop(store);
    assert_eq!(
        SqliteWitnessStore::open(&source, witness_id)?.load_validated()?,
        expected
    );
    backup_witness_database(&source, &backup)?;
    restore_witness_database(&backup, &restored)?;
    assert_eq!(
        SqliteWitnessStore::open(&restored, witness_id)?.load_validated()?,
        expected
    );
    Ok(())
}

#[test]
fn empty_snapshots_use_record_lists_and_reject_old_object_format() -> TestResult {
    let state = PersistedWitnessState::empty(PrincipalId::from_bytes([1; 32])?);
    let bytes = persisted_json::encode(&state).map_err(|_| "encode failed")?;
    let document: serde_json::Value = serde_json::from_slice(&bytes)?;
    assert_eq!(document["logical"]["replay"], serde_json::json!([]));
    assert_eq!(persisted_json::decode(&bytes), Ok(state.clone()));
    let old_object_format = serde_json::to_vec(&state)?;
    assert!(persisted_json::decode(&old_object_format).is_err());
    Ok(())
}

#[test]
fn malformed_replay_cannot_be_silently_dropped_or_overwritten() -> TestResult {
    let state = populated_state()?;
    let bytes = persisted_json::encode(&state).map_err(|_| "encode failed")?;
    let mut document: serde_json::Value = serde_json::from_slice(&bytes)?;
    let record = document["logical"]["replay"][0].clone();
    for replacement in [
        serde_json::json!([record.clone(), record]),
        serde_json::json!({"invalid": {}}),
        serde_json::Value::Null,
    ] {
        document["logical"]["replay"] = replacement;
        assert!(persisted_json::decode(&serde_json::to_vec(&document)?).is_err());
    }
    let mut mismatched = state;
    let (key, record) = mismatched
        .logical
        .replay
        .pop_first()
        .ok_or("missing replay")?;
    mismatched
        .logical
        .replay
        .insert((key.0, RequestId::from_bytes([99; 32])?), record);
    assert!(persisted_json::encode(&mismatched).is_err());
    Ok(())
}
