use super::*;
use jury_core::{
    witness_operations::{CheckpointPropagationPhase, verify_checkpoint_propagation},
    witness_receipt::ReceiptPolicyMaterialV1,
};
use jury_protocol::witness_v1::{
    RegistrationBytes, VaultPolicyCheckpointV1, WitnessCheckpointAcknowledgementV1,
};
use serde::{Deserialize, Serialize};

#[path = "rollover/candidate.rs"]
mod candidate;

#[derive(Serialize)]
struct Registration {
    policy_material: ReceiptPolicyMaterialV1,
    accepted_registration: RegistrationBytes,
    checkpoint: VaultPolicyCheckpointV1,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Accepted {
    status: String,
    durability: String,
    global_freshness_claimed: bool,
    acknowledgement: WitnessCheckpointAcknowledgementV1,
}

#[test]
fn rollover_registration_survives_real_service_and_anchor_restarts() -> TestResult {
    let _process_test = PROCESS_TEST_LOCK
        .lock()
        .map_err(|_| "process-test lock poisoned")?;
    let fixture = tempfile::tempdir()?;
    let root = fixture.path();
    fs::set_permissions(root, fs::Permissions::from_mode(0o700))?;
    let identity_file = root.join("ExampleWitness.identity.json");
    let witness_id = create_witness_identity(&identity_file)?;
    let registration = candidate::prepare(&identity_file)?;
    let original = serde_json::to_vec(&registration)?;
    let (anchor_port, witness_port) = two_unused_ports()?;
    let anchor_base = format!("https://127.0.0.1:{anchor_port}");
    let witness_base = format!("https://127.0.0.1:{witness_port}");
    let (anchor_config, witness_config) =
        configurations(root, witness_id, &identity_file, anchor_port, witness_port)?;
    let executable = env!("CARGO_BIN_EXE_juryd");
    run_success(executable, &["anchor", "init", "--config"], &anchor_config)?;
    run_success(
        executable,
        &["database", "init", "--config"],
        &witness_config,
    )?;
    let prior_database = root.join("ExamplePriorWitness.sqlite3");
    rusqlite::Connection::open(root.join("witness.sqlite3"))?.backup(
        "main",
        &prior_database,
        None,
    )?;
    fs::set_permissions(&prior_database, fs::Permissions::from_mode(0o600))?;
    let client = Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(&fs::read(
            root.join("ExampleCa.pem"),
        )?)?)
        .no_proxy()
        .timeout(Duration::from_secs(10))
        .build()?;
    let mut anchor =
        ProcessGuard::spawn(executable, &["anchor", "serve", "--config"], &anchor_config)?;
    wait_ready(&client, &format!("{anchor_base}/readyz"), &mut anchor)?;
    let mut witness = ProcessGuard::spawn(executable, &["serve", "--config"], &witness_config)?;
    wait_ready(&client, &format!("{witness_base}/readyz"), &mut witness)?;
    let url = format!("{witness_base}/v1/operator/register");
    let wrong = client
        .post(&url)
        .bearer_auth(CLIENT_TOKEN)
        .json(&registration)
        .send()?;
    assert_eq!(wrong.status(), StatusCode::UNAUTHORIZED);

    // With the real external anchor unavailable, registration must not return
    // a durable acknowledgement. The pending database write may survive.
    anchor.stop_abruptly()?;
    let unavailable = client
        .post(&url)
        .bearer_auth(OPERATOR_TOKEN)
        .json(&registration)
        .send()?;
    assert_eq!(unavailable.status(), StatusCode::SERVICE_UNAVAILABLE);
    witness.stop_abruptly()?;
    anchor = ProcessGuard::spawn(executable, &["anchor", "serve", "--config"], &anchor_config)?;
    wait_ready(&client, &format!("{anchor_base}/readyz"), &mut anchor)?;
    witness = ProcessGuard::spawn(executable, &["serve", "--config"], &witness_config)?;
    wait_ready(&client, &format!("{witness_base}/readyz"), &mut witness)?;
    let first = register(&client, &url, &registration)?;
    assert_anchor(&client, &anchor_base, &first)?;

    // Kill both real processes after acknowledgement, then reopen both actual
    // SQLite stores. No fixture database or anchor snapshots are substituted.
    witness.stop_abruptly()?;
    anchor.stop_abruptly()?;
    anchor = ProcessGuard::spawn(executable, &["anchor", "serve", "--config"], &anchor_config)?;
    wait_ready(&client, &format!("{anchor_base}/readyz"), &mut anchor)?;
    witness = ProcessGuard::spawn(executable, &["serve", "--config"], &witness_config)?;
    wait_ready(&client, &format!("{witness_base}/readyz"), &mut witness)?;
    assert_anchor(&client, &anchor_base, &first)?;
    let retried = register(&client, &url, &registration)?;
    assert_eq!(retried.checkpoint_digest, first.checkpoint_digest);
    assert_eq!(retried.vault_id, first.vault_id);
    assert_eq!(retried.vault_policy_sequence, 1);
    assert_anchor(&client, &anchor_base, &retried)?;
    assert_eq!(serde_json::to_vec(&registration)?, original);

    // Restore only the witness's actual SQLite database to its earlier state;
    // the separate live anchor retains the acknowledged registration. A retry
    // of the same valid candidate must not erase this rollback discrepancy.
    witness.stop_abruptly()?;
    {
        let mut database = rusqlite::Connection::open(root.join("witness.sqlite3"))?;
        database.restore(
            "main",
            &prior_database,
            None::<fn(rusqlite::backup::Progress)>,
        )?;
    }
    witness = ProcessGuard::spawn(executable, &["serve", "--config"], &witness_config)?;
    wait_ready(&client, &format!("{witness_base}/livez"), &mut witness)?;
    wait_not_ready(&client, &format!("{witness_base}/readyz"), &mut witness)?;
    let rolled_back = client
        .post(&url)
        .bearer_auth(OPERATOR_TOKEN)
        .json(&registration)
        .send()?;
    assert_eq!(rolled_back.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let refusal: serde_json::Value = rolled_back.json()?;
    assert_eq!(
        refusal,
        json!({"status": "refused", "reason": {"protocol": "anchor-conflict"}})
    );
    assert_anchor(&client, &anchor_base, &retried)?;
    witness.stop_gracefully()?;
    anchor.stop_gracefully()?;
    Ok(())
}

fn register(
    client: &Client,
    url: &str,
    registration: &Registration,
) -> Result<WitnessCheckpointAcknowledgementV1, Box<dyn Error>> {
    let response = client
        .post(url)
        .bearer_auth(OPERATOR_TOKEN)
        .json(registration)
        .send()?;
    assert_eq!(response.status(), StatusCode::OK);
    let accepted: Accepted = serde_json::from_slice(&response.bytes()?)?;
    assert_eq!(accepted.status, "accepted");
    assert_eq!(
        accepted.durability,
        "witness-database-and-external-anchor-readback"
    );
    assert!(!accepted.global_freshness_claimed);
    let status = verify_checkpoint_propagation(
        &registration.policy_material.replay()?,
        &registration.checkpoint,
        std::slice::from_ref(&accepted.acknowledgement),
    )?;
    // This test operates one of the two required witnesses. Its real durability
    // is evidence for that endpoint, never a complete quorum/readiness claim.
    assert_eq!(
        status.phase,
        CheckpointPropagationPhase::PartiallyPropagated
    );
    assert_eq!(status.expected_witness_count, 2);
    assert_eq!(status.acknowledged_witness_count, 1);
    assert!(!status.global_freshness_claimed);
    Ok(accepted.acknowledgement)
}

fn assert_anchor(
    client: &Client,
    base: &str,
    ack: &WitnessCheckpointAcknowledgementV1,
) -> TestResult {
    let response = client
        .get(format!("{base}/v1/anchors/{}", hex_id(&ack.witness_id)))
        .send()?
        .error_for_status()?;
    let saved: WitnessStateAnchorV1 = serde_json::from_slice(&response.bytes()?)?;
    assert_eq!(saved, ack.exact_anchor);
    Ok(())
}

fn configurations(
    root: &Path,
    witness_id: PrincipalId,
    identity: &Path,
    anchor_port: u16,
    witness_port: u16,
) -> Result<(std::path::PathBuf, std::path::PathBuf), Box<dyn Error>> {
    let anchor_token = root.join("anchor.token");
    let operator_token = root.join("operator.token");
    let client_token = root.join("client.token");
    let passphrase = root.join("identity.passphrase");
    write_file(&anchor_token, ANCHOR_TOKEN.as_bytes(), 0o600)?;
    write_file(&operator_token, OPERATOR_TOKEN.as_bytes(), 0o600)?;
    write_file(&client_token, CLIENT_TOKEN.as_bytes(), 0o600)?;
    write_file(&passphrase, PASSPHRASE, 0o600)?;
    let anchor_config = root.join("anchor.json");
    let witness_config = root.join("witness.json");
    let authority = |prefix: &str| {
        json!({
            "administration_authority": format!("{prefix}-admin"),
            "backup_authority": format!("{prefix}-backup"),
            "restore_authority": format!("{prefix}-restore"),
            "failure_domain": format!("{prefix}-host")
        })
    };
    let certificate = root.join("ExampleCa.pem");
    let private_key = root.join("ExampleTls.key");
    let CertifiedKey { cert, signing_key } = generate_simple_self_signed(vec!["127.0.0.1".into()])?;
    write_file(&certificate, cert.pem().as_bytes(), 0o644)?;
    write_file(&private_key, signing_key.serialize_pem().as_bytes(), 0o600)?;
    let tls = json!({"certificate_file": certificate, "private_key_file": private_key, "allow_insecure_loopback": false});
    write_json(
        &anchor_config,
        &json!({
            "schema": 1, "witness_id": witness_id, "listen": format!("127.0.0.1:{anchor_port}"),
            "tls": tls,
            "database": {"path": root.join("anchor.sqlite3"), "authority": authority("anchor")},
            "write_credential_file": anchor_token, "write_authority": "anchor-writer", "limits": anchor_limits()
        }),
    )?;
    write_json(
        &witness_config,
        &json!({
            "schema": 1, "witness_id": witness_id, "listen": format!("127.0.0.1:{witness_port}"),
            "tls": tls,
            "identity": {"provider": "software-file", "identity_file": identity, "passphrase_file": passphrase},
            "database": {"path": root.join("witness.sqlite3"), "authority": authority("witness-db")},
            "external_anchor": {
                "base_url": format!("https://127.0.0.1:{anchor_port}/"), "ca_certificate_file": certificate,
                "write_credential_file": anchor_token, "write_authority": "anchor-writer",
                "authority": authority("anchor"), "allow_insecure_loopback": false
            },
            "client_credential_file": client_token, "operator_credential_file": operator_token,
            "limits": anchor_limits()
        }),
    )?;
    Ok((anchor_config, witness_config))
}
