#![cfg(target_os = "linux")]

use std::{
    error::Error,
    fs,
    io::{ErrorKind, Read as _, Write as _},
    net::{TcpListener, TcpStream},
    os::unix::fs::PermissionsExt as _,
    path::Path,
    process::{Child, Command, Stdio},
    sync::Mutex,
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use jury_core::identity::IdentityCreator;
use jury_protected::{ProtectedMemory, ProtectionPolicy};
use jury_protocol::{
    identity_v1::KdfProfile,
    vault_v1::{Digest32, PrincipalId, PrincipalKind, Signature64},
    witness_v1::WitnessStateAnchorV1,
};
use rcgen::{CertifiedKey, generate_simple_self_signed};
use reqwest::{StatusCode, blocking::Client};
use rustix::process::{Pid, Signal, kill_process};
use serde_json::json;

type TestResult = Result<(), Box<dyn Error>>;

const CLIENT_TOKEN: &str = "ExampleClientCredential_0123456789abcdef";
const OPERATOR_TOKEN: &str = "ExampleOperatorCredential_0123456789abcdef";
const ANCHOR_TOKEN: &str = "ExampleAnchorCredential_0123456789abcdef";
const PASSPHRASE: &[u8] = b"ExampleWitnessPassphrase";
static PROCESS_TEST_LOCK: Mutex<()> = Mutex::new(());

#[test]
fn documented_loopback_services_are_bounded_safe_and_graceful() -> TestResult {
    let _process_test = PROCESS_TEST_LOCK
        .lock()
        .map_err(|_| "process-test lock is poisoned")?;
    let fixture = tempfile::tempdir()?;
    fs::set_permissions(fixture.path(), fs::Permissions::from_mode(0o700))?;
    let (anchor_port, witness_port) = two_unused_ports()?;
    let certificate = fixture.path().join("ExampleCa.pem");
    let private_key = fixture.path().join("ExampleTls.key");
    let CertifiedKey { cert, signing_key } =
        generate_simple_self_signed(vec!["127.0.0.1".to_owned()])?;
    write_file(&certificate, cert.pem().as_bytes(), 0o644)?;
    write_file(&private_key, signing_key.serialize_pem().as_bytes(), 0o600)?;

    let anchor_token = fixture.path().join("anchor.token");
    let client_token = fixture.path().join("client.token");
    let operator_token = fixture.path().join("operator.token");
    write_file(&anchor_token, ANCHOR_TOKEN.as_bytes(), 0o600)?;
    write_file(&client_token, CLIENT_TOKEN.as_bytes(), 0o600)?;
    write_file(&operator_token, OPERATOR_TOKEN.as_bytes(), 0o600)?;

    let identity_file = fixture.path().join("ExampleWitness.identity.json");
    let passphrase_file = fixture.path().join("identity.passphrase");
    let witness_id = create_witness_identity(&identity_file)?;
    write_file(&passphrase_file, PASSPHRASE, 0o600)?;

    let anchor_database = fixture.path().join("anchor.sqlite3");
    let witness_database = fixture.path().join("witness.sqlite3");
    let anchor_config = fixture.path().join("anchor.json");
    let witness_config = fixture.path().join("witness.json");
    write_json(
        &anchor_config,
        &json!({
            "schema": 1,
            "witness_id": witness_id,
            "listen": format!("127.0.0.1:{anchor_port}"),
            "tls": {
                "certificate_file": certificate,
                "private_key_file": private_key,
                "allow_insecure_loopback": false
            },
            "database": {
                "path": anchor_database,
                "authority": {
                    "administration_authority": "anchor-admin",
                    "backup_authority": "anchor-backup",
                    "restore_authority": "anchor-restore",
                    "failure_domain": "anchor-host"
                }
            },
            "write_credential_file": anchor_token,
            "write_authority": "anchor-writer",
            "limits": anchor_limits()
        }),
    )?;
    write_json(
        &witness_config,
        &json!({
            "schema": 1,
            "witness_id": witness_id,
            "listen": format!("127.0.0.1:{witness_port}"),
            "tls": {
                "certificate_file": certificate,
                "private_key_file": private_key,
                "allow_insecure_loopback": false
            },
            "identity": {
                "provider": "software-file",
                "identity_file": identity_file,
                "passphrase_file": passphrase_file
            },
            "database": {
                "path": witness_database,
                "authority": {
                    "administration_authority": "witness-db-admin",
                    "backup_authority": "witness-db-backup",
                    "restore_authority": "witness-db-restore",
                    "failure_domain": "witness-host"
                }
            },
            "external_anchor": {
                "base_url": format!("https://127.0.0.1:{anchor_port}/"),
                "ca_certificate_file": certificate,
                "write_credential_file": anchor_token,
                "write_authority": "anchor-writer",
                "authority": {
                    "administration_authority": "anchor-admin",
                    "backup_authority": "anchor-backup",
                    "restore_authority": "anchor-restore",
                    "failure_domain": "anchor-host"
                },
                "allow_insecure_loopback": false
            },
            "client_credential_file": client_token,
            "operator_credential_file": operator_token,
            "limits": limits()
        }),
    )?;

    let executable = env!("CARGO_BIN_EXE_juryd");
    run_success(executable, &["anchor", "init", "--config"], &anchor_config)?;
    run_success(
        executable,
        &["database", "init", "--config"],
        &witness_config,
    )?;
    assert_initial_audit(executable, &witness_config, fixture.path())?;
    let mut anchor =
        ProcessGuard::spawn(executable, &["anchor", "serve", "--config"], &anchor_config)?;
    let certificate_bytes = fs::read(&certificate)?;
    let client = Client::builder()
        .no_proxy()
        .add_root_certificate(reqwest::Certificate::from_pem(&certificate_bytes)?)
        .timeout(Duration::from_secs(2))
        .build()?;
    wait_ready(
        &client,
        &format!("https://127.0.0.1:{anchor_port}/readyz"),
        &mut anchor,
    )?;
    let foreign_witness_id = PrincipalId::from_bytes([8; 32])?;
    let foreign_anchor = WitnessStateAnchorV1 {
        schema: 1,
        witness_id: foreign_witness_id,
        witness_signing_key_fingerprint: Digest32::new([8; 32]),
        witness_signing_key_epoch: 1,
        state_generation: 1,
        database_state_digest: Digest32::new([8; 32]),
        vault_high_watermarks: Vec::new(),
        replay_retain_through_ms: 0,
        last_accepted_wall_time_ms: 1,
        predecessor_anchor_digest: Digest32::new([0; 32]),
        issued_at_ms: 1,
        signature: Signature64::new([8; 64]),
    };
    let foreign_path = format!(
        "https://127.0.0.1:{anchor_port}/v1/anchors/{}",
        hex_id(&foreign_witness_id)
    );
    assert_eq!(
        client.get(&foreign_path).send()?.status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        client
            .post(&foreign_path)
            .bearer_auth(ANCHOR_TOKEN)
            .json(&json!({
                "expected_anchor_digest": null,
                "next_exact_anchor": foreign_anchor
            }))
            .send()?
            .status(),
        StatusCode::BAD_REQUEST
    );
    let mut witness = ProcessGuard::spawn(executable, &["serve", "--config"], &witness_config)?;
    let witness_base = format!("https://127.0.0.1:{witness_port}");
    wait_ready(&client, &format!("{witness_base}/readyz"), &mut witness)?;

    let live: serde_json::Value = client
        .get(format!("{witness_base}/livez"))
        .send()?
        .error_for_status()?
        .json()?;
    assert_eq!(live["status"], "live");
    let live_text = live.to_string();
    assert!(!live_text.contains("principal"));
    assert!(!live_text.contains("policy"));
    assert!(!live_text.contains("item"));

    assert_operator_status(&client, &witness_base)?;

    let marker = "ExampleSecretMustNotAppear";
    let unauthenticated = client
        .post(format!("{witness_base}/v1/requests/reserve"))
        .body(format!("{{\"marker\":\"{marker}\"}}"))
        .send()?;
    assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);
    let unauthenticated_body = unauthenticated.text()?;
    assert!(!unauthenticated_body.contains(marker));
    let wrong = client
        .post(format!("{witness_base}/v1/requests/reserve"))
        .bearer_auth("WrongCredential_0123456789abcdef")
        .body(format!("{{\"marker\":\"{marker}\"}}"))
        .send()?;
    assert_eq!(wrong.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(wrong.text()?, unauthenticated_body);

    let malformed = client
        .post(format!("{witness_base}/v1/requests/reserve"))
        .bearer_auth(CLIENT_TOKEN)
        .body(format!("{{\"marker\":\"{marker}\"}}"))
        .send()?;
    assert_eq!(malformed.status(), StatusCode::BAD_REQUEST);
    assert!(!malformed.text()?.contains(marker));

    let oversized = client
        .post(format!("{witness_base}/v1/requests/reserve"))
        .bearer_auth(CLIENT_TOKEN)
        .body(vec![b'x'; 2048])
        .send()?;
    assert_eq!(oversized.status(), StatusCode::PAYLOAD_TOO_LARGE);

    let conflicting_anchor = WitnessStateAnchorV1 {
        schema: 1,
        witness_id,
        witness_signing_key_fingerprint: Digest32::new([2; 32]),
        witness_signing_key_epoch: 1,
        state_generation: 1,
        database_state_digest: Digest32::new([3; 32]),
        vault_high_watermarks: Vec::new(),
        replay_retain_through_ms: 0,
        last_accepted_wall_time_ms: 1,
        predecessor_anchor_digest: Digest32::new([0; 32]),
        issued_at_ms: 1,
        signature: Signature64::new([4; 64]),
    };
    let anchor_cas = client
        .post(format!(
            "https://127.0.0.1:{anchor_port}/v1/anchors/{}",
            hex_id(&witness_id)
        ))
        .bearer_auth(ANCHOR_TOKEN)
        .json(&json!({
            "expected_anchor_digest": null,
            "next_exact_anchor": conflicting_anchor
        }))
        .send()?;
    assert_eq!(anchor_cas.status(), StatusCode::OK);
    wait_not_ready(&client, &format!("{witness_base}/readyz"), &mut witness)?;

    witness.stop_gracefully()?;
    anchor.stop_gracefully()?;
    Ok(())
}

fn assert_initial_audit(executable: &str, witness_config: &Path, root: &Path) -> TestResult {
    let audit_export = root.join("witness-audit.json");
    run_success_with_output(
        executable,
        &["database", "audit", "--config"],
        witness_config,
        &audit_export,
    )?;
    let audit: serde_json::Value = serde_json::from_slice(&fs::read(audit_export)?)?;
    assert_eq!(audit["scope"], "offline-witness-database-only");
    assert_eq!(audit["external_anchor_compared"], false);
    assert_eq!(audit["contribution_readiness_claimed"], false);
    Ok(())
}

fn assert_operator_status(client: &Client, witness_base: &str) -> TestResult {
    let status: serde_json::Value = client
        .get(format!("{witness_base}/v1/operator/status"))
        .bearer_auth(OPERATOR_TOKEN)
        .send()?
        .error_for_status()?
        .json()?;
    assert_eq!(status["scope"], "this-witness-only");
    assert_eq!(status["global_freshness_claimed"], false);
    assert_eq!(
        status["operational"]["checkpoint_acknowledgements"],
        json!([])
    );
    let text = status.to_string();
    for forbidden in [
        "policy_material",
        "accepted_registration",
        "passphrase",
        "contribution_envelope",
    ] {
        assert!(!text.contains(forbidden));
    }
    Ok(())
}

#[test]
fn slow_headers_and_inflight_shutdown_are_bounded() -> TestResult {
    let _process_test = PROCESS_TEST_LOCK
        .lock()
        .map_err(|_| "process-test lock is poisoned")?;
    let fixture = tempfile::tempdir()?;
    fs::set_permissions(fixture.path(), fs::Permissions::from_mode(0o700))?;
    let port = unused_port()?;
    let token = fixture.path().join("anchor.token");
    let witness_id = PrincipalId::from_bytes([9; 32])?;
    write_file(&token, ANCHOR_TOKEN.as_bytes(), 0o600)?;
    let config = fixture.path().join("anchor.json");
    write_json(
        &config,
        &json!({
            "schema": 1,
            "witness_id": witness_id,
            "listen": format!("127.0.0.1:{port}"),
            "tls": {
                "certificate_file": null,
                "private_key_file": null,
                "allow_insecure_loopback": true
            },
            "database": {
                "path": fixture.path().join("anchor.sqlite3"),
                "authority": {
                    "administration_authority": "anchor-admin",
                    "backup_authority": "anchor-backup",
                    "restore_authority": "anchor-restore",
                    "failure_domain": "anchor-host"
                }
            },
            "write_credential_file": token,
            "write_authority": "anchor-writer",
            "limits": {
                "maximum_request_bytes": 1048576,
                "maximum_concurrency": 2,
                "requests_per_second": 100,
                "burst_requests": 200,
                "request_timeout_ms": 200,
                "shutdown_grace_ms": 300
            }
        }),
    )?;

    let executable = env!("CARGO_BIN_EXE_juryd");
    run_success(executable, &["anchor", "init", "--config"], &config)?;
    let mut anchor = ProcessGuard::spawn(executable, &["anchor", "serve", "--config"], &config)?;
    let client = Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(2))
        .build()?;
    wait_ready(
        &client,
        &format!("http://127.0.0.1:{port}/readyz"),
        &mut anchor,
    )?;
    assert_unauthenticated_body_is_rejected_before_read(port, &witness_id)?;

    let mut timed_out = slow_header_connection(port)?;
    thread::sleep(Duration::from_millis(350));
    timed_out.set_read_timeout(Some(Duration::from_secs(1)))?;
    let mut byte = [0_u8; 1];
    match timed_out.read(&mut byte) {
        Ok(0) => {}
        Err(error)
            if matches!(
                error.kind(),
                ErrorKind::ConnectionReset | ErrorKind::BrokenPipe | ErrorKind::UnexpectedEof
            ) => {}
        result => return Err(format!("slow header connection remained open: {result:?}").into()),
    }

    let _inflight = slow_header_connection(port)?;
    let shutdown_started = Instant::now();
    anchor.stop_gracefully()?;
    assert!(shutdown_started.elapsed() < Duration::from_secs(2));
    Ok(())
}

fn limits() -> serde_json::Value {
    json!({
        "maximum_request_bytes": 1024,
        "maximum_concurrency": 4,
        "requests_per_second": 100,
        "burst_requests": 200,
        "request_timeout_ms": 5000,
        "shutdown_grace_ms": 5000
    })
}

fn anchor_limits() -> serde_json::Value {
    json!({
        "maximum_request_bytes": 1048576,
        "maximum_concurrency": 4,
        "requests_per_second": 100,
        "burst_requests": 200,
        "request_timeout_ms": 5000,
        "shutdown_grace_ms": 5000
    })
}

fn create_witness_identity(path: &Path) -> Result<PrincipalId, Box<dyn Error>> {
    let passphrase =
        ProtectedMemory::initialize(PASSPHRASE.len(), ProtectionPolicy::Strict, |destination| {
            destination.copy_from_slice(PASSPHRASE);
            Ok::<usize, ()>(destination.len())
        })?;
    let created_at_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_millis()
        .try_into()?;
    let identity = IdentityCreator::new().create(
        PrincipalKind::Witness,
        KdfProfile::PortableV1,
        created_at_ms,
        &passphrase,
        |_| false,
    )?;
    let witness_id = identity.descriptor.principal_id;
    write_file(path, &identity.file.to_json_bytes()?, 0o600)?;
    Ok(witness_id)
}

fn hex_id(id: &PrincipalId) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(64);
    for byte in id.as_bytes() {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn unused_port() -> Result<u16, Box<dyn Error>> {
    Ok(TcpListener::bind(("127.0.0.1", 0))?.local_addr()?.port())
}

fn two_unused_ports() -> Result<(u16, u16), Box<dyn Error>> {
    let first = TcpListener::bind(("127.0.0.1", 0))?;
    let second = TcpListener::bind(("127.0.0.1", 0))?;
    Ok((first.local_addr()?.port(), second.local_addr()?.port()))
}

fn slow_header_connection(port: u16) -> Result<TcpStream, Box<dyn Error>> {
    let mut connection = TcpStream::connect(("127.0.0.1", port))?;
    connection.write_all(b"GET /readyz HTTP/1.1\r\nHost:")?;
    connection.flush()?;
    Ok(connection)
}

fn assert_unauthenticated_body_is_rejected_before_read(
    port: u16,
    witness_id: &PrincipalId,
) -> Result<(), Box<dyn Error>> {
    let mut stream = TcpStream::connect(("127.0.0.1", port))?;
    stream.set_read_timeout(Some(Duration::from_secs(1)))?;
    write!(
        stream,
        "POST /v1/anchors/{} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 1024\r\nConnection: close\r\n\r\n",
        hex_id(witness_id)
    )?;
    stream.flush()?;
    let mut response = [0_u8; 4096];
    let read = stream.read(&mut response)?;
    let response = std::str::from_utf8(&response[..read])?;
    if !response.starts_with("HTTP/1.1 401") {
        return Err(format!("server awaited an unauthenticated body: {response:?}").into());
    }
    Ok(())
}

fn write_json(path: &Path, value: &serde_json::Value) -> TestResult {
    write_file(path, &serde_json::to_vec_pretty(value)?, 0o600)
}

fn write_file(path: &Path, bytes: &[u8], mode: u32) -> TestResult {
    fs::write(path, bytes)?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    Ok(())
}

fn wait_ready(client: &Client, url: &str, process: &mut ProcessGuard) -> TestResult {
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        if let Some(status) = process.child.try_wait()? {
            return Err(format!("juryd exited before readiness with {status}").into());
        }
        if client
            .get(url)
            .send()
            .is_ok_and(|response| response.status() == StatusCode::OK)
        {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(50));
    }
    Err("juryd readiness timeout".into())
}

fn wait_not_ready(client: &Client, url: &str, process: &mut ProcessGuard) -> TestResult {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if let Some(status) = process.child.try_wait()? {
            return Err(format!("juryd exited during rollback check with {status}").into());
        }
        if client
            .get(url)
            .send()
            .is_ok_and(|response| response.status() == StatusCode::SERVICE_UNAVAILABLE)
        {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(25));
    }
    Err("juryd did not fail closed on an external anchor ahead of its database".into())
}

struct ProcessGuard {
    child: Child,
}

fn run_success(executable: &str, arguments: &[&str], config: &Path) -> TestResult {
    let status = Command::new(executable)
        .args(arguments)
        .arg(config)
        .stdin(Stdio::null())
        .status()?;
    if !status.success() {
        return Err(format!("juryd administration command failed with {status}").into());
    }
    Ok(())
}

fn run_success_with_output(
    executable: &str,
    arguments: &[&str],
    config: &Path,
    output: &Path,
) -> TestResult {
    let status = Command::new(executable)
        .args(arguments)
        .arg(config)
        .args(["--output"])
        .arg(output)
        .stdin(Stdio::null())
        .status()?;
    if !status.success() {
        return Err(format!("juryd administration command failed with {status}").into());
    }
    Ok(())
}

impl ProcessGuard {
    fn spawn(executable: &str, arguments: &[&str], config: &Path) -> Result<Self, Box<dyn Error>> {
        let mut command = Command::new(executable);
        command.args(arguments).arg(config);
        let child = command
            .stdin(Stdio::null())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()?;
        Ok(Self { child })
    }

    fn stop_gracefully(&mut self) -> TestResult {
        if self.child.try_wait()?.is_some() {
            return Err("juryd exited before graceful shutdown".into());
        }
        kill_process(Pid::from_child(&self.child), Signal::TERM)?;
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if let Some(status) = self.child.try_wait()? {
                if status.success() {
                    return Ok(());
                }
                return Err(format!("juryd graceful shutdown failed with {status}").into());
            }
            thread::sleep(Duration::from_millis(25));
        }
        Err("juryd graceful shutdown timeout".into())
    }
}

impl Drop for ProcessGuard {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}
