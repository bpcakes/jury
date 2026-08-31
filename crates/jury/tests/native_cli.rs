#![cfg(target_os = "linux")]

use std::fs;
use std::io::Write as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::process::{Command, Output, Stdio};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn run(
    repository: &Path,
    data: &Path,
    state: &Path,
    arguments: &[&str],
    input: &[u8],
) -> TestResult<Output> {
    let mut child = Command::new(env!("CARGO_BIN_EXE_jury"))
        .args(arguments)
        .current_dir(repository)
        .env_clear()
        .env("HOME", data)
        .env("XDG_DATA_HOME", data)
        .env("XDG_STATE_HOME", state)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    child
        .stdin
        .take()
        .ok_or("child standard input is unavailable")?
        .write_all(input)?;
    Ok(child.wait_with_output()?)
}

fn success_json(output: Output) -> TestResult<serde_json::Value> {
    if !output.status.success() {
        return Err(format!(
            "command failed: status={:?}, stdout={:?}, stderr={:?}",
            output.status.code(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    assert!(output.stderr.is_empty());
    Ok(serde_json::from_slice(&output.stdout)?)
}

#[test]
fn fresh_repository_identity_vault_and_public_status_flow() -> TestResult {
    let temporary = tempfile::tempdir()?;
    let repository = temporary.path().join("repository");
    let data = temporary.path().join("data");
    let state = temporary.path().join("state");
    fs::create_dir(&repository)?;
    fs::create_dir(repository.join(".git"))?;
    fs::write(
        repository.join(".git").join("HEAD"),
        [b"ref: refs".as_slice(), b"/heads/main\n"].concat(),
    )?;

    let identity = success_json(run(
        &repository,
        &data,
        &state,
        &[
            "--json",
            "--passphrase-stdin",
            "--allow-degraded-protection",
            "identity",
            "init",
        ],
        b"ExamplePass1234\nExamplePass1234\n",
    )?)?;
    assert_eq!(identity["operation"], "identity-init");
    assert_eq!(identity["kind"], "human");
    assert_eq!(identity["kdf_profile"], "portable-v1");
    assert!(!repository.join(".jury").exists());
    assert!(data.join("jury/identities/default.identity.json").is_file());

    let identity_status = success_json(run(
        &repository,
        &data,
        &state,
        &["--json", "identity", "status"],
        b"",
    )?)?;
    assert_eq!(identity_status["operation"], "identity-status");
    assert_eq!(identity_status["public_fields_authenticated"], false);
    assert_eq!(identity_status["private_payload_verified"], false);
    let identities = success_json(run(
        &repository,
        &data,
        &state,
        &["--json", "identity", "list"],
        b"",
    )?)?;
    assert_eq!(identities["operation"], "identity-list");
    assert_eq!(identities["count"], 1);
    assert_eq!(identities["identities"][0]["name"], "default");
    assert_eq!(
        identities["identities"][0]["principal_id"],
        identity["principal_id"]
    );

    let vault = success_json(run(
        &repository,
        &data,
        &state,
        &[
            "--json",
            "--passphrase-stdin",
            "--allow-degraded-protection",
            "vault",
            "init",
        ],
        b"ExamplePass1234\n",
    )?)?;
    assert_eq!(vault["operation"], "vault-init");
    assert_eq!(vault["home_source"], "repository");
    assert_eq!(vault["local_state"], "initialized");

    let mut shared_entries = fs::read_dir(repository.join(".jury"))?
        .map(|entry| entry.map(|entry| entry.file_name()))
        .collect::<Result<Vec<_>, _>>()?;
    shared_entries.sort();
    assert_eq!(shared_entries, [".gitattributes", "vault.json"]);
    assert_eq!(
        fs::read(repository.join(".jury/.gitattributes"))?,
        b"vault.json -diff -merge\n"
    );
    let shared = fs::read(repository.join(".jury/vault.json"))?;
    assert!(
        !shared
            .windows("ExamplePass1234".len())
            .any(|window| window == b"ExamplePass1234")
    );

    // Git preserves only the executable bit. A fresh checkout ordinarily
    // recreates these public encrypted files and their directory as 0644/0755.
    fs::set_permissions(repository.join(".jury"), fs::Permissions::from_mode(0o755))?;
    fs::set_permissions(
        repository.join(".jury/.gitattributes"),
        fs::Permissions::from_mode(0o644),
    )?;
    fs::set_permissions(
        repository.join(".jury/vault.json"),
        fs::Permissions::from_mode(0o644),
    )?;

    let status = success_json(run(
        &repository,
        &data,
        &state,
        &["--json", "vault", "status"],
        b"",
    )?)?;
    assert_eq!(status["operation"], "vault-status");
    assert_eq!(status["public_validation"], "valid");
    assert_eq!(status["identity_unlocked"], false);
    assert_eq!(status["principal_count"], 1);
    assert_eq!(status["owner_count"], 1);
    assert_eq!(status["item_count"], 0);
    assert_eq!(status["vault_id"], vault["vault_id"]);
    assert_eq!(status["genesis_fingerprint"], vault["genesis_fingerprint"]);

    let changed = success_json(run(
        &repository,
        &data,
        &state,
        &[
            "--json",
            "--passphrase-stdin",
            "--allow-degraded-protection",
            "identity",
            "passphrase",
            "change",
        ],
        b"ExamplePass1234\nExamplePass5678\nExamplePass5678\n",
    )?)?;
    assert_eq!(changed["operation"], "identity-passphrase-change");
    assert_eq!(changed["principal_keys_changed"], false);
    assert_eq!(changed["principal_id"], identity["principal_id"]);
    assert_eq!(changed["fingerprint"], identity["fingerprint"]);

    let after_change = success_json(run(
        &repository,
        &data,
        &state,
        &["--json", "identity", "status"],
        b"",
    )?)?;
    assert_eq!(after_change["principal_id"], identity["principal_id"]);
    assert_eq!(after_change["fingerprint"], identity["fingerprint"]);
    assert_eq!(after_change["kdf_profile"], "portable-v1");
    Ok(())
}

#[test]
fn non_terminal_passphrase_requires_explicit_opt_in() -> TestResult {
    let temporary = tempfile::tempdir()?;
    let repository = temporary.path().join("repository");
    fs::create_dir(&repository)?;
    fs::create_dir(repository.join(".git"))?;
    fs::write(
        repository.join(".git").join("HEAD"),
        [b"ref: refs".as_slice(), b"/heads/main\n"].concat(),
    )?;
    let output = run(
        &repository,
        &temporary.path().join("data"),
        &temporary.path().join("state"),
        &["--json", "--allow-degraded-protection", "identity", "init"],
        b"ExamplePass1234\nExamplePass1234\n",
    )?;
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let error: serde_json::Value = serde_json::from_slice(&output.stderr)?;
    assert_eq!(error["error"]["code"], "passphrase-input-opt-in-required");
    Ok(())
}
