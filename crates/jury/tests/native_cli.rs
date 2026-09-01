#![cfg(target_os = "linux")]

use std::fs;
use std::io::Write as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::process::{Command, Output, Stdio};

use jury_protocol::vault_v1::{PolicyOperationV1, VaultFileV1};

use self::support::*;

#[path = "native_cli/additional.rs"]
mod native_cli_additional;

#[path = "native_cli/execution.rs"]
mod native_cli_execution;

#[path = "native_cli/plaintext.rs"]
mod native_cli_plaintext;

#[path = "native_cli/transfer.rs"]
mod native_cli_transfer;

#[path = "native_cli/support.rs"]
mod support;

#[derive(Clone, Copy)]
struct NativePaths<'a> {
    repository: &'a Path,
    data: &'a Path,
    state: &'a Path,
}

struct CandidateFixture {
    identity: serde_json::Value,
    descriptor_path: std::path::PathBuf,
    proof_path: std::path::PathBuf,
}

fn initialize_identity(paths: NativePaths<'_>) -> TestResult<serde_json::Value> {
    let NativePaths {
        repository,
        data,
        state,
    } = paths;
    let identity = success_json(run(
        repository,
        data,
        state,
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
    Ok(identity)
}

fn assert_identity_inventory(paths: NativePaths<'_>, identity: &serde_json::Value) -> TestResult {
    let NativePaths {
        repository,
        data,
        state,
    } = paths;
    let identity_status = success_json(run(
        repository,
        data,
        state,
        &["--json", "identity", "status"],
        b"",
    )?)?;
    assert_eq!(identity_status["operation"], "identity-status");
    assert_eq!(identity_status["public_fields_authenticated"], false);
    assert_eq!(identity_status["private_payload_verified"], false);
    let identities = success_json(run(
        repository,
        data,
        state,
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
    Ok(())
}

fn initialize_vault(paths: NativePaths<'_>) -> TestResult<serde_json::Value> {
    let NativePaths {
        repository,
        data,
        state,
    } = paths;
    let vault = success_json(run(
        repository,
        data,
        state,
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
    Ok(vault)
}

fn assert_public_vault_status(paths: NativePaths<'_>, vault: &serde_json::Value) -> TestResult {
    let NativePaths {
        repository,
        data,
        state,
    } = paths;
    let status = success_json(run(
        repository,
        data,
        state,
        &["--json", "vault", "status"],
        b"",
    )?)?;
    assert_eq!(status["operation"], "vault-status");
    assert_eq!(status["public_validation"], "valid");
    assert_eq!(status["identity_unlocked"], false);
    assert_eq!(status["principal_count"], 1);
    assert_eq!(status["owner_count"], 1);
    assert_eq!(status["item_count"], 0);
    assert_eq!(status["tombstone_count"], 0);
    assert_eq!(status["format_version"], 1);
    assert_eq!(status["suite_id"], 1);
    assert_eq!(status["cryptographic_scopes"], true);
    assert_eq!(status["capacity"]["item_revision_proofs"]["used"], 0);
    assert_eq!(status["vault_id"], vault["vault_id"]);
    assert_eq!(status["genesis_fingerprint"], vault["genesis_fingerprint"]);

    let history = success_json(run(
        repository,
        data,
        state,
        &["--json", "history", "status"],
        b"",
    )?)?;
    assert_eq!(history["operation"], "history-status");
    assert_eq!(history["identity_unlocked"], false);
    assert_eq!(history["capacity"], status["capacity"]);
    Ok(())
}

fn assert_local_audit(paths: NativePaths<'_>) -> TestResult {
    let NativePaths {
        repository,
        data,
        state,
    } = paths;
    let audit = success_json(run(
        repository,
        data,
        state,
        &[
            "--json",
            "--passphrase-stdin",
            "--allow-degraded-protection",
            "vault",
            "audit",
            "verify",
        ],
        b"ExamplePass1234\n",
    )?)?;
    assert_eq!(audit["operation"], "vault-audit-verify");
    assert_eq!(audit["evidence"], "current-jury-v1-local");
    assert_eq!(audit["event_count"], 1);
    assert_eq!(audit["local_activity_only"], true);
    assert_eq!(audit["other_principals_verified"], false);
    assert_eq!(audit["remote_freshness_verified"], false);
    Ok(())
}

fn create_direct_item(paths: NativePaths<'_>) -> TestResult {
    let NativePaths {
        repository,
        data,
        state,
    } = paths;
    let preview = success_json(run(
        repository,
        data,
        state,
        &[
            "--json",
            "--passphrase-stdin",
            "--allow-degraded-protection",
            "item",
            "create",
            "ExampleItem",
            "--allow-direct",
            "--dry-run",
        ],
        b"ExamplePass1234\n",
    )?)?;
    assert_eq!(preview["operation"], "item-create");
    assert_eq!(preview["dry_run"], true);
    assert_eq!(preview["vault_changed"], false);
    assert_eq!(preview["delivery_claimed"], false);
    let unchanged = success_json(run(
        repository,
        data,
        state,
        &["--json", "vault", "status"],
        b"",
    )?)?;
    assert_eq!(unchanged["item_count"], 0);

    let created_item = success_json(run(
        repository,
        data,
        state,
        &[
            "--json",
            "--passphrase-stdin",
            "--allow-degraded-protection",
            "item",
            "create",
            "ExampleItem",
            "--allow-direct",
        ],
        b"ExamplePass1234\n",
    )?)?;
    assert_eq!(created_item["operation"], "item-create");
    assert_eq!(created_item["item"], "ExampleItem");
    assert_eq!(created_item["dry_run"], false);
    assert_eq!(created_item["vault_changed"], true);
    assert_eq!(created_item["redistribution_recommended"], true);
    assert_eq!(created_item["delivery_claimed"], false);
    let with_item = success_json(run(
        repository,
        data,
        state,
        &["--json", "vault", "status"],
        b"",
    )?)?;
    assert_eq!(with_item["item_count"], 1);
    assert_eq!(with_item["capacity"]["item_revision_proofs"]["used"], 1);

    let before_duplicate = fs::read(repository.join(".jury/vault.json"))?;
    let duplicate = run(
        repository,
        data,
        state,
        &[
            "--json",
            "--passphrase-stdin",
            "--allow-degraded-protection",
            "item",
            "create",
            "ExampleItem",
            "--allow-direct",
        ],
        b"ExamplePass1234\n",
    )?;
    assert_eq!(duplicate.status.code(), Some(4));
    assert!(duplicate.stdout.is_empty());
    let duplicate_error: serde_json::Value = serde_json::from_slice(&duplicate.stderr)?;
    assert_eq!(duplicate_error["error"]["code"], "duplicate-item-name");
    assert_eq!(
        fs::read(repository.join(".jury/vault.json"))?,
        before_duplicate
    );
    Ok(())
}

fn assert_owner_access(paths: NativePaths<'_>) -> TestResult {
    let NativePaths {
        repository,
        data,
        state,
    } = paths;
    let principals = success_json(run(
        repository,
        data,
        state,
        &["--json", "principal", "list"],
        b"",
    )?)?;
    assert_eq!(principals["operation"], "principal-list");
    assert_eq!(principals["count"], 1);
    assert_eq!(principals["item_names_disclosed"], false);
    assert!(!principals.to_string().contains("ExampleItem"));

    let my_access = success_json(run(
        repository,
        data,
        state,
        &[
            "--json",
            "--passphrase-stdin",
            "--allow-degraded-protection",
            "access",
            "list",
            "--me",
        ],
        b"ExamplePass1234\n",
    )?)?;
    assert_eq!(my_access["operation"], "access-list-me");
    assert_eq!(my_access["count"], 1);
    assert_eq!(my_access["items"][0]["item"], "ExampleItem");
    assert_eq!(my_access["items"][0]["role"], "owner");
    assert_eq!(my_access["items"][0]["path"], "direct");
    assert_eq!(my_access["items"][0]["carries_item_quorum_claim"], false);

    let policy = success_json(run(
        repository,
        data,
        state,
        &[
            "--json",
            "--passphrase-stdin",
            "--allow-degraded-protection",
            "policy",
            "status",
            "--item",
            "ExampleItem",
        ],
        b"ExamplePass1234\n",
    )?)?;
    assert_eq!(policy["operation"], "policy-status");
    assert_eq!(policy["mode"], "direct-only");
    assert_eq!(policy["carries_item_quorum_claim"], false);
    assert_eq!(policy["item_quorum_claim_suppressed"], true);
    Ok(())
}

fn register_candidate(temporary: &Path, paths: NativePaths<'_>) -> TestResult<CandidateFixture> {
    let NativePaths {
        repository,
        data,
        state,
    } = paths;
    let candidate = success_json(run(
        repository,
        data,
        state,
        &[
            "--json",
            "--passphrase-stdin",
            "--allow-degraded-protection",
            "identity",
            "init",
            "--name",
            "candidate",
            "--kind",
            "machine",
        ],
        b"CandidatePass1234\nCandidatePass1234\n",
    )?)?;
    assert_eq!(candidate["kind"], "machine");
    let registration = temporary.join("registration");
    fs::create_dir(&registration)?;
    fs::set_permissions(&registration, fs::Permissions::from_mode(0o700))?;
    let descriptor_path = registration.join("candidate.json");
    let challenge_path = registration.join("challenge.json");
    let proof_path = registration.join("proof.json");
    let public = success_json(run(
        repository,
        data,
        state,
        &[
            "--json",
            "--identity",
            "candidate",
            "--passphrase-stdin",
            "--allow-degraded-protection",
            "identity",
            "public",
            "--out",
            descriptor_path
                .to_str()
                .ok_or("non-UTF-8 descriptor path")?,
        ],
        b"CandidatePass1234\n",
    )?)?;
    assert_eq!(public["operation"], "identity-public");
    assert_eq!(public["principal_id"], candidate["principal_id"]);
    let challenge = success_json(run(
        repository,
        data,
        state,
        &[
            "--json",
            "--passphrase-stdin",
            "--allow-degraded-protection",
            "principal",
            "challenge",
            "--from",
            descriptor_path
                .to_str()
                .ok_or("non-UTF-8 descriptor path")?,
            "--out",
            challenge_path.to_str().ok_or("non-UTF-8 challenge path")?,
        ],
        b"ExamplePass1234\n",
    )?)?;
    assert_eq!(challenge["operation"], "principal-challenge");
    assert_eq!(
        challenge["candidate_principal_id"],
        candidate["principal_id"]
    );
    let proof = success_json(run(
        repository,
        data,
        state,
        &[
            "--json",
            "--identity",
            "candidate",
            "--passphrase-stdin",
            "--allow-degraded-protection",
            "identity",
            "prove",
            "--challenge",
            challenge_path.to_str().ok_or("non-UTF-8 challenge path")?,
            "--out",
            proof_path.to_str().ok_or("non-UTF-8 proof path")?,
        ],
        b"CandidatePass1234\n",
    )?)?;
    assert_eq!(proof["operation"], "identity-prove");
    assert_eq!(proof["principal_id"], candidate["principal_id"]);
    assert_eq!(proof["recovered_response_disclosed"], false);
    Ok(CandidateFixture {
        identity: candidate,
        descriptor_path,
        proof_path,
    })
}

fn grant_candidate_access(
    paths: NativePaths<'_>,
    vault: &serde_json::Value,
    candidate: &CandidateFixture,
) -> TestResult {
    let NativePaths {
        repository,
        data,
        state,
    } = paths;
    let before_unacknowledged_grant = fs::read(repository.join(".jury/vault.json"))?;
    let unacknowledged_grant = run(
        repository,
        data,
        state,
        &[
            "--json",
            "--passphrase-stdin",
            "--allow-degraded-protection",
            "principal",
            "add",
            "--from",
            candidate
                .descriptor_path
                .to_str()
                .ok_or("non-UTF-8 descriptor path")?,
            "--proof",
            candidate
                .proof_path
                .to_str()
                .ok_or("non-UTF-8 proof path")?,
            "--reader",
            "ExampleItem",
        ],
        b"",
    )?;
    assert_eq!(unacknowledged_grant.status.code(), Some(2));
    assert!(unacknowledged_grant.stdout.is_empty());
    let grant_error: serde_json::Value = serde_json::from_slice(&unacknowledged_grant.stderr)?;
    assert_eq!(
        grant_error["error"]["code"],
        "direct-access-acknowledgement-required"
    );
    assert_eq!(
        fs::read(repository.join(".jury/vault.json"))?,
        before_unacknowledged_grant
    );
    let added = success_json(run(
        repository,
        data,
        state,
        &[
            "--json",
            "--passphrase-stdin",
            "--allow-degraded-protection",
            "principal",
            "add",
            "--from",
            candidate
                .descriptor_path
                .to_str()
                .ok_or("non-UTF-8 descriptor path")?,
            "--proof",
            candidate
                .proof_path
                .to_str()
                .ok_or("non-UTF-8 proof path")?,
            "--reader",
            "ExampleItem",
            "--acknowledge-direct-access",
        ],
        b"ExamplePass1234\n",
    )?)?;
    assert_eq!(added["operation"], "principal-add");
    assert_eq!(added["vault_changed"], true);

    let candidate_access = success_json(run(
        repository,
        data,
        state,
        &[
            "--json",
            "--identity",
            "candidate",
            "--expected-genesis",
            vault["genesis_fingerprint"]
                .as_str()
                .ok_or("missing genesis fingerprint")?,
            "--passphrase-stdin",
            "--allow-degraded-protection",
            "access",
            "list",
            "--me",
        ],
        b"CandidatePass1234\n",
    )?)?;
    assert_eq!(candidate_access["count"], 1);
    assert_eq!(candidate_access["items"][0]["item"], "ExampleItem");
    assert_eq!(candidate_access["items"][0]["role"], "reader");
    assert_eq!(candidate_access["items"][0]["path"], "direct");
    Ok(())
}

fn change_and_revoke_candidate_access(
    paths: NativePaths<'_>,
    candidate: &CandidateFixture,
) -> TestResult {
    let NativePaths {
        repository,
        data,
        state,
    } = paths;
    let changed_access = success_json(run(
        repository,
        data,
        state,
        &[
            "--json",
            "--passphrase-stdin",
            "--allow-degraded-protection",
            "access",
            "change",
            "ExampleItem",
            "--principal",
            candidate.identity["principal_id"]
                .as_str()
                .ok_or("missing candidate principal")?,
            "--role",
            "writer",
        ],
        b"ExamplePass1234\n",
    )?)?;
    assert_eq!(changed_access["operation"], "access-change");
    assert_eq!(changed_access["vault_changed"], true);
    let candidate_writer = success_json(run(
        repository,
        data,
        state,
        &[
            "--json",
            "--identity",
            "candidate",
            "--passphrase-stdin",
            "--allow-degraded-protection",
            "access",
            "list",
            "--me",
        ],
        b"CandidatePass1234\n",
    )?)?;
    assert_eq!(candidate_writer["items"][0]["role"], "writer");

    let revoked_access = success_json(run(
        repository,
        data,
        state,
        &[
            "--json",
            "--passphrase-stdin",
            "--allow-degraded-protection",
            "access",
            "revoke",
            "ExampleItem",
            "--principal",
            candidate.identity["principal_id"]
                .as_str()
                .ok_or("missing candidate principal")?,
        ],
        b"ExamplePass1234\n",
    )?)?;
    assert_eq!(revoked_access["operation"], "access-revoke");
    assert_eq!(revoked_access["vault_changed"], true);
    let candidate_revoked = success_json(run(
        repository,
        data,
        state,
        &[
            "--json",
            "--identity",
            "candidate",
            "--passphrase-stdin",
            "--allow-degraded-protection",
            "access",
            "list",
            "--me",
        ],
        b"CandidatePass1234\n",
    )?)?;
    assert_eq!(candidate_revoked["count"], 0);
    Ok(())
}

fn set_example_field(paths: NativePaths<'_>) -> TestResult {
    let NativePaths {
        repository,
        data,
        state,
    } = paths;
    let field_set = success_json(run(
        repository,
        data,
        state,
        &[
            "--json",
            "--passphrase-stdin",
            "--allow-degraded-protection",
            "vault",
            "field",
            "set",
            "ExampleItem",
            "ExampleField",
            "--value-stdin",
        ],
        b"ExamplePass1234\nExampleValue",
    )?)?;
    assert_eq!(field_set["operation"], "field-set");
    assert_eq!(field_set["vault_changed"], true);
    assert!(!field_set.to_string().contains("ExampleValue"));
    Ok(())
}

fn exercise_execution_and_plaintext(temporary: &Path, paths: NativePaths<'_>) -> TestResult {
    let NativePaths {
        repository,
        data,
        state,
    } = paths;
    native_cli_execution::exercise_successful_execution(temporary, repository, data, state)?;

    native_cli_execution::exercise_adversarial_execution(temporary, repository, data, state)?;

    native_cli_plaintext::exercise_plaintext_sinks(temporary, repository, data, state)
}

fn cover_and_remove_fields(paths: NativePaths<'_>) -> TestResult {
    let NativePaths {
        repository,
        data,
        state,
    } = paths;
    let cover = success_json(run(
        repository,
        data,
        state,
        &[
            "--json",
            "--passphrase-stdin",
            "--allow-degraded-protection",
            "privacy",
            "cover",
            "--item",
            "ExampleItem",
        ],
        b"ExamplePass1234\n",
    )?)?;
    assert_eq!(cover["operation"], "privacy-cover");
    assert_eq!(cover["vault_changed"], true);

    let removed = success_json(run(
        repository,
        data,
        state,
        &[
            "--json",
            "--passphrase-stdin",
            "--allow-degraded-protection",
            "vault",
            "field",
            "remove",
            "ExampleItem",
            "ExampleField",
        ],
        b"ExamplePass1234\n",
    )?)?;
    assert_eq!(removed["operation"], "field-remove");
    assert_eq!(removed["vault_changed"], true);
    let removed_secret = success_json(run(
        repository,
        data,
        state,
        &[
            "--json",
            "--passphrase-stdin",
            "--allow-degraded-protection",
            "vault",
            "field",
            "remove",
            "ExampleItem",
            "ExampleSecret",
        ],
        b"ExamplePass1234\n",
    )?)?;
    assert_eq!(removed_secret["operation"], "field-remove");
    assert_eq!(removed_secret["vault_changed"], true);
    let removed_binary = success_json(run(
        repository,
        data,
        state,
        &[
            "--json",
            "--passphrase-stdin",
            "--allow-degraded-protection",
            "vault",
            "field",
            "remove",
            "ExampleItem",
            "ExampleBinary",
        ],
        b"ExamplePass1234\n",
    )?)?;
    assert_eq!(removed_binary["operation"], "field-remove");
    assert_eq!(removed_binary["vault_changed"], true);
    let no_fields = success_json(run(
        repository,
        data,
        state,
        &[
            "--json",
            "--passphrase-stdin",
            "--allow-degraded-protection",
            "vault",
            "field",
            "list",
            "ExampleItem",
        ],
        b"ExamplePass1234\n",
    )?)?;
    assert_eq!(no_fields["count"], 0);
    Ok(())
}

fn change_identity_passphrase(paths: NativePaths<'_>, identity: &serde_json::Value) -> TestResult {
    let NativePaths {
        repository,
        data,
        state,
    } = paths;
    let changed = success_json(run(
        repository,
        data,
        state,
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
        repository,
        data,
        state,
        &["--json", "identity", "status"],
        b"",
    )?)?;
    assert_eq!(after_change["principal_id"], identity["principal_id"]);
    assert_eq!(after_change["fingerprint"], identity["fingerprint"]);
    assert_eq!(after_change["kdf_profile"], "portable-v1");
    Ok(())
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
    let paths = NativePaths {
        repository: &repository,
        data: &data,
        state: &state,
    };

    let identity = initialize_identity(paths)?;
    assert_identity_inventory(paths, &identity)?;
    let vault = initialize_vault(paths)?;
    assert_public_vault_status(paths, &vault)?;
    assert_local_audit(paths)?;
    create_direct_item(paths)?;
    assert_owner_access(paths)?;
    let candidate = register_candidate(temporary.path(), paths)?;
    grant_candidate_access(paths, &vault, &candidate)?;
    change_and_revoke_candidate_access(paths, &candidate)?;
    set_example_field(paths)?;
    exercise_execution_and_plaintext(temporary.path(), paths)?;
    cover_and_remove_fields(paths)?;
    change_identity_passphrase(paths, &identity)
}
