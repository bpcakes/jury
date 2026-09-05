use std::path::PathBuf;

use jury_filesystem::{RepositoryLocation, VaultStateDirectory};
use jury_protocol::transfer_v1::TransferEnvelopeV1;

use super::*;

fn initialize_repository(path: &Path) -> TestResult {
    fs::create_dir(path)?;
    fs::create_dir(path.join(".git"))?;
    fs::write(path.join(".git/HEAD"), b"ref: refs/heads/main\n")?;
    Ok(())
}

fn copy_default_identity(source_data: &Path, target_data: &Path) -> TestResult {
    let target = target_data.join("jury/identities/default.identity.json");
    fs::create_dir_all(target.parent().ok_or("identity target has no parent")?)?;
    for directory in [
        target_data.to_path_buf(),
        target_data.join("jury"),
        target_data.join("jury/identities"),
    ] {
        fs::set_permissions(directory, fs::Permissions::from_mode(0o700))?;
    }
    fs::copy(
        source_data.join("jury/identities/default.identity.json"),
        target,
    )?;
    Ok(())
}

fn hex_bytes(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 16] = b"0123456789abcdef";
    bytes
        .iter()
        .flat_map(|byte| {
            [
                ALPHABET[usize::from(byte >> 4)] as char,
                ALPHABET[usize::from(byte & 0x0f)] as char,
            ]
        })
        .collect()
}

fn snapshot_tree(root: &Path) -> TestResult<Vec<(PathBuf, Option<Vec<u8>>)>> {
    fn visit(
        root: &Path,
        current: &Path,
        output: &mut Vec<(PathBuf, Option<Vec<u8>>)>,
    ) -> TestResult {
        if !current.exists() {
            return Ok(());
        }
        let relative = current.strip_prefix(root)?.to_path_buf();
        if current.is_dir() {
            if !relative.as_os_str().is_empty() {
                output.push((relative, None));
            }
            for entry in fs::read_dir(current)? {
                visit(root, &entry?.path(), output)?;
            }
        } else {
            output.push((relative, Some(fs::read(current)?)));
        }
        Ok(())
    }

    let mut output = Vec::new();
    visit(root, root, &mut output)?;
    output.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(output)
}

fn import_arguments<'a>(genesis: &'a str, input: &'a str, dry_run: bool) -> Vec<&'a str> {
    let mut arguments = vec![
        "--json",
        "--expected-genesis",
        genesis,
        "--passphrase-stdin",
        "--allow-degraded-protection",
        "transfer",
        "import",
        "--in",
        input,
        "--allow-no-access",
    ];
    if dry_run {
        arguments.push("--dry-run");
    }
    arguments
}

fn relabel(paths: NativePaths<'_>, principal_id: &str, label: &str) -> TestResult {
    let output = success_json(run(
        paths.repository,
        paths.data,
        paths.state,
        &[
            "--json",
            "--passphrase-stdin",
            "--allow-degraded-protection",
            "principal",
            "label",
            principal_id,
            "--label",
            label,
        ],
        b"ExamplePass1234\n",
    )?)?;
    assert_eq!(output["operation"], "principal-label");
    assert_eq!(output["vault_changed"], true);
    Ok(())
}

fn export(paths: NativePaths<'_>, destination: &Path) -> TestResult<serde_json::Value> {
    success_json(run(
        paths.repository,
        paths.data,
        paths.state,
        &[
            "--json",
            "--passphrase-stdin",
            "--allow-degraded-protection",
            "transfer",
            "export",
            "--out",
            destination.to_str().ok_or("non-UTF-8 transfer path")?,
        ],
        b"ExamplePass1234\n",
    )?)
}

fn assert_published_export_reports_unrecorded_receipt(
    paths: NativePaths<'_>,
    destination: &Path,
) -> TestResult {
    let vault = VaultFileV1::parse(&fs::read(paths.repository.join(".jury/vault.json"))?)?;
    let repository = RepositoryLocation::discover(paths.repository)?;
    let state = VaultStateDirectory::open_existing(
        &paths.state.join("jury/vaults"),
        vault.header.vault_id.as_bytes(),
        vault.header.genesis_fingerprint.as_bytes(),
        &[&repository],
    )?;
    let lock = state.try_lock()?;

    let output = export(paths, destination)?;
    assert_eq!(output["local_export_receipt_recorded"], false);
    assert!(destination.is_file());
    drop(lock);
    Ok(())
}

fn assert_portable_export(
    output: &serde_json::Value,
    vault: &serde_json::Value,
    transfer: &Path,
) -> TestResult {
    assert_eq!(output["operation"], "transfer-export");
    assert_eq!(output["local_export_receipt_recorded"], true);
    assert_eq!(output["delivery_claimed"], false);
    let bytes = fs::read(transfer)?;
    let envelope = TransferEnvelopeV1::parse(&bytes)?;
    assert_eq!(
        hex_bytes(envelope.source_vault_id.as_bytes()),
        vault["vault_id"]
            .as_str()
            .ok_or("vault output lacks an ID")?
    );
    let top_level = serde_json::from_slice::<serde_json::Value>(&bytes)?;
    let object = top_level
        .as_object()
        .ok_or("transfer is not a JSON object")?;
    for forbidden in ["identity", "audit", "checkpoint", "receipts"] {
        assert!(!object.contains_key(forbidden));
    }
    assert!(
        !bytes
            .windows("ExamplePass1234".len())
            .any(|window| window == b"ExamplePass1234")
    );
    Ok(())
}

fn assert_export_destination_is_rejected_without_mutation(
    paths: NativePaths<'_>,
    destination: &Path,
) -> TestResult {
    let before = fs::read(destination).ok();
    let rejected = run(
        paths.repository,
        paths.data,
        paths.state,
        &[
            "--json",
            "--passphrase-stdin",
            "--allow-degraded-protection",
            "transfer",
            "export",
            "--out",
            destination.to_str().ok_or("non-UTF-8 transfer path")?,
            "--overwrite",
        ],
        b"ExamplePass1234\n",
    )?;
    assert!(!rejected.status.success());
    assert!(rejected.stdout.is_empty());
    let error = serde_json::from_slice::<serde_json::Value>(&rejected.stderr)?;
    assert_eq!(error["error"]["code"], "private-state-overlap");
    assert_eq!(fs::read(destination).ok(), before);
    Ok(())
}

fn assert_export_destination_containment(
    paths: NativePaths<'_>,
    temporary: &Path,
    vault: &serde_json::Value,
    principal_id: &str,
    genesis: &str,
) -> TestResult {
    let identity = paths.data.join("jury/identities/default.identity.json");
    assert_export_destination_is_rejected_without_mutation(paths, &identity)?;

    let receipts = paths
        .state
        .join("jury/vaults")
        .join(
            vault["vault_id"]
                .as_str()
                .ok_or("vault output lacks an ID")?,
        )
        .join(genesis)
        .join(principal_id)
        .join("receipts.json");
    assert_export_destination_is_rejected_without_mutation(paths, &receipts)?;

    let other_repository = temporary.join("other-repository");
    initialize_repository(&other_repository)?;
    fs::create_dir(other_repository.join(".jury"))?;
    fs::set_permissions(
        other_repository.join(".jury"),
        fs::Permissions::from_mode(0o700),
    )?;
    let other_vault = other_repository.join(".jury/vault.json");
    fs::write(&other_vault, b"ExampleEncryptedVault")?;
    assert_export_destination_is_rejected_without_mutation(paths, &other_vault)?;
    Ok(())
}

fn inspect_and_preview_first_install(
    target: NativePaths<'_>,
    transfer: &Path,
    genesis: &str,
) -> TestResult {
    let input = transfer.to_str().ok_or("non-UTF-8 transfer path")?;
    let inspected = success_json(run(
        target.repository,
        target.data,
        target.state,
        &["--json", "transfer", "inspect", "--in", input],
        b"",
    )?)?;
    assert_eq!(inspected["operation"], "transfer-inspect");
    assert_eq!(inspected["identity_unlocked"], false);
    assert_eq!(inspected["inaccessible_names_disclosed"], false);
    assert_eq!(inspected["public_review_labels_disclosed"], true);
    assert!(inspected["public_review_labels"].is_array());
    assert_eq!(inspected["mutated"], false);

    let repository_before = snapshot_tree(target.repository)?;
    let state_before = snapshot_tree(target.state)?;
    let preview = success_json(run(
        target.repository,
        target.data,
        target.state,
        &import_arguments(genesis, input, true),
        b"ExamplePass1234\n",
    )?)?;
    assert_eq!(preview["result"], "first-install");
    assert_eq!(preview["dry_run"], true);
    assert_eq!(preview["committed"], false);
    assert_eq!(snapshot_tree(target.repository)?, repository_before);
    assert_eq!(snapshot_tree(target.state)?, state_before);
    Ok(())
}

fn install_first(
    source: NativePaths<'_>,
    target: NativePaths<'_>,
    transfer: &Path,
    genesis: &str,
) -> TestResult {
    let installed = success_json(run(
        target.repository,
        target.data,
        target.state,
        &import_arguments(
            genesis,
            transfer.to_str().ok_or("non-UTF-8 transfer path")?,
            false,
        ),
        b"ExamplePass1234\n",
    )?)?;
    assert_eq!(installed["result"], "first-install");
    assert_eq!(installed["committed"], true);
    assert_eq!(
        fs::read(source.repository.join(".jury/vault.json"))?,
        fs::read(target.repository.join(".jury/vault.json"))?
    );
    Ok(())
}

fn assert_first_install_retry_recovers_exact_partial_state(
    source: NativePaths<'_>,
    target: NativePaths<'_>,
    transfer: &Path,
    vault: &serde_json::Value,
    principal_id: &str,
    genesis: &str,
) -> TestResult {
    let principal_state = target
        .state
        .join("jury/vaults")
        .join(
            vault["vault_id"]
                .as_str()
                .ok_or("vault output lacks an ID")?,
        )
        .join(genesis)
        .join(principal_id);
    let audit = principal_state.join("audit.jsonl");
    let checkpoint = principal_state.join("checkpoint.json");
    let receipts = principal_state.join("receipts.json");
    let audit_before = fs::read(&audit)?;
    let checkpoint_before = fs::read(&checkpoint)?;
    let receipts_before = fs::read(&receipts)?;

    fs::remove_file(target.repository.join(".jury/vault.json"))?;
    fs::remove_file(&receipts)?;
    install_first(source, target, transfer, genesis)?;
    assert_eq!(fs::read(&audit)?, audit_before);
    assert_eq!(fs::read(&checkpoint)?, checkpoint_before);
    assert_eq!(fs::read(&receipts)?, receipts_before);

    fs::remove_file(target.repository.join(".jury/vault.json"))?;
    fs::write(&receipts, b"invalid retained state")?;
    let rejected = run(
        target.repository,
        target.data,
        target.state,
        &import_arguments(
            genesis,
            transfer.to_str().ok_or("non-UTF-8 transfer path")?,
            false,
        ),
        b"ExamplePass1234\n",
    )?;
    assert!(!rejected.status.success());
    assert!(rejected.stdout.is_empty());
    let error = serde_json::from_slice::<serde_json::Value>(&rejected.stderr)?;
    assert_eq!(error["error"]["code"], "local-state-error");
    assert!(!target.repository.join(".jury/vault.json").exists());

    fs::write(&receipts, receipts_before)?;
    install_first(source, target, transfer, genesis)?;
    Ok(())
}

fn import_descendant(
    source: NativePaths<'_>,
    target: NativePaths<'_>,
    principal_id: &str,
    genesis: &str,
    transfer: &Path,
) -> TestResult {
    relabel(source, principal_id, "source-first")?;
    export(source, transfer)?;
    let input = transfer.to_str().ok_or("non-UTF-8 transfer path")?;
    let vault_before = fs::read(target.repository.join(".jury/vault.json"))?;
    let state_before = snapshot_tree(target.state)?;
    let preview = success_json(run(
        target.repository,
        target.data,
        target.state,
        &import_arguments(genesis, input, true),
        b"ExamplePass1234\n",
    )?)?;
    assert_eq!(preview["result"], "incoming-strict-descendant");
    assert_eq!(preview["committed"], false);
    assert_eq!(
        fs::read(target.repository.join(".jury/vault.json"))?,
        vault_before
    );
    assert_eq!(snapshot_tree(target.state)?, state_before);

    let imported = success_json(run(
        target.repository,
        target.data,
        target.state,
        &import_arguments(genesis, input, false),
        b"ExamplePass1234\n",
    )?)?;
    assert_eq!(imported["operation"], "transfer-import");
    assert_eq!(imported["committed"], true);
    assert_eq!(imported["redistribution_recommended"], false);
    assert_eq!(
        fs::read(source.repository.join(".jury/vault.json"))?,
        fs::read(target.repository.join(".jury/vault.json"))?
    );
    Ok(())
}

fn assert_public_conflict_is_read_only(
    target: NativePaths<'_>,
    transfer: &Path,
    expected_code: &str,
) -> TestResult {
    let repository_before = snapshot_tree(target.repository)?;
    let state_before = snapshot_tree(target.state)?;
    let rejected = run(
        target.repository,
        target.data,
        target.state,
        &[
            "--json",
            "transfer",
            "import",
            "--in",
            transfer.to_str().ok_or("non-UTF-8 transfer path")?,
        ],
        b"",
    )?;
    assert!(!rejected.status.success());
    assert!(rejected.stdout.is_empty());
    let error = serde_json::from_slice::<serde_json::Value>(&rejected.stderr)?;
    assert_eq!(error["error"]["code"], expected_code);
    assert_eq!(snapshot_tree(target.repository)?, repository_before);
    assert_eq!(snapshot_tree(target.state)?, state_before);
    Ok(())
}

fn assert_retained_checkpoint_rejects_absent_home(
    target: NativePaths<'_>,
    transfer: &Path,
    genesis: &str,
) -> TestResult {
    fs::remove_file(target.repository.join(".jury/vault.json"))?;
    let repository_before = snapshot_tree(target.repository)?;
    let state_before = snapshot_tree(target.state)?;
    let rejected = run(
        target.repository,
        target.data,
        target.state,
        &import_arguments(
            genesis,
            transfer.to_str().ok_or("non-UTF-8 transfer path")?,
            false,
        ),
        b"ExamplePass1234\n",
    )?;
    assert!(!rejected.status.success());
    assert!(rejected.stdout.is_empty());
    let error = serde_json::from_slice::<serde_json::Value>(&rejected.stderr)?;
    assert_eq!(error["error"]["code"], "checkpoint-conflict");
    assert_eq!(snapshot_tree(target.repository)?, repository_before);
    assert_eq!(snapshot_tree(target.state)?, state_before);
    Ok(())
}

fn git(repository: &Path, arguments: &[&str]) -> TestResult<Output> {
    let output = Command::new("git")
        .current_dir(repository)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("HOME", repository)
        .env("XDG_CONFIG_HOME", repository)
        .args(arguments)
        .output()?;
    if !output.status.success() {
        return Err(format!(
            "git command failed: arguments={arguments:?}, stdout={:?}, stderr={:?}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(output)
}

fn assert_transfer_inspect_rejected_without_mutation(
    paths: NativePaths<'_>,
    transfer: &Path,
) -> TestResult {
    let repository_before = snapshot_tree(paths.repository)?;
    let state_before = snapshot_tree(paths.state)?;
    let rejected = run(
        paths.repository,
        paths.data,
        paths.state,
        &[
            "--json",
            "transfer",
            "inspect",
            "--in",
            transfer.to_str().ok_or("non-UTF-8 transfer path")?,
        ],
        b"",
    )?;
    assert!(!rejected.status.success());
    assert!(rejected.stdout.is_empty());
    let error = serde_json::from_slice::<serde_json::Value>(&rejected.stderr)?;
    assert_eq!(
        error["error"]["code"], "invalid-transfer",
        "unexpected transfer inspection error: {error}"
    );
    let repository_after = snapshot_tree(paths.repository)?;
    if repository_after != repository_before {
        let changed: Vec<_> = repository_after
            .iter()
            .chain(repository_before.iter())
            .filter(|entry| !repository_before.contains(entry) || !repository_after.contains(entry))
            .map(|entry| &entry.0)
            .take(16)
            .collect();
        panic!("transfer inspection changed repository paths (up to 16): {changed:?}");
    }
    assert_eq!(snapshot_tree(paths.state)?, state_before);
    Ok(())
}

fn assert_forged_git_metadata_and_merge_output_grant_no_transfer_authority(
    temporary: &Path,
    data: &Path,
    state: &Path,
    base: &Path,
    divergent: &Path,
) -> TestResult {
    let repository = temporary.join("forged-git-metadata");
    fs::create_dir(&repository)?;
    git(&repository, &["init", "--quiet"])?;
    git(&repository, &["config", "user.name", "ExampleForger"])?;
    git(
        &repository,
        &["config", "user.email", "example-forger@example.invalid"],
    )?;

    let conflict = repository.join("conflict.jury-transfer.json");
    let mut conflict_bytes = b"<<<<<<< current\n".to_vec();
    conflict_bytes.extend_from_slice(&fs::read(base)?);
    conflict_bytes.extend_from_slice(b"=======\n");
    conflict_bytes.extend_from_slice(&fs::read(divergent)?);
    conflict_bytes.extend_from_slice(b">>>>>>> incoming\n");
    fs::write(&conflict, conflict_bytes)?;
    fs::set_permissions(&conflict, fs::Permissions::from_mode(0o644))?;

    let mut spliced = TransferEnvelopeV1::parse(&fs::read(base)?)?;
    let divergent_envelope = TransferEnvelopeV1::parse(&fs::read(divergent)?)?;
    spliced.source_public_revision_hash = divergent_envelope.source_public_revision_hash;
    spliced.vault_digest = divergent_envelope.vault_digest;
    spliced.catalog_digest = divergent_envelope.catalog_digest;
    spliced.vault_json = divergent_envelope.vault_json;
    spliced.public_catalog_json = divergent_envelope.public_catalog_json;
    let semantic_merge = repository.join("semantic-merge.jury-transfer.json");
    fs::write(&semantic_merge, spliced.to_json_bytes()?)?;
    fs::set_permissions(&semantic_merge, fs::Permissions::from_mode(0o644))?;
    TransferEnvelopeV1::parse(&fs::read(&semantic_merge)?)?;

    let signer = repository.join("fake-signer");
    fs::write(
        &signer,
        b"#!/bin/sh\ncat >/dev/null\nprintf '%s\\n' '[GNUPG:] SIG_CREATED D 1 10 00 0 0000000000000000000000000000000000000000' >&2\nprintf '%s\\n' '-----BEGIN PGP SIGNATURE-----' '' 'Zm9yZ2VkLWV4YW1wbGU=' '=AAAA' '-----END PGP SIGNATURE-----'\n",
    )?;
    fs::set_permissions(&signer, fs::Permissions::from_mode(0o700))?;
    git(
        &repository,
        &[
            "config",
            "gpg.program",
            signer.to_str().ok_or("non-UTF-8 signer path")?,
        ],
    )?;
    git(&repository, &["add", "."])?;
    git(
        &repository,
        &[
            "commit",
            "--quiet",
            "-S",
            "-m",
            "Example forged signature metadata",
        ],
    )?;
    let commit = git(&repository, &["cat-file", "-p", "HEAD"])?;
    let commit = String::from_utf8(commit.stdout)?;
    assert!(commit.contains("author ExampleForger <example-forger@example.invalid>"));
    assert!(commit.contains("gpgsig -----BEGIN PGP SIGNATURE-----"));

    let paths = NativePaths {
        repository: &repository,
        data,
        state,
    };
    assert_transfer_inspect_rejected_without_mutation(paths, &conflict)?;
    assert_transfer_inspect_rejected_without_mutation(paths, &semantic_merge)?;
    Ok(())
}

#[test]
fn transfer_is_portable_strict_and_write_free_on_preview_or_conflict() -> TestResult {
    let temporary = tempfile::tempdir()?;
    fs::create_dir(temporary.path().join(".git"))?;
    fs::write(
        temporary.path().join(".git/HEAD"),
        b"ref: refs/heads/main\n",
    )?;
    let source_repository = temporary.path().join("source-repository");
    let target_repository = temporary.path().join("target-repository");
    let source_data = temporary.path().join("source-data");
    let target_data = temporary.path().join("target-data");
    let source_state = temporary.path().join("source-state");
    let target_state = temporary.path().join("target-state");
    initialize_repository(&source_repository)?;
    initialize_repository(&target_repository)?;
    let source = NativePaths {
        repository: &source_repository,
        data: &source_data,
        state: &source_state,
    };
    let target = NativePaths {
        repository: &target_repository,
        data: &target_data,
        state: &target_state,
    };

    let identity = initialize_identity(source)?;
    let vault = initialize_vault(source)?;
    copy_default_identity(&source_data, &target_data)?;
    let principal_id = identity["principal_id"]
        .as_str()
        .ok_or("identity output lacks a principal ID")?;
    let genesis = vault["genesis_fingerprint"]
        .as_str()
        .ok_or("vault output lacks a genesis fingerprint")?;

    assert_published_export_reports_unrecorded_receipt(
        source,
        &temporary.path().join("unrecorded.jury-transfer.json"),
    )?;

    let base_path = temporary.path().join("base.jury-transfer.json");
    let base = export(source, &base_path)?;
    assert_portable_export(&base, &vault, &base_path)?;
    assert_export_destination_containment(source, temporary.path(), &vault, principal_id, genesis)?;
    inspect_and_preview_first_install(target, &base_path, genesis)?;
    install_first(source, target, &base_path, genesis)?;
    assert_first_install_retry_recovers_exact_partial_state(
        source,
        target,
        &base_path,
        &vault,
        principal_id,
        genesis,
    )?;

    let descendant_path = temporary.path().join("descendant.jury-transfer.json");
    import_descendant(source, target, principal_id, genesis, &descendant_path)?;
    assert_public_conflict_is_read_only(target, &base_path, "transfer-behind")?;

    relabel(target, principal_id, "target-branch")?;
    relabel(source, principal_id, "source-branch")?;
    let divergent_path = temporary.path().join("divergent.jury-transfer.json");
    export(source, &divergent_path)?;
    assert_public_conflict_is_read_only(target, &divergent_path, "transfer-diverged")?;
    assert_forged_git_metadata_and_merge_output_grant_no_transfer_authority(
        temporary.path(),
        &target_data,
        &target_state,
        &base_path,
        &divergent_path,
    )?;
    assert_retained_checkpoint_rejects_absent_home(target, &divergent_path, genesis)?;
    Ok(())
}
