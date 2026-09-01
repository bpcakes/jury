use std::path::PathBuf;

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

#[test]
fn transfer_is_portable_strict_and_write_free_on_preview_or_conflict() -> TestResult {
    let temporary = tempfile::tempdir()?;
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

    let base_path = temporary.path().join("base.jury-transfer.json");
    let base = export(source, &base_path)?;
    assert_portable_export(&base, &vault, &base_path)?;
    inspect_and_preview_first_install(target, &base_path, genesis)?;
    install_first(source, target, &base_path, genesis)?;

    let descendant_path = temporary.path().join("descendant.jury-transfer.json");
    import_descendant(source, target, principal_id, genesis, &descendant_path)?;
    assert_public_conflict_is_read_only(target, &base_path, "transfer-behind")?;

    relabel(target, principal_id, "target-branch")?;
    relabel(source, principal_id, "source-branch")?;
    let divergent_path = temporary.path().join("divergent.jury-transfer.json");
    export(source, &divergent_path)?;
    assert_public_conflict_is_read_only(target, &divergent_path, "transfer-diverged")?;
    assert_retained_checkpoint_rejects_absent_home(target, &divergent_path, genesis)?;
    Ok(())
}
