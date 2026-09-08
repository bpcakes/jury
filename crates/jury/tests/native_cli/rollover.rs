use super::*;

fn private_directory(path: &Path) -> TestResult {
    fs::create_dir_all(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[test]
fn direct_rollover_cli_previews_then_publishes_new_backup_transfer_and_receipts() -> TestResult {
    exercise_direct_lineage(false)
}

#[test]
fn direct_suite_migration_cli_preserves_values_and_restores_backup() -> TestResult {
    exercise_direct_lineage(true)
}

pub(super) fn lineage_contract(migration: bool) -> (&'static str, &'static str, u16) {
    if migration {
        ("migrate-suite", "vault-migrate-suite", 2)
    } else {
        ("rollover", "vault-rollover", 1)
    }
}

fn exercise_direct_lineage(migration: bool) -> TestResult {
    let (command, operation, suite) = lineage_contract(migration);
    let temporary = tempfile::tempdir()?;
    let root = temporary.path();
    let repository = root.join("repository");
    let data = root.join("data");
    let state = root.join("state");
    fs::create_dir(&repository)?;
    fs::create_dir(repository.join(".git"))?;
    fs::write(repository.join(".git/HEAD"), "ref: refs/heads/main\n")?;
    let paths = NativePaths {
        repository: &repository,
        data: &data,
        state: &state,
    };
    initialize_identity(paths)?;
    initialize_vault(paths)?;
    create_direct_item(paths)?;
    set_example_field(paths)?;
    let source = fs::read(repository.join(".jury/vault.json"))?;
    let attributes = fs::read(repository.join(".jury/.gitattributes"))?;
    let git_head = fs::read(repository.join(".git/HEAD"))?;
    let destinations = root.join("destinations");
    let offline = root.join("offline");
    let transfers = root.join("transfers");
    for directory in [&destinations, &offline, &transfers] {
        private_directory(directory)?;
    }
    let out = destinations.join("ExampleVault");
    let backup = offline.join("ExampleVault.backup");
    let transfer = transfers.join("ExampleVault.transfer");
    let mut args = vec![
        "--json",
        "--passphrase-stdin",
        "--allow-degraded-protection",
        "vault",
        command,
        "--out",
        out.to_str().ok_or("invalid output path")?,
        "--backup-out",
        backup.to_str().ok_or("invalid backup path")?,
        "--transfer-out",
        transfer.to_str().ok_or("invalid transfer path")?,
    ];
    if migration {
        args.extend(["--to", "2"]);
    }
    let mut preview_args = args.clone();
    preview_args.push("--dry-run");
    check_invalid_outputs(paths, &preview_args, root)?;
    let preview = success_json(run(
        &repository,
        &data,
        &state,
        &preview_args,
        b"ExamplePass1234\nExampleBackupPassphrase\nExampleBackupPassphrase\n",
    )?)?;
    assert_eq!(preview["published"], false);
    assert_eq!(preview["local_owner_adopted"], false);
    assert!(!out.exists() && !backup.exists() && !transfer.exists());
    let mut publish_args = args.clone();
    publish_args.push("--adopt-new-lineage");
    let published = success_json(run(
        &repository,
        &data,
        &state,
        &publish_args,
        b"ExamplePass1234\nExampleBackupPassphrase\nExampleBackupPassphrase\n",
    )?)?;
    assert_eq!(published["operation"], operation);
    assert_eq!(published["suite"], suite);
    check_published_outputs(&published, &out, &backup, &transfer)?;
    let source_vault = VaultFileV1::parse(&source)?;
    let destination = VaultFileV1::parse(&fs::read(out.join("vault.json"))?)?;
    assert_eq!(destination.header.suite, suite);
    assert_eq!(destination.suite_migration.is_some(), migration);
    jury_core::rollover::RolloverSource::validate(&source_vault, &[])?
        .verify_fresh_direct_destination(&destination)?;
    assert_eq!(fs::read(repository.join(".jury/vault.json"))?, source);
    assert_eq!(
        fs::read(repository.join(".jury/.gitattributes"))?,
        attributes
    );
    assert_eq!(fs::read(repository.join(".git/HEAD"))?, git_head);
    check_completed_rollover_retry(paths, &publish_args, &out, &backup, &transfer)?;
    check_destination(&out, &backup, paths)?;
    check_recovery_copy(root, &out, &backup, paths, &source_vault)?;
    check_pending_publication_is_unavailable(&out, paths)?;
    let occupied = run(&repository, &data, &state, &preview_args, b"")?;
    assert!(!occupied.status.success());
    assert_eq!(fs::read(repository.join(".jury/vault.json"))?, source);
    Ok(())
}

fn check_completed_rollover_retry(
    paths: NativePaths<'_>,
    arguments: &[&str],
    out: &Path,
    backup: &Path,
    transfer: &Path,
) -> TestResult {
    let expected = [
        fs::read(out.join("vault.json"))?,
        fs::read(backup)?,
        fs::read(transfer)?,
    ];
    let mut arguments = arguments.to_vec();
    arguments.push("--resume");
    let retried = success_json(run(
        paths.repository,
        paths.data,
        paths.state,
        &arguments,
        b"ExamplePass1234\nExampleBackupPassphrase\n",
    )?)?;
    assert_eq!(retried["published"], true);
    check_resume_command_mismatch(paths, &arguments)?;
    assert_eq!(
        [
            fs::read(out.join("vault.json"))?,
            fs::read(backup)?,
            fs::read(transfer)?
        ],
        expected
    );
    Ok(())
}

fn check_resume_command_mismatch(paths: NativePaths<'_>, arguments: &[&str]) -> TestResult {
    let mut changed = arguments.to_vec();
    if let Some(index) = changed.iter().position(|argument| *argument == "--to") {
        changed.drain(index..index + 2);
        let command = changed
            .iter_mut()
            .find(|argument| **argument == "migrate-suite")
            .ok_or("missing migration command")?;
        *command = "rollover";
    } else {
        let command = changed
            .iter_mut()
            .find(|argument| **argument == "rollover")
            .ok_or("missing rollover command")?;
        *command = "migrate-suite";
        changed.extend(["--to", "2"]);
    }
    let refused = run(
        paths.repository,
        paths.data,
        paths.state,
        &changed,
        b"ExamplePass1234\n",
    )?;
    assert!(!refused.status.success() && refused.stdout.is_empty());
    let error: serde_json::Value = serde_json::from_slice(&refused.stderr)?;
    assert_eq!(error["error"]["code"], "invalid-rollover-target");
    Ok(())
}

fn check_pending_publication_is_unavailable(out: &Path, paths: NativePaths<'_>) -> TestResult {
    let bytes = fs::read(out.join("vault.json"))?;
    for name in [
        "rollover.pending.json",
        "rollover.pending.cleanup.json",
        "rollover.outputs.pending.json",
        "rollover.outputs.cleanup.json",
    ] {
        let pending = out.join(name);
        assert!(!pending.exists());
        // Model the retained on-disk state after an interrupted publication or
        // cleanup. This tests the real reader, not a claim of a live crash.
        fs::write(&pending, &bytes)?;
        fs::set_permissions(&pending, fs::Permissions::from_mode(0o600))?;
        let output = run(
            paths.repository,
            paths.data,
            paths.state,
            &[
                "--json",
                "--home",
                out.to_str().ok_or("invalid home")?,
                "vault",
                "status",
            ],
            b"",
        )?;
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        let error: serde_json::Value = serde_json::from_slice(&output.stderr)?;
        assert_eq!(error["error"]["code"], "rollover-publication-incomplete");
        assert_eq!(fs::read(out.join("vault.json"))?, bytes);
        fs::remove_file(pending)?;
    }
    Ok(())
}

fn check_recovery_copy(
    root: &Path,
    out: &Path,
    backup: &Path,
    paths: NativePaths<'_>,
    source: &VaultFileV1,
) -> TestResult {
    let homes = root.join("recovery-homes");
    let identities = root.join("recovery-identities");
    let states = root.join("recovery-states");
    let values = root.join("recovery-values");
    for parent in [&homes, &identities, &states, &values] {
        private_directory(parent)?;
    }
    let restored_home = homes.join("ExampleVault");
    let restored_identity = identities.join("ExamplePrincipal.identity");
    let restored_state = states.join("ExampleState");
    let drilled = success_json(run(paths.repository, paths.data, paths.state, &[
        "--json", "--home", out.to_str().ok_or("invalid home")?, "--passphrase-stdin", "--allow-degraded-protection",
        "backup", "drill", "--in", backup.to_str().ok_or("invalid backup")?,
        "--vault-out", restored_home.to_str().ok_or("invalid home")?,
        "--identity-out", restored_identity.to_str().ok_or("invalid identity")?,
        "--state-out", restored_state.to_str().ok_or("invalid state")?,
    ], b"ExamplePass1234\nExampleBackupPassphrase\nExampleDrillPassphrase\nExampleDrillPassphrase\n")?)?;
    assert_eq!(drilled["details"]["restored_direct_access_validated"], true);
    assert_eq!(drilled["details"]["source_drill_receipt_recorded"], true);
    let restored = VaultFileV1::parse(&fs::read(restored_home.join("vault.json"))?)?;
    jury_core::rollover::RolloverSource::validate(source, &[])?
        .verify_fresh_direct_destination(&restored)?;
    let value_path = values.join("ExampleValue.txt");
    success_json(run_with_environment(
        paths.repository,
        paths.data,
        paths.state,
        &[
            "--json",
            "--home",
            restored_home.to_str().ok_or("invalid home")?,
            "--identity-file",
            restored_identity.to_str().ok_or("invalid identity")?,
            "--passphrase-stdin",
            "--allow-degraded-protection",
            "read",
            "ExampleItem",
            "ExampleField",
            "--direct",
            "--out",
            value_path.to_str().ok_or("invalid output")?,
        ],
        b"ExampleDrillPassphrase\n",
        &[(
            "JURY_STATE_HOME",
            restored_state.to_str().ok_or("invalid state")?,
        )],
    )?)?;
    assert!(fs::read(value_path)? == b"ExampleValue");
    Ok(())
}

fn check_destination(out: &Path, backup: &Path, paths: NativePaths<'_>) -> TestResult {
    let common = [
        "--json",
        "--passphrase-stdin",
        "--allow-degraded-protection",
        "--home",
        out.to_str().ok_or("invalid home")?,
    ];
    let mut args = common.to_vec();
    args.extend(["vault", "field", "list"]);
    let fields = success_json(run(
        paths.repository,
        paths.data,
        paths.state,
        &args,
        b"ExamplePass1234\n",
    )?)?;
    assert_eq!(fields["operation"], "field-list");
    let mut args = common.to_vec();
    args.extend(["backup", "status"]);
    let status = success_json(run(
        paths.repository,
        paths.data,
        paths.state,
        &args,
        b"ExamplePass1234\n",
    )?)?;
    assert_eq!(status["creation"], "current");
    let mut args = common.to_vec();
    args.extend(["transfer", "status"]);
    let status = success_json(run(
        paths.repository,
        paths.data,
        paths.state,
        &args,
        b"ExamplePass1234\n",
    )?)?;
    assert_eq!(status["operation"], "transfer-status");
    assert_eq!(status["status"], "matches-last-local-export");
    assert_eq!(
        status["last_exported_public_revision"],
        status["current_public_revision"]
    );
    let mut args = common.to_vec();
    args.extend([
        "backup",
        "verify",
        "--in",
        backup.to_str().ok_or("invalid backup")?,
    ]);
    let verified = success_json(run(
        paths.repository,
        paths.data,
        paths.state,
        &args,
        b"ExampleBackupPassphrase\nExamplePass1234\n",
    )?)?;
    let vault = VaultFileV1::parse(&fs::read(out.join("vault.json"))?)?;
    if vault.header.suite == 2 {
        let mut repeated = common.to_vec();
        repeated.extend([
            "vault",
            "migrate-suite",
            "--to",
            "2",
            "--dry-run",
            "--out",
            out.to_str().ok_or("invalid home")?,
            "--backup-out",
            backup.to_str().ok_or("invalid backup")?,
            "--transfer-out",
            out.to_str().ok_or("invalid home")?,
        ]);
        let refused = run(paths.repository, paths.data, paths.state, &repeated, b"")?;
        assert!(!refused.status.success() && refused.stdout.is_empty());
        let error: serde_json::Value = serde_json::from_slice(&refused.stderr)?;
        assert_eq!(error["error"]["code"], "unsupported-suite-transition");
    }
    assert_eq!(
        verified["vault_id"],
        serde_json::to_value(vault.header.vault_id)?
    );
    assert_eq!(
        verified["direct_item_ids"].as_array().map(Vec::len),
        Some(1)
    );
    Ok(())
}

fn check_invalid_outputs(paths: NativePaths<'_>, arguments: &[&str], root: &Path) -> TestResult {
    let forbidden = paths.repository.join("forbidden-output");
    for flag in ["--out", "--backup-out", "--transfer-out"] {
        let mut changed = arguments.to_vec();
        let index = changed
            .iter()
            .position(|argument| *argument == flag)
            .ok_or("missing argument")?
            + 1;
        changed[index] = forbidden.to_str().ok_or("invalid path")?;
        assert!(
            !run(paths.repository, paths.data, paths.state, &changed, b"")?
                .status
                .success()
        );
        assert!(!forbidden.exists());
    }
    let link = root.join("linked-output");
    std::os::unix::fs::symlink(&forbidden, &link)?;
    let mut changed = arguments.to_vec();
    let index = changed
        .iter()
        .position(|argument| *argument == "--out")
        .ok_or("missing argument")?
        + 1;
    changed[index] = link.to_str().ok_or("invalid path")?;
    assert!(
        !run(paths.repository, paths.data, paths.state, &changed, b"")?
            .status
            .success()
    );
    assert!(fs::symlink_metadata(&link)?.file_type().is_symlink());
    assert!(!forbidden.exists());
    Ok(())
}

fn check_published_outputs(
    published: &serde_json::Value,
    out: &Path,
    backup: &Path,
    transfer: &Path,
) -> TestResult {
    assert_eq!(published["published"], true);
    assert_eq!(published["local_export_receipt_recorded"], true);
    assert_eq!(published["local_owner_adopted"], true);
    assert_eq!(published["redistributed"], false);
    assert!(out.join("vault.json").exists() && backup.exists() && transfer.exists());
    assert_eq!(fs::metadata(out)?.permissions().mode() & 0o777, 0o700);
    assert_eq!(fs::metadata(backup)?.permissions().mode() & 0o777, 0o600);
    Ok(())
}
