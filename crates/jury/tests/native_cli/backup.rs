use super::*;

fn private_directory(path: &Path) -> TestResult {
    fs::create_dir_all(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

fn assert_source_unchanged(paths: NativePaths<'_>, expected: &[u8]) -> TestResult {
    assert_eq!(
        fs::read(paths.repository.join(".jury/vault.json"))?,
        expected
    );
    Ok(())
}

fn create_and_verify_backup(
    root: &Path,
    paths: NativePaths<'_>,
    source_before: &[u8],
) -> TestResult<std::path::PathBuf> {
    let offline = root.join("offline");
    private_directory(&offline)?;
    let backup = offline.join("ExampleVault.backup");
    let created = success_json(run(
        paths.repository,
        paths.data,
        paths.state,
        &[
            "--json",
            "--passphrase-stdin",
            "--allow-degraded-protection",
            "backup",
            "create",
            "--out",
            backup.to_str().ok_or("non-UTF-8 backup path")?,
        ],
        b"ExamplePass1234\nExampleBackupPassphrase\nExampleBackupPassphrase\n",
    )?)?;
    assert_eq!(created["operation"], "backup-create");
    assert_eq!(
        created["included_identity_roles"],
        serde_json::json!(["vault-principal"])
    );
    assert_eq!(created["direct_item_ids"].as_array().map(Vec::len), Some(1));
    assert_eq!(created["external_witness_recovery_required"], false);
    assert_eq!(created["recovers_juryd_replay_state"], false);
    assert_eq!(created["recovers_external_anchors"], false);
    assert_eq!(created["details"]["artifact_bytes"], 4 * 1024 * 1024);
    assert_eq!(fs::metadata(&backup)?.permissions().mode() & 0o777, 0o600);
    assert_source_unchanged(paths, source_before)?;

    let verified = success_json(run(
        paths.repository,
        paths.data,
        paths.state,
        &[
            "--json",
            "--passphrase-stdin",
            "--allow-degraded-protection",
            "backup",
            "verify",
            "--in",
            backup.to_str().ok_or("non-UTF-8 backup path")?,
        ],
        b"ExampleBackupPassphrase\nExamplePass1234\n",
    )?)?;
    assert_eq!(verified["operation"], "backup-verify");
    assert_eq!(verified["details"]["published_restore"], false);
    assert_eq!(
        verified["details"]["local_verification_receipt_recorded"],
        true
    );
    assert_source_unchanged(paths, source_before)?;
    Ok(backup)
}

fn assert_backup_status(paths: NativePaths<'_>, drilled: bool) -> TestResult {
    let status = success_json(run(
        paths.repository,
        paths.data,
        paths.state,
        &[
            "--json",
            "--passphrase-stdin",
            "--allow-degraded-protection",
            "backup",
            "status",
        ],
        b"ExamplePass1234\n",
    )?)?;
    assert_eq!(status["creation"], "current");
    assert_eq!(status["verification"], "recorded");
    assert_eq!(
        status["real_restore_drill"],
        if drilled { "recorded" } else { "unknown" }
    );
    assert_eq!(status["backup_file_exists_or_readable"], "unknown");
    Ok(())
}

fn assert_drill_rejects_every_output_inside_source_repository(
    root: &Path,
    paths: NativePaths<'_>,
    backup: &Path,
) -> TestResult {
    for target in ["vault", "owner", "approver", "witness", "state"] {
        let forbidden = paths.repository.join(format!("forbidden-{target}"));
        let mut vault = root.join(format!("outside-vault-{target}"));
        let mut owner = root.join(format!("outside-owner-{target}.identity"));
        let mut state = root.join(format!("outside-state-{target}"));
        let mut optional = None;
        match target {
            "vault" => vault = forbidden.clone(),
            "owner" => owner = forbidden.clone(),
            "approver" => optional = Some(("--approver-identity-out", forbidden.clone())),
            "witness" => optional = Some(("--witness-identity-out", forbidden.clone())),
            "state" => state = forbidden.clone(),
            _ => return Err("unknown drill output fixture".into()),
        }
        let mut arguments = vec![
            "--json".to_owned(),
            "backup".to_owned(),
            "drill".to_owned(),
            "--in".to_owned(),
            backup.to_str().ok_or("non-UTF-8 backup path")?.to_owned(),
            "--vault-out".to_owned(),
            vault.to_str().ok_or("non-UTF-8 vault path")?.to_owned(),
            "--identity-out".to_owned(),
            owner.to_str().ok_or("non-UTF-8 identity path")?.to_owned(),
            "--state-out".to_owned(),
            state.to_str().ok_or("non-UTF-8 state path")?.to_owned(),
        ];
        if let Some((option, path)) = optional {
            arguments.push(option.to_owned());
            arguments.push(path.to_str().ok_or("non-UTF-8 role path")?.to_owned());
        }
        let arguments = arguments.iter().map(String::as_str).collect::<Vec<_>>();
        let rejected = run(paths.repository, paths.data, paths.state, &arguments, b"")?;
        assert_eq!(rejected.status.code(), Some(2));
        assert!(rejected.stdout.is_empty());
        let error: serde_json::Value = serde_json::from_slice(&rejected.stderr)?;
        assert_eq!(error["error"]["code"], "private-state-overlap");
        assert!(!forbidden.exists());
    }
    Ok(())
}

struct DrillInstallation {
    vault: std::path::PathBuf,
    identity: std::path::PathBuf,
    state: std::path::PathBuf,
}

fn run_real_drill(
    root: &Path,
    paths: NativePaths<'_>,
    backup: &Path,
    source_before: &[u8],
) -> TestResult<DrillInstallation> {
    let vault_parent = root.join("drill-vault-parent");
    let identity_parent = root.join("drill-identity-parent");
    let state_parent = root.join("drill-state-parent");
    for directory in [&vault_parent, &identity_parent, &state_parent] {
        private_directory(directory)?;
    }
    let installation = DrillInstallation {
        vault: vault_parent.join("ExampleVaultDrill"),
        identity: identity_parent.join("ExampleDrillOwner.identity"),
        state: state_parent.join("ExampleDrillState"),
    };
    let drilled = success_json(run(
        paths.repository,
        paths.data,
        paths.state,
        &[
            "--json",
            "--passphrase-stdin",
            "--allow-degraded-protection",
            "backup",
            "drill",
            "--in",
            backup.to_str().ok_or("non-UTF-8 backup path")?,
            "--vault-out",
            installation
                .vault
                .to_str()
                .ok_or("non-UTF-8 drill vault path")?,
            "--identity-out",
            installation
                .identity
                .to_str()
                .ok_or("non-UTF-8 drill identity path")?,
            "--state-out",
            installation
                .state
                .to_str()
                .ok_or("non-UTF-8 drill state path")?,
        ],
        b"ExamplePass1234\nExampleBackupPassphrase\nExampleDrillPassphrase\nExampleDrillPassphrase\n",
    )?)?;
    assert_eq!(drilled["operation"], "backup-drill");
    assert_eq!(drilled["details"]["committed"], true);
    assert_eq!(drilled["details"]["restored_direct_access_validated"], true);
    assert_eq!(drilled["details"]["source_drill_receipt_recorded"], true);
    assert_eq!(drilled["details"]["drill_copy_retained"], true);
    assert!(drilled["details"]["protection_degraded"].is_boolean());
    assert!(installation.vault.join("vault.json").is_file());
    assert!(installation.identity.is_file());
    assert!(installation.state.is_dir());
    assert_source_unchanged(paths, source_before)?;
    Ok(installation)
}

fn inspect_drill(
    root: &Path,
    paths: NativePaths<'_>,
    installation: &DrillInstallation,
) -> TestResult {
    let controlled = root.join("controlled-output");
    private_directory(&controlled)?;
    let recovered_value = controlled.join("ExampleRecoveryValue.txt");
    let state = installation
        .state
        .to_str()
        .ok_or("non-UTF-8 drill state path")?;
    let read = success_json(run_with_environment(
        paths.repository,
        paths.data,
        paths.state,
        &[
            "--json",
            "--home",
            installation
                .vault
                .to_str()
                .ok_or("non-UTF-8 drill vault path")?,
            "--identity-file",
            installation
                .identity
                .to_str()
                .ok_or("non-UTF-8 drill identity path")?,
            "--passphrase-stdin",
            "--allow-degraded-protection",
            "read",
            "ExampleItem",
            "ExampleField",
            "--direct",
            "--out",
            recovered_value
                .to_str()
                .ok_or("non-UTF-8 controlled output path")?,
        ],
        b"ExampleDrillPassphrase\n",
        &[("JURY_STATE_HOME", state)],
    )?)?;
    assert_eq!(read["operation"], "field-read");
    assert_eq!(read["authority"], "direct-unilateral");
    assert_eq!(fs::read(recovered_value)?, b"ExampleValue");

    let audit = success_json(run_with_environment(
        paths.repository,
        paths.data,
        paths.state,
        &[
            "--json",
            "--home",
            installation
                .vault
                .to_str()
                .ok_or("non-UTF-8 drill vault path")?,
            "--identity-file",
            installation
                .identity
                .to_str()
                .ok_or("non-UTF-8 drill identity path")?,
            "--passphrase-stdin",
            "--allow-degraded-protection",
            "vault",
            "audit",
            "verify",
        ],
        b"ExampleDrillPassphrase\n",
        &[("JURY_STATE_HOME", state)],
    )?)?;
    assert_eq!(audit["operation"], "vault-audit-verify");
    assert_eq!(audit["audit_events_after_checkpoint"], 0);
    Ok(())
}

fn restore_into_repository(
    root: &Path,
    paths: NativePaths<'_>,
    backup: &Path,
    identity: &serde_json::Value,
    vault: &serde_json::Value,
    source_before: &[u8],
) -> TestResult {
    let expected_genesis = vault["genesis_fingerprint"]
        .as_str()
        .ok_or("vault genesis fingerprint is absent")?;
    let repository = root.join("restore-repository");
    fs::create_dir(&repository)?;
    fs::create_dir(repository.join(".git"))?;
    fs::write(
        repository.join(".git/HEAD"),
        [b"ref: refs".as_slice(), b"/heads/main\n"].concat(),
    )?;
    let git_head_before = fs::read(repository.join(".git/HEAD"))?;
    let identity_parent = root.join("restore-identity-parent");
    let state_parent = root.join("restore-state-parent");
    for directory in [&identity_parent, &state_parent] {
        private_directory(directory)?;
    }
    let restored_identity = identity_parent.join("ExampleRestoredOwner.identity");
    let restored_state = state_parent.join("ExampleRestoredState");
    let restored = success_json(run(
        &repository,
        paths.data,
        paths.state,
        &[
            "--json",
            "--expected-genesis",
            expected_genesis,
            "--passphrase-stdin",
            "--allow-degraded-protection",
            "backup",
            "restore",
            "--in",
            backup.to_str().ok_or("non-UTF-8 backup path")?,
            "--identity-out",
            restored_identity
                .to_str()
                .ok_or("non-UTF-8 restore identity path")?,
            "--state-out",
            restored_state
                .to_str()
                .ok_or("non-UTF-8 restore state path")?,
        ],
        b"ExampleBackupPassphrase\nExampleRestoredPassphrase\nExampleRestoredPassphrase\n",
    )?)?;
    assert_eq!(restored["operation"], "backup-restore");
    assert_eq!(restored["details"]["committed"], true);
    assert_eq!(restored["details"]["transaction_marker_removed"], true);
    assert!(restored["details"]["protection_degraded"].is_boolean());
    let mut shared_entries = fs::read_dir(repository.join(".jury"))?
        .map(|entry| entry.map(|entry| entry.file_name()))
        .collect::<Result<Vec<_>, _>>()?;
    shared_entries.sort();
    assert_eq!(shared_entries, [".gitattributes", "vault.json"]);
    assert_eq!(fs::read(repository.join(".git/HEAD"))?, git_head_before);
    assert!(restored_identity.is_file());
    assert!(restored_state.is_dir());
    assert_eq!(identity["principal_id"], restored["owner_principal_id"]);
    assert_eq!(
        vault["genesis_fingerprint"],
        restored["genesis_fingerprint"]
    );
    assert_source_unchanged(paths, source_before)
}

#[test]
fn native_backup_verify_restore_and_real_drill_preserve_the_source_vault() -> TestResult {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path();
    let repository = root.join("repository");
    let data = root.join("data");
    let state = root.join("state");
    fs::create_dir(&repository)?;
    fs::create_dir(repository.join(".git"))?;
    fs::write(
        repository.join(".git/HEAD"),
        [b"ref: refs".as_slice(), b"/heads/main\n"].concat(),
    )?;
    let paths = NativePaths {
        repository: &repository,
        data: &data,
        state: &state,
    };
    let identity = initialize_identity(paths)?;
    let vault = initialize_vault(paths)?;
    create_direct_item(paths)?;
    set_example_field(paths)?;
    let source_before = fs::read(repository.join(".jury/vault.json"))?;

    let backup = create_and_verify_backup(root, paths, &source_before)?;
    assert_drill_rejects_every_output_inside_source_repository(root, paths, &backup)?;
    assert_backup_status(paths, false)?;
    let drill = run_real_drill(root, paths, &backup, &source_before)?;
    inspect_drill(root, paths, &drill)?;
    restore_into_repository(root, paths, &backup, &identity, &vault, &source_before)?;
    assert_backup_status(paths, true)
}
