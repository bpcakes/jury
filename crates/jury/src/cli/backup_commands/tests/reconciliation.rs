use super::*;

#[test]
fn restore_reconciles_each_injected_cross_directory_publication_failure() -> TestResult {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path();
    let offline = root.join("offline");
    let current = root.join("current");
    let data = root.join("data");
    let source_state = root.join("source-state");
    for directory in [&offline, &current, &data, &source_state] {
        private_directory(directory)?;
    }
    let backup = offline.join("ExampleVault.backup");
    let original_archive = write_owner_backup(&backup)?;
    let environment = Environment {
        jury_home: None,
        jury_identity_home: None,
        jury_identity: None,
        jury_identity_file: None,
        jury_state_home: Some(source_state.into_os_string()),
        xdg_data_home: Some(data.clone().into_os_string()),
        xdg_state_home: Some(root.join("xdg-state").into_os_string()),
        user_home: Some(data.into_os_string()),
        jury_identity_passphrase: None,
        jury_backup_passphrase: Some(Zeroizing::new(b"ExampleBackupPassphrase".to_vec())),
        jury_new_passphrase: Some(Zeroizing::new(b"ExampleNewIdentityPassphrase".to_vec())),
    };
    let points = [
        RestorePublicationPoint::MarkerCreated,
        RestorePublicationPoint::OwnerIdentityPublished,
        RestorePublicationPoint::VaultPublished,
        RestorePublicationPoint::StateFilePublished,
    ];

    for (index, fault) in points.into_iter().enumerate() {
        let vault_parent = root.join(format!("vault-parent-{index}"));
        let identity_parent = root.join(format!("identity-parent-{index}"));
        let state_parent = root.join(format!("state-parent-{index}"));
        for directory in [&vault_parent, &identity_parent, &state_parent] {
            private_directory(directory)?;
        }
        let vault = vault_parent.join("ExampleRestoredVault");
        let identity = identity_parent.join("ExampleRestoredOwner.identity");
        let state = state_parent.join("ExampleRestoredState");
        let cli = restore_cli(&backup, vault.clone(), identity.clone(), state.clone())?;
        let mut injected = false;
        let injected_result = backup_restore_with_observer(
            &cli,
            restore_arguments(&cli),
            &environment,
            &current,
            ProtectionPolicy::EmergencyAllowDegraded,
            &mut |observed| {
                inject_once_at(observed, fault, &mut injected, "injected-restore-failure")
            },
        );
        let error = match injected_result {
            Err(error) => error,
            Ok(_) => return Err("the selected transaction point was not injected".into()),
        };
        assert_eq!(error.code(), "injected-restore-failure");
        assert!(injected);

        if fault == RestorePublicationPoint::MarkerCreated {
            let mismatched_vault_parent = root.join("mismatched-vault-parent");
            private_directory(&mismatched_vault_parent)?;
            let mismatched_vault = mismatched_vault_parent.join("DifferentRestoredVault");
            let mismatched_cli = restore_cli(
                &backup,
                mismatched_vault.clone(),
                identity.clone(),
                state.clone(),
            )?;
            let mismatch = backup_restore(
                &mismatched_cli,
                restore_arguments(&mismatched_cli),
                &environment,
                &current,
                ProtectionPolicy::EmergencyAllowDegraded,
            )
            .err()
            .ok_or("a different retry target unexpectedly matched the marker")?;
            assert_eq!(mismatch.code(), "restore-marker-mismatch");
            assert!(!mismatched_vault.exists());
        }

        backup_restore_with_observer(
            &cli,
            restore_arguments(&cli),
            &environment,
            &current,
            ProtectionPolicy::EmergencyAllowDegraded,
            &mut |_| Ok(()),
        )?;
        assert!(vault.join("vault.json").is_file());
        assert!(identity.is_file());
        assert!(state.is_dir());
        assert!(!fs::read_dir(&identity_parent)?.any(|entry| {
            entry.is_ok_and(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".jury-vault-restore-")
            })
        }));
        assert_eq!(fs::read(&backup)?, original_archive);
    }
    Ok(())
}
