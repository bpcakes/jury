use std::fs;
use std::fs::File;
use std::os::unix::fs::PermissionsExt as _;

use zeroize::Zeroizing;

use super::*;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn protected(value: &[u8]) -> TestResult<ProtectedMemory> {
    Ok(ProtectedMemory::initialize(
        value.len(),
        ProtectionPolicy::EmergencyAllowDegraded,
        |destination| {
            destination.copy_from_slice(value);
            Ok::<usize, ()>(destination.len())
        },
    )?)
}

fn private_directory(path: &Path) -> TestResult {
    fs::create_dir_all(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[test]
fn backup_local_state_snapshot_requires_the_vault_edit_lock() -> TestResult {
    let temporary = tempfile::tempdir()?;
    let state_root = temporary.path().join("state");
    private_directory(&state_root)?;
    let state =
        VaultStateDirectory::open_or_create(&state_root, &[0x11; 32], &[0x22; 32], &[], &[])?;
    let principal_id = PrincipalId::from_bytes([0x33; 32])?;
    let held = state.try_lock()?;
    let error = match read_local_state_snapshots(&state, &[principal_id]) {
        Ok(_) => return Err("backup state snapshot ignored the held edit lock".into()),
        Err(error) => error,
    };
    assert_eq!(error.code(), "local-state-error");
    drop(held);
    Ok(())
}

#[test]
fn backup_local_state_budget_rejects_oversized_audit_before_reading_it() -> TestResult {
    let temporary = tempfile::tempdir()?;
    let state_root = temporary.path().join("state");
    private_directory(&state_root)?;
    let vault_id = [0x11; 32];
    let genesis = [0x22; 32];
    let principal_id = PrincipalId::from_bytes([0x33; 32])?;
    let state = VaultStateDirectory::open_or_create(&state_root, &vault_id, &genesis, &[], &[])?;
    let principal_root = state_root
        .join(hex(&vault_id))
        .join(hex(&genesis))
        .join(hex(principal_id.as_bytes()));
    private_directory(&principal_root)?;
    let audit_path = principal_root.join("audit.jsonl");
    let audit = File::create(&audit_path)?;
    audit.set_len(u64::try_from(MAX_BACKUP_ENVELOPE_BYTES)? + 1)?;
    fs::set_permissions(&audit_path, fs::Permissions::from_mode(0o600))?;

    let error = match read_local_state_snapshots(&state, &[principal_id]) {
        Err(error) => error,
        Ok(_) => return Err("oversized audit should fail before allocation".into()),
    };
    assert_eq!(error.code(), "backup-audit-capacity-exhausted");
    assert!(!principal_root.join("checkpoint.json").exists());
    Ok(())
}

fn write_owner_backup(path: &Path) -> TestResult<Vec<u8>> {
    let identity_passphrase = protected(b"ExampleIdentityPassphrase")?;
    let created_identity = IdentityCreator::new().create(
        PrincipalKind::Human,
        KdfProfile::PortableV1,
        10,
        &identity_passphrase,
        |_| false,
    )?;
    let UnlockedIdentity::VaultPrincipal(owner) =
        unlock(&created_identity.file, &identity_passphrase)?
    else {
        return Err("fixture did not create a vault principal".into());
    };
    let created_policy = PolicyCreator::new().create(&owner, 11, |_| false)?;
    let genesis_fingerprint = created_policy.journal.genesis.recomputed_fingerprint()?;
    let vault = VaultFileV1 {
        header: VaultHeaderV1 {
            magic: "jury-vault".to_owned(),
            version: 1,
            vault_id: created_policy.journal.genesis.vault_id,
            created_at_ms: created_policy.journal.genesis.created_at_ms,
            suite: 1,
            policy_schema: 1,
            item_schema: 1,
            identity_schema: 1,
            genesis_fingerprint,
        },
        policy: created_policy.journal,
        items: Vec::new(),
        suite_migration: None,
    };
    vault.validate()?;
    let policy = replay_policy(&vault.policy)?;
    let checkpoint = CheckpointCandidate::from_validated(&policy, &vault.policy, &vault.items)?;
    let local = PrincipalLocalState::for_vault_principal(
        &owner,
        vault.header.vault_id,
        vault.header.genesis_fingerprint.clone(),
    )?;
    let files = local.serialize(&local.initialize(&checkpoint, 12)?)?;
    let identities = [BackupIdentitySource::VaultPrincipal {
        identity: &owner,
        local_state: LocalStateArchive {
            audit: files.audit(),
            checkpoint: files.checkpoint(),
            receipts: files.receipts(),
        },
    }];
    let backup_passphrase = protected(b"ExampleBackupPassphrase")?;
    let created = BackupCreator::new().create(BackupCreateRequest {
        vault: &vault,
        catalog: &TransferPublicCatalogV1::empty(),
        identities: &identities,
        profile: KdfProfile::PortableV1,
        created_at_ms: 13,
        backup_passphrase: &backup_passphrase,
    })?;
    let bytes = created.envelope().to_bytes()?;
    fs::write(path, &bytes)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(bytes)
}

fn register_test_role(
    vault: &mut VaultFileV1,
    owner: &VaultPrincipalIdentity,
    identity: UnlockedIdentity,
    label: &str,
    timestamp_ms: u64,
    witness_share_index: Option<u8>,
) -> TestResult<RegistrationProofV1> {
    let descriptor = identity.public_descriptor()?;
    let policy = replay_policy(&vault.policy)?;
    let challenge = RegistrationCreator::new(ProtectionPolicy::Strict).create_challenge(
        &policy,
        owner,
        descriptor.clone(),
        timestamp_ms,
        1_000,
        witness_share_index,
    )?;
    let proof = answer_challenge(&policy, &identity, &challenge, timestamp_ms + 1)?;
    let revision = policy.prepare_revision(
        owner,
        timestamp_ms + 2,
        vec![PolicyOperationV1::PrincipalAdd {
            descriptor,
            display_label: label.to_owned(),
            registration_proof_digest: proof.digest()?,
        }],
    )?;
    vault.policy.revisions.push(revision.revision);
    vault.validate()?;
    Ok(proof)
}

fn require_vault_principal(identity: UnlockedIdentity) -> TestResult<VaultPrincipalIdentity> {
    let UnlockedIdentity::VaultPrincipal(identity) = identity else {
        return Err("fixture did not create a vault principal".into());
    };
    Ok(identity)
}

fn require_approver(
    identity: UnlockedIdentity,
) -> TestResult<jury_core::identity::ApproverIdentity> {
    let UnlockedIdentity::Approver(identity) = identity else {
        return Err("fixture did not create an approver".into());
    };
    Ok(identity)
}

fn require_witness(identity: UnlockedIdentity) -> TestResult<jury_core::identity::WitnessIdentity> {
    let UnlockedIdentity::Witness(identity) = identity else {
        return Err("fixture did not create a witness".into());
    };
    Ok(identity)
}

fn write_all_roles_backup(path: &Path) -> TestResult<Vec<u8>> {
    let identity_passphrase = protected(b"ExampleIdentityPassphrase")?;
    let created_owner = IdentityCreator::new().create(
        PrincipalKind::Human,
        KdfProfile::PortableV1,
        10,
        &identity_passphrase,
        |_| false,
    )?;
    let owner = require_vault_principal(unlock(&created_owner.file, &identity_passphrase)?)?;
    let created_policy = PolicyCreator::new().create(&owner, 11, |_| false)?;
    let genesis_fingerprint = created_policy.journal.genesis.recomputed_fingerprint()?;
    let mut vault = VaultFileV1 {
        header: VaultHeaderV1 {
            magic: "jury-vault".to_owned(),
            version: 1,
            vault_id: created_policy.journal.genesis.vault_id,
            created_at_ms: created_policy.journal.genesis.created_at_ms,
            suite: 1,
            policy_schema: 1,
            item_schema: 1,
            identity_schema: 1,
            genesis_fingerprint,
        },
        policy: created_policy.journal,
        items: Vec::new(),
        suite_migration: None,
    };
    let created_approver = IdentityCreator::new().create(
        PrincipalKind::Approver,
        KdfProfile::PortableV1,
        20,
        &identity_passphrase,
        |_| false,
    )?;
    let approver = unlock(&created_approver.file, &identity_passphrase)?;
    let approver_proof =
        register_test_role(&mut vault, &owner, approver, "ExampleApprover", 21, None)?;
    let created_witness = IdentityCreator::new().create(
        PrincipalKind::Witness,
        KdfProfile::PortableV1,
        30,
        &identity_passphrase,
        |_| false,
    )?;
    let witness = unlock(&created_witness.file, &identity_passphrase)?;
    let witness_proof =
        register_test_role(&mut vault, &owner, witness, "ExampleWitness", 31, Some(7))?;
    let approver = require_approver(unlock(&created_approver.file, &identity_passphrase)?)?;
    let witness = require_witness(unlock(&created_witness.file, &identity_passphrase)?)?;
    let policy = replay_policy(&vault.policy)?;
    let checkpoint = CheckpointCandidate::from_validated(&policy, &vault.policy, &vault.items)?;
    let owner_local = PrincipalLocalState::for_vault_principal(
        &owner,
        vault.header.vault_id,
        vault.header.genesis_fingerprint.clone(),
    )?;
    let approver_local = PrincipalLocalState::for_approver(
        &approver,
        vault.header.vault_id,
        vault.header.genesis_fingerprint.clone(),
    )?;
    let witness_local = PrincipalLocalState::for_witness(
        &witness,
        vault.header.vault_id,
        vault.header.genesis_fingerprint.clone(),
    )?;
    let owner_files = owner_local.serialize(&owner_local.initialize(&checkpoint, 40)?)?;
    let approver_files = approver_local.serialize(&approver_local.initialize(&checkpoint, 40)?)?;
    let witness_files = witness_local.serialize(&witness_local.initialize(&checkpoint, 40)?)?;
    let identities = [
        BackupIdentitySource::VaultPrincipal {
            identity: &owner,
            local_state: LocalStateArchive {
                audit: owner_files.audit(),
                checkpoint: owner_files.checkpoint(),
                receipts: owner_files.receipts(),
            },
        },
        BackupIdentitySource::Approver {
            identity: &approver,
            local_state: LocalStateArchive {
                audit: approver_files.audit(),
                checkpoint: approver_files.checkpoint(),
                receipts: approver_files.receipts(),
            },
        },
        BackupIdentitySource::WitnessClient {
            identity: &witness,
            local_state: LocalStateArchive {
                audit: witness_files.audit(),
                checkpoint: witness_files.checkpoint(),
                receipts: witness_files.receipts(),
            },
        },
    ];
    let mut registration_proofs = vec![approver_proof, witness_proof];
    registration_proofs.sort_by_key(|proof| proof.candidate_principal_id);
    let catalog = TransferPublicCatalogV1::new(registration_proofs, Vec::new())?;
    let backup_passphrase = protected(b"ExampleBackupPassphrase")?;
    let created = BackupCreator::new().create(BackupCreateRequest {
        vault: &vault,
        catalog: &catalog,
        identities: &identities,
        profile: KdfProfile::PortableV1,
        created_at_ms: 41,
        backup_passphrase: &backup_passphrase,
    })?;
    let bytes = created.envelope().to_bytes()?;
    fs::write(path, &bytes)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(bytes)
}

fn restore_cli(
    backup: &Path,
    vault: PathBuf,
    identity: PathBuf,
    state: PathBuf,
) -> TestResult<Cli> {
    let envelope = BackupEnvelopeV1::parse(&fs::read(backup)?)?;
    Ok(Cli {
        json: true,
        home: Some(vault),
        global_home: false,
        identity: None,
        identity_file: None,
        expected_genesis: Some(hex(envelope.header.genesis_fingerprint.as_bytes())),
        passphrase_stdin: false,
        allow_degraded_protection: true,
        command: Command::Backup {
            command: BackupCommand::Restore(BackupRestoreArgs {
                input: backup.to_path_buf(),
                identity_out: Some(identity),
                reuse_identity: None,
                state_out: Some(state),
                approver_identity_out: None,
                witness_identity_out: None,
                identity_kdf_profile: KdfProfileArg::Portable,
            }),
        },
    })
}

fn restore_arguments(cli: &Cli) -> &BackupRestoreArgs {
    let Command::Backup {
        command: BackupCommand::Restore(arguments),
    } = &cli.command
    else {
        unreachable!("test CLI always carries restore arguments")
    };
    arguments
}

#[test]
fn restore_publishes_and_reads_back_every_included_identity_role() -> TestResult {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path();
    let offline = root.join("offline");
    let current = root.join("current");
    let data = root.join("data");
    let source_state = root.join("source-state");
    let vault_parent = root.join("vault-parent");
    let identity_parent = root.join("identity-parent");
    let state_parent = root.join("state-parent");
    for directory in [
        &offline,
        &current,
        &data,
        &source_state,
        &vault_parent,
        &identity_parent,
        &state_parent,
    ] {
        private_directory(directory)?;
    }
    let backup = offline.join("ExampleAllRoles.backup");
    write_all_roles_backup(&backup)?;
    let owner = identity_parent.join("ExampleOwner.identity");
    let approver = identity_parent.join("ExampleApprover.identity");
    let witness = identity_parent.join("ExampleWitness.identity");
    let vault = vault_parent.join("ExampleRestoredVault");
    let state = state_parent.join("ExampleRestoredState");
    let cli = Cli {
        json: true,
        home: Some(vault.clone()),
        global_home: false,
        identity: None,
        identity_file: None,
        expected_genesis: Some(hex(BackupEnvelopeV1::parse(&fs::read(&backup)?)?
            .header
            .genesis_fingerprint
            .as_bytes())),
        passphrase_stdin: false,
        allow_degraded_protection: true,
        command: Command::Backup {
            command: BackupCommand::Restore(BackupRestoreArgs {
                input: backup,
                identity_out: Some(owner.clone()),
                reuse_identity: None,
                state_out: Some(state.clone()),
                approver_identity_out: Some(approver.clone()),
                witness_identity_out: Some(witness.clone()),
                identity_kdf_profile: KdfProfileArg::Portable,
            }),
        },
    };
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
    let output = backup_restore(
        &cli,
        restore_arguments(&cli),
        &environment,
        &current,
        ProtectionPolicy::EmergencyAllowDegraded,
    )?;
    let CommandOutput::Safe { fields, lines, .. } = output else {
        return Err("restore returned an unexpected output shape".into());
    };
    assert_eq!(
        fields["included_identity_roles"],
        serde_json::json!(["vault-principal", "approver", "witness-client"])
    );
    assert!(fields["details"]["protection_degraded"].is_boolean());
    assert!(
        lines
            .iter()
            .any(|line| line.starts_with("Protection degraded: "))
    );
    assert!(vault.join("vault.json").is_file());
    assert!(owner.is_file());
    assert!(approver.is_file());
    assert!(witness.is_file());
    assert!(state.is_dir());
    assert!(!fs::read_dir(identity_parent)?.any(|entry| {
        entry.is_ok_and(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .starts_with(".jury-vault-restore-")
        })
    }));
    Ok(())
}

#[test]
fn restore_requires_and_validates_expected_genesis_before_publication() -> TestResult {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path();
    let offline = root.join("offline");
    let current = root.join("current");
    let data = root.join("data");
    let source_state = root.join("source-state");
    let vault_parent = root.join("vault-parent");
    let identity_parent = root.join("identity-parent");
    let state_parent = root.join("state-parent");
    for directory in [
        &offline,
        &current,
        &data,
        &source_state,
        &vault_parent,
        &identity_parent,
        &state_parent,
    ] {
        private_directory(directory)?;
    }
    let backup = offline.join("ExampleVault.backup");
    write_owner_backup(&backup)?;
    let vault = vault_parent.join("ExampleRestoredVault");
    let identity = identity_parent.join("ExampleRestoredOwner.identity");
    let state = state_parent.join("ExampleRestoredState");
    let mut cli = restore_cli(&backup, vault.clone(), identity.clone(), state.clone())?;
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

    cli.expected_genesis = None;
    let missing_error = backup_restore(
        &cli,
        restore_arguments(&cli),
        &environment,
        &current,
        ProtectionPolicy::EmergencyAllowDegraded,
    )
    .err()
    .ok_or("missing expected genesis unexpectedly restored the backup")?;
    assert_eq!(missing_error.code(), "expected-genesis-required");
    assert!(!vault.exists());
    assert!(!identity.exists());
    assert!(!state.exists());

    cli.expected_genesis = Some(hex(&[0xff; 32]));
    let error = backup_restore(
        &cli,
        restore_arguments(&cli),
        &environment,
        &current,
        ProtectionPolicy::EmergencyAllowDegraded,
    )
    .err()
    .ok_or("wrong expected genesis unexpectedly restored the backup")?;
    assert_eq!(error.code(), "genesis-fingerprint-mismatch");
    assert!(!vault.exists());
    assert!(!identity.exists());
    assert!(!state.exists());
    assert!(!fs::read_dir(identity_parent)?.any(|entry| {
        entry.is_ok_and(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .starts_with(".jury-vault-restore-")
        })
    }));
    Ok(())
}

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
                if !injected && observed == fault {
                    injected = true;
                    Err(CliError::new(
                        CliErrorKind::Filesystem,
                        "injected-restore-failure",
                        "injected restore failure",
                    ))
                } else {
                    Ok(())
                }
            },
        );
        let error = match injected_result {
            Err(error) => error,
            Ok(_) => return Err("the selected transaction point was not injected".into()),
        };
        assert_eq!(error.code(), "injected-restore-failure");
        assert!(injected);

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
