use super::*;

pub(super) fn backup_create(
    cli: &Cli,
    arguments: &BackupCreateArgs,
    environment: &Environment,
    current: &Path,
    protection: ProtectionPolicy,
) -> Result<CommandOutput, CliError> {
    let home = selected_home(cli, environment, current)?;
    let output_root = private_backup_parent(&home, &arguments.out)?;
    let output_parent = arguments.out.parent().ok_or_else(filesystem_error)?;
    let identity_home = identity_root(environment)?;
    let (owner_selector, _) = selected_identity(cli, None, environment)?;
    let owner_identity_parent = match &owner_selector {
        IdentitySelector::Named(_) => identity_home.as_path(),
        IdentitySelector::ExplicitFile(path) => path.parent().ok_or_else(invalid_restore_target)?,
    };
    let state_home = resolve_linux_state_root(
        environment.jury_state_home.as_deref(),
        environment.xdg_state_home.as_deref(),
        environment.user_home.as_deref(),
    )
    .map_err(|_| filesystem_error())?;
    let additional_identity_parents = [
        arguments.approver_identity_file.as_deref(),
        arguments.witness_identity_file.as_deref(),
    ]
    .into_iter()
    .flatten()
    .map(|path| {
        direct_utf8_path(path)?;
        path.parent().ok_or_else(invalid_restore_target)
    })
    .collect::<Result<Vec<_>, _>>()?;
    if overlaps(output_parent, &identity_home)
        || overlaps(output_parent, owner_identity_parent)
        || overlaps(output_parent, &state_home)
        || additional_identity_parents
            .iter()
            .any(|parent| overlaps(output_parent, parent))
    {
        return Err(containment_error());
    }
    let output_name = arguments.out.file_name().ok_or_else(filesystem_error)?;
    let destination = output_root
        .preview_private_file(Path::new(output_name))
        .map_err(map_filesystem_error)?;
    if destination.destination_exists() && !arguments.overwrite {
        return Err(CliError::new(
            CliErrorKind::Conflict,
            "backup-exists",
            "the selected backup destination already exists",
        ));
    }

    let (context, identity_passphrase) =
        load_vault_principal_with_passphrase(cli, environment, current, protection)?;
    let mut additional = Vec::new();
    let mut additional_passphrases = Vec::new();
    if let Some(path) = &arguments.approver_identity_file {
        let (identity, passphrase) = load_additional_backup_identity(
            &context,
            path,
            RecoveryRole::Approver,
            "Approver identity passphrase",
            cli,
            protection,
        )?;
        additional.push(identity);
        additional_passphrases.push(passphrase);
    }
    if let Some(path) = &arguments.witness_identity_file {
        let (identity, passphrase) = load_additional_backup_identity(
            &context,
            path,
            RecoveryRole::WitnessClient,
            "Witness identity passphrase",
            cli,
            protection,
        )?;
        additional.push(identity);
        additional_passphrases.push(passphrase);
    }
    let principal_id = context.identity.principal_id();
    let mut state_principal_ids = vec![principal_id];
    state_principal_ids.extend(additional.iter().map(|entry| match &entry.identity {
        UnlockedIdentity::Approver(identity) => identity.principal_id(),
        UnlockedIdentity::Witness(identity) => identity.principal_id(),
        UnlockedIdentity::VaultPrincipal(identity) => identity.principal_id(),
    }));
    let local_state_snapshots = read_local_state_snapshots(&context.state, &state_principal_ids)?;
    let catalog = context.catalog.transfer_catalog(&context.policy)?;
    let backup_passphrase = secret_input::capture_named_or_environment(
        protection,
        cli.passphrase_stdin,
        true,
        "Backup passphrase",
        environment
            .jury_backup_passphrase
            .as_deref()
            .map(Vec::as_slice),
    )
    .map_err(map_secret_error)?;
    let passphrases_match = identity_passphrase
        .matches(&backup_passphrase)
        .map_err(map_secret_error)?
        || additional_passphrases
            .iter()
            .map(|passphrase| passphrase.matches(&backup_passphrase))
            .collect::<Result<Vec<_>, _>>()
            .map_err(map_secret_error)?
            .into_iter()
            .any(|matches| matches);
    if passphrases_match && !arguments.reuse_identity_passphrase {
        return Err(CliError::new(
            CliErrorKind::InvalidArguments,
            "independent-backup-passphrase-required",
            "backup and identity passphrases match; deliberate reuse requires --reuse-identity-passphrase",
        ));
    }
    drop(identity_passphrase);
    drop(additional_passphrases);
    let (owner_local_state, additional_local_state) = local_state_snapshots
        .split_first()
        .ok_or_else(local_state_error)?;
    let local_state = LocalStateArchive {
        audit: &owner_local_state.audit,
        checkpoint: &owner_local_state.checkpoint,
        receipts: &owner_local_state.receipts,
    };
    let mut identities = vec![BackupIdentitySource::VaultPrincipal {
        identity: &context.identity,
        local_state,
    }];
    for (entry, local_state_snapshot) in additional.iter().zip(additional_local_state) {
        let local_state = LocalStateArchive {
            audit: &local_state_snapshot.audit,
            checkpoint: &local_state_snapshot.checkpoint,
            receipts: &local_state_snapshot.receipts,
        };
        identities.push(match &entry.identity {
            UnlockedIdentity::Approver(identity) => BackupIdentitySource::Approver {
                identity,
                local_state,
            },
            UnlockedIdentity::Witness(identity) => BackupIdentitySource::WitnessClient {
                identity,
                local_state,
            },
            UnlockedIdentity::VaultPrincipal(_) => return Err(invalid_identity()),
        });
    }
    let created_at_ms = timestamp_ms()?;
    let created = BackupCreator::new()
        .create(BackupCreateRequest {
            vault: &context.vault,
            catalog: &catalog,
            identities: &identities,
            profile: arguments.kdf_profile.into(),
            created_at_ms,
            backup_passphrase: backup_passphrase.memory(),
        })
        .map_err(map_backup_error)?;
    let header = created.envelope().header.clone();
    let coverage = created.coverage().clone();
    let bytes = created
        .into_envelope()
        .to_bytes()
        .map_err(|_| invalid_backup())?;
    let publication = PreparedPrivateFile::prepare_bounded_private_bytes_if_unchanged(
        destination,
        &bytes,
        MAX_BACKUP_ENVELOPE_BYTES,
        arguments.overwrite,
    )
    .map_err(map_filesystem_error)?
    .publish()
    .map_err(map_filesystem_error)?;
    let local_receipt_recorded = publication == PublicationOutcome::PublishedAndSynced
        && record_backup_receipt(&context, backup_receipt(&header, &coverage), protection).is_ok();
    let mut lines = coverage_lines(&coverage);
    lines.insert(
        0,
        "Backup created. Anyone with its passphrase can recover the included owner identity and current direct-access items; it is more sensitive than a transfer."
            .to_owned(),
    );
    lines.push(format!("Durability: {}", durability(publication)));
    if passphrases_match {
        lines.push(
            "Warning: deliberate identity-passphrase reuse reduces custody independence."
                .to_owned(),
        );
    }
    if !local_receipt_recorded {
        lines.push(
            "The archive was published, but its authenticated local creation receipt was not recorded."
                .to_owned(),
        );
    }
    Ok(recovery_output(
        "backup-create",
        &header,
        &coverage,
        serde_json::json!({
            "artifact_bytes": bytes.len(),
            "durability": durability(publication),
            "local_creation_receipt_recorded": local_receipt_recorded,
            "identity_passphrase_reused": passphrases_match,
            "protection_degraded": context.protection_degraded || backup_passphrase.protection_degraded(),
        }),
        lines,
    ))
}

pub(super) fn backup_verify(
    cli: &Cli,
    arguments: &BackupVerifyArgs,
    environment: &Environment,
    current: &Path,
    protection: ProtectionPolicy,
) -> Result<CommandOutput, CliError> {
    let bytes = read_private_file(&arguments.input, MAX_BACKUP_ENVELOPE_BYTES)
        .map_err(map_filesystem_error)?;
    let envelope = BackupEnvelopeV1::parse(&bytes).map_err(|_| invalid_backup())?;
    let backup_passphrase = secret_input::capture_named_or_environment(
        protection,
        cli.passphrase_stdin,
        false,
        "Backup passphrase",
        environment
            .jury_backup_passphrase
            .as_deref()
            .map(Vec::as_slice),
    )
    .map_err(map_secret_error)?;
    let recovered = open_backup(&envelope, backup_passphrase.memory()).map_err(map_backup_error)?;
    let context = load_vault_principal(cli, environment, current, protection)?;
    if context.vault.header.vault_id != recovered.header().vault_id
        || context.vault.header.genesis_fingerprint != recovered.header().genesis_fingerprint
        || context.identity.principal_id() != recovered.header().owner_principal_id
    {
        return Err(CliError::new(
            CliErrorKind::Conflict,
            "backup-current-state-mismatch",
            "the verified backup does not match the selected vault and owner identity",
        ));
    }
    let verified_at_ms = timestamp_ms()?;
    let local_receipt_recorded = record_backup_verification_receipt(
        &context,
        BackupVerificationReceipt {
            backup_id: digest_from_recovery_id(&recovered.header().backup_id),
            captured_public_revision_hash: recovered.header().source_public_revision_hash.clone(),
            timestamp_ms: verified_at_ms,
            payload_digest: recovered.header().payload_digest.clone(),
        },
        protection,
    )
    .is_ok();
    let mut lines =
        vec!["Backup fully decrypted and validated without publishing a restore.".to_owned()];
    lines.extend(coverage_lines(recovered.coverage()));
    if !local_receipt_recorded {
        lines.push(
            "Verification succeeded, but no matching authenticated local verification receipt was recorded."
                .to_owned(),
        );
    }
    Ok(recovery_output(
        "backup-verify",
        recovered.header(),
        recovered.coverage(),
        serde_json::json!({
            "verified_at_ms": verified_at_ms,
            "published_restore": false,
            "local_verification_receipt_recorded": local_receipt_recorded,
            "protection_degraded": context.protection_degraded || backup_passphrase.protection_degraded(),
        }),
        lines,
    ))
}

pub(super) fn backup_status(
    cli: &Cli,
    environment: &Environment,
    current: &Path,
    protection: ProtectionPolicy,
) -> Result<CommandOutput, CliError> {
    let context = load_vault_principal(cli, environment, current, protection)?;
    let receipts = recovery_receipts(&context)?;
    let current_revision = context.policy.terminal_revision_hash();
    let creation_state = match &receipts.backup {
        None => "unknown",
        Some(receipt) if &receipt.captured_public_revision_hash == current_revision => "current",
        Some(_) => "stale",
    };
    let matching_verification = receipts.backup.as_ref().and_then(|backup| {
        receipts.verification.as_ref().filter(|verification| {
            verification.backup_id == backup.backup_id
                && verification.payload_digest == backup.payload_digest
                && verification.captured_public_revision_hash
                    == backup.captured_public_revision_hash
        })
    });
    let matching_drill = receipts.backup.as_ref().and_then(|backup| {
        receipts.drill.as_ref().filter(|drill| {
            drill.backup_id == backup.backup_id
                && drill.captured_public_revision_hash == backup.captured_public_revision_hash
        })
    });
    let verified = matching_verification.is_some();
    let drilled = matching_drill.is_some();
    let now = timestamp_ms()?;
    let age_ms = receipts
        .backup
        .as_ref()
        .map(|receipt| now.saturating_sub(receipt.timestamp_ms));
    let role_names = receipts.backup.as_ref().map_or_else(Vec::new, |receipt| {
        role_names_from_mask(receipt.identity_role_mask)
    });
    let direct_items = receipts.backup.as_ref().map_or_else(Vec::new, |receipt| {
        receipt
            .direct_item_ids
            .iter()
            .map(|id| hex(id.as_bytes()))
            .collect()
    });
    let witnessed_items = receipts.backup.as_ref().map_or_else(Vec::new, |receipt| {
        receipt
            .witnessed_item_ids
            .iter()
            .map(|id| hex(id.as_bytes()))
            .collect()
    });
    let unavailable_witnessed_items = receipts.backup.as_ref().map_or_else(Vec::new, |receipt| {
        receipt
            .unavailable_witnessed_item_ids
            .iter()
            .map(|id| hex(id.as_bytes()))
            .collect()
    });
    let external_required = receipts
        .backup
        .as_ref()
        .is_some_and(|receipt| receipt.external_witness_recovery_required);
    let has_approver = receipts
        .backup
        .as_ref()
        .is_some_and(|receipt| receipt.identity_role_mask & 2 != 0);
    let has_witness = receipts
        .backup
        .as_ref()
        .is_some_and(|receipt| receipt.identity_role_mask & 4 != 0);
    let mut create_command = String::from("jury backup create --out ABSOLUTE_FILE");
    let mut drill_command = String::from(
        "jury backup drill --in ABSOLUTE_FILE --vault-out ABSENT_PATH --identity-out ABSENT_PATH --state-out ABSENT_PATH",
    );
    if has_approver {
        create_command.push_str(" --approver-identity-file FILE");
        drill_command.push_str(" --approver-identity-out ABSENT_PATH");
    }
    if has_witness {
        create_command.push_str(" --witness-identity-file FILE");
        drill_command.push_str(" --witness-identity-out ABSENT_PATH");
    }
    let next_command = if receipts.backup.is_none() || creation_state == "stale" {
        create_command
    } else if !verified {
        "jury backup verify --in ABSOLUTE_FILE".to_owned()
    } else if !drilled {
        drill_command
    } else if external_required {
        "complete the separate J23 witness-service recovery path before witnessed private use"
            .to_owned()
    } else {
        "none".to_owned()
    };
    Ok(CommandOutput::Safe {
        operation: "backup-status",
        fields: serde_json::json!({
            "creation": creation_state,
            "verification": if verified { "recorded" } else { "unknown" },
            "real_restore_drill": if drilled { "recorded" } else { "unknown" },
            "current_public_revision": hex(current_revision.as_bytes()),
            "captured_public_revision": receipts.backup.as_ref().map(|receipt| hex(receipt.captured_public_revision_hash.as_bytes())),
            "backup_age_ms": age_ms,
            "last_full_verification_at_ms": matching_verification.map(|receipt| receipt.timestamp_ms),
            "included_identity_roles": role_names,
            "direct_item_ids": direct_items,
            "witnessed_item_ids": witnessed_items,
            "unavailable_witnessed_item_ids": unavailable_witnessed_items,
            "local_verification_state_included": receipts.backup.as_ref().is_some_and(|receipt| receipt.checkpoints_current),
            "external_witness_recovery_required": external_required,
            "backup_file_exists_or_readable": "unknown",
            "recovers_juryd_replay_state": false,
            "recovers_external_anchors": false,
            "proves_witness_availability": false,
            "proves_quorum_availability": false,
            "next_command": &next_command,
        }),
        lines: vec![
            format!("Backup creation: {creation_state}"),
            format!("Full verification: {}", if verified { "recorded" } else { "unknown" }),
            format!("Real restore drill: {}", if drilled { "recorded" } else { "unknown" }),
            format!("Next: {next_command}"),
            "A local receipt cannot prove that a backup file still exists or remains readable."
                .to_owned(),
            "Client recovery does not recover juryd replay state, external anchors, witness availability, or quorum availability."
                .to_owned(),
        ],
    })
}

pub(super) fn backup_restore(
    cli: &Cli,
    arguments: &BackupRestoreArgs,
    environment: &Environment,
    current: &Path,
    protection: ProtectionPolicy,
) -> Result<CommandOutput, CliError> {
    backup_restore_with_observer(
        cli,
        arguments,
        environment,
        current,
        protection,
        &mut |_| Ok(()),
    )
}

fn backup_restore_with_observer(
    cli: &Cli,
    arguments: &BackupRestoreArgs,
    environment: &Environment,
    current: &Path,
    protection: ProtectionPolicy,
    observer: &mut dyn FnMut(RestorePublicationPoint) -> Result<(), CliError>,
) -> Result<CommandOutput, CliError> {
    let mut target_home = selected_home(cli, environment, current)?;
    let identity_target = arguments
        .identity_out
        .as_deref()
        .or(arguments.reuse_identity.as_deref())
        .ok_or_else(|| {
            CliError::new(
                CliErrorKind::InvalidArguments,
                "identity-restore-target-required",
                "select either an absent identity output or an exact existing identity",
            )
        })?;
    let state_root = match &arguments.state_out {
        Some(path) => path.clone(),
        None => resolve_linux_state_root(
            environment.jury_state_home.as_deref(),
            environment.xdg_state_home.as_deref(),
            environment.user_home.as_deref(),
        )
        .map_err(|_| filesystem_error())?,
    };
    let restored = restore_archive_with_observer(
        RestoreRequest {
            cli,
            input: &arguments.input,
            target_home: &mut target_home,
            identity_target,
            approver_identity_target: arguments.approver_identity_out.as_deref(),
            witness_identity_target: arguments.witness_identity_out.as_deref(),
            reuse_identity: arguments.reuse_identity.is_some(),
            identity_profile: arguments.identity_kdf_profile.into(),
            state_root: &state_root,
            require_absent_state_root: false,
            environment,
            protection,
            validate_access: false,
        },
        observer,
    )?;
    let mut lines = vec![
        "Backup restored without overwriting an existing vault or identity.".to_owned(),
        format!("Transaction marker removed: {}", restored.marker_removed),
    ];
    lines.extend(coverage_lines(&restored.coverage));
    Ok(recovery_output(
        "backup-restore",
        &restored.header,
        &restored.coverage,
        serde_json::json!({
            "committed": true,
            "identity_reused": arguments.reuse_identity.is_some(),
            "restored_direct_access_validated": false,
            "transaction_marker_removed": restored.marker_removed,
            "local_state_published": true,
        }),
        lines,
    ))
}

pub(super) fn backup_drill(
    cli: &Cli,
    arguments: &BackupDrillArgs,
    environment: &Environment,
    current: &Path,
    protection: ProtectionPolicy,
) -> Result<CommandOutput, CliError> {
    let source_home = selected_home(cli, environment, current)?;
    if source_home
        .detached_path()
        .is_some_and(|source| overlaps(source, &arguments.vault_out))
    {
        return Err(containment_error());
    }
    let mut target_home = VaultHomeLocation::Detached {
        path: arguments.vault_out.clone(),
        source: HomeSource::Explicit,
    };
    let restored = restore_archive(RestoreRequest {
        cli,
        input: &arguments.input,
        target_home: &mut target_home,
        identity_target: &arguments.identity_out,
        approver_identity_target: arguments.approver_identity_out.as_deref(),
        witness_identity_target: arguments.witness_identity_out.as_deref(),
        reuse_identity: false,
        identity_profile: arguments.identity_kdf_profile.into(),
        state_root: &arguments.state_out,
        require_absent_state_root: true,
        environment,
        protection,
        validate_access: true,
    })?;

    // Receipt authentication intentionally happens only after the restored
    // files were read back and every direct descriptor was actually opened.
    let source = load_vault_principal(cli, environment, current, protection)?;
    if source.vault.header.vault_id != restored.header.vault_id
        || source.vault.header.genesis_fingerprint != restored.header.genesis_fingerprint
        || source.identity.principal_id() != restored.header.owner_principal_id
    {
        return Err(CliError::new(
            CliErrorKind::Conflict,
            "drill-source-mismatch",
            "the committed drill does not match the selected source owner and vault",
        ));
    }
    let receipt_recorded = record_restore_drill_receipt(
        &source,
        RestoreDrillReceipt {
            backup_id: digest_from_recovery_id(&restored.header.backup_id),
            captured_public_revision_hash: restored.header.source_public_revision_hash.clone(),
            timestamp_ms: timestamp_ms()?,
            output_digest: restored.output_digest,
        },
        protection,
    )
    .is_ok();
    let mut lines = vec![
        "Real restore drill committed; restored direct descriptors were opened and validated."
            .to_owned(),
        "The drill copy remains in place for operator inspection.".to_owned(),
    ];
    lines.extend(coverage_lines(&restored.coverage));
    if !receipt_recorded {
        lines.push(
            "The restore remains committed, but its source drill receipt was not recorded."
                .to_owned(),
        );
    }
    Ok(recovery_output(
        "backup-drill",
        &restored.header,
        &restored.coverage,
        serde_json::json!({
            "committed": true,
            "restored_direct_access_validated": true,
            "source_drill_receipt_recorded": receipt_recorded,
            "drill_copy_retained": true,
            "transaction_marker_removed": restored.marker_removed,
            "external_witness_recovery_complete": !restored.coverage.external_witness_recovery_required,
            "local_state_published": true,
        }),
        lines,
    ))
}

const MAX_RESTORE_MARKER_BYTES: usize = 16 * 1024;

struct AdditionalBackupIdentity {
    identity: UnlockedIdentity,
}

struct LocalStateSnapshot {
    audit: Vec<u8>,
    checkpoint: Vec<u8>,
    receipts: Vec<u8>,
}

fn read_local_state_snapshots(
    state: &VaultStateDirectory,
    principal_ids: &[PrincipalId],
) -> Result<Vec<LocalStateSnapshot>, CliError> {
    let locked = state.try_lock().map_err(|_| local_state_error())?;
    principal_ids
        .iter()
        .map(|principal_id| {
            Ok(LocalStateSnapshot {
                audit: locked
                    .read(principal_id.as_bytes(), PrincipalStateFile::Audit)
                    .map_err(map_filesystem_error)?,
                checkpoint: locked
                    .read(principal_id.as_bytes(), PrincipalStateFile::Checkpoint)
                    .map_err(map_filesystem_error)?,
                receipts: locked
                    .read(principal_id.as_bytes(), PrincipalStateFile::Receipts)
                    .map_err(map_filesystem_error)?,
            })
        })
        .collect()
}

fn load_additional_backup_identity(
    context: &VaultPrincipalContext,
    path: &Path,
    role: RecoveryRole,
    label: &str,
    cli: &Cli,
    protection: ProtectionPolicy,
) -> Result<(AdditionalBackupIdentity, secret_input::CapturedPassphrase), CliError> {
    direct_utf8_path(path)?;
    let parent = path.parent().ok_or_else(invalid_restore_target)?;
    validate_detached_separation(parent, &context.home)?;
    let root = HardenedStateRoot::open_existing(parent, &repository_refs(&context.home))
        .map_err(map_filesystem_error)?;
    let selector =
        IdentitySelector::select(None, Some(path.to_path_buf())).map_err(|_| invalid_identity())?;
    let bytes = selector
        .read(
            &root,
            &repository_refs(&context.home),
            MAX_IDENTITY_FILE_BYTES,
        )
        .map_err(map_filesystem_error)?;
    let file = IdentityFileV1::parse(&bytes).map_err(|_| invalid_identity())?;
    let passphrase = secret_input::capture_named(protection, cli.passphrase_stdin, false, label)
        .map_err(map_secret_error)?;
    let identity =
        unlock(&file, passphrase.memory()).map_err(|error| map_identity_error(error.kind()))?;
    let role_matches = matches!(
        (&identity, role),
        (UnlockedIdentity::Approver(_), RecoveryRole::Approver)
            | (UnlockedIdentity::Witness(_), RecoveryRole::WitnessClient)
    );
    if !role_matches {
        return Err(CliError::new(
            CliErrorKind::InvalidIdentity,
            "backup-role-identity-mismatch",
            "an explicitly selected backup identity has the wrong local role",
        ));
    }
    Ok((AdditionalBackupIdentity { identity }, passphrase))
}

#[derive(Clone, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct RestoreMarker {
    version: u16,
    transaction_id: String,
    backup_id: String,
    vault_target: String,
    identity_target: String,
    state_root: String,
    vault_id: String,
    genesis_fingerprint: String,
    payload_digest: String,
    timestamp_ms: u64,
    identity_reused: bool,
    identity_published: bool,
    approver_identity_target: Option<String>,
    approver_identity_published: bool,
    witness_identity_target: Option<String>,
    witness_identity_published: bool,
    vault_published: bool,
    state_published: bool,
}

struct RestoreRequest<'a> {
    cli: &'a Cli,
    input: &'a Path,
    target_home: &'a mut VaultHomeLocation,
    identity_target: &'a Path,
    approver_identity_target: Option<&'a Path>,
    witness_identity_target: Option<&'a Path>,
    reuse_identity: bool,
    identity_profile: KdfProfile,
    state_root: &'a Path,
    require_absent_state_root: bool,
    environment: &'a Environment,
    protection: ProtectionPolicy,
    validate_access: bool,
}

struct RestoredInstallation {
    header: jury_protocol::backup_v1::BackupHeaderV1,
    coverage: RecoveryCoverage,
    output_digest: Digest32,
    marker_removed: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RestorePublicationPoint {
    MarkerCreated,
    OwnerIdentityPublished,
    ApproverIdentityPublished,
    WitnessIdentityPublished,
    VaultPublished,
    StateFilePublished,
}

fn restore_archive(request: RestoreRequest<'_>) -> Result<RestoredInstallation, CliError> {
    restore_archive_with_observer(request, &mut |_| Ok(()))
}

fn restore_archive_with_observer(
    request: RestoreRequest<'_>,
    observer: &mut dyn FnMut(RestorePublicationPoint) -> Result<(), CliError>,
) -> Result<RestoredInstallation, CliError> {
    validate_restore_paths(&request)?;
    let archive_bytes = read_private_file(request.input, MAX_BACKUP_ENVELOPE_BYTES)
        .map_err(map_filesystem_error)?;
    let envelope = BackupEnvelopeV1::parse(&archive_bytes).map_err(|_| invalid_backup())?;
    let identity_parent = request
        .identity_target
        .parent()
        .ok_or_else(filesystem_error)?;
    let identity_name = request
        .identity_target
        .file_name()
        .ok_or_else(filesystem_error)?;
    let identity_root =
        HardenedStateRoot::open_existing(identity_parent, &repository_refs(request.target_home))
            .map_err(map_filesystem_error)?;
    let identity_preview = identity_root
        .preview_private_file(Path::new(identity_name))
        .map_err(map_filesystem_error)?;
    let marker_name = marker_name(&envelope.header.backup_id);
    let prior_marker_bytes =
        match identity_root.read_private_file(Path::new(&marker_name), MAX_RESTORE_MARKER_BYTES) {
            Ok(bytes) => Some(bytes),
            Err(error) if error.kind() == FilesystemErrorKind::NotFound => None,
            Err(error) => return Err(map_filesystem_error(error)),
        };
    let prior_marker = prior_marker_bytes
        .as_deref()
        .map(parse_marker)
        .transpose()?;
    if prior_marker.is_none() {
        preflight_new_restore_targets(&request, identity_preview.destination_exists(), &envelope)?;
    }

    let backup_passphrase = secret_input::capture_named_or_environment(
        request.protection,
        request.cli.passphrase_stdin,
        false,
        "Backup passphrase",
        request
            .environment
            .jury_backup_passphrase
            .as_deref()
            .map(Vec::as_slice),
    )
    .map_err(map_secret_error)?;
    let recovered = open_backup(&envelope, backup_passphrase.memory()).map_err(map_backup_error)?;
    let owner = recovered
        .identity(RecoveryRole::VaultPrincipal)
        .ok_or_else(invalid_backup)?;
    validate_role_restore_targets(&request, &recovered)?;
    let vault_target = vault_target_label(request.target_home)?;
    let mut marker = RestoreMarker {
        version: 1,
        transaction_id: hex(recovered.header().backup_id.as_bytes()),
        backup_id: hex(recovered.header().backup_id.as_bytes()),
        vault_target,
        identity_target: direct_utf8_path(request.identity_target)?,
        state_root: direct_utf8_path(request.state_root)?,
        vault_id: hex(recovered.header().vault_id.as_bytes()),
        genesis_fingerprint: hex(recovered.header().genesis_fingerprint.as_bytes()),
        payload_digest: hex(recovered.header().payload_digest.as_bytes()),
        timestamp_ms: match &prior_marker {
            Some(marker) => marker.timestamp_ms,
            None => timestamp_ms()?,
        },
        identity_reused: request.reuse_identity,
        identity_published: request.reuse_identity,
        approver_identity_target: request
            .approver_identity_target
            .map(direct_utf8_path)
            .transpose()?,
        approver_identity_published: false,
        witness_identity_target: request
            .witness_identity_target
            .map(direct_utf8_path)
            .transpose()?,
        witness_identity_published: false,
        vault_published: false,
        state_published: false,
    };
    if let Some(prior) = prior_marker {
        let states = (
            prior.identity_published,
            prior.approver_identity_published,
            prior.witness_identity_published,
            prior.vault_published,
            prior.state_published,
        );
        let mut expected = marker.clone();
        expected.identity_published = prior.identity_published;
        expected.approver_identity_published = prior.approver_identity_published;
        expected.witness_identity_published = prior.witness_identity_published;
        expected.vault_published = prior.vault_published;
        expected.state_published = prior.state_published;
        if prior != expected {
            return Err(CliError::new(
                CliErrorKind::Conflict,
                "restore-marker-mismatch",
                "an existing restore marker belongs to different authenticated targets",
            ));
        }
        (
            marker.identity_published,
            marker.approver_identity_published,
            marker.witness_identity_published,
            marker.vault_published,
            marker.state_published,
        ) = states;
    }

    if marker.identity_published
        && !request.reuse_identity
        && !identity_preview.destination_exists()
    {
        return Err(restore_partial_conflict());
    }

    let identity_environment = if request.reuse_identity {
        request.environment.jury_identity_passphrase.as_deref()
    } else {
        request.environment.jury_new_passphrase.as_deref()
    };
    let identity_passphrase = secret_input::capture_named_or_environment(
        request.protection,
        request.cli.passphrase_stdin,
        !request.reuse_identity,
        if request.reuse_identity {
            "Identity passphrase"
        } else {
            "New identity passphrase"
        },
        identity_environment.map(Vec::as_slice),
    )
    .map_err(map_secret_error)?;
    if !request.reuse_identity
        && backup_passphrase
            .matches(&identity_passphrase)
            .map_err(map_secret_error)?
    {
        return Err(independent_restored_identity_passphrase_required());
    }
    let selector = IdentitySelector::select(None, Some(request.identity_target.to_path_buf()))
        .map_err(|_| invalid_restore_target())?;
    let (identity_file, publish_identity) = if identity_preview.destination_exists() {
        let bytes = selector
            .read(
                &identity_root,
                &repository_refs(request.target_home),
                MAX_IDENTITY_FILE_BYTES,
            )
            .map_err(map_filesystem_error)?;
        let file = IdentityFileV1::parse(&bytes).map_err(|_| invalid_identity())?;
        let unlocked = unlock(&file, identity_passphrase.memory())
            .map_err(|error| map_identity_error(error.kind()))?;
        if !owner
            .identity()
            .matches_unlocked(&unlocked)
            .map_err(|error| map_identity_error(error.kind()))?
            || (!request.reuse_identity && prior_marker_bytes.is_none())
        {
            return Err(CliError::new(
                CliErrorKind::Conflict,
                "restore-identity-mismatch",
                "the existing identity is not an authenticated retry target for this backup",
            ));
        }
        (file, false)
    } else {
        if request.reuse_identity {
            return Err(CliError::new(
                CliErrorKind::NotFound,
                "reuse-identity-not-found",
                "the selected identity to reuse does not exist",
            ));
        }
        let created = IdentityCreator::new()
            .restore(
                owner.identity(),
                request.identity_profile,
                marker.timestamp_ms,
                identity_passphrase.memory(),
            )
            .map_err(|error| map_identity_error(error.kind()))?;
        (created.file, true)
    };
    let identity_bytes = identity_file
        .to_json_bytes()
        .map_err(|_| invalid_identity())?;
    if prior_marker_bytes.is_none() {
        write_marker(&identity_root, &marker, false, request.protection)?;
        observer(RestorePublicationPoint::MarkerCreated)?;
    }
    if publish_identity {
        let protected = protect(&identity_bytes, request.protection)?;
        let outcome = selector
            .prepare(
                &identity_root,
                &repository_refs(request.target_home),
                &protected,
                PublicationPolicy::CreateNew,
            )
            .map_err(map_filesystem_error)?
            .publish()
            .map_err(map_filesystem_error)?;
        require_durable_restore_step(outcome)?;
        observer(RestorePublicationPoint::OwnerIdentityPublished)?;
    }
    if !marker.identity_published {
        marker.identity_published = true;
        write_marker(&identity_root, &marker, true, request.protection)?;
    }

    if let Some(target) = request.approver_identity_target {
        restore_additional_role_identity(
            &request,
            &recovered,
            RecoveryRole::Approver,
            target,
            "New approver identity passphrase",
            &identity_root,
            &mut marker,
            prior_marker_bytes.is_some(),
            &backup_passphrase,
            observer,
        )?;
    }
    if let Some(target) = request.witness_identity_target {
        restore_additional_role_identity(
            &request,
            &recovered,
            RecoveryRole::WitnessClient,
            target,
            "New witness identity passphrase",
            &identity_root,
            &mut marker,
            prior_marker_bytes.is_some(),
            &backup_passphrase,
            observer,
        )?;
    }

    match read_vault(request.target_home) {
        Ok(observed) => {
            if observed != recovered.vault_bytes() || prior_marker_bytes.is_none() {
                return Err(restore_partial_conflict());
            }
            if !marker.vault_published {
                marker.vault_published = true;
                write_marker(&identity_root, &marker, true, request.protection)?;
            }
        }
        Err(error) if error.kind() == CliErrorKind::NotFound => {
            if marker.vault_published {
                return Err(restore_partial_conflict());
            }
            ensure_detached_restore_home(request.target_home, prior_marker_bytes.is_some())?;
            let protected_vault = protect(recovered.vault_bytes(), request.protection)?;
            let outcome = prepare_new_vault(request.target_home, &protected_vault)?
                .publish()
                .map_err(map_filesystem_error)?;
            require_durable_restore_step(outcome)?;
            observer(RestorePublicationPoint::VaultPublished)?;
            marker.vault_published = true;
            write_marker(&identity_root, &marker, true, request.protection)?;
        }
        Err(error) => return Err(error),
    }

    publish_recovered_state(
        &request,
        &recovered,
        &marker,
        prior_marker_bytes.is_some(),
        marker.state_published,
        observer,
    )?;
    if !marker.state_published {
        marker.state_published = true;
        write_marker(&identity_root, &marker, true, request.protection)?;
    }

    let installed_identity_bytes = selector
        .read(
            &identity_root,
            &repository_refs(request.target_home),
            MAX_IDENTITY_FILE_BYTES,
        )
        .map_err(map_filesystem_error)?;
    if installed_identity_bytes != identity_bytes {
        return Err(restore_partial_conflict());
    }
    let installed_identity =
        IdentityFileV1::parse(&installed_identity_bytes).map_err(|_| invalid_identity())?;
    let unlocked = unlock(&installed_identity, identity_passphrase.memory())
        .map_err(|error| map_identity_error(error.kind()))?;
    if !owner
        .identity()
        .matches_unlocked(&unlocked)
        .map_err(|error| map_identity_error(error.kind()))?
    {
        return Err(restore_partial_conflict());
    }
    let (installed_vault, installed_policy) =
        validate_restored_state_publication(&request, &recovered, &marker)?;
    if request.validate_access {
        let UnlockedIdentity::VaultPrincipal(installed_owner) = unlocked else {
            return Err(invalid_identity());
        };
        let mut accessed =
            discover_accessible_items_in(&installed_vault, &installed_policy, &installed_owner)?
                .into_iter()
                .map(|item| installed_vault.items[item.envelope_index].item_id)
                .collect::<Vec<_>>();
        accessed.sort_unstable();
        if accessed != recovered.coverage().direct_item_ids {
            return Err(CliError::new(
                CliErrorKind::Conflict,
                "restore-access-validation-failed",
                "restored direct descriptor access did not match backup coverage",
            ));
        }
    }

    let marker_bytes = marker_bytes(&marker)?;
    identity_root
        .remove_private_file_if_exact(Path::new(&marker_name), &marker_bytes)
        .map_err(map_filesystem_error)?;
    let mut output_preimage = Vec::new();
    output_preimage.extend_from_slice(recovered.vault_bytes());
    output_preimage.extend_from_slice(&identity_bytes);
    output_preimage.extend_from_slice(recovered.header().payload_digest.as_bytes());
    Ok(RestoredInstallation {
        header: recovered.header().clone(),
        coverage: recovered.coverage().clone(),
        output_digest: sha256_digest(&output_preimage),
        marker_removed: true,
    })
}

fn validate_restore_paths(request: &RestoreRequest<'_>) -> Result<(), CliError> {
    let mut paths = vec![request.input, request.identity_target, request.state_root];
    paths.extend(request.approver_identity_target);
    paths.extend(request.witness_identity_target);
    for path in paths {
        direct_utf8_path(path)?;
    }
    let mut identity_targets = vec![request.identity_target];
    identity_targets.extend(request.approver_identity_target);
    identity_targets.extend(request.witness_identity_target);
    identity_targets.sort_unstable();
    if identity_targets.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(invalid_restore_target());
    }
    let identity_parents = identity_targets
        .iter()
        .map(|target| target.parent().ok_or_else(invalid_restore_target))
        .collect::<Result<Vec<_>, _>>()?;
    if request.input.starts_with(request.state_root)
        || identity_targets
            .iter()
            .any(|target| target.starts_with(request.state_root))
        || identity_parents.iter().any(|parent| {
            request.input.starts_with(parent) || request.state_root.starts_with(parent)
        })
    {
        return Err(containment_error());
    }
    if let Some(vault) = request.target_home.detached_path()
        && (overlaps(vault, request.state_root)
            || request.input.starts_with(vault)
            || identity_parents
                .iter()
                .any(|parent| overlaps(vault, parent)))
    {
        return Err(containment_error());
    }
    Ok(())
}

fn validate_role_restore_targets(
    request: &RestoreRequest<'_>,
    recovered: &jury_core::backup::RecoveredBackup,
) -> Result<(), CliError> {
    for (role, target) in [
        (RecoveryRole::Approver, request.approver_identity_target),
        (RecoveryRole::WitnessClient, request.witness_identity_target),
    ] {
        if recovered.identity(role).is_some() != target.is_some() {
            return Err(CliError::new(
                CliErrorKind::InvalidArguments,
                "restore-role-target-mismatch",
                "provide exactly one absent identity output for every role included in the backup",
            ));
        }
    }
    Ok(())
}

fn preflight_new_restore_targets(
    request: &RestoreRequest<'_>,
    identity_exists: bool,
    envelope: &BackupEnvelopeV1,
) -> Result<(), CliError> {
    if identity_exists != request.reuse_identity {
        return Err(if identity_exists {
            CliError::new(
                CliErrorKind::Conflict,
                "restore-identity-exists",
                "restore never overwrites an existing identity",
            )
        } else {
            CliError::new(
                CliErrorKind::NotFound,
                "reuse-identity-not-found",
                "the selected identity to reuse does not exist",
            )
        });
    }
    for target in [
        request.approver_identity_target,
        request.witness_identity_target,
    ]
    .into_iter()
    .flatten()
    {
        let parent = target.parent().ok_or_else(invalid_restore_target)?;
        let name = target.file_name().ok_or_else(invalid_restore_target)?;
        let root = HardenedStateRoot::open_existing(parent, &repository_refs(request.target_home))
            .map_err(map_filesystem_error)?;
        if root
            .private_child_exists(Path::new(name))
            .map_err(map_filesystem_error)?
        {
            return Err(CliError::new(
                CliErrorKind::Conflict,
                "restore-identity-exists",
                "restore never overwrites an existing identity",
            ));
        }
    }
    match &*request.target_home {
        VaultHomeLocation::Repository { repository } => {
            if repository.has_jury_directory() {
                return Err(existing_restore_vault());
            }
        }
        VaultHomeLocation::Detached { path, .. } => {
            let parent = path.parent().ok_or_else(invalid_restore_target)?;
            let name = path.file_name().ok_or_else(invalid_restore_target)?;
            let parent =
                HardenedStateRoot::open_existing(parent, &[]).map_err(map_filesystem_error)?;
            if parent
                .private_child_exists(Path::new(name))
                .map_err(map_filesystem_error)?
            {
                return Err(existing_restore_vault());
            }
        }
    }
    if request.require_absent_state_root {
        let parent = request
            .state_root
            .parent()
            .ok_or_else(invalid_restore_target)?;
        let name = request
            .state_root
            .file_name()
            .ok_or_else(invalid_restore_target)?;
        let parent =
            HardenedStateRoot::open_existing(parent, &repository_refs(request.target_home))
                .map_err(map_filesystem_error)?;
        if parent
            .private_child_exists(Path::new(name))
            .map_err(map_filesystem_error)?
        {
            return Err(CliError::new(
                CliErrorKind::Conflict,
                "restore-state-exists",
                "the drill state root must be absent",
            ));
        }
    } else {
        match VaultStateDirectory::open_existing(
            request.state_root,
            envelope.header.vault_id.as_bytes(),
            envelope.header.genesis_fingerprint.as_bytes(),
            &repository_refs(request.target_home),
        ) {
            Ok(_) => {
                return Err(CliError::new(
                    CliErrorKind::Conflict,
                    "restore-state-exists",
                    "authenticated local state already exists for this vault lineage",
                ));
            }
            Err(error) if error.kind() == FilesystemErrorKind::NotFound => {}
            Err(error) => return Err(map_filesystem_error(error)),
        }
    }
    Ok(())
}

fn ensure_detached_restore_home(home: &mut VaultHomeLocation, retry: bool) -> Result<(), CliError> {
    let VaultHomeLocation::Detached { path, .. } = home else {
        return Ok(());
    };
    let parent_path = path.parent().ok_or_else(invalid_restore_target)?;
    let name = path.file_name().ok_or_else(invalid_restore_target)?;
    let parent =
        HardenedStateRoot::open_existing(parent_path, &[]).map_err(map_filesystem_error)?;
    if parent
        .private_child_exists(Path::new(name))
        .map_err(map_filesystem_error)?
    {
        if retry {
            return Ok(());
        }
        return Err(existing_restore_vault());
    }
    parent
        .create_private_child_new(Path::new(name))
        .map_err(map_filesystem_error)?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn restore_additional_role_identity(
    request: &RestoreRequest<'_>,
    recovered: &jury_core::backup::RecoveredBackup,
    role: RecoveryRole,
    target: &Path,
    label: &str,
    marker_root: &HardenedStateRoot,
    marker: &mut RestoreMarker,
    retry: bool,
    backup_passphrase: &secret_input::CapturedPassphrase,
    observer: &mut dyn FnMut(RestorePublicationPoint) -> Result<(), CliError>,
) -> Result<(), CliError> {
    let recovered_role = recovered.identity(role).ok_or_else(invalid_backup)?;
    let parent = target.parent().ok_or_else(invalid_restore_target)?;
    let name = target.file_name().ok_or_else(invalid_restore_target)?;
    let root = HardenedStateRoot::open_existing(parent, &repository_refs(request.target_home))
        .map_err(map_filesystem_error)?;
    let preview = root
        .preview_private_file(Path::new(name))
        .map_err(map_filesystem_error)?;
    let already_published = match role {
        RecoveryRole::Approver => marker.approver_identity_published,
        RecoveryRole::WitnessClient => marker.witness_identity_published,
        RecoveryRole::VaultPrincipal => return Err(invalid_backup()),
    };
    if already_published && !preview.destination_exists() {
        return Err(restore_partial_conflict());
    }
    if preview.destination_exists() && !retry {
        return Err(CliError::new(
            CliErrorKind::Conflict,
            "restore-identity-exists",
            "restore never overwrites an existing identity",
        ));
    }
    let passphrase = secret_input::capture_named_or_environment(
        request.protection,
        request.cli.passphrase_stdin,
        true,
        label,
        request
            .environment
            .jury_new_passphrase
            .as_deref()
            .map(Vec::as_slice),
    )
    .map_err(map_secret_error)?;
    if backup_passphrase
        .matches(&passphrase)
        .map_err(map_secret_error)?
    {
        return Err(independent_restored_identity_passphrase_required());
    }
    let selector = IdentitySelector::select(None, Some(target.to_path_buf()))
        .map_err(|_| invalid_restore_target())?;
    let file = if preview.destination_exists() {
        let bytes = selector
            .read(
                &root,
                &repository_refs(request.target_home),
                MAX_IDENTITY_FILE_BYTES,
            )
            .map_err(map_filesystem_error)?;
        IdentityFileV1::parse(&bytes).map_err(|_| invalid_identity())?
    } else {
        let file = IdentityCreator::new()
            .restore(
                recovered_role.identity(),
                request.identity_profile,
                marker.timestamp_ms,
                passphrase.memory(),
            )
            .map_err(|error| map_identity_error(error.kind()))?
            .file;
        let bytes = file.to_json_bytes().map_err(|_| invalid_identity())?;
        let protected = protect(&bytes, request.protection)?;
        let outcome = selector
            .prepare(
                &root,
                &repository_refs(request.target_home),
                &protected,
                PublicationPolicy::CreateNew,
            )
            .map_err(map_filesystem_error)?
            .publish()
            .map_err(map_filesystem_error)?;
        require_durable_restore_step(outcome)?;
        file
    };
    let expected_bytes = file.to_json_bytes().map_err(|_| invalid_identity())?;
    let installed_bytes = selector
        .read(
            &root,
            &repository_refs(request.target_home),
            MAX_IDENTITY_FILE_BYTES,
        )
        .map_err(map_filesystem_error)?;
    if installed_bytes != expected_bytes {
        return Err(restore_partial_conflict());
    }
    let installed = IdentityFileV1::parse(&installed_bytes).map_err(|_| invalid_identity())?;
    let unlocked = unlock(&installed, passphrase.memory())
        .map_err(|error| map_identity_error(error.kind()))?;
    if !recovered_role
        .identity()
        .matches_unlocked(&unlocked)
        .map_err(|error| map_identity_error(error.kind()))?
    {
        return Err(restore_partial_conflict());
    }
    match role {
        RecoveryRole::Approver => marker.approver_identity_published = true,
        RecoveryRole::WitnessClient => marker.witness_identity_published = true,
        RecoveryRole::VaultPrincipal => return Err(invalid_backup()),
    }
    if !already_published {
        observer(match role {
            RecoveryRole::Approver => RestorePublicationPoint::ApproverIdentityPublished,
            RecoveryRole::WitnessClient => RestorePublicationPoint::WitnessIdentityPublished,
            RecoveryRole::VaultPrincipal => return Err(invalid_backup()),
        })?;
        write_marker(marker_root, marker, true, request.protection)?;
    }
    Ok(())
}

fn publish_recovered_state(
    request: &RestoreRequest<'_>,
    recovered: &jury_core::backup::RecoveredBackup,
    marker: &RestoreMarker,
    retry: bool,
    must_already_exist: bool,
    observer: &mut dyn FnMut(RestorePublicationPoint) -> Result<(), CliError>,
) -> Result<(), CliError> {
    if request.require_absent_state_root && !retry {
        let parent_path = request
            .state_root
            .parent()
            .ok_or_else(invalid_restore_target)?;
        let name = request
            .state_root
            .file_name()
            .ok_or_else(invalid_restore_target)?;
        let parent =
            HardenedStateRoot::open_existing(parent_path, &repository_refs(request.target_home))
                .map_err(map_filesystem_error)?;
        parent
            .create_private_child_new(Path::new(name))
            .map_err(map_filesystem_error)?;
    }
    let repositories = repository_refs(request.target_home);
    let state = if must_already_exist {
        VaultStateDirectory::open_existing(
            request.state_root,
            recovered.header().vault_id.as_bytes(),
            recovered.header().genesis_fingerprint.as_bytes(),
            &repositories,
        )
    } else {
        VaultStateDirectory::open_or_create(
            request.state_root,
            recovered.header().vault_id.as_bytes(),
            recovered.header().genesis_fingerprint.as_bytes(),
            &repositories,
            &detached_paths(request.target_home),
        )
    }
    .map_err(map_filesystem_error)?;
    let operation_id = digest_from_recovery_id(&recovered.header().backup_id);
    let policy = replay_policy_with_witness_policies(
        &recovered.vault().policy,
        &recovered.catalog().witness_policies,
    )
    .map_err(|_| invalid_vault())?;
    let mut catalog = PolicyCatalogV1::empty();
    catalog.merge_transfer(recovered.catalog())?;
    let catalog_bytes = policy_catalog_json_bytes(&catalog)?;
    let locked = state.try_lock().map_err(|_| local_state_error())?;
    let mut prepared = Vec::new();
    for identity in recovered.identities() {
        let files = restored_local_files(recovered, identity, marker, &policy, &operation_id)?;
        for (kind, bytes) in [
            (PrincipalStateFile::Audit, files.audit()),
            (PrincipalStateFile::Checkpoint, files.checkpoint()),
            (PrincipalStateFile::Receipts, files.receipts()),
        ] {
            prepare_or_compare_principal(
                &locked,
                identity.identity().principal_id().as_bytes(),
                kind,
                bytes,
                request.protection,
                must_already_exist,
                &mut prepared,
            )?;
        }
    }
    match locked.read_vault_state(VaultStateFile::PolicyCatalog) {
        Ok(existing) if existing == catalog_bytes => {}
        Ok(_) => return Err(restore_partial_conflict()),
        Err(error) if error.kind() == FilesystemErrorKind::NotFound && !must_already_exist => {
            let protected = protect(&catalog_bytes, request.protection)?;
            prepared.push(
                locked
                    .prepare_vault_state(VaultStateFile::PolicyCatalog, &protected)
                    .map_err(map_filesystem_error)?,
            );
        }
        Err(error) => return Err(map_filesystem_error(error)),
    }
    for output in prepared {
        let outcome = output.publish().map_err(map_filesystem_error)?;
        require_durable_restore_step(outcome)?;
        observer(RestorePublicationPoint::StateFilePublished)?;
    }
    Ok(())
}

fn restored_local_files(
    recovered: &jury_core::backup::RecoveredBackup,
    identity: &jury_core::backup::RecoveredRoleIdentity,
    marker: &RestoreMarker,
    policy: &PolicyState,
    operation_id: &Digest32,
) -> Result<LocalStateFiles, CliError> {
    let local = PrincipalLocalState::for_recovered_identity(
        identity.identity(),
        recovered.header().vault_id,
        recovered.header().genesis_fingerprint.clone(),
    )
    .map_err(|_| local_state_error())?;
    let mut verified = local
        .verify_files(
            Some(identity.local_state().audit()),
            Some(identity.local_state().checkpoint()),
            Some(identity.local_state().receipts()),
        )
        .map_err(|_| local_state_error())?;
    if !verified.contains_operation(operation_id) {
        local
            .append_event(
                &mut verified,
                AuditEventDraft {
                    timestamp_ms: marker.timestamp_ms,
                    operation_id: operation_id.clone(),
                    policy_sequence: policy.sequence(),
                    action: AuditAction::Restore,
                    outcome: AuditOutcome::Success,
                    item: None,
                    witness: None,
                },
            )
            .map_err(|_| local_state_error())?;
    }
    local.serialize(&verified).map_err(|_| local_state_error())
}

fn validate_restored_state_publication(
    request: &RestoreRequest<'_>,
    recovered: &jury_core::backup::RecoveredBackup,
    marker: &RestoreMarker,
) -> Result<(VaultFileV1, PolicyState), CliError> {
    let installed_vault_bytes = read_vault(request.target_home)?;
    if installed_vault_bytes != recovered.vault_bytes() {
        return Err(restore_partial_conflict());
    }
    let installed_vault =
        VaultFileV1::parse(&installed_vault_bytes).map_err(|_| invalid_vault())?;
    let installed_policy = replay_policy_with_witness_policies(
        &installed_vault.policy,
        &recovered.catalog().witness_policies,
    )
    .map_err(|_| invalid_vault())?;
    let mut expected_catalog = PolicyCatalogV1::empty();
    expected_catalog.merge_transfer(recovered.catalog())?;
    let expected_catalog_bytes = policy_catalog_json_bytes(&expected_catalog)?;
    let state = VaultStateDirectory::open_existing(
        request.state_root,
        recovered.header().vault_id.as_bytes(),
        recovered.header().genesis_fingerprint.as_bytes(),
        &repository_refs(request.target_home),
    )
    .map_err(map_filesystem_error)?;
    if state
        .read_vault_state(VaultStateFile::PolicyCatalog)
        .map_err(map_filesystem_error)?
        != expected_catalog_bytes
    {
        return Err(restore_partial_conflict());
    }
    let operation_id = digest_from_recovery_id(&recovered.header().backup_id);
    for identity in recovered.identities() {
        let expected = restored_local_files(
            recovered,
            identity,
            marker,
            &installed_policy,
            &operation_id,
        )?;
        for (kind, bytes) in [
            (PrincipalStateFile::Audit, expected.audit()),
            (PrincipalStateFile::Checkpoint, expected.checkpoint()),
            (PrincipalStateFile::Receipts, expected.receipts()),
        ] {
            if state
                .read_principal_state(identity.identity().principal_id().as_bytes(), kind)
                .map_err(map_filesystem_error)?
                != bytes
            {
                return Err(restore_partial_conflict());
            }
        }
    }
    Ok((installed_vault, installed_policy))
}

fn prepare_or_compare_principal(
    locked: &LockedVaultState<'_>,
    principal_id: &[u8; 32],
    kind: PrincipalStateFile,
    target: &[u8],
    protection: ProtectionPolicy,
    must_already_exist: bool,
    prepared: &mut Vec<PreparedPrivateFile>,
) -> Result<(), CliError> {
    match locked.read(principal_id, kind) {
        Ok(existing) if existing == target => Ok(()),
        Ok(_) => Err(restore_partial_conflict()),
        Err(error) if error.kind() == FilesystemErrorKind::NotFound && !must_already_exist => {
            let protected = protect(target, protection)?;
            prepared.push(
                locked
                    .prepare(principal_id, kind, &protected)
                    .map_err(map_filesystem_error)?,
            );
            Ok(())
        }
        Err(error) => Err(map_filesystem_error(error)),
    }
}

fn write_marker(
    root: &HardenedStateRoot,
    marker: &RestoreMarker,
    replace: bool,
    protection: ProtectionPolicy,
) -> Result<(), CliError> {
    let bytes = marker_bytes(marker)?;
    let protected = protect(&bytes, protection)?;
    let outcome = PreparedPrivateFile::prepare_if_unchanged(
        root.preview_private_file(Path::new(&marker_name_from_text(&marker.transaction_id)))
            .map_err(map_filesystem_error)?,
        &protected,
        replace,
    )
    .map_err(map_filesystem_error)?
    .publish()
    .map_err(map_filesystem_error)?;
    require_durable_restore_step(outcome)
}

fn parse_marker(bytes: &[u8]) -> Result<RestoreMarker, CliError> {
    let marker: RestoreMarker =
        serde_json::from_slice(bytes).map_err(|_| invalid_restore_marker())?;
    if marker_bytes(&marker)?.as_slice() != bytes || marker.version != 1 || marker.timestamp_ms == 0
    {
        return Err(invalid_restore_marker());
    }
    Ok(marker)
}

fn marker_bytes(marker: &RestoreMarker) -> Result<Vec<u8>, CliError> {
    let bytes = serde_json::to_vec(marker).map_err(|_| invalid_restore_marker())?;
    if bytes.len() > MAX_RESTORE_MARKER_BYTES {
        return Err(invalid_restore_marker());
    }
    Ok(bytes)
}

fn marker_name(id: &jury_protocol::vault_v1::RecoveryId) -> String {
    marker_name_from_text(&hex(id.as_bytes()))
}

fn marker_name_from_text(id: &str) -> String {
    format!(".jury-vault-restore-{id}.json")
}

fn vault_target_label(home: &VaultHomeLocation) -> Result<String, CliError> {
    match home {
        VaultHomeLocation::Repository { repository } => {
            direct_utf8_path(&repository.worktree_path().join(".jury/vault.json"))
        }
        VaultHomeLocation::Detached { path, .. } => direct_utf8_path(&path.join("vault.json")),
    }
}

fn direct_utf8_path(path: &Path) -> Result<String, CliError> {
    if !path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )
        })
    {
        return Err(invalid_restore_target());
    }
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(invalid_restore_target)
}

fn require_durable_restore_step(outcome: PublicationOutcome) -> Result<(), CliError> {
    if outcome == PublicationOutcome::PublishedAndSynced {
        Ok(())
    } else {
        Err(CliError::new(
            CliErrorKind::Filesystem,
            "restore-step-not-durable",
            "a restore step was published but not fully synchronized; use the retained marker to retry",
        ))
    }
}

fn invalid_restore_target() -> CliError {
    CliError::new(
        CliErrorKind::InvalidArguments,
        "invalid-restore-target",
        "restore targets must be absolute direct paths in separate custody roots",
    )
}

fn invalid_restore_marker() -> CliError {
    CliError::new(
        CliErrorKind::Conflict,
        "invalid-restore-marker",
        "the retained restore transaction marker is invalid",
    )
}

fn independent_restored_identity_passphrase_required() -> CliError {
    CliError::new(
        CliErrorKind::InvalidArguments,
        "independent-restored-identity-passphrase-required",
        "a newly restored identity requires a passphrase different from the backup passphrase",
    )
}

fn existing_restore_vault() -> CliError {
    CliError::new(
        CliErrorKind::Conflict,
        "restore-vault-exists",
        "restore never overwrites an existing vault target",
    )
}

fn restore_partial_conflict() -> CliError {
    CliError::new(
        CliErrorKind::Conflict,
        "restore-partial-state-conflict",
        "retained restore state differs from the authenticated retry transaction",
    )
}

fn private_backup_parent(
    home: &VaultHomeLocation,
    path: &Path,
) -> Result<HardenedStateRoot, CliError> {
    if !path.is_absolute()
        || path.file_name().is_none()
        || path.components().any(|component| {
            matches!(
                component,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )
        })
    {
        return Err(CliError::new(
            CliErrorKind::InvalidArguments,
            "invalid-backup-path",
            "backup paths must be absolute and direct",
        ));
    }
    let parent = path.parent().ok_or_else(filesystem_error)?;
    validate_detached_separation(parent, home)?;
    HardenedStateRoot::open_existing(parent, &repository_refs(home)).map_err(map_filesystem_error)
}

fn backup_receipt(
    header: &jury_protocol::backup_v1::BackupHeaderV1,
    coverage: &RecoveryCoverage,
) -> BackupReceipt {
    BackupReceipt {
        backup_id: digest_from_recovery_id(&header.backup_id),
        captured_public_revision_hash: header.source_public_revision_hash.clone(),
        timestamp_ms: header.created_at_ms,
        payload_digest: header.payload_digest.clone(),
        owner_descriptor_fingerprint: header.owner_descriptor_fingerprint.clone(),
        identity_role_mask: role_mask(&coverage.identity_roles),
        direct_item_ids: coverage.direct_item_ids.clone(),
        witnessed_item_ids: coverage.witnessed_item_ids.clone(),
        unavailable_witnessed_item_ids: coverage.unavailable_witnessed_item_ids.clone(),
        checkpoints_current: coverage.checkpoints_current,
        external_witness_recovery_required: coverage.external_witness_recovery_required,
    }
}

fn digest_from_recovery_id(id: &jury_protocol::vault_v1::RecoveryId) -> Digest32 {
    Digest32::new(*id.as_bytes())
}

fn role_mask(roles: &[RecoveryRole]) -> u8 {
    roles.iter().fold(0, |mask, role| {
        mask | match role {
            RecoveryRole::VaultPrincipal => 1,
            RecoveryRole::Approver => 2,
            RecoveryRole::WitnessClient => 4,
        }
    })
}

fn role_names_from_mask(mask: u8) -> Vec<&'static str> {
    [
        (1, "vault-principal"),
        (2, "approver"),
        (4, "witness-client"),
    ]
    .into_iter()
    .filter_map(|(bit, name)| (mask & bit != 0).then_some(name))
    .collect()
}

fn recovery_output(
    operation: &'static str,
    header: &jury_protocol::backup_v1::BackupHeaderV1,
    coverage: &RecoveryCoverage,
    details: serde_json::Value,
    lines: Vec<String>,
) -> CommandOutput {
    CommandOutput::Safe {
        operation,
        fields: serde_json::json!({
            "backup_id": hex(header.backup_id.as_bytes()),
            "vault_id": hex(header.vault_id.as_bytes()),
            "genesis_fingerprint": hex(header.genesis_fingerprint.as_bytes()),
            "captured_public_revision": hex(header.source_public_revision_hash.as_bytes()),
            "owner_principal_id": hex(header.owner_principal_id.as_bytes()),
            "owner_descriptor_fingerprint": hex(header.owner_descriptor_fingerprint.as_bytes()),
            "kdf_profile": kdf_profile(header.kdf_profile),
            "target_bucket_bytes": bytes_for_bucket(header.target_bucket_id),
            "included_identity_roles": coverage.identity_roles.iter().map(role_name).collect::<Vec<_>>(),
            "direct_item_ids": coverage.direct_item_ids.iter().map(|id| hex(id.as_bytes())).collect::<Vec<_>>(),
            "witnessed_item_ids": coverage.witnessed_item_ids.iter().map(|id| hex(id.as_bytes())).collect::<Vec<_>>(),
            "unavailable_witnessed_item_ids": coverage.unavailable_witnessed_item_ids.iter().map(|id| hex(id.as_bytes())).collect::<Vec<_>>(),
            "checkpoints_current": coverage.checkpoints_current,
            "external_witness_recovery_required": coverage.external_witness_recovery_required,
            "recovers_juryd_replay_state": false,
            "recovers_external_anchors": false,
            "proves_witness_availability": false,
            "proves_quorum_availability": false,
            "details": details,
        }),
        lines,
    }
}

fn coverage_lines(coverage: &RecoveryCoverage) -> Vec<String> {
    vec![
        format!(
            "Included local roles: {}",
            coverage
                .identity_roles
                .iter()
                .map(role_name)
                .collect::<Vec<_>>()
                .join(", ")
        ),
        format!("Directly recoverable items: {}", coverage.direct_item_ids.len()),
        format!("Witnessed items requiring external recovery: {}", coverage.witnessed_item_ids.len()),
        "This does not recover juryd replay state, external anchors, witness availability, or quorum availability."
            .to_owned(),
    ]
}

const fn role_name(role: &RecoveryRole) -> &'static str {
    match role {
        RecoveryRole::VaultPrincipal => "vault-principal",
        RecoveryRole::Approver => "approver",
        RecoveryRole::WitnessClient => "witness-client",
    }
}

fn bytes_for_bucket(bucket: u8) -> Option<usize> {
    jury_protocol::backup_v1::bucket_bytes(bucket).ok()
}

fn invalid_backup() -> CliError {
    CliError::new(
        CliErrorKind::InvalidVault,
        "invalid-backup",
        "the backup archive is invalid",
    )
}

fn map_backup_error(error: jury_core::backup::BackupError) -> CliError {
    match error.kind() {
        BackupErrorKind::AuthenticationFailed => CliError::new(
            CliErrorKind::AuthenticationFailed,
            "backup-authentication-failed",
            "backup authentication failed",
        ),
        BackupErrorKind::InvalidPassphrase => CliError::new(
            CliErrorKind::InvalidArguments,
            "invalid-backup-passphrase",
            "the backup passphrase does not meet the exact byte-length policy",
        ),
        BackupErrorKind::UnauthorizedOwner | BackupErrorKind::OwnerRequired => CliError::new(
            CliErrorKind::AccessDenied,
            "active-owner-required",
            "backup creation requires an active owner",
        ),
        BackupErrorKind::IdentityMismatch => CliError::new(
            CliErrorKind::Conflict,
            "backup-identity-mismatch",
            "backup identity material does not match authenticated policy",
        ),
        BackupErrorKind::StaleCheckpoint => CliError::new(
            CliErrorKind::Conflict,
            "stale-backup-checkpoint",
            "backup local checkpoint state is not current",
        ),
        BackupErrorKind::DirectRecoveryUnavailable => CliError::new(
            CliErrorKind::Conflict,
            "direct-recovery-unavailable",
            "current direct item recovery material is incomplete",
        ),
        BackupErrorKind::ProtectionUnavailable | BackupErrorKind::ResourceUnavailable => {
            CliError::new(
                CliErrorKind::ProtectionUnavailable,
                "backup-protection-unavailable",
                "required backup protection resources are unavailable",
            )
        }
        BackupErrorKind::CapacityExhausted => CliError::new(
            CliErrorKind::InvalidArguments,
            "backup-capacity-exhausted",
            "backup recovery metadata exceeds a hard capacity",
        ),
        _ => invalid_backup(),
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::fs;
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

    fn require_witness(
        identity: UnlockedIdentity,
    ) -> TestResult<jury_core::identity::WitnessIdentity> {
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
        let approver_files =
            approver_local.serialize(&approver_local.initialize(&checkpoint, 40)?)?;
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

    fn restore_cli(backup: &Path, vault: PathBuf, identity: PathBuf, state: PathBuf) -> Cli {
        Cli {
            json: true,
            home: Some(vault),
            global_home: false,
            identity: None,
            identity_file: None,
            expected_genesis: None,
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
        }
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
            expected_genesis: None,
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
        let CommandOutput::Safe { fields, .. } = output else {
            return Err("restore returned an unexpected output shape".into());
        };
        assert_eq!(
            fields["included_identity_roles"],
            serde_json::json!(["vault-principal", "approver", "witness-client"])
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
            let cli = restore_cli(&backup, vault.clone(), identity.clone(), state.clone());
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
}
