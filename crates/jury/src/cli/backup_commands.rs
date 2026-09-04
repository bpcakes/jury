use super::*;

mod output;
mod restore;

use output::{coverage_lines, recovery_output};
#[cfg(test)]
use restore::{RestorePublicationPoint, backup_restore_with_observer};
pub(super) use restore::{backup_drill, backup_restore};

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
    let mut private_boundaries = vec![identity_home.as_path(), owner_identity_parent, &state_home];
    private_boundaries.extend(additional_identity_parents.iter().copied());
    if let Some(repository) = home.repository() {
        private_boundaries.push(repository.worktree_path());
    }
    private_boundaries.extend(home.detached_path());
    for boundary in private_boundaries {
        validate_path_separation(&[output_parent, boundary]).map_err(map_filesystem_error)?;
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
        environment.backup_passphrase(),
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
    let protection_degraded = any_protection_degraded(
        [
            context.protection_degraded,
            backup_passphrase.protection_degraded(),
        ]
        .into_iter()
        .chain(
            additional_passphrases
                .iter()
                .map(secret_input::CapturedPassphrase::protection_degraded),
        ),
    );
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
            "protection_degraded": protection_degraded,
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
        environment.backup_passphrase(),
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
        Some(receipt) if receipt.captured_public_revision_hash() == current_revision => "current",
        Some(_) => "stale",
    };
    let matching_verification = receipts.backup.as_ref().and_then(|backup| {
        receipts.verification.as_ref().filter(|verification| {
            &verification.backup_id == backup.backup_id()
                && &verification.payload_digest == backup.payload_digest()
                && &verification.captured_public_revision_hash
                    == backup.captured_public_revision_hash()
        })
    });
    let matching_drill = receipts.backup.as_ref().and_then(|backup| {
        receipts.drill.as_ref().filter(|drill| {
            &drill.backup_id == backup.backup_id()
                && &drill.captured_public_revision_hash == backup.captured_public_revision_hash()
        })
    });
    let verified = matching_verification.is_some();
    let drilled = matching_drill.is_some();
    let now = timestamp_ms()?;
    let age_ms = receipts
        .backup
        .as_ref()
        .map(|receipt| now.saturating_sub(receipt.timestamp_ms()));
    let coverage = receipts.backup.as_ref().and_then(BackupReceipt::coverage);
    let role_names = coverage.map(|coverage| role_names_from_mask(coverage.identity_role_mask));
    let direct_items = coverage.map(|coverage| {
        coverage
            .direct_item_ids
            .iter()
            .map(|id| hex(id.as_bytes()))
            .collect::<Vec<_>>()
    });
    let witnessed_items = coverage.map(|coverage| {
        coverage
            .witnessed_item_ids
            .iter()
            .map(|id| hex(id.as_bytes()))
            .collect::<Vec<_>>()
    });
    let unavailable_witnessed_items = coverage.map(|coverage| {
        coverage
            .unavailable_witnessed_item_ids
            .iter()
            .map(|id| hex(id.as_bytes()))
            .collect::<Vec<_>>()
    });
    let external_required = coverage.map(|coverage| coverage.external_witness_recovery_required);
    let has_approver = coverage.is_some_and(|coverage| coverage.identity_role_mask & 2 != 0);
    let has_witness = coverage.is_some_and(|coverage| coverage.identity_role_mask & 4 != 0);
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
    let next_command =
        if receipts.backup.is_none() || creation_state == "stale" || coverage.is_none() {
            create_command
        } else if !verified {
            "jury backup verify --in ABSOLUTE_FILE".to_owned()
        } else if !drilled {
            drill_command
        } else if external_required == Some(true) {
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
            "captured_public_revision": receipts.backup.as_ref().map(|receipt| hex(receipt.captured_public_revision_hash().as_bytes())),
            "backup_age_ms": age_ms,
            "last_full_verification_at_ms": matching_verification.map(|receipt| receipt.timestamp_ms),
            "included_identity_roles": role_names,
            "direct_item_ids": direct_items,
            "witnessed_item_ids": witnessed_items,
            "unavailable_witnessed_item_ids": unavailable_witnessed_items,
            "local_verification_state_included": coverage.map(|coverage| coverage.checkpoints_current),
            "external_witness_recovery_required": external_required,
            "coverage_metadata": if coverage.is_some() { "recorded" } else { "unknown" },
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

struct AdditionalBackupIdentity {
    identity: UnlockedIdentity,
}

fn any_protection_degraded(states: impl IntoIterator<Item = bool>) -> bool {
    states.into_iter().any(std::convert::identity)
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
    let mut remaining = MAX_BACKUP_ENVELOPE_BYTES;
    let mut snapshots = Vec::with_capacity(principal_ids.len());
    for principal_id in principal_ids {
        let audit = read_budgeted_local_state(
            &locked,
            principal_id,
            PrincipalStateFile::Audit,
            BackupCapacityClass::Audit,
            &mut remaining,
        )?;
        let checkpoint = read_budgeted_local_state(
            &locked,
            principal_id,
            PrincipalStateFile::Checkpoint,
            BackupCapacityClass::Checkpoint,
            &mut remaining,
        )?;
        let receipts = read_budgeted_local_state(
            &locked,
            principal_id,
            PrincipalStateFile::Receipts,
            BackupCapacityClass::Receipts,
            &mut remaining,
        )?;
        snapshots.push(LocalStateSnapshot {
            audit,
            checkpoint,
            receipts,
        });
    }
    Ok(snapshots)
}

fn read_budgeted_local_state(
    locked: &LockedVaultState<'_>,
    principal_id: &PrincipalId,
    file: PrincipalStateFile,
    class: BackupCapacityClass,
    remaining: &mut usize,
) -> Result<Vec<u8>, CliError> {
    let bytes = locked
        .read_bounded(principal_id.as_bytes(), file, *remaining)
        .map_err(|error| {
            if error.kind() == FilesystemErrorKind::Capacity {
                backup_capacity_error(class)
            } else {
                map_filesystem_error(error)
            }
        })?;
    *remaining = remaining
        .checked_sub(bytes.len())
        .ok_or_else(|| backup_capacity_error(class))?;
    Ok(bytes)
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
    BackupReceipt::with_coverage(
        digest_from_recovery_id(&header.backup_id),
        header.source_public_revision_hash.clone(),
        header.created_at_ms,
        header.payload_digest.clone(),
        BackupReceiptCoverage {
            owner_descriptor_fingerprint: header.owner_descriptor_fingerprint.clone(),
            identity_role_mask: role_mask(&coverage.identity_roles),
            direct_item_ids: coverage.direct_item_ids.clone(),
            witnessed_item_ids: coverage.witnessed_item_ids.clone(),
            unavailable_witnessed_item_ids: coverage.unavailable_witnessed_item_ids.clone(),
            checkpoints_current: coverage.checkpoints_current,
            external_witness_recovery_required: coverage.external_witness_recovery_required,
        },
    )
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
        BackupErrorKind::CapacityExhausted => backup_capacity_error(
            error
                .capacity_class()
                .unwrap_or(BackupCapacityClass::Envelope),
        ),
        _ => invalid_backup(),
    }
}

fn backup_capacity_error(class: BackupCapacityClass) -> CliError {
    let (code, message) = match class {
        BackupCapacityClass::Envelope => (
            "backup-capacity-exhausted",
            "backup recovery metadata exceeds the archive capacity",
        ),
        BackupCapacityClass::Vault => (
            "backup-vault-capacity-exhausted",
            "backup vault metadata exceeds the archive capacity",
        ),
        BackupCapacityClass::Catalog => (
            "backup-catalog-capacity-exhausted",
            "backup public catalog metadata exceeds the archive capacity",
        ),
        BackupCapacityClass::Identity => (
            "backup-identity-capacity-exhausted",
            "backup identity metadata exceeds the archive capacity",
        ),
        BackupCapacityClass::Audit => (
            "backup-audit-capacity-exhausted",
            "backup audit metadata exceeds the archive capacity",
        ),
        BackupCapacityClass::Checkpoint => (
            "backup-checkpoint-capacity-exhausted",
            "backup checkpoint metadata exceeds the archive capacity",
        ),
        BackupCapacityClass::Receipts => (
            "backup-receipts-capacity-exhausted",
            "backup receipt metadata exceeds the archive capacity",
        ),
    };
    CliError::new(CliErrorKind::InvalidArguments, code, message)
}

#[cfg(all(test, target_os = "linux"))]
#[path = "backup_commands/tests.rs"]
mod tests;
