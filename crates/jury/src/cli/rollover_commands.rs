use super::*;
use jury_core::rollover::{RolloverError, RolloverSource};
use jury_protocol::hpke_context::VaultSuite;

mod governed;
mod publication;
mod recovery;
mod registration;
#[cfg(test)]
mod test_support;
#[cfg(test)]
pub(super) use governed::exercise_polling_repair;

// Reader-consumed recovery control for J18: a crash between output writes must
// not expose an incomplete new installation. Retain the exact encrypted
// candidate until every output is durable; remove it after publication.
pub(super) const PENDING_ROLLOVER: &str = "rollover.pending.json";
pub(super) const PENDING_ROLLOVER_CLEANUP: &str = "rollover.pending.cleanup.json";
pub(super) const PENDING_OUTPUTS: &str = "rollover.outputs.pending.json";
pub(super) const PENDING_OUTPUTS_CLEANUP: &str = "rollover.outputs.cleanup.json";

pub(super) fn vault_rollover(
    cli: &Cli,
    arguments: &VaultRolloverArgs,
    migration: Option<u16>,
    environment: &Environment,
    current: &Path,
    protection: ProtectionPolicy,
) -> Result<CommandOutput, CliError> {
    let home = selected_home(cli, environment, current)?;
    // Reject unsupported or reverse transitions before unlocking any identity.
    let public_source = VaultFileV1::parse(&read_vault(&home)?).map_err(|_| invalid_vault())?;
    let destination_suite = selected_suite(public_source.header.suite, migration)?;
    let targets = RolloverTargets::preflight(cli, arguments, environment, &home)?;
    let (context, identity_passphrase) =
        load_vault_principal_with_passphrase(cli, environment, current, protection)?;
    let source_bytes = read_vault(&context.home)?;
    if VaultFileV1::parse(&source_bytes).map_err(|_| invalid_vault())? != context.vault {
        return Err(checkpoint_conflict());
    }
    let source = RolloverSource::validate(&context.vault, &context.catalog.witness_policies)
        .map_err(map_rollover_error)?;
    if selected_suite(context.vault.header.suite, migration)? != destination_suite {
        return Err(checkpoint_conflict());
    }
    if arguments.resume {
        return recovery::resume(
            cli,
            arguments,
            destination_suite,
            environment,
            &context,
            targets,
            protection,
        );
    }
    let now = timestamp_ms()?;
    let governed_source = context.policy.principals().any(|(_, principal)| {
        matches!(
            principal.descriptor.principal_kind,
            PrincipalKind::Approver | PrincipalKind::Witness
        )
    });
    let (vault, catalog) = if governed_source {
        registration::preflight_endpoints(&context.policy, arguments)?;
        if arguments.dry_run {
            return governed::preview(&source, &context, arguments, destination_suite, protection);
        }
        let draft = governed::prepare(
            &source,
            &context,
            arguments,
            migration.map(|_| destination_suite),
            now,
            protection,
        )?;
        let prepared = governed::complete(&source, &context, arguments, draft, protection)?;
        (prepared.vault().clone(), prepared.catalog().clone())
    } else {
        if arguments.registration_dir.is_some()
            || !arguments.destination_witness.is_empty()
            || arguments.administrative_access.is_some()
        {
            return Err(rollover_target_error());
        }
        let prepared = if migration.is_some() {
            source.prepare_direct_migration(
                destination_suite,
                &context.identity,
                now,
                protection,
                &NeverCancelled,
            )
        } else {
            source.prepare_direct(&context.identity, now, protection, &NeverCancelled)
        }
        .map_err(map_rollover_error)?;
        (
            prepared.vault().clone(),
            TransferPublicCatalogV1 {
                version: 1,
                registration_proofs: Vec::new(),
                witness_policies: Vec::new(),
                review_label_sets: Vec::new(),
            },
        )
    };
    let vault = &vault;
    let now = timestamp_ms()?;
    let policy = replay_policy_with_witness_policies(&vault.policy, &catalog.witness_policies)
        .map_err(|_| invalid_vault())?;
    let candidate = CheckpointCandidate::from_validated(&policy, &vault.policy, &vault.items)
        .map_err(|_| invalid_vault())?;
    let local = PrincipalLocalState::for_vault_principal(
        &context.identity,
        vault.header.vault_id,
        vault.header.genesis_fingerprint.clone(),
    )
    .map_err(|_| local_state_error())?;
    let mut initialized = local
        .initialize(&candidate, now)
        .map_err(|_| local_state_error())?;
    let initial_files = local
        .serialize(&initialized)
        .map_err(|_| local_state_error())?;
    let transfer = TransferCreator::new()
        .create(vault, catalog.clone(), &context.identity, now)
        .map_err(map_transfer_error)?;
    let registration = registration::DestinationRegistration::prepare(
        vault,
        &catalog,
        &context.identity,
        arguments,
        now,
    )?;
    let transfer_bytes = transfer.to_json_bytes().map_err(|_| invalid_transfer())?;
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
        .map_err(map_secret_error)?;
    if passphrases_match && !arguments.reuse_identity_passphrase {
        return Err(CliError::new(
            CliErrorKind::InvalidArguments,
            "independent-backup-passphrase-required",
            "backup and identity passphrases match; deliberate reuse requires --reuse-identity-passphrase",
        ));
    }
    let identities = [BackupIdentitySource::VaultPrincipal {
        identity: &context.identity,
        local_state: LocalStateArchive {
            audit: initial_files.audit(),
            checkpoint: initial_files.checkpoint(),
            receipts: initial_files.receipts(),
        },
    }];
    let backup = BackupCreator::new()
        .create(BackupCreateRequest {
            vault,
            catalog: &catalog,
            identities: &identities,
            profile: arguments.backup_kdf_profile.into(),
            created_at_ms: now,
            backup_passphrase: backup_passphrase.memory(),
        })
        .map_err(map_backup_error)?;
    let backup_receipt =
        backup_commands::backup_receipt(&backup.envelope().header, backup.coverage());
    let backup_bytes = backup
        .into_envelope()
        .to_bytes()
        .map_err(|_| invalid_backup())?;
    local
        .record_receipt(&mut initialized, ReceiptUpdate::Backup(backup_receipt))
        .map_err(|_| local_state_error())?;
    local
        .record_receipt(
            &mut initialized,
            ReceiptUpdate::Transfer(TransferReceipt {
                transfer_id: transfer.transfer_id.clone(),
                captured_public_revision_hash: transfer.source_public_revision_hash.clone(),
                timestamp_ms: now,
                output_digest: sha256_digest(&transfer_bytes),
            }),
        )
        .map_err(|_| local_state_error())?;
    let bytes = vault.to_json_bytes().map_err(|_| invalid_vault())?;
    let operation_id = recovery::publication_operation_id(
        arguments,
        &targets.state_root,
        &source_bytes,
        &bytes,
        &backup_bytes,
        &transfer_bytes,
        registration.checkpoint(),
    )?;
    // Authenticate the immutable publication intent, not a claim that external
    // registration or durable output publication has already succeeded.
    local
        .append_event(
            &mut initialized,
            AuditEventDraft {
                timestamp_ms: now,
                operation_id,
                policy_sequence: policy.sequence(),
                action: AuditAction::Verification,
                outcome: AuditOutcome::Success,
                item: None,
                witness: None,
            },
        )
        .map_err(|_| local_state_error())?;
    let files = local
        .serialize(&initialized)
        .map_err(|_| local_state_error())?;
    let protection_degraded =
        context.protection_degraded || backup_passphrase.protection_degraded();
    if arguments.dry_run {
        return Ok(rollover_output(vault, false, protection_degraded));
    }
    if !arguments.adopt_new_lineage {
        return Err(CliError::new(
            CliErrorKind::InvalidArguments,
            "new-lineage-adoption-required",
            "rollover requires explicit adoption of the generated new lineage",
        ));
    }
    if read_vault(&context.home)? != source_bytes {
        return Err(checkpoint_conflict());
    }
    publish_rollover(RolloverPublication {
        targets,
        arguments,
        context: &context,
        source_bytes: &source_bytes,
        vault,
        vault_bytes: &bytes,
        backup_bytes: &backup_bytes,
        transfer_bytes: &transfer_bytes,
        files: &files,
        catalog: &catalog,
        registration: &registration,
        protection,
    })?;
    Ok(rollover_output(vault, true, protection_degraded))
}

struct RolloverTargets {
    parent: HardenedStateRoot,
    backup_root: HardenedStateRoot,
    state_root: PathBuf,
}

impl RolloverTargets {
    fn preflight(
        cli: &Cli,
        arguments: &VaultRolloverArgs,
        environment: &Environment,
        home: &VaultHomeLocation,
    ) -> Result<Self, CliError> {
        for path in [
            &arguments.out,
            &arguments.backup_out,
            &arguments.transfer_out,
        ]
        .into_iter()
        .chain(arguments.registration_dir.iter())
        {
            if !path.is_absolute()
                || path.file_name().is_none()
                || path.components().any(|component| {
                    matches!(
                        component,
                        std::path::Component::CurDir | std::path::Component::ParentDir
                    )
                })
            {
                return Err(rollover_target_error());
            }
        }
        let identity_home = identity_root(environment)?;
        let (selector, _) = selected_identity(cli, None, environment)?;
        let identity_parent = match &selector {
            IdentitySelector::Named(_) => identity_home.as_path(),
            IdentitySelector::ExplicitFile(path) => {
                path.parent().ok_or_else(rollover_target_error)?
            }
        };
        let state_root = state_root(environment)?;
        let backup_parent = arguments
            .backup_out
            .parent()
            .ok_or_else(rollover_target_error)?;
        // Each output is outside every source/private-state boundary, and the
        // backup parent is private and separate from the public transfer.
        let mut boundaries = vec![
            identity_home.as_path(),
            identity_parent,
            state_root.as_path(),
        ];
        boundaries.extend(home.repository().map(RepositoryLocation::worktree_path));
        boundaries.extend(home.detached_path());
        for boundary in boundaries {
            for output in [
                arguments.out.as_path(),
                backup_parent,
                arguments.transfer_out.as_path(),
            ]
            .into_iter()
            .chain(arguments.registration_dir.as_deref())
            {
                validate_path_separation(&[boundary, output])
                    .map_err(|_| rollover_target_error())?;
            }
        }
        validate_path_separation(&[&arguments.out, backup_parent, &arguments.transfer_out])
            .map_err(|_| rollover_target_error())?;
        if let Some(path) = &arguments.registration_dir {
            for other in [&arguments.out, backup_parent, &arguments.transfer_out] {
                validate_path_separation(&[path, other]).map_err(|_| rollover_target_error())?;
            }
            if !arguments.resume {
                governed::preflight_directory(path)?;
            }
        }
        let repositories = repository_refs(home);
        let exclusions = detached_paths(home);
        let parent = HardenedStateRoot::open_existing_excluding(
            arguments.out.parent().ok_or_else(rollover_target_error)?,
            &repositories,
            &exclusions,
        )
        .map_err(map_filesystem_error)?;
        if parent
            .private_child_exists(Path::new(
                arguments
                    .out
                    .file_name()
                    .ok_or_else(rollover_target_error)?,
            ))
            .map_err(map_filesystem_error)?
            != arguments.resume
        {
            return Err(rollover_target_error());
        }
        let backup_root =
            HardenedStateRoot::open_existing_excluding(backup_parent, &repositories, &exclusions)
                .map_err(map_filesystem_error)?;
        let backup = backup_root
            .preview_private_file(Path::new(
                arguments
                    .backup_out
                    .file_name()
                    .ok_or_else(rollover_target_error)?,
            ))
            .map_err(map_filesystem_error)?;
        let transfer =
            preview_public_file(&arguments.transfer_out).map_err(map_filesystem_error)?;
        if !arguments.resume && (backup.destination_exists() || transfer.destination_exists()) {
            return Err(rollover_target_error());
        }
        Ok(Self {
            parent,
            backup_root,
            state_root,
        })
    }
}

struct RolloverPublication<'a> {
    targets: RolloverTargets,
    arguments: &'a VaultRolloverArgs,
    context: &'a VaultPrincipalContext,
    source_bytes: &'a [u8],
    vault: &'a VaultFileV1,
    vault_bytes: &'a [u8],
    backup_bytes: &'a [u8],
    transfer_bytes: &'a [u8],
    files: &'a LocalStateFiles,
    catalog: &'a TransferPublicCatalogV1,
    registration: &'a registration::DestinationRegistration,
    protection: ProtectionPolicy,
}

fn publish_rollover(request: RolloverPublication<'_>) -> Result<(), CliError> {
    publication::publish(request)
}

pub(super) fn incomplete_rollover() -> CliError {
    CliError::new(
        CliErrorKind::Filesystem,
        "rollover-publication-incomplete",
        "rollover publication is incomplete; retain the pending candidate and backup-directory staging, then use --resume with the same output paths and unchanged source",
    )
}

fn require_synced(outcome: PublicationOutcome) -> Result<(), CliError> {
    if outcome == PublicationOutcome::PublishedAndSynced {
        Ok(())
    } else {
        Err(incomplete_rollover())
    }
}

fn rollover_target_error() -> CliError {
    CliError::new(
        CliErrorKind::InvalidArguments,
        "invalid-rollover-target",
        "rollover requires separate outputs outside source and private-state boundaries; use absent outputs for preparation or the exact original paths with --resume",
    )
}

fn map_rollover_error(error: RolloverError) -> CliError {
    use jury_core::rollover::RolloverErrorKind;
    if error.kind() == RolloverErrorKind::ReviewLabelLifetime {
        return CliError::new(
            CliErrorKind::Conflict,
            "rollover-review-label-lifetime",
            "a copied owner review label expires before the 24-hour registration deadline; refresh the source labels and their witness policies before fresh preparation",
        );
    }
    let message = match error.kind() {
        RolloverErrorKind::UnsupportedTopology => {
            "the source topology requires governed preparation and destination registration"
        }
        RolloverErrorKind::Unauthorized => "rollover requires an active source owner",
        _ => "rollover source authentication or complete destination preparation failed",
    };
    CliError::new(
        CliErrorKind::AuthenticationFailed,
        "rollover-failed",
        message,
    )
}

fn rollover_output(
    vault: &VaultFileV1,
    published: bool,
    protection_degraded: bool,
) -> CommandOutput {
    let witnessed = vault
        .policy
        .revisions
        .iter()
        .flat_map(|revision| &revision.operations)
        .any(|operation| {
            matches!(
                operation,
                PolicyOperationV1::ItemCreate {
                    witnessed_state: Some(_),
                    ..
                }
            )
        });
    CommandOutput::Safe {
        operation: if vault.suite_migration.is_some() { "vault-migrate-suite" } else { "vault-rollover" },
        fields: serde_json::json!({
            "published": published, "dry_run": !published,
            "destination_vault_id": hex(vault.header.vault_id.as_bytes()),
            "destination_genesis_fingerprint": hex(vault.header.genesis_fingerprint.as_bytes()),
            "suite": vault.header.suite, "active_items": vault.items.len(),
            "source_suite": vault.suite_migration.as_ref().map_or(vault.header.suite, |migration| migration.old_suite),
            "suite_migration": vault.suite_migration.is_some(),
            "backup_published": published, "transfer_published": published,
            "local_export_receipt_recorded": published, "local_owner_adopted": published,
            "witness_registration_required": witnessed,
            "witness_registration_complete": published && witnessed,
            "global_freshness_claimed": false,
            "redistributed": false, "protection_degraded": protection_degraded,
        }),
        lines: vec![
            if published { "Rollover published with a fresh backup, transfer and local receipts.".into() } else { "Dry-run preparation passed; no destination was published. A real run generates a new candidate.".into() },
            format!("New genesis: {}", hex(vault.header.genesis_fingerprint.as_bytes())),
            "The source remains unchanged. Retain its history and backups; old copies retain their original access and cryptography.".into(),
            "Redistribute the new transfer and verify its new genesis separately on every installation. No Git action or recipient delivery is implicit.".into(),
        ],
    }
}

fn selected_suite(source: u16, migration: Option<u16>) -> Result<VaultSuite, CliError> {
    match (source, migration) {
        (1, None) => Ok(VaultSuite::Suite1),
        (2, None) | (1, Some(2)) => Ok(VaultSuite::Suite2),
        _ => Err(CliError::new(
            CliErrorKind::InvalidArguments,
            "unsupported-suite-transition",
            "suite migration requires an explicit transition from suite 1 to suite 2; rollover preserves the source suite",
        )),
    }
}
