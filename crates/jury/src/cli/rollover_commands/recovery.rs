use super::*;

mod binding;
mod completed;
pub(super) use binding::publication_operation_id;
mod snapshot;
pub(super) use snapshot::Snapshot;

pub(super) fn resume(
    cli: &Cli,
    arguments: &VaultRolloverArgs,
    destination_suite: VaultSuite,
    environment: &Environment,
    context: &VaultPrincipalContext,
    targets: RolloverTargets,
    protection: ProtectionPolicy,
) -> Result<CommandOutput, CliError> {
    let root = targets
        .parent
        .open_private_child(Path::new(
            arguments
                .out
                .file_name()
                .ok_or_else(rollover_target_error)?,
        ))
        .map_err(map_filesystem_error)?;
    let snapshot = Snapshot::read_if_present(&root)?;
    let source_bytes = read_vault(&context.home)?;
    let vault_bytes = if let Some(snapshot) = &snapshot {
        snapshot.validate_paths(arguments, &targets.state_root)?;
        if sha256_digest(&source_bytes) != snapshot.source_digest {
            return Err(checkpoint_conflict());
        }
        snapshot.read_vault(&root)?
    } else {
        completed::vault(&root)?
    };
    let vault = VaultFileV1::parse(&vault_bytes).map_err(|_| invalid_vault())?;
    if vault.header.suite != destination_suite.id()
        || vault.policy.genesis.owner.principal_id != context.identity.principal_id()
    {
        return Err(rollover_target_error());
    }
    let mut exclusions = detached_paths(&context.home);
    exclusions.push(&arguments.out);
    let state = VaultStateDirectory::open_or_create(
        &targets.state_root,
        vault.header.vault_id.as_bytes(),
        vault.header.genesis_fingerprint.as_bytes(),
        &repository_refs(&context.home),
        &exclusions,
    )
    .map_err(map_filesystem_error)?;
    let saved = if let Some(snapshot) = &snapshot {
        snapshot.load(
            &targets.backup_root,
            &state,
            context.identity.principal_id(),
            arguments,
        )?
    } else {
        completed::outputs(
            &targets.backup_root,
            &state,
            context.identity.principal_id(),
            arguments,
        )?
    };
    let transfer = jury_core::transfer::ValidatedTransfer::parse(&saved.transfer)
        .map_err(map_transfer_error)?;
    if transfer.vault() != &vault {
        return Err(incomplete_rollover());
    }
    let catalog = transfer.catalog();
    let source = RolloverSource::validate(&context.vault, &context.catalog.witness_policies)
        .map_err(map_rollover_error)?;
    if catalog.registration_proofs.is_empty() {
        source
            .verify_fresh_direct_destination(&vault)
            .map_err(map_rollover_error)?;
    } else {
        source
            .verify_fresh_governed_destination(
                &context.catalog.transfer_catalog(&context.vault)?,
                &vault,
                catalog,
            )
            .map_err(map_rollover_error)?;
    }
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
    let verified = local
        .verify_files(
            Some(&saved.audit),
            Some(&saved.checkpoint),
            Some(&saved.receipts),
        )
        .map_err(|_| local_state_error())?;
    if candidate
        .relation_to(verified.checkpoint())
        .map_err(|_| local_state_error())?
        != jury_core::local_state::CheckpointRelation::Equal
    {
        return Err(checkpoint_conflict());
    }
    let files = local
        .serialize(&verified)
        .map_err(|_| local_state_error())?;
    if files.audit() != saved.audit
        || files.checkpoint() != saved.checkpoint
        || files.receipts() != saved.receipts
    {
        return Err(local_state_error());
    }
    let backup_passphrase = secret_input::capture_named_or_environment(
        protection,
        cli.passphrase_stdin,
        false,
        "Backup passphrase",
        environment.backup_passphrase(),
    )
    .map_err(map_secret_error)?;
    let envelope = BackupEnvelopeV1::parse(&saved.backup).map_err(|_| invalid_backup())?;
    let recovered = open_backup(&envelope, backup_passphrase.memory()).map_err(map_backup_error)?;
    if recovered.vault() != &vault
        || recovered.catalog() != catalog
        || recovered.header().owner_principal_id != context.identity.principal_id()
    {
        return Err(incomplete_rollover());
    }
    let backup_receipt = verified
        .receipts()
        .latest_backup()
        .ok_or_else(incomplete_rollover)?;
    let transfer_receipt = verified
        .receipts()
        .latest_transfer()
        .ok_or_else(incomplete_rollover)?;
    if backup_receipt != &backup_commands::backup_receipt(recovered.header(), recovered.coverage())
        || transfer_receipt.transfer_id != transfer.envelope().transfer_id
        || transfer_receipt.output_digest != sha256_digest(&saved.transfer)
        || transfer_receipt.captured_public_revision_hash
            != transfer.envelope().source_public_revision_hash
    {
        return Err(incomplete_rollover());
    }
    let registration_checkpoint = if let Some(snapshot) = &snapshot {
        snapshot.registration_checkpoint.clone()
    } else {
        completed::checkpoint(&root)?
    };
    let operation_id = publication_operation_id(
        arguments,
        &targets.state_root,
        &source_bytes,
        &vault_bytes,
        &saved.backup,
        &saved.transfer,
        registration_checkpoint.as_ref(),
    )?;
    if !verified.contains_operation(&operation_id) {
        return Err(incomplete_rollover());
    }
    let registration = registration::DestinationRegistration::restore(
        &vault,
        catalog,
        arguments,
        registration_checkpoint,
    )?;
    if snapshot.is_none() {
        let _source_lock = context.state.try_lock().map_err(|_| local_state_error())?;
        completed::verify_catalog(&state, catalog)?;
        if !registration.verify_saved(&root)? || read_vault(&context.home)? != source_bytes {
            return Err(incomplete_rollover());
        }
        completed::confirm_cleanup(&root)?;
    } else {
        publication::publish(RolloverPublication {
            targets,
            arguments,
            context,
            source_bytes: &source_bytes,
            vault: &vault,
            vault_bytes: &vault_bytes,
            backup_bytes: &saved.backup,
            transfer_bytes: &saved.transfer,
            files: &files,
            catalog,
            registration: &registration,
            protection,
        })?;
    }
    Ok(rollover_output(
        &vault,
        true,
        context.protection_degraded || backup_passphrase.protection_degraded(),
    ))
}
