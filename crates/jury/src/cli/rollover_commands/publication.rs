use super::*;

pub(super) fn publish(request: RolloverPublication<'_>) -> Result<(), CliError> {
    // Source authorization is complete. Lock source before destination and
    // retain both locks across remote registration and durable publication,
    // so ordinary mutations cannot change the adopted snapshot in that window.
    let _source_lock = lock_current_source(request.context, request.source_bytes)?;
    let name = Path::new(
        request
            .arguments
            .out
            .file_name()
            .ok_or_else(rollover_target_error)?,
    );
    let root = if request.arguments.resume {
        request.targets.parent.open_private_child(name)
    } else {
        request.targets.parent.create_private_child_new(name)
    }
    .map_err(map_filesystem_error)?;
    let snapshot = if request.arguments.resume {
        let snapshot = recovery::Snapshot::read(&root)?;
        snapshot.validate_paths(request.arguments, &request.targets.state_root)?;
        if snapshot.read_vault(&root)? != request.vault_bytes {
            return Err(incomplete_rollover());
        }
        snapshot
    } else {
        let snapshot = recovery::Snapshot::create(&request)?;
        registration::publish_private(
            &root,
            PENDING_ROLLOVER,
            request.vault_bytes,
            request.protection,
        )?;
        snapshot.save(&root, &request)?;
        snapshot
    };
    let backup = prepare_backup(&request)?;
    let transfer = prepare_transfer(&request)?;
    let vault = prepare_vault(&root, &request)?;
    let mut exclusions = detached_paths(&request.context.home);
    exclusions.push(&request.arguments.out);
    let state = VaultStateDirectory::open_or_create(
        &request.targets.state_root,
        request.vault.header.vault_id.as_bytes(),
        request.vault.header.genesis_fingerprint.as_bytes(),
        &repository_refs(&request.context.home),
        &exclusions,
    )
    .map_err(map_filesystem_error)?;
    let locked = state.try_lock().map_err(|_| local_state_error())?;
    let mut catalog = PolicyCatalogV1::empty();
    catalog.merge_transfer(request.catalog)?;
    let catalog_bytes = policy_catalog_json_bytes(&catalog)?;
    // Prepare from retained destination snapshots before validating the old
    // bytes. Every accepted resume output is republished and synced, including
    // a prior write that became visible but failed its parent-directory sync.
    let catalog_file = locked
        .prepare_vault_state(
            VaultStateFile::PolicyCatalog,
            &protect(&catalog_bytes, request.protection)?,
        )
        .map_err(map_filesystem_error)?;
    validate_existing(
        locked.read_vault_state(VaultStateFile::PolicyCatalog),
        &catalog_bytes,
        request.arguments.resume,
    )?;
    let mut files = vec![catalog_file];
    for (kind, bytes) in [
        (PrincipalStateFile::Audit, request.files.audit()),
        (PrincipalStateFile::Checkpoint, request.files.checkpoint()),
        (PrincipalStateFile::Receipts, request.files.receipts()),
    ] {
        let file = locked
            .prepare(
                request.context.identity.principal_id().as_bytes(),
                kind,
                &protect(bytes, request.protection)?,
            )
            .map_err(map_filesystem_error)?;
        validate_existing(
            locked.read(request.context.identity.principal_id().as_bytes(), kind),
            bytes,
            request.arguments.resume,
        )?;
        files.push(file);
    }
    if read_vault(&request.context.home)? != request.source_bytes {
        return Err(checkpoint_conflict());
    }
    request
        .registration
        .register_all(&root, request.protection, vault.is_none())?;
    require_synced(backup.publish().map_err(map_filesystem_error)?)?;
    require_synced(transfer.publish().map_err(map_filesystem_error)?)?;
    for file in files {
        require_synced(file.publish().map_err(map_filesystem_error)?)?;
    }
    if let Some(vault) = vault {
        require_synced(vault.publish().map_err(map_filesystem_error)?)?;
    }
    if root
        .read_private_file(Path::new("vault.json"), MAX_VAULT_BYTES)
        .map_err(map_filesystem_error)?
        != request.vault_bytes
        || read_private_file(&request.arguments.backup_out, MAX_BACKUP_ENVELOPE_BYTES)
            .map_err(map_filesystem_error)?
            != request.backup_bytes
        || read_public_file(&request.arguments.transfer_out, MAX_TRANSFER_BYTES)
            .map_err(map_filesystem_error)?
            != request.transfer_bytes
        || locked
            .read_vault_state(VaultStateFile::PolicyCatalog)
            .map_err(map_filesystem_error)?
            != catalog_bytes
    {
        return Err(incomplete_rollover());
    }
    for (kind, bytes) in [
        (PrincipalStateFile::Audit, request.files.audit()),
        (PrincipalStateFile::Checkpoint, request.files.checkpoint()),
        (PrincipalStateFile::Receipts, request.files.receipts()),
    ] {
        if locked
            .read(request.context.identity.principal_id().as_bytes(), kind)
            .map_err(map_filesystem_error)?
            != bytes
        {
            return Err(incomplete_rollover());
        }
    }
    snapshot.finish(&root, &request)
}

// A source context is a preparation snapshot, not a freshness guarantee. Other
// clones share this principal's checkpoint without sharing the source file.
// Return the lock only after authenticating both under that same lock; callers
// retain it through publication or completed-output cleanup.
pub(super) fn lock_current_source<'a>(
    context: &'a VaultPrincipalContext,
    source_bytes: &[u8],
) -> Result<LockedVaultState<'a>, CliError> {
    let locked = context.state.try_lock().map_err(|_| local_state_error())?;
    if read_vault(&context.home)? != source_bytes {
        return Err(checkpoint_conflict());
    }
    let principal = context.identity.principal_id();
    let audit = locked
        .read(principal.as_bytes(), PrincipalStateFile::Audit)
        .map_err(map_filesystem_error)?;
    let checkpoint = locked
        .read(principal.as_bytes(), PrincipalStateFile::Checkpoint)
        .map_err(map_filesystem_error)?;
    let receipts = locked
        .read(principal.as_bytes(), PrincipalStateFile::Receipts)
        .map_err(map_filesystem_error)?;
    let verified = context
        .local
        .verify_files(Some(&audit), Some(&checkpoint), Some(&receipts))
        .map_err(|_| local_state_error())?;
    let candidate = CheckpointCandidate::from_validated(
        &context.policy,
        &context.vault.policy,
        &context.vault.items,
    )
    .map_err(|_| invalid_vault())?;
    if candidate
        .relation_to(verified.checkpoint())
        .map_err(|_| checkpoint_conflict())?
        == CheckpointRelation::Divergent
    {
        return Err(checkpoint_conflict());
    }
    Ok(locked)
}

#[cfg(test)]
mod tests;

fn prepare_backup(request: &RolloverPublication<'_>) -> Result<PreparedPrivateFile, CliError> {
    let name = Path::new(
        request
            .arguments
            .backup_out
            .file_name()
            .ok_or_else(rollover_target_error)?,
    );
    let target = request
        .targets
        .backup_root
        .preview_private_file(name)
        .map_err(map_filesystem_error)?;
    if target.destination_exists()
        && (!request.arguments.resume
            || request
                .targets
                .backup_root
                .read_private_file(name, MAX_BACKUP_ENVELOPE_BYTES)
                .map_err(map_filesystem_error)?
                != request.backup_bytes)
    {
        return Err(incomplete_rollover());
    }
    PreparedPrivateFile::prepare_bounded_private_bytes_if_unchanged(
        target,
        request.backup_bytes,
        MAX_BACKUP_ENVELOPE_BYTES,
        request.arguments.resume,
    )
    .map_err(map_filesystem_error)
}

fn prepare_transfer(request: &RolloverPublication<'_>) -> Result<PreparedPublicFile, CliError> {
    let target =
        preview_public_file(&request.arguments.transfer_out).map_err(map_filesystem_error)?;
    if target.destination_exists()
        && (!request.arguments.resume
            || read_public_file(&request.arguments.transfer_out, MAX_TRANSFER_BYTES)
                .map_err(map_filesystem_error)?
                != request.transfer_bytes)
    {
        return Err(incomplete_rollover());
    }
    PreparedPublicFile::prepare_bounded_if_unchanged(
        target,
        request.transfer_bytes,
        MAX_TRANSFER_BYTES,
        request.arguments.resume,
    )
    .map_err(map_filesystem_error)
}

fn prepare_vault(
    root: &HardenedStateRoot,
    request: &RolloverPublication<'_>,
) -> Result<Option<PreparedPrivateFile>, CliError> {
    if validate_existing(
        root.read_private_file(Path::new("vault.json"), MAX_VAULT_BYTES),
        request.vault_bytes,
        request.arguments.resume,
    )? {
        return Ok(None);
    }
    PreparedPrivateFile::prepare_state(
        root,
        Path::new("vault.json"),
        &protect(request.vault_bytes, request.protection)?,
        PublicationPolicy::CreateNew,
    )
    .map(Some)
    .map_err(map_filesystem_error)
}

fn validate_existing(
    existing: Result<Vec<u8>, jury_filesystem::FilesystemError>,
    expected: &[u8],
    resume: bool,
) -> Result<bool, CliError> {
    match existing {
        Ok(bytes) if resume && bytes == expected => Ok(true),
        Ok(_) => Err(incomplete_rollover()),
        Err(error) if error.kind() == FilesystemErrorKind::NotFound => Ok(false),
        Err(error) => Err(map_filesystem_error(error)),
    }
}
