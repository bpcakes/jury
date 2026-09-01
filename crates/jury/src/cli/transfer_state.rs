use super::*;

pub(super) fn reconcile_first_install_local_state(
    state_root: &Path,
    home: &VaultHomeLocation,
    transfer: &ValidatedTransfer,
    local: &PrincipalLocalState,
    candidate: &CheckpointCandidate,
    principal_id: &PrincipalId,
    protection: ProtectionPolicy,
) -> Result<(), CliError> {
    let repositories = repository_refs(home);
    let state = VaultStateDirectory::open_or_create(
        state_root,
        transfer.vault().header.vault_id.as_bytes(),
        transfer.vault().header.genesis_fingerprint.as_bytes(),
        &repositories,
        &detached_paths(home),
    )
    .map_err(map_filesystem_error)?;
    let locked = state.try_lock().map_err(|_| local_state_error())?;
    let existing = [
        read_optional_principal_state(&locked, principal_id, PrincipalStateFile::Audit)?,
        read_optional_principal_state(&locked, principal_id, PrincipalStateFile::Checkpoint)?,
        read_optional_principal_state(&locked, principal_id, PrincipalStateFile::Receipts)?,
    ];

    if let [Some(audit), Some(checkpoint), Some(receipts)] = &existing {
        let verified = local
            .verify_files(Some(audit), Some(checkpoint), Some(receipts))
            .map_err(|_| local_state_error())?;
        if candidate
            .relation_to(verified.checkpoint())
            .map_err(|_| checkpoint_conflict())?
            == CheckpointRelation::Divergent
        {
            return Err(checkpoint_conflict());
        }
        reconcile_transfer_catalog_locked(&locked, transfer.catalog(), protection)?;
        drop(locked);
        return advance_principal_checkpoint(
            &state,
            local,
            candidate,
            principal_id,
            transfer.envelope().created_at_ms,
            protection,
        );
    }

    let initialized = local
        .initialize(candidate, transfer.envelope().created_at_ms)
        .map_err(|_| local_state_error())?;
    let files = local
        .serialize(&initialized)
        .map_err(|_| local_state_error())?;
    let targets = [files.audit(), files.checkpoint(), files.receipts()];
    if existing
        .iter()
        .zip(targets)
        .any(|(current, target)| current.as_deref().is_some_and(|bytes| bytes != target))
    {
        return Err(local_state_error());
    }

    reconcile_transfer_catalog_locked(&locked, transfer.catalog(), protection)?;
    let protected = [
        protect(files.audit(), protection)?,
        protect(files.checkpoint(), protection)?,
        protect(files.receipts(), protection)?,
    ];
    let kinds = [
        PrincipalStateFile::Audit,
        PrincipalStateFile::Checkpoint,
        PrincipalStateFile::Receipts,
    ];
    let mut prepared = Vec::new();
    for ((current, contents), kind) in existing.iter().zip(&protected).zip(kinds) {
        if current.is_none() {
            prepared.push(
                locked
                    .prepare(principal_id.as_bytes(), kind, contents)
                    .map_err(map_filesystem_error)?,
            );
        }
    }
    for file in prepared {
        if file.publish().map_err(map_filesystem_error)? != PublicationOutcome::PublishedAndSynced {
            return Err(local_state_error());
        }
    }
    Ok(())
}

fn read_optional_principal_state(
    locked: &LockedVaultState<'_>,
    principal_id: &PrincipalId,
    file: PrincipalStateFile,
) -> Result<Option<Vec<u8>>, CliError> {
    match locked.read(principal_id.as_bytes(), file) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.kind() == FilesystemErrorKind::NotFound => Ok(None),
        Err(error) => Err(map_filesystem_error(error)),
    }
}

pub(super) fn reconcile_transfer_catalog(
    state: &VaultStateDirectory,
    transfer: &TransferPublicCatalogV1,
    protection: ProtectionPolicy,
) -> Result<(), CliError> {
    let locked = state.try_lock().map_err(|_| local_state_error())?;
    reconcile_transfer_catalog_locked(&locked, transfer, protection)
}

fn reconcile_transfer_catalog_locked(
    locked: &LockedVaultState<'_>,
    transfer: &TransferPublicCatalogV1,
    protection: ProtectionPolicy,
) -> Result<(), CliError> {
    let prior = match locked.read_vault_state(VaultStateFile::PolicyCatalog) {
        Ok(bytes) => Some(bytes),
        Err(error) if error.kind() == FilesystemErrorKind::NotFound => None,
        Err(error) => return Err(map_filesystem_error(error)),
    };
    let mut catalog = match prior.as_deref() {
        Some(bytes) => PolicyCatalogV1::parse_local_compatible(bytes)?,
        None => PolicyCatalogV1::empty(),
    };
    catalog.merge_transfer(transfer)?;
    let target = policy_catalog_json_bytes(&catalog)?;
    if prior.as_deref() == Some(target.as_slice()) {
        return Ok(());
    }
    let protected = protect(&target, protection)?;
    let outcome = locked
        .prepare_vault_state(VaultStateFile::PolicyCatalog, &protected)
        .map_err(map_filesystem_error)?
        .publish()
        .map_err(map_filesystem_error)?;
    if outcome == PublicationOutcome::PublishedAndSynced {
        Ok(())
    } else {
        Err(local_state_error())
    }
}

pub(super) fn record_transfer_receipt(
    context: &VaultPrincipalContext,
    receipt: TransferReceipt,
    protection: ProtectionPolicy,
) -> Result<(), CliError> {
    let locked = context.state.try_lock().map_err(|_| local_state_error())?;
    let principal_id = context.identity.principal_id();
    let audit = locked
        .read(principal_id.as_bytes(), PrincipalStateFile::Audit)
        .map_err(map_filesystem_error)?;
    let checkpoint = locked
        .read(principal_id.as_bytes(), PrincipalStateFile::Checkpoint)
        .map_err(map_filesystem_error)?;
    let receipts = locked
        .read(principal_id.as_bytes(), PrincipalStateFile::Receipts)
        .map_err(map_filesystem_error)?;
    let mut verified = context
        .local
        .verify_files(Some(&audit), Some(&checkpoint), Some(&receipts))
        .map_err(|_| local_state_error())?;
    context
        .local
        .record_receipt(&mut verified, ReceiptUpdate::Transfer(receipt))
        .map_err(|_| local_state_error())?;
    let files = context
        .local
        .serialize(&verified)
        .map_err(|_| local_state_error())?;
    let protected = protect(files.receipts(), protection)?;
    let publication = locked
        .publish(
            principal_id.as_bytes(),
            PrincipalStateFile::Receipts,
            &protected,
        )
        .map_err(map_filesystem_error)?;
    if publication == PublicationOutcome::PublishedAndSynced {
        Ok(())
    } else {
        Err(local_state_error())
    }
}

pub(super) fn latest_transfer_receipt(
    context: &VaultPrincipalContext,
) -> Result<Option<TransferReceipt>, CliError> {
    let principal_id = context.identity.principal_id();
    let audit = context
        .state
        .read_principal_state(principal_id.as_bytes(), PrincipalStateFile::Audit)
        .map_err(map_filesystem_error)?;
    let checkpoint = context
        .state
        .read_principal_state(principal_id.as_bytes(), PrincipalStateFile::Checkpoint)
        .map_err(map_filesystem_error)?;
    let receipts = context
        .state
        .read_principal_state(principal_id.as_bytes(), PrincipalStateFile::Receipts)
        .map_err(map_filesystem_error)?;
    let verified = context
        .local
        .verify_files(Some(&audit), Some(&checkpoint), Some(&receipts))
        .map_err(|_| local_state_error())?;
    Ok(verified.receipts().latest_transfer().cloned())
}
