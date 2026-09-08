use super::*;

pub(super) fn vault(root: &HardenedStateRoot) -> Result<Vec<u8>, CliError> {
    for name in [PENDING_ROLLOVER, PENDING_ROLLOVER_CLEANUP] {
        match root.read_private_file(Path::new(name), MAX_VAULT_BYTES) {
            Ok(_) => return Err(incomplete_rollover()),
            Err(error) if error.kind() == FilesystemErrorKind::NotFound => {}
            Err(error) => return Err(map_filesystem_error(error)),
        }
    }
    root.read_private_file(Path::new("vault.json"), MAX_VAULT_BYTES)
        .map_err(map_filesystem_error)
}

pub(super) fn outputs(
    backup_root: &HardenedStateRoot,
    state: &VaultStateDirectory,
    principal: PrincipalId,
    arguments: &VaultRolloverArgs,
) -> Result<snapshot::SavedOutputs, CliError> {
    let locked = state.try_lock().map_err(|_| local_state_error())?;
    Ok(snapshot::SavedOutputs {
        backup: backup_root
            .read_private_file(
                Path::new(
                    arguments
                        .backup_out
                        .file_name()
                        .ok_or_else(rollover_target_error)?,
                ),
                MAX_BACKUP_ENVELOPE_BYTES,
            )
            .map_err(map_filesystem_error)?,
        transfer: read_public_file(&arguments.transfer_out, MAX_TRANSFER_BYTES)
            .map_err(map_filesystem_error)?,
        audit: locked
            .read(principal.as_bytes(), PrincipalStateFile::Audit)
            .map_err(map_filesystem_error)?,
        checkpoint: locked
            .read(principal.as_bytes(), PrincipalStateFile::Checkpoint)
            .map_err(map_filesystem_error)?,
        receipts: locked
            .read(principal.as_bytes(), PrincipalStateFile::Receipts)
            .map_err(map_filesystem_error)?,
    })
}

pub(super) fn checkpoint(
    root: &HardenedStateRoot,
) -> Result<Option<VaultPolicyCheckpointV1>, CliError> {
    match root.read_private_file(Path::new("witness.checkpoint.json"), 64 * 1024) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|_| incomplete_rollover()),
        Err(error) if error.kind() == FilesystemErrorKind::NotFound => Ok(None),
        Err(error) => Err(map_filesystem_error(error)),
    }
}

pub(super) fn verify_catalog(
    state: &VaultStateDirectory,
    catalog: &TransferPublicCatalogV1,
) -> Result<(), CliError> {
    let mut expected = PolicyCatalogV1::empty();
    expected.merge_transfer(catalog)?;
    let locked = state.try_lock().map_err(|_| local_state_error())?;
    if locked
        .read_vault_state(VaultStateFile::PolicyCatalog)
        .map_err(map_filesystem_error)?
        != policy_catalog_json_bytes(&expected)?
    {
        return Err(incomplete_rollover());
    }
    Ok(())
}

pub(super) fn confirm_cleanup(root: &HardenedStateRoot) -> Result<(), CliError> {
    for (name, quarantine) in [
        (PENDING_ROLLOVER, PENDING_ROLLOVER_CLEANUP),
        (PENDING_OUTPUTS, PENDING_OUTPUTS_CLEANUP),
    ] {
        if root
            .confirm_private_cleanup_absent(Path::new(name), Path::new(quarantine))
            .map_err(map_filesystem_error)?
            != PrivateFileCleanupOutcome::RemovedAndSynced
        {
            return Err(incomplete_rollover());
        }
    }
    Ok(())
}
