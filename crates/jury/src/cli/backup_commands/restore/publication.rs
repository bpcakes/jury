use super::targets::{
    open_restore_root, restore_repository_refs, restore_vault_home_paths, source_detached_paths,
};
use super::*;

#[allow(clippy::too_many_arguments)]
pub(super) fn restore_additional_role_identity(
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
) -> Result<bool, CliError> {
    let recovered_role = recovered.identity(role).ok_or_else(invalid_backup)?;
    let parent = target.parent().ok_or_else(invalid_restore_target)?;
    let name = target.file_name().ok_or_else(invalid_restore_target)?;
    let root = open_restore_root(parent, request)?;
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
    let file = if preview.destination_exists() {
        let bytes = root
            .read_private_file(Path::new(name), MAX_IDENTITY_FILE_BYTES)
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
        let outcome = PreparedPrivateFile::prepare_state(
            &root,
            Path::new(name),
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
    let installed_bytes = root
        .read_private_file(Path::new(name), MAX_IDENTITY_FILE_BYTES)
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
    Ok(passphrase.protection_degraded())
}

pub(super) fn publish_recovered_state(
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
        let parent = open_restore_root(parent_path, request)?;
        parent
            .create_private_child_new(Path::new(name))
            .map_err(map_filesystem_error)?;
    }
    let repositories = restore_repository_refs(request);
    let excluded_paths = source_detached_paths(request);
    let state = if must_already_exist {
        VaultStateDirectory::open_existing_excluding(
            request.state_root,
            recovered.header().vault_id.as_bytes(),
            recovered.header().genesis_fingerprint.as_bytes(),
            &repositories,
            &excluded_paths,
        )
    } else {
        VaultStateDirectory::open_or_create(
            request.state_root,
            recovered.header().vault_id.as_bytes(),
            recovered.header().genesis_fingerprint.as_bytes(),
            &repositories,
            &restore_vault_home_paths(request),
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

pub(super) fn validate_restored_state_publication(
    request: &RestoreRequest<'_>,
    recovered: &jury_core::backup::RecoveredBackup,
    marker: &RestoreMarker,
) -> Result<(VaultFileV1, PolicyState), CliError> {
    let installed_vault_bytes = read_restore_vault(request)?;
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
    let state = VaultStateDirectory::open_existing_excluding(
        request.state_root,
        recovered.header().vault_id.as_bytes(),
        recovered.header().genesis_fingerprint.as_bytes(),
        &restore_repository_refs(request),
        &source_detached_paths(request),
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

pub(super) fn write_marker(
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

pub(super) fn parse_marker(bytes: &[u8]) -> Result<RestoreMarker, CliError> {
    let marker: RestoreMarker =
        serde_json::from_slice(bytes).map_err(|_| invalid_restore_marker())?;
    if marker_bytes(&marker)?.as_slice() != bytes || marker.version != 1 || marker.timestamp_ms == 0
    {
        return Err(invalid_restore_marker());
    }
    Ok(marker)
}

pub(super) fn marker_bytes(marker: &RestoreMarker) -> Result<Vec<u8>, CliError> {
    let bytes = serde_json::to_vec(marker).map_err(|_| invalid_restore_marker())?;
    if bytes.len() > MAX_RESTORE_MARKER_BYTES {
        return Err(invalid_restore_marker());
    }
    Ok(bytes)
}

pub(super) fn marker_name(id: &jury_protocol::vault_v1::RecoveryId) -> String {
    marker_name_from_text(&hex(id.as_bytes()))
}

fn marker_name_from_text(id: &str) -> String {
    format!(".jury-vault-restore-{id}.json")
}

pub(super) fn vault_target_label(home: &VaultHomeLocation) -> Result<String, CliError> {
    match home {
        VaultHomeLocation::Repository { repository } => {
            direct_utf8_path(&repository.worktree_path().join(".jury/vault.json"))
        }
        VaultHomeLocation::Detached { path, .. } => direct_utf8_path(&path.join("vault.json")),
    }
}
