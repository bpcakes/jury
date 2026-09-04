use super::*;

mod model;
mod publication;

pub(super) use model::RestorePublicationPoint;
use model::{RestoreIdentityTarget, RestoreMarker, RestoreRequest, RestoredInstallation};
use publication::{
    marker_bytes, marker_name, parse_marker, publish_recovered_state,
    restore_additional_role_identity, validate_restored_state_publication, vault_target_label,
    write_marker,
};

const MAX_RESTORE_MARKER_BYTES: usize = 16 * 1024;

pub(in crate::cli) fn backup_restore(
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

pub(super) fn backup_restore_with_observer(
    cli: &Cli,
    arguments: &BackupRestoreArgs,
    environment: &Environment,
    current: &Path,
    protection: ProtectionPolicy,
    observer: &mut dyn FnMut(RestorePublicationPoint) -> Result<(), CliError>,
) -> Result<CommandOutput, CliError> {
    let mut target_home = selected_home(cli, environment, current)?;
    let identity_target = match (
        arguments.identity_out.as_deref(),
        arguments.reuse_identity.as_deref(),
    ) {
        (Some(path), None) => RestoreIdentityTarget::Create(path),
        (None, Some(path)) => RestoreIdentityTarget::Reuse(path),
        _ => {
            return Err(CliError::new(
                CliErrorKind::InvalidArguments,
                "identity-restore-target-required",
                "select either an absent identity output or an exact existing identity",
            ));
        }
    };
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
            source_home: None,
            identity_target,
            approver_identity_target: arguments.approver_identity_out.as_deref(),
            witness_identity_target: arguments.witness_identity_out.as_deref(),
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
            "identity_reused": identity_target.is_reuse(),
            "restored_direct_access_validated": false,
            "transaction_marker_removed": restored.marker_removed,
            "local_state_published": true,
        }),
        lines,
    ))
}

pub(in crate::cli) fn backup_drill(
    cli: &Cli,
    arguments: &BackupDrillArgs,
    environment: &Environment,
    current: &Path,
    protection: ProtectionPolicy,
) -> Result<CommandOutput, CliError> {
    let source_home = selected_home(cli, environment, current)?;
    let mut target_home = VaultHomeLocation::Detached {
        path: arguments.vault_out.clone(),
        source: HomeSource::Explicit,
    };
    let restored = restore_archive(RestoreRequest {
        cli,
        input: &arguments.input,
        target_home: &mut target_home,
        source_home: Some(&source_home),
        identity_target: RestoreIdentityTarget::Create(&arguments.identity_out),
        approver_identity_target: arguments.approver_identity_out.as_deref(),
        witness_identity_target: arguments.witness_identity_out.as_deref(),
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

fn restore_archive(request: RestoreRequest<'_>) -> Result<RestoredInstallation, CliError> {
    restore_archive_with_observer(request, &mut |_| Ok(()))
}

fn restore_archive_with_observer(
    mut request: RestoreRequest<'_>,
    observer: &mut dyn FnMut(RestorePublicationPoint) -> Result<(), CliError>,
) -> Result<RestoredInstallation, CliError> {
    validate_restore_paths(&request)?;
    let archive_bytes = read_private_file(request.input, MAX_BACKUP_ENVELOPE_BYTES)
        .map_err(map_filesystem_error)?;
    let envelope = BackupEnvelopeV1::parse(&archive_bytes).map_err(|_| invalid_backup())?;
    let identity_parent = request
        .identity_target
        .path()
        .parent()
        .ok_or_else(filesystem_error)?;
    let identity_name = request
        .identity_target
        .path()
        .file_name()
        .ok_or_else(filesystem_error)?;
    let identity_root = open_restore_root(identity_parent, &request)?;
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
        identity_target: direct_utf8_path(request.identity_target.path())?,
        state_root: direct_utf8_path(request.state_root)?,
        vault_id: hex(recovered.header().vault_id.as_bytes()),
        genesis_fingerprint: hex(recovered.header().genesis_fingerprint.as_bytes()),
        payload_digest: hex(recovered.header().payload_digest.as_bytes()),
        timestamp_ms: match &prior_marker {
            Some(marker) => marker.timestamp_ms,
            None => timestamp_ms()?,
        },
        identity_reused: request.identity_target.is_reuse(),
        identity_published: request.identity_target.is_reuse(),
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
        && !request.identity_target.is_reuse()
        && !identity_preview.destination_exists()
    {
        return Err(restore_partial_conflict());
    }

    let identity_environment = if request.identity_target.is_reuse() {
        request.environment.jury_identity_passphrase.as_deref()
    } else {
        request.environment.jury_new_passphrase.as_deref()
    };
    let identity_passphrase = secret_input::capture_named_or_environment(
        request.protection,
        request.cli.passphrase_stdin,
        !request.identity_target.is_reuse(),
        if request.identity_target.is_reuse() {
            "Identity passphrase"
        } else {
            "New identity passphrase"
        },
        identity_environment.map(Vec::as_slice),
    )
    .map_err(map_secret_error)?;
    if !request.identity_target.is_reuse()
        && backup_passphrase
            .matches(&identity_passphrase)
            .map_err(map_secret_error)?
    {
        return Err(independent_restored_identity_passphrase_required());
    }
    let (identity_file, publish_identity) = if identity_preview.destination_exists() {
        let bytes = identity_root
            .read_private_file(Path::new(identity_name), MAX_IDENTITY_FILE_BYTES)
            .map_err(map_filesystem_error)?;
        let file = IdentityFileV1::parse(&bytes).map_err(|_| invalid_identity())?;
        let unlocked = unlock(&file, identity_passphrase.memory())
            .map_err(|error| map_identity_error(error.kind()))?;
        if !owner
            .identity()
            .matches_unlocked(&unlocked)
            .map_err(|error| map_identity_error(error.kind()))?
            || (!request.identity_target.is_reuse() && prior_marker_bytes.is_none())
        {
            return Err(CliError::new(
                CliErrorKind::Conflict,
                "restore-identity-mismatch",
                "the existing identity is not an authenticated retry target for this backup",
            ));
        }
        (file, false)
    } else {
        if request.identity_target.is_reuse() {
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
        let outcome = PreparedPrivateFile::prepare_state(
            &identity_root,
            Path::new(identity_name),
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

    match read_restore_vault(&request) {
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
            ensure_detached_restore_home(&request, prior_marker_bytes.is_some())?;
            let protected_vault = protect(recovered.vault_bytes(), request.protection)?;
            let outcome = prepare_restore_vault(&mut request, &protected_vault)?
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

    let installed_identity_bytes = identity_root
        .read_private_file(Path::new(identity_name), MAX_IDENTITY_FILE_BYTES)
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
    let mut paths = vec![
        request.input,
        request.identity_target.path(),
        request.state_root,
    ];
    paths.extend(request.approver_identity_target);
    paths.extend(request.witness_identity_target);
    for path in paths {
        direct_utf8_path(path)?;
    }
    let mut identity_targets = vec![request.identity_target.path()];
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
    if let Some(source_home) = request.source_home {
        let source_root = source_home
            .repository()
            .map(RepositoryLocation::worktree_path)
            .or_else(|| source_home.detached_path())
            .ok_or_else(containment_error)?;
        let mut output_paths = vec![request.identity_target.path(), request.state_root];
        output_paths.extend(request.approver_identity_target);
        output_paths.extend(request.witness_identity_target);
        output_paths.extend(request.target_home.detached_path());
        if output_paths
            .into_iter()
            .any(|output| overlaps(source_root, output))
        {
            return Err(containment_error());
        }
    }
    Ok(())
}

fn restore_repository_refs<'a>(request: &'a RestoreRequest<'_>) -> Vec<&'a RepositoryLocation> {
    request
        .target_home
        .repository()
        .into_iter()
        .chain(request.source_home.and_then(VaultHomeLocation::repository))
        .collect()
}

fn source_detached_paths<'a>(request: &'a RestoreRequest<'_>) -> Vec<&'a Path> {
    request
        .source_home
        .and_then(VaultHomeLocation::detached_path)
        .into_iter()
        .collect()
}

fn restore_vault_home_paths<'a>(request: &'a RestoreRequest<'_>) -> Vec<&'a Path> {
    request
        .target_home
        .detached_path()
        .into_iter()
        .chain(source_detached_paths(request))
        .collect()
}

fn open_restore_root(
    path: &Path,
    request: &RestoreRequest<'_>,
) -> Result<HardenedStateRoot, CliError> {
    HardenedStateRoot::open_existing_excluding(
        path,
        &restore_repository_refs(request),
        &source_detached_paths(request),
    )
    .map_err(map_filesystem_error)
}

fn read_restore_vault(request: &RestoreRequest<'_>) -> Result<Vec<u8>, CliError> {
    match &*request.target_home {
        VaultHomeLocation::Repository { repository } => repository
            .read_encrypted_shared_artifact(MAX_VAULT_BYTES)
            .map_err(map_filesystem_error),
        VaultHomeLocation::Detached { path, .. } => open_restore_root(path, request)?
            .read_private_file(Path::new("vault.json"), MAX_VAULT_BYTES)
            .map_err(map_filesystem_error),
    }
}

fn prepare_restore_vault(
    request: &mut RestoreRequest<'_>,
    contents: &ProtectedMemory,
) -> Result<PreparedPrivateFile, CliError> {
    match &mut *request.target_home {
        VaultHomeLocation::Repository { .. } => prepare_new_vault(request.target_home, contents),
        VaultHomeLocation::Detached { path, .. } => {
            let repositories = request
                .source_home
                .and_then(VaultHomeLocation::repository)
                .into_iter()
                .collect::<Vec<_>>();
            let excluded_paths = request
                .source_home
                .and_then(VaultHomeLocation::detached_path)
                .into_iter()
                .collect::<Vec<_>>();
            let root =
                HardenedStateRoot::open_existing_excluding(path, &repositories, &excluded_paths)
                    .map_err(map_filesystem_error)?;
            PreparedPrivateFile::prepare_state(
                &root,
                Path::new("vault.json"),
                contents,
                PublicationPolicy::CreateNew,
            )
            .map_err(map_filesystem_error)
        }
    }
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
    if identity_exists != request.identity_target.is_reuse() {
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
        let root = open_restore_root(parent, request)?;
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
            let parent = open_restore_root(parent, request)?;
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
        let parent = open_restore_root(parent, request)?;
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
        match VaultStateDirectory::open_existing_excluding(
            request.state_root,
            envelope.header.vault_id.as_bytes(),
            envelope.header.genesis_fingerprint.as_bytes(),
            &restore_repository_refs(request),
            &source_detached_paths(request),
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

fn ensure_detached_restore_home(request: &RestoreRequest<'_>, retry: bool) -> Result<(), CliError> {
    let VaultHomeLocation::Detached { path, .. } = &*request.target_home else {
        return Ok(());
    };
    let parent_path = path.parent().ok_or_else(invalid_restore_target)?;
    let name = path.file_name().ok_or_else(invalid_restore_target)?;
    let parent = open_restore_root(parent_path, request)?;
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
