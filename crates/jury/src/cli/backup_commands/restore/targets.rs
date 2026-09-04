use super::*;

pub(super) fn validate_restore_paths(request: &RestoreRequest<'_>) -> Result<(), CliError> {
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
    let mut identity_parents = identity_targets
        .iter()
        .map(|target| target.parent().ok_or_else(invalid_restore_target))
        .collect::<Result<Vec<_>, _>>()?;
    identity_parents.sort_unstable();
    identity_parents.dedup();
    let mut boundaries = vec![
        request.input.to_path_buf(),
        request.state_root.to_path_buf(),
    ];
    boundaries.extend(identity_parents.into_iter().map(Path::to_path_buf));
    if let Some(repository) = request.target_home.repository() {
        boundaries.push(repository.worktree_path().to_path_buf());
    }
    boundaries.extend(request.target_home.detached_path().map(Path::to_path_buf));
    if let Some(source_home) = request.mode.source_home() {
        if let Some(repository) = source_home.repository() {
            boundaries.push(repository.worktree_path().to_path_buf());
        }
        boundaries.extend(source_home.detached_path().map(Path::to_path_buf));
    }
    let boundaries = boundaries.iter().map(PathBuf::as_path).collect::<Vec<_>>();
    validate_path_separation(&boundaries).map_err(map_filesystem_error)
}

pub(super) fn restore_repository_refs<'a>(
    request: &'a RestoreRequest<'_>,
) -> Vec<&'a RepositoryLocation> {
    request
        .target_home
        .repository()
        .into_iter()
        .chain(
            request
                .mode
                .source_home()
                .and_then(VaultHomeLocation::repository),
        )
        .collect()
}

pub(super) fn source_detached_paths<'a>(request: &'a RestoreRequest<'_>) -> Vec<&'a Path> {
    request
        .mode
        .source_home()
        .and_then(VaultHomeLocation::detached_path)
        .into_iter()
        .collect()
}

pub(super) fn restore_vault_home_paths<'a>(request: &'a RestoreRequest<'_>) -> Vec<&'a Path> {
    request
        .target_home
        .detached_path()
        .into_iter()
        .chain(source_detached_paths(request))
        .collect()
}

pub(super) fn open_restore_root(
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

pub(super) fn read_restore_vault(request: &RestoreRequest<'_>) -> Result<Vec<u8>, CliError> {
    match &*request.target_home {
        VaultHomeLocation::Repository { repository } => repository
            .read_encrypted_shared_artifact(MAX_VAULT_BYTES)
            .map_err(map_filesystem_error),
        VaultHomeLocation::Detached { path, .. } => open_restore_root(path, request)?
            .read_private_file(Path::new("vault.json"), MAX_VAULT_BYTES)
            .map_err(map_filesystem_error),
    }
}

pub(super) fn prepare_restore_vault(
    request: &mut RestoreRequest<'_>,
    contents: &ProtectedMemory,
) -> Result<PreparedPrivateFile, CliError> {
    match &mut *request.target_home {
        VaultHomeLocation::Repository { .. } => prepare_new_vault(request.target_home, contents),
        VaultHomeLocation::Detached { path, .. } => {
            let repositories = request
                .mode
                .source_home()
                .and_then(VaultHomeLocation::repository)
                .into_iter()
                .collect::<Vec<_>>();
            let excluded_paths = request
                .mode
                .source_home()
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

pub(super) fn validate_role_restore_targets(
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

pub(super) fn preflight_new_restore_targets(
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
    if request.mode.requires_absent_state_root() {
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

pub(super) fn ensure_detached_restore_home(
    request: &RestoreRequest<'_>,
    retry: bool,
) -> Result<(), CliError> {
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
