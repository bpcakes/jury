use super::*;

pub(super) fn vault_init(
    cli: &Cli,
    _: &VaultInitArgs,
    environment: &Environment,
    current: &Path,
    protection: ProtectionPolicy,
) -> Result<CommandOutput, CliError> {
    let mut home = selected_home(cli, environment, current)?;
    let (selector, _) = selected_identity(cli, None, environment)?;
    validate_explicit_identity_separation(&selector, &home)?;
    let identity_root = identity_root(environment)?;
    validate_detached_separation(&identity_root, &home)?;
    let identity_bytes = {
        let repositories = repository_refs(&home);
        let root = HardenedStateRoot::open_existing(&identity_root, &repositories)
            .map_err(map_filesystem_error)?;
        selector
            .read(&root, &repositories, MAX_IDENTITY_FILE_BYTES)
            .map_err(map_filesystem_error)?
    };
    let identity_file = IdentityFileV1::parse(&identity_bytes).map_err(|_| invalid_identity())?;
    let passphrase =
        secret_input::capture(protection, cli.passphrase_stdin, false).map_err(map_secret_error)?;
    let UnlockedIdentity::VaultPrincipal(owner) = unlock(&identity_file, passphrase.memory())
        .map_err(|error| map_identity_error(error.kind()))?
    else {
        return Err(CliError::new(
            CliErrorKind::InvalidIdentity,
            "owner-identity-required",
            "vault initialization requires a human owner identity",
        ));
    };
    if identity_file.header.principal_kind != PrincipalKind::Human {
        return Err(CliError::new(
            CliErrorKind::InvalidIdentity,
            "human-owner-required",
            "vault initialization requires a human owner identity",
        ));
    }

    let created_at_ms = timestamp_ms()?;
    let created_policy = PolicyCreator::new()
        .create(&owner, created_at_ms, |_| false)
        .map_err(|_| invalid_vault())?;
    let genesis_fingerprint = created_policy
        .journal
        .genesis
        .recomputed_fingerprint()
        .map_err(|_| invalid_vault())?;
    let vault = VaultFileV1 {
        header: VaultHeaderV1 {
            magic: "jury-vault".to_owned(),
            version: 1,
            vault_id: created_policy.journal.genesis.vault_id,
            created_at_ms,
            suite: 1,
            policy_schema: 1,
            item_schema: 1,
            identity_schema: 1,
            genesis_fingerprint: genesis_fingerprint.clone(),
        },
        policy: created_policy.journal,
        items: Vec::new(),
        suite_migration: None,
    };
    let vault_bytes = vault.to_json_bytes().map_err(|_| invalid_vault())?;
    let protected_vault = protect(&vault_bytes, protection)?;
    let prepared_shared = prepare_new_vault(&mut home, &protected_vault)?;

    let state_root = resolve_linux_state_root(
        environment.jury_state_home.as_deref(),
        environment.xdg_state_home.as_deref(),
        environment.user_home.as_deref(),
    )
    .map_err(|_| {
        CliError::new(
            CliErrorKind::Filesystem,
            "state-home-unavailable",
            "the separate local-state home is unavailable",
        )
    })?;
    let repositories = repository_refs(&home);
    let exclusions = detached_paths(&home);
    let state = VaultStateDirectory::open_or_create(
        &state_root,
        vault.header.vault_id.as_bytes(),
        vault.header.genesis_fingerprint.as_bytes(),
        &repositories,
        &exclusions,
    )
    .map_err(map_filesystem_error)?;
    let local = PrincipalLocalState::for_vault_principal(
        &owner,
        vault.header.vault_id,
        genesis_fingerprint.clone(),
    )
    .map_err(|_| local_state_error())?;
    let policy = replay_policy(&vault.policy).map_err(|_| invalid_vault())?;
    let candidate = CheckpointCandidate::from_validated(&policy, &vault.policy, &vault.items)
        .map_err(|_| invalid_vault())?;
    let initialized = local
        .initialize(&candidate, created_at_ms)
        .map_err(|_| local_state_error())?;
    let files = local
        .serialize(&initialized)
        .map_err(|_| local_state_error())?;
    let protected_audit = protect(files.audit(), protection)?;
    let protected_checkpoint = protect(files.checkpoint(), protection)?;
    let protected_receipts = protect(files.receipts(), protection)?;
    let locked = state.try_lock().map_err(|_| local_state_error())?;
    let prepared_audit = locked
        .prepare(
            owner.principal_id().as_bytes(),
            PrincipalStateFile::Audit,
            &protected_audit,
        )
        .map_err(map_filesystem_error)?;
    let prepared_checkpoint = locked
        .prepare(
            owner.principal_id().as_bytes(),
            PrincipalStateFile::Checkpoint,
            &protected_checkpoint,
        )
        .map_err(map_filesystem_error)?;
    let prepared_receipts = locked
        .prepare(
            owner.principal_id().as_bytes(),
            PrincipalStateFile::Receipts,
            &protected_receipts,
        )
        .map_err(map_filesystem_error)?;

    let shared_outcome = prepared_shared.publish().map_err(map_filesystem_error)?;
    let mut local_complete = true;
    for prepared in [prepared_audit, prepared_checkpoint, prepared_receipts] {
        match prepared.publish() {
            Ok(PublicationOutcome::PublishedAndSynced) => {}
            Ok(_) | Err(_) => local_complete = false,
        }
    }
    Ok(CommandOutput::VaultCreated {
        home_source: home_source(home.source()),
        vault_id: hex(vault.header.vault_id.as_bytes()),
        genesis_fingerprint: hex(vault.header.genesis_fingerprint.as_bytes()),
        owner_principal_id: hex(owner.principal_id().as_bytes()),
        local_state: if local_complete {
            "initialized"
        } else {
            "recovery-required"
        },
        durability: durability(shared_outcome),
    })
}

pub(super) fn vault_status(
    cli: &Cli,
    environment: &Environment,
    current: &Path,
    operation: &'static str,
) -> Result<CommandOutput, CliError> {
    let home = selected_home(cli, environment, current)?;
    let bytes = read_vault(&home)?;
    let vault = VaultFileV1::parse(&bytes).map_err(|_| invalid_vault())?;
    let catalog = load_policy_catalog_for_vault(environment, &home, &vault)?;
    let policy = replay_policy_with_witness_policies(&vault.policy, &catalog.witness_policies)
        .map_err(|_| invalid_vault())?;
    CheckpointCandidate::from_validated(&policy, &vault.policy, &vault.items)
        .map_err(|_| invalid_vault())?;
    let item_revision_proof_count = vault
        .items
        .iter()
        .map(|item| item.prior_revisions.len().saturating_add(1))
        .sum();
    Ok(CommandOutput::VaultStatus {
        operation,
        home_source: home_source(home.source()),
        format_version: vault.header.version,
        suite: vault.header.suite,
        vault_id: hex(vault.header.vault_id.as_bytes()),
        genesis_fingerprint: hex(vault.header.genesis_fingerprint.as_bytes()),
        policy_sequence: policy.sequence(),
        current_revision: hex(policy.terminal_revision_hash().as_bytes()),
        principal_count: policy.principal_count(),
        owner_count: policy.owner_count(),
        item_count: policy.item_count(),
        tombstone_count: policy.tombstone_count(),
        item_revision_proof_count,
        artifact_bytes: bytes.len(),
    })
}

pub(super) fn vault_audit_verify(
    cli: &Cli,
    environment: &Environment,
    current: &Path,
    protection: ProtectionPolicy,
) -> Result<CommandOutput, CliError> {
    let home = selected_home(cli, environment, current)?;
    let bytes = read_vault(&home)?;
    let vault = VaultFileV1::parse(&bytes).map_err(|_| invalid_vault())?;
    let catalog = load_policy_catalog_for_vault(environment, &home, &vault)?;
    let policy = replay_policy_with_witness_policies(&vault.policy, &catalog.witness_policies)
        .map_err(|_| invalid_vault())?;
    CheckpointCandidate::from_validated(&policy, &vault.policy, &vault.items)
        .map_err(|_| invalid_vault())?;

    let (selector, _) = selected_identity(cli, None, environment)?;
    validate_explicit_identity_separation(&selector, &home)?;
    let identity_root = identity_root(environment)?;
    validate_detached_separation(&identity_root, &home)?;
    let repositories = repository_refs(&home);
    let root = HardenedStateRoot::open_existing(&identity_root, &repositories)
        .map_err(map_filesystem_error)?;
    let identity_bytes = selector
        .read(&root, &repositories, MAX_IDENTITY_FILE_BYTES)
        .map_err(map_filesystem_error)?;
    let identity_file = IdentityFileV1::parse(&identity_bytes).map_err(|_| invalid_identity())?;
    let passphrase =
        secret_input::capture(protection, cli.passphrase_stdin, false).map_err(map_secret_error)?;
    let unlocked = unlock(&identity_file, passphrase.memory())
        .map_err(|error| map_identity_error(error.kind()))?;
    let local = match unlocked {
        UnlockedIdentity::VaultPrincipal(identity) => PrincipalLocalState::for_vault_principal(
            &identity,
            vault.header.vault_id,
            vault.header.genesis_fingerprint.clone(),
        ),
        UnlockedIdentity::Approver(identity) => PrincipalLocalState::for_approver(
            &identity,
            vault.header.vault_id,
            vault.header.genesis_fingerprint.clone(),
        ),
        UnlockedIdentity::Witness(identity) => PrincipalLocalState::for_witness(
            &identity,
            vault.header.vault_id,
            vault.header.genesis_fingerprint.clone(),
        ),
    }
    .map_err(|_| local_state_error())?;

    let state_root = resolve_linux_state_root(
        environment.jury_state_home.as_deref(),
        environment.xdg_state_home.as_deref(),
        environment.user_home.as_deref(),
    )
    .map_err(|_| filesystem_error())?;
    validate_detached_separation(&state_root, &home)?;
    let state = VaultStateDirectory::open_existing(
        &state_root,
        vault.header.vault_id.as_bytes(),
        vault.header.genesis_fingerprint.as_bytes(),
        &repositories,
    )
    .map_err(map_filesystem_error)?;
    let principal_id = local.scope().principal_id();
    let audit = state
        .read_principal_state(principal_id.as_bytes(), PrincipalStateFile::Audit)
        .map_err(map_filesystem_error)?;
    let checkpoint = state
        .read_principal_state(principal_id.as_bytes(), PrincipalStateFile::Checkpoint)
        .map_err(map_filesystem_error)?;
    let receipts = state
        .read_principal_state(principal_id.as_bytes(), PrincipalStateFile::Receipts)
        .map_err(map_filesystem_error)?;
    let verified = local
        .verify_files(Some(&audit), Some(&checkpoint), Some(&receipts))
        .map_err(|_| local_state_error())?;
    let audit = verified.audit();
    Ok(CommandOutput::AuditVerified {
        vault_id: hex(vault.header.vault_id.as_bytes()),
        principal_id: hex(principal_id.as_bytes()),
        event_count: audit.event_count,
        latest_mac: hex(audit.latest_mac.as_bytes()),
        audit_events_after_checkpoint: verified.audit_events_after_checkpoint(),
    })
}
