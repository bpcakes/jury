use super::*;

struct LocalTransferState {
    vault: VaultFileV1,
    policy: PolicyState,
}

pub(super) fn transfer_export(
    cli: &Cli,
    arguments: &TransferExportArgs,
    environment: &Environment,
    current: &Path,
    protection: ProtectionPolicy,
) -> Result<CommandOutput, CliError> {
    let home = selected_home(cli, environment, current)?;
    reject_transfer_home_alias(&home, &arguments.out)?;
    let destination = preview_public_file(&arguments.out).map_err(map_filesystem_error)?;
    if destination.destination_exists() && !arguments.overwrite {
        return Err(CliError::new(
            CliErrorKind::Conflict,
            "already-exists",
            "the selected destination already exists",
        ));
    }

    let context = load_vault_principal(cli, environment, current, protection)?;
    let catalog = transfer_catalog(&context.catalog)?;
    let envelope = TransferCreator::new()
        .create(&context.vault, catalog, &context.identity, timestamp_ms()?)
        .map_err(map_transfer_error)?;
    let bytes = envelope.to_json_bytes().map_err(|_| invalid_transfer())?;
    let output_digest = sha256_digest(&bytes);
    let protected = protect(&bytes, protection)?;
    let publication =
        PreparedPrivateFile::prepare_if_unchanged(destination, &protected, arguments.overwrite)
            .map_err(map_filesystem_error)?
            .publish()
            .map_err(map_filesystem_error)?;
    record_transfer_receipt(
        &context,
        TransferReceipt {
            transfer_id: envelope.transfer_id.clone(),
            captured_public_revision_hash: envelope.source_public_revision_hash.clone(),
            timestamp_ms: envelope.created_at_ms,
            output_digest,
        },
        protection,
    )?;
    Ok(CommandOutput::Safe {
        operation: "transfer-export",
        fields: serde_json::json!({
            "transfer_id": hex(envelope.transfer_id.as_bytes()),
            "vault_id": hex(envelope.source_vault_id.as_bytes()),
            "genesis_fingerprint": hex(envelope.source_genesis_fingerprint.as_bytes()),
            "public_revision": hex(envelope.source_public_revision_hash.as_bytes()),
            "exporting_principal_id": hex(envelope.exporting_principal_id.as_bytes()),
            "artifact_bytes": bytes.len(),
            "durability": durability(publication),
            "local_export_receipt_recorded": true,
            "delivery_claimed": false,
        }),
        lines: vec![
            format!(
                "Transfer exported: {}",
                hex(envelope.transfer_id.as_bytes())
            ),
            format!(
                "Public revision: {}",
                grouped(&hex(envelope.source_public_revision_hash.as_bytes()))
            ),
            format!("Durability: {}", durability(publication)),
            "This records a local export only; delivery to another recipient is not claimed."
                .to_owned(),
        ],
    })
}

pub(super) fn transfer_inspect(
    cli: &Cli,
    arguments: &TransferInspectArgs,
    environment: &Environment,
    current: &Path,
    protection: ProtectionPolicy,
) -> Result<CommandOutput, CliError> {
    let bytes =
        read_public_file(&arguments.input, MAX_TRANSFER_BYTES).map_err(map_filesystem_error)?;
    let transfer = ValidatedTransfer::parse(&bytes).map_err(map_transfer_error)?;
    let home = selected_home(cli, environment, current)?;
    let local = if arguments.against_current {
        let local_bytes = read_vault(&home)?;
        let local = VaultFileV1::parse(&local_bytes).map_err(|_| invalid_vault())?;
        let catalog = load_policy_catalog_for_vault(environment, &home, &local)?;
        let policy = replay_policy_with_witness_policies(&local.policy, &catalog.witness_policies)
            .map_err(|_| invalid_vault())?;
        CheckpointCandidate::from_validated(&policy, &local.policy, &local.items)
            .map_err(|_| invalid_vault())?;
        Some(local)
    } else {
        None
    };
    let relation = local
        .as_ref()
        .map(|local| compare_artifacts(local, transfer.vault()));
    let deltas = local.as_ref().map_or_else(
        || {
            transfer
                .vault()
                .items
                .iter()
                .map(|item| jury_core::transfer::TransferItemDelta {
                    item_id: item.item_id,
                    local_revision: None,
                    incoming_revision: Some(item.current_revision.item_revision),
                })
                .collect()
        },
        |local| item_deltas(local, transfer.vault()),
    );

    let names = if arguments.me {
        let unlocked = unlock_selected_identity(cli, environment, current, protection)?;
        let UnlockedIdentity::VaultPrincipal(identity) = unlocked.identity else {
            return Err(CliError::new(
                CliErrorKind::InvalidIdentity,
                "vault-principal-required",
                "transfer name inspection requires a vault-principal identity",
            ));
        };
        let mut names = accessible_name_map(transfer.vault(), transfer.policy(), &identity)?;
        if let Some(local) = &local {
            let catalog = load_policy_catalog_for_vault(environment, &home, local)?;
            let policy =
                replay_policy_with_witness_policies(&local.policy, &catalog.witness_policies)
                    .map_err(|_| invalid_vault())?;
            names.extend(accessible_name_map(local, &policy, &identity)?);
        }
        names
    } else {
        BTreeMap::new()
    };
    let delta_json = deltas
        .iter()
        .map(|delta| {
            serde_json::json!({
                "item_id": hex(delta.item_id.as_bytes()),
                "local_revision": delta.local_revision,
                "incoming_revision": delta.incoming_revision,
                "item": names.get(&delta.item_id),
            })
        })
        .collect::<Vec<_>>();
    let relation_name = relation.map_or("not-compared", relation_label);
    let mut lines = vec![
        format!(
            "Transfer: {}",
            hex(transfer.envelope().transfer_id.as_bytes())
        ),
        format!(
            "Vault ID: {}",
            hex(transfer.vault().header.vault_id.as_bytes())
        ),
        format!("Ancestry: {relation_name}"),
        format!("Opaque item deltas: {}", delta_json.len()),
    ];
    for delta in &deltas {
        let label = names
            .get(&delta.item_id)
            .cloned()
            .unwrap_or_else(|| hex(delta.item_id.as_bytes()));
        lines.push(format!(
            "{label}: {:?} -> {:?}",
            delta.local_revision, delta.incoming_revision
        ));
    }
    if !arguments.me {
        lines.push("Item names remain concealed; no identity was unlocked.".to_owned());
    }
    Ok(CommandOutput::Safe {
        operation: "transfer-inspect",
        fields: serde_json::json!({
            "transfer_id": hex(transfer.envelope().transfer_id.as_bytes()),
            "vault_id": hex(transfer.vault().header.vault_id.as_bytes()),
            "genesis_fingerprint": hex(transfer.vault().header.genesis_fingerprint.as_bytes()),
            "exporting_principal_id": hex(transfer.envelope().exporting_principal_id.as_bytes()),
            "public_revision": hex(transfer.envelope().source_public_revision_hash.as_bytes()),
            "policy_sequence": transfer.policy().sequence(),
            "item_count": transfer.policy().item_count(),
            "relation": relation_name,
            "deltas": delta_json,
            "identity_unlocked": arguments.me,
            "inaccessible_names_disclosed": false,
            "mutated": false,
        }),
        lines,
    })
}

pub(super) fn transfer_import(
    cli: &Cli,
    arguments: &TransferImportArgs,
    environment: &Environment,
    current: &Path,
    protection: ProtectionPolicy,
) -> Result<CommandOutput, CliError> {
    let bytes =
        read_public_file(&arguments.input, MAX_TRANSFER_BYTES).map_err(map_filesystem_error)?;
    let transfer = ValidatedTransfer::parse(&bytes).map_err(map_transfer_error)?;
    let home = selected_home(cli, environment, current)?;
    match read_vault(&home) {
        Ok(local_bytes) => {
            let local = VaultFileV1::parse(&local_bytes).map_err(|_| invalid_vault())?;
            let local_catalog = load_policy_catalog_for_vault(environment, &home, &local)?;
            let local_policy =
                replay_policy_with_witness_policies(&local.policy, &local_catalog.witness_policies)
                    .map_err(|_| invalid_vault())?;
            CheckpointCandidate::from_validated(&local_policy, &local.policy, &local.items)
                .map_err(|_| invalid_vault())?;
            VaultMutationPlan::preflight_transfer_import(
                &local,
                transfer.vault(),
                &transfer.catalog().witness_policies,
            )
            .map_err(map_transfer_import_error)?;
            import_existing(
                cli,
                arguments,
                environment,
                current,
                protection,
                transfer,
                LocalTransferState {
                    vault: local,
                    policy: local_policy,
                },
            )
        }
        Err(error) if error.kind() == CliErrorKind::NotFound => {
            import_absent(cli, arguments, environment, current, protection, transfer)
        }
        Err(error) => Err(error),
    }
}

pub(super) fn transfer_status(
    cli: &Cli,
    environment: &Environment,
    current: &Path,
    protection: ProtectionPolicy,
) -> Result<CommandOutput, CliError> {
    let context = load_vault_principal(cli, environment, current, protection)?;
    let receipt = latest_transfer_receipt(&context)?;
    let current_revision = context.policy.terminal_revision_hash();
    let status = match &receipt {
        None => "never-exported",
        Some(receipt) if &receipt.captured_public_revision_hash == current_revision => {
            "matches-last-local-export"
        }
        Some(_) => "changed-since-last-local-export",
    };
    Ok(CommandOutput::Safe {
        operation: "transfer-status",
        fields: serde_json::json!({
            "status": status,
            "current_public_revision": hex(current_revision.as_bytes()),
            "last_transfer_id": receipt.as_ref().map(|receipt| hex(receipt.transfer_id.as_bytes())),
            "last_exported_public_revision": receipt.as_ref().map(|receipt| hex(receipt.captured_public_revision_hash.as_bytes())),
            "last_exported_at_ms": receipt.as_ref().map(|receipt| receipt.timestamp_ms),
            "local_export_only": true,
            "delivery_claimed": false,
        }),
        lines: vec![
            format!("Transfer status: {}", status.replace('-', " ")),
            "This is local export freshness only; distribution or synchronization is not claimed."
                .to_owned(),
        ],
    })
}

fn import_existing(
    cli: &Cli,
    arguments: &TransferImportArgs,
    environment: &Environment,
    current: &Path,
    protection: ProtectionPolicy,
    transfer: ValidatedTransfer,
    local: LocalTransferState,
) -> Result<CommandOutput, CliError> {
    if arguments.dry_run {
        return preview_existing_import_read_only(
            cli,
            environment,
            current,
            protection,
            &transfer,
            &local.vault,
            &local.policy,
        );
    }
    let mut context = load_vault_principal(cli, environment, current, protection)?;
    if transfer
        .policy()
        .principal(&context.identity.principal_id())
        .is_none()
    {
        return Err(identity_not_registered());
    }
    let mut plan = VaultMutationPlan::prepare_transfer_import(
        &context.vault,
        transfer.vault(),
        &transfer.catalog().witness_policies,
        context.identity.principal_id(),
        timestamp_ms()?,
    )
    .map_err(map_transfer_import_error)?;
    let Some(mut plan) = plan.take() else {
        return transfer_import_output(&context.policy, transfer.policy(), true, false, false);
    };
    context.catalog = PolicyCatalogV1 {
        version: transfer.catalog().version,
        role_descriptors: transfer.catalog().role_descriptors.clone(),
        witness_policies: transfer.catalog().witness_policies.clone(),
    };
    context.catalog.to_json_bytes()?;
    if let Some(repository) = context.home.repository() {
        plan = plan.bind_repository_ancestry(
            repository
                .git_ancestry_digest()
                .map_err(map_filesystem_error)?,
        );
    }
    let outcome = commit_mutation(&context, &plan, protection)?;
    Ok(mutation_output(
        "transfer-import",
        None,
        &context,
        &plan,
        false,
        Some(&outcome),
    ))
}

fn preview_existing_import_read_only(
    cli: &Cli,
    environment: &Environment,
    current: &Path,
    protection: ProtectionPolicy,
    transfer: &ValidatedTransfer,
    local_vault: &VaultFileV1,
    local_policy: &PolicyState,
) -> Result<CommandOutput, CliError> {
    let unlocked = unlock_selected_identity(cli, environment, current, protection)?;
    let UnlockedIdentity::VaultPrincipal(identity) = unlocked.identity else {
        return Err(CliError::new(
            CliErrorKind::InvalidIdentity,
            "vault-principal-required",
            "transfer import requires a vault-principal identity",
        ));
    };
    if local_policy.principal(&identity.principal_id()).is_none()
        || transfer
            .policy()
            .principal(&identity.principal_id())
            .is_none()
    {
        return Err(identity_not_registered());
    }
    let state_root = resolve_linux_state_root(
        environment.jury_state_home.as_deref(),
        environment.xdg_state_home.as_deref(),
        environment.user_home.as_deref(),
    )
    .map_err(|_| filesystem_error())?;
    validate_detached_separation(&state_root, &unlocked.home)?;
    let repositories = repository_refs(&unlocked.home);
    match probe_principal_state(
        &state_root,
        local_vault,
        &identity.principal_id(),
        &repositories,
    )? {
        PrincipalStateProbe::Absent => confirm_expected_genesis(cli, local_vault)?,
        PrincipalStateProbe::Existing {
            audit,
            checkpoint,
            receipts,
            ..
        } => {
            let local = PrincipalLocalState::for_vault_principal(
                &identity,
                local_vault.header.vault_id,
                local_vault.header.genesis_fingerprint.clone(),
            )
            .map_err(|_| local_state_error())?;
            let verified = local
                .verify_files(Some(&audit), Some(&checkpoint), Some(&receipts))
                .map_err(|_| local_state_error())?;
            let candidate = CheckpointCandidate::from_validated(
                local_policy,
                &local_vault.policy,
                &local_vault.items,
            )
            .map_err(|_| invalid_vault())?;
            if candidate
                .relation_to(verified.checkpoint())
                .map_err(|_| checkpoint_conflict())?
                == CheckpointRelation::Divergent
            {
                return Err(checkpoint_conflict());
            }
        }
    }
    transfer_import_output(
        local_policy,
        transfer.policy(),
        local_vault == transfer.vault(),
        true,
        false,
    )
}

fn import_absent(
    cli: &Cli,
    arguments: &TransferImportArgs,
    environment: &Environment,
    current: &Path,
    protection: ProtectionPolicy,
    transfer: ValidatedTransfer,
) -> Result<CommandOutput, CliError> {
    confirm_expected_genesis(cli, transfer.vault())?;
    let unlocked = unlock_selected_identity(cli, environment, current, protection)?;
    let UnlockedIdentity::VaultPrincipal(identity) = unlocked.identity else {
        return Err(CliError::new(
            CliErrorKind::InvalidIdentity,
            "vault-principal-required",
            "transfer import requires a vault-principal identity",
        ));
    };
    if transfer
        .policy()
        .principal(&identity.principal_id())
        .is_none()
    {
        return Err(identity_not_registered());
    }
    let names = accessible_name_map(transfer.vault(), transfer.policy(), &identity)?;
    if names.is_empty() && !arguments.allow_no_access {
        return Err(CliError::new(
            CliErrorKind::AccessDenied,
            "transfer-no-access",
            "first transfer import requires one directly accessible descriptor or --allow-no-access",
        ));
    }
    let local = PrincipalLocalState::for_vault_principal(
        &identity,
        transfer.vault().header.vault_id,
        transfer.vault().header.genesis_fingerprint.clone(),
    )
    .map_err(|_| local_state_error())?;
    let candidate = CheckpointCandidate::from_validated(
        transfer.policy(),
        &transfer.vault().policy,
        &transfer.vault().items,
    )
    .map_err(|_| invalid_vault())?;
    let state_root = resolve_linux_state_root(
        environment.jury_state_home.as_deref(),
        environment.xdg_state_home.as_deref(),
        environment.user_home.as_deref(),
    )
    .map_err(|_| filesystem_error())?;
    validate_detached_separation(&state_root, &unlocked.home)?;
    let retained_state = {
        let repositories = repository_refs(&unlocked.home);
        match probe_principal_state(
            &state_root,
            transfer.vault(),
            &identity.principal_id(),
            &repositories,
        )? {
            PrincipalStateProbe::Absent => None,
            PrincipalStateProbe::Existing {
                state,
                audit,
                checkpoint,
                receipts,
            } => {
                let verified = local
                    .verify_files(Some(&audit), Some(&checkpoint), Some(&receipts))
                    .map_err(|_| local_state_error())?;
                if candidate
                    .relation_to(verified.checkpoint())
                    .map_err(|_| checkpoint_conflict())?
                    == CheckpointRelation::Divergent
                {
                    return Err(checkpoint_conflict());
                }
                Some(state)
            }
        }
    };
    if arguments.dry_run {
        return absent_import_output(&transfer, &names, true, false, "not-written");
    }

    let mut home = unlocked.home;
    let vault_bytes = transfer
        .vault()
        .to_json_bytes()
        .map_err(|_| invalid_vault())?;
    let protected = protect(&vault_bytes, protection)?;
    let shared_publication = prepare_new_vault(&mut home, &protected)?
        .publish()
        .map_err(map_filesystem_error)?;

    let repositories = repository_refs(&home);
    let (catalog_state, retained) = match retained_state {
        Some(state) => (state, true),
        None => (
            VaultStateDirectory::open_or_create(
                &state_root,
                transfer.vault().header.vault_id.as_bytes(),
                transfer.vault().header.genesis_fingerprint.as_bytes(),
                &repositories,
                &detached_paths(&home),
            )
            .map_err(map_filesystem_error)?,
            false,
        ),
    };
    let catalog = PolicyCatalogV1 {
        version: transfer.catalog().version,
        role_descriptors: transfer.catalog().role_descriptors.clone(),
        witness_policies: transfer.catalog().witness_policies.clone(),
    };
    let catalog_bytes = catalog.to_json_bytes()?;
    {
        let locked = catalog_state.try_lock().map_err(|_| local_state_error())?;
        let protected_catalog = protect(&catalog_bytes, protection)?;
        let publication = locked
            .prepare_vault_state(VaultStateFile::PolicyCatalog, &protected_catalog)
            .map_err(map_filesystem_error)?
            .publish()
            .map_err(map_filesystem_error)?;
        if publication != PublicationOutcome::PublishedAndSynced {
            return Err(local_state_error());
        }
    }
    let state = if retained {
        advance_principal_checkpoint(
            &catalog_state,
            &local,
            &candidate,
            &identity.principal_id(),
            timestamp_ms()?,
            protection,
        )?;
        catalog_state
    } else {
        initialize_principal_state(PrincipalStateInitialization {
            state_root: &state_root,
            home: &home,
            vault: transfer.vault(),
            local: &local,
            candidate: &candidate,
            principal_id: &identity.principal_id(),
            timestamp: timestamp_ms()?,
            protection,
        })?
    };
    let context = VaultPrincipalContext {
        home,
        vault: transfer.vault().clone(),
        policy: replay_policy_with_witness_policies(
            &transfer.vault().policy,
            &catalog.witness_policies,
        )
        .map_err(|_| invalid_vault())?,
        catalog_before: catalog.clone(),
        catalog_before_bytes: Some(catalog_bytes),
        catalog,
        identity,
        state,
        local,
        protection_degraded: unlocked.protection_degraded,
    };
    append_operational_audit_outcome(
        &context,
        AuditAction::Transfer,
        &[],
        transfer.envelope().transfer_id.clone(),
        AuditOutcome::Success,
        protection,
    )?;
    absent_import_output(
        &transfer,
        &names,
        false,
        true,
        durability(shared_publication),
    )
}

fn transfer_catalog(catalog: &PolicyCatalogV1) -> Result<TransferPublicCatalogV1, CliError> {
    TransferPublicCatalogV1::new(
        catalog.role_descriptors.clone(),
        catalog.witness_policies.clone(),
    )
    .map_err(map_transfer_error)
}

fn accessible_name_map(
    vault: &VaultFileV1,
    policy: &PolicyState,
    identity: &VaultPrincipalIdentity,
) -> Result<BTreeMap<jury_protocol::vault_v1::ItemId, String>, CliError> {
    Ok(discover_accessible_items_in(vault, policy, identity)?
        .into_iter()
        .map(|item| {
            (
                vault.items[item.envelope_index].item_id,
                item.descriptor.name().to_owned(),
            )
        })
        .collect())
}

fn record_transfer_receipt(
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

fn latest_transfer_receipt(
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

fn transfer_import_output(
    current: &PolicyState,
    target: &PolicyState,
    identical: bool,
    dry_run: bool,
    committed: bool,
) -> Result<CommandOutput, CliError> {
    Ok(CommandOutput::Safe {
        operation: "transfer-import",
        fields: serde_json::json!({
            "result": if identical { "identical" } else { "incoming-strict-descendant" },
            "previous_revision": hex(current.terminal_revision_hash().as_bytes()),
            "current_revision": hex(target.terminal_revision_hash().as_bytes()),
            "dry_run": dry_run,
            "vault_changed": committed,
            "committed": committed,
            "candidate_synthesized": false,
            "delivery_claimed": false,
        }),
        lines: vec![
            format!(
                "Import result: {}",
                if identical {
                    "identical no-op"
                } else {
                    "incoming strict descendant"
                }
            ),
            format!("Dry run: {dry_run}"),
            format!("Local vault changed: {committed}"),
            "No merged artifact was synthesized.".to_owned(),
        ],
    })
}

fn absent_import_output(
    transfer: &ValidatedTransfer,
    names: &BTreeMap<jury_protocol::vault_v1::ItemId, String>,
    dry_run: bool,
    committed: bool,
    durability: &str,
) -> Result<CommandOutput, CliError> {
    Ok(CommandOutput::Safe {
        operation: "transfer-import",
        fields: serde_json::json!({
            "result": "first-install",
            "transfer_id": hex(transfer.envelope().transfer_id.as_bytes()),
            "vault_id": hex(transfer.vault().header.vault_id.as_bytes()),
            "genesis_fingerprint": hex(transfer.vault().header.genesis_fingerprint.as_bytes()),
            "accessible_items": names.iter().map(|(item_id, name)| serde_json::json!({
                "item_id": hex(item_id.as_bytes()),
                "item": name,
            })).collect::<Vec<_>>(),
            "dry_run": dry_run,
            "vault_changed": committed,
            "committed": committed,
            "durability": durability,
            "identity_imported": false,
            "inaccessible_names_disclosed": false,
            "delivery_claimed": false,
        }),
        lines: vec![
            format!(
                "Transfer first install: {}",
                if committed { "committed" } else { "preview" }
            ),
            format!("Accessible item names: {}", names.len()),
            format!("Durability: {durability}"),
            "No private identity was imported from the transfer.".to_owned(),
        ],
    })
}

fn reject_transfer_home_alias(home: &VaultHomeLocation, path: &Path) -> Result<(), CliError> {
    let aliases = match home {
        VaultHomeLocation::Repository { repository } => {
            repository.is_encrypted_shared_artifact_path(path)
        }
        VaultHomeLocation::Detached { path: home, .. } => path == home.join("vault.json"),
    };
    if aliases {
        Err(containment_error())
    } else {
        Ok(())
    }
}

fn relation_label(relation: ArtifactRelation) -> &'static str {
    match relation {
        ArtifactRelation::Identical => "identical",
        ArtifactRelation::IncomingStrictDescendant => "incoming-strict-descendant",
        ArtifactRelation::LocalStrictDescendant => "rejected-behind",
        ArtifactRelation::Divergent => "rejected-divergent",
    }
}

fn map_transfer_error(error: jury_core::transfer::TransferError) -> CliError {
    use jury_core::transfer::TransferErrorKind;
    match error.kind() {
        TransferErrorKind::UnauthorizedExporter => CliError::new(
            CliErrorKind::AuthenticationFailed,
            "unauthorized-transfer-exporter",
            "the transfer exporter is not an active vault principal",
        ),
        TransferErrorKind::EntropyUnavailable | TransferErrorKind::ProtectionUnavailable => {
            CliError::new(
                CliErrorKind::ProtectionUnavailable,
                "protection-unavailable",
                "required transfer protection is unavailable",
            )
        }
        _ => invalid_transfer(),
    }
}

fn map_transfer_import_error(error: jury_core::mutation::MutationError) -> CliError {
    use jury_core::mutation::MutationErrorKind;
    match error.kind() {
        MutationErrorKind::TransferBehind => CliError::new(
            CliErrorKind::Conflict,
            "transfer-behind",
            "the incoming transfer is behind retained local state",
        ),
        MutationErrorKind::TransferDiverged => CliError::new(
            CliErrorKind::Conflict,
            "transfer-diverged",
            "the incoming transfer diverges from retained local state",
        ),
        MutationErrorKind::TransferDowngrade => CliError::new(
            CliErrorKind::Conflict,
            "transfer-authority-downgrade",
            "the incoming transfer weakens direct or witnessed authority",
        ),
        MutationErrorKind::Unauthorized => identity_not_registered(),
        kind => map_mutation_error(kind),
    }
}

const fn invalid_transfer() -> CliError {
    CliError::new(
        CliErrorKind::InvalidVault,
        "invalid-transfer",
        "the selected transfer is malformed or failed authentication",
    )
}

const fn identity_not_registered() -> CliError {
    CliError::new(
        CliErrorKind::AuthenticationFailed,
        "identity-not-registered",
        "the selected identity is not active in the incoming vault",
    )
}

fn sha256_digest(bytes: &[u8]) -> Digest32 {
    Digest32::new(Sha256::digest(bytes).into())
}
