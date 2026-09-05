use super::*;

pub(super) fn prepare_rekey(
    context: &VaultPrincipalContext,
    accessible: &AccessibleItem,
    mut creator: ItemCreator,
    state: ItemStateV1,
    bucket_id: u8,
    timestamp: u64,
) -> Result<jury_core::item::PreparedItemMutation, CliError> {
    let envelope = &context.vault.items[accessible.envelope_index];
    let inventory = ItemArtifactInventory::from_vault(&context.vault)
        .map_err(|error| map_item_error(error.kind()))?;
    creator
        .prepare_rekey(
            &context.policy,
            &context.identity,
            timestamp,
            envelope,
            RekeyedItem {
                descriptor: accessible.descriptor.clone(),
                state,
                bucket_id,
                access: retained_access_plan(&context.policy, envelope)?,
                principal_replacement: None,
                principal_registration: None,
                owner_change: None,
            },
            &inventory,
        )
        .map_err(|error| map_item_error(error.kind()))
}

pub(super) fn retained_access_plan(
    policy: &PolicyState,
    envelope: &ItemEnvelopeV1,
) -> Result<ItemAccessPlan, CliError> {
    let item = policy.item(&envelope.item_id).ok_or_else(invalid_vault)?;
    let grants = item
        .grants
        .iter()
        .map(|(principal_id, role)| ItemGrant {
            principal_id: *principal_id,
            role: *role,
        })
        .collect();
    let mut direct_recipient_ids = item
        .direct_slots
        .iter()
        .map(|slot| slot.recipient_principal_id)
        .collect::<Vec<_>>();
    direct_recipient_ids.sort_unstable();
    direct_recipient_ids.dedup();
    let witness_policy_digest = item
        .witnessed_state
        .as_ref()
        .and_then(|state| state.slots.first())
        .map(|slot| slot.witness_policy_digest.clone());
    Ok(ItemAccessPlan {
        grants,
        direct_recipient_ids,
        witness_policy_digest,
    })
}

pub(super) fn current_bucket(context: &VaultPrincipalContext, accessible: &AccessibleItem) -> u8 {
    context.vault.items[accessible.envelope_index]
        .current_revision
        .bucket_id
}

pub(super) fn smallest_bucket(state: &ItemStateV1, minimum: u8) -> Result<u8, CliError> {
    for bucket_id in minimum..=12 {
        if let Ok(mut framed) = state.frame(bucket_id) {
            framed.zeroize();
            return Ok(bucket_id);
        }
    }
    Err(CliError::new(
        CliErrorKind::Conflict,
        "item-capacity-exhausted",
        "the item body exceeds the largest active storage bucket",
    ))
}

pub(super) struct MutationFinishOptions {
    pub(super) operation: &'static str,
    pub(super) dry_run: bool,
    pub(super) acknowledgement: DirectDowngradeAcknowledgement,
    pub(super) kind: MutationKind,
    pub(super) protection: ProtectionPolicy,
}

pub(super) fn finish_item_mutation(
    context: VaultPrincipalContext,
    prepared: jury_core::item::PreparedItemMutation,
    operation: &'static str,
    item: String,
    dry_run: bool,
    kind: MutationKind,
    protection: ProtectionPolicy,
) -> Result<CommandOutput, CliError> {
    finish_item_mutation_with_ack(
        context,
        prepared,
        item,
        MutationFinishOptions {
            operation,
            dry_run,
            acknowledgement: DirectDowngradeAcknowledgement::Absent,
            kind,
            protection,
        },
    )
}

pub(super) fn finish_item_mutation_with_ack(
    context: VaultPrincipalContext,
    prepared: jury_core::item::PreparedItemMutation,
    item: String,
    options: MutationFinishOptions,
) -> Result<CommandOutput, CliError> {
    let timestamp = prepared.policy.revision.timestamp_ms;
    let plan = VaultMutationPlan::prepare_item_batch(
        &context.vault,
        &context.catalog.witness_policies,
        &context.identity,
        timestamp,
        Vec::new(),
        vec![prepared],
        options.acknowledgement,
        options.kind,
    )
    .map_err(|error| map_mutation_error(error.kind()))?;
    finish_mutation_plan(
        context,
        plan,
        options.operation,
        Some(item),
        options.dry_run,
        options.protection,
    )
}

pub(super) fn finish_item_batch_mutation(
    context: VaultPrincipalContext,
    prepared: Vec<jury_core::item::PreparedItemMutation>,
    additional_operations: Vec<PolicyOperationV1>,
    options: MutationFinishOptions,
) -> Result<CommandOutput, CliError> {
    let timestamp = prepared
        .first()
        .ok_or_else(invalid_vault)?
        .policy
        .revision
        .timestamp_ms;
    let plan = VaultMutationPlan::prepare_item_batch(
        &context.vault,
        &context.catalog.witness_policies,
        &context.identity,
        timestamp,
        additional_operations,
        prepared,
        options.acknowledgement,
        options.kind,
    )
    .map_err(|error| map_mutation_error(error.kind()))?;
    finish_mutation_plan(
        context,
        plan,
        options.operation,
        None,
        options.dry_run,
        options.protection,
    )
}

pub(super) fn finish_item_component_batch_mutation(
    context: VaultPrincipalContext,
    components: Vec<jury_core::item::PreparedItemBatchComponent>,
    additional_operations: Vec<PolicyOperationV1>,
    timestamp: u64,
    options: MutationFinishOptions,
) -> Result<CommandOutput, CliError> {
    let plan = VaultMutationPlan::prepare_item_component_batch(
        &context.vault,
        &context.catalog.witness_policies,
        &context.identity,
        timestamp,
        additional_operations,
        components,
        options.acknowledgement,
        options.kind,
    )
    .map_err(|error| map_mutation_error(error.kind()))?;
    finish_mutation_plan(
        context,
        plan,
        options.operation,
        None,
        options.dry_run,
        options.protection,
    )
}

pub(super) fn finish_policy_mutation(
    context: VaultPrincipalContext,
    operations: Vec<PolicyOperationV1>,
    timestamp: u64,
    operation: &'static str,
    dry_run: bool,
    protection: ProtectionPolicy,
) -> Result<CommandOutput, CliError> {
    let plan = VaultMutationPlan::prepare_policy(
        &context.vault,
        &context.catalog.witness_policies,
        &context.identity,
        timestamp,
        operations,
        DirectDowngradeAcknowledgement::Absent,
        MutationKind::Policy,
    )
    .map_err(|error| map_mutation_error(error.kind()))?;
    finish_mutation_plan(context, plan, operation, None, dry_run, protection)
}

pub(super) fn finish_mutation_plan(
    context: VaultPrincipalContext,
    mut plan: VaultMutationPlan,
    operation: &'static str,
    item: Option<String>,
    dry_run: bool,
    protection: ProtectionPolicy,
) -> Result<CommandOutput, CliError> {
    if let Some(repository) = context.home.repository() {
        plan = plan.bind_repository_ancestry(
            repository
                .git_ancestry_digest()
                .map_err(map_filesystem_error)?,
        );
    }
    if dry_run {
        return Ok(mutation_output(
            operation, item, &context, &plan, true, None,
        ));
    }
    let outcome = commit_mutation(&context, &plan, protection)?;
    Ok(mutation_output(
        operation,
        item,
        &context,
        &plan,
        false,
        Some(&outcome),
    ))
}

pub(super) fn commit_mutation(
    context: &VaultPrincipalContext,
    plan: &VaultMutationPlan,
    protection: ProtectionPolicy,
) -> Result<MutationCommitOutcome, CliError> {
    let catalog_before = policy_catalog_json_bytes(&context.catalog_before)?;
    let catalog_target = policy_catalog_json_bytes(&context.catalog)?;
    let catalog_update = (catalog_before != catalog_target).then(|| {
        MutationCatalogUpdate::new(
            context.catalog_before_bytes.as_deref(),
            &catalog_before,
            &catalog_target,
        )
    });
    let result = match &context.home {
        VaultHomeLocation::Repository { repository } => {
            let target = RepositoryMutationTarget::new(
                repository,
                &context.state,
                &context.local,
                protection,
            );
            if let Some(update) = catalog_update {
                target.commit_with_catalog(plan, update)
            } else {
                target.commit(plan)
            }
        }
        VaultHomeLocation::Detached { path, .. } => {
            let home = HardenedStateRoot::open_existing(path, &[]).map_err(map_filesystem_error)?;
            let target =
                DetachedMutationTarget::new(&home, &context.state, &context.local, protection);
            if let Some(update) = catalog_update {
                target.commit_with_catalog(plan, update)
            } else {
                target.commit(plan)
            }
        }
    };
    result.map_err(|error| map_mutation_commit_error(error.kind()))
}

pub(super) fn append_operational_audit(
    context: &VaultPrincipalContext,
    action: AuditAction,
    item_ids: &[jury_protocol::vault_v1::ItemId],
    protection: ProtectionPolicy,
) -> Result<(), CliError> {
    let operation_id = random_operation_id()?;
    append_operational_audit_outcome(
        context,
        action,
        item_ids,
        operation_id,
        AuditOutcome::Success,
        protection,
    )
}

pub(super) fn append_operational_audit_outcome(
    context: &VaultPrincipalContext,
    action: AuditAction,
    item_ids: &[jury_protocol::vault_v1::ItemId],
    operation_id: Digest32,
    outcome: AuditOutcome,
    protection: ProtectionPolicy,
) -> Result<(), CliError> {
    let timestamp = timestamp_ms()?;
    let item = (item_ids.len() == 1).then(|| AuditItemScope {
        item_id: item_ids[0],
        permitted_item_name: None,
    });
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
        .append_event(
            &mut verified,
            AuditEventDraft {
                timestamp_ms: timestamp,
                operation_id,
                policy_sequence: context.policy.sequence(),
                action,
                outcome,
                item,
                witness: None,
            },
        )
        .map_err(|_| local_state_error())?;
    let files = context
        .local
        .serialize(&verified)
        .map_err(|_| local_state_error())?;
    let protected_audit = protect(files.audit(), protection)?;
    let protected_checkpoint = protect(files.checkpoint(), protection)?;
    let prepared_audit = locked
        .prepare(
            principal_id.as_bytes(),
            PrincipalStateFile::Audit,
            &protected_audit,
        )
        .map_err(map_filesystem_error)?;
    let prepared_checkpoint = locked
        .prepare(
            principal_id.as_bytes(),
            PrincipalStateFile::Checkpoint,
            &protected_checkpoint,
        )
        .map_err(map_filesystem_error)?;
    if prepared_audit.publish().map_err(map_filesystem_error)?
        != PublicationOutcome::PublishedAndSynced
    {
        return Err(local_state_error());
    }
    if prepared_checkpoint
        .publish()
        .map_err(map_filesystem_error)?
        != PublicationOutcome::PublishedAndSynced
    {
        return Err(local_state_error());
    }
    Ok(())
}

pub(super) fn random_operation_id() -> Result<Digest32, CliError> {
    let mut source = OsRandom;
    for _ in 0..8 {
        let mut bytes = [0_u8; 32];
        source.fill(&mut bytes).map_err(|_| {
            CliError::new(
                CliErrorKind::ProtectionUnavailable,
                "entropy-unavailable",
                "operating-system entropy is unavailable",
            )
        })?;
        if bytes.iter().any(|byte| *byte != 0) {
            return Ok(Digest32::new(bytes));
        }
    }
    Err(CliError::new(
        CliErrorKind::ProtectionUnavailable,
        "entropy-unavailable",
        "operating-system entropy is unavailable",
    ))
}

pub(super) fn validate_plaintext_sink(
    cli: &Cli,
    out: Option<&Path>,
    reveal: bool,
) -> Result<(), CliError> {
    if out.is_some() == reveal || (reveal && cli.json) {
        return Err(CliError::new(
            CliErrorKind::InvalidArguments,
            "private-output-selection-required",
            "select exactly one private file sink or explicit non-JSON reveal",
        ));
    }
    Ok(())
}

pub(super) fn write_private_file(
    home: &VaultHomeLocation,
    path: &Path,
    bytes: &[u8],
    overwrite: bool,
    protection: ProtectionPolicy,
) -> Result<PublicationOutcome, CliError> {
    if !path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )
        })
    {
        return Err(CliError::new(
            CliErrorKind::InvalidArguments,
            "invalid-private-output-path",
            "private output paths must be absolute and direct",
        ));
    }
    let parent = path.parent().ok_or_else(filesystem_error)?;
    let name = path.file_name().ok_or_else(filesystem_error)?;
    validate_detached_separation(parent, home)?;
    let repositories = repository_refs(home);
    let root =
        HardenedStateRoot::open_existing(parent, &repositories).map_err(map_filesystem_error)?;
    let protected = protect(bytes, protection)?;
    PreparedPrivateFile::prepare_state(
        &root,
        Path::new(name),
        &protected,
        if overwrite {
            PublicationPolicy::ReplaceExisting
        } else {
            PublicationPolicy::CreateNew
        },
    )
    .map_err(map_filesystem_error)?
    .publish()
    .map_err(map_filesystem_error)
}

pub(super) fn read_bounded_standard_input(maximum: usize) -> Result<Zeroizing<Vec<u8>>, CliError> {
    let mut bytes = Zeroizing::new(Vec::new());
    bytes
        .try_reserve_exact(maximum.saturating_add(1))
        .map_err(|_| filesystem_error())?;
    let limit = u64::try_from(maximum).unwrap_or(u64::MAX).saturating_add(1);
    std::io::stdin()
        .lock()
        .take(limit)
        .read_to_end(&mut bytes)
        .map_err(|_| filesystem_error())?;
    if bytes.len() > maximum {
        return Err(CliError::new(
            CliErrorKind::InvalidArguments,
            "protected-input-too-large",
            "protected input exceeds the active bound",
        ));
    }
    Ok(bytes)
}
