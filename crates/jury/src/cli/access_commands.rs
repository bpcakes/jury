use super::*;

pub(super) fn access_list(
    cli: &Cli,
    arguments: &AccessListArgs,
    environment: &Environment,
    current: &Path,
    protection: ProtectionPolicy,
) -> Result<CommandOutput, CliError> {
    if let Some(item) = &arguments.item {
        ItemSelector::parse(item.clone()).map_err(|_| invalid_item_selector())?;
    }
    let context = load_vault_principal(cli, environment, current, protection)?;
    if arguments.me {
        let accessible = discover_accessible_items(&context)?;
        let entries = accessible
            .iter()
            .map(|item| {
                let envelope = &context.vault.items[item.envelope_index];
                let explanation = context.policy.access(
                    &envelope.item_id,
                    &context.identity.principal_id(),
                    Capability::Read,
                );
                serde_json::json!({
                    "item": item.descriptor.name(),
                    "item_id": hex(envelope.item_id.as_bytes()),
                    "role": explanation.effective_role.map(access_role),
                    "path": access_path(explanation.path),
                    "read": true,
                    "write": explanation.effective_role.is_some_and(|role| matches!(role, AccessRole::Writer | AccessRole::Owner)),
                    "administer": explanation.effective_role == Some(AccessRole::Owner),
                    "carries_item_quorum_claim": explanation.carries_quorum_claim,
                })
            })
            .collect::<Vec<_>>();
        return Ok(CommandOutput::Safe {
            operation: "access-list-me",
            fields: serde_json::json!({
                "principal_id": hex(context.identity.principal_id().as_bytes()),
                "count": entries.len(),
                "items": entries,
                "inaccessible_items_disclosed": false,
            }),
            lines: vec![format!("Accessible items: {}", entries.len())],
        });
    }
    let item_name = arguments
        .item
        .as_deref()
        .ok_or_else(invalid_item_selector)?;
    let accessible = selected_accessible_item(&context, item_name)?;
    let envelope = &context.vault.items[accessible.envelope_index];
    let policy_item = context
        .policy
        .item(&envelope.item_id)
        .ok_or_else(invalid_vault)?;
    let grants = policy_item
        .grants
        .iter()
        .map(|(principal_id, role)| {
            serde_json::json!({
                "principal_id": hex(principal_id.as_bytes()),
                "role": access_role(*role),
            })
        })
        .collect::<Vec<_>>();
    Ok(CommandOutput::Safe {
        operation: "access-list-item",
        fields: serde_json::json!({
            "item": item_name,
            "item_id": hex(envelope.item_id.as_bytes()),
            "grants": grants,
            "owner_count": context.policy.owner_count(),
            "access_mode": policy_item.access_mode().map(item_access_mode),
            "direct_slot_count": policy_item.direct_slots.len(),
            "item_quorum_claim_suppressed": !policy_item.direct_slots.is_empty(),
        }),
        lines: vec![
            format!("Item access: {item_name}"),
            format!("Explicit grants: {}", grants.len()),
        ],
    })
}

pub(super) fn access_explain(
    cli: &Cli,
    arguments: &AccessExplainArgs,
    check: bool,
    environment: &Environment,
    current: &Path,
    protection: ProtectionPolicy,
) -> Result<CommandOutput, CliError> {
    ItemSelector::parse(arguments.item.clone()).map_err(|_| invalid_item_selector())?;
    if check && arguments.require.is_none() {
        return Err(CliError::new(
            CliErrorKind::InvalidArguments,
            "required-capability-missing",
            "access check requires --require",
        ));
    }
    let context = load_vault_principal(cli, environment, current, protection)?;
    let accessible = selected_accessible_item(&context, &arguments.item)?;
    let envelope = &context.vault.items[accessible.envelope_index];
    let capability = required_capability(arguments.require.unwrap_or(RequiredCapabilityArg::Read));
    let explanation = context.policy.access(
        &envelope.item_id,
        &context.identity.principal_id(),
        capability,
    );
    if check && !explanation.allowed {
        return Err(access_denied());
    }
    Ok(CommandOutput::Safe {
        operation: if check {
            "access-check"
        } else {
            "access-explain"
        },
        fields: serde_json::json!({
            "item": arguments.item,
            "item_id": hex(envelope.item_id.as_bytes()),
            "principal_id": hex(context.identity.principal_id().as_bytes()),
            "required": capability_name(capability),
            "allowed": explanation.allowed,
            "role": explanation.effective_role.map(access_role),
            "path": access_path(explanation.path),
            "carries_item_quorum_claim": explanation.carries_quorum_claim,
        }),
        lines: vec![format!(
            "{}: {} ({})",
            arguments.item,
            if explanation.allowed {
                "allowed"
            } else {
                "denied"
            },
            capability_name(capability)
        )],
    })
}

pub(super) fn access_matrix(
    cli: &Cli,
    environment: &Environment,
    current: &Path,
    protection: ProtectionPolicy,
) -> Result<CommandOutput, CliError> {
    let context = load_vault_principal(cli, environment, current, protection)?;
    require_owner(&context)?;
    let accessible = discover_accessible_items(&context)?;
    if accessible.len() != context.policy.item_count() {
        return Err(invalid_vault());
    }
    let entries = accessible
        .iter()
        .map(|accessible| {
            let envelope = &context.vault.items[accessible.envelope_index];
            let item = context
                .policy
                .item(&envelope.item_id)
                .ok_or_else(invalid_vault)?;
            let grants = item
                .grants
                .iter()
                .map(|(principal_id, role)| {
                    serde_json::json!({
                        "principal_id": hex(principal_id.as_bytes()),
                        "role": access_role(*role),
                    })
                })
                .collect::<Vec<_>>();
            Ok(serde_json::json!({
                "item": accessible.descriptor.name(),
                "item_id": hex(envelope.item_id.as_bytes()),
                "owners": context.policy.owner_ids().map(|id| hex(id.as_bytes())).collect::<Vec<_>>(),
                "grants": grants,
                "mode": item.access_mode().map(item_access_mode),
            }))
        })
        .collect::<Result<Vec<_>, CliError>>()?;
    Ok(CommandOutput::Safe {
        operation: "access-matrix",
        fields: serde_json::json!({
            "item_count": entries.len(),
            "items": entries,
            "owner_only_view": true,
        }),
        lines: vec![format!("Item access matrix: {} items", entries.len())],
    })
}

pub(super) fn access_grant(
    cli: &Cli,
    arguments: &AccessGrantArgs,
    environment: &Environment,
    current: &Path,
    protection: ProtectionPolicy,
) -> Result<CommandOutput, CliError> {
    let requested = requested_access_grants(arguments)?;
    if !arguments.acknowledge_direct_access {
        return Err(direct_access_acknowledgement_required());
    }
    let principal_id = parse_principal_id(&arguments.principal)?;
    let context = load_vault_principal(cli, environment, current, protection)?;
    require_owner(&context)?;
    let principal = grantable_principal(&context.policy, &principal_id)?;
    if context.policy.is_owner(&principal_id) {
        return Err(CliError::new(
            CliErrorKind::Conflict,
            "owner-grant-is-implicit",
            "owners already have item authority and cannot receive explicit roles",
        ));
    }
    if !matches!(
        principal.descriptor.principal_kind,
        PrincipalKind::Human | PrincipalKind::Machine
    ) {
        return Err(CliError::new(
            CliErrorKind::InvalidArguments,
            "principal-kind-cannot-read-items",
            "approver and witness identities cannot receive vault-item roles",
        ));
    }
    let selected = select_admin_items(&context, requested.keys())?;
    for (item, accessible) in &selected {
        let envelope = &context.vault.items[accessible.envelope_index];
        if context
            .policy
            .item(&envelope.item_id)
            .and_then(|state| state.grants.get(&principal_id))
            .is_some()
        {
            let _ = item;
            return Err(CliError::new(
                CliErrorKind::Conflict,
                "access-grant-already-exists",
                "the principal already has an explicit role for a selected item",
            ));
        }
    }
    let timestamp = timestamp_ms()?;
    let inventory = ItemArtifactInventory::from_vault(&context.vault)
        .map_err(|error| map_item_error(error.kind()))?;
    let mut creator = ItemCreator::new(protection);
    let mut prepared = Vec::with_capacity(selected.len());
    for (item, accessible) in selected {
        let envelope = &context.vault.items[accessible.envelope_index];
        let state = open_item_body(&context, &accessible, Capability::Administer)?;
        let mut access = retained_access_plan(&context.policy, envelope)?;
        access.grants.push(ItemGrant {
            principal_id,
            role: requested[&item],
        });
        access.grants.sort_by_key(|grant| grant.principal_id);
        if !access.direct_recipient_ids.is_empty() {
            access.direct_recipient_ids.push(principal_id);
            access.direct_recipient_ids.sort_unstable();
            access.direct_recipient_ids.dedup();
        }
        prepared.push(
            creator
                .prepare_rekey(
                    &context.policy,
                    &context.identity,
                    timestamp,
                    envelope,
                    RekeyedItem {
                        descriptor: accessible.descriptor,
                        state,
                        bucket_id: envelope.current_revision.bucket_id,
                        access,
                        principal_replacement: None,
                        principal_registration: None,
                        owner_change: None,
                    },
                    &inventory,
                )
                .map_err(|error| map_item_error(error.kind()))?,
        );
    }
    finish_item_batch_mutation(
        context,
        prepared,
        Vec::new(),
        MutationFinishOptions {
            operation: "access-grant",
            dry_run: arguments.dry_run,
            acknowledgement: DirectDowngradeAcknowledgement::Acknowledged,
            kind: MutationKind::Policy,
            protection,
        },
    )
}

pub(super) fn access_change(
    cli: &Cli,
    arguments: &AccessChangeArgs,
    environment: &Environment,
    current: &Path,
    protection: ProtectionPolicy,
) -> Result<CommandOutput, CliError> {
    ItemSelector::parse(arguments.item.clone()).map_err(|_| invalid_item_selector())?;
    let principal_id = parse_principal_id(&arguments.principal)?;
    let next_role = access_role_argument(arguments.role);
    let context = load_vault_principal(cli, environment, current, protection)?;
    require_owner(&context)?;
    grantable_principal(&context.policy, &principal_id)?;
    let accessible = selected_accessible_item(&context, &arguments.item)?;
    let envelope = &context.vault.items[accessible.envelope_index];
    let item_id = envelope.item_id;
    let prior_role = context
        .policy
        .item(&envelope.item_id)
        .and_then(|item| item.grants.get(&principal_id).copied())
        .ok_or_else(|| {
            CliError::new(
                CliErrorKind::NotFound,
                "access-grant-not-found",
                "the principal has no explicit role for the selected item",
            )
        })?;
    if prior_role == next_role {
        return Err(CliError::new(
            CliErrorKind::Conflict,
            "no-change",
            "the requested mutation makes no change",
        ));
    }
    let timestamp = timestamp_ms()?;
    finish_policy_mutation(
        context,
        vec![PolicyOperationV1::ItemRoleChange {
            item_id,
            principal_id,
            prior_role: Some(prior_role),
            next_role: Some(next_role),
        }],
        timestamp,
        "access-change",
        arguments.dry_run,
        protection,
    )
}

pub(super) fn access_revoke(
    cli: &Cli,
    arguments: &AccessRevokeArgs,
    environment: &Environment,
    current: &Path,
    protection: ProtectionPolicy,
) -> Result<CommandOutput, CliError> {
    ItemSelector::parse(arguments.item.clone()).map_err(|_| invalid_item_selector())?;
    let principal_id = parse_principal_id(&arguments.principal)?;
    let context = load_vault_principal(cli, environment, current, protection)?;
    require_owner(&context)?;
    let accessible = selected_accessible_item(&context, &arguments.item)?;
    let envelope = &context.vault.items[accessible.envelope_index];
    let item = context
        .policy
        .item(&envelope.item_id)
        .ok_or_else(invalid_vault)?;
    if !item.grants.contains_key(&principal_id) {
        return Err(CliError::new(
            CliErrorKind::NotFound,
            "access-grant-not-found",
            "the principal has no explicit role for the selected item",
        ));
    }
    let state = open_item_body(&context, &accessible, Capability::Administer)?;
    let mut access = retained_access_plan(&context.policy, envelope)?;
    access
        .grants
        .retain(|grant| grant.principal_id != principal_id);
    access
        .direct_recipient_ids
        .retain(|recipient| *recipient != principal_id);
    let timestamp = timestamp_ms()?;
    let inventory = ItemArtifactInventory::from_vault(&context.vault)
        .map_err(|error| map_item_error(error.kind()))?;
    let prepared = ItemCreator::new(protection)
        .prepare_rekey(
            &context.policy,
            &context.identity,
            timestamp,
            envelope,
            RekeyedItem {
                descriptor: accessible.descriptor,
                state,
                bucket_id: envelope.current_revision.bucket_id,
                access,
                principal_replacement: None,
                principal_registration: None,
                owner_change: None,
            },
            &inventory,
        )
        .map_err(|error| map_item_error(error.kind()))?;
    finish_item_mutation(
        context,
        prepared,
        "access-revoke",
        arguments.item.clone(),
        arguments.dry_run,
        MutationKind::Policy,
        protection,
    )
}

pub(super) fn requested_access_grants(
    arguments: &AccessGrantArgs,
) -> Result<BTreeMap<String, AccessRole>, CliError> {
    match (&arguments.item, arguments.role) {
        (Some(item), Some(role))
            if arguments.readers.is_empty() && arguments.writers.is_empty() =>
        {
            ItemSelector::parse(item.clone()).map_err(|_| invalid_item_selector())?;
            Ok(BTreeMap::from([(item.clone(), access_role_argument(role))]))
        }
        (None, None) if !arguments.readers.is_empty() || !arguments.writers.is_empty() => {
            validate_initial_roles(&arguments.readers, &arguments.writers)?;
            Ok(arguments
                .readers
                .iter()
                .map(|item| (item.clone(), AccessRole::Reader))
                .chain(
                    arguments
                        .writers
                        .iter()
                        .map(|item| (item.clone(), AccessRole::Writer)),
                )
                .collect())
        }
        _ => Err(CliError::new(
            CliErrorKind::InvalidArguments,
            "invalid-access-grant-selection",
            "select either one item and role or a nonempty repeated role batch",
        )),
    }
}

pub(super) fn select_admin_items<'a, 'b>(
    context: &'a VaultPrincipalContext,
    names: impl Iterator<Item = &'b String>,
) -> Result<BTreeMap<String, AccessibleItem>, CliError> {
    let requested = names.cloned().collect::<BTreeSet<_>>();
    let mut accessible = accessible_items_by_name(context)?;
    if requested.iter().any(|name| !accessible.contains_key(name)) {
        return Err(item_unavailable());
    }
    Ok(requested
        .into_iter()
        .filter_map(|name| accessible.remove(&name).map(|item| (name, item)))
        .collect())
}

pub(super) fn require_owner(context: &VaultPrincipalContext) -> Result<(), CliError> {
    if context.policy.is_owner(&context.identity.principal_id()) {
        Ok(())
    } else {
        Err(access_denied())
    }
}

pub(super) fn grantable_principal<'a>(
    policy: &'a PolicyState,
    principal_id: &PrincipalId,
) -> Result<&'a jury_core::policy::PrincipalPolicyState, CliError> {
    policy.principal(principal_id).ok_or_else(|| {
        CliError::new(
            CliErrorKind::NotFound,
            "principal-not-found",
            "the selected principal is not active",
        )
    })
}
