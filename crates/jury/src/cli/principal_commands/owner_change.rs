pub(super) fn principal_owner_change(
    cli: &Cli,
    arguments: &PrincipalTargetArgs,
    grant: bool,
    environment: &Environment,
    current: &Path,
    protection: ProtectionPolicy,
) -> Result<CommandOutput, CliError> {
    let principal_id = parse_principal_id(&arguments.principal)?;
    let mut context = load_vault_principal(cli, environment, current, protection)?;
    require_owner(&context)?;
    let principal = grantable_principal(&context.policy, &principal_id)?;
    if grant
        && !arguments.acknowledge_direct_access
        && context.policy.items().any(|(_, item)| {
            !item.direct_slots.is_empty()
                && !item
                    .direct_slots
                    .iter()
                    .any(|slot| slot.recipient_principal_id == principal_id)
        })
    {
        return Err(direct_access_acknowledgement_required());
    }
    if principal.descriptor.principal_kind != PrincipalKind::Human {
        return Err(CliError::new(
            CliErrorKind::InvalidArguments,
            "human-owner-required",
            "only human vault principals may receive owner authority",
        ));
    }
    if grant == context.policy.is_owner(&principal_id) {
        return Err(CliError::new(
            CliErrorKind::Conflict,
            "no-change",
            "the requested mutation makes no change",
        ));
    }
    if !grant
        && (principal_id == context.identity.principal_id() || context.policy.owner_count() <= 1)
    {
        return Err(CliError::new(
            CliErrorKind::Conflict,
            "owner-revocation-refused",
            "self-revocation and last-owner revocation require a different remaining owner",
        ));
    }
    let timestamp = timestamp_ms()?;
    let operation = if grant {
        PolicyOperationV1::OwnerGrant { principal_id }
    } else {
        PolicyOperationV1::OwnerRevoke { principal_id }
    };
    if context.policy.item_count() == 0 {
        if arguments.administrative_access.is_some() {
            open_owner_change_items(&context, arguments, grant, principal_id, protection)?;
        }
        return finish_policy_mutation(
            context,
            vec![operation],
            timestamp,
            if grant {
                "principal-grant-owner"
            } else {
                "principal-revoke-owner"
            },
            arguments.dry_run,
            protection,
        );
    }
    preflight_owner_change_labels(&context, timestamp)?;
    let opened = open_owner_change_items(&context, arguments, grant, principal_id, protection)?;
    let timestamp = timestamp_ms()?;
    let successors = prepare_owner_change_policies(&mut context, timestamp)?;
    let inventory = ItemArtifactInventory::from_vault(&context.vault)
        .map_err(|error| map_item_error(error.kind()))?;
    let mut creator = ItemCreator::new(protection);
    let mut prepared = Vec::with_capacity(opened.len());
    for opened in &opened {
        let accessible = &opened.accessible;
        let envelope = &context.vault.items[accessible.envelope_index];
        let mut access = retained_access_plan(&context.policy, envelope)?;
        if let Some(prior) = &access.witness_policy_digest {
            access.witness_policy_digest =
                Some(successors.get(prior).ok_or_else(invalid_vault)?.clone());
        }
        if grant {
            access
                .grants
                .retain(|entry| entry.principal_id != principal_id);
            if !access.direct_recipient_ids.is_empty() {
                access.direct_recipient_ids.push(principal_id);
                access.direct_recipient_ids.sort_unstable();
                access.direct_recipient_ids.dedup();
            }
        } else {
            access
                .direct_recipient_ids
                .retain(|recipient| *recipient != principal_id);
        }
        prepared.push(
            creator
                .prepare_rekey_batch_component(
                    &context.policy,
                    &context.identity,
                    timestamp,
                    envelope,
                    RekeyedItem {
                        descriptor: accessible.descriptor.clone(),
                        state: opened.state.clone(),
                        bucket_id: envelope.current_revision.bucket_id,
                        access,
                        principal_replacement: None,
                        principal_registration: None,
                        owner_change: Some(if grant {
                            OwnerChange::Grant(principal_id)
                        } else {
                            OwnerChange::Revoke(principal_id)
                        }),
                    },
                    &inventory,
                )
                .map_err(|error| map_item_error(error.kind()))?,
        );
    }
    finish_item_component_batch_mutation(
        context,
        prepared,
        Vec::new(),
        timestamp,
        MutationFinishOptions {
            operation: if grant {
                "principal-grant-owner"
            } else {
                "principal-revoke-owner"
            },
            dry_run: arguments.dry_run,
            acknowledgement: if arguments.acknowledge_direct_access {
                DirectDowngradeAcknowledgement::Acknowledged
            } else {
                DirectDowngradeAcknowledgement::Absent
            },
            kind: MutationKind::Policy,
            protection,
        },
    )
}

include!("owner_access.rs");
include!("owner_policies.rs");
