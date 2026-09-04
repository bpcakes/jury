use super::*;

pub(super) fn policy_require_witnessed(
    cli: &Cli,
    arguments: &PolicyRequireWitnessedArgs,
    environment: &Environment,
    current: &Path,
    protection: ProtectionPolicy,
) -> Result<CommandOutput, CliError> {
    ItemSelector::parse(arguments.item.clone()).map_err(|_| invalid_item_selector())?;
    let approver_ids = if arguments.approvers.is_empty() {
        Vec::new()
    } else {
        parse_unique_principal_ids(&arguments.approvers)?
    };
    let witness_ids = parse_unique_principal_ids(&arguments.witnesses)?;
    let approval_threshold = u8::try_from(arguments.approvals).map_err(|_| invalid_quorum())?;
    let witness_threshold = u8::try_from(arguments.witness_quorum).map_err(|_| invalid_quorum())?;
    if usize::from(approval_threshold) > approver_ids.len()
        || witness_ids.len() < 2
        || usize::from(witness_threshold) < 2
        || usize::from(witness_threshold) > witness_ids.len()
    {
        return Err(invalid_quorum());
    }
    let lifetime_ms = arguments
        .request_lifetime
        .checked_mul(1_000)
        .filter(|lifetime| (1..=900_000).contains(lifetime))
        .ok_or_else(invalid_policy_controls)?;
    let operations = parse_witness_operations(&arguments.operations)?;
    let automatic = approval_threshold == 0;
    if (automatic
        && (!approver_ids.is_empty()
            || operations.as_slice() != [WitnessOperation::ReadStdout]
            || arguments.automatic_read_fields.is_empty()
            || arguments.review_label.is_some()
            || !arguments.field_review_labels.is_empty()))
        || (!automatic
            && (approver_ids.is_empty()
                || !arguments.automatic_read_fields.is_empty()
                || arguments.review_label.is_none()
                || (operations.iter().any(|operation| {
                    matches!(
                        operation,
                        WitnessOperation::ReadStdout
                            | WitnessOperation::WritePrivateFile
                            | WitnessOperation::TemplateInjection
                            | WitnessOperation::ChildEnvironment
                            | WitnessOperation::ChildStdin
                            | WitnessOperation::ItemMutation
                    )
                }) && arguments.field_review_labels.is_empty())))
    {
        return Err(invalid_policy_controls());
    }
    if arguments.workload.is_some() {
        return Err(invalid_policy_controls());
    }
    let context = load_vault_principal(cli, environment, current, protection)?;
    require_owner(&context)?;
    let accessible = selected_accessible_item(&context, &arguments.item)?;
    let envelope = &context.vault.items[accessible.envelope_index];
    let item = context
        .policy
        .item(&envelope.item_id)
        .ok_or_else(invalid_vault)?;
    let catalog = read_policy_catalog(&context.state)?;
    let state = open_item_body(&context, &accessible, Capability::Administer)?;
    let approver_descriptors = approver_ids
        .iter()
        .map(|principal_id| {
            let principal = grantable_principal(&context.policy, principal_id)?;
            if principal.descriptor.principal_kind != PrincipalKind::Approver {
                return Err(invalid_policy_membership());
            }
            catalog
                .role_descriptors
                .iter()
                .find_map(|role| match role {
                    RegistrationRoleDescriptorV1::Approver { descriptor }
                        if descriptor.approver_id == *principal_id =>
                    {
                        Some(descriptor.clone())
                    }
                    _ => None,
                })
                .ok_or_else(invalid_policy_membership)
        })
        .collect::<Result<Vec<_>, CliError>>()?;
    let witness_descriptors = witness_ids
        .iter()
        .map(|principal_id| {
            let principal = grantable_principal(&context.policy, principal_id)?;
            if principal.descriptor.principal_kind != PrincipalKind::Witness {
                return Err(invalid_policy_membership());
            }
            catalog
                .role_descriptors
                .iter()
                .find_map(|role| match role {
                    RegistrationRoleDescriptorV1::Witness { descriptor }
                        if descriptor.witness_id == *principal_id =>
                    {
                        Some(descriptor.as_ref().clone())
                    }
                    _ => None,
                })
                .ok_or_else(invalid_policy_membership)
        })
        .collect::<Result<Vec<_>, CliError>>()?;
    if approver_descriptors.iter().any(|descriptor| {
        operations
            .iter()
            .any(|operation| !descriptor.allowed_operations.contains(operation))
    }) {
        return Err(invalid_policy_membership());
    }
    let prior_policy =
        item.witnessed_state
            .as_ref()
            .and_then(|state| state.slots.first())
            .and_then(|slot| {
                context.catalog.witness_policies.iter().find(|policy| {
                    policy.digest().ok().as_ref() == Some(&slot.witness_policy_digest)
                })
            });
    let (policy_id, revision, predecessor) = if let Some(prior) = prior_policy {
        (
            prior.witness_policy_id,
            prior
                .revision
                .checked_add(1)
                .ok_or_else(invalid_policy_controls)?,
            prior.digest().map_err(|_| invalid_policy_catalog())?,
        )
    } else {
        (random_witness_policy_id()?, 1, Digest32::new([0; 32]))
    };
    let next_sequence = context
        .policy
        .sequence()
        .checked_add(1)
        .ok_or_else(invalid_policy_controls)?;
    let timestamp = timestamp_ms()?;
    let mut label_creator = OwnerReviewLabelCreator::new();
    let mut review_labels = Vec::new();
    if let Some(public_label) = &arguments.review_label {
        let public_label = ReviewLabelBytes::new(public_label.as_bytes().to_vec())
            .map_err(|_| invalid_policy_controls())?;
        let review_label = label_creator
            .create(
                OwnerReviewLabelInput {
                    policy: &context.policy,
                    owner: &context.identity,
                    label_revision: 1,
                    subject: ReviewLabelSubject::Item(envelope.item_id),
                    public_label,
                    target_policy_sequence: next_sequence,
                    issued_at_ms: timestamp,
                    expires_at_ms: None,
                },
                |candidate| {
                    catalog
                        .review_label_sets
                        .iter()
                        .flat_map(|set| &set.labels)
                        .any(|label| label.label_id == *candidate)
                },
            )
            .map_err(|_| invalid_policy_controls())?;
        review_labels.push(review_label);
    }
    let mut reviewed_fields = BTreeSet::new();
    for mapping in &arguments.field_review_labels {
        let (field_name, public_label) = mapping
            .split_once('=')
            .filter(|(field, label)| !field.is_empty() && !label.is_empty())
            .ok_or_else(invalid_policy_controls)?;
        let field = state
            .fields
            .iter()
            .find(|field| field.name == field_name)
            .ok_or_else(invalid_policy_controls)?;
        if !reviewed_fields.insert(field.field_id) {
            return Err(invalid_policy_controls());
        }
        let public_label = ReviewLabelBytes::new(public_label.as_bytes().to_vec())
            .map_err(|_| invalid_policy_controls())?;
        let label = label_creator
            .create(
                OwnerReviewLabelInput {
                    policy: &context.policy,
                    owner: &context.identity,
                    label_revision: 1,
                    subject: ReviewLabelSubject::Field {
                        item_id: envelope.item_id,
                        field_id: field.field_id,
                    },
                    public_label,
                    target_policy_sequence: next_sequence,
                    issued_at_ms: timestamp,
                    expires_at_ms: None,
                },
                |candidate| {
                    catalog
                        .review_label_sets
                        .iter()
                        .flat_map(|set| &set.labels)
                        .chain(&review_labels)
                        .any(|label| label.label_id == *candidate)
                },
            )
            .map_err(|_| invalid_policy_controls())?;
        review_labels.push(label);
    }
    let review_label_set =
        ReviewLabelSetV1::new(review_labels).map_err(|_| invalid_policy_controls())?;
    let review_label_set_digest = review_label_set.digest.clone();
    let mut automatic_read_targets = arguments
        .automatic_read_fields
        .iter()
        .map(|field_name| {
            state
                .fields
                .iter()
                .find(|field| &field.name == field_name)
                .map(|field| AutomaticReadTarget {
                    item_id: envelope.item_id,
                    field_id: Some(field.field_id),
                })
                .ok_or_else(invalid_policy_controls)
        })
        .collect::<Result<Vec<_>, _>>()?;
    automatic_read_targets.sort_unstable();
    if automatic_read_targets
        .windows(2)
        .any(|pair| pair[0] == pair[1])
    {
        return Err(invalid_policy_controls());
    }
    let operation_rules = operations
        .iter()
        .map(|operation| OperationRule {
            operation: *operation,
            eligible_approver_ids: approver_ids.clone(),
            approval_threshold,
            allowed_request_lifetime_ms: lifetime_ms,
            max_timeout_ms: lifetime_ms.min(30_000),
            max_output_bytes: u32::try_from(MAX_TEMPLATE_OUTPUT_BYTES).unwrap_or(u32::MAX),
            max_target_count: u8::try_from(if automatic {
                automatic_read_targets.len()
            } else {
                reviewed_fields.len().saturating_add(1)
            })
            .unwrap_or(u8::MAX),
            required_platform_assurance: PlatformAssurance::NormalizedPathOnly,
            automatic_read_targets: automatic_read_targets.clone(),
        })
        .collect::<Vec<_>>();
    let witness_policy = WitnessPolicy {
        schema: 1,
        witness_policy_id: policy_id,
        revision,
        predecessor_policy_digest: predecessor,
        vault_id: context.policy.vault_id(),
        genesis_fingerprint: context.policy.genesis_fingerprint().clone(),
        vault_policy_sequence: next_sequence,
        vault_policy_hash: context.policy.terminal_revision_hash().clone(),
        construction: 1,
        suite: 1,
        approver_descriptors,
        witness_descriptors,
        witness_threshold,
        operation_rules,
        review_label_set_digest,
        direct_fallback: false,
    };
    witness_policy
        .validate()
        .map_err(|_| invalid_policy_controls())?;
    let witness_digest = witness_policy
        .digest()
        .map_err(|_| invalid_policy_controls())?;
    let mut witness_policies = context.catalog.witness_policies.clone();
    witness_policies.push(witness_policy.clone());
    let planning_policy =
        replay_policy_with_witness_policies(&context.vault.policy, &witness_policies)
            .map_err(|_| invalid_policy_catalog())?;
    let mut access = retained_access_plan(&planning_policy, envelope)?;
    access.direct_recipient_ids.clear();
    access.witness_policy_digest = Some(witness_digest);
    let inventory = ItemArtifactInventory::from_vault(&context.vault)
        .map_err(|error| map_item_error(error.kind()))?;
    let prepared = ItemCreator::new(protection)
        .prepare_rekey(
            &planning_policy,
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
    let mut context = context;
    add_catalog_review_label_set(&mut context.catalog, review_label_set)?;
    add_catalog_witness_policy(&mut context.catalog, &context.policy, &witness_policy)?;
    context.policy = planning_policy;
    finish_item_mutation(
        context,
        prepared,
        "policy-require-witnessed",
        arguments.item.clone(),
        arguments.dry_run,
        MutationKind::Policy,
        protection,
    )
}

pub(super) fn policy_allow_direct(
    cli: &Cli,
    arguments: &PolicyAllowDirectArgs,
    environment: &Environment,
    current: &Path,
    protection: ProtectionPolicy,
) -> Result<CommandOutput, CliError> {
    ItemSelector::parse(arguments.item.clone()).map_err(|_| invalid_item_selector())?;
    if !arguments.acknowledge_direct_access {
        return Err(CliError::new(
            CliErrorKind::InvalidArguments,
            "direct-access-acknowledgement-required",
            "direct access is unilateral and requires explicit acknowledgement",
        ));
    }
    let principals = parse_unique_principal_ids(&arguments.principals)?;
    let context = load_vault_principal(cli, environment, current, protection)?;
    require_owner(&context)?;
    let accessible = selected_accessible_item(&context, &arguments.item)?;
    let envelope = &context.vault.items[accessible.envelope_index];
    for principal_id in &principals {
        let principal = grantable_principal(&context.policy, principal_id)?;
        if !matches!(
            principal.descriptor.principal_kind,
            PrincipalKind::Human | PrincipalKind::Machine
        ) || !context
            .policy
            .access(&envelope.item_id, principal_id, Capability::Read)
            .allowed
        {
            return Err(invalid_policy_membership());
        }
    }
    let state = open_item_body(&context, &accessible, Capability::Administer)?;
    let mut access = retained_access_plan(&context.policy, envelope)?;
    access.direct_recipient_ids.extend(principals);
    access.direct_recipient_ids.sort_unstable();
    access.direct_recipient_ids.dedup();
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
    finish_item_mutation_with_ack(
        context,
        prepared,
        arguments.item.clone(),
        MutationFinishOptions {
            operation: "policy-allow-direct",
            dry_run: arguments.dry_run,
            acknowledgement: DirectDowngradeAcknowledgement::Acknowledged,
            kind: MutationKind::Policy,
            protection,
        },
    )
}

pub(super) fn parse_unique_principal_ids(values: &[String]) -> Result<Vec<PrincipalId>, CliError> {
    let mut ids = values
        .iter()
        .map(|value| parse_principal_id(value))
        .collect::<Result<Vec<_>, _>>()?;
    ids.sort_unstable();
    if ids.is_empty() || ids.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(invalid_policy_membership());
    }
    Ok(ids)
}

pub(super) fn parse_witness_operations(
    values: &[String],
) -> Result<Vec<WitnessOperation>, CliError> {
    let mut operations = values
        .iter()
        .map(|value| match value.as_str() {
            "read-stdout" => Ok(WitnessOperation::ReadStdout),
            "write-private-file" => Ok(WitnessOperation::WritePrivateFile),
            "template-injection" => Ok(WitnessOperation::TemplateInjection),
            "child-environment" => Ok(WitnessOperation::ChildEnvironment),
            "child-stdin" => Ok(WitnessOperation::ChildStdin),
            "item-mutation" => Ok(WitnessOperation::ItemMutation),
            "backup" => Ok(WitnessOperation::Backup),
            "recovery" => Ok(WitnessOperation::Recovery),
            "administrative-rekey" => Ok(WitnessOperation::AdministrativeRekey),
            _ => Err(invalid_policy_controls()),
        })
        .collect::<Result<Vec<_>, _>>()?;
    operations.sort_unstable();
    if operations.is_empty() || operations.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(invalid_policy_controls());
    }
    Ok(operations)
}

pub(super) fn random_witness_policy_id() -> Result<WitnessPolicyId, CliError> {
    let digest = random_operation_id()?;
    WitnessPolicyId::from_bytes(*digest.as_bytes()).map_err(|_| invalid_policy_controls())
}

pub(super) fn policy_status(
    cli: &Cli,
    arguments: &PolicyItemArgs,
    explain: bool,
    environment: &Environment,
    current: &Path,
    protection: ProtectionPolicy,
) -> Result<CommandOutput, CliError> {
    ItemSelector::parse(arguments.item.clone()).map_err(|_| invalid_item_selector())?;
    let context = load_vault_principal(cli, environment, current, protection)?;
    let accessible = selected_accessible_item(&context, &arguments.item)?;
    let envelope = &context.vault.items[accessible.envelope_index];
    let item = context
        .policy
        .item(&envelope.item_id)
        .ok_or_else(invalid_vault)?;
    let mode = item.access_mode().ok_or_else(invalid_vault)?;
    let witnessed = item.witnessed_state.as_ref();
    let carries_quorum_claim =
        witnessed.is_some_and(|state| state.has_item_quorum_claim(item.direct_slots.len()));
    let witness_policy =
        witnessed
            .and_then(|state| state.slots.first())
            .and_then(|slot| {
                context.catalog.witness_policies.iter().find(|policy| {
                    policy.digest().ok().as_ref() == Some(&slot.witness_policy_digest)
                })
            });
    let witness_policy_id = witness_policy.map(|policy| hex(policy.witness_policy_id.as_bytes()));
    let witness_policy_revision = witness_policy.map(|policy| policy.revision);
    let witness_policy_digest = witness_policy
        .and_then(|policy| policy.digest().ok())
        .map(|digest| hex(digest.as_bytes()));
    let witness_count = witness_policy.map(|policy| {
        policy
            .witness_descriptors
            .iter()
            .filter(|descriptor| descriptor.status == DescriptorStatus::Active)
            .count()
    });
    let witness_threshold = witness_policy.map(|policy| policy.witness_threshold);
    let approver_count = witness_policy.map(|policy| {
        policy
            .approver_descriptors
            .iter()
            .filter(|descriptor| descriptor.status == DescriptorStatus::Active)
            .count()
    });
    let operation_rules = witness_policy
        .map(|policy| {
            policy
                .operation_rules
                .iter()
                .map(|rule| {
                    serde_json::json!({
                        "operation": witness_operation(rule.operation),
                        "eligible_approver_count": rule.eligible_approver_ids.len(),
                        "approval_threshold": rule.approval_threshold,
                        "request_lifetime_ms": rule.allowed_request_lifetime_ms,
                        "workload_bound": true,
                    })
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let quorum_satisfiable = witness_policy.map(|policy| {
        let active_approvers = policy
            .approver_descriptors
            .iter()
            .filter(|descriptor| descriptor.status == DescriptorStatus::Active)
            .map(|descriptor| descriptor.approver_id)
            .collect::<BTreeSet<_>>();
        let active_witnesses = policy
            .witness_descriptors
            .iter()
            .filter(|descriptor| descriptor.status == DescriptorStatus::Active)
            .count();
        active_witnesses >= usize::from(policy.witness_threshold)
            && policy.operation_rules.iter().all(|rule| {
                usize::from(rule.approval_threshold)
                    <= rule
                        .eligible_approver_ids
                        .iter()
                        .filter(|id| active_approvers.contains(id))
                        .count()
            })
    });
    Ok(CommandOutput::Safe {
        operation: if explain {
            "policy-explain"
        } else {
            "policy-status"
        },
        fields: serde_json::json!({
            "item": arguments.item,
            "item_id": hex(envelope.item_id.as_bytes()),
            "mode": item_access_mode(mode),
            "direct_slot_count": item.direct_slots.len(),
            "witnessed_slots_present": witnessed.is_some(),
            "witness_policy_id": witness_policy_id,
            "witness_policy_revision": witness_policy_revision,
            "witness_policy_digest": witness_policy_digest,
            "active_approver_count": approver_count,
            "active_witness_count": witness_count,
            "witness_threshold": witness_threshold,
            "operation_rules": operation_rules,
            "quorum_satisfiable": quorum_satisfiable,
            "carries_item_quorum_claim": carries_quorum_claim,
            "item_quorum_claim_suppressed": !item.direct_slots.is_empty(),
            "pending_request_invalidation_on_policy_change": true,
            "value_free": true,
        }),
        lines: vec![
            format!(
                "Policy mode for {}: {}",
                arguments.item,
                item_access_mode(mode)
            ),
            format!("Carries item quorum claim: {carries_quorum_claim}"),
        ],
    })
}

pub(super) const fn witness_operation(operation: WitnessOperation) -> &'static str {
    match operation {
        WitnessOperation::ReadStdout => "read-stdout",
        WitnessOperation::WritePrivateFile => "write-private-file",
        WitnessOperation::TemplateInjection => "template-injection",
        WitnessOperation::ChildEnvironment => "child-environment",
        WitnessOperation::ChildStdin => "child-stdin",
        WitnessOperation::ItemMutation => "item-mutation",
        WitnessOperation::Backup => "backup",
        WitnessOperation::Recovery => "recovery",
        WitnessOperation::AdministrativeRekey => "administrative-rekey",
    }
}
