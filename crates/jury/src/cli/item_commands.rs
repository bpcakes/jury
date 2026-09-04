use super::*;

pub(super) fn item_create(
    cli: &Cli,
    arguments: &ItemCreateArgs,
    environment: &Environment,
    current: &Path,
    protection: ProtectionPolicy,
) -> Result<CommandOutput, CliError> {
    let descriptor = ItemDescriptorV1::new(arguments.item.clone()).map_err(|_| {
        CliError::new(
            CliErrorKind::InvalidArguments,
            "invalid-item-name",
            "the item name is invalid",
        )
    })?;
    if !arguments.allow_direct {
        return Err(CliError::new(
            CliErrorKind::InvalidArguments,
            "direct-access-acknowledgement-required",
            "creating a directly accessible item requires --allow-direct",
        ));
    }
    let mut grants = Vec::new();
    for principal in &arguments.readers {
        grants.push(ItemGrant {
            principal_id: parse_principal_id(principal)?,
            role: AccessRole::Reader,
        });
    }
    for principal in &arguments.writers {
        grants.push(ItemGrant {
            principal_id: parse_principal_id(principal)?,
            role: AccessRole::Writer,
        });
    }
    grants.sort_by_key(|grant| grant.principal_id);
    if grants
        .windows(2)
        .any(|pair| pair[0].principal_id == pair[1].principal_id)
    {
        return Err(CliError::new(
            CliErrorKind::InvalidArguments,
            "duplicate-item-grant",
            "an initial principal grant is duplicated or contradictory",
        ));
    }

    let context = load_vault_principal(cli, environment, current, protection)?;
    if !context.policy.is_owner(&context.identity.principal_id()) {
        return Err(access_denied());
    }
    if all_admin_items(&context)?
        .iter()
        .any(|item| item.descriptor.name() == arguments.item)
    {
        return Err(CliError::new(
            CliErrorKind::Conflict,
            "duplicate-item-name",
            "an active item already uses the selected name",
        ));
    }
    if grants
        .iter()
        .any(|grant| grant.principal_id == context.identity.principal_id())
    {
        return Err(CliError::new(
            CliErrorKind::InvalidArguments,
            "owner-grant-is-implicit",
            "owners already have item authority and cannot receive an explicit item role",
        ));
    }
    let mut direct_recipient_ids = grants
        .iter()
        .map(|grant| grant.principal_id)
        .collect::<Vec<_>>();
    direct_recipient_ids.push(context.identity.principal_id());
    direct_recipient_ids.sort_unstable();
    direct_recipient_ids.dedup();

    let timestamp = timestamp_ms()?;
    let state = ItemStateV1 {
        plaintext_schema: 1,
        fields: Vec::new(),
    };
    let inventory = ItemArtifactInventory::from_vault(&context.vault)
        .map_err(|error| map_item_error(error.kind()))?;
    let prepared = ItemCreator::new(protection)
        .prepare_create(
            &context.policy,
            &context.identity,
            timestamp,
            NewItem {
                kind: ItemKind::Canonical,
                descriptor,
                state,
                bucket_id: 1,
                access: ItemAccessPlan {
                    grants,
                    direct_recipient_ids,
                    witness_policy_digest: None,
                },
            },
            &inventory,
        )
        .map_err(|error| map_item_error(error.kind()))?;
    let plan = VaultMutationPlan::prepare_item_batch(
        &context.vault,
        &context.catalog.witness_policies,
        &context.identity,
        timestamp,
        Vec::new(),
        vec![prepared],
        DirectDowngradeAcknowledgement::Acknowledged,
        MutationKind::Item,
    )
    .map_err(|error| map_mutation_error(error.kind()))?;
    finish_mutation_plan(
        context,
        plan,
        "item-create",
        Some(arguments.item.clone()),
        arguments.dry_run,
        protection,
    )
}

pub(super) fn field_list(
    cli: &Cli,
    arguments: &FieldListArgs,
    environment: &Environment,
    current: &Path,
    protection: ProtectionPolicy,
) -> Result<CommandOutput, CliError> {
    if let Some(item) = &arguments.item {
        ItemSelector::parse(item.clone()).map_err(|_| invalid_item_selector())?;
    }
    let context = load_vault_principal(cli, environment, current, protection)?;
    let mut accessible = if let Some(item) = &arguments.item {
        vec![selected_accessible_item(&context, item)?]
    } else {
        discover_accessible_items(&context)?
    };
    accessible.sort_by(|left, right| {
        left.descriptor
            .name()
            .as_bytes()
            .cmp(right.descriptor.name().as_bytes())
    });
    let mut fields = Vec::new();
    for item in &accessible {
        let mut state = open_item_body(&context, item, Capability::Read)?;
        let item_id = context.vault.items[item.envelope_index].item_id;
        for field in &state.fields {
            fields.push(FieldSummary {
                item: item.descriptor.name().to_owned(),
                item_id: hex(item_id.as_bytes()),
                field: field.name.clone(),
                kind: field_kind(field.kind),
                updated_at_ms: field.updated_at_ms,
            });
        }
        state.clear_sensitive();
    }
    Ok(CommandOutput::FieldList { fields })
}

pub(super) fn field_set(
    cli: &Cli,
    arguments: &FieldSetArgs,
    environment: &Environment,
    current: &Path,
    protection: ProtectionPolicy,
) -> Result<CommandOutput, CliError> {
    FieldSelector::parse(arguments.item.clone(), arguments.field.clone())
        .map_err(|_| invalid_field_selector())?;
    if !arguments.value_stdin {
        return Err(CliError::new(
            CliErrorKind::InvalidArguments,
            "field-input-opt-in-required",
            "field values must be supplied with --value-stdin",
        ));
    }
    let context = load_vault_principal(cli, environment, current, protection)?;
    let value = read_bounded_standard_input(MAX_FIELD_VALUE_BYTES)?;
    let field_value = ItemFieldValue::new(value.as_slice().to_vec()).map_err(|_| {
        CliError::new(
            CliErrorKind::InvalidArguments,
            "invalid-field-value",
            "the field value exceeds the active bound",
        )
    })?;
    let decoded_length = u32::try_from(field_value.len()).map_err(|_| {
        CliError::new(
            CliErrorKind::InvalidArguments,
            "invalid-field-value",
            "the field value exceeds the active bound",
        )
    })?;
    let accessible = selected_accessible_item(&context, &arguments.item)?;
    let mut state = open_item_body(&context, &accessible, Capability::Write)?;
    let timestamp = timestamp_ms()?;
    let mut creator = ItemCreator::new(protection);
    match state
        .fields
        .binary_search_by(|field| field.name.as_bytes().cmp(arguments.field.as_bytes()))
    {
        Ok(index) => {
            let field = &mut state.fields[index];
            field.value = field_value;
            field.decoded_length = decoded_length;
            field.kind = if arguments.concealed {
                ItemFieldKind::Concealed
            } else {
                ItemFieldKind::Text
            };
            field.updated_at_ms = timestamp;
        }
        Err(index) => {
            let ids = state
                .fields
                .iter()
                .map(|field| field.field_id)
                .collect::<Vec<_>>();
            let field_id = creator
                .generate_field_id(&ids)
                .map_err(|error| map_item_error(error.kind()))?;
            state.fields.insert(
                index,
                ItemFieldV1 {
                    name: arguments.field.clone(),
                    field_id,
                    value: field_value,
                    decoded_length,
                    kind: if arguments.concealed {
                        ItemFieldKind::Concealed
                    } else {
                        ItemFieldKind::Text
                    },
                    created_at_ms: timestamp,
                    updated_at_ms: timestamp,
                },
            );
        }
    }
    state.validate().map_err(|_| {
        CliError::new(
            CliErrorKind::InvalidArguments,
            "invalid-field-value",
            "the field value does not meet the selected field profile",
        )
    })?;
    let bucket_id = smallest_bucket(&state, current_bucket(&context, &accessible))?;
    let prepared = prepare_rekey(&context, &accessible, creator, state, bucket_id, timestamp)?;
    finish_item_mutation(
        context,
        prepared,
        "field-set",
        arguments.item.clone(),
        arguments.dry_run,
        MutationKind::Item,
        protection,
    )
}

pub(super) fn field_remove(
    cli: &Cli,
    arguments: &FieldRemoveArgs,
    environment: &Environment,
    current: &Path,
    protection: ProtectionPolicy,
) -> Result<CommandOutput, CliError> {
    FieldSelector::parse(arguments.item.clone(), arguments.field.clone())
        .map_err(|_| invalid_field_selector())?;
    let context = load_vault_principal(cli, environment, current, protection)?;
    let accessible = selected_accessible_item(&context, &arguments.item)?;
    let mut state = open_item_body(&context, &accessible, Capability::Write)?;
    let index = state
        .fields
        .binary_search_by(|field| field.name.as_bytes().cmp(arguments.field.as_bytes()))
        .map_err(|_| field_unavailable())?;
    let mut removed = state.fields.remove(index);
    removed.name.zeroize();
    removed.value.clear_sensitive();
    let timestamp = timestamp_ms()?;
    let bucket_id = current_bucket(&context, &accessible);
    let prepared = prepare_rekey(
        &context,
        &accessible,
        ItemCreator::new(protection),
        state,
        bucket_id,
        timestamp,
    )?;
    finish_item_mutation(
        context,
        prepared,
        "field-remove",
        arguments.item.clone(),
        arguments.dry_run,
        MutationKind::Item,
        protection,
    )
}

pub(super) fn privacy_cover(
    cli: &Cli,
    arguments: &PrivacyCoverArgs,
    environment: &Environment,
    current: &Path,
    protection: ProtectionPolicy,
) -> Result<CommandOutput, CliError> {
    ItemSelector::parse(arguments.item.clone()).map_err(|_| invalid_item_selector())?;
    let context = load_vault_principal(cli, environment, current, protection)?;
    let accessible = selected_accessible_item(&context, &arguments.item)?;
    let state = open_item_body(&context, &accessible, Capability::Write)?;
    let timestamp = timestamp_ms()?;
    let bucket_id = current_bucket(&context, &accessible);
    let prepared = prepare_rekey(
        &context,
        &accessible,
        ItemCreator::new(protection),
        state,
        bucket_id,
        timestamp,
    )?;
    finish_item_mutation(
        context,
        prepared,
        "privacy-cover",
        arguments.item.clone(),
        arguments.dry_run,
        MutationKind::PrivacyCover,
        protection,
    )
}

pub(super) fn field_read(
    cli: &Cli,
    arguments: &ReadArgs,
    environment: &Environment,
    current: &Path,
    protection: ProtectionPolicy,
) -> Result<CommandOutput, CliError> {
    if !arguments.direct {
        return request_execute(
            cli,
            &RequestExecuteArgs {
                item: Some(arguments.item.clone()),
                item_id: None,
                field: Some(arguments.field.clone()),
                field_id: None,
                checkpoint: arguments
                    .checkpoint
                    .clone()
                    .ok_or_else(witnessed_execution_arguments_required)?,
                request_out: arguments
                    .request_out
                    .clone()
                    .ok_or_else(witnessed_execution_arguments_required)?,
                receipt: arguments
                    .receipt
                    .clone()
                    .ok_or_else(witnessed_execution_arguments_required)?,
                approvals: arguments.approvals.clone(),
                witnesses: arguments.witnesses.clone(),
                allow_insecure_loopback: arguments.allow_insecure_loopback,
                wait_seconds: arguments.wait_seconds,
                out: arguments.out.clone(),
                reveal: arguments.reveal,
                overwrite: arguments.overwrite,
            },
            environment,
            current,
            protection,
        );
    }
    FieldSelector::parse(arguments.item.clone(), arguments.field.clone())
        .map_err(|_| invalid_field_selector())?;
    validate_plaintext_sink(cli, arguments.out.as_deref(), arguments.reveal)?;
    let context = load_vault_principal(cli, environment, current, protection)?;
    let accessible = selected_accessible_item(&context, &arguments.item)?;
    let mut state = open_item_body(&context, &accessible, Capability::Read)?;
    let field = state
        .fields
        .iter()
        .find(|field| field.name == arguments.field)
        .ok_or_else(field_unavailable)?;
    let item_id = context.vault.items[accessible.envelope_index].item_id;
    append_operational_audit(&context, AuditAction::ItemRead, &[item_id], protection)?;
    let result = if let Some(path) = &arguments.out {
        let outcome = write_private_file(
            &context.home,
            path,
            field.value.as_bytes(),
            arguments.overwrite,
            protection,
        )?;
        CommandOutput::PrivateOutput {
            operation: "field-read",
            item: Some(arguments.item.clone()),
            field: Some(arguments.field.clone()),
            sink: "private-file",
            durability: Some(durability(outcome)),
            authority: "direct-unilateral",
        }
    } else {
        eprintln!("Authority: direct-unilateral");
        let mut output = std::io::stdout().lock();
        output
            .write_all(field.value.as_bytes())
            .and_then(|()| output.flush())
            .map_err(|_| filesystem_error())?;
        CommandOutput::Silent
    };
    state.clear_sensitive();
    Ok(result)
}

const fn witnessed_execution_arguments_required() -> CliError {
    CliError::new(
        CliErrorKind::InvalidArguments,
        "witnessed-execution-arguments-required",
        "governed read requires --checkpoint, --request-out, --receipt, and the exact --witness set; use --direct only for visible unilateral access",
    )
}
