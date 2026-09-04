fn execute_witnessed_prepared(
    cli: &Cli,
    environment: &Environment,
    current: &Path,
    protection: ProtectionPolicy,
    prepared: PreparedExecution,
    files: WitnessExecutionFiles<'_>,
) -> Result<CommandOutput, CliError> {
    use jury_protocol::vault_v1::BoundedBytes;
    use jury_protocol::witness_v1::{
        EnvironmentInjectionV1, ManifestArgumentV1, OperationContextV1, OutputSinkV1, StdinModeV1,
        WitnessTargetV1,
    };

    let checkpoint_path = files
        .checkpoint
        .ok_or_else(witnessed_execution_arguments_required)?;
    let request_out = files
        .request_out
        .ok_or_else(witnessed_execution_arguments_required)?;
    let receipt_path = files
        .receipt
        .ok_or_else(witnessed_execution_arguments_required)?;
    let receipt_destination = prepare_witness_receipt_destination(receipt_path)?;
    read_checkpoint(checkpoint_path)?;
    let endpoints = files
        .witnesses
        .iter()
        .map(|specification| {
            WitnessEndpointClient::parse(specification, files.allow_insecure_loopback)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let references = execution_references(&prepared);
    if references.is_empty() {
        return Err(invalid_execution_arguments());
    }
    let has_stdin = prepared.stdin.is_some();
    let has_environment = prepared
        .environment
        .iter()
        .any(|binding| matches!(binding.source, EnvironmentSource::Field(_)))
        || !prepared.files.is_empty();
    if (has_stdin && has_environment)
        || prepared
            .environment
            .iter()
            .any(|binding| matches!(binding.source, EnvironmentSource::Literal(_)))
    {
        return Err(CliError::new(
            CliErrorKind::InvalidArguments,
            "governed-execution-shape-unsupported",
            "governed execution requires either typed field environment/file injections or one field on stdin, and cannot carry uncommitted literal environment values",
        ));
    }
    let context = load_vault_principal(cli, environment, current, protection)?;
    let checkpoint = read_checkpoint(checkpoint_path)?;
    let review_labels = review_labels_for_checkpoint(&context.catalog, &checkpoint)?;
    let mut target_ids = BTreeMap::new();
    for reference in &references {
        let target = resolve_request_target(
            &review_labels,
            Some(&reference.item),
            None,
            Some(&reference.field),
            None,
        )?;
        target_ids.insert(reference.clone(), target);
    }
    let item_ids = target_ids
        .values()
        .map(|(item_id, _)| *item_id)
        .collect::<BTreeSet<_>>();
    if item_ids.len() != 1 {
        return Err(CliError::new(
            CliErrorKind::InvalidArguments,
            "governed-execution-single-item-required",
            "one governed execution request may reference exactly one witnessed item",
        ));
    }
    let item_id = item_ids
        .iter()
        .next()
        .copied()
        .ok_or_else(invalid_execution_arguments)?;
    let field_ids = target_ids
        .values()
        .map(|(_, field_id)| *field_id)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let mut environment_injections = prepared
        .environment
        .iter()
        .filter_map(|binding| match &binding.source {
            EnvironmentSource::Literal(_) => None,
            EnvironmentSource::Field(reference) => Some((binding.name.as_str(), reference)),
        })
        .chain(
            prepared
                .files
                .iter()
                .map(|binding| (binding.name.as_str(), &binding.source)),
        )
        .map(|(name, reference)| {
            let (target_item_id, field_id) = target_ids
                .get(reference)
                .copied()
                .ok_or_else(invalid_execution_arguments)?;
            Ok(EnvironmentInjectionV1 {
                name: BoundedBytes::<128>::new(name.as_bytes().to_vec())
                    .map_err(|_| invalid_execution_arguments())?,
                target: WitnessTargetV1 {
                    item_id: target_item_id,
                    field_id: Some(field_id),
                },
            })
        })
        .collect::<Result<Vec<_>, CliError>>()?;
    environment_injections.sort_by(|left, right| left.name.as_bytes().cmp(right.name.as_bytes()));
    let stdin_target = prepared
        .stdin
        .as_ref()
        .map(|reference| {
            target_ids
                .get(reference)
                .copied()
                .map(|(target_item_id, field_id)| WitnessTargetV1 {
                    item_id: target_item_id,
                    field_id: Some(field_id),
                })
                .ok_or_else(invalid_execution_arguments)
        })
        .transpose()?;
    let manifest_arguments = prepared
        .command
        .arguments
        .iter()
        .map(|argument| {
            jury_protocol::witness_v1::OperationBytes::new(argument.as_os_str().as_bytes().to_vec())
                .map(|bytes| ManifestArgumentV1::PublicLiteral { bytes })
                .map_err(|_| invalid_execution_arguments())
        })
        .collect::<Result<Vec<_>, _>>()?;
    let timeout_ms = prepared
        .timeout
        .map(|timeout| {
            u64::try_from(timeout.as_millis()).map_err(|_| invalid_execution_arguments())
        })
        .transpose()?
        .unwrap_or(0);
    let output_limit_bytes =
        u32::try_from(prepared.output_limit).map_err(|_| invalid_execution_arguments())?;
    let action = WitnessActionRequest {
        item_id,
        field_ids,
        operation_context: if has_stdin {
            OperationContextV1::ChildStdin
        } else {
            OperationContextV1::ChildEnvironment
        },
        executable_identity: Some(execution_identity(&prepared.command)?),
        arguments: manifest_arguments,
        working_directory: Some(
            jury_protocol::witness_v1::OperationBytes::new(
                prepared
                    .command
                    .working_directory
                    .as_os_str()
                    .as_bytes()
                    .to_vec(),
            )
            .map_err(|_| invalid_execution_arguments())?,
        ),
        environment_injections,
        stdin_target,
        stdin_mode: if has_stdin {
            StdinModeV1::SecretBytes
        } else {
            StdinModeV1::None
        },
        output_sink: OutputSinkV1::Stdout,
        output_destination: None,
        timeout_ms,
        output_limit_bytes,
    };
    let mut authorization = collect_witness_authorization(
        &context,
        action,
        &endpoints,
        &WitnessActionFiles {
            checkpoint: checkpoint_path,
            request_out,
            approvals: files.approvals,
            wait_seconds: files.wait_seconds,
        },
        protection,
    )?;
    let mut state = open_witnessed_body(&context, item_id, &mut authorization)?;
    let mut values = BTreeMap::new();
    let mut total_value_bytes = 0_usize;
    for (reference, (_, field_id)) in target_ids {
        let field = state
            .fields
            .iter()
            .find(|field| field.field_id == field_id)
            .ok_or_else(field_unavailable)?;
        total_value_bytes = total_value_bytes
            .checked_add(field.value.len())
            .filter(|total| *total <= MAX_ENV_TOTAL_BYTES)
            .ok_or_else(invalid_execution_arguments)?;
        values.insert(
            reference,
            ResolvedField {
                value: protect(field.value.as_bytes(), protection)?,
                concealed: field.kind == ItemFieldKind::Concealed,
            },
        );
    }
    state.clear_sensitive();
    let receipt_digest = publish_witness_receipt(&context, &authorization, receipt_destination)?;
    let operation_id = random_operation_id()?;
    run_resolved(
        &context,
        prepared,
        ResolvedExecution {
            values,
            item_ids: vec![item_id],
        },
        operation_id,
        protection,
        ExecutionEvidence {
            authority: ExecutionAuthority::WitnessedApproved,
            receipt: Some(receipt_path.display().to_string()),
            receipt_digest: Some(hex(receipt_digest.as_bytes())),
            receipt_nonclaim: Some(VerifiedWitnessReceipt::NONCLAIM),
        },
    )
}
fn execution_identity(
    command: &NormalizedCommand,
) -> Result<jury_protocol::witness_v1::OperationBytes, CliError> {
    let metadata = command
        .executable
        .metadata()
        .map_err(|_| invalid_execution_path())?;
    let path = command
        .executable_path
        .to_str()
        .ok_or_else(invalid_execution_path)?;
    let descriptor = format!(
        "jury-executable-v1|{path}|{}|{}|{}|{}",
        metadata.dev(),
        metadata.ino(),
        metadata.mode(),
        metadata.len()
    );
    jury_protocol::witness_v1::OperationBytes::new(descriptor.into_bytes())
        .map_err(|_| invalid_execution_arguments())
}
