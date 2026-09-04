use super::*;

pub(super) const MAX_TEMPLATE_BYTES: usize = 1_048_576;
pub(super) const MAX_TEMPLATE_OUTPUT_BYTES: usize = 8_388_608;
pub(super) const MAX_TEMPLATE_REFERENCES: usize = 1_024;
pub(super) const MAX_TEMPLATE_ITEMS: usize = 10;

pub(super) struct TemplateReference {
    pub(super) start: usize,
    pub(super) end: usize,
    pub(super) item: String,
    pub(super) field: String,
}

pub(super) fn template_inject(
    cli: &Cli,
    arguments: &InjectArgs,
    environment: &Environment,
    current: &Path,
    protection: ProtectionPolicy,
) -> Result<CommandOutput, CliError> {
    validate_plaintext_sink(cli, arguments.out.as_deref(), arguments.reveal)?;
    let template_bytes =
        read_public_file(&arguments.template, MAX_TEMPLATE_BYTES).map_err(map_filesystem_error)?;
    let template = std::str::from_utf8(&template_bytes).map_err(|_| invalid_template())?;
    let references = parse_template(template)?;
    if !arguments.direct {
        return witnessed_template_inject(
            cli,
            arguments,
            environment,
            current,
            protection,
            template,
            &references,
        );
    }
    let distinct_items = references
        .iter()
        .map(|reference| reference.item.clone())
        .collect::<BTreeSet<_>>();
    if distinct_items.len() > MAX_TEMPLATE_ITEMS {
        return Err(CliError::new(
            CliErrorKind::InvalidArguments,
            "template-item-limit",
            "the template references too many distinct items",
        ));
    }

    let context = load_vault_principal(cli, environment, current, protection)?;
    let mut accessible = accessible_items_by_name(&context)?;

    // Resolve every item name before opening any body. A denied multi-item
    // operation therefore reaches no output sink and decrypts no item body.
    if distinct_items
        .iter()
        .any(|item| !accessible.contains_key(item))
    {
        return Err(item_unavailable());
    }
    let audited_item_ids = distinct_items
        .iter()
        .map(|name| {
            accessible
                .get(name)
                .map(|item| context.vault.items[item.envelope_index].item_id)
                .ok_or_else(item_unavailable)
        })
        .collect::<Result<Vec<_>, CliError>>()?;

    let requested_fields = references
        .iter()
        .map(|reference| (reference.item.clone(), reference.field.clone()))
        .collect::<BTreeSet<_>>();
    let mut values = BTreeMap::<(String, String), Zeroizing<Vec<u8>>>::new();
    for item_name in distinct_items {
        let item = accessible.remove(&item_name).ok_or_else(item_unavailable)?;
        let mut state = open_item_body(&context, &item, Capability::Read)?;
        for (_, field_name) in requested_fields
            .iter()
            .filter(|(requested_item, _)| requested_item == &item_name)
        {
            let field = state
                .fields
                .iter()
                .find(|field| &field.name == field_name)
                .ok_or_else(field_unavailable)?;
            values.insert(
                (item_name.clone(), field_name.clone()),
                Zeroizing::new(field.value.as_bytes().to_vec()),
            );
        }
        state.clear_sensitive();
    }

    let mut output = Zeroizing::new(Vec::new());
    output
        .try_reserve_exact(MAX_TEMPLATE_OUTPUT_BYTES)
        .map_err(|_| filesystem_error())?;
    let mut cursor = 0;
    for reference in &references {
        append_bounded_output(&mut output, &template.as_bytes()[cursor..reference.start])?;
        let value = values
            .get(&(reference.item.clone(), reference.field.clone()))
            .ok_or_else(field_unavailable)?;
        append_bounded_output(&mut output, value)?;
        cursor = reference.end;
    }
    append_bounded_output(&mut output, &template.as_bytes()[cursor..])?;
    append_operational_audit(
        &context,
        AuditAction::ExecuteOrInject,
        &audited_item_ids,
        protection,
    )?;

    if let Some(path) = &arguments.out {
        let outcome = write_private_file(
            &context.home,
            path,
            &output,
            arguments.overwrite,
            protection,
        )?;
        Ok(CommandOutput::PrivateOutput {
            operation: "template-inject",
            item: None,
            field: None,
            sink: "private-file",
            durability: Some(durability(outcome)),
            authority: "direct-unilateral",
        })
    } else {
        eprintln!("Authority: direct-unilateral");
        let mut stdout = std::io::stdout().lock();
        stdout
            .write_all(&output)
            .and_then(|()| stdout.flush())
            .map_err(|_| filesystem_error())?;
        Ok(CommandOutput::Silent)
    }
}

fn witnessed_template_inject(
    cli: &Cli,
    arguments: &InjectArgs,
    environment: &Environment,
    current: &Path,
    protection: ProtectionPolicy,
    template: &str,
    references: &[TemplateReference],
) -> Result<CommandOutput, CliError> {
    use jury_protocol::witness_v1::{
        OperationBytes, OperationContextV1, OutputSinkV1, StdinModeV1,
    };

    let checkpoint_path = arguments
        .checkpoint
        .as_deref()
        .ok_or_else(witnessed_template_arguments_required)?;
    let request_out = arguments
        .request_out
        .as_deref()
        .ok_or_else(witnessed_template_arguments_required)?;
    let receipt_path = arguments
        .receipt
        .as_deref()
        .ok_or_else(witnessed_template_arguments_required)?;
    read_checkpoint(checkpoint_path)?;
    let output_destination = arguments
        .out
        .as_deref()
        .map(normalized_private_output)
        .transpose()?
        .map(OperationBytes::new)
        .transpose()
        .map_err(|_| invalid_template())?;
    let endpoints = arguments
        .witnesses
        .iter()
        .map(|specification| {
            WitnessEndpointClient::parse(specification, arguments.allow_insecure_loopback)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let context = load_vault_principal(cli, environment, current, protection)?;
    let checkpoint = read_checkpoint(checkpoint_path)?;
    let review_labels = review_labels_for_checkpoint(&context.catalog, &checkpoint)?;
    let mut target_ids = BTreeMap::new();
    for reference in references {
        let target = resolve_request_target(
            &review_labels,
            Some(&reference.item),
            None,
            Some(&reference.field),
            None,
        )?;
        target_ids.insert((reference.item.clone(), reference.field.clone()), target);
    }
    let item_ids = target_ids
        .values()
        .map(|(item_id, _)| *item_id)
        .collect::<BTreeSet<_>>();
    if item_ids.len() != 1 {
        return Err(CliError::new(
            CliErrorKind::InvalidArguments,
            "governed-template-single-item-required",
            "one governed template request may reference exactly one witnessed item",
        ));
    }
    let item_id = item_ids
        .iter()
        .next()
        .copied()
        .ok_or_else(invalid_template)?;
    let field_ids = target_ids
        .values()
        .map(|(_, field_id)| *field_id)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let manifest_arguments = template_manifest_arguments(template, references, &target_ids)?;
    let working_directory = std::fs::canonicalize(current)
        .map_err(|_| invalid_template())?
        .to_str()
        .ok_or_else(invalid_template)?
        .as_bytes()
        .to_vec();
    let action = WitnessActionRequest {
        item_id,
        field_ids,
        operation_context: OperationContextV1::TemplateInjection,
        executable_identity: Some(template_executable_identity()?),
        arguments: manifest_arguments,
        working_directory: Some(
            OperationBytes::new(working_directory).map_err(|_| invalid_template())?,
        ),
        environment_injections: Vec::new(),
        stdin_target: None,
        stdin_mode: StdinModeV1::None,
        output_sink: if arguments.out.is_some() {
            OutputSinkV1::PrivateFile
        } else {
            OutputSinkV1::Stdout
        },
        output_destination,
        timeout_ms: 0,
        output_limit_bytes: u32::try_from(MAX_TEMPLATE_OUTPUT_BYTES)
            .map_err(|_| invalid_template())?,
    };
    let authorization = collect_witness_authorization(
        &context,
        action,
        &endpoints,
        &WitnessActionFiles {
            checkpoint: checkpoint_path,
            request_out,
            approvals: &arguments.approvals,
            wait_seconds: arguments.wait_seconds,
        },
        protection,
    )?;
    let mut state = open_witnessed_body(&context, item_id, &authorization)?;
    let mut values = BTreeMap::<(String, String), Zeroizing<Vec<u8>>>::new();
    for (name, (_, field_id)) in target_ids {
        let field = state
            .fields
            .iter()
            .find(|field| field.field_id == field_id)
            .ok_or_else(field_unavailable)?;
        values.insert(name, Zeroizing::new(field.value.as_bytes().to_vec()));
    }
    state.clear_sensitive();
    let output = render_template(template, references, &values)?;
    let receipt_digest = publish_witness_receipt(&context, &authorization, receipt_path)?;
    append_operational_audit(
        &context,
        AuditAction::ExecuteOrInject,
        &[item_id],
        protection,
    )?;
    if let Some(path) = &arguments.out {
        let outcome = write_private_file(
            &context.home,
            path,
            &output,
            arguments.overwrite,
            protection,
        )?;
        Ok(CommandOutput::Safe {
            operation: "template-inject",
            fields: serde_json::json!({
                "authority": "witnessed-approved",
                "sink": "private-file",
                "durability": durability(outcome),
                "request_id": hex(authorization.prepared.request.request_id.as_bytes()),
                "receipt": receipt_path,
                "receipt_digest": hex(receipt_digest.as_bytes()),
                "receipt_nonclaim": VerifiedWitnessReceipt::NONCLAIM,
                "plaintext_in_structured_output": false,
            }),
            lines: vec![
                "Template injection completed".to_owned(),
                "Authority: witnessed-approved".to_owned(),
                format!("Private output: {}", path.display()),
                format!("Receipt: {}", receipt_path.display()),
                VerifiedWitnessReceipt::NONCLAIM.to_owned(),
            ],
        })
    } else {
        eprintln!("Authority: witnessed-approved");
        eprintln!("Receipt: {}", receipt_path.display());
        eprintln!("{}", VerifiedWitnessReceipt::NONCLAIM);
        let mut stdout = std::io::stdout().lock();
        stdout
            .write_all(&output)
            .and_then(|()| stdout.flush())
            .map_err(|_| filesystem_error())?;
        Ok(CommandOutput::Silent)
    }
}

fn template_manifest_arguments(
    template: &str,
    references: &[TemplateReference],
    targets: &BTreeMap<(String, String), (ItemId, FieldId)>,
) -> Result<Vec<jury_protocol::witness_v1::ManifestArgumentV1>, CliError> {
    use jury_protocol::witness_v1::{ManifestArgumentV1, WitnessTargetV1};
    let mut arguments = Vec::new();
    let mut cursor = 0;
    for reference in references {
        append_public_manifest_bytes(
            &mut arguments,
            &template.as_bytes()[cursor..reference.start],
        )?;
        let (item_id, field_id) = targets
            .get(&(reference.item.clone(), reference.field.clone()))
            .ok_or_else(invalid_template)?;
        arguments.push(ManifestArgumentV1::SecretPlaceholder {
            target: WitnessTargetV1 {
                item_id: *item_id,
                field_id: Some(*field_id),
            },
        });
        cursor = reference.end;
    }
    append_public_manifest_bytes(&mut arguments, &template.as_bytes()[cursor..])?;
    if arguments.len() > jury_protocol::witness_v1::MAX_ARGUMENTS {
        return Err(invalid_template());
    }
    Ok(arguments)
}

fn append_public_manifest_bytes(
    arguments: &mut Vec<jury_protocol::witness_v1::ManifestArgumentV1>,
    mut bytes: &[u8],
) -> Result<(), CliError> {
    use jury_protocol::witness_v1::{ManifestArgumentV1, OperationBytes};
    while !bytes.is_empty() {
        let take = bytes.len().min(4_096);
        arguments.push(ManifestArgumentV1::PublicLiteral {
            bytes: OperationBytes::new(bytes[..take].to_vec()).map_err(|_| invalid_template())?,
        });
        bytes = &bytes[take..];
    }
    Ok(())
}

fn template_executable_identity() -> Result<jury_protocol::witness_v1::OperationBytes, CliError> {
    use std::os::unix::fs::MetadataExt as _;
    let path = std::fs::canonicalize("/proc/self/exe").map_err(|_| invalid_template())?;
    let metadata = std::fs::metadata(&path).map_err(|_| invalid_template())?;
    let path = path.to_str().ok_or_else(invalid_template)?;
    let descriptor = format!(
        "jury-template-renderer-v1|{path}|{}|{}|{}|{}",
        metadata.dev(),
        metadata.ino(),
        metadata.mode(),
        metadata.len()
    );
    jury_protocol::witness_v1::OperationBytes::new(descriptor.into_bytes())
        .map_err(|_| invalid_template())
}

fn normalized_private_output(path: &Path) -> Result<Vec<u8>, CliError> {
    if !path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )
        })
    {
        return Err(invalid_template());
    }
    let parent = std::fs::canonicalize(path.parent().ok_or_else(invalid_template)?)
        .map_err(|_| invalid_template())?;
    let normalized = parent.join(path.file_name().ok_or_else(invalid_template)?);
    normalized
        .to_str()
        .map(str::as_bytes)
        .map(<[u8]>::to_vec)
        .ok_or_else(invalid_template)
}

fn render_template(
    template: &str,
    references: &[TemplateReference],
    values: &BTreeMap<(String, String), Zeroizing<Vec<u8>>>,
) -> Result<Zeroizing<Vec<u8>>, CliError> {
    let mut output = Zeroizing::new(Vec::new());
    output
        .try_reserve_exact(MAX_TEMPLATE_OUTPUT_BYTES)
        .map_err(|_| filesystem_error())?;
    let mut cursor = 0;
    for reference in references {
        append_bounded_output(&mut output, &template.as_bytes()[cursor..reference.start])?;
        let value = values
            .get(&(reference.item.clone(), reference.field.clone()))
            .ok_or_else(field_unavailable)?;
        append_bounded_output(&mut output, value)?;
        cursor = reference.end;
    }
    append_bounded_output(&mut output, &template.as_bytes()[cursor..])?;
    Ok(output)
}

const fn witnessed_template_arguments_required() -> CliError {
    CliError::new(
        CliErrorKind::InvalidArguments,
        "witnessed-execution-arguments-required",
        "governed injection requires --checkpoint, --request-out, --receipt, and the exact --witness set; use --direct only for visible unilateral access",
    )
}

pub(super) fn parse_template(template: &str) -> Result<Vec<TemplateReference>, CliError> {
    let bytes = template.as_bytes();
    let mut references = Vec::new();
    let mut cursor = 0;
    while cursor < bytes.len() {
        let Some(relative_start) = bytes[cursor..]
            .windows(2)
            .position(|window| window == b"{{")
        else {
            if bytes[cursor..].windows(2).any(|window| window == b"}}") {
                return Err(invalid_template());
            }
            break;
        };
        let start = cursor + relative_start;
        if bytes[cursor..start]
            .windows(2)
            .any(|window| window == b"}}")
        {
            return Err(invalid_template());
        }
        let content_start = start + 2;
        let relative_end = bytes[content_start..]
            .windows(2)
            .position(|window| window == b"}}")
            .ok_or_else(invalid_template)?;
        let content_end = content_start + relative_end;
        let content = &template[content_start..content_end];
        let (item, field) = content.split_once('.').ok_or_else(invalid_template)?;
        FieldSelector::parse(item.to_owned(), field.to_owned()).map_err(|_| invalid_template())?;
        references.push(TemplateReference {
            start,
            end: content_end + 2,
            item: item.to_owned(),
            field: field.to_owned(),
        });
        if references.len() > MAX_TEMPLATE_REFERENCES {
            return Err(CliError::new(
                CliErrorKind::InvalidArguments,
                "template-reference-limit",
                "the template contains too many field references",
            ));
        }
        cursor = content_end + 2;
    }
    if references.is_empty() {
        return Err(CliError::new(
            CliErrorKind::InvalidArguments,
            "template-has-no-references",
            "the injection template contains no field references",
        ));
    }
    Ok(references)
}

pub(super) fn append_bounded_output(output: &mut Vec<u8>, bytes: &[u8]) -> Result<(), CliError> {
    if output.len().saturating_add(bytes.len()) > MAX_TEMPLATE_OUTPUT_BYTES {
        return Err(CliError::new(
            CliErrorKind::InvalidArguments,
            "template-output-limit",
            "the resolved template exceeds the active output bound",
        ));
    }
    output.extend_from_slice(bytes);
    Ok(())
}
