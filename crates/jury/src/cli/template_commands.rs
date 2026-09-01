use super::*;

pub(super) const MAX_TEMPLATE_BYTES: usize = 1_048_576;
pub(super) const MAX_TEMPLATE_OUTPUT_BYTES: usize = 8_388_608;
pub(super) const MAX_TEMPLATE_REFERENCES: usize = 1_024;
pub(super) const MAX_TEMPLATE_ITEMS: usize = 10;

pub(super) struct TemplateReference {
    start: usize,
    end: usize,
    item: String,
    field: String,
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
        })
    } else {
        let mut stdout = std::io::stdout().lock();
        stdout
            .write_all(&output)
            .and_then(|()| stdout.flush())
            .map_err(|_| filesystem_error())?;
        Ok(CommandOutput::Silent)
    }
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
