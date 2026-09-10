#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnerAccessPlan {
    version: u16,
    total_wait_seconds: u64,
    entries: Vec<OwnerAccessEntry>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnerAccessEntry {
    item_id: String,
    content_role: ContentRole,
    checkpoint: PathBuf,
    request_out: PathBuf,
    receipt: PathBuf,
    #[serde(default)]
    approvals: Vec<PathBuf>,
    witnesses: Vec<String>,
    #[serde(default)]
    allow_insecure_loopback: bool,
    wait_seconds: u64,
}

struct OpenedOwnerItem {
    accessible: AccessibleItem,
    state: ItemStateV1,
}

impl Drop for OpenedOwnerItem {
    fn drop(&mut self) {
        self.accessible.descriptor.clear_sensitive();
        self.state.clear_sensitive();
    }
}

struct OwnerAccessEntryContext {
    entry: OwnerAccessEntry,
    endpoints: Vec<WitnessEndpointClient>,
    checkpoint: jury_protocol::witness_v1::VaultPolicyCheckpointV1,
}

fn open_owner_change_items(
    context: &VaultPrincipalContext,
    arguments: &PrincipalTargetArgs,
    grant: bool,
    principal_id: PrincipalId,
    protection: ProtectionPolicy,
) -> Result<Vec<OpenedOwnerItem>, CliError> {
    let mut opened = discover_accessible_items(context)?
        .into_iter()
        .map(|accessible| OpenedOwnerItem {
            accessible,
            state: ItemStateV1 {
                plaintext_schema: 1,
                fields: Vec::new(),
            },
        })
        .collect::<Vec<_>>();
    let direct_ids = opened
        .iter()
        .map(|item| context.vault.items[item.accessible.envelope_index].item_id)
        .collect::<BTreeSet<_>>();
    let missing = context
        .vault
        .items
        .iter()
        .enumerate()
        .filter(|(_, item)| !direct_ids.contains(&item.item_id))
        .map(|(index, item)| (item.item_id, index))
        .collect::<BTreeMap<_, _>>();
    let plan = match &arguments.administrative_access {
        Some(path) => {
            let bytes = read_public_file(path, 1024 * 1024).map_err(map_filesystem_error)?;
            serde_json::from_slice::<OwnerAccessPlan>(&bytes)
                .map_err(|_| invalid_owner_access_plan())?
        }
        None if missing.is_empty() => OwnerAccessPlan {
            version: 1,
            total_wait_seconds: 300,
            entries: Vec::new(),
        },
        None => {
            return Err(CliError::new(
                CliErrorKind::InvalidArguments,
                "owner-change-authorization-required",
                "owner changes require current descriptor and body approvals for every witnessed-only item; supply --administrative-access FILE (see docs/owner-changes.md)",
            ));
        }
    };
    if plan.version != 1
        || !(1..=86_400).contains(&plan.total_wait_seconds)
        || plan.entries.len() != missing.len() * 2
    {
        return Err(invalid_owner_access_plan());
    }
    let mut entries = BTreeMap::new();
    let mut destinations = BTreeSet::new();
    for entry in plan.entries {
        let item_id = parse_item_id(&entry.item_id)?;
        let key = (item_id, entry.content_role.tag());
        if !missing.contains_key(&item_id)
            || entries.contains_key(&key)
            || entry.wait_seconds > 900
            || entry.witnesses.is_empty()
            || !destinations.insert(entry.request_out.clone())
            || !destinations.insert(entry.receipt.clone())
        {
            return Err(invalid_owner_access_plan());
        }
        prepare_witness_receipt_destination(&entry.request_out)?;
        prepare_witness_receipt_destination(&entry.receipt)?;
        let endpoints = entry
            .witnesses
            .iter()
            .map(|spec| WitnessEndpointClient::load(spec, entry.allow_insecure_loopback))
            .collect::<Result<Vec<_>, _>>()?;
        let checkpoint = read_checkpoint(&entry.checkpoint)?;
        entries.insert(
            key,
            OwnerAccessEntryContext {
                entry,
                endpoints,
                checkpoint,
            },
        );
    }
    let direct_count = opened.len();
    let deadline =
        std::time::Instant::now() + std::time::Duration::from_secs(plan.total_wait_seconds);
    for (item_id, envelope_index) in missing {
        let descriptor_entry = entries
            .remove(&(item_id, ContentRole::Descriptor.tag()))
            .ok_or_else(invalid_owner_access_plan)?;
        let mut authorization = collect_owner_change_authorization(
            context,
            item_id,
            principal_id,
            grant,
            descriptor_entry,
            deadline,
            protection,
        )?;
        let descriptor = open_witnessed_descriptor(context, item_id, &mut authorization.0)?;
        opened.push(OpenedOwnerItem {
            accessible: AccessibleItem {
                envelope_index,
                descriptor,
            },
            state: ItemStateV1 {
                plaintext_schema: 1,
                fields: Vec::new(),
            },
        });
        publish_witness_receipt(context, &authorization.0, authorization.1)?;
        let body_entry = entries
            .remove(&(item_id, ContentRole::Body.tag()))
            .ok_or_else(invalid_owner_access_plan)?;
        let mut authorization = collect_owner_change_authorization(
            context,
            item_id,
            principal_id,
            grant,
            body_entry,
            deadline,
            protection,
        )?;
        let item = opened.last_mut().ok_or_else(invalid_vault)?;
        item.state = open_witnessed_body(context, item_id, &mut authorization.0)?;
        publish_witness_receipt(context, &authorization.0, authorization.1)?;
    }
    for item in &mut opened[..direct_count] {
        item.state = open_item_body(context, &item.accessible, Capability::Administer)?;
    }
    if opened.len() != context.policy.item_count() || !entries.is_empty() {
        return Err(invalid_vault());
    }
    Ok(opened)
}

fn collect_owner_change_authorization(
    context: &VaultPrincipalContext,
    item_id: ItemId,
    principal_id: PrincipalId,
    grant: bool,
    input: OwnerAccessEntryContext,
    deadline: std::time::Instant,
    protection: ProtectionPolicy,
) -> Result<
    (
        CollectedWitnessAuthorization,
        PreparedWitnessReceiptDestination,
    ),
    CliError,
> {
    use jury_protocol::witness_v1::OwnerChangeKindV1;
    let entry = input.entry;
    let prepared = WitnessRequestCreator::new(protection).create_owner_change(
        WitnessRequestContext { policy: &context.policy, checkpoint: &input.checkpoint,
            requester: &context.identity, now_ms: timestamp_ms()?,
            review_labels: review_labels_for_item(context, &item_id, entry.content_role)? },
        item_id, entry.content_role, if grant { OwnerChangeKindV1::Grant } else { OwnerChangeKindV1::Revoke }, principal_id,
    ).map_err(|_| CliError::new(CliErrorKind::AccessDenied, "owner-change-not-authorized",
        "the current item policy must authorize administrative-rekey with human approvals for this owner change"))?;
    let receipt = prepare_witness_receipt_destination(&entry.receipt)?;
    let files = WitnessActionFiles {
        checkpoint: &entry.checkpoint,
        request_out: &entry.request_out,
        approvals: &entry.approvals,
        wait_seconds: entry.wait_seconds,
    };
    let authorization = collect_prepared_witness_authorization(
        context,
        prepared,
        &input.endpoints,
        &files,
        input.checkpoint,
        Some(deadline),
    )?;
    Ok((authorization, receipt))
}

const fn invalid_owner_access_plan() -> CliError {
    CliError::new(
        CliErrorKind::InvalidArguments,
        "invalid-owner-access-plan",
        "provide exactly one descriptor and one body entry for every witnessed-only item, unique absent request/receipt destinations, waits of 0..=900 seconds, and a total_wait_seconds budget of 1..=86400",
    )
}
