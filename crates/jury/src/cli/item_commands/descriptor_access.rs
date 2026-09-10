use super::*;

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct DescriptorAccessPlan {
    version: u16,
    #[serde(default = "default_wait_seconds")]
    total_wait_seconds: u64,
    entries: Vec<DescriptorAccessEntry>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct DescriptorAccessEntry {
    item_id: String,
    checkpoint: PathBuf,
    request_out: PathBuf,
    receipt: PathBuf,
    #[serde(default)]
    approvals: Vec<PathBuf>,
    witnesses: Vec<String>,
    #[serde(default)]
    allow_insecure_loopback: bool,
    #[serde(default = "default_wait_seconds")]
    wait_seconds: u64,
}

const fn default_wait_seconds() -> u64 {
    300
}

struct Names(Vec<AccessibleItem>);

impl Drop for Names {
    fn drop(&mut self) {
        for item in &mut self.0 {
            item.descriptor.clear_sensitive();
        }
    }
}

pub(super) fn check_new_item_name(
    context: &VaultPrincipalContext,
    arguments: &ItemCreateArgs,
    protection: ProtectionPolicy,
) -> Result<(), CliError> {
    if context.vault.items.len() != context.policy.item_count() {
        return Err(invalid_vault());
    }
    let mut names = Names(discover_accessible_items(context)?);
    if names
        .0
        .iter()
        .any(|item| item.descriptor.name() == arguments.item)
    {
        return Err(duplicate_name());
    }
    let accessible = names
        .0
        .iter()
        .map(|item| context.vault.items[item.envelope_index].item_id)
        .collect::<BTreeSet<_>>();
    let missing = context
        .vault
        .items
        .iter()
        .enumerate()
        .filter(|(_, item)| !accessible.contains(&item.item_id))
        .map(|(index, item)| (item.item_id, index))
        .collect::<BTreeMap<_, _>>();
    let (entries, total_wait_seconds) = match &arguments.descriptor_access {
        Some(path) => {
            let bytes = read_public_file(path, 1024 * 1024).map_err(map_filesystem_error)?;
            let plan: DescriptorAccessPlan =
                serde_json::from_slice(&bytes).map_err(|_| invalid_access_plan())?;
            if plan.version != 1
                || plan.entries.len() > 1024
                || !(1..=86_400).contains(&plan.total_wait_seconds)
            {
                return Err(invalid_access_plan());
            }
            (plan.entries, plan.total_wait_seconds)
        }
        None if missing.is_empty() => (Vec::new(), 300),
        None => {
            return Err(CliError::new(
                CliErrorKind::InvalidArguments,
                "descriptor-authorization-required",
                "checking all item names requires fresh witnessed descriptor reads; supply --descriptor-access FILE (see docs/item-creation.md)",
            ));
        }
    };
    let mut by_item = BTreeMap::new();
    let mut destinations = BTreeSet::new();
    for entry in entries {
        let item_id = parse_item_id(&entry.item_id)?;
        if !missing.contains_key(&item_id)
            || entry.wait_seconds > 900
            || entry.witnesses.is_empty()
            || by_item.contains_key(&item_id)
            || !destinations.insert(entry.request_out.clone())
            || !destinations.insert(entry.receipt.clone())
        {
            return Err(invalid_access_plan());
        }
        by_item.insert(item_id, entry);
    }
    if by_item.len() != missing.len() {
        return Err(invalid_access_plan());
    }
    // Validate coverage and absent output destinations before issuing any
    // request. No vault mutation is committed until every name was authenticated.
    for entry in by_item.values() {
        prepare_witness_receipt_destination(&entry.request_out)?;
        prepare_witness_receipt_destination(&entry.receipt)?;
    }
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(total_wait_seconds);
    for (item_id, envelope_index) in missing {
        let entry = by_item.remove(&item_id).ok_or_else(invalid_access_plan)?;
        let checkpoint = read_checkpoint(&entry.checkpoint)?;
        let review_labels = review_labels_for_item(
            context,
            &item_id,
            jury_protocol::vault_v1::ContentRole::Descriptor,
        )?;
        let prepared = WitnessRequestCreator::new(protection)
            .create_descriptor_read_stdout(
                WitnessRequestContext {
                    policy: &context.policy,
                    checkpoint: &checkpoint,
                    requester: &context.identity,
                    review_labels,
                    now_ms: timestamp_ms()?,
                },
                item_id,
            )
            .map_err(|_| CliError::new(
                CliErrorKind::AccessDenied,
                "descriptor-read-not-authorized",
                "the checkpoint policy must explicitly authorize read-stdout for the item descriptor; select --automatic-descriptor or a human read rule when configuring it",
            ))?;
        let endpoints = entry
            .witnesses
            .iter()
            .map(|spec| WitnessEndpointClient::load(spec, entry.allow_insecure_loopback))
            .collect::<Result<Vec<_>, _>>()?;
        let files = WitnessActionFiles {
            checkpoint: &entry.checkpoint,
            request_out: &entry.request_out,
            approvals: &entry.approvals,
            wait_seconds: entry.wait_seconds,
        };
        let destination = prepare_witness_receipt_destination(&entry.receipt)?;
        let mut authorization = collect_prepared_witness_authorization(
            context,
            prepared,
            &endpoints,
            &files,
            checkpoint,
            Some(deadline),
        )?;
        let descriptor = open_witnessed_descriptor(context, item_id, &mut authorization)?;
        names.0.push(AccessibleItem {
            envelope_index,
            descriptor,
        });
        publish_witness_receipt(context, &authorization, destination)?;
    }
    if names.0.len() != context.policy.item_count() {
        return Err(invalid_vault());
    }
    let mut unique = BTreeSet::new();
    for item in &names.0 {
        if !unique.insert(item.descriptor.name()) {
            return Err(invalid_vault());
        }
    }
    if unique.contains(arguments.item.as_str()) {
        return Err(duplicate_name());
    }
    Ok(())
}

fn invalid_access_plan() -> CliError {
    CliError::new(
        CliErrorKind::InvalidArguments,
        "invalid-descriptor-access-plan",
        "provide exactly one entry for each witnessed-only descriptor, with unique request and receipt paths, entry waits of at most 900 seconds, and a total_wait_seconds budget of 1..=86400",
    )
}

fn duplicate_name() -> CliError {
    CliError::new(
        CliErrorKind::Conflict,
        "duplicate-item-name",
        "an active item already uses the selected name",
    )
}
