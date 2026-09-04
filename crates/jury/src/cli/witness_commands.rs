use super::*;

pub(super) fn witness_checkpoint(
    cli: &Cli,
    arguments: &WitnessCheckpointArgs,
    environment: &Environment,
    current: &Path,
    protection: ProtectionPolicy,
) -> Result<CommandOutput, CliError> {
    let item_id = parse_item_id(&arguments.item_id)?;
    let context = load_vault_principal(cli, environment, current, protection)?;
    require_owner(&context)?;
    let item = context.policy.item(&item_id).ok_or_else(item_unavailable)?;
    let witnessed = item.witnessed_state.as_ref().ok_or_else(|| {
        CliError::new(
            CliErrorKind::Conflict,
            "witnessed-authority-unavailable",
            "the selected item does not have witnessed authority",
        )
    })?;
    let mut policy_digests = witnessed
        .slots
        .iter()
        .map(|slot| slot.witness_policy_digest.clone())
        .collect::<BTreeSet<_>>();
    if policy_digests.len() != 1 {
        return Err(invalid_vault());
    }
    let witness_policy_digest = policy_digests.pop_first().ok_or_else(invalid_vault)?;
    let predecessor_checkpoint_digest = match &arguments.predecessor {
        Some(path) => {
            let checkpoint = read_checkpoint(path)?;
            if checkpoint.vault_id != context.policy.vault_id()
                || checkpoint.genesis_fingerprint != *context.policy.genesis_fingerprint()
            {
                return Err(invalid_checkpoint());
            }
            checkpoint.digest().map_err(|_| invalid_checkpoint())?
        }
        None => Digest32::new([0; 32]),
    };
    let checkpoint = VaultPolicyCheckpointCreator::create(
        &context.policy,
        &witness_policy_digest,
        predecessor_checkpoint_digest,
        &context.identity,
        timestamp_ms()?,
    )
    .map_err(|_| invalid_checkpoint())?;
    let bytes = serde_json::to_vec(&checkpoint).map_err(|_| invalid_checkpoint())?;
    let destination = preview_public_file(&arguments.output).map_err(map_filesystem_error)?;
    let publication = PreparedPublicFile::prepare_bounded_if_unchanged(
        destination,
        &bytes,
        MAX_RECEIPT_JSON_BYTES,
        false,
    )
    .map_err(map_filesystem_error)?
    .publish()
    .map_err(map_filesystem_error)?;
    let checkpoint_digest = checkpoint.digest().map_err(|_| invalid_checkpoint())?;
    Ok(CommandOutput::Safe {
        operation: "witness-checkpoint",
        fields: serde_json::json!({
            "item_id": hex(item_id.as_bytes()),
            "checkpoint_digest": hex(checkpoint_digest.as_bytes()),
            "witness_policy_digest": hex(witness_policy_digest.as_bytes()),
            "policy_sequence": checkpoint.vault_policy_sequence,
            "output": arguments.output,
            "durability": durability(publication),
            "contains_private_material": false,
        }),
        lines: vec![
            format!(
                "Witness checkpoint: {}",
                grouped(&hex(checkpoint_digest.as_bytes()))
            ),
            format!("Policy sequence: {}", checkpoint.vault_policy_sequence),
            format!("Output: {}", arguments.output.display()),
            "Contains private material: false".to_owned(),
        ],
    })
}

pub(super) fn parse_item_id(value: &str) -> Result<ItemId, CliError> {
    let bytes = decode_hex_32(value).ok_or_else(|| {
        CliError::new(
            CliErrorKind::InvalidArguments,
            "invalid-item-id",
            "item IDs must be canonical lowercase hexadecimal",
        )
    })?;
    ItemId::from_bytes(bytes).map_err(|_| {
        CliError::new(
            CliErrorKind::InvalidArguments,
            "invalid-item-id",
            "item IDs must be canonical lowercase hexadecimal",
        )
    })
}

pub(super) fn witness_policy_material(
    cli: &Cli,
    arguments: &WitnessPolicyMaterialArgs,
    environment: &Environment,
    current: &Path,
) -> Result<CommandOutput, CliError> {
    let home = selected_home(cli, environment, current)?;
    let vault_bytes = read_vault(&home)?;
    let vault = VaultFileV1::parse(&vault_bytes).map_err(|_| invalid_vault())?;
    let catalog = load_policy_catalog_for_vault(environment, &home, &vault)?;
    let material = ReceiptPolicyMaterialV1 {
        schema: 1,
        journal: vault.policy.clone(),
        witness_policies: catalog.witness_policies,
    };
    let policy = material.replay().map_err(|_| invalid_policy_material())?;
    let encoded = material.encode().map_err(|_| {
        CliError::new(
            CliErrorKind::Conflict,
            "witness-policy-material-capacity-exhausted",
            "the public witness policy material exceeds the protocol capacity",
        )
    })?;
    let bytes = encoded.as_bytes();
    let destination = preview_public_file(&arguments.output).map_err(map_filesystem_error)?;
    let publication = PreparedPublicFile::prepare_bounded_if_unchanged(
        destination,
        bytes,
        MAX_RECEIPT_JSON_BYTES,
        false,
    )
    .map_err(map_filesystem_error)?
    .publish()
    .map_err(map_filesystem_error)?;
    let digest = Digest32::new(Sha256::digest(bytes).into());
    Ok(CommandOutput::Safe {
        operation: "witness-policy-material",
        fields: serde_json::json!({
            "output": arguments.output,
            "policy_sequence": policy.sequence(),
            "witness_policy_count": material.witness_policies.len(),
            "sha256": hex(digest.as_bytes()),
            "durability": durability(publication),
            "contains_private_material": false,
        }),
        lines: vec![
            format!(
                "Witness policy material exported: {}",
                arguments.output.display()
            ),
            format!("Policy sequence: {}", policy.sequence()),
            "Contains private material: false".to_owned(),
        ],
    })
}

pub(super) fn witness_policy_status(
    arguments: &WitnessPolicyStatusArgs,
) -> Result<CommandOutput, CliError> {
    let material_bytes = read_public_file(&arguments.policy_material, MAX_RECEIPT_JSON_BYTES)
        .map_err(map_filesystem_error)?;
    let encoded =
        PolicyMaterialBytes::new(material_bytes).map_err(|_| invalid_policy_material())?;
    let material =
        ReceiptPolicyMaterialV1::decode(&encoded).map_err(|_| invalid_policy_material())?;
    let policy = material.replay().map_err(|_| invalid_policy_material())?;
    let checkpoint = read_checkpoint(&arguments.checkpoint)?;
    let acknowledgements = arguments
        .acknowledgements
        .iter()
        .map(|path| read_acknowledgement(path))
        .collect::<Result<Vec<_>, _>>()?;
    let status = verify_checkpoint_propagation(&policy, &checkpoint, &acknowledgements)
        .map_err(|_| invalid_acknowledgement())?;
    let acknowledged = status
        .acknowledgements
        .iter()
        .map(|acknowledgement| {
            serde_json::json!({
                "witness_id": hex(acknowledgement.witness_id.as_bytes()),
                "state_generation": acknowledgement.state_generation,
                "anchor_digest": hex(acknowledgement.anchor_digest.as_bytes()),
            })
        })
        .collect::<Vec<_>>();
    Ok(CommandOutput::Safe {
        operation: "witness-policy-status",
        fields: serde_json::json!({
            "checkpoint_digest": hex(status.checkpoint_digest.as_bytes()),
            "phase": status.phase,
            "expected_witness_count": status.expected_witness_count,
            "acknowledged_witness_count": status.acknowledged_witness_count,
            "acknowledgements": acknowledged,
            "global_freshness_claimed": status.global_freshness_claimed,
            "offline": true,
        }),
        lines: vec![
            format!("Checkpoint propagation: {:?}", status.phase),
            format!(
                "Durable per-witness acknowledgements: {}/{}",
                status.acknowledged_witness_count, status.expected_witness_count
            ),
            "Global freshness claimed: false".to_owned(),
        ],
    })
}

fn read_acknowledgement(path: &Path) -> Result<WitnessCheckpointAcknowledgementV1, CliError> {
    let bytes = read_public_file(path, MAX_RECEIPT_JSON_BYTES).map_err(map_filesystem_error)?;
    let value = serde_json::from_slice::<serde_json::Value>(&bytes)
        .map_err(|_| invalid_acknowledgement())?;
    let acknowledgement = value.get("acknowledgement").cloned().unwrap_or(value);
    serde_json::from_value::<WitnessCheckpointAcknowledgementV1>(acknowledgement)
        .map_err(|_| invalid_acknowledgement())
}

const fn invalid_policy_material() -> CliError {
    CliError::new(
        CliErrorKind::InvalidArguments,
        "invalid-witness-policy-material",
        "the owner-signed witness policy material is invalid",
    )
}

const fn invalid_acknowledgement() -> CliError {
    CliError::new(
        CliErrorKind::AuthenticationFailed,
        "invalid-witness-acknowledgement",
        "one or more per-witness checkpoint acknowledgements did not verify",
    )
}
