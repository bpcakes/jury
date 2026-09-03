use super::*;

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
    let bytes = serde_json::to_vec(&material).map_err(|_| invalid_policy_material())?;
    PolicyMaterialBytes::new(bytes.clone()).map_err(|_| {
        CliError::new(
            CliErrorKind::Conflict,
            "witness-policy-material-capacity-exhausted",
            "the public witness policy material exceeds the protocol capacity",
        )
    })?;
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
    let digest = Digest32::new(Sha256::digest(&bytes).into());
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
    let material = serde_json::from_slice::<ReceiptPolicyMaterialV1>(&material_bytes)
        .map_err(|_| invalid_policy_material())?;
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
