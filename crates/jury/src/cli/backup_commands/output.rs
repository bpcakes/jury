use super::*;

pub(super) fn recovery_output(
    operation: &'static str,
    header: &jury_protocol::backup_v1::BackupHeaderV1,
    coverage: &RecoveryCoverage,
    details: serde_json::Value,
    lines: Vec<String>,
) -> CommandOutput {
    CommandOutput::Safe {
        operation,
        fields: serde_json::json!({
            "backup_id": hex(header.backup_id.as_bytes()),
            "vault_id": hex(header.vault_id.as_bytes()),
            "genesis_fingerprint": hex(header.genesis_fingerprint.as_bytes()),
            "captured_public_revision": hex(header.source_public_revision_hash.as_bytes()),
            "owner_principal_id": hex(header.owner_principal_id.as_bytes()),
            "owner_descriptor_fingerprint": hex(header.owner_descriptor_fingerprint.as_bytes()),
            "kdf_profile": kdf_profile(header.kdf_profile),
            "target_bucket_bytes": bytes_for_bucket(header.target_bucket_id),
            "included_identity_roles": coverage.identity_roles.iter().map(role_name).collect::<Vec<_>>(),
            "direct_item_ids": coverage.direct_item_ids.iter().map(|id| hex(id.as_bytes())).collect::<Vec<_>>(),
            "witnessed_item_ids": coverage.witnessed_item_ids.iter().map(|id| hex(id.as_bytes())).collect::<Vec<_>>(),
            "unavailable_witnessed_item_ids": coverage.unavailable_witnessed_item_ids.iter().map(|id| hex(id.as_bytes())).collect::<Vec<_>>(),
            "checkpoints_current": coverage.checkpoints_current,
            "external_witness_recovery_required": coverage.external_witness_recovery_required,
            "recovers_juryd_replay_state": false,
            "recovers_external_anchors": false,
            "proves_witness_availability": false,
            "proves_quorum_availability": false,
            "details": details,
        }),
        lines,
    }
}

pub(super) fn coverage_lines(coverage: &RecoveryCoverage) -> Vec<String> {
    vec![
        format!(
            "Included local roles: {}",
            coverage
                .identity_roles
                .iter()
                .map(role_name)
                .collect::<Vec<_>>()
                .join(", ")
        ),
        format!("Directly recoverable items: {}", coverage.direct_item_ids.len()),
        format!("Witnessed items requiring external recovery: {}", coverage.witnessed_item_ids.len()),
        "This does not recover juryd replay state, external anchors, witness availability, or quorum availability."
            .to_owned(),
    ]
}

const fn role_name(role: &RecoveryRole) -> &'static str {
    match role {
        RecoveryRole::VaultPrincipal => "vault-principal",
        RecoveryRole::Approver => "approver",
        RecoveryRole::WitnessClient => "witness-client",
    }
}

fn bytes_for_bucket(bucket: u8) -> Option<usize> {
    jury_protocol::backup_v1::bucket_bytes(bucket).ok()
}
