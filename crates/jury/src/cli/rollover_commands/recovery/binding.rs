use super::*;

/// The existing owner-MAC audit event authenticates this operation digest.
/// Exclude local file hashes to avoid a self-reference through the audit bytes.
/// Payload hashes and the exact checkpoint prevent internally consistent
/// changes to an otherwise unsigned recovery snapshot from authorizing a retry.
#[derive(serde::Serialize)]
struct PublicationBinding<'a> {
    purpose: &'static str,
    out: &'a Path,
    backup_out: &'a Path,
    transfer_out: &'a Path,
    state_root: &'a Path,
    source_digest: Digest32,
    vault_digest: Digest32,
    backup_digest: Digest32,
    transfer_digest: Digest32,
    registration_checkpoint: Option<&'a VaultPolicyCheckpointV1>,
}

pub(in crate::cli::rollover_commands) fn publication_operation_id(
    arguments: &VaultRolloverArgs,
    state_root: &Path,
    source_bytes: &[u8],
    vault_bytes: &[u8],
    backup_bytes: &[u8],
    transfer_bytes: &[u8],
    registration_checkpoint: Option<&VaultPolicyCheckpointV1>,
) -> Result<Digest32, CliError> {
    let binding = PublicationBinding {
        purpose: "jury-rollover-publication-v1",
        out: &arguments.out,
        backup_out: &arguments.backup_out,
        transfer_out: &arguments.transfer_out,
        state_root,
        source_digest: sha256_digest(source_bytes),
        vault_digest: sha256_digest(vault_bytes),
        backup_digest: sha256_digest(backup_bytes),
        transfer_digest: sha256_digest(transfer_bytes),
        registration_checkpoint,
    };
    Ok(sha256_digest(
        &serde_json::to_vec(&binding).map_err(|_| incomplete_rollover())?,
    ))
}
