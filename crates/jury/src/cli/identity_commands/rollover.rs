use super::*;

#[cfg(test)]
mod tests;

pub(super) fn answer_rollover_proof(
    arguments: &IdentityProveArgs,
    source_vault: &VaultFileV1,
    source_catalog: &PolicyCatalogV1,
    identity: &UnlockedIdentity,
    challenge: &RegistrationChallengeV1,
    now_ms: u64,
) -> Result<RegistrationProofV1, CliError> {
    let path = arguments
        .rollover_draft
        .as_ref()
        .ok_or_else(invalid_draft)?;
    let bytes = read_public_file(path, MAX_VAULT_BYTES).map_err(map_filesystem_error)?;
    let journal: jury_protocol::vault_v1::PolicyJournalV1 =
        serde_json::from_slice(&bytes).map_err(|_| invalid_draft())?;
    if serde_json::to_vec(&journal).map_err(|_| invalid_draft())? != bytes {
        return Err(invalid_draft());
    }
    let source = jury_core::rollover::RolloverSource::validate(
        source_vault,
        &source_catalog.witness_policies,
    )
    .map_err(|_| invalid_draft())?;
    let initial = source
        .verify_registration_draft(&journal)
        .map_err(|_| invalid_draft())?;
    if arguments
        .expected_rollover_genesis
        .as_deref()
        .and_then(decode_presented_hex_32)
        .as_ref()
        != Some(initial.genesis_fingerprint().as_bytes())
    {
        return Err(CliError::new(
            CliErrorKind::Conflict,
            "rollover-genesis-fingerprint-mismatch",
            "the externally expected rollover genesis differs from the draft",
        ));
    }
    let catalog = source_catalog.transfer_catalog(source_vault)?;
    let prior_role = source
        .source_registration_role(&catalog, challenge.candidate_descriptor.principal_id)
        .map_err(|_| invalid_draft())?;
    jury_core::registration::answer_rollover_challenge(
        &initial, identity, challenge, prior_role, now_ms,
    )
    .map_err(|error| map_registration_error(error.kind()))
}

const fn invalid_draft() -> CliError {
    CliError::new(
        CliErrorKind::InvalidVault,
        "invalid-rollover-registration-draft",
        "the rollover registration draft does not authenticate against the selected source vault",
    )
}
