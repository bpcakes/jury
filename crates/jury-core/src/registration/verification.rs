use super::*;

/// Authenticate the public challenge, candidate consent, role descriptor and
/// their exact vault/time binding. This does not verify the encrypted response
/// MAC and therefore does not independently prove recipient-key possession.
/// Owners must use [`verify_proof`] before admitting a new registration; public
/// bootstrap readers additionally check the owner's signed admission digest.
pub fn verify_proof_signatures(
    policy: &PolicyState,
    challenge: &RegistrationChallengeV1,
    proof: &RegistrationProofV1,
    now_ms: u64,
) -> Result<Digest32, RegistrationError> {
    challenge.validate_shape()?;
    if challenge.vault_id != policy.vault_id()
        || challenge.genesis_fingerprint != *policy.genesis_fingerprint()
    {
        return Err(RegistrationError::new(RegistrationErrorKind::Unauthorized));
    }
    let owner = policy
        .principal(&challenge.owner_principal_id)
        .filter(|_| policy.is_owner(&challenge.owner_principal_id))
        .ok_or_else(|| RegistrationError::new(RegistrationErrorKind::Unauthorized))?;
    if now_ms < challenge.issued_at_ms || now_ms > challenge.expires_at_ms {
        return Err(RegistrationError::new(RegistrationErrorKind::Expired));
    }
    crypto::verify_bytes(
        &owner.descriptor.verification_public_key,
        &challenge.signed_preimage()?,
        &challenge.owner_signature,
    )
    .map_err(|_| RegistrationError::new(RegistrationErrorKind::AuthenticationFailed))?;
    if proof.version != PROOF_VERSION
        || proof.challenge != *challenge
        || proof.challenge_digest != challenge.digest()?
        || proof.candidate_principal_id != challenge.candidate_descriptor.principal_id
        || proof.created_at_ms < challenge.issued_at_ms
        || proof.created_at_ms > now_ms
    {
        return Err(RegistrationError::new(
            RegistrationErrorKind::InvalidArtifact,
        ));
    }
    validate_role_descriptor(
        &challenge.candidate_descriptor,
        &challenge.role_profile,
        &proof.role_descriptor,
    )?;
    crypto::verify_bytes(
        &challenge.candidate_descriptor.verification_public_key,
        &proof.signed_preimage()?,
        &proof.candidate_signature,
    )
    .map_err(|_| RegistrationError::new(RegistrationErrorKind::AuthenticationFailed))?;
    proof.digest()
}
