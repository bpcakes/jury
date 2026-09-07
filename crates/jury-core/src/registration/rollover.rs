use super::*;

/// Answer a new-lineage registration challenge while retaining the candidate's
/// signed role settings. The role's creation timestamp is fixed by the new
/// challenge, so its unsigned body can be committed before genesis exists.
///
/// The prior descriptor proves candidate consent to its settings, not source
/// vault membership. The rollover constructor/verifier must independently
/// compare it with the authenticated source policy. Ordinary registration uses
/// [`answer_challenge`] and its default initial settings.
pub fn answer_rollover_challenge(
    policy: &PolicyState,
    identity: &UnlockedIdentity,
    challenge: &RegistrationChallengeV1,
    prior_role: &RegistrationRoleDescriptorV1,
    now_ms: u64,
) -> Result<RegistrationProofV1, RegistrationError> {
    validate_role_descriptor(
        &challenge.candidate_descriptor,
        &challenge.role_profile,
        prior_role,
    )?;
    // Authenticate the complete new challenge and both candidate keys before
    // signing a replacement role descriptor.
    let mut proof = answer_challenge(policy, identity, challenge, now_ms)?;
    let mut role = prior_role.clone();
    match &mut role {
        RegistrationRoleDescriptorV1::Approver { descriptor } => {
            if descriptor.created_at_ms > challenge.issued_at_ms {
                return Err(RegistrationError::new(
                    RegistrationErrorKind::InvalidDescriptor,
                ));
            }
            descriptor.created_at_ms = challenge.issued_at_ms;
            descriptor.self_signature = identity
                .sign_registration_statement(&descriptor.self_signature_preimage().map_err(
                    |_| RegistrationError::new(RegistrationErrorKind::InvalidDescriptor),
                )?)
                .map_err(|_| RegistrationError::new(RegistrationErrorKind::AuthenticationFailed))?;
        }
        RegistrationRoleDescriptorV1::Witness { descriptor } => {
            if descriptor.created_at_ms > challenge.issued_at_ms {
                return Err(RegistrationError::new(
                    RegistrationErrorKind::InvalidDescriptor,
                ));
            }
            descriptor.created_at_ms = challenge.issued_at_ms;
            descriptor.self_signature = identity
                .sign_registration_statement(&descriptor.self_signature_preimage().map_err(
                    |_| RegistrationError::new(RegistrationErrorKind::InvalidDescriptor),
                )?)
                .map_err(|_| RegistrationError::new(RegistrationErrorKind::AuthenticationFailed))?;
        }
        RegistrationRoleDescriptorV1::VaultPrincipal => {
            return Err(RegistrationError::new(
                RegistrationErrorKind::InvalidDescriptor,
            ));
        }
    }
    // Reuse all ordinary challenge authentication, key possession and expiry
    // checks before returning any signed result to the caller.
    proof.role_descriptor = role;
    proof.candidate_signature = identity
        .sign_registration_statement(&proof.signed_preimage()?)
        .map_err(|_| RegistrationError::new(RegistrationErrorKind::AuthenticationFailed))?;
    Ok(proof)
}
