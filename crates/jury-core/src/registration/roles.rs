use super::*;

pub(super) fn create_role_descriptor(
    identity: &UnlockedIdentity,
    principal: &PrincipalDescriptorV1,
    profile: &RegistrationRoleProfileV1,
    created_at_ms: u64,
) -> Result<RegistrationRoleDescriptorV1, RegistrationError> {
    match profile {
        RegistrationRoleProfileV1::VaultPrincipal => {
            Ok(RegistrationRoleDescriptorV1::VaultPrincipal)
        }
        RegistrationRoleProfileV1::Approver => {
            let allowed_operations = vec![
                WitnessOperation::ReadStdout,
                WitnessOperation::WritePrivateFile,
                WitnessOperation::TemplateInjection,
                WitnessOperation::ChildEnvironment,
                WitnessOperation::ChildStdin,
                WitnessOperation::ItemMutation,
                WitnessOperation::Backup,
                WitnessOperation::Recovery,
                WitnessOperation::AdministrativeRekey,
            ];
            let mut descriptor = ApproverPolicyDescriptor {
                schema: 1,
                approver_id: principal.principal_id,
                signing_public_key: principal.verification_public_key.clone(),
                signing_key_fingerprint: signing_key_fingerprint(
                    2,
                    &principal.principal_id,
                    1,
                    &principal.verification_public_key,
                ),
                signing_key_epoch: 1,
                status: DescriptorStatus::Active,
                approval_mode: ApprovalMode::Human,
                allowed_operations,
                created_at_ms,
                self_signature: Signature64::new([0; 64]),
            };
            descriptor.self_signature = identity
                .sign_registration_statement(&descriptor.self_signature_preimage().map_err(
                    |_| RegistrationError::new(RegistrationErrorKind::InvalidDescriptor),
                )?)
                .map_err(|_| RegistrationError::new(RegistrationErrorKind::AuthenticationFailed))?;
            Ok(RegistrationRoleDescriptorV1::Approver { descriptor })
        }
        RegistrationRoleProfileV1::Witness { share_index } => {
            let mut descriptor = WitnessPolicyDescriptor {
                schema: 1,
                witness_id: principal.principal_id,
                share_index: *share_index,
                signing_public_key: principal.verification_public_key.clone(),
                signing_key_fingerprint: signing_key_fingerprint(
                    3,
                    &principal.principal_id,
                    1,
                    &principal.verification_public_key,
                ),
                signing_key_epoch: 1,
                contribution_public_key: principal.recipient_public_key.clone(),
                contribution_key_fingerprint: recipient_public_key_fingerprint(
                    &principal.recipient_public_key,
                ),
                contribution_key_epoch: 1,
                status: DescriptorStatus::Active,
                created_at_ms,
                self_signature: Signature64::new([0; 64]),
            };
            descriptor.self_signature = identity
                .sign_registration_statement(&descriptor.self_signature_preimage().map_err(
                    |_| RegistrationError::new(RegistrationErrorKind::InvalidDescriptor),
                )?)
                .map_err(|_| RegistrationError::new(RegistrationErrorKind::AuthenticationFailed))?;
            Ok(RegistrationRoleDescriptorV1::Witness {
                descriptor: Box::new(descriptor),
            })
        }
    }
}

pub(super) fn validate_role_descriptor(
    principal: &PrincipalDescriptorV1,
    profile: &RegistrationRoleProfileV1,
    role: &RegistrationRoleDescriptorV1,
) -> Result<(), RegistrationError> {
    let valid = match (profile, role) {
        (
            RegistrationRoleProfileV1::VaultPrincipal,
            RegistrationRoleDescriptorV1::VaultPrincipal,
        ) => matches!(
            principal.principal_kind,
            PrincipalKind::Human | PrincipalKind::Machine
        ),
        (
            RegistrationRoleProfileV1::Approver,
            RegistrationRoleDescriptorV1::Approver { descriptor },
        ) => {
            principal.principal_kind == PrincipalKind::Approver
                && descriptor.approver_id == principal.principal_id
                && descriptor.signing_public_key == principal.verification_public_key
                && descriptor.validate().is_ok()
        }
        (
            RegistrationRoleProfileV1::Witness { share_index },
            RegistrationRoleDescriptorV1::Witness { descriptor },
        ) => {
            principal.principal_kind == PrincipalKind::Witness
                && descriptor.witness_id == principal.principal_id
                && descriptor.share_index == *share_index
                && descriptor.signing_public_key == principal.verification_public_key
                && descriptor.contribution_public_key == principal.recipient_public_key
                && descriptor.validate().is_ok()
        }
        _ => false,
    };
    if valid {
        Ok(())
    } else {
        Err(RegistrationError::new(
            RegistrationErrorKind::InvalidDescriptor,
        ))
    }
}
