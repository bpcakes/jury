pub(super) trait PolicySigner {
    fn principal_id(&self) -> PrincipalId;
    fn descriptor(&self) -> Result<PrincipalDescriptorV1, PolicyError>;
    fn sign(&self, preimage: &[u8]) -> Result<Signature64, PolicyError>;
}

struct IdentityPolicySigner<'a> {
    owner: &'a VaultPrincipalIdentity,
    descriptor: PrincipalDescriptorV1,
}

impl PolicySigner for IdentityPolicySigner<'_> {
    fn principal_id(&self) -> PrincipalId {
        self.owner.principal_id()
    }

    fn descriptor(&self) -> Result<PrincipalDescriptorV1, PolicyError> {
        Ok(self.descriptor.clone())
    }

    fn sign(&self, preimage: &[u8]) -> Result<Signature64, PolicyError> {
        self.owner
            .sign_validated_statement(preimage)
            .map_err(|_| PolicyError::new(PolicyErrorKind::InvalidSignature))
    }
}

#[cfg(test)]
pub(super) fn create_with_test_signer<R: RandomSource>(
    creator: &mut PolicyCreator<R>,
    signer: &impl PolicySigner,
    created_at_ms: u64,
    vault_is_known: impl FnMut(&VaultId) -> bool,
) -> Result<CreatedPolicy, PolicyError> {
    creator.create_with_signer(signer, created_at_ms, vault_is_known)
}

#[cfg(test)]
pub(super) fn prepare_with_test_signer(
    state: &PolicyState,
    signer: &impl PolicySigner,
    timestamp_ms: u64,
    operations: Vec<PolicyOperationV1>,
) -> Result<PreparedPolicyRevision, PolicyError> {
    state.prepare_with_signer(signer, timestamp_ms, operations)
}
