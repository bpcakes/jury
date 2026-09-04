#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WitnessRequestErrorKind {
    InvalidInput,
    InvalidPresentation,
    WrongIdentity,
    StalePolicy,
    EntropyUnavailable,
    ProtectionUnavailable,
    ProviderFailure,
}
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct WitnessRequestError {
    kind: WitnessRequestErrorKind,
}

impl WitnessRequestError {
    const fn new(kind: WitnessRequestErrorKind) -> Self {
        Self { kind }
    }

    #[must_use]
    pub const fn kind(self) -> WitnessRequestErrorKind {
        self.kind
    }
}

impl fmt::Debug for WitnessRequestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WitnessRequestError")
            .field("kind", &self.kind)
            .finish()
    }
}

impl fmt::Display for WitnessRequestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.kind {
            WitnessRequestErrorKind::InvalidInput => "witness request input is invalid",
            WitnessRequestErrorKind::InvalidPresentation => {
                "witness request presentation is invalid"
            }
            WitnessRequestErrorKind::WrongIdentity => "witness requester identity differs",
            WitnessRequestErrorKind::StalePolicy => "witness request policy is stale",
            WitnessRequestErrorKind::EntropyUnavailable => {
                "witness request entropy was unavailable"
            }
            WitnessRequestErrorKind::ProtectionUnavailable => {
                "witness request memory protection was unavailable"
            }
            WitnessRequestErrorKind::ProviderFailure => "witness request provider failed",
        })
    }
}

impl std::error::Error for WitnessRequestError {}

pub struct RequestCancellationCreator<R = OsRandom> {
    source: R,
}

impl RequestCancellationCreator<OsRandom> {
    #[must_use]
    pub const fn new() -> Self {
        Self { source: OsRandom }
    }
}

impl Default for RequestCancellationCreator<OsRandom> {
    fn default() -> Self {
        Self::new()
    }
}

impl<R: RandomSource> RequestCancellationCreator<R> {
    #[cfg(test)]
    pub(crate) const fn from_source(source: R) -> Self {
        Self { source }
    }

    pub fn create(
        &mut self,
        policy: &PolicyState,
        request: &WitnessRequestV1,
        canceller: &VaultPrincipalIdentity,
        issued_at_ms: u64,
    ) -> Result<RequestCancellationV1, WitnessRequestError> {
        let public = canceller
            .public_descriptor()
            .map_err(|_| WitnessRequestError::new(WitnessRequestErrorKind::ProviderFailure))?;
        if policy
            .principal(&canceller.principal_id())
            .is_none_or(|principal| principal.descriptor != public)
        {
            return Err(WitnessRequestError::new(
                WitnessRequestErrorKind::WrongIdentity,
            ));
        }
        let canceller_role = if canceller.principal_id() == request.requester_principal_id {
            CancellerRoleV1::OriginalRequester
        } else if policy.is_owner(&canceller.principal_id()) {
            CancellerRoleV1::CurrentOwner
        } else {
            return Err(WitnessRequestError::new(
                WitnessRequestErrorKind::WrongIdentity,
            ));
        };
        let cancellation_id = self.draw_cancellation_id(None)?;
        let nonce = self.draw_cancellation_id(Some(cancellation_id))?;
        let request_signature_preimage = RequestBytes::new(
            request
                .signature_preimage()
                .map_err(|_| WitnessRequestError::new(WitnessRequestErrorKind::InvalidInput))?,
        )
        .map_err(|_| WitnessRequestError::new(WitnessRequestErrorKind::InvalidInput))?;
        let mut cancellation = RequestCancellationV1 {
            schema: 1,
            cancellation_id,
            request_signature_preimage,
            client_signature: request.client_signature.clone(),
            request_id: request.request_id,
            request_digest: request
                .digest()
                .map_err(|_| WitnessRequestError::new(WitnessRequestErrorKind::InvalidInput))?,
            canceller_id: canceller.principal_id(),
            canceller_key_fingerprint: signing_key_fingerprint(
                1,
                &canceller.principal_id(),
                1,
                &public.verification_public_key,
            ),
            canceller_key_epoch: 1,
            canceller_role,
            issued_at_ms,
            reason: WitnessReasonV1::Cancelled,
            nonce,
            signature: Signature64::new([0; 64]),
        };
        cancellation.signature = canceller
            .sign_validated_statement(
                &cancellation
                    .signature_preimage()
                    .map_err(|_| WitnessRequestError::new(WitnessRequestErrorKind::InvalidInput))?,
            )
            .map_err(|_| WitnessRequestError::new(WitnessRequestErrorKind::ProviderFailure))?;
        validate_request_cancellation(policy, request, &cancellation, issued_at_ms)
            .map_err(|_| WitnessRequestError::new(WitnessRequestErrorKind::InvalidInput))?;
        Ok(cancellation)
    }

    fn draw_cancellation_id(
        &mut self,
        disallowed: Option<CancellationId>,
    ) -> Result<CancellationId, WitnessRequestError> {
        for _ in 0..IDENTIFIER_RETRY_ATTEMPTS {
            let mut bytes = [0_u8; 32];
            self.source.fill(&mut bytes).map_err(|_| {
                WitnessRequestError::new(WitnessRequestErrorKind::EntropyUnavailable)
            })?;
            if let Ok(value) = CancellationId::from_bytes(bytes)
                && Some(value) != disallowed
            {
                return Ok(value);
            }
        }
        Err(WitnessRequestError::new(
            WitnessRequestErrorKind::EntropyUnavailable,
        ))
    }
}

/// Constructs one exact owner-signed checkpoint from authenticated policy
/// state. Callers choose only the witnessed-policy digest and predecessor
/// checkpoint link; every duplicated policy field is derived here.
pub struct VaultPolicyCheckpointCreator;

impl VaultPolicyCheckpointCreator {
    pub fn create(
        policy: &PolicyState,
        witness_policy_digest: &Digest32,
        predecessor_checkpoint_digest: Digest32,
        owner: &VaultPrincipalIdentity,
        issued_at_ms: u64,
    ) -> Result<jury_protocol::witness_v1::VaultPolicyCheckpointV1, WitnessRequestError> {
        if issued_at_ms == 0 || !policy.is_owner(&owner.principal_id()) {
            return Err(WitnessRequestError::new(
                WitnessRequestErrorKind::WrongIdentity,
            ));
        }
        let owner_descriptor = owner
            .public_descriptor()
            .map_err(|_| WitnessRequestError::new(WitnessRequestErrorKind::ProviderFailure))?;
        if policy
            .principal(&owner.principal_id())
            .is_none_or(|principal| principal.descriptor != owner_descriptor)
        {
            return Err(WitnessRequestError::new(
                WitnessRequestErrorKind::WrongIdentity,
            ));
        }
        let witness_policy = policy
            .witness_policy(witness_policy_digest)
            .ok_or_else(|| WitnessRequestError::new(WitnessRequestErrorKind::StalePolicy))?;
        let (approver_set_digest, witness_set_digest) = witness_policy
            .active_descriptor_set_digests()
            .map_err(|_| WitnessRequestError::new(WitnessRequestErrorKind::InvalidInput))?;
        if witness_policy.vault_policy_sequence > policy.sequence()
            || policy.predecessor_hash_for_sequence(witness_policy.vault_policy_sequence)
                != Some(&witness_policy.vault_policy_hash)
        {
            return Err(WitnessRequestError::new(
                WitnessRequestErrorKind::StalePolicy,
            ));
        }
        let mut checkpoint = jury_protocol::witness_v1::VaultPolicyCheckpointV1 {
            schema: 1,
            vault_id: policy.vault_id(),
            genesis_fingerprint: policy.genesis_fingerprint().clone(),
            vault_policy_sequence: policy.sequence(),
            vault_policy_hash: policy.terminal_revision_hash().clone(),
            witness_policy_id: witness_policy.witness_policy_id,
            witness_policy_revision: witness_policy.revision,
            witness_policy_digest: witness_policy_digest.clone(),
            witness_set_digest,
            approver_set_digest,
            review_label_set_digest: witness_policy.review_label_set_digest.clone(),
            predecessor_checkpoint_digest,
            issued_at_ms,
            issuer_owner_id: owner.principal_id(),
            issuer_key_fingerprint: signing_key_fingerprint(
                1,
                &owner.principal_id(),
                1,
                &owner_descriptor.verification_public_key,
            ),
            issuer_key_epoch: 1,
            signature: Signature64::new([0; 64]),
        };
        checkpoint.signature = owner
            .sign_validated_statement(
                &checkpoint
                    .signature_preimage()
                    .map_err(|_| WitnessRequestError::new(WitnessRequestErrorKind::InvalidInput))?,
            )
            .map_err(|_| WitnessRequestError::new(WitnessRequestErrorKind::ProviderFailure))?;
        validate_checkpoint_public(policy, &checkpoint)
            .map_err(|_| WitnessRequestError::new(WitnessRequestErrorKind::InvalidInput))?;
        Ok(checkpoint)
    }
}
