use super::*;

impl<'a, S, A, C, R, I> WitnessEngine<'a, S, A, C, R, I>
where
    S: WitnessStateStore,
    A: ExternalWitnessAnchor,
    C: WitnessClock,
    R: RandomSource,
    I: WitnessEngineIdentity + ?Sized,
{
    pub(super) fn validate_request(
        &self,
        policy: &PolicyState,
        state: &PersistedWitnessState,
        request: &jury_protocol::witness_v1::WitnessRequestV1,
        manifest: &ActionManifestV1,
        now_ms: u64,
    ) -> Result<ValidatedRequest, WitnessEngineError> {
        validate_request_manifest(request, manifest)?;
        let registered = state
            .logical
            .vaults
            .get(&request.vault_id)
            .ok_or_else(|| refused(WitnessReasonV1::StalePolicy))?;
        validate_registered_checkpoint(policy, &registered.current_checkpoint, self.identity)?;
        let checkpoint_digest = registered
            .current_checkpoint
            .digest()
            .map_err(|_| refused(WitnessReasonV1::Invalid))?;
        if request.policy_checkpoint_digest != checkpoint_digest {
            return Err(refused(WitnessReasonV1::StalePolicy));
        }
        validate_request_time(request, now_ms)?;
        let validated =
            crate::witness_validation::validate_manifest_policy(policy, request, manifest)
                .map_err(map_request_policy_error)?;
        if manifest.timeout_ms > validated.rule.max_timeout_ms
            || manifest.output_limit_bytes > validated.rule.max_output_bytes
            || manifest.approval_target.entries.len() > usize::from(validated.rule.max_target_count)
            || manifest.platform_assurance.tag()
                < platform_assurance_tag(validated.rule.required_platform_assurance)
        {
            return Err(refused(WitnessReasonV1::WorkloadExceeded));
        }
        validate_automatic_rule(manifest, &validated.rule)?;

        let capsule = validated
            .slot
            .capsules
            .iter()
            .find(|capsule| capsule.witness_id == self.identity.principal_id())
            .ok_or_else(|| refused(WitnessReasonV1::PolicyDenied))?
            .clone();
        let witness_descriptor = validated
            .policy
            .witness_descriptors
            .iter()
            .find(|descriptor| {
                descriptor.status == DescriptorStatus::Active
                    && descriptor.witness_id == self.identity.principal_id()
            })
            .ok_or_else(|| refused(WitnessReasonV1::PolicyDenied))?;
        let identity_descriptor = self
            .identity
            .public_descriptor()
            .map_err(|_| refused(WitnessReasonV1::InternalFailure))?;
        if witness_descriptor.signing_public_key != identity_descriptor.verification_public_key
            || witness_descriptor.contribution_public_key
                != identity_descriptor.recipient_public_key
            || witness_descriptor.share_index != capsule.share_index
            || witness_descriptor.contribution_key_fingerprint
                != capsule.contribution_key_fingerprint
        {
            return Err(refused(WitnessReasonV1::PolicyDenied));
        }
        Ok(ValidatedRequest {
            rule: validated.rule,
            policy: validated.policy,
            capsule,
            capsule_set_digest: validated.slot.capsule_set_digest,
        })
    }

    pub(super) fn validate_embedded_request(
        &self,
        policy: &PolicyState,
        state: &PersistedWitnessState,
        request: &jury_protocol::witness_v1::WitnessRequestV1,
        now_ms: u64,
    ) -> Result<(), WitnessEngineError> {
        validate_request_time(request, now_ms)?;
        let registered = state
            .logical
            .vaults
            .get(&request.vault_id)
            .ok_or_else(|| refused(WitnessReasonV1::StalePolicy))?;
        validate_registered_checkpoint(policy, &registered.current_checkpoint, self.identity)?;
        if request.policy_checkpoint_digest
            != registered
                .current_checkpoint
                .digest()
                .map_err(|_| refused(WitnessReasonV1::Invalid))?
        {
            return Err(refused(WitnessReasonV1::StalePolicy));
        }
        validate_request_policy(policy, request)
            .map(|_| ())
            .map_err(map_request_policy_error)
    }

    pub(super) fn denial_response(
        &mut self,
        request: &jury_protocol::witness_v1::WitnessRequestV1,
        action_manifest_digest: &Digest32,
        reason: WitnessReasonV1,
        state_generation: u64,
        now_ms: u64,
    ) -> Result<WitnessResponseV1, WitnessEngineError> {
        let response_id = random_response_id(self.random)?;
        let descriptor = self
            .identity
            .public_descriptor()
            .map_err(|_| refused(WitnessReasonV1::InternalFailure))?;
        let mut decision = WitnessDecisionV1 {
            schema: 1,
            response_id,
            request_id: request.request_id,
            request_digest: request
                .digest()
                .map_err(|_| refused(WitnessReasonV1::Invalid))?,
            action_manifest_digest: action_manifest_digest.clone(),
            witness_id: descriptor.principal_id,
            witness_signing_key_fingerprint: signing_key_fingerprint(
                3,
                &descriptor.principal_id,
                1,
                &descriptor.verification_public_key,
            ),
            witness_signing_key_epoch: 1,
            witness_policy_id: request.witness_policy_id,
            witness_policy_revision: request.witness_policy_revision,
            witness_policy_digest: request.witness_policy_digest.clone(),
            policy_checkpoint_digest: request.policy_checkpoint_digest.clone(),
            state_generation,
            decision: WitnessDecisionKindV1::Deny,
            reason,
            issued_at_ms: now_ms,
            expires_at_ms: request.expires_at_ms,
            contribution_digest: None,
            share_index: None,
            share_commitment: None,
            signature: Signature64::new([0; 64]),
        };
        decision.signature = self
            .identity
            .sign_witness_statement(
                &decision
                    .signature_preimage()
                    .map_err(|_| refused(WitnessReasonV1::Invalid))?,
            )
            .map_err(|_| refused(WitnessReasonV1::InternalFailure))?;
        Ok(WitnessResponseV1 {
            decision,
            contribution: None,
        })
    }

    pub(super) fn approval_response(
        &mut self,
        request: &jury_protocol::witness_v1::WitnessRequestV1,
        manifest: &ActionManifestV1,
        validated: &ValidatedRequest,
        state_generation: u64,
        now_ms: u64,
    ) -> Result<WitnessResponseV1, WitnessEngineError> {
        let response_id = random_response_id(self.random)?;
        let request_digest = request
            .digest()
            .map_err(|_| refused(WitnessReasonV1::Invalid))?;
        let action_manifest_digest = manifest
            .digest()
            .map_err(|_| refused(WitnessReasonV1::Invalid))?;
        let contribution = self
            .identity
            .seal_witness_contribution(
                &validated.capsule,
                &WitnessContributionTarget {
                    request_digest: request_digest.clone(),
                    action_manifest_digest: action_manifest_digest.clone(),
                    response_id,
                    checkpoint_digest: request.policy_checkpoint_digest.clone(),
                    capsule_set_digest: validated.capsule_set_digest.clone(),
                    session_public_key: request.request_session_public_key.clone(),
                    session_fingerprint: request.request_session_key_fingerprint.clone(),
                    expires_at_ms: request.expires_at_ms,
                },
                self.random,
            )
            .map_err(|_| refused(WitnessReasonV1::InvalidContribution))?;
        let contribution_digest = contribution
            .digest()
            .map_err(|_| refused(WitnessReasonV1::InvalidContribution))?;
        let descriptor = self
            .identity
            .public_descriptor()
            .map_err(|_| refused(WitnessReasonV1::InternalFailure))?;
        let mut decision = WitnessDecisionV1 {
            schema: 1,
            response_id,
            request_id: request.request_id,
            request_digest,
            action_manifest_digest,
            witness_id: descriptor.principal_id,
            witness_signing_key_fingerprint: signing_key_fingerprint(
                3,
                &descriptor.principal_id,
                1,
                &descriptor.verification_public_key,
            ),
            witness_signing_key_epoch: 1,
            witness_policy_id: request.witness_policy_id,
            witness_policy_revision: request.witness_policy_revision,
            witness_policy_digest: request.witness_policy_digest.clone(),
            policy_checkpoint_digest: request.policy_checkpoint_digest.clone(),
            state_generation,
            decision: WitnessDecisionKindV1::Approve,
            reason: WitnessReasonV1::None,
            issued_at_ms: now_ms,
            expires_at_ms: request.expires_at_ms,
            contribution_digest: Some(contribution_digest),
            share_index: Some(contribution.share_index),
            share_commitment: Some(contribution.share_commitment.clone()),
            signature: Signature64::new([0; 64]),
        };
        decision.signature = self
            .identity
            .sign_witness_statement(
                &decision
                    .signature_preimage()
                    .map_err(|_| refused(WitnessReasonV1::Invalid))?,
            )
            .map_err(|_| refused(WitnessReasonV1::InternalFailure))?;
        Ok(WitnessResponseV1 {
            decision,
            contribution: Some(contribution),
        })
    }
}
