use super::*;

impl<'a, S, A, C, R, I> WitnessEngine<'a, S, A, C, R, I>
where
    S: WitnessStateStore,
    A: ExternalWitnessAnchor,
    C: WitnessClock,
    R: RandomSource,
    I: WitnessEngineIdentity + ?Sized,
{
    pub(super) fn ready_state(&mut self) -> Result<PersistedWitnessState, WitnessEngineError> {
        let state = self.store.load().map_err(map_store_error)?;
        self.validate_stored_identity(&state)?;
        if state.pending_anchor.is_some() {
            self.publish_pending(state)?;
        } else {
            self.require_published_equality(&state)?;
        }
        let ready = self.store.load().map_err(map_store_error)?;
        self.validate_stored_identity(&ready)?;
        if ready.pending_anchor.is_some() {
            return Err(refused(WitnessReasonV1::AnchorConflict));
        }
        self.require_published_equality(&ready)?;
        Ok(ready)
    }

    pub(super) fn validate_stored_identity(
        &self,
        state: &PersistedWitnessState,
    ) -> Result<(), WitnessEngineError> {
        if state.logical.witness_id != self.identity.principal_id() {
            return Err(refused(WitnessReasonV1::RestoredStateUnsafe));
        }
        if state.logical.state_generation == 0
            && (!state.logical.vaults.is_empty()
                || !state.logical.replay.is_empty()
                || state.logical.last_accepted_wall_time_ms != 0
                || state.published_anchor.is_some()
                || state.pending_anchor.is_some())
        {
            return Err(refused(WitnessReasonV1::RestoredStateUnsafe));
        }
        Ok(())
    }

    pub(super) fn require_published_equality(
        &mut self,
        state: &PersistedWitnessState,
    ) -> Result<(), WitnessEngineError> {
        let external = self.external_anchor.read().map_err(map_anchor_error)?;
        match (&state.published_anchor, &external) {
            (None, None) if state.logical.state_generation == 0 => Ok(()),
            (Some(local), Some(external))
                if exact_anchor_eq(local, external)?
                    && local.state_generation == state.logical.state_generation
                    && local.database_state_digest
                        == state
                            .logical
                            .canonical_database_state()?
                            .digest()
                            .map_err(|_| refused(WitnessReasonV1::Invalid))? =>
            {
                self.validate_anchor(local)
            }
            _ => Err(refused(WitnessReasonV1::AnchorConflict)),
        }
    }

    pub(super) fn publish_pending(
        &mut self,
        state: PersistedWitnessState,
    ) -> Result<(), WitnessEngineError> {
        let candidate = state
            .pending_anchor
            .as_ref()
            .ok_or_else(|| refused(WitnessReasonV1::AnchorConflict))?;
        self.validate_anchor(candidate)?;
        let database_digest = state
            .logical
            .canonical_database_state()?
            .digest()
            .map_err(|_| refused(WitnessReasonV1::Invalid))?;
        let expected_predecessor = state
            .published_anchor
            .as_ref()
            .map(WitnessStateAnchorV1::digest)
            .transpose()
            .map_err(|_| refused(WitnessReasonV1::Invalid))?
            .unwrap_or_else(|| ZERO_DIGEST.clone());
        if candidate.state_generation != state.logical.state_generation
            || candidate.database_state_digest != database_digest
            || candidate.predecessor_anchor_digest != expected_predecessor
        {
            return Err(refused(WitnessReasonV1::AnchorConflict));
        }

        let external = self.external_anchor.read().map_err(map_anchor_error)?;
        if external
            .as_ref()
            .is_some_and(|external| exact_anchor_eq(external, candidate).unwrap_or(false))
        {
            return self.mark_published(candidate);
        }
        let predecessor_matches = match (&state.published_anchor, &external) {
            (None, None) => true,
            (Some(expected), Some(actual)) => exact_anchor_eq(expected, actual)?,
            _ => false,
        };
        if !predecessor_matches {
            return Err(refused(WitnessReasonV1::AnchorConflict));
        }
        match self
            .external_anchor
            .compare_and_swap(state.published_anchor.as_ref(), candidate)
            .map_err(map_anchor_error)?
        {
            AnchorCompareAndSwap::Published => {}
            AnchorCompareAndSwap::Conflict => {
                let observed = self.external_anchor.read().map_err(map_anchor_error)?;
                if !observed
                    .as_ref()
                    .is_some_and(|observed| exact_anchor_eq(observed, candidate).unwrap_or(false))
                {
                    return Err(refused(WitnessReasonV1::AnchorConflict));
                }
            }
        }
        let readback = self
            .external_anchor
            .read()
            .map_err(map_anchor_error)?
            .ok_or_else(|| refused(WitnessReasonV1::AnchorConflict))?;
        if !exact_anchor_eq(&readback, candidate)? {
            return Err(refused(WitnessReasonV1::AnchorConflict));
        }
        self.mark_published(candidate)
    }

    pub(super) fn mark_published(
        &mut self,
        candidate: &WitnessStateAnchorV1,
    ) -> Result<(), WitnessEngineError> {
        let digest = candidate
            .digest()
            .map_err(|_| refused(WitnessReasonV1::Invalid))?;
        self.store
            .mark_anchor_published(&digest)
            .map_err(map_store_error)
    }

    pub(super) fn commit_and_publish(
        &mut self,
        mut state: PersistedWitnessState,
        now_ms: u64,
    ) -> Result<PersistedWitnessState, WitnessEngineError> {
        let expected_generation = state.logical.state_generation;
        state.logical.state_generation = expected_generation
            .checked_add(1)
            .ok_or_else(|| refused(WitnessReasonV1::CapacityExhausted))?;
        state.logical.last_accepted_wall_time_ms =
            state.logical.last_accepted_wall_time_ms.max(now_ms);
        let candidate = self.build_anchor(&state, now_ms)?;
        self.external_anchor
            .ensure_publishable(&candidate)
            .map_err(map_anchor_error)?;
        state.pending_anchor = Some(candidate);
        self.store
            .commit(expected_generation, state)
            .map_err(map_store_error)?;
        self.ready_state()
    }

    pub(super) fn build_anchor(
        &self,
        state: &PersistedWitnessState,
        now_ms: u64,
    ) -> Result<WitnessStateAnchorV1, WitnessEngineError> {
        let descriptor = self
            .identity
            .public_descriptor()
            .map_err(|_| refused(WitnessReasonV1::InternalFailure))?;
        let database_state_digest = state
            .logical
            .canonical_database_state()?
            .digest()
            .map_err(|_| refused(WitnessReasonV1::Invalid))?;
        let vault_high_watermarks = state
            .logical
            .vaults
            .iter()
            .map(|(vault_id, vault)| {
                let highest_expiry = state
                    .logical
                    .replay
                    .iter()
                    .filter(|((record_vault_id, _), _)| record_vault_id == vault_id)
                    .map(|(_, record)| record.request.expires_at_ms)
                    .max()
                    .unwrap_or(0);
                Ok(VaultHighWatermarkV1 {
                    vault_id: *vault_id,
                    genesis_fingerprint: vault.current_checkpoint.genesis_fingerprint.clone(),
                    policy_sequence: vault.current_checkpoint.vault_policy_sequence,
                    checkpoint_digest: vault
                        .current_checkpoint
                        .digest()
                        .map_err(|_| refused(WitnessReasonV1::Invalid))?,
                    highest_retained_request_expiry_ms: highest_expiry,
                })
            })
            .collect::<Result<Vec<_>, WitnessEngineError>>()?;
        let replay_retain_through_ms = state
            .logical
            .replay
            .values()
            .map(|record| record.retain_through_ms)
            .max()
            .unwrap_or(0);
        let predecessor_anchor_digest = state
            .published_anchor
            .as_ref()
            .map(WitnessStateAnchorV1::digest)
            .transpose()
            .map_err(|_| refused(WitnessReasonV1::Invalid))?
            .unwrap_or_else(|| ZERO_DIGEST.clone());
        let signing_fingerprint = signing_key_fingerprint(
            3,
            &descriptor.principal_id,
            1,
            &descriptor.verification_public_key,
        );
        let mut anchor = WitnessStateAnchorV1 {
            schema: 1,
            witness_id: descriptor.principal_id,
            witness_signing_key_fingerprint: signing_fingerprint,
            witness_signing_key_epoch: 1,
            state_generation: state.logical.state_generation,
            database_state_digest,
            vault_high_watermarks,
            replay_retain_through_ms,
            last_accepted_wall_time_ms: state.logical.last_accepted_wall_time_ms,
            predecessor_anchor_digest,
            issued_at_ms: now_ms,
            signature: Signature64::new([0; 64]),
        };
        anchor.signature = self
            .identity
            .sign_witness_statement(
                &anchor
                    .signature_preimage()
                    .map_err(|_| refused(WitnessReasonV1::Invalid))?,
            )
            .map_err(|_| refused(WitnessReasonV1::InternalFailure))?;
        Ok(anchor)
    }

    pub(super) fn validate_anchor(
        &self,
        anchor: &WitnessStateAnchorV1,
    ) -> Result<(), WitnessEngineError> {
        let descriptor = self
            .identity
            .public_descriptor()
            .map_err(|_| refused(WitnessReasonV1::InternalFailure))?;
        if anchor.witness_id != descriptor.principal_id
            || anchor.witness_signing_key_epoch != 1
            || anchor.witness_signing_key_fingerprint
                != signing_key_fingerprint(
                    3,
                    &descriptor.principal_id,
                    1,
                    &descriptor.verification_public_key,
                )
        {
            return Err(refused(WitnessReasonV1::RestoredStateUnsafe));
        }
        crypto::verify_bytes(
            &descriptor.verification_public_key,
            &anchor
                .signature_preimage()
                .map_err(|_| refused(WitnessReasonV1::Invalid))?,
            &anchor.signature,
        )
        .map_err(|_| refused(WitnessReasonV1::RestoredStateUnsafe))
    }

    pub(super) fn require_safe_clock(
        &self,
        state: &PersistedWitnessState,
        now_ms: u64,
    ) -> Result<(), WitnessEngineError> {
        if now_ms.saturating_add(ACCEPTED_CLOCK_SKEW_MS) < state.logical.last_accepted_wall_time_ms
        {
            return Err(refused(WitnessReasonV1::UnsafeClock));
        }
        Ok(())
    }
}
