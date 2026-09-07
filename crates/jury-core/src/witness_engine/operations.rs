use super::*;

impl<'a, S, A, C, R, I> WitnessEngine<'a, S, A, C, R, I>
where
    S: WitnessStateStore,
    A: ExternalWitnessAnchor,
    C: WitnessClock,
    R: RandomSource,
    I: WitnessEngineIdentity + ?Sized,
{
    pub fn new(
        identity: &'a I,
        store: &'a mut S,
        external_anchor: &'a mut A,
        clock: &'a C,
        random: &'a mut R,
    ) -> Self {
        Self {
            identity,
            store,
            external_anchor,
            clock,
            random,
        }
    }

    /// Reconciles the sole permitted pending-anchor crash state and verifies
    /// that durable database state, the published local marker, the external
    /// anchor, witness identity, and wall clock are safe to serve.
    ///
    /// This releases no contribution and exposes no registered identifiers.
    pub fn check_ready(&mut self) -> Result<(), WitnessEngineError> {
        let state = self.ready_state()?;
        self.require_safe_clock(&state, self.clock.wall_time_ms())
    }

    /// Returns safe operational state after the same reconciliation required
    /// before contribution service. It exposes no registrations, policy
    /// material, request messages, approvals, or encrypted contributions.
    pub fn operational_status(&mut self) -> Result<WitnessOperationalStatus, WitnessEngineError> {
        let now_ms = self.clock.wall_time_ms();
        let state = self.ready_state()?;
        self.require_safe_clock(&state, now_ms)?;
        Ok(WitnessOperationalStatus {
            witness_id: state.logical.witness_id,
            state_generation: state.logical.state_generation,
            replay_record_count: state.logical.replay.len(),
            compactable_replay_record_count: state
                .logical
                .replay
                .values()
                .filter(|entry| now_ms > entry.retain_through_ms)
                .count(),
            replay_retain_through_ms: state
                .logical
                .replay
                .values()
                .map(|entry| entry.retain_through_ms)
                .max()
                .unwrap_or(0),
            published_anchor: state.published_anchor,
        })
    }

    pub fn register_vault(
        &mut self,
        policy: &PolicyState,
        accepted_registration: RegistrationBytes,
        checkpoint: VaultPolicyCheckpointV1,
        current_policy_material: PolicyMaterialBytes,
    ) -> Result<WitnessCheckpointAcknowledgementV1, WitnessEngineError> {
        if accepted_registration.is_empty() || current_policy_material.is_empty() {
            return Err(refused(WitnessReasonV1::Invalid));
        }
        let now_ms = self.clock.wall_time_ms();
        let mut state = self.ready_state()?;
        self.require_safe_clock(&state, now_ms)?;
        validate_checkpoint(policy, &checkpoint, self.identity)?;
        if checkpoint.issued_at_ms > now_ms.saturating_add(ACCEPTED_CLOCK_SKEW_MS) {
            return Err(refused(WitnessReasonV1::NotYetValid));
        }
        // A witness joining an established vault anchors its current global
        // checkpoint, which can have a predecessor. Existing per-vault state
        // still permits only exact registration replay; advancement below
        // requires the stored predecessor and complete authenticated lineage.
        if let Some(current) = state.logical.vaults.get(&checkpoint.vault_id) {
            if current.current_checkpoint == checkpoint
                && current.accepted_registration == accepted_registration
                && current.current_policy_material == current_policy_material
            {
                return checkpoint_acknowledgement(&state, &checkpoint.vault_id);
            }
            return Err(refused(WitnessReasonV1::CheckpointFork));
        }
        let vault_id = checkpoint.vault_id;
        state.logical.vaults.insert(
            vault_id,
            RegisteredWitnessVault {
                accepted_registration,
                current_checkpoint: checkpoint,
                current_policy_material,
            },
        );
        let state = self.commit_and_publish(state, now_ms)?;
        checkpoint_acknowledgement(&state, &vault_id)
    }

    pub fn advance_checkpoint(
        &mut self,
        policy: &PolicyState,
        checkpoint: VaultPolicyCheckpointV1,
        current_policy_material: PolicyMaterialBytes,
    ) -> Result<WitnessCheckpointAcknowledgementV1, WitnessEngineError> {
        if current_policy_material.is_empty() {
            return Err(refused(WitnessReasonV1::Invalid));
        }
        let now_ms = self.clock.wall_time_ms();
        let mut state = self.ready_state()?;
        self.require_safe_clock(&state, now_ms)?;
        validate_checkpoint_public(policy, &checkpoint)?;
        if checkpoint.issued_at_ms > now_ms.saturating_add(ACCEPTED_CLOCK_SKEW_MS) {
            return Err(refused(WitnessReasonV1::NotYetValid));
        }
        let current = state
            .logical
            .vaults
            .get(&checkpoint.vault_id)
            .ok_or_else(|| refused(WitnessReasonV1::StalePolicy))?;
        if current.current_checkpoint == checkpoint {
            if current.current_policy_material == current_policy_material {
                return checkpoint_acknowledgement(&state, &checkpoint.vault_id);
            }
            return Err(refused(WitnessReasonV1::CheckpointFork));
        }
        if checkpoint.vault_policy_sequence < current.current_checkpoint.vault_policy_sequence {
            return Err(refused(WitnessReasonV1::StalePolicy));
        }
        if checkpoint.vault_policy_sequence == current.current_checkpoint.vault_policy_sequence {
            return Err(refused(WitnessReasonV1::CheckpointFork));
        }
        if checkpoint.vault_policy_sequence
            != current
                .current_checkpoint
                .vault_policy_sequence
                .saturating_add(1)
        {
            return Err(refused(WitnessReasonV1::WitnessBehind));
        }
        let predecessor = current
            .current_checkpoint
            .digest()
            .map_err(|_| refused(WitnessReasonV1::Invalid))?;
        if checkpoint.predecessor_checkpoint_digest != predecessor
            || checkpoint.issued_at_ms <= current.current_checkpoint.issued_at_ms
        {
            return Err(refused(WitnessReasonV1::CheckpointFork));
        }

        let stale_requests = state
            .logical
            .replay
            .iter()
            .filter(|((vault_id, _), entry)| {
                *vault_id == checkpoint.vault_id && entry.state == ReplayStateV1::Reserved
            })
            .map(|(key, entry)| {
                (
                    *key,
                    entry.request.clone(),
                    entry.action_manifest_digest.clone(),
                )
            })
            .collect::<Vec<_>>();
        let next_generation = state.logical.state_generation.saturating_add(1);
        for (key, request, action_manifest_digest) in stale_requests {
            let response = self.denial_response(
                &request,
                &action_manifest_digest,
                WitnessReasonV1::StalePolicy,
                next_generation,
                now_ms,
            )?;
            let entry = state
                .logical
                .replay
                .get_mut(&key)
                .ok_or_else(|| refused(WitnessReasonV1::InternalFailure))?;
            entry.state = ReplayStateV1::Denied;
            entry.response = Some(response);
        }
        let vault_id = checkpoint.vault_id;
        let current = state
            .logical
            .vaults
            .get_mut(&vault_id)
            .ok_or_else(|| refused(WitnessReasonV1::InternalFailure))?;
        current.current_checkpoint = checkpoint;
        current.current_policy_material = current_policy_material;
        let state = self.commit_and_publish(state, now_ms)?;
        checkpoint_acknowledgement(&state, &vault_id)
    }

    pub fn cancel(
        &mut self,
        policy: &PolicyState,
        request: &jury_protocol::witness_v1::WitnessRequestV1,
        cancellation: &RequestCancellationV1,
    ) -> Result<CancellationProgress, WitnessEngineError> {
        let now_ms = self.clock.wall_time_ms();
        let mut state = self.ready_state()?;
        self.require_safe_clock(&state, now_ms)?;
        let key = (request.vault_id, request.request_id);
        if let Some(known) = state.logical.replay.get(&key) {
            if !same_request(&known.request, request)? {
                return Err(refused(WitnessReasonV1::ReplayConflict));
            }
            if let Some(response) = &known.response {
                validate_request_cancellation(policy, request, cancellation, now_ms)?;
                return Ok(if known.state == ReplayStateV1::Cancelled {
                    CancellationProgress::Cancelled(Box::new(response.clone()))
                } else {
                    CancellationProgress::TooLate(Box::new(response.clone()))
                });
            }
        }
        self.validate_embedded_request(policy, &state, request, now_ms)?;
        validate_request_cancellation(policy, request, cancellation, now_ms)?;
        let cancellation_bytes = CancellationBytes::new(
            cancellation
                .canonical_bytes()
                .map_err(|_| refused(WitnessReasonV1::Invalid))?,
        )
        .map_err(|_| refused(WitnessReasonV1::CapacityExhausted))?;
        let response = self.denial_response(
            request,
            &request.action_manifest_digest,
            WitnessReasonV1::Cancelled,
            state.logical.state_generation.saturating_add(1),
            now_ms,
        )?;
        let retain_through_ms = request
            .expires_at_ms
            .checked_add(REPLAY_RETENTION_MS)
            .ok_or_else(|| refused(WitnessReasonV1::Invalid))?;
        match state.logical.replay.get_mut(&key) {
            Some(entry) => {
                entry.state = ReplayStateV1::Cancelled;
                entry.cancellation = Some(cancellation_bytes);
                entry.response = Some(response.clone());
            }
            None => {
                state.logical.replay.insert(
                    key,
                    WitnessReplayEntry {
                        request: request.clone(),
                        action_manifest_digest: request.action_manifest_digest.clone(),
                        state: ReplayStateV1::Cancelled,
                        retain_through_ms,
                        approvals: Vec::new(),
                        cancellation: Some(cancellation_bytes),
                        response: Some(response.clone()),
                    },
                );
            }
        }
        self.commit_and_publish(state, now_ms)?;
        Ok(CancellationProgress::Cancelled(Box::new(response)))
    }

    pub fn compact_replay(&mut self) -> Result<usize, WitnessEngineError> {
        let now_ms = self.clock.wall_time_ms();
        let mut state = self.ready_state()?;
        self.require_safe_clock(&state, now_ms)?;
        let before = state.logical.replay.len();
        state
            .logical
            .replay
            .retain(|_, entry| now_ms <= entry.retain_through_ms);
        let removed = before.saturating_sub(state.logical.replay.len());
        if removed != 0 {
            self.commit_and_publish(state, now_ms)?;
        }
        Ok(removed)
    }

    pub fn reserve(
        &mut self,
        policy: &PolicyState,
        request: jury_protocol::witness_v1::WitnessRequestV1,
        manifest: &ActionManifestV1,
    ) -> Result<WitnessProgress, WitnessEngineError> {
        let now_ms = self.clock.wall_time_ms();
        let mut state = self.ready_state()?;
        self.require_safe_clock(&state, now_ms)?;
        let key = (request.vault_id, request.request_id);
        if let Some(known) = state.logical.replay.get(&key) {
            if same_request(&known.request, &request)? {
                validate_request_manifest(&request, manifest)?;
                if known.action_manifest_digest
                    != manifest
                        .digest()
                        .map_err(|_| refused(WitnessReasonV1::Invalid))?
                {
                    return Err(refused(WitnessReasonV1::WrongScope));
                }
                return Ok(match &known.response {
                    Some(response) => WitnessProgress::Stable(Box::new(response.clone())),
                    None => WitnessProgress::Reserved,
                });
            }
            if known.state != ReplayStateV1::Reserved {
                return Err(refused(WitnessReasonV1::ReplayConflict));
            }
            let response = self.denial_response(
                &known.request,
                &known.action_manifest_digest,
                WitnessReasonV1::ReplayConflict,
                state.logical.state_generation.saturating_add(1),
                now_ms,
            )?;
            let known = state
                .logical
                .replay
                .get_mut(&key)
                .ok_or_else(|| refused(WitnessReasonV1::InternalFailure))?;
            known.state = ReplayStateV1::Denied;
            known.response = Some(response.clone());
            self.commit_and_publish(state, now_ms)?;
            return Ok(WitnessProgress::Stable(Box::new(response)));
        }
        self.validate_request(policy, &state, &request, manifest, now_ms)?;
        if state.logical.replay.len() >= MAX_REPLAY_RECORDS_PER_SERVICE
            || state
                .logical
                .replay
                .keys()
                .filter(|(vault_id, _)| *vault_id == request.vault_id)
                .count()
                >= MAX_REPLAY_RECORDS_PER_VAULT
        {
            return Err(refused(WitnessReasonV1::CapacityExhausted));
        }
        let action_manifest_digest = manifest
            .digest()
            .map_err(|_| refused(WitnessReasonV1::Invalid))?;
        let retain_through_ms = request
            .expires_at_ms
            .checked_add(REPLAY_RETENTION_MS)
            .ok_or_else(|| refused(WitnessReasonV1::Invalid))?;
        state.logical.replay.insert(
            key,
            WitnessReplayEntry {
                request,
                action_manifest_digest,
                state: ReplayStateV1::Reserved,
                retain_through_ms,
                approvals: Vec::new(),
                cancellation: None,
                response: None,
            },
        );
        self.commit_and_publish(state, now_ms)?;
        Ok(WitnessProgress::Reserved)
    }

    pub fn decide(
        &mut self,
        policy: &PolicyState,
        request: &jury_protocol::witness_v1::WitnessRequestV1,
        manifest: &ActionManifestV1,
        approvals: &[ApprovalDecisionV1],
    ) -> Result<WitnessProgress, WitnessEngineError> {
        if approvals.len() > MAX_RECORDED_APPROVALS {
            return Err(refused(WitnessReasonV1::CapacityExhausted));
        }
        let now_ms = self.clock.wall_time_ms();
        let mut state = self.ready_state()?;
        self.require_safe_clock(&state, now_ms)?;
        let key = (request.vault_id, request.request_id);
        let known = state
            .logical
            .replay
            .get(&key)
            .ok_or_else(|| refused(WitnessReasonV1::Invalid))?;
        if !same_request(&known.request, request)? {
            return Err(refused(WitnessReasonV1::ReplayConflict));
        }
        validate_request_manifest(request, manifest)?;
        if known.action_manifest_digest
            != manifest
                .digest()
                .map_err(|_| refused(WitnessReasonV1::Invalid))?
        {
            return Err(refused(WitnessReasonV1::WrongScope));
        }
        if let Some(response) = &known.response {
            return Ok(WitnessProgress::Stable(Box::new(response.clone())));
        }
        let validated = match self.validate_request(policy, &state, request, manifest, now_ms) {
            Ok(validated) => validated,
            Err(error) if error.reason() == WitnessReasonV1::Expired => {
                let response = self.denial_response(
                    request,
                    &known.action_manifest_digest,
                    WitnessReasonV1::Expired,
                    state.logical.state_generation.saturating_add(1),
                    now_ms,
                )?;
                let entry = state
                    .logical
                    .replay
                    .get_mut(&key)
                    .ok_or_else(|| refused(WitnessReasonV1::InternalFailure))?;
                entry.state = ReplayStateV1::Denied;
                entry.response = Some(response.clone());
                self.commit_and_publish(state, now_ms)?;
                return Ok(WitnessProgress::Stable(Box::new(response)));
            }
            Err(error) => return Err(error),
        };
        if known.action_manifest_digest
            != manifest
                .digest()
                .map_err(|_| refused(WitnessReasonV1::Invalid))?
        {
            return Err(refused(WitnessReasonV1::WrongScope));
        }

        let mut accepted = known
            .approvals
            .iter()
            .map(|approval| {
                validate_approval_static(approval, request, manifest, &validated)?;
                Ok(approval.clone())
            })
            .collect::<Result<Vec<_>, WitnessEngineError>>()?;
        accepted.retain(|approval| approval_is_current(approval, now_ms));
        for approval in approvals {
            validate_approval(approval, request, manifest, &validated, now_ms)?;
            accepted.push(approval.clone());
        }
        accepted = normalize_approvals(accepted)?;
        let tally = tally_approvals(&accepted, &validated.rule);
        let threshold = usize::from(validated.rule.approval_threshold);
        if tally.approved >= threshold {
            let response = self.approval_response(
                request,
                manifest,
                &validated,
                state.logical.state_generation.saturating_add(1),
                now_ms,
            )?;
            let entry = state
                .logical
                .replay
                .get_mut(&key)
                .ok_or_else(|| refused(WitnessReasonV1::InternalFailure))?;
            entry.approvals = accepted;
            entry.state = ReplayStateV1::Approved;
            entry.response = Some(response.clone());
            self.commit_and_publish(state, now_ms)?;
            return Ok(WitnessProgress::Stable(Box::new(response)));
        }
        if tally.approved.saturating_add(tally.undecided) < threshold {
            let reason = if tally.conflicted {
                WitnessReasonV1::ApprovalConflict
            } else {
                WitnessReasonV1::ApprovalDenied
            };
            let response = self.denial_response(
                request,
                &known.action_manifest_digest,
                reason,
                state.logical.state_generation.saturating_add(1),
                now_ms,
            )?;
            let entry = state
                .logical
                .replay
                .get_mut(&key)
                .ok_or_else(|| refused(WitnessReasonV1::InternalFailure))?;
            entry.approvals = accepted;
            entry.state = ReplayStateV1::Denied;
            entry.response = Some(response.clone());
            self.commit_and_publish(state, now_ms)?;
            return Ok(WitnessProgress::Stable(Box::new(response)));
        }
        if accepted != known.approvals {
            let entry = state
                .logical
                .replay
                .get_mut(&key)
                .ok_or_else(|| refused(WitnessReasonV1::InternalFailure))?;
            entry.approvals = accepted;
            self.commit_and_publish(state, now_ms)?;
        }
        Ok(WitnessProgress::Pending)
    }
}
