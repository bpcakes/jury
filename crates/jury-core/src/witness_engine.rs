//! Transport-independent witnessed authorization and replay state.
//!
//! The engine accepts only already parsed public protocol values. Storage,
//! clocks, and the external rollback anchor are injected. The sole private-key
//! operation happens after public scope, policy, time, replay, and approval
//! validation, and a response is returned only after the resulting anchor has
//! been published and read back byte-for-byte.

use std::{collections::BTreeMap, fmt};

use jury_protocol::{
    vault_v1::{
        BoundedBytes, Digest32, PrincipalId, PrincipalKind, RequestId, ResponseId, Signature64,
        VaultId,
    },
    witness_v1::{
        ACCEPTED_CLOCK_SKEW_MS, ActionManifestV1, ApprovalBytes, ApprovalDecisionKindV1,
        ApprovalDecisionV1, ApprovalModeV1, CancellationBytes, CancellerRoleV1, IntendedWitnessV1,
        MAX_RECORDED_APPROVALS, MAX_REPLAY_RECORDS_PER_SERVICE, MAX_REPLAY_RECORDS_PER_VAULT,
        PolicyMaterialBytes, REPLAY_RETENTION_MS, RegistrationBytes, ReplayStateV1,
        RequestCancellationV1, VaultHighWatermarkV1, VaultPolicyCheckpointV1,
        WitnessDatabaseStateV1, WitnessDecisionKindV1, WitnessDecisionV1, WitnessOperationV1,
        WitnessReasonV1, WitnessReceiptMaterialV1, WitnessReplayRecordV1, WitnessResponseV1,
        WitnessStateAnchorV1, WitnessVaultStateV1, signing_key_fingerprint,
    },
};
use serde::{Deserialize, Serialize};

use crate::{
    crypto,
    domain::Capability,
    entropy::RandomSource,
    identity::{WitnessContributionTarget, WitnessIdentity},
    policy::{
        ApprovalMode, DescriptorStatus, PlatformAssurance, PolicyError, PolicyErrorKind,
        PolicyState, WitnessAccessRule, WitnessOperation, WitnessPolicy,
    },
};

const ZERO_DIGEST: Digest32 = Digest32::new([0; 32]);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WitnessEngineErrorKind {
    Refused(WitnessReasonV1),
    StoreUnavailable,
    AnchorUnavailable,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct WitnessEngineError {
    kind: WitnessEngineErrorKind,
}

impl WitnessEngineError {
    const fn refused(reason: WitnessReasonV1) -> Self {
        Self {
            kind: WitnessEngineErrorKind::Refused(reason),
        }
    }

    const fn store_unavailable() -> Self {
        Self {
            kind: WitnessEngineErrorKind::StoreUnavailable,
        }
    }

    const fn anchor_unavailable() -> Self {
        Self {
            kind: WitnessEngineErrorKind::AnchorUnavailable,
        }
    }

    #[must_use]
    pub const fn kind(self) -> WitnessEngineErrorKind {
        self.kind
    }

    #[must_use]
    pub const fn reason(self) -> WitnessReasonV1 {
        match self.kind {
            WitnessEngineErrorKind::Refused(reason) => reason,
            WitnessEngineErrorKind::StoreUnavailable => WitnessReasonV1::InternalFailure,
            WitnessEngineErrorKind::AnchorUnavailable => WitnessReasonV1::Unavailable,
        }
    }
}

impl fmt::Debug for WitnessEngineError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WitnessEngineError")
            .field("kind", &self.kind)
            .finish()
    }
}

impl fmt::Display for WitnessEngineError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.kind {
            WitnessEngineErrorKind::Refused(_) => "witness request was refused",
            WitnessEngineErrorKind::StoreUnavailable => "witness state is unavailable",
            WitnessEngineErrorKind::AnchorUnavailable => "witness anchor is unavailable",
        })
    }
}

impl std::error::Error for WitnessEngineError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AnchorCompareAndSwap {
    Published,
    Conflict,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WitnessStoreError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WitnessAnchorError;

pub trait WitnessClock {
    fn wall_time_ms(&self) -> u64;
    fn monotonic_time_ms(&self) -> u64;
}

pub trait WitnessStateStore {
    fn load(&mut self) -> Result<PersistedWitnessState, WitnessStoreError>;

    fn commit(
        &mut self,
        expected_generation: u64,
        replacement: PersistedWitnessState,
    ) -> Result<(), WitnessStoreError>;

    fn mark_anchor_published(
        &mut self,
        candidate_digest: &Digest32,
    ) -> Result<(), WitnessStoreError>;
}

pub trait ExternalWitnessAnchor {
    fn read(&mut self) -> Result<Option<WitnessStateAnchorV1>, WitnessAnchorError>;

    fn compare_and_swap(
        &mut self,
        expected: Option<&WitnessStateAnchorV1>,
        candidate: &WitnessStateAnchorV1,
    ) -> Result<AnchorCompareAndSwap, WitnessAnchorError>;
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RegisteredWitnessVault {
    pub accepted_registration: RegistrationBytes,
    pub current_checkpoint: VaultPolicyCheckpointV1,
    pub current_policy_material: PolicyMaterialBytes,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessReplayEntry {
    pub request: jury_protocol::witness_v1::WitnessRequestV1,
    pub action_manifest_digest: Digest32,
    pub state: ReplayStateV1,
    pub retain_through_ms: u64,
    pub approvals: Vec<ApprovalDecisionV1>,
    pub cancellation: Option<CancellationBytes>,
    pub response: Option<WitnessResponseV1>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessLogicalState {
    pub witness_id: PrincipalId,
    pub state_generation: u64,
    pub vaults: BTreeMap<VaultId, RegisteredWitnessVault>,
    pub replay: BTreeMap<(VaultId, RequestId), WitnessReplayEntry>,
    pub last_accepted_wall_time_ms: u64,
}

impl WitnessLogicalState {
    #[must_use]
    pub fn empty(witness_id: PrincipalId) -> Self {
        Self {
            witness_id,
            state_generation: 0,
            vaults: BTreeMap::new(),
            replay: BTreeMap::new(),
            last_accepted_wall_time_ms: 0,
        }
    }

    pub fn canonical_database_state(&self) -> Result<WitnessDatabaseStateV1, WitnessEngineError> {
        let vault_states = self
            .vaults
            .iter()
            .map(|(vault_id, vault)| {
                Ok(WitnessVaultStateV1 {
                    schema: 1,
                    vault_id: *vault_id,
                    genesis_fingerprint: vault.current_checkpoint.genesis_fingerprint.clone(),
                    accepted_registration: vault.accepted_registration.clone(),
                    current_checkpoint: BoundedBytes::new(
                        vault
                            .current_checkpoint
                            .canonical_bytes()
                            .map_err(|_| refused(WitnessReasonV1::Invalid))?,
                    )
                    .map_err(|_| refused(WitnessReasonV1::CapacityExhausted))?,
                    current_policy_material: vault.current_policy_material.clone(),
                })
            })
            .collect::<Result<Vec<_>, WitnessEngineError>>()?;
        let replay_records = self
            .replay
            .iter()
            .map(|((vault_id, request_id), entry)| entry.to_protocol(*vault_id, *request_id))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(WitnessDatabaseStateV1 {
            schema: 1,
            witness_id: self.witness_id,
            state_generation: self.state_generation,
            vault_states,
            replay_records,
            last_accepted_wall_time_ms: self.last_accepted_wall_time_ms,
        })
    }
}

impl WitnessReplayEntry {
    fn to_protocol(
        &self,
        vault_id: VaultId,
        request_id: RequestId,
    ) -> Result<WitnessReplayRecordV1, WitnessEngineError> {
        let request_message = BoundedBytes::new(
            self.request
                .canonical_bytes()
                .map_err(|_| refused(WitnessReasonV1::Invalid))?,
        )
        .map_err(|_| refused(WitnessReasonV1::CapacityExhausted))?;
        let approvals = self
            .approvals
            .iter()
            .map(|approval| {
                BoundedBytes::new(
                    approval
                        .canonical_bytes()
                        .map_err(|_| refused(WitnessReasonV1::Invalid))?,
                )
                .map_err(|_| refused(WitnessReasonV1::CapacityExhausted))
            })
            .collect::<Result<Vec<ApprovalBytes>, _>>()?;
        let response = self
            .response
            .as_ref()
            .map(|response| {
                BoundedBytes::new(
                    response
                        .canonical_bytes()
                        .map_err(|_| refused(WitnessReasonV1::Invalid))?,
                )
                .map_err(|_| refused(WitnessReasonV1::CapacityExhausted))
            })
            .transpose()?;
        Ok(WitnessReplayRecordV1 {
            schema: 1,
            vault_id,
            request_id,
            request_digest: self
                .request
                .digest()
                .map_err(|_| refused(WitnessReasonV1::Invalid))?,
            request_message,
            action_manifest_digest: self.action_manifest_digest.clone(),
            state: self.state,
            expires_at_ms: self.request.expires_at_ms,
            retain_through_ms: self.retain_through_ms,
            approval_decisions: approvals,
            cancellation: self.cancellation.clone(),
            witness_response: response,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PersistedWitnessState {
    pub logical: WitnessLogicalState,
    pub published_anchor: Option<WitnessStateAnchorV1>,
    pub pending_anchor: Option<WitnessStateAnchorV1>,
}

impl PersistedWitnessState {
    #[must_use]
    pub fn empty(witness_id: PrincipalId) -> Self {
        Self {
            logical: WitnessLogicalState::empty(witness_id),
            published_anchor: None,
            pending_anchor: None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WitnessProgress {
    Reserved,
    Pending,
    Stable(Box<WitnessResponseV1>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CancellationProgress {
    Cancelled(Box<WitnessResponseV1>),
    TooLate(Box<WitnessResponseV1>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ApprovalTally {
    approved: usize,
    undecided: usize,
    conflicted: bool,
}

#[derive(Clone)]
struct ValidatedRequest {
    rule: WitnessAccessRule,
    policy: WitnessPolicy,
    capsule: jury_protocol::vault_v1::WitnessShareCapsuleV1,
    capsule_set_digest: Digest32,
}

#[derive(Clone)]
struct ValidatedPublicRequest {
    rule: WitnessAccessRule,
    policy: WitnessPolicy,
    slot: jury_protocol::vault_v1::WitnessedSlotV1,
}

pub struct WitnessEngine<'a, S, A, C, R> {
    identity: &'a WitnessIdentity,
    store: &'a mut S,
    external_anchor: &'a mut A,
    clock: &'a C,
    random: &'a mut R,
}

impl<'a, S, A, C, R> WitnessEngine<'a, S, A, C, R>
where
    S: WitnessStateStore,
    A: ExternalWitnessAnchor,
    C: WitnessClock,
    R: RandomSource,
{
    pub fn new(
        identity: &'a WitnessIdentity,
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

    pub fn register_vault(
        &mut self,
        policy: &PolicyState,
        accepted_registration: RegistrationBytes,
        checkpoint: VaultPolicyCheckpointV1,
        current_policy_material: PolicyMaterialBytes,
    ) -> Result<(), WitnessEngineError> {
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
        if checkpoint.predecessor_checkpoint_digest != ZERO_DIGEST {
            return Err(refused(WitnessReasonV1::CheckpointFork));
        }
        if let Some(current) = state.logical.vaults.get(&checkpoint.vault_id) {
            if current.current_checkpoint == checkpoint
                && current.accepted_registration == accepted_registration
                && current.current_policy_material == current_policy_material
            {
                return Ok(());
            }
            return Err(refused(WitnessReasonV1::CheckpointFork));
        }
        state.logical.vaults.insert(
            checkpoint.vault_id,
            RegisteredWitnessVault {
                accepted_registration,
                current_checkpoint: checkpoint,
                current_policy_material,
            },
        );
        self.commit_and_publish(state, now_ms).map(|_| ())
    }

    pub fn advance_checkpoint(
        &mut self,
        policy: &PolicyState,
        checkpoint: VaultPolicyCheckpointV1,
        current_policy_material: PolicyMaterialBytes,
    ) -> Result<(), WitnessEngineError> {
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
                return Ok(());
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
        let current = state
            .logical
            .vaults
            .get_mut(&checkpoint.vault_id)
            .ok_or_else(|| refused(WitnessReasonV1::InternalFailure))?;
        current.current_checkpoint = checkpoint;
        current.current_policy_material = current_policy_material;
        self.commit_and_publish(state, now_ms).map(|_| ())
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
                validate_cancellation(policy, request, cancellation, now_ms)?;
                return Ok(if known.state == ReplayStateV1::Cancelled {
                    CancellationProgress::Cancelled(Box::new(response.clone()))
                } else {
                    CancellationProgress::TooLate(Box::new(response.clone()))
                });
            }
        }
        self.validate_embedded_request(policy, &state, request, now_ms)?;
        validate_cancellation(policy, request, cancellation, now_ms)?;
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

    fn ready_state(&mut self) -> Result<PersistedWitnessState, WitnessEngineError> {
        let state = self
            .store
            .load()
            .map_err(|_| WitnessEngineError::store_unavailable())?;
        self.validate_stored_identity(&state)?;
        if state.pending_anchor.is_some() {
            self.publish_pending(state)?;
        } else {
            self.require_published_equality(&state)?;
        }
        let ready = self
            .store
            .load()
            .map_err(|_| WitnessEngineError::store_unavailable())?;
        self.validate_stored_identity(&ready)?;
        if ready.pending_anchor.is_some() {
            return Err(refused(WitnessReasonV1::AnchorConflict));
        }
        self.require_published_equality(&ready)?;
        Ok(ready)
    }

    fn validate_stored_identity(
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

    fn require_published_equality(
        &mut self,
        state: &PersistedWitnessState,
    ) -> Result<(), WitnessEngineError> {
        let external = self
            .external_anchor
            .read()
            .map_err(|_| WitnessEngineError::anchor_unavailable())?;
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

    fn publish_pending(&mut self, state: PersistedWitnessState) -> Result<(), WitnessEngineError> {
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

        let external = self
            .external_anchor
            .read()
            .map_err(|_| WitnessEngineError::anchor_unavailable())?;
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
            .map_err(|_| WitnessEngineError::anchor_unavailable())?
        {
            AnchorCompareAndSwap::Published => {}
            AnchorCompareAndSwap::Conflict => {
                let observed = self
                    .external_anchor
                    .read()
                    .map_err(|_| WitnessEngineError::anchor_unavailable())?;
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
            .map_err(|_| WitnessEngineError::anchor_unavailable())?
            .ok_or_else(|| refused(WitnessReasonV1::AnchorConflict))?;
        if !exact_anchor_eq(&readback, candidate)? {
            return Err(refused(WitnessReasonV1::AnchorConflict));
        }
        self.mark_published(candidate)
    }

    fn mark_published(
        &mut self,
        candidate: &WitnessStateAnchorV1,
    ) -> Result<(), WitnessEngineError> {
        let digest = candidate
            .digest()
            .map_err(|_| refused(WitnessReasonV1::Invalid))?;
        self.store
            .mark_anchor_published(&digest)
            .map_err(|_| WitnessEngineError::store_unavailable())
    }

    fn commit_and_publish(
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
        state.pending_anchor = Some(candidate);
        self.store
            .commit(expected_generation, state)
            .map_err(|_| WitnessEngineError::store_unavailable())?;
        self.ready_state()
    }

    fn build_anchor(
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
            .sign_validated_decision(
                &anchor
                    .signature_preimage()
                    .map_err(|_| refused(WitnessReasonV1::Invalid))?,
            )
            .map_err(|_| refused(WitnessReasonV1::InternalFailure))?;
        Ok(anchor)
    }

    fn validate_anchor(&self, anchor: &WitnessStateAnchorV1) -> Result<(), WitnessEngineError> {
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

    fn require_safe_clock(
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

    fn validate_request(
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
        if request.vault_id != policy.vault_id()
            || request.genesis_fingerprint != *policy.genesis_fingerprint()
            || request.vault_policy_sequence != policy.sequence()
            || request.vault_policy_hash != *policy.terminal_revision_hash()
        {
            return Err(refused(WitnessReasonV1::StalePolicy));
        }

        validate_request_time(request, now_ms)?;
        let request_lifetime = request
            .expires_at_ms
            .checked_sub(request.issued_at_ms)
            .ok_or_else(|| refused(WitnessReasonV1::Invalid))?;
        let operation = core_operation(request.operation);
        let rule = policy
            .witness_access_rule(&request.item_id, operation)
            .map_err(map_witness_rule_error)?;
        if request.witness_policy_id != rule.policy_id
            || request.witness_policy_revision != rule.policy_revision
            || request.witness_policy_digest != rule.policy_digest
            || request_lifetime > rule.allowed_request_lifetime_ms
        {
            return Err(refused(WitnessReasonV1::StalePolicy));
        }
        if manifest.timeout_ms > rule.max_timeout_ms
            || manifest.output_limit_bytes > rule.max_output_bytes
            || manifest.approval_target.entries.len() > usize::from(rule.max_target_count)
            || platform_rank(manifest.platform_assurance)
                < required_platform_rank(rule.required_platform_assurance)
        {
            return Err(refused(WitnessReasonV1::WorkloadExceeded));
        }
        validate_automatic_rule(manifest, &rule)?;

        let capability = operation_capability(request.operation);
        let access = policy.access(
            &request.item_id,
            &request.requester_principal_id,
            capability,
        );
        if !access.allowed || access.effective_role != Some(request.requested_access_role) {
            return Err(refused(WitnessReasonV1::PolicyDenied));
        }
        let requester = policy
            .principal(&request.requester_principal_id)
            .ok_or_else(|| refused(WitnessReasonV1::PolicyDenied))?;
        if matches!(
            requester.descriptor.principal_kind,
            PrincipalKind::Approver | PrincipalKind::Witness
        ) || request.requester_signing_key_epoch != 1
            || request.requester_signing_key_fingerprint
                != signing_key_fingerprint(
                    1,
                    &request.requester_principal_id,
                    1,
                    &requester.descriptor.verification_public_key,
                )
        {
            return Err(refused(WitnessReasonV1::InvalidSignature));
        }
        crypto::verify_bytes(
            &requester.descriptor.verification_public_key,
            &request
                .signature_preimage()
                .map_err(|_| refused(WitnessReasonV1::Invalid))?,
            &request.client_signature,
        )
        .map_err(|_| refused(WitnessReasonV1::InvalidSignature))?;

        let witness_policy = policy
            .witness_policy(&request.witness_policy_digest)
            .ok_or_else(|| refused(WitnessReasonV1::StalePolicy))?
            .clone();
        let expected_witnesses = witness_policy
            .witness_descriptors
            .iter()
            .filter(|descriptor| descriptor.status == DescriptorStatus::Active)
            .map(|descriptor| IntendedWitnessV1 {
                witness_id: descriptor.witness_id,
                share_index: descriptor.share_index,
                signing_key_fingerprint: descriptor.signing_key_fingerprint.clone(),
                contribution_key_fingerprint: descriptor.contribution_key_fingerprint.clone(),
            })
            .collect::<Vec<_>>();
        if request.intended_witness_set != expected_witnesses
            || request
                .intended_witness_set_digest()
                .map_err(|_| refused(WitnessReasonV1::Invalid))?
                != policy
                    .intended_witness_set_digest(&request.item_id)
                    .map_err(|_| refused(WitnessReasonV1::StalePolicy))?
        {
            return Err(refused(WitnessReasonV1::WrongScope));
        }

        let item = policy
            .item(&request.item_id)
            .ok_or_else(|| refused(WitnessReasonV1::WrongScope))?;
        if item.key_epoch != request.key_epoch
            || item.access_mode() != Some(request.item_access_mode)
        {
            return Err(refused(WitnessReasonV1::WrongScope));
        }
        let slot = item
            .witnessed_state
            .as_ref()
            .and_then(|witnessed| {
                witnessed.slots.iter().find(|slot| {
                    slot.slot_id == request.slot_id
                        && slot.content_role == request.content_role
                        && slot.revision == request.revision
                        && slot.revision_seal_id == request.revision_seal_id
                        && slot.key_epoch == request.key_epoch
                        && slot.item_access_mode == request.item_access_mode
                        && slot.vault_policy_sequence == request.vault_policy_sequence
                        && slot.witness_policy_id == request.witness_policy_id
                        && slot.witness_policy_revision == request.witness_policy_revision
                        && slot.witness_policy_digest == request.witness_policy_digest
                })
            })
            .ok_or_else(|| refused(WitnessReasonV1::WrongScope))?;
        let capsule = slot
            .capsules
            .iter()
            .find(|capsule| capsule.witness_id == self.identity.principal_id())
            .ok_or_else(|| refused(WitnessReasonV1::PolicyDenied))?
            .clone();
        let witness_descriptor = witness_policy
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
            || slot.threshold != rule.witness_threshold
            || usize::from(slot.member_count) != expected_witnesses.len()
        {
            return Err(refused(WitnessReasonV1::PolicyDenied));
        }
        Ok(ValidatedRequest {
            rule,
            policy: witness_policy,
            capsule,
            capsule_set_digest: slot.capsule_set_digest.clone(),
        })
    }

    fn validate_embedded_request(
        &self,
        policy: &PolicyState,
        state: &PersistedWitnessState,
        request: &jury_protocol::witness_v1::WitnessRequestV1,
        now_ms: u64,
    ) -> Result<(), WitnessEngineError> {
        request
            .validate_shape()
            .map_err(|_| refused(WitnessReasonV1::Invalid))?;
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
            || request.vault_id != policy.vault_id()
            || request.genesis_fingerprint != *policy.genesis_fingerprint()
            || request.vault_policy_sequence != policy.sequence()
            || request.vault_policy_hash != *policy.terminal_revision_hash()
        {
            return Err(refused(WitnessReasonV1::StalePolicy));
        }
        let requester = policy
            .principal(&request.requester_principal_id)
            .ok_or_else(|| refused(WitnessReasonV1::PolicyDenied))?;
        if request.requester_signing_key_epoch != 1
            || request.requester_signing_key_fingerprint
                != signing_key_fingerprint(
                    1,
                    &request.requester_principal_id,
                    1,
                    &requester.descriptor.verification_public_key,
                )
        {
            return Err(refused(WitnessReasonV1::InvalidSignature));
        }
        crypto::verify_bytes(
            &requester.descriptor.verification_public_key,
            &request
                .signature_preimage()
                .map_err(|_| refused(WitnessReasonV1::Invalid))?,
            &request.client_signature,
        )
        .map_err(|_| refused(WitnessReasonV1::InvalidSignature))
    }

    fn denial_response(
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
            .sign_validated_decision(
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

    fn approval_response(
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
        let share = self
            .identity
            .open_contribution_share(&validated.capsule)
            .map_err(|_| refused(WitnessReasonV1::InvalidContribution))?;
        let contribution = share
            .seal_for_request_with_source(
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
            .map_err(|_| refused(WitnessReasonV1::InvalidContribution))?
            .into_protocol();
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
            .sign_validated_decision(
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

fn validate_checkpoint(
    policy: &PolicyState,
    checkpoint: &VaultPolicyCheckpointV1,
    identity: &WitnessIdentity,
) -> Result<(), WitnessEngineError> {
    let witness_policy = validate_checkpoint_public(policy, checkpoint)?;
    let own_descriptor = identity
        .public_descriptor()
        .map_err(|_| refused(WitnessReasonV1::InternalFailure))?;
    if !witness_policy.witness_descriptors.iter().any(|descriptor| {
        descriptor.status == DescriptorStatus::Active
            && descriptor.witness_id == own_descriptor.principal_id
            && descriptor.signing_public_key == own_descriptor.verification_public_key
            && descriptor.contribution_public_key == own_descriptor.recipient_public_key
    }) {
        return Err(refused(WitnessReasonV1::PolicyDenied));
    }
    Ok(())
}

fn validate_registered_checkpoint(
    policy: &PolicyState,
    checkpoint: &VaultPolicyCheckpointV1,
    identity: &WitnessIdentity,
) -> Result<(), WitnessEngineError> {
    if checkpoint.vault_policy_sequence < policy.sequence() {
        return Err(refused(WitnessReasonV1::WitnessBehind));
    }
    if checkpoint.vault_policy_sequence > policy.sequence() {
        return Err(refused(WitnessReasonV1::StalePolicy));
    }
    validate_checkpoint(policy, checkpoint, identity)
}

fn validate_checkpoint_public<'a>(
    policy: &'a PolicyState,
    checkpoint: &VaultPolicyCheckpointV1,
) -> Result<&'a WitnessPolicy, WitnessEngineError> {
    checkpoint
        .validate_shape()
        .map_err(|_| refused(WitnessReasonV1::Invalid))?;
    if checkpoint.vault_id != policy.vault_id()
        || checkpoint.genesis_fingerprint != *policy.genesis_fingerprint()
        || checkpoint.vault_policy_sequence != policy.sequence()
        || checkpoint.vault_policy_hash != *policy.terminal_revision_hash()
    {
        return Err(refused(WitnessReasonV1::CheckpointFork));
    }
    let witness_policy = policy
        .witness_policy(&checkpoint.witness_policy_digest)
        .ok_or_else(|| refused(WitnessReasonV1::CheckpointFork))?;
    let (approver_set_digest, witness_set_digest) = witness_policy
        .active_descriptor_set_digests()
        .map_err(|_| refused(WitnessReasonV1::Invalid))?;
    if checkpoint.witness_policy_id != witness_policy.witness_policy_id
        || checkpoint.witness_policy_revision != witness_policy.revision
        || checkpoint.witness_policy_digest
            != witness_policy
                .digest()
                .map_err(|_| refused(WitnessReasonV1::Invalid))?
        || checkpoint.witness_set_digest != witness_set_digest
        || checkpoint.approver_set_digest != approver_set_digest
        || checkpoint.review_label_set_digest != witness_policy.review_label_set_digest
        || witness_policy.vault_policy_sequence != policy.sequence()
        || witness_policy.vault_policy_hash != *policy.terminal_revision_hash()
    {
        return Err(refused(WitnessReasonV1::CheckpointFork));
    }
    let owner = policy
        .principal(&checkpoint.issuer_owner_id)
        .filter(|_| policy.is_owner(&checkpoint.issuer_owner_id))
        .ok_or_else(|| refused(WitnessReasonV1::InvalidSignature))?;
    if checkpoint.issuer_key_epoch != 1
        || checkpoint.issuer_key_fingerprint
            != signing_key_fingerprint(
                1,
                &checkpoint.issuer_owner_id,
                1,
                &owner.descriptor.verification_public_key,
            )
    {
        return Err(refused(WitnessReasonV1::InvalidSignature));
    }
    crypto::verify_bytes(
        &owner.descriptor.verification_public_key,
        &checkpoint
            .signature_preimage()
            .map_err(|_| refused(WitnessReasonV1::Invalid))?,
        &checkpoint.signature,
    )
    .map_err(|_| refused(WitnessReasonV1::InvalidSignature))?;
    Ok(witness_policy)
}

fn validate_request_time(
    request: &jury_protocol::witness_v1::WitnessRequestV1,
    now_ms: u64,
) -> Result<(), WitnessEngineError> {
    let skewed_now = now_ms.saturating_add(ACCEPTED_CLOCK_SKEW_MS);
    if request.issued_at_ms > skewed_now {
        return Err(refused(WitnessReasonV1::NotYetValid));
    }
    if request
        .not_before_ms
        .is_some_and(|not_before| not_before > skewed_now)
    {
        return Err(refused(WitnessReasonV1::NotYetValid));
    }
    if now_ms >= request.expires_at_ms {
        return Err(refused(WitnessReasonV1::Expired));
    }
    Ok(())
}

fn validate_automatic_rule(
    manifest: &ActionManifestV1,
    rule: &WitnessAccessRule,
) -> Result<(), WitnessEngineError> {
    if rule.approval_threshold != 0 {
        return Ok(());
    }
    let all_allowed = manifest.approval_target.entries.iter().all(|entry| {
        rule.automatic_read_targets
            .iter()
            .any(|target| target.item_id == entry.item_id && target.field_id == entry.field_id)
    });
    if !all_allowed || manifest.operation != WitnessOperationV1::ReadStdout {
        return Err(refused(WitnessReasonV1::PolicyDenied));
    }
    Ok(())
}

fn validate_approval(
    approval: &ApprovalDecisionV1,
    request: &jury_protocol::witness_v1::WitnessRequestV1,
    manifest: &ActionManifestV1,
    validated: &ValidatedRequest,
    now_ms: u64,
) -> Result<(), WitnessEngineError> {
    validate_approval_static(approval, request, manifest, validated)?;
    if !approval_is_current(approval, now_ms) {
        return Err(refused(WitnessReasonV1::Invalid));
    }
    Ok(())
}

fn validate_approval_static(
    approval: &ApprovalDecisionV1,
    request: &jury_protocol::witness_v1::WitnessRequestV1,
    manifest: &ActionManifestV1,
    validated: &ValidatedRequest,
) -> Result<(), WitnessEngineError> {
    approval
        .validate_shape()
        .map_err(|_| refused(WitnessReasonV1::Invalid))?;
    let descriptor = validated
        .policy
        .approver_descriptors
        .iter()
        .find(|descriptor| {
            descriptor.status == DescriptorStatus::Active
                && descriptor.approver_id == approval.approver_id
        })
        .ok_or_else(|| refused(WitnessReasonV1::PolicyDenied))?;
    if !validated
        .rule
        .eligible_approver_ids
        .contains(&approval.approver_id)
        || approval.request_id != request.request_id
        || approval.request_digest
            != request
                .digest()
                .map_err(|_| refused(WitnessReasonV1::Invalid))?
        || approval.action_manifest_digest
            != manifest
                .digest()
                .map_err(|_| refused(WitnessReasonV1::Invalid))?
        || approval.presentation_digest != manifest.presentation_digest
        || approval.witness_policy_id != request.witness_policy_id
        || approval.witness_policy_revision != request.witness_policy_revision
        || approval.witness_policy_digest != request.witness_policy_digest
        || approval.intended_witness_set_digest
            != request
                .intended_witness_set_digest()
                .map_err(|_| refused(WitnessReasonV1::Invalid))?
        || approval.approver_key_fingerprint != descriptor.signing_key_fingerprint
        || approval.approver_key_epoch != descriptor.signing_key_epoch
        || approval.approval_mode != protocol_approval_mode(descriptor.approval_mode)
        || approval.issued_at_ms < request.issued_at_ms
        || approval.expires_at_ms > request.expires_at_ms
    {
        return Err(refused(WitnessReasonV1::Invalid));
    }
    crypto::verify_bytes(
        &descriptor.signing_public_key,
        &approval
            .signature_preimage()
            .map_err(|_| refused(WitnessReasonV1::Invalid))?,
        &approval.signature,
    )
    .map_err(|_| refused(WitnessReasonV1::InvalidSignature))
}

fn approval_is_current(approval: &ApprovalDecisionV1, now_ms: u64) -> bool {
    approval.issued_at_ms <= now_ms.saturating_add(ACCEPTED_CLOCK_SKEW_MS)
        && now_ms < approval.expires_at_ms
        && approval
            .not_before_ms
            .is_none_or(|not_before| not_before <= now_ms.saturating_add(ACCEPTED_CLOCK_SKEW_MS))
}

fn validate_cancellation(
    policy: &PolicyState,
    request: &jury_protocol::witness_v1::WitnessRequestV1,
    cancellation: &RequestCancellationV1,
    now_ms: u64,
) -> Result<(), WitnessEngineError> {
    cancellation
        .validate_shape()
        .map_err(|_| refused(WitnessReasonV1::Invalid))?;
    if cancellation.request_signature_preimage.as_bytes()
        != request
            .signature_preimage()
            .map_err(|_| refused(WitnessReasonV1::Invalid))?
        || cancellation.client_signature != request.client_signature
        || cancellation.request_id != request.request_id
        || cancellation.request_digest
            != request
                .digest()
                .map_err(|_| refused(WitnessReasonV1::Invalid))?
        || cancellation.issued_at_ms > now_ms.saturating_add(ACCEPTED_CLOCK_SKEW_MS)
        || cancellation.issued_at_ms < request.issued_at_ms
        || cancellation.canceller_key_epoch != 1
    {
        return Err(refused(WitnessReasonV1::Invalid));
    }
    let canceller = policy
        .principal(&cancellation.canceller_id)
        .ok_or_else(|| refused(WitnessReasonV1::PolicyDenied))?;
    let role_valid = match cancellation.canceller_role {
        CancellerRoleV1::OriginalRequester => {
            cancellation.canceller_id == request.requester_principal_id
        }
        CancellerRoleV1::CurrentOwner => policy.is_owner(&cancellation.canceller_id),
    };
    if !role_valid
        || cancellation.canceller_key_fingerprint
            != signing_key_fingerprint(
                1,
                &cancellation.canceller_id,
                1,
                &canceller.descriptor.verification_public_key,
            )
    {
        return Err(refused(WitnessReasonV1::PolicyDenied));
    }
    crypto::verify_bytes(
        &canceller.descriptor.verification_public_key,
        &cancellation
            .signature_preimage()
            .map_err(|_| refused(WitnessReasonV1::Invalid))?,
        &cancellation.signature,
    )
    .map_err(|_| refused(WitnessReasonV1::InvalidSignature))
}

fn normalize_approvals(
    approvals: Vec<ApprovalDecisionV1>,
) -> Result<Vec<ApprovalDecisionV1>, WitnessEngineError> {
    let mut keyed = approvals
        .into_iter()
        .map(|approval| {
            let bytes = approval
                .canonical_bytes()
                .map_err(|_| refused(WitnessReasonV1::Invalid))?;
            Ok((approval.approver_id, bytes, approval))
        })
        .collect::<Result<Vec<_>, WitnessEngineError>>()?;
    keyed.sort_by(|left, right| (&left.0, &left.1).cmp(&(&right.0, &right.1)));
    keyed.dedup_by(|left, right| left.0 == right.0 && left.1 == right.1);
    let mut retained: Vec<(PrincipalId, Vec<u8>, ApprovalDecisionV1)> = Vec::new();
    for entry in keyed {
        let same_approver = retained
            .iter()
            .rev()
            .take_while(|prior| prior.0 == entry.0)
            .count();
        if same_approver < 2 {
            retained.push(entry);
        }
    }
    if retained.len() > MAX_RECORDED_APPROVALS {
        return Err(refused(WitnessReasonV1::CapacityExhausted));
    }
    Ok(retained
        .into_iter()
        .map(|(_, _, approval)| approval)
        .collect())
}

fn tally_approvals(approvals: &[ApprovalDecisionV1], rule: &WitnessAccessRule) -> ApprovalTally {
    let mut approved = 0;
    let mut undecided = 0;
    let mut conflicted = false;
    for approver_id in &rule.eligible_approver_ids {
        let decisions = approvals
            .iter()
            .filter(|decision| decision.approver_id == *approver_id)
            .collect::<Vec<_>>();
        match decisions.as_slice() {
            [] => undecided += 1,
            [decision] if decision.decision == ApprovalDecisionKindV1::Approve => approved += 1,
            [_] => {}
            _ => conflicted = true,
        }
    }
    ApprovalTally {
        approved,
        undecided,
        conflicted,
    }
}

const fn protocol_approval_mode(mode: ApprovalMode) -> ApprovalModeV1 {
    match mode {
        ApprovalMode::Human => ApprovalModeV1::Human,
        ApprovalMode::Automatic => ApprovalModeV1::Automatic,
    }
}

fn same_request(
    left: &jury_protocol::witness_v1::WitnessRequestV1,
    right: &jury_protocol::witness_v1::WitnessRequestV1,
) -> Result<bool, WitnessEngineError> {
    Ok(left
        .canonical_bytes()
        .map_err(|_| refused(WitnessReasonV1::Invalid))?
        == right
            .canonical_bytes()
            .map_err(|_| refused(WitnessReasonV1::Invalid))?)
}

fn exact_anchor_eq(
    left: &WitnessStateAnchorV1,
    right: &WitnessStateAnchorV1,
) -> Result<bool, WitnessEngineError> {
    Ok(left
        .canonical_bytes()
        .map_err(|_| refused(WitnessReasonV1::Invalid))?
        == right
            .canonical_bytes()
            .map_err(|_| refused(WitnessReasonV1::Invalid))?)
}

fn random_response_id(source: &mut impl RandomSource) -> Result<ResponseId, WitnessEngineError> {
    let mut bytes = [0_u8; 32];
    source
        .fill(&mut bytes)
        .map_err(|_| refused(WitnessReasonV1::InternalFailure))?;
    ResponseId::from_bytes(bytes).map_err(|_| refused(WitnessReasonV1::InternalFailure))
}

const fn core_operation(operation: WitnessOperationV1) -> WitnessOperation {
    match operation {
        WitnessOperationV1::ReadStdout => WitnessOperation::ReadStdout,
        WitnessOperationV1::WritePrivateFile => WitnessOperation::WritePrivateFile,
        WitnessOperationV1::TemplateInjection => WitnessOperation::TemplateInjection,
        WitnessOperationV1::ChildEnvironment => WitnessOperation::ChildEnvironment,
        WitnessOperationV1::ChildStdin => WitnessOperation::ChildStdin,
        WitnessOperationV1::ItemMutation => WitnessOperation::ItemMutation,
        WitnessOperationV1::Backup => WitnessOperation::Backup,
        WitnessOperationV1::Recovery => WitnessOperation::Recovery,
        WitnessOperationV1::AdministrativeRekey => WitnessOperation::AdministrativeRekey,
    }
}

const fn operation_capability(operation: WitnessOperationV1) -> Capability {
    match operation {
        WitnessOperationV1::ReadStdout
        | WitnessOperationV1::TemplateInjection
        | WitnessOperationV1::ChildEnvironment
        | WitnessOperationV1::ChildStdin => Capability::Read,
        WitnessOperationV1::WritePrivateFile
        | WitnessOperationV1::ItemMutation
        | WitnessOperationV1::Backup => Capability::Write,
        WitnessOperationV1::Recovery | WitnessOperationV1::AdministrativeRekey => {
            Capability::Administer
        }
    }
}

const fn platform_rank(platform: jury_protocol::witness_v1::PlatformAssuranceV1) -> u8 {
    match platform {
        jury_protocol::witness_v1::PlatformAssuranceV1::NormalizedPathOnly => 1,
        jury_protocol::witness_v1::PlatformAssuranceV1::StableExecutableIdentity => 2,
    }
}

const fn required_platform_rank(platform: PlatformAssurance) -> u8 {
    match platform {
        PlatformAssurance::NormalizedPathOnly => 1,
        PlatformAssurance::StableExecutableIdentity => 2,
    }
}

fn validate_public_request(
    policy: &PolicyState,
    checkpoint: &VaultPolicyCheckpointV1,
    request: &jury_protocol::witness_v1::WitnessRequestV1,
    manifest: &ActionManifestV1,
) -> Result<ValidatedPublicRequest, WitnessEngineError> {
    validate_request_manifest(request, manifest)?;
    let witness_policy = validate_checkpoint_public(policy, checkpoint)?.clone();
    let checkpoint_digest = checkpoint
        .digest()
        .map_err(|_| refused(WitnessReasonV1::Invalid))?;
    if request.vault_id != checkpoint.vault_id
        || request.genesis_fingerprint != checkpoint.genesis_fingerprint
        || request.vault_policy_sequence != checkpoint.vault_policy_sequence
        || request.vault_policy_hash != checkpoint.vault_policy_hash
        || request.policy_checkpoint_digest != checkpoint_digest
        || request.witness_policy_id != checkpoint.witness_policy_id
        || request.witness_policy_revision != checkpoint.witness_policy_revision
        || request.witness_policy_digest != checkpoint.witness_policy_digest
    {
        return Err(refused(WitnessReasonV1::WrongScope));
    }

    let request_lifetime = request
        .expires_at_ms
        .checked_sub(request.issued_at_ms)
        .ok_or_else(|| refused(WitnessReasonV1::Invalid))?;
    let rule = policy
        .witness_access_rule(&request.item_id, core_operation(request.operation))
        .map_err(map_witness_rule_error)?;
    if request.witness_policy_id != rule.policy_id
        || request.witness_policy_revision != rule.policy_revision
        || request.witness_policy_digest != rule.policy_digest
        || request_lifetime > rule.allowed_request_lifetime_ms
    {
        return Err(refused(WitnessReasonV1::StalePolicy));
    }
    if manifest.timeout_ms > rule.max_timeout_ms
        || manifest.output_limit_bytes > rule.max_output_bytes
        || manifest.approval_target.entries.len() > usize::from(rule.max_target_count)
        || platform_rank(manifest.platform_assurance)
            < required_platform_rank(rule.required_platform_assurance)
    {
        return Err(refused(WitnessReasonV1::WorkloadExceeded));
    }
    validate_automatic_rule(manifest, &rule)?;

    let access = policy.access(
        &request.item_id,
        &request.requester_principal_id,
        operation_capability(request.operation),
    );
    if !access.allowed || access.effective_role != Some(request.requested_access_role) {
        return Err(refused(WitnessReasonV1::PolicyDenied));
    }
    let requester = policy
        .principal(&request.requester_principal_id)
        .ok_or_else(|| refused(WitnessReasonV1::PolicyDenied))?;
    if matches!(
        requester.descriptor.principal_kind,
        PrincipalKind::Approver | PrincipalKind::Witness
    ) || request.requester_signing_key_epoch != 1
        || request.requester_signing_key_fingerprint
            != signing_key_fingerprint(
                1,
                &request.requester_principal_id,
                1,
                &requester.descriptor.verification_public_key,
            )
    {
        return Err(refused(WitnessReasonV1::InvalidSignature));
    }
    crypto::verify_bytes(
        &requester.descriptor.verification_public_key,
        &request
            .signature_preimage()
            .map_err(|_| refused(WitnessReasonV1::Invalid))?,
        &request.client_signature,
    )
    .map_err(|_| refused(WitnessReasonV1::InvalidSignature))?;

    let expected_witnesses = witness_policy
        .witness_descriptors
        .iter()
        .filter(|descriptor| descriptor.status == DescriptorStatus::Active)
        .map(|descriptor| IntendedWitnessV1 {
            witness_id: descriptor.witness_id,
            share_index: descriptor.share_index,
            signing_key_fingerprint: descriptor.signing_key_fingerprint.clone(),
            contribution_key_fingerprint: descriptor.contribution_key_fingerprint.clone(),
        })
        .collect::<Vec<_>>();
    if request.intended_witness_set != expected_witnesses
        || request
            .intended_witness_set_digest()
            .map_err(|_| refused(WitnessReasonV1::Invalid))?
            != policy
                .intended_witness_set_digest(&request.item_id)
                .map_err(|_| refused(WitnessReasonV1::StalePolicy))?
    {
        return Err(refused(WitnessReasonV1::WrongScope));
    }

    let item = policy
        .item(&request.item_id)
        .ok_or_else(|| refused(WitnessReasonV1::WrongScope))?;
    if item.key_epoch != request.key_epoch || item.access_mode() != Some(request.item_access_mode) {
        return Err(refused(WitnessReasonV1::WrongScope));
    }
    let slot = item
        .witnessed_state
        .as_ref()
        .and_then(|witnessed| {
            witnessed.slots.iter().find(|slot| {
                slot.slot_id == request.slot_id
                    && slot.content_role == request.content_role
                    && slot.revision == request.revision
                    && slot.revision_seal_id == request.revision_seal_id
                    && slot.key_epoch == request.key_epoch
                    && slot.item_access_mode == request.item_access_mode
                    && slot.vault_policy_sequence == request.vault_policy_sequence
                    && slot.witness_policy_id == request.witness_policy_id
                    && slot.witness_policy_revision == request.witness_policy_revision
                    && slot.witness_policy_digest == request.witness_policy_digest
            })
        })
        .ok_or_else(|| refused(WitnessReasonV1::WrongScope))?;
    if slot.threshold != rule.witness_threshold
        || usize::from(slot.member_count) != expected_witnesses.len()
    {
        return Err(refused(WitnessReasonV1::WrongScope));
    }
    Ok(ValidatedPublicRequest {
        rule,
        policy: witness_policy,
        slot: slot.clone(),
    })
}

pub fn validate_request_manifest(
    request: &jury_protocol::witness_v1::WitnessRequestV1,
    manifest: &ActionManifestV1,
) -> Result<(), WitnessEngineError> {
    if request.schema != 1
        || request.protocol_version != jury_protocol::witness_v1::PROTOCOL_VERSION
        || request.construction != jury_protocol::witness_v1::CONSTRUCTION
        || manifest.schema != 1
    {
        return Err(refused(WitnessReasonV1::UnsupportedVersion));
    }
    request
        .validate_shape()
        .map_err(|_| refused(WitnessReasonV1::Invalid))?;
    manifest
        .validate_shape()
        .map_err(|_| refused(WitnessReasonV1::WrongScope))?;
    if manifest.approval_target.entries.iter().any(|entry| {
        entry.item_id != request.item_id
            || (request.content_role == jury_protocol::vault_v1::ContentRole::Descriptor
                && entry.field_id.is_some())
    }) {
        return Err(refused(WitnessReasonV1::WrongScope));
    }
    let manifest_digest = manifest
        .digest()
        .map_err(|_| refused(WitnessReasonV1::Invalid))?;
    let workload_digest = manifest
        .workload_digest()
        .map_err(|_| refused(WitnessReasonV1::Invalid))?;
    if request.request_id != manifest.request_id
        || request.vault_id != manifest.vault_id
        || request.genesis_fingerprint != manifest.genesis_fingerprint
        || request.item_id != manifest.item_id
        || request.key_epoch != manifest.key_epoch
        || request.item_access_mode != manifest.item_access_mode
        || request.slot_id != manifest.slot_id
        || request.content_role != manifest.content_role
        || request.revision != manifest.revision
        || request.revision_seal_id != manifest.revision_seal_id
        || request.vault_policy_sequence != manifest.vault_policy_sequence
        || request.vault_policy_hash != manifest.vault_policy_hash
        || request.witness_policy_id != manifest.witness_policy_id
        || request.witness_policy_revision != manifest.witness_policy_revision
        || request.witness_policy_digest != manifest.witness_policy_digest
        || request.requester_principal_id != manifest.requester_principal_id
        || request.requested_access_role != manifest.requested_access_role
        || request.operation != manifest.operation
        || request.approval_target_digest != manifest.approval_target_digest
        || request.action_manifest_digest != manifest_digest
        || request.workload_digest != workload_digest
        || request.issued_at_ms != manifest.issued_at_ms
        || request.not_before_ms != manifest.not_before_ms
        || request.expires_at_ms != manifest.expires_at_ms
    {
        return Err(refused(WitnessReasonV1::WrongScope));
    }
    Ok(())
}

pub fn validate_witness_response(
    policy: &PolicyState,
    checkpoint: &VaultPolicyCheckpointV1,
    request: &jury_protocol::witness_v1::WitnessRequestV1,
    manifest: &ActionManifestV1,
    response: &WitnessResponseV1,
) -> Result<(), WitnessEngineError> {
    let validated = validate_public_request(policy, checkpoint, request, manifest)?;
    let witness_policy = &validated.policy;
    let request_digest = request
        .digest()
        .map_err(|_| refused(WitnessReasonV1::Invalid))?;
    let manifest_digest = manifest
        .digest()
        .map_err(|_| refused(WitnessReasonV1::Invalid))?;
    let checkpoint_digest = checkpoint
        .digest()
        .map_err(|_| refused(WitnessReasonV1::Invalid))?;
    response
        .canonical_bytes()
        .map_err(|_| refused(WitnessReasonV1::InvalidContribution))?;
    let decision = &response.decision;
    if decision.request_id != request.request_id
        || decision.request_digest != request_digest
        || decision.action_manifest_digest != manifest_digest
        || decision.witness_policy_id != request.witness_policy_id
        || decision.witness_policy_revision != request.witness_policy_revision
        || decision.witness_policy_digest != request.witness_policy_digest
        || decision.policy_checkpoint_digest != checkpoint_digest
        || decision.policy_checkpoint_digest != request.policy_checkpoint_digest
        || decision.issued_at_ms < request.issued_at_ms
        || decision.expires_at_ms != request.expires_at_ms
    {
        return Err(refused(WitnessReasonV1::WrongScope));
    }
    let descriptor = witness_policy
        .witness_descriptors
        .iter()
        .find(|descriptor| {
            descriptor.status == DescriptorStatus::Active
                && descriptor.witness_id == decision.witness_id
        })
        .ok_or_else(|| refused(WitnessReasonV1::PolicyDenied))?;
    if decision.witness_signing_key_epoch != descriptor.signing_key_epoch
        || decision.witness_signing_key_fingerprint != descriptor.signing_key_fingerprint
    {
        return Err(refused(WitnessReasonV1::InvalidSignature));
    }
    crypto::verify_bytes(
        &descriptor.signing_public_key,
        &decision
            .signature_preimage()
            .map_err(|_| refused(WitnessReasonV1::Invalid))?,
        &decision.signature,
    )
    .map_err(|_| refused(WitnessReasonV1::InvalidSignature))?;
    if decision.decision != WitnessDecisionKindV1::Approve {
        return Ok(());
    }
    let contribution = response
        .contribution
        .as_ref()
        .ok_or_else(|| refused(WitnessReasonV1::InvalidContribution))?;
    let capsule = validated
        .slot
        .capsules
        .iter()
        .find(|capsule| capsule.witness_id == decision.witness_id)
        .ok_or_else(|| refused(WitnessReasonV1::InvalidContribution))?;
    if contribution.response_id != decision.response_id
        || decision.share_index != Some(contribution.share_index)
        || decision.share_commitment.as_ref() != Some(&contribution.share_commitment)
        || contribution.share_index != descriptor.share_index
        || contribution.share_index != capsule.share_index
        || contribution.share_commitment != capsule.share_commitment
        || contribution.capsule_context_digest != capsule.context_digest
        || contribution.capsule_set_digest != validated.slot.capsule_set_digest
        || contribution.request_session_key_fingerprint != request.request_session_key_fingerprint
    {
        return Err(refused(WitnessReasonV1::InvalidContribution));
    }
    Ok(())
}

pub fn validate_receipt_material(
    policy: &PolicyState,
    checkpoint: &VaultPolicyCheckpointV1,
    request: &jury_protocol::witness_v1::WitnessRequestV1,
    manifest: &ActionManifestV1,
    material: &WitnessReceiptMaterialV1,
) -> Result<(), WitnessEngineError> {
    let validated = validate_public_request(policy, checkpoint, request, manifest)?;
    material
        .canonical_bytes()
        .map_err(|_| refused(WitnessReasonV1::Invalid))?;
    let rule = &validated.rule;
    let valid_approvers = material
        .counted_approver_ids
        .iter()
        .all(|id| rule.eligible_approver_ids.contains(id));
    let valid_witnesses = material
        .counted_witness_ids
        .iter()
        .all(|id| rule.witness_ids.contains(id));
    let successful = material.reason == WitnessReasonV1::None;
    if material.request_digest
        != request
            .digest()
            .map_err(|_| refused(WitnessReasonV1::Invalid))?
        || material.action_manifest_digest
            != manifest
                .digest()
                .map_err(|_| refused(WitnessReasonV1::Invalid))?
        || material.presentation_digest != manifest.presentation_digest
        || material.policy_checkpoint_digest
            != checkpoint
                .digest()
                .map_err(|_| refused(WitnessReasonV1::Invalid))?
        || material.witness_policy_digest != request.witness_policy_digest
        || material.approval_threshold != rule.approval_threshold
        || material.witness_threshold != rule.witness_threshold
        || material.issued_at_ms < request.issued_at_ms
        || material.expires_at_ms != request.expires_at_ms
        || !valid_approvers
        || !valid_witnesses
        || (successful
            && (material.counted_approver_ids.len() < usize::from(rule.approval_threshold)
                || material.counted_witness_ids.len() < usize::from(rule.witness_threshold)))
    {
        return Err(refused(WitnessReasonV1::WrongScope));
    }
    Ok(())
}

fn map_witness_rule_error(error: PolicyError) -> WitnessEngineError {
    match error.kind() {
        PolicyErrorKind::UnknownItem => refused(WitnessReasonV1::WrongScope),
        PolicyErrorKind::Unauthorized => refused(WitnessReasonV1::WrongOperation),
        PolicyErrorKind::MissingWitnessPolicy => refused(WitnessReasonV1::StalePolicy),
        _ => refused(WitnessReasonV1::PolicyDenied),
    }
}

const fn refused(reason: WitnessReasonV1) -> WitnessEngineError {
    WitnessEngineError::refused(reason)
}

#[cfg(test)]
#[path = "witness_engine_tests.rs"]
mod tests;
