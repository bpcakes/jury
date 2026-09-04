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
        BoundedBytes, Digest32, PrincipalDescriptorV1, PrincipalId, RequestId, ResponseId,
        Signature64, VaultId, WitnessShareCapsuleV1,
    },
    witness_v1::{
        ACCEPTED_CLOCK_SKEW_MS, ActionManifestV1, ApprovalBytes, ApprovalDecisionKindV1,
        ApprovalDecisionV1, CancellationBytes, CancellerRoleV1, MAX_RECORDED_APPROVALS,
        MAX_REPLAY_RECORDS_PER_SERVICE, MAX_REPLAY_RECORDS_PER_VAULT, PolicyMaterialBytes,
        REPLAY_RETENTION_MS, RegistrationBytes, ReplayStateV1, RequestCancellationV1,
        VaultHighWatermarkV1, VaultPolicyCheckpointV1, WitnessCheckpointAcknowledgementV1,
        WitnessContributionEnvelopeV1, WitnessDatabaseStateV1, WitnessDecisionKindV1,
        WitnessDecisionV1, WitnessOperationV1, WitnessReasonV1, WitnessReceiptMaterialV1,
        WitnessReplayRecordV1, WitnessResponseV1, WitnessStateAnchorV1, WitnessVaultStateV1,
        signing_key_fingerprint,
    },
};
use serde::{Deserialize, Serialize};

use crate::{
    crypto,
    entropy::RandomSource,
    identity::{WitnessContributionTarget, WitnessIdentity},
    policy::{
        DescriptorStatus, PolicyState, WitnessAccessRule, WitnessPolicy, platform_assurance_tag,
        protocol_approval_mode,
    },
    witness_validation::{RequestPolicyError, validate_request_policy},
};

const ZERO_DIGEST: Digest32 = Digest32::new([0; 32]);

/// Value-free failure from a software or hardware-backed witness identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WitnessIdentityOperationError;

impl WitnessIdentityOperationError {
    /// Creates the only public provider failure value. Provider-specific errors
    /// must remain behind the adapter boundary and must not expose key details.
    #[must_use]
    pub const fn provider_failure() -> Self {
        Self
    }
}

impl fmt::Display for WitnessIdentityOperationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("witness identity provider operation failed")
    }
}

impl std::error::Error for WitnessIdentityOperationError {}

/// The complete private-operation boundary consumed by the witness engine.
///
/// A hardware provider can implement this trait without exporting signing
/// keys, contribution private keys, or plaintext witness shares. The returned
/// contribution is already encrypted to the request session.
pub trait WitnessEngineIdentity: Send {
    fn principal_id(&self) -> PrincipalId;

    fn public_descriptor(&self) -> Result<PrincipalDescriptorV1, WitnessIdentityOperationError>;

    fn sign_witness_statement(
        &self,
        preimage: &[u8],
    ) -> Result<Signature64, WitnessIdentityOperationError>;

    fn seal_witness_contribution(
        &self,
        capsule: &WitnessShareCapsuleV1,
        target: &WitnessContributionTarget,
        random: &mut dyn RandomSource,
    ) -> Result<WitnessContributionEnvelopeV1, WitnessIdentityOperationError>;
}

impl WitnessEngineIdentity for WitnessIdentity {
    fn principal_id(&self) -> PrincipalId {
        WitnessIdentity::principal_id(self)
    }

    fn public_descriptor(&self) -> Result<PrincipalDescriptorV1, WitnessIdentityOperationError> {
        WitnessIdentity::public_descriptor(self).map_err(|_| WitnessIdentityOperationError)
    }

    fn sign_witness_statement(
        &self,
        preimage: &[u8],
    ) -> Result<Signature64, WitnessIdentityOperationError> {
        self.sign_validated_decision(preimage)
            .map_err(|_| WitnessIdentityOperationError)
    }

    fn seal_witness_contribution(
        &self,
        capsule: &WitnessShareCapsuleV1,
        target: &WitnessContributionTarget,
        random: &mut dyn RandomSource,
    ) -> Result<WitnessContributionEnvelopeV1, WitnessIdentityOperationError> {
        self.open_contribution_share(capsule)
            .and_then(|share| share.seal_for_request_with_source(target, random))
            .map(|contribution| contribution.into_protocol())
            .map_err(|_| WitnessIdentityOperationError)
    }
}

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
pub enum WitnessStoreErrorKind {
    Unavailable,
    CapacityExhausted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WitnessStoreError {
    kind: WitnessStoreErrorKind,
}

impl WitnessStoreError {
    #[must_use]
    pub const fn unavailable() -> Self {
        Self {
            kind: WitnessStoreErrorKind::Unavailable,
        }
    }

    #[must_use]
    pub const fn capacity_exhausted() -> Self {
        Self {
            kind: WitnessStoreErrorKind::CapacityExhausted,
        }
    }

    #[must_use]
    pub const fn kind(self) -> WitnessStoreErrorKind {
        self.kind
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WitnessAnchorErrorKind {
    Unavailable,
    CapacityExhausted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WitnessAnchorError {
    kind: WitnessAnchorErrorKind,
}

impl WitnessAnchorError {
    #[must_use]
    pub const fn unavailable() -> Self {
        Self {
            kind: WitnessAnchorErrorKind::Unavailable,
        }
    }

    #[must_use]
    pub const fn capacity_exhausted() -> Self {
        Self {
            kind: WitnessAnchorErrorKind::CapacityExhausted,
        }
    }

    #[must_use]
    pub const fn kind(self) -> WitnessAnchorErrorKind {
        self.kind
    }
}

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
    fn ensure_publishable(
        &mut self,
        _candidate: &WitnessStateAnchorV1,
    ) -> Result<(), WitnessAnchorError> {
        Ok(())
    }

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

/// Value-free state exported only after exact database/external-anchor
/// reconciliation. One signed anchor contains all per-vault watermarks, so the
/// status payload grows linearly rather than cloning that anchor once per
/// vault. Callers must not infer aggregate freshness across witnesses.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessOperationalStatus {
    pub witness_id: PrincipalId,
    pub state_generation: u64,
    pub replay_record_count: usize,
    pub compactable_replay_record_count: usize,
    pub replay_retain_through_ms: u64,
    pub published_anchor: Option<WitnessStateAnchorV1>,
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
pub(crate) struct ValidatedPublicRequest {
    pub(crate) rule: WitnessAccessRule,
    pub(crate) policy: WitnessPolicy,
    pub(crate) slot: jury_protocol::vault_v1::WitnessedSlotV1,
}

pub struct WitnessEngine<'a, S, A, C, R, I: ?Sized = WitnessIdentity> {
    identity: &'a I,
    store: &'a mut S,
    external_anchor: &'a mut A,
    clock: &'a C,
    random: &'a mut R,
}

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
        if checkpoint.predecessor_checkpoint_digest != ZERO_DIGEST {
            return Err(refused(WitnessReasonV1::CheckpointFork));
        }
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

    fn ready_state(&mut self) -> Result<PersistedWitnessState, WitnessEngineError> {
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

    fn mark_published(
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
        self.external_anchor
            .ensure_publishable(&candidate)
            .map_err(map_anchor_error)?;
        state.pending_anchor = Some(candidate);
        self.store
            .commit(expected_generation, state)
            .map_err(map_store_error)?;
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
            .sign_witness_statement(
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
        validate_request_time(request, now_ms)?;
        let validated =
            validate_request_policy(policy, request).map_err(map_request_policy_error)?;
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

    fn validate_embedded_request(
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

fn checkpoint_acknowledgement(
    state: &PersistedWitnessState,
    vault_id: &VaultId,
) -> Result<WitnessCheckpointAcknowledgementV1, WitnessEngineError> {
    let vault = state
        .logical
        .vaults
        .get(vault_id)
        .ok_or_else(|| refused(WitnessReasonV1::StalePolicy))?;
    let exact_anchor = state
        .published_anchor
        .clone()
        .ok_or_else(|| refused(WitnessReasonV1::AnchorConflict))?;
    let acknowledgement = WitnessCheckpointAcknowledgementV1 {
        schema: 1,
        witness_id: state.logical.witness_id,
        vault_id: *vault_id,
        checkpoint_digest: vault
            .current_checkpoint
            .digest()
            .map_err(|_| refused(WitnessReasonV1::Invalid))?,
        vault_policy_sequence: vault.current_checkpoint.vault_policy_sequence,
        witness_policy_digest: vault.current_checkpoint.witness_policy_digest.clone(),
        state_generation: state.logical.state_generation,
        anchor_digest: exact_anchor
            .digest()
            .map_err(|_| refused(WitnessReasonV1::Invalid))?,
        exact_anchor,
    };
    acknowledgement
        .validate_shape()
        .map_err(|_| refused(WitnessReasonV1::InternalFailure))?;
    Ok(acknowledgement)
}

fn validate_checkpoint<I: WitnessEngineIdentity + ?Sized>(
    policy: &PolicyState,
    checkpoint: &VaultPolicyCheckpointV1,
    identity: &I,
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

fn validate_registered_checkpoint<I: WitnessEngineIdentity + ?Sized>(
    policy: &PolicyState,
    checkpoint: &VaultPolicyCheckpointV1,
    identity: &I,
) -> Result<(), WitnessEngineError> {
    if checkpoint.vault_policy_sequence < policy.sequence() {
        return Err(refused(WitnessReasonV1::WitnessBehind));
    }
    if checkpoint.vault_policy_sequence > policy.sequence() {
        return Err(refused(WitnessReasonV1::StalePolicy));
    }
    validate_checkpoint(policy, checkpoint, identity)
}

pub(crate) fn validate_checkpoint_public<'a>(
    policy: &'a PolicyState,
    checkpoint: &VaultPolicyCheckpointV1,
) -> Result<&'a WitnessPolicy, WitnessEngineError> {
    checkpoint
        .validate_shape()
        .map_err(|_| refused(WitnessReasonV1::Invalid))?;
    if checkpoint.vault_id != policy.vault_id()
        || checkpoint.genesis_fingerprint != *policy.genesis_fingerprint()
        || checkpoint.vault_policy_sequence != policy.sequence()
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
        || witness_policy.vault_policy_hash != checkpoint.vault_policy_hash
        || policy.current_predecessor_hash() != Some(&checkpoint.vault_policy_hash)
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
    validate_approval_against_policy(
        approval,
        request,
        manifest,
        &validated.rule,
        &validated.policy,
    )
}

include!("witness_engine/approval_validation.rs");

fn approval_is_current(approval: &ApprovalDecisionV1, now_ms: u64) -> bool {
    approval.issued_at_ms <= now_ms.saturating_add(ACCEPTED_CLOCK_SKEW_MS)
        && now_ms < approval.expires_at_ms
        && approval
            .not_before_ms
            .is_none_or(|not_before| not_before <= now_ms.saturating_add(ACCEPTED_CLOCK_SKEW_MS))
}

/// Validates a cancellation against the exact signed request and current actor policy.
pub fn validate_request_cancellation(
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

pub(crate) fn validate_public_request(
    policy: &PolicyState,
    checkpoint: &VaultPolicyCheckpointV1,
    request: &jury_protocol::witness_v1::WitnessRequestV1,
    manifest: &ActionManifestV1,
) -> Result<ValidatedPublicRequest, WitnessEngineError> {
    validate_request_manifest(request, manifest)?;
    validate_checkpoint_public(policy, checkpoint)?;
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

    let validated = validate_request_policy(policy, request).map_err(map_request_policy_error)?;
    if manifest.timeout_ms > validated.rule.max_timeout_ms
        || manifest.output_limit_bytes > validated.rule.max_output_bytes
        || manifest.approval_target.entries.len() > usize::from(validated.rule.max_target_count)
        || manifest.platform_assurance.tag()
            < platform_assurance_tag(validated.rule.required_platform_assurance)
    {
        return Err(refused(WitnessReasonV1::WorkloadExceeded));
    }
    validate_automatic_rule(manifest, &validated.rule)?;
    Ok(ValidatedPublicRequest {
        rule: validated.rule,
        policy: validated.policy,
        slot: validated.slot,
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

const fn map_request_policy_error(error: RequestPolicyError) -> WitnessEngineError {
    match error {
        RequestPolicyError::Invalid => refused(WitnessReasonV1::Invalid),
        RequestPolicyError::InvalidSignature => refused(WitnessReasonV1::InvalidSignature),
        RequestPolicyError::PolicyDenied => refused(WitnessReasonV1::PolicyDenied),
        RequestPolicyError::StalePolicy => refused(WitnessReasonV1::StalePolicy),
        RequestPolicyError::WrongScope => refused(WitnessReasonV1::WrongScope),
    }
}

const fn map_store_error(error: WitnessStoreError) -> WitnessEngineError {
    match error.kind() {
        WitnessStoreErrorKind::Unavailable => WitnessEngineError::store_unavailable(),
        WitnessStoreErrorKind::CapacityExhausted => refused(WitnessReasonV1::CapacityExhausted),
    }
}

const fn map_anchor_error(error: WitnessAnchorError) -> WitnessEngineError {
    match error.kind() {
        WitnessAnchorErrorKind::Unavailable => WitnessEngineError::anchor_unavailable(),
        WitnessAnchorErrorKind::CapacityExhausted => refused(WitnessReasonV1::CapacityExhausted),
    }
}

const fn refused(reason: WitnessReasonV1) -> WitnessEngineError {
    WitnessEngineError::refused(reason)
}

#[cfg(test)]
#[path = "witness_engine_tests.rs"]
mod tests;
