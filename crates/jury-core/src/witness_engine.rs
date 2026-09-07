//! Transport-independent witnessed authorization and replay state.
//!
//! The engine accepts only already parsed public protocol values. Storage,
//! clocks, and the external rollback anchor are injected. The sole private-key
//! operation happens after public scope, policy, time, replay, and approval
//! validation, and a response is returned only after the resulting anchor has
//! been published and read back byte-for-byte.

mod operations;
mod requests;
mod state;
mod validation;

use validation::*;
pub use validation::{
    validate_approval_decision, validate_receipt_material, validate_request_cancellation,
    validate_request_manifest, validate_witness_response,
};
pub(crate) use validation::{validate_checkpoint_public, validate_public_request};

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

#[cfg(test)]
#[path = "witness_engine_tests.rs"]
mod tests;
