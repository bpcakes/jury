use jury_protected::ProtectedMemory;
use jury_protocol::vault_v1::{Digest32, ItemId, RevisionSealId};
use serde::{Deserialize, Serialize};

use super::{
    LocalStateError, LocalStateErrorKind, LocalStateScope, MAX_AUDIT_BYTES, MAX_AUDIT_EVENT_BYTES,
    MAX_AUDIT_EVENTS, append_optional_digest, digest_is_zero, jce, map_crypto_error,
};
use crate::crypto;

const ZERO_DIGEST: [u8; 32] = [0; 32];
const MAX_PERMITTED_ITEM_NAME_BYTES: usize = 256;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditAction {
    VaultCreateOrImport,
    IdentityAction,
    PolicyMutation,
    ItemMutation,
    ItemRead,
    Transfer,
    Backup,
    Restore,
    ExecuteOrInject,
    WitnessRequest,
    Verification,
    PrivacyCover,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditFailureStage {
    PublicSyntax,
    Authorization,
    PrivateAuthentication,
    Mutation,
    DurableCommit,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "status", content = "stage", rename_all = "snake_case")]
pub enum AuditOutcome {
    Success,
    Denied,
    Cancelled,
    Failed(AuditFailureStage),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuditItemScope {
    pub item_id: ItemId,
    pub permitted_item_name: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessAuditLink {
    pub request_digest: Digest32,
    pub decision_digest: Option<Digest32>,
    pub receipt_digest: Option<Digest32>,
    pub policy_revision_hash: Digest32,
    pub revision_seal_id: RevisionSealId,
}

impl WitnessAuditLink {
    /// The event's canonical operation ID transitively authenticates the
    /// bounded witnessed identifiers without extending the frozen event MAC.
    #[must_use]
    pub fn operation_id(&self) -> Digest32 {
        let mut preimage = jce("jury-v1/audit/witness-link");
        preimage.extend_from_slice(self.request_digest.as_bytes());
        append_optional_digest(&mut preimage, self.decision_digest.as_ref());
        append_optional_digest(&mut preimage, self.receipt_digest.as_ref());
        preimage.extend_from_slice(self.policy_revision_hash.as_bytes());
        preimage.extend_from_slice(self.revision_seal_id.as_bytes());
        Digest32::new(crypto::sha256(&preimage))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuditEventDraft {
    /// Used to advance the authenticated checkpoint time; event records do not
    /// add a timestamp outside the frozen MAC preimage.
    pub timestamp_ms: u64,
    pub operation_id: Digest32,
    pub policy_sequence: u64,
    pub action: AuditAction,
    pub outcome: AuditOutcome,
    pub item: Option<AuditItemScope>,
    pub witness: Option<WitnessAuditLink>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuditEvent {
    pub version: u16,
    pub sequence: u64,
    pub operation_id: Digest32,
    pub principal_id: jury_protocol::vault_v1::PrincipalId,
    pub vault_id: jury_protocol::vault_v1::VaultId,
    pub genesis_fingerprint: Digest32,
    pub policy_sequence: u64,
    pub action: AuditAction,
    pub item: Option<AuditItemScope>,
    pub outcome: AuditOutcome,
    pub witness: Option<WitnessAuditLink>,
    pub previous_mac: Digest32,
    pub mac: Digest32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuditEvidenceKind {
    CurrentJuryV1Local,
    MigrationAttestedLegacyArchive,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditVerification {
    pub event_count: usize,
    pub latest_mac: Digest32,
    pub principal_id: jury_protocol::vault_v1::PrincipalId,
    pub evidence_kind: AuditEvidenceKind,
    pub local_activity_only: bool,
    pub remote_freshness_verified: bool,
}

pub(super) struct AuditLog {
    events: Vec<AuditEvent>,
}

impl AuditLog {
    pub(super) fn initialize(
        scope: &LocalStateScope,
        policy_sequence: u64,
        audit_genesis_digest: Digest32,
        key: &ProtectedMemory,
    ) -> Result<Self, LocalStateError> {
        if digest_is_zero(&audit_genesis_digest) {
            return Err(LocalStateError::new(LocalStateErrorKind::InvalidFormat));
        }
        let mut event = AuditEvent {
            version: 1,
            sequence: 1,
            operation_id: audit_genesis_digest,
            principal_id: scope.principal_id,
            vault_id: scope.vault_id,
            genesis_fingerprint: scope.genesis_fingerprint.clone(),
            policy_sequence,
            action: AuditAction::VaultCreateOrImport,
            item: None,
            outcome: AuditOutcome::Success,
            witness: None,
            previous_mac: Digest32::new(ZERO_DIGEST),
            mac: Digest32::new(ZERO_DIGEST),
        };
        event.mac = event_mac(&event, key)?;
        Ok(Self {
            events: vec![event],
        })
    }

    pub(super) fn parse(
        bytes: &[u8],
        scope: &LocalStateScope,
        key: &ProtectedMemory,
    ) -> Result<Self, LocalStateError> {
        if bytes.is_empty() || bytes.len() > MAX_AUDIT_BYTES {
            return Err(LocalStateError::new(LocalStateErrorKind::InvalidFormat));
        }
        let mut events = Vec::new();
        let mut previous_mac = Digest32::new(ZERO_DIGEST);
        for line_with_ending in bytes.split_inclusive(|byte| *byte == b'\n') {
            if !line_with_ending.ends_with(b"\n")
                || line_with_ending.len() <= 1
                || line_with_ending.len() > MAX_AUDIT_EVENT_BYTES
                || events.len() >= MAX_AUDIT_EVENTS
            {
                return Err(LocalStateError::new(LocalStateErrorKind::AuditTampered));
            }
            let line = &line_with_ending[..line_with_ending.len() - 1];
            let event: AuditEvent = serde_json::from_slice(line)
                .map_err(|_| LocalStateError::new(LocalStateErrorKind::AuditTampered))?;
            let canonical = serde_json::to_vec(&event)
                .map_err(|_| LocalStateError::new(LocalStateErrorKind::ProviderFailure))?;
            if canonical != line
                || event.sequence != u64::try_from(events.len()).unwrap_or(u64::MAX) + 1
                || event.previous_mac != previous_mac
                || !event.matches_scope(scope)
                || event.validate_shape().is_err()
            {
                return Err(LocalStateError::new(LocalStateErrorKind::AuditTampered));
            }
            verify_event_mac(&event, key)
                .map_err(|_| LocalStateError::new(LocalStateErrorKind::AuditTampered))?;
            previous_mac = event.mac.clone();
            events.push(event);
        }
        if events.is_empty()
            || events[0].action != AuditAction::VaultCreateOrImport
            || events[0].outcome != AuditOutcome::Success
        {
            return Err(LocalStateError::new(LocalStateErrorKind::AuditTampered));
        }
        Ok(Self { events })
    }

    pub(super) fn append(
        &mut self,
        draft: AuditEventDraft,
        scope: &LocalStateScope,
        key: &ProtectedMemory,
    ) -> Result<(), LocalStateError> {
        if self.events.len() >= MAX_AUDIT_EVENTS
            || draft.timestamp_ms == 0
            || digest_is_zero(&draft.operation_id)
            || draft.action == AuditAction::VaultCreateOrImport
        {
            return Err(LocalStateError::new(LocalStateErrorKind::InvalidFormat));
        }
        let sequence = u64::try_from(self.events.len())
            .ok()
            .and_then(|value| value.checked_add(1))
            .ok_or_else(|| LocalStateError::new(LocalStateErrorKind::CapacityExhausted))?;
        let mut event = AuditEvent {
            version: 1,
            sequence,
            operation_id: draft.operation_id,
            principal_id: scope.principal_id,
            vault_id: scope.vault_id,
            genesis_fingerprint: scope.genesis_fingerprint.clone(),
            policy_sequence: draft.policy_sequence,
            action: draft.action,
            item: draft.item,
            outcome: draft.outcome,
            witness: draft.witness,
            previous_mac: self.latest_mac().clone(),
            mac: Digest32::new(ZERO_DIGEST),
        };
        event.validate_shape()?;
        event.mac = event_mac(&event, key)?;
        let encoded = serde_json::to_vec(&event)
            .map_err(|_| LocalStateError::new(LocalStateErrorKind::ProviderFailure))?;
        if encoded.len().saturating_add(1) > MAX_AUDIT_EVENT_BYTES {
            return Err(LocalStateError::new(LocalStateErrorKind::CapacityExhausted));
        }
        self.events.push(event);
        if self.encoded_len()? > MAX_AUDIT_BYTES {
            self.events.pop();
            return Err(LocalStateError::new(LocalStateErrorKind::CapacityExhausted));
        }
        Ok(())
    }

    pub(super) fn to_bytes(&self) -> Result<Vec<u8>, LocalStateError> {
        let capacity = self.encoded_len()?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(capacity)
            .map_err(|_| LocalStateError::new(LocalStateErrorKind::CapacityExhausted))?;
        for event in &self.events {
            bytes.extend_from_slice(
                &serde_json::to_vec(event)
                    .map_err(|_| LocalStateError::new(LocalStateErrorKind::ProviderFailure))?,
            );
            bytes.push(b'\n');
        }
        Ok(bytes)
    }

    fn encoded_len(&self) -> Result<usize, LocalStateError> {
        let mut length = 0_usize;
        for event in &self.events {
            length = length
                .checked_add(
                    serde_json::to_vec(event)
                        .map_err(|_| LocalStateError::new(LocalStateErrorKind::ProviderFailure))?
                        .len()
                        .saturating_add(1),
                )
                .ok_or_else(|| LocalStateError::new(LocalStateErrorKind::CapacityExhausted))?;
        }
        Ok(length)
    }

    pub(super) fn latest_mac(&self) -> &Digest32 {
        &self.events[self.events.len() - 1].mac
    }

    pub(super) fn audit_genesis_digest(&self) -> &Digest32 {
        &self.events[0].operation_id
    }

    pub(super) fn mac_index(&self, mac: &Digest32) -> Option<usize> {
        self.events.iter().position(|event| &event.mac == mac)
    }

    pub(super) fn matches_scope(&self, scope: &LocalStateScope) -> bool {
        self.events
            .first()
            .is_some_and(|event| event.matches_scope(scope))
    }

    pub(super) fn len(&self) -> usize {
        self.events.len()
    }

    pub(super) fn verification(&self) -> AuditVerification {
        AuditVerification {
            event_count: self.events.len(),
            latest_mac: self.latest_mac().clone(),
            principal_id: self.events[0].principal_id,
            evidence_kind: AuditEvidenceKind::CurrentJuryV1Local,
            local_activity_only: true,
            remote_freshness_verified: false,
        }
    }
}

impl AuditEvent {
    fn matches_scope(&self, scope: &LocalStateScope) -> bool {
        self.vault_id == scope.vault_id
            && self.genesis_fingerprint == scope.genesis_fingerprint
            && self.principal_id == scope.principal_id
    }

    fn validate_shape(&self) -> Result<(), LocalStateError> {
        if self.version != 1 || self.sequence == 0 || digest_is_zero(&self.operation_id) {
            return Err(LocalStateError::new(LocalStateErrorKind::InvalidFormat));
        }
        if let Some(item) = &self.item
            && item
                .permitted_item_name
                .as_ref()
                .is_some_and(|name| name.is_empty() || name.len() > MAX_PERMITTED_ITEM_NAME_BYTES)
        {
            return Err(LocalStateError::new(LocalStateErrorKind::InvalidFormat));
        }
        match self.action {
            AuditAction::VaultCreateOrImport => {
                if self.sequence != 1
                    || self.outcome != AuditOutcome::Success
                    || self.item.is_some()
                    || self.witness.is_some()
                    || self.previous_mac.as_bytes() != &ZERO_DIGEST
                {
                    return Err(LocalStateError::new(LocalStateErrorKind::InvalidFormat));
                }
            }
            AuditAction::ItemRead => {
                if self.item.is_none() || self.witness.is_some() {
                    return Err(LocalStateError::new(LocalStateErrorKind::InvalidFormat));
                }
            }
            AuditAction::WitnessRequest | AuditAction::Verification => {
                if self.witness.is_none()
                    || self.item.is_none()
                    || self
                        .item
                        .as_ref()
                        .and_then(|item| item.permitted_item_name.as_ref())
                        .is_some()
                {
                    return Err(LocalStateError::new(LocalStateErrorKind::InvalidFormat));
                }
            }
            _ => {
                if self.witness.is_some() {
                    return Err(LocalStateError::new(LocalStateErrorKind::InvalidFormat));
                }
            }
        }
        if let Some(witness) = &self.witness
            && (digest_is_zero(&witness.request_digest)
                || digest_is_zero(&witness.policy_revision_hash)
                || witness.decision_digest.as_ref().is_some_and(digest_is_zero)
                || witness.receipt_digest.as_ref().is_some_and(digest_is_zero)
                || self.operation_id != witness.operation_id())
        {
            return Err(LocalStateError::new(LocalStateErrorKind::InvalidFormat));
        }
        Ok(())
    }

    fn mac_preimage(&self) -> Vec<u8> {
        event_mac_preimage(
            self.version,
            self.principal_id.as_bytes(),
            self.vault_id.as_bytes(),
            self.genesis_fingerprint.as_bytes(),
            self.policy_sequence,
            self.operation_id.as_bytes(),
            self.action,
            self.item.as_ref(),
            self.outcome,
            self.previous_mac.as_bytes(),
        )
    }
}

fn event_mac(event: &AuditEvent, key: &ProtectedMemory) -> Result<Digest32, LocalStateError> {
    Ok(Digest32::new(
        crypto::hmac_sha256(key, &event.mac_preimage()).map_err(map_crypto_error)?,
    ))
}

fn verify_event_mac(event: &AuditEvent, key: &ProtectedMemory) -> Result<(), LocalStateError> {
    crypto::verify_hmac_sha256(key, &event.mac_preimage(), event.mac.as_bytes())
        .map_err(map_crypto_error)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn event_mac_preimage(
    version: u16,
    principal_id: &[u8; 32],
    vault_id: &[u8; 32],
    genesis_fingerprint: &[u8; 32],
    policy_sequence: u64,
    operation_id: &[u8; 32],
    action: AuditAction,
    item: Option<&AuditItemScope>,
    outcome: AuditOutcome,
    previous_mac: &[u8; 32],
) -> Vec<u8> {
    let mut output = jce("jury-v1/audit/event-mac");
    output.extend_from_slice(&version.to_be_bytes());
    output.extend_from_slice(principal_id);
    output.extend_from_slice(vault_id);
    output.extend_from_slice(genesis_fingerprint);
    output.extend_from_slice(&policy_sequence.to_be_bytes());
    output.extend_from_slice(operation_id);
    output.push(action_tag(action));
    match item {
        Some(item) => {
            output.push(1);
            output.extend_from_slice(item.item_id.as_bytes());
        }
        None => output.push(0),
    }
    match item.and_then(|item| item.permitted_item_name.as_ref()) {
        Some(name) => {
            output.push(1);
            output.extend_from_slice(&(name.len() as u32).to_be_bytes());
            output.extend_from_slice(name.as_bytes());
        }
        None => output.push(0),
    }
    let (outcome, failure_stage) = outcome_tags(outcome);
    output.push(outcome);
    output.push(failure_stage);
    output.extend_from_slice(previous_mac);
    output
}

const fn action_tag(action: AuditAction) -> u8 {
    match action {
        AuditAction::VaultCreateOrImport => 1,
        AuditAction::IdentityAction => 2,
        AuditAction::PolicyMutation => 3,
        AuditAction::ItemMutation => 4,
        AuditAction::ItemRead => 5,
        AuditAction::Transfer => 6,
        AuditAction::Backup => 7,
        AuditAction::Restore => 8,
        AuditAction::ExecuteOrInject => 9,
        AuditAction::WitnessRequest => 10,
        AuditAction::Verification => 11,
        AuditAction::PrivacyCover => 12,
    }
}

const fn outcome_tags(outcome: AuditOutcome) -> (u8, u8) {
    match outcome {
        AuditOutcome::Success => (1, 0),
        AuditOutcome::Denied => (2, 0),
        AuditOutcome::Cancelled => (3, 0),
        AuditOutcome::Failed(stage) => (4, failure_stage_tag(stage)),
    }
}

const fn failure_stage_tag(stage: AuditFailureStage) -> u8 {
    match stage {
        AuditFailureStage::PublicSyntax => 1,
        AuditFailureStage::Authorization => 2,
        AuditFailureStage::PrivateAuthentication => 3,
        AuditFailureStage::Mutation => 4,
        AuditFailureStage::DurableCommit => 5,
    }
}
