use std::collections::{BTreeMap, BTreeSet};

use jury_protected::ProtectedMemory;
use jury_protocol::vault_v1::{Digest32, ItemEnvelopeV1, PolicyJournalV1, PrincipalId, VaultId};
use serde::{Deserialize, Serialize};

use super::{
    LocalStateError, LocalStateErrorKind, LocalStateScope, MAX_CHECKPOINT_BYTES, digest_is_zero,
    jce, map_crypto_error,
};
use crate::crypto;
use crate::item::verify_item_ancestry;
use crate::policy::PolicyState;

const ZERO_DIGEST: [u8; 32] = [0; 32];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CheckpointRelation {
    Equal,
    StrictDescendant,
    Divergent,
}

/// Public state already validated against its policy and item signature chains.
pub struct CheckpointCandidate {
    vault_id: VaultId,
    genesis_fingerprint: Digest32,
    principals: BTreeSet<PrincipalId>,
    policy_history: BTreeMap<u64, Digest32>,
}

impl CheckpointCandidate {
    pub fn from_validated(
        policy: &PolicyState,
        journal: &PolicyJournalV1,
        envelopes: &[ItemEnvelopeV1],
    ) -> Result<Self, LocalStateError> {
        let genesis_fingerprint = journal
            .genesis
            .recomputed_fingerprint()
            .map_err(|_| LocalStateError::new(LocalStateErrorKind::InvalidFormat))?;
        if journal.genesis.vault_id != policy.vault_id()
            || genesis_fingerprint != *policy.genesis_fingerprint()
            || journal.revisions.len() != usize::try_from(policy.sequence()).unwrap_or(usize::MAX)
            || envelopes.len() != policy.items.len()
        {
            return Err(LocalStateError::new(LocalStateErrorKind::InvalidFormat));
        }

        let mut policy_history = BTreeMap::new();
        policy_history.insert(0, genesis_fingerprint.clone());
        let mut previous = genesis_fingerprint.clone();
        for (index, revision) in journal.revisions.iter().enumerate() {
            let sequence = u64::try_from(index)
                .ok()
                .and_then(|value| value.checked_add(1))
                .ok_or_else(|| LocalStateError::new(LocalStateErrorKind::CapacityExhausted))?;
            if revision.sequence != sequence
                || revision.vault_id != policy.vault_id()
                || revision.previous_revision_hash != previous
            {
                return Err(LocalStateError::new(LocalStateErrorKind::InvalidFormat));
            }
            previous = revision
                .recomputed_hash()
                .map_err(|_| LocalStateError::new(LocalStateErrorKind::InvalidFormat))?;
            policy_history.insert(sequence, previous.clone());
        }
        if previous != *policy.terminal_revision_hash() {
            return Err(LocalStateError::new(LocalStateErrorKind::InvalidFormat));
        }
        if let Some(terminal) = journal.revisions.last()
            && policy
                .normalized_state_hash()
                .map_err(|_| LocalStateError::new(LocalStateErrorKind::InvalidFormat))?
                != terminal.resulting_policy_state_hash
        {
            return Err(LocalStateError::new(LocalStateErrorKind::InvalidFormat));
        }

        let mut seen_items = BTreeSet::new();
        for envelope in envelopes {
            if !seen_items.insert(envelope.item_id) {
                return Err(LocalStateError::new(LocalStateErrorKind::InvalidFormat));
            }
            verify_item_ancestry(envelope, |principal_id| {
                policy.verification_key(&principal_id)
            })
            .map_err(|_| LocalStateError::new(LocalStateErrorKind::InvalidFormat))?;
            let item = policy
                .items
                .get(&envelope.item_id)
                .ok_or_else(|| LocalStateError::new(LocalStateErrorKind::InvalidFormat))?;
            let current_hash = envelope
                .current_revision
                .recomputed_hash()
                .map_err(|_| LocalStateError::new(LocalStateErrorKind::InvalidFormat))?;
            if current_hash != item.current_item_revision_hash
                || envelope.descriptor != item.descriptor
            {
                return Err(LocalStateError::new(LocalStateErrorKind::InvalidFormat));
            }
        }

        if policy
            .items
            .keys()
            .any(|item_id| policy.tombstones.contains_key(item_id))
        {
            return Err(LocalStateError::new(LocalStateErrorKind::InvalidFormat));
        }
        Ok(Self {
            vault_id: policy.vault_id(),
            genesis_fingerprint,
            principals: policy.principals.keys().copied().collect(),
            policy_history,
        })
    }

    #[cfg(test)]
    pub(crate) fn from_test_parts(
        scope: &LocalStateScope,
        policy_history: BTreeMap<u64, Digest32>,
    ) -> Self {
        Self {
            vault_id: scope.vault_id,
            genesis_fingerprint: scope.genesis_fingerprint.clone(),
            principals: [scope.principal_id].into_iter().collect(),
            policy_history,
        }
    }

    pub(super) fn validate_scope(&self, scope: &LocalStateScope) -> Result<(), LocalStateError> {
        if self.vault_id != scope.vault_id
            || self.genesis_fingerprint != scope.genesis_fingerprint
            || !self.principals.contains(&scope.principal_id)
            || self.policy_history.is_empty()
            || self
                .policy_history
                .iter()
                .any(|(sequence, hash)| digest_is_zero(hash) || *sequence == u64::MAX)
            || self
                .policy_history
                .keys()
                .copied()
                .ne(0..u64::try_from(self.policy_history.len()).unwrap_or(u64::MAX))
        {
            return Err(LocalStateError::new(LocalStateErrorKind::ScopeMismatch));
        }
        Ok(())
    }

    pub fn relation_to(
        &self,
        checkpoint: &LocalCheckpoint,
    ) -> Result<CheckpointRelation, LocalStateError> {
        if self.vault_id != checkpoint.scope.vault_id
            || self.genesis_fingerprint != checkpoint.scope.genesis_fingerprint
        {
            return Ok(CheckpointRelation::Divergent);
        }
        let Some((current_sequence, current_hash)) = self.policy_history.last_key_value() else {
            return Err(LocalStateError::new(LocalStateErrorKind::InvalidFormat));
        };
        if current_hash == &checkpoint.accepted_public_revision_hash {
            return Ok(CheckpointRelation::Equal);
        }
        let retained_sequence = self.policy_history.iter().find_map(|(sequence, hash)| {
            (hash == &checkpoint.accepted_public_revision_hash).then_some(*sequence)
        });
        Ok(
            if retained_sequence.is_some_and(|sequence| sequence < *current_sequence) {
                CheckpointRelation::StrictDescendant
            } else {
                CheckpointRelation::Divergent
            },
        )
    }

    pub(super) fn current_policy(&self) -> Result<(u64, Digest32), LocalStateError> {
        self.policy_history
            .last_key_value()
            .map(|(sequence, hash)| (*sequence, hash.clone()))
            .ok_or_else(|| LocalStateError::new(LocalStateErrorKind::InvalidFormat))
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LocalCheckpoint {
    version: u16,
    pub(super) scope: LocalStateScope,
    accepted_public_revision_hash: Digest32,
    pub(super) latest_audit_mac: Digest32,
    pub(super) audit_genesis_digest: Digest32,
    updated_at_ms: u64,
    mac: Digest32,
}

impl LocalCheckpoint {
    pub(super) fn initial(
        candidate: &CheckpointCandidate,
        scope: &LocalStateScope,
        timestamp_ms: u64,
    ) -> Result<Self, LocalStateError> {
        let (_, accepted_public_revision_hash) = candidate.current_policy()?;
        let mut checkpoint = Self {
            version: 1,
            scope: scope.clone(),
            accepted_public_revision_hash,
            latest_audit_mac: Digest32::new(ZERO_DIGEST),
            audit_genesis_digest: Digest32::new(ZERO_DIGEST),
            updated_at_ms: timestamp_ms,
            mac: Digest32::new(ZERO_DIGEST),
        };
        checkpoint.audit_genesis_digest = checkpoint.genesis_digest();
        Ok(checkpoint)
    }

    pub(super) fn parse(
        bytes: &[u8],
        scope: &LocalStateScope,
        key: &ProtectedMemory,
    ) -> Result<Self, LocalStateError> {
        if bytes.is_empty() || bytes.len() > MAX_CHECKPOINT_BYTES {
            return Err(LocalStateError::new(LocalStateErrorKind::InvalidFormat));
        }
        let checkpoint: Self = serde_json::from_slice(bytes)
            .map_err(|_| LocalStateError::new(LocalStateErrorKind::InvalidFormat))?;
        if checkpoint.to_bytes()? != bytes || checkpoint.validate_shape().is_err() {
            return Err(LocalStateError::new(LocalStateErrorKind::InvalidFormat));
        }
        if checkpoint.scope != *scope {
            return Err(LocalStateError::new(LocalStateErrorKind::ScopeMismatch));
        }
        checkpoint.verify(key)?;
        Ok(checkpoint)
    }

    pub(super) fn advance(
        &mut self,
        candidate: &CheckpointCandidate,
        timestamp_ms: u64,
    ) -> Result<(), LocalStateError> {
        if timestamp_ms < self.updated_at_ms {
            return Err(LocalStateError::new(LocalStateErrorKind::InvalidFormat));
        }
        self.accepted_public_revision_hash = candidate.current_policy()?.1;
        self.updated_at_ms = timestamp_ms;
        Ok(())
    }

    pub(super) fn record_audit(
        &mut self,
        latest_audit_mac: Digest32,
        timestamp_ms: u64,
    ) -> Result<(), LocalStateError> {
        if timestamp_ms < self.updated_at_ms || digest_is_zero(&latest_audit_mac) {
            return Err(LocalStateError::new(LocalStateErrorKind::InvalidFormat));
        }
        self.latest_audit_mac = latest_audit_mac;
        self.updated_at_ms = timestamp_ms;
        Ok(())
    }

    pub(super) fn authenticate(&mut self, key: &ProtectedMemory) -> Result<(), LocalStateError> {
        self.validate_shape()?;
        self.mac = Digest32::new(
            crypto::hmac_sha256(key, &self.mac_preimage()).map_err(map_crypto_error)?,
        );
        Ok(())
    }

    fn verify(&self, key: &ProtectedMemory) -> Result<(), LocalStateError> {
        crypto::verify_hmac_sha256(key, &self.mac_preimage(), self.mac.as_bytes())
            .map_err(map_crypto_error)
    }

    fn genesis_digest(&self) -> Digest32 {
        let mut preimage = jce("jury-v1/checkpoint/genesis-digest");
        preimage.extend_from_slice(&self.version.to_be_bytes());
        preimage.extend_from_slice(self.scope.principal_id.as_bytes());
        preimage.extend_from_slice(self.scope.vault_id.as_bytes());
        preimage.extend_from_slice(self.scope.genesis_fingerprint.as_bytes());
        preimage.extend_from_slice(self.accepted_public_revision_hash.as_bytes());
        preimage.extend_from_slice(&self.updated_at_ms.to_be_bytes());
        Digest32::new(crypto::sha256(&preimage))
    }

    fn mac_preimage(&self) -> Vec<u8> {
        checkpoint_mac_preimage(
            self.version,
            &self.scope,
            &self.accepted_public_revision_hash,
            &self.latest_audit_mac,
            &self.audit_genesis_digest,
            self.updated_at_ms,
        )
    }

    fn validate_shape(&self) -> Result<(), LocalStateError> {
        if self.version != 1
            || self.updated_at_ms == 0
            || digest_is_zero(&self.accepted_public_revision_hash)
            || digest_is_zero(&self.latest_audit_mac)
            || digest_is_zero(&self.audit_genesis_digest)
        {
            return Err(LocalStateError::new(LocalStateErrorKind::InvalidFormat));
        }
        Ok(())
    }

    pub(super) fn to_bytes(&self) -> Result<Vec<u8>, LocalStateError> {
        let mut bytes = serde_json::to_vec_pretty(self)
            .map_err(|_| LocalStateError::new(LocalStateErrorKind::ProviderFailure))?;
        bytes.push(b'\n');
        if bytes.len() > MAX_CHECKPOINT_BYTES {
            return Err(LocalStateError::new(LocalStateErrorKind::CapacityExhausted));
        }
        Ok(bytes)
    }

    #[must_use]
    pub const fn scope(&self) -> &LocalStateScope {
        &self.scope
    }

    #[must_use]
    pub const fn accepted_public_revision_hash(&self) -> &Digest32 {
        &self.accepted_public_revision_hash
    }

    #[must_use]
    pub const fn updated_at_ms(&self) -> u64 {
        self.updated_at_ms
    }
}

impl std::fmt::Debug for LocalCheckpoint {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LocalCheckpoint")
            .field("scope", &self.scope)
            .field(
                "accepted_public_revision_hash",
                &self.accepted_public_revision_hash,
            )
            .field("updated_at_ms", &self.updated_at_ms)
            .field("authentication", &"[REDACTED]")
            .finish()
    }
}

pub(super) fn checkpoint_mac_preimage(
    version: u16,
    scope: &LocalStateScope,
    accepted_public_revision_hash: &Digest32,
    latest_audit_mac: &Digest32,
    audit_genesis_digest: &Digest32,
    updated_at_ms: u64,
) -> Vec<u8> {
    let mut output = jce("jury-v1/checkpoint/file-mac");
    output.extend_from_slice(&version.to_be_bytes());
    output.extend_from_slice(scope.principal_id.as_bytes());
    output.extend_from_slice(scope.vault_id.as_bytes());
    output.extend_from_slice(scope.genesis_fingerprint.as_bytes());
    output.extend_from_slice(accepted_public_revision_hash.as_bytes());
    output.extend_from_slice(latest_audit_mac.as_bytes());
    output.extend_from_slice(audit_genesis_digest.as_bytes());
    output.extend_from_slice(&updated_at_ms.to_be_bytes());
    output
}
