//! Exact public HPKE contexts. Selecting a profile is not source authorization
//! or runtime acceptance of a candidate cryptographic suite.
use crate::vault_v1::{Digest32, PrincipalId, ResponseId};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VaultSuite {
    Suite1,
    Suite2,
}

impl VaultSuite {
    #[must_use]
    pub const fn from_id(id: u16) -> Option<Self> {
        match id {
            1 => Some(Self::Suite1),
            2 => Some(Self::Suite2),
            _ => None,
        }
    }

    #[must_use]
    pub const fn id(self) -> u16 {
        match self {
            Self::Suite1 => 1,
            Self::Suite2 => 2,
        }
    }

    #[must_use]
    pub const fn hpke_aead(self) -> u16 {
        match self {
            Self::Suite1 => 3,
            Self::Suite2 => 2,
        }
    }
}

pub(crate) fn prefix(domain: &str, suite: u16) -> Vec<u8> {
    let mut output = Vec::with_capacity(domain.len() + 3);
    output.extend_from_slice(domain.as_bytes());
    output.push(0);
    output.extend_from_slice(&suite.to_be_bytes());
    output
}

/// Public binding for one witness-to-request-session HPKE ciphertext. Suite is
/// supplied by the validated containing slot, never by response negotiation.
pub struct ContributionHpkeContext {
    pub suite: VaultSuite,
    pub request_digest: Digest32,
    pub action_manifest_digest: Digest32,
    pub response_id: ResponseId,
    pub witness_id: PrincipalId,
    pub witness_policy_digest: Digest32,
    pub checkpoint_digest: Digest32,
    pub share_commitment: Digest32,
    pub share_index: u8,
    pub capsule_set_digest: Digest32,
    pub capsule_context_digest: Digest32,
    pub session_fingerprint: Digest32,
    pub expires_at_ms: u64,
}

impl ContributionHpkeContext {
    #[must_use]
    pub fn info_preimage(&self) -> Vec<u8> {
        let mut output = prefix("jury-witness-v1/contribution/info", self.suite.id());
        output.extend_from_slice(self.request_digest.as_bytes());
        output.extend_from_slice(self.action_manifest_digest.as_bytes());
        output.extend_from_slice(self.response_id.as_bytes());
        output.extend_from_slice(self.witness_id.as_bytes());
        output.extend_from_slice(self.witness_policy_digest.as_bytes());
        output.extend_from_slice(self.checkpoint_digest.as_bytes());
        output.extend_from_slice(self.share_commitment.as_bytes());
        output.push(self.share_index);
        output
    }

    #[must_use]
    pub fn aad_preimage(&self) -> Vec<u8> {
        let mut output = prefix("jury-witness-v1/contribution/aad", self.suite.id());
        output.extend_from_slice(self.capsule_set_digest.as_bytes());
        output.extend_from_slice(self.capsule_context_digest.as_bytes());
        output.extend_from_slice(self.session_fingerprint.as_bytes());
        output.extend_from_slice(&self.expires_at_ms.to_be_bytes());
        output
    }
}
