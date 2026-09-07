//! Authentication of a rollover's source-owner authorization.
//!
//! Source provenance does not establish destination bootstrap completeness,
//! witnessed readiness, or trust in either genesis. Callers must separately
//! establish source trust/freshness and validate the destination bootstrap.

use std::fmt;

mod bootstrap;
mod direct;
pub(crate) use bootstrap::validate_retained_bootstrap;
use bootstrap::{bootstrap_state, verify_fresh_envelope};
mod governed;
mod intent;
mod migration;
mod registration;
pub use direct::PreparedDirectRollover;
pub use governed::{GovernedRolloverDraft, GovernedRolloverOptions, PreparedGovernedRollover};
pub use intent::{witness_intent_digest, witness_intent_preimage};

use jury_protocol::vault_v1::{PolicyGenesisV1, SourceAttestationV1, VaultFileV1};

use crate::{
    crypto,
    local_state::CheckpointCandidate,
    policy::{PolicyState, WitnessPolicy, replay_policy, replay_policy_with_witness_policies},
};

#[cfg(test)]
mod intent_tests;
#[cfg(test)]
mod tests;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RolloverErrorKind {
    InvalidSource,
    InvalidDestination,
    SourceMismatch,
    Unauthorized,
    UnsupportedTopology,
    AccessFailed,
    ReviewLabelLifetime,
    PreparationFailed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RolloverError {
    kind: RolloverErrorKind,
}

impl RolloverError {
    const fn new(kind: RolloverErrorKind) -> Self {
        Self { kind }
    }

    #[must_use]
    pub const fn kind(self) -> RolloverErrorKind {
        self.kind
    }
}

impl fmt::Display for RolloverError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.kind {
            RolloverErrorKind::InvalidSource => "rollover source is invalid",
            RolloverErrorKind::InvalidDestination => "rollover destination is invalid",
            RolloverErrorKind::SourceMismatch => "rollover source lineage or revision differs",
            RolloverErrorKind::Unauthorized => "rollover source-owner authorization is invalid",
            RolloverErrorKind::UnsupportedTopology => "rollover requires witnessed preparation",
            RolloverErrorKind::AccessFailed => "rollover source item access failed",
            RolloverErrorKind::ReviewLabelLifetime => {
                "rollover review labels expire before the registration deadline"
            }
            RolloverErrorKind::PreparationFailed => "rollover preparation failed",
        })
    }
}

impl std::error::Error for RolloverError {}

/// Publicly authenticated source state. Validation is read-only and does not
/// append a source revision, including when its history is at capacity.
///
/// This proves integrity against the supplied source genesis, not freshness or
/// external trust. The caller must check its trusted local checkpoint before
/// using this source to authorize a new lineage.
pub struct RolloverSource<'a> {
    vault: &'a VaultFileV1,
    policy: PolicyState,
}

impl<'a> RolloverSource<'a> {
    pub fn validate(
        vault: &'a VaultFileV1,
        witness_policies: &[WitnessPolicy],
    ) -> Result<Self, RolloverError> {
        let invalid = || RolloverError::new(RolloverErrorKind::InvalidSource);
        // Enforce the encoded-size cap as well as the structured limits even
        // when callers constructed the value without going through `parse`.
        vault.to_json_bytes().map_err(|_| invalid())?;
        migration::verify(vault).map_err(|_| invalid())?;
        let policy = replay_policy_with_witness_policies(&vault.policy, witness_policies)
            .map_err(|_| invalid())?;
        CheckpointCandidate::from_validated(&policy, &vault.policy, &vault.items)
            .map_err(|_| invalid())?;
        Ok(Self { vault, policy })
    }

    /// Verify that an owner at this exact source terminal revision signed the
    /// bridge to this destination genesis and its claimed bootstrap digest.
    /// A supplied manifest must match the signed digest. Its absence is only
    /// compatible with a suite-1 source and proves the reserved bridge alone;
    /// complete destination verification always requires the manifest.
    pub fn verify_source_authorization(
        &self,
        destination: &PolicyGenesisV1,
    ) -> Result<(), RolloverError> {
        let invalid = || RolloverError::new(RolloverErrorKind::InvalidDestination);
        let Some(SourceAttestationV1::Rollover { statement }) = &destination.source_attestation
        else {
            return Err(invalid());
        };
        if statement.rollover_format != 1
            || statement.destination_vault_id != destination.vault_id
            || statement.destination_suite != destination.suite
            || destination.vault_id == self.vault.header.vault_id
            || destination.created_at_ms
                < self
                    .vault
                    .policy
                    .revisions
                    .last()
                    .map_or(self.vault.policy.genesis.created_at_ms, |revision| {
                        revision.timestamp_ms
                    })
        {
            return Err(invalid());
        }
        let source_suite = match &statement.bootstrap_manifest {
            Some(manifest) => {
                if manifest.digest().map_err(|_| invalid())? != statement.bootstrap_manifest_digest
                {
                    return Err(invalid());
                }
                manifest.source_suite.unwrap_or(1)
            }
            None => 1,
        };
        if statement.source_vault_id != self.vault.header.vault_id
            || source_suite != self.vault.header.suite
            || statement.source_genesis_fingerprint != *self.policy.genesis_fingerprint()
            || statement.terminal_source_revision_hash != *self.policy.terminal_revision_hash()
        {
            return Err(RolloverError::new(RolloverErrorKind::SourceMismatch));
        }
        let unauthorized = || RolloverError::new(RolloverErrorKind::Unauthorized);
        let owner = self
            .policy
            .principal(&statement.acting_owner_principal_id)
            .filter(|_| self.policy.is_owner(&statement.acting_owner_principal_id))
            .ok_or_else(unauthorized)?;
        if destination.owner != owner.descriptor {
            return Err(unauthorized());
        }
        crypto::verify_bytes(
            &owner.descriptor.verification_public_key,
            &statement.signature_preimage(),
            &statement.signature,
        )
        .map_err(|_| unauthorized())?;
        // Reuse ordinary genesis replay for descriptor and genesis signatures,
        // suite support, sequence zero, and empty genesis inventory/grants.
        replay_policy(&jury_protocol::vault_v1::PolicyJournalV1 {
            genesis: destination.clone(),
            revisions: Vec::new(),
        })
        .map_err(|_| invalid())?;
        Ok(())
    }
}
