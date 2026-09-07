use super::*;
use crate::{domain::NativeIdGenerator, identity::VaultPrincipalIdentity};
use jury_protocol::{
    hpke_context::VaultSuite,
    vault_v1::{MigrationId, Signature64, SignedSuiteMigrationV1},
};

fn invalid() -> RolloverError {
    RolloverError::new(RolloverErrorKind::InvalidDestination)
}

impl RolloverSource<'_> {
    pub(super) fn require_migration(&self, destination: VaultSuite) -> Result<(), RolloverError> {
        if self.policy.suite() != 1 || destination != VaultSuite::Suite2 {
            return Err(invalid());
        }
        Ok(())
    }
}

pub(super) fn attach(
    vault: &mut VaultFileV1,
    owner: &VaultPrincipalIdentity,
) -> Result<(), RolloverError> {
    let Some(SourceAttestationV1::Rollover { statement }) =
        &vault.policy.genesis.source_attestation
    else {
        return Err(invalid());
    };
    let manifest = statement.bootstrap_manifest.as_ref().ok_or_else(invalid)?;
    let old_suite = manifest.source_suite.ok_or_else(invalid)?;
    if old_suite == vault.header.suite {
        return verify(vault);
    }
    if old_suite != 1
        || vault.header.suite != 2
        || owner.principal_id() != vault.policy.genesis.owner.principal_id
    {
        return Err(invalid());
    }
    let generated = NativeIdGenerator::new()
        .generate_item_id(|_| false)
        .map_err(|_| invalid())?;
    let mut migration = SignedSuiteMigrationV1 {
        migration_format: 1,
        migration_id: MigrationId::from_bytes(*generated.as_bytes()).map_err(|_| invalid())?,
        old_vault_id: statement.source_vault_id,
        old_genesis_fingerprint: statement.source_genesis_fingerprint.clone(),
        old_terminal_revision_hash: statement.terminal_source_revision_hash.clone(),
        old_suite,
        new_vault_id: vault.header.vault_id,
        new_genesis_fingerprint: vault.header.genesis_fingerprint.clone(),
        new_suite: vault.header.suite,
        migrated_item_manifest_digest: statement.bootstrap_manifest_digest.clone(),
        signature: Signature64::new([0; 64]),
    };
    migration.signature = owner
        .sign_validated_statement(&migration.signature_preimage())
        .map_err(|_| invalid())?;
    vault.suite_migration = Some(migration);
    verify(vault)
}

/// Authenticity is checked against the retained genesis owner, even after a
/// later owner removal. Source authority/freshness remains a separate check.
pub(super) fn verify(vault: &VaultFileV1) -> Result<(), RolloverError> {
    let statement = match &vault.policy.genesis.source_attestation {
        Some(SourceAttestationV1::Rollover { statement }) => Some(statement),
        _ => None,
    };
    let source_suite = statement
        .and_then(|value| value.bootstrap_manifest.as_ref())
        .and_then(|manifest| manifest.source_suite);
    let required = source_suite.is_some_and(|suite| suite != vault.header.suite);
    let Some(migration) = &vault.suite_migration else {
        return if required { Err(invalid()) } else { Ok(()) };
    };
    let statement = statement.ok_or_else(invalid)?;
    let manifest = statement.bootstrap_manifest.as_ref().ok_or_else(invalid)?;
    if !required
        || source_suite != Some(1)
        || vault.header.suite != 2
        || migration.migration_format != 1
        || migration.old_suite != 1
        || migration.new_suite != 2
        || migration.old_vault_id != statement.source_vault_id
        || migration.old_genesis_fingerprint != statement.source_genesis_fingerprint
        || migration.old_terminal_revision_hash != statement.terminal_source_revision_hash
        || migration.new_vault_id != vault.header.vault_id
        || migration.new_genesis_fingerprint != vault.header.genesis_fingerprint
        || migration.migrated_item_manifest_digest != statement.bootstrap_manifest_digest
        || manifest.digest().map_err(|_| invalid())? != migration.migrated_item_manifest_digest
        || statement.acting_owner_principal_id != vault.policy.genesis.owner.principal_id
    {
        return Err(invalid());
    }
    crypto::verify_bytes(
        &vault.policy.genesis.owner.verification_public_key,
        &migration.signature_preimage(),
        &migration.signature,
    )
    .map_err(|_| invalid())
}
