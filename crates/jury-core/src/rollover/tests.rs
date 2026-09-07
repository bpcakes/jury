use jury_protected::{ProtectedMemory, ProtectionPolicy};
use jury_protocol::{
    identity_v1::KdfProfile,
    vault_v1::{
        Digest32, PolicyOperationV1, PrincipalKind, RolloverId, Signature64, SignedRolloverV1,
        VaultHeaderV1,
    },
};

use super::*;
use crate::{
    identity::{IdentityCreator, UnlockedIdentity, VaultPrincipalIdentity, unlock},
    policy::PolicyCreator,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

pub(super) fn owner() -> TestResult<VaultPrincipalIdentity> {
    let protection = ProtectionPolicy::EmergencyAllowDegraded;
    let passphrase = ProtectedMemory::initialize(15, protection, |output| {
        output.copy_from_slice(b"ExamplePass1234");
        Ok::<usize, ()>(output.len())
    })?;
    let identity = IdentityCreator::new().create(
        PrincipalKind::Human,
        KdfProfile::PortableV1,
        1,
        &passphrase,
        |_| false,
    )?;
    match unlock(&identity.file, &passphrase)? {
        UnlockedIdentity::VaultPrincipal(owner) => Ok(owner),
        _ => Err("unexpected fixture role".into()),
    }
}

pub(super) fn source(owner: &VaultPrincipalIdentity) -> TestResult<VaultFileV1> {
    let mut created = PolicyCreator::new().create(owner, 1, |_| false)?;
    let updated = created.state.prepare_revision(
        owner,
        2,
        vec![PolicyOperationV1::PrincipalLabelChange {
            principal_id: owner.principal_id(),
            prior_label: "owner".to_owned(),
            next_label: "ExamplePrincipal".to_owned(),
        }],
    )?;
    created.journal.revisions.push(updated.revision);
    Ok(VaultFileV1 {
        header: VaultHeaderV1 {
            magic: "jury-vault".to_owned(),
            version: 1,
            vault_id: created.state.vault_id(),
            created_at_ms: 1,
            suite: 1,
            policy_schema: 1,
            item_schema: 1,
            identity_schema: 1,
            genesis_fingerprint: created.state.genesis_fingerprint().clone(),
        },
        policy: created.journal,
        items: Vec::new(),
        suite_migration: None,
    })
}

fn destination(
    source: &VaultFileV1,
    owner: &VaultPrincipalIdentity,
) -> TestResult<PolicyGenesisV1> {
    let mut genesis = PolicyCreator::new()
        .create(
            owner,
            source
                .policy
                .revisions
                .last()
                .map_or(1, |revision| revision.timestamp_ms)
                + 1,
            |id| *id == source.header.vault_id,
        )?
        .journal
        .genesis;
    let mut statement = SignedRolloverV1 {
        rollover_format: 1,
        rollover_id: RolloverId::from_bytes([0x51; 32])?,
        source_vault_id: source.header.vault_id,
        source_genesis_fingerprint: source.header.genesis_fingerprint.clone(),
        terminal_source_revision_hash: replay_policy(&source.policy)?
            .terminal_revision_hash()
            .clone(),
        destination_vault_id: genesis.vault_id,
        destination_suite: 1,
        bootstrap_manifest_digest: Digest32::new([0x52; 32]),
        bootstrap_manifest: None,
        acting_owner_principal_id: owner.principal_id(),
        signature: Signature64::new([0; 64]),
    };
    statement.signature = owner.sign_validated_statement(&statement.signature_preimage())?;
    genesis.source_attestation = Some(SourceAttestationV1::Rollover {
        statement: Box::new(statement),
    });
    resign_genesis(&mut genesis, owner)?;
    Ok(genesis)
}

fn resign_genesis(genesis: &mut PolicyGenesisV1, owner: &VaultPrincipalIdentity) -> TestResult {
    genesis.owner_signature = owner.sign_validated_statement(&genesis.signature_preimage()?)?;
    Ok(())
}

#[test]
fn authenticates_exact_source_owner_and_bridge_without_modifying_source() -> TestResult {
    let owner = owner()?;
    let source_vault = source(&owner)?;
    let before = source_vault.to_json_bytes()?;
    let destination = destination(&source_vault, &owner)?;
    let validated = RolloverSource::validate(&source_vault, &[])?;
    validated.verify_source_authorization(&destination)?;
    assert_ne!(destination.vault_id, source_vault.header.vault_id);
    assert_ne!(
        destination.recomputed_fingerprint()?,
        source_vault.header.genesis_fingerprint
    );
    assert_eq!(source_vault.to_json_bytes()?, before);
    Ok(())
}

#[test]
fn genesis_signature_cannot_substitute_for_source_bridge_signature() -> TestResult {
    let owner = owner()?;
    let vault = source(&owner)?;
    let valid = destination(&vault, &owner)?;
    let source = RolloverSource::validate(&vault, &[])?;
    // Re-signing the enclosing genesis must not bless a modified bridge.
    for field in 0..10 {
        let mut changed = valid.clone();
        let Some(SourceAttestationV1::Rollover { statement }) = &mut changed.source_attestation
        else {
            return Err("fixture bridge absent".into());
        };
        match field {
            0 => statement.rollover_format = 2,
            1 => statement.rollover_id = RolloverId::from_bytes([0x61; 32])?,
            2 => statement.source_vault_id = valid.vault_id,
            3 => statement.source_genesis_fingerprint = Digest32::new([0x62; 32]),
            4 => statement.terminal_source_revision_hash = Digest32::new([0x63; 32]),
            5 => statement.destination_vault_id = vault.header.vault_id,
            6 => statement.destination_suite = 2,
            7 => statement.bootstrap_manifest_digest = Digest32::new([0x64; 32]),
            8 => {
                statement.acting_owner_principal_id =
                    jury_protocol::vault_v1::PrincipalId::from_bytes([0x65; 32])?;
            }
            _ => statement.signature = Signature64::new([0x66; 64]),
        }
        resign_genesis(&mut changed, &owner)?;
        assert!(
            source.verify_source_authorization(&changed).is_err(),
            "field {field}"
        );
    }
    let mut changed = valid.clone();
    changed.owner_signature = Signature64::new([0; 64]);
    assert_eq!(
        source
            .verify_source_authorization(&changed)
            .err()
            .map(RolloverError::kind),
        Some(RolloverErrorKind::InvalidDestination)
    );
    Ok(())
}

#[test]
fn rejects_valid_bridge_from_a_nonowner_and_a_different_terminal_revision() -> TestResult {
    let actual_owner = owner()?;
    let stranger = owner()?;
    let vault = source(&actual_owner)?;
    let unauthorized = destination(&vault, &stranger)?;
    let validated = RolloverSource::validate(&vault, &[])?;
    assert_eq!(
        validated
            .verify_source_authorization(&unauthorized)
            .err()
            .map(RolloverError::kind),
        Some(RolloverErrorKind::Unauthorized)
    );

    let valid = destination(&vault, &actual_owner)?;
    let mut older = vault.clone();
    older.policy.revisions.clear();
    assert_eq!(
        RolloverSource::validate(&older, &[])?
            .verify_source_authorization(&valid)
            .err()
            .map(RolloverError::kind),
        Some(RolloverErrorKind::SourceMismatch)
    );
    let mut corrupt = vault.clone();
    corrupt.policy.revisions[0].signature = Signature64::new([0; 64]);
    assert_eq!(
        RolloverSource::validate(&corrupt, &[])
            .err()
            .map(RolloverError::kind),
        Some(RolloverErrorKind::InvalidSource)
    );
    Ok(())
}

#[test]
fn source_authority_is_the_terminal_owner_set_not_the_genesis_owner() -> TestResult {
    let first = owner()?;
    let second = owner()?;
    let mut vault = source(&first)?;
    let added = replay_policy(&vault.policy)?.prepare_revision(
        &first,
        3,
        vec![PolicyOperationV1::PrincipalAdd {
            descriptor: second.public_descriptor()?,
            display_label: "ExampleSuccessor".to_owned(),
            registration_proof_digest: Digest32::new([0x71; 32]),
        }],
    )?;
    vault.policy.revisions.push(added.revision);
    let nonowner = destination(&vault, &second)?;
    assert_eq!(
        RolloverSource::validate(&vault, &[])?
            .verify_source_authorization(&nonowner)
            .err()
            .map(RolloverError::kind),
        Some(RolloverErrorKind::Unauthorized)
    );
    let changed = replay_policy(&vault.policy)?.prepare_revision(
        &first,
        4,
        vec![
            PolicyOperationV1::OwnerGrant {
                principal_id: second.principal_id(),
            },
            PolicyOperationV1::OwnerRevoke {
                principal_id: first.principal_id(),
            },
        ],
    )?;
    vault.policy.revisions.push(changed.revision);
    let validated = RolloverSource::validate(&vault, &[])?;
    assert_eq!(
        validated
            .verify_source_authorization(&destination(&vault, &first)?)
            .err()
            .map(RolloverError::kind),
        Some(RolloverErrorKind::Unauthorized)
    );
    validated.verify_source_authorization(&destination(&vault, &second)?)?;
    Ok(())
}
