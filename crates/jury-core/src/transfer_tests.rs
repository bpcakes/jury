use jury_protected::{EntropyError, RandomSource};
use jury_protocol::vault_v1::{
    PolicyOperationV1, PrincipalId, PrincipalKind, Signature64, VaultFileV1, VaultHeaderV1,
};

use super::*;
use crate::identity::{UnlockedIdentity, unlocked_identity_for_test};
use crate::policy::{PolicyCreator, replay_policy};
use crate::registration::{RegistrationCreator, answer_challenge};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

struct CounterRandom(u8);

impl RandomSource for CounterRandom {
    fn fill(&mut self, destination: &mut [u8]) -> Result<(), EntropyError> {
        self.0 = self.0.wrapping_add(1);
        destination.fill(self.0);
        Ok(())
    }
}

fn fixture() -> TestResult<(VaultPrincipalIdentity, VaultFileV1)> {
    let principal_id = PrincipalId::from_bytes([0x21; 32])?;
    let UnlockedIdentity::VaultPrincipal(owner) =
        unlocked_identity_for_test(principal_id, PrincipalKind::Human, &mut CounterRandom(0x30))?
    else {
        return Err("fixture identity role differs".into());
    };
    let created = PolicyCreator::from_source(CounterRandom(0x50)).create(&owner, 10, |_| false)?;
    let genesis_fingerprint = created.journal.genesis.recomputed_fingerprint()?;
    let vault = VaultFileV1 {
        header: VaultHeaderV1 {
            magic: "jury-vault".to_owned(),
            version: 1,
            vault_id: created.journal.genesis.vault_id,
            created_at_ms: created.journal.genesis.created_at_ms,
            suite: 1,
            policy_schema: 1,
            item_schema: 1,
            identity_schema: 1,
            genesis_fingerprint,
        },
        policy: created.journal,
        items: Vec::new(),
        suite_migration: None,
    };
    vault.validate()?;
    Ok((owner, vault))
}

fn relabel(
    vault: &VaultFileV1,
    owner: &VaultPrincipalIdentity,
    prior_label: &str,
    next_label: &str,
    timestamp_ms: u64,
) -> TestResult<VaultFileV1> {
    let state = replay_policy_with_witness_policies(&vault.policy, &[])?;
    let prepared = state.prepare_revision(
        owner,
        timestamp_ms,
        vec![PolicyOperationV1::PrincipalLabelChange {
            principal_id: owner.principal_id(),
            prior_label: prior_label.to_owned(),
            next_label: next_label.to_owned(),
        }],
    )?;
    let mut target = vault.clone();
    target.policy.revisions.push(prepared.revision);
    target.validate()?;
    Ok(target)
}

fn register_approver(
    vault: &VaultFileV1,
    owner: &VaultPrincipalIdentity,
) -> TestResult<(VaultFileV1, RegistrationProofV1)> {
    let candidate_id = PrincipalId::from_bytes([0x22; 32])?;
    let candidate = unlocked_identity_for_test(
        candidate_id,
        PrincipalKind::Approver,
        &mut CounterRandom(0x60),
    )?;
    let candidate_descriptor = candidate.public_descriptor()?;
    let policy = replay_policy(&vault.policy)?;
    let challenge = RegistrationCreator::new(jury_protected::ProtectionPolicy::Strict)
        .create_challenge(
            &policy,
            owner,
            candidate_descriptor.clone(),
            11,
            1_000,
            None,
        )?;
    let proof = answer_challenge(&policy, &candidate, &challenge, 12)?;
    let revision = policy.prepare_revision(
        owner,
        13,
        vec![PolicyOperationV1::PrincipalAdd {
            descriptor: candidate_descriptor,
            display_label: "ExampleApprover".to_owned(),
            registration_proof_digest: proof.digest()?,
        }],
    )?;
    let mut registered = vault.clone();
    registered.policy.revisions.push(revision.revision);
    registered.validate()?;
    Ok((registered, proof))
}

#[test]
fn signed_transfer_round_trip_carries_only_public_portable_state() -> TestResult {
    let (owner, vault) = fixture()?;
    let catalog = TransferPublicCatalogV1::new(Vec::new(), Vec::new())?;
    let mut creator = TransferCreator::from_source(CounterRandom(0x80));
    let envelope = creator.create(&vault, catalog, &owner, 20)?;
    let bytes = envelope.to_json_bytes()?;
    let parsed = ValidatedTransfer::parse(&bytes)?;

    assert_eq!(parsed.vault(), &vault);
    assert_eq!(parsed.policy().sequence(), 0);
    assert_eq!(
        parsed.envelope().exporting_principal_id,
        owner.principal_id()
    );
    assert!(!bytes.windows(5).any(|window| window == b"audit"));
    assert!(!bytes.windows(10).any(|window| window == b"checkpoint"));
    assert!(!bytes.windows(7).any(|window| window == b"receipt"));
    assert!(!bytes.windows(11).any(|window| window == b"private_key"));
    Ok(())
}

#[test]
fn portable_catalog_requires_the_registration_proof_bound_by_policy() -> TestResult {
    let (owner, vault) = fixture()?;
    let (registered, proof) = register_approver(&vault, &owner)?;

    let missing = TransferPublicCatalogV1::empty();
    assert!(matches!(
        TransferCreator::from_source(CounterRandom(0x70)).create(
            &registered,
            missing,
            &owner,
            20
        ),
        Err(error) if error.kind() == TransferErrorKind::InvalidCatalog
    ));

    let mut substituted = proof.clone();
    substituted.response_mac = jury_protocol::vault_v1::Digest32::new([0x55; 32]);
    let substituted = TransferPublicCatalogV1::new(vec![substituted], Vec::new())?;
    assert!(matches!(
        TransferCreator::from_source(CounterRandom(0x71)).create(
            &registered,
            substituted,
            &owner,
            20
        ),
        Err(error) if error.kind() == TransferErrorKind::InvalidCatalog
    ));

    let catalog = TransferPublicCatalogV1::new(vec![proof], Vec::new())?;
    let envelope = TransferCreator::from_source(CounterRandom(0x72)).create(
        &registered,
        catalog,
        &owner,
        20,
    )?;
    assert_eq!(
        ValidatedTransfer::parse(&envelope.to_json_bytes()?)?.vault(),
        &registered
    );
    Ok(())
}

#[test]
fn envelope_metadata_or_signature_tampering_is_rejected() -> TestResult {
    let (owner, vault) = fixture()?;
    let catalog = TransferPublicCatalogV1::new(Vec::new(), Vec::new())?;
    let mut creator = TransferCreator::from_source(CounterRandom(0x90));
    let envelope = creator.create(&vault, catalog, &owner, 20)?;

    let mut metadata_tamper = envelope.clone();
    metadata_tamper.created_at_ms = 21;
    let metadata_bytes = metadata_tamper.to_json_bytes()?;
    assert!(matches!(
        ValidatedTransfer::parse(&metadata_bytes),
        Err(error) if error.kind() == TransferErrorKind::AuthenticationFailed
    ));

    let mut signature_tamper = envelope;
    signature_tamper.exporter_signature = Signature64::new([0x55; 64]);
    let signature_bytes = signature_tamper.to_json_bytes()?;
    assert!(matches!(
        ValidatedTransfer::parse(&signature_bytes),
        Err(error) if error.kind() == TransferErrorKind::AuthenticationFailed
    ));
    Ok(())
}

#[test]
fn relation_requires_one_complete_branch_to_be_an_exact_prefix() -> TestResult {
    let (owner, base) = fixture()?;
    let first = relabel(&base, &owner, "owner", "first-owner", 20)?;
    let second = relabel(&first, &owner, "first-owner", "second-owner", 30)?;
    let independent = relabel(&base, &owner, "owner", "independent-owner", 20)?;

    assert_eq!(compare_artifacts(&base, &base), ArtifactRelation::Identical);
    assert_eq!(
        compare_artifacts(&base, &first),
        ArtifactRelation::IncomingStrictDescendant
    );
    assert_eq!(
        compare_artifacts(&second, &first),
        ArtifactRelation::LocalStrictDescendant
    );
    assert_eq!(
        compare_artifacts(&first, &independent),
        ArtifactRelation::Divergent
    );
    Ok(())
}
