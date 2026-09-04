use std::cell::Cell;
use std::collections::VecDeque;

use ed25519_dalek::{Signer as _, SigningKey};
use jury_protected::{EntropyError, RandomSource};
use jury_protocol::vault_v1::{
    AccessRole, ContentRole, DescriptorMetadataV1, Digest32, DirectCiphertext48, DirectSlotV1,
    Encapsulation1120, FixedBytes, ItemAccessMode, ItemId, ItemKind, Nonce12, PolicyOperationV1,
    PrincipalDescriptorV1, PrincipalId, PrincipalKind, RecipientPublicKey1216, RevisionSealId,
    ShareCiphertext49, Signature64, SignedPolicyRevisionV1, SlotId, VaultId,
    VerificationPublicKey32, WitnessPolicyId, WitnessShareCapsuleV1, WitnessedSlotV1,
    WitnessedStateV1, recipient_public_key_fingerprint,
};
use sha2::{Digest as _, Sha256};

use crate::domain::Capability;
use crate::domain::IDENTIFIER_COLLISION_RETRY_ATTEMPTS;

use super::replay::{
    PolicySigner, apply_operations, create_with_test_signer, prepare_with_test_signer,
    replay_policy,
};
use super::{
    AccessPath, ApprovalMode, ApproverPolicyDescriptor, DescriptorStatus, OperationRule,
    PlatformAssurance, PolicyCreator, PolicyError, PolicyErrorKind, WitnessOperation,
    WitnessPolicy, WitnessPolicyDescriptor, replay_policy_with_witness_policies,
};

type AnyResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

struct ScriptedRandom {
    draws: VecDeque<Result<[u8; 32], EntropyError>>,
}

impl ScriptedRandom {
    fn bytes(draws: impl IntoIterator<Item = [u8; 32]>) -> Self {
        Self {
            draws: draws.into_iter().map(Ok).collect(),
        }
    }

    fn failing() -> Self {
        Self {
            draws: VecDeque::from([Err(EntropyError)]),
        }
    }
}

impl RandomSource for ScriptedRandom {
    fn fill(&mut self, destination: &mut [u8]) -> Result<(), EntropyError> {
        let draw = self.draws.pop_front().ok_or(EntropyError)??;
        if destination.len() != draw.len() {
            return Err(EntropyError);
        }
        destination.copy_from_slice(&draw);
        Ok(())
    }
}

struct TestSigner {
    key: SigningKey,
    descriptor: PrincipalDescriptorV1,
    signatures: Cell<usize>,
}

impl TestSigner {
    fn new(id_byte: u8, seed_byte: u8, kind: PrincipalKind) -> AnyResult<Self> {
        let key = SigningKey::from_bytes(&[seed_byte; 32]);
        let mut descriptor = PrincipalDescriptorV1 {
            descriptor_version: 1,
            principal_id: PrincipalId::from_bytes([id_byte; 32])?,
            principal_kind: kind,
            recipient_public_key: RecipientPublicKey1216::new([seed_byte.wrapping_add(1); 1216]),
            verification_public_key: VerificationPublicKey32::new(key.verifying_key().to_bytes()),
            self_signature: Signature64::new([0; 64]),
        };
        let preimage = descriptor.self_signature_preimage()?;
        descriptor.self_signature = Signature64::new(key.sign(&preimage).to_bytes());
        Ok(Self {
            key,
            descriptor,
            signatures: Cell::new(0),
        })
    }
}

impl PolicySigner for TestSigner {
    fn principal_id(&self) -> PrincipalId {
        self.descriptor.principal_id
    }

    fn descriptor(&self) -> Result<PrincipalDescriptorV1, PolicyError> {
        Ok(self.descriptor.clone())
    }

    fn sign(&self, preimage: &[u8]) -> Result<Signature64, PolicyError> {
        self.signatures.set(self.signatures.get() + 1);
        Ok(Signature64::new(self.key.sign(preimage).to_bytes()))
    }
}

fn created_policy() -> AnyResult<(TestSigner, super::CreatedPolicy)> {
    let owner = TestSigner::new(0x21, 0x31, PrincipalKind::Human)?;
    let mut creator = PolicyCreator::from_source(ScriptedRandom::bytes([[0x11; 32]]));
    let created = create_with_test_signer(&mut creator, &owner, 1_700_000_000_000, |_| false)?;
    Ok((owner, created))
}

#[test]
fn genesis_uses_generated_vault_id_and_replays_from_public_signatures() -> AnyResult {
    let (owner, created) = created_policy()?;

    assert_eq!(created.state.vault_id().as_bytes(), &[0x11; 32]);
    assert!(created.state.is_owner(&owner.principal_id()));
    assert_eq!(owner.signatures.get(), 1);
    assert_eq!(replay_policy(&created.journal), Ok(created.state));
    Ok(())
}

#[test]
fn vault_generation_propagates_entropy_and_known_lineage_collisions() -> AnyResult {
    let owner = TestSigner::new(0x21, 0x31, PrincipalKind::Human)?;
    let mut failing = PolicyCreator::from_source(ScriptedRandom::failing());
    let error = match create_with_test_signer(&mut failing, &owner, 1, |_| false) {
        Err(error) => error,
        Ok(_) => panic!("entropy failure must return no genesis"),
    };
    assert_eq!(error.kind(), PolicyErrorKind::EntropyUnavailable);
    assert_eq!(owner.signatures.get(), 0);

    let mut retry = PolicyCreator::from_source(ScriptedRandom::bytes([[0x41; 32], [0x42; 32]]));
    let created = create_with_test_signer(&mut retry, &owner, 1, |candidate| {
        candidate.as_bytes() == &[0x41; 32]
    })?;
    assert_eq!(created.state.vault_id().as_bytes(), &[0x42; 32]);

    let exhausted_owner = TestSigner::new(0x24, 0x34, PrincipalKind::Human)?;
    let draws = (0..IDENTIFIER_COLLISION_RETRY_ATTEMPTS)
        .map(|index| Ok([u8::try_from(index + 1)?; 32]))
        .collect::<AnyResult<Vec<_>>>()?;
    let mut exhausted = PolicyCreator::from_source(ScriptedRandom::bytes(draws));
    let exhausted_result = create_with_test_signer(&mut exhausted, &exhausted_owner, 1, |_| true);
    assert!(
        matches!(exhausted_result, Err(error) if error.kind() == PolicyErrorKind::RetryExhausted)
    );
    assert_eq!(exhausted_owner.signatures.get(), 0);
    Ok(())
}

#[test]
fn only_the_current_owner_can_sign_a_revision() -> AnyResult {
    let (_owner, created) = created_policy()?;
    let outsider = TestSigner::new(0x22, 0x32, PrincipalKind::Human)?;
    let result = prepare_with_test_signer(
        &created.state,
        &outsider,
        1_700_000_000_001,
        vec![PolicyOperationV1::PrincipalAdd {
            descriptor: outsider.descriptor.clone(),
            display_label: "ExamplePrincipal".to_owned(),
            registration_proof_digest: FixedBytes::new([0x44; 32]),
        }],
    );

    assert!(matches!(result, Err(error) if error.kind() == PolicyErrorKind::Unauthorized));
    assert_eq!(outsider.signatures.get(), 0);
    Ok(())
}

#[test]
fn replayed_state_retains_exact_policy_ancestry() -> AnyResult {
    let (owner, created) = created_policy()?;
    let principal = TestSigner::new(0x22, 0x32, PrincipalKind::Human)?;
    let descendant = prepare_with_test_signer(
        &created.state,
        &owner,
        1_700_000_000_001,
        vec![PolicyOperationV1::PrincipalAdd {
            descriptor: principal.descriptor,
            display_label: "ExamplePrincipal".to_owned(),
            registration_proof_digest: FixedBytes::new([0x44; 32]),
        }],
    )?;
    assert!(descendant.state.is_direct_descendant_of(&created.state));

    let mut unrelated = descendant.state;
    unrelated.revision_hashes[0] = FixedBytes::new([0xff; 32]);
    assert!(!unrelated.is_direct_descendant_of(&created.state));
    Ok(())
}

#[test]
fn signed_principal_lifecycle_replays_and_never_reuses_an_id() -> AnyResult {
    let (owner, mut created) = created_policy()?;
    let principal = TestSigner::new(0x22, 0x32, PrincipalKind::Human)?;
    let add = prepare_with_test_signer(
        &created.state,
        &owner,
        1_700_000_000_001,
        vec![PolicyOperationV1::PrincipalAdd {
            descriptor: principal.descriptor.clone(),
            display_label: "ExamplePrincipal".to_owned(),
            registration_proof_digest: FixedBytes::new([0x44; 32]),
        }],
    )?;
    created.journal.revisions.push(add.revision);
    created.state = add.state;
    let remove = prepare_with_test_signer(
        &created.state,
        &owner,
        1_700_000_000_002,
        vec![PolicyOperationV1::PrincipalRemove {
            principal_id: principal.principal_id(),
            removal_reason: jury_protocol::vault_v1::RemovalReason::Retirement,
        }],
    )?;
    created.journal.revisions.push(remove.revision);
    created.state = remove.state;

    assert_eq!(replay_policy(&created.journal), Ok(created.state.clone()));
    let reused = prepare_with_test_signer(
        &created.state,
        &owner,
        1_700_000_000_003,
        vec![PolicyOperationV1::PrincipalAdd {
            descriptor: principal.descriptor,
            display_label: "ReusedPrincipal".to_owned(),
            registration_proof_digest: FixedBytes::new([0x45; 32]),
        }],
    );
    assert!(matches!(reused, Err(error) if error.kind() == PolicyErrorKind::IdentifierReused));
    Ok(())
}

#[test]
fn sole_owner_cannot_be_revoked() -> AnyResult {
    let (owner, created) = created_policy()?;
    let result = prepare_with_test_signer(
        &created.state,
        &owner,
        1_700_000_000_001,
        vec![PolicyOperationV1::OwnerRevoke {
            principal_id: owner.principal_id(),
        }],
    );
    assert!(matches!(result, Err(error) if error.kind() == PolicyErrorKind::SoleOwner));
    Ok(())
}

#[test]
fn forged_revision_and_resulting_state_are_rejected() -> AnyResult {
    let (owner, mut created) = created_policy()?;
    let principal = TestSigner::new(0x22, 0x32, PrincipalKind::Approver)?;
    let prepared = prepare_with_test_signer(
        &created.state,
        &owner,
        1_700_000_000_001,
        vec![PolicyOperationV1::PrincipalAdd {
            descriptor: principal.descriptor,
            display_label: "ExampleApprover".to_owned(),
            registration_proof_digest: FixedBytes::new([0x44; 32]),
        }],
    )?;
    created.journal.revisions.push(prepared.revision.clone());
    let mut forged_signature = *created.journal.revisions[0].signature.as_bytes();
    forged_signature[0] ^= 1;
    created.journal.revisions[0].signature = Signature64::new(forged_signature);
    assert!(
        matches!(replay_policy(&created.journal), Err(error) if error.kind() == PolicyErrorKind::InvalidSignature)
    );

    created.journal.revisions[0] = prepared.revision;
    created.journal.revisions[0].resulting_policy_state_hash = FixedBytes::new([0x99; 32]);
    assert!(
        matches!(replay_policy(&created.journal), Err(error) if error.kind() == PolicyErrorKind::InvalidSignature)
    );
    Ok(())
}

#[test]
fn direct_item_state_exposes_authority_and_suppresses_a_quorum_claim() -> AnyResult {
    let (owner, created) = created_policy()?;
    let item_id = ItemId::from_bytes([0x51; 32])?;
    let descriptor = descriptor_metadata(1, 1, 0x61)?;
    let current_hash = FixedBytes::new([0x62; 32]);
    let slots = direct_slots(
        created.state.vault_id(),
        item_id,
        owner.principal_id(),
        1,
        1,
        AccessRole::Owner,
        ItemAccessMode::DirectOnly,
        recipient_public_key_fingerprint(&owner.descriptor.recipient_public_key),
    )?;
    let prepared = prepare_with_test_signer(
        &created.state,
        &owner,
        1_700_000_000_001,
        vec![PolicyOperationV1::ItemCreate {
            item_id,
            item_kind: ItemKind::Canonical,
            key_epoch: 1,
            descriptor,
            current_item_revision_hash: current_hash,
            direct_slots: slots,
            witnessed_state: None,
        }],
    )?;

    let read = prepared
        .state
        .access(&item_id, &owner.principal_id(), Capability::Read);
    assert!(read.allowed);
    assert_eq!(read.effective_role, Some(AccessRole::Owner));
    assert_eq!(read.path, AccessPath::Direct);
    assert!(!read.carries_quorum_claim);
    Ok(())
}

#[test]
fn replay_accepts_legacy_item_without_every_implicit_owner_slot() -> AnyResult {
    let (owner, mut created) = created_policy()?;
    let next_owner = TestSigner::new(0x22, 0x32, PrincipalKind::Human)?;
    let owner_added = prepare_with_test_signer(
        &created.state,
        &owner,
        1_700_000_000_001,
        vec![
            PolicyOperationV1::PrincipalAdd {
                descriptor: next_owner.descriptor.clone(),
                display_label: "ExampleOwner".to_owned(),
                registration_proof_digest: FixedBytes::new([0x44; 32]),
            },
            PolicyOperationV1::OwnerGrant {
                principal_id: next_owner.principal_id(),
            },
        ],
    )?;
    created.journal.revisions.push(owner_added.revision);

    let item_id = ItemId::from_bytes([0x51; 32])?;
    let operations = vec![PolicyOperationV1::ItemCreate {
        item_id,
        item_kind: ItemKind::Canonical,
        key_epoch: 1,
        descriptor: descriptor_metadata(1, 1, 0x61)?,
        current_item_revision_hash: FixedBytes::new([0x62; 32]),
        direct_slots: direct_slots(
            owner_added.state.vault_id(),
            item_id,
            owner.principal_id(),
            1,
            2,
            AccessRole::Owner,
            ItemAccessMode::DirectOnly,
            recipient_public_key_fingerprint(&owner.descriptor.recipient_public_key),
        )?,
        witnessed_state: None,
    }];
    let Err(new_write_error) = prepare_with_test_signer(
        &owner_added.state,
        &owner,
        1_700_000_000_002,
        operations.clone(),
    ) else {
        panic!("new writes must include every implicit owner slot");
    };
    assert_eq!(
        new_write_error.kind(),
        PolicyErrorKind::IncompleteRotation
    );

    // This revision models bytes produced before implicit owner-slot
    // completion became a new-write invariant. It remains fully signed and
    // state-hash checked; only its historical construction rule differs.
    let mut legacy_state = apply_operations(&owner_added.state, 2, &operations)?;
    let mut legacy_revision = SignedPolicyRevisionV1 {
        vault_id: owner_added.state.vault_id(),
        sequence: 2,
        previous_revision_hash: owner_added.state.terminal_revision_hash().clone(),
        timestamp_ms: 1_700_000_000_002,
        author_principal_id: owner.principal_id(),
        operations,
        resulting_policy_state_hash: legacy_state.normalized_state_hash()?,
        signature: Signature64::new([0; 64]),
    };
    legacy_revision.signature = owner.sign(&legacy_revision.signature_preimage()?)?;
    legacy_state.terminal_revision_hash = legacy_revision.recomputed_hash()?;
    legacy_state
        .revision_hashes
        .push(legacy_state.terminal_revision_hash.clone());
    created.journal.revisions.push(legacy_revision);

    assert_eq!(replay_policy(&created.journal), Ok(legacy_state));
    Ok(())
}
