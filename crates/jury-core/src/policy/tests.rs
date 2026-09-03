use std::cell::Cell;
use std::collections::VecDeque;

use ed25519_dalek::{Signer as _, SigningKey};
use jury_protected::{EntropyError, RandomSource};
use jury_protocol::vault_v1::{
    AccessRole, ContentRole, DescriptorMetadataV1, Digest32, DirectCiphertext48, DirectSlotV1,
    Encapsulation1120, FixedBytes, ItemAccessMode, ItemId, ItemKind, Nonce12, PolicyOperationV1,
    PrincipalDescriptorV1, PrincipalId, PrincipalKind, RecipientPublicKey1216, RevisionSealId,
    ShareCiphertext49, Signature64, SlotId, VaultId, VerificationPublicKey32, WitnessPolicyId,
    WitnessShareCapsuleV1, WitnessedSlotV1, WitnessedStateV1, recipient_public_key_fingerprint,
};
use sha2::{Digest as _, Sha256};

use crate::domain::Capability;
use crate::domain::IDENTIFIER_COLLISION_RETRY_ATTEMPTS;

use super::replay::{
    PolicySigner, create_with_test_signer, prepare_with_test_signer, replay_policy,
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
fn witnessed_item_uses_only_the_bound_membership_quorums_and_workload_rule() -> AnyResult {
    let (owner, mut created) = created_policy()?;
    let approvers = [
        TestSigner::new(0x41, 0x21, PrincipalKind::Approver)?,
        TestSigner::new(0x42, 0x22, PrincipalKind::Approver)?,
    ];
    let witnesses = [
        TestSigner::new(0x51, 0x51, PrincipalKind::Witness)?,
        TestSigner::new(0x52, 0x52, PrincipalKind::Witness)?,
        TestSigner::new(0x53, 0x53, PrincipalKind::Witness)?,
    ];
    let add_operations = approvers
        .iter()
        .chain(&witnesses)
        .map(|signer| PolicyOperationV1::PrincipalAdd {
            descriptor: signer.descriptor.clone(),
            display_label: "ExampleAuthority".to_owned(),
            registration_proof_digest: FixedBytes::new([0x45; 32]),
        })
        .collect();
    let add = prepare_with_test_signer(&created.state, &owner, 1_700_000_000_001, add_operations)?;
    created.journal.revisions.push(add.revision);

    let item_id = ItemId::from_bytes([0x61; 32])?;
    let share_indexes = [2, 7, 31];
    let policy = witnessed_policy(
        add.state.vault_id(),
        add.state.genesis_fingerprint().clone(),
        2,
        &approvers,
        &witnesses,
        share_indexes,
        item_id,
    )?;
    policy
        .validate()
        .map_err(|error| std::io::Error::other(format!("policy fixture: {error:?}")))?;
    let policy_digest = policy.digest()?;
    let bound =
        replay_policy_with_witness_policies(&created.journal, std::slice::from_ref(&policy))
            .map_err(|error| std::io::Error::other(format!("catalog replay: {error:?}")))?;
    let witnessed_only_state = witnessed_state(
        bound.vault_id(),
        bound.genesis_fingerprint().clone(),
        item_id,
        2,
        policy.witness_policy_id,
        policy_digest.clone(),
        &witnesses,
        share_indexes,
        ItemAccessMode::WitnessedOnly,
        0x75,
    )?;
    let mixed_item_id = ItemId::from_bytes([0x64; 32])?;
    let mixed_state = witnessed_state(
        bound.vault_id(),
        bound.genesis_fingerprint().clone(),
        mixed_item_id,
        2,
        policy.witness_policy_id,
        policy_digest,
        &witnesses,
        share_indexes,
        ItemAccessMode::Mixed,
        0x95,
    )?;
    let mixed_direct = direct_slots(
        bound.vault_id(),
        mixed_item_id,
        owner.principal_id(),
        1,
        2,
        AccessRole::Owner,
        ItemAccessMode::Mixed,
        recipient_public_key_fingerprint(&owner.descriptor.recipient_public_key),
    )?;
    let item = prepare_with_test_signer(
        &bound,
        &owner,
        1_700_000_000_002,
        vec![
            PolicyOperationV1::ItemCreate {
                item_id,
                item_kind: ItemKind::Canonical,
                key_epoch: 1,
                descriptor: descriptor_metadata(1, 1, 0x62)?,
                current_item_revision_hash: FixedBytes::new([0x63; 32]),
                direct_slots: Vec::new(),
                witnessed_state: Some(witnessed_only_state),
            },
            PolicyOperationV1::ItemCreate {
                item_id: mixed_item_id,
                item_kind: ItemKind::Canonical,
                key_epoch: 1,
                descriptor: descriptor_metadata(1, 1, 0x65)?,
                current_item_revision_hash: FixedBytes::new([0x66; 32]),
                direct_slots: mixed_direct,
                witnessed_state: Some(mixed_state),
            },
        ],
    )
    .map_err(|error| std::io::Error::other(format!("witnessed item: {error:?}")))?;
    created.journal.revisions.push(item.revision);
    let replayed = replay_policy_with_witness_policies(&created.journal, &[policy])?;

    let access = replayed.access(&item_id, &owner.principal_id(), Capability::Read);
    assert!(access.allowed);
    assert_eq!(access.path, AccessPath::Witnessed);
    assert!(access.carries_quorum_claim);
    let rule = replayed.witness_access_rule(&item_id, WitnessOperation::ReadStdout)?;
    assert_eq!(rule.approval_threshold, 2);
    assert_eq!(rule.witness_threshold, 2);
    assert_eq!(rule.eligible_approver_ids.len(), 2);
    assert_eq!(rule.witness_ids.len(), 3);
    assert_eq!(rule.allowed_request_lifetime_ms, 300_000);
    assert_eq!(rule.max_timeout_ms, 30_000);
    assert_eq!(rule.max_output_bytes, 4_096);
    assert!(rule.carries_quorum_claim);

    let mixed = replayed.access(&mixed_item_id, &owner.principal_id(), Capability::Read);
    assert_eq!(mixed.path, AccessPath::Mixed);
    assert!(!mixed.carries_quorum_claim);
    assert!(
        !replayed
            .witness_access_rule(&mixed_item_id, WitnessOperation::ReadStdout)?
            .carries_quorum_claim
    );

    assert!(
        matches!(replay_policy(&created.journal), Err(error) if error.kind() == PolicyErrorKind::MissingWitnessPolicy)
    );
    Ok(())
}

#[test]
fn principal_replacement_requires_and_applies_one_complete_reader_rotation() -> AnyResult {
    let (owner, mut created) = created_policy()?;
    let reader = TestSigner::new(0x31, 0x41, PrincipalKind::Human)?;
    let replacement = TestSigner::new(0x32, 0x42, PrincipalKind::Human)?;
    let add = prepare_with_test_signer(
        &created.state,
        &owner,
        1_700_000_000_001,
        vec![PolicyOperationV1::PrincipalAdd {
            descriptor: reader.descriptor.clone(),
            display_label: "ExampleReader".to_owned(),
            registration_proof_digest: FixedBytes::new([0x43; 32]),
        }],
    )?;
    created.journal.revisions.push(add.revision);
    created.state = add.state;

    let item_id = ItemId::from_bytes([0x54; 32])?;
    let mut slots = direct_slots(
        created.state.vault_id(),
        item_id,
        owner.principal_id(),
        1,
        2,
        AccessRole::Owner,
        ItemAccessMode::DirectOnly,
        recipient_public_key_fingerprint(&owner.descriptor.recipient_public_key),
    )?;
    slots.extend(direct_slots(
        created.state.vault_id(),
        item_id,
        reader.principal_id(),
        1,
        2,
        AccessRole::Reader,
        ItemAccessMode::DirectOnly,
        recipient_public_key_fingerprint(&reader.descriptor.recipient_public_key),
    )?);
    sort_direct_slots(&mut slots);
    let create = prepare_with_test_signer(
        &created.state,
        &owner,
        1_700_000_000_002,
        vec![PolicyOperationV1::ItemCreate {
            item_id,
            item_kind: ItemKind::Canonical,
            key_epoch: 1,
            descriptor: descriptor_metadata(1, 1, 0x55)?,
            current_item_revision_hash: FixedBytes::new([0x56; 32]),
            direct_slots: slots,
            witnessed_state: None,
        }],
    )?;
    created.journal.revisions.push(create.revision);
    created.state = create.state;

    let replacement_operation = PolicyOperationV1::PrincipalReplace {
        prior_principal_id: reader.principal_id(),
        next_descriptor: replacement.descriptor.clone(),
        registration_proof_digest: FixedBytes::new([0x57; 32]),
    };
    let missing_rotation = prepare_with_test_signer(
        &created.state,
        &owner,
        1_700_000_000_003,
        vec![replacement_operation.clone()],
    );
    assert!(
        matches!(missing_rotation, Err(error) if error.kind() == PolicyErrorKind::IncompleteRotation)
    );

    let mut replacement_slots = direct_slots(
        created.state.vault_id(),
        item_id,
        owner.principal_id(),
        2,
        3,
        AccessRole::Owner,
        ItemAccessMode::DirectOnly,
        recipient_public_key_fingerprint(&owner.descriptor.recipient_public_key),
    )?;
    replacement_slots.extend(direct_slots(
        created.state.vault_id(),
        item_id,
        replacement.principal_id(),
        2,
        3,
        AccessRole::Reader,
        ItemAccessMode::DirectOnly,
        recipient_public_key_fingerprint(&replacement.descriptor.recipient_public_key),
    )?);
    sort_direct_slots(&mut replacement_slots);
    let replaced = prepare_with_test_signer(
        &created.state,
        &owner,
        1_700_000_000_003,
        vec![
            replacement_operation,
            PolicyOperationV1::ItemReaderSetChange {
                item_id,
                prior_epoch: 1,
                next_epoch: 2,
                prior_reader_ids: vec![owner.principal_id(), reader.principal_id()],
                next_reader_ids: vec![owner.principal_id(), replacement.principal_id()],
                replacement_descriptor: descriptor_metadata(2, 2, 0x58)?,
                replacement_current_item_revision_hash: FixedBytes::new([0x59; 32]),
            },
            PolicyOperationV1::ItemSlotsReplace {
                item_id,
                next_epoch: 2,
                direct_slots: replacement_slots,
                witnessed_state: None,
            },
        ],
    )?;

    assert!(replaced.state.principal(&reader.principal_id()).is_none());
    assert!(replaced.state.principal_id_was_used(&reader.principal_id()));
    assert!(
        replaced
            .state
            .access(&item_id, &replacement.principal_id(), Capability::Read)
            .allowed
    );
    created.journal.revisions.push(replaced.revision);
    assert_eq!(replay_policy(&created.journal)?, replaced.state);
    Ok(())
}

#[test]
fn deleted_item_identifier_stays_tombstoned_and_cannot_be_recreated() -> AnyResult {
    let (owner, mut created) = created_policy()?;
    let item_id = ItemId::from_bytes([0x67; 32])?;
    let descriptor = descriptor_metadata(1, 1, 0x68)?;
    let current_hash = FixedBytes::new([0x69; 32]);
    let create = prepare_with_test_signer(
        &created.state,
        &owner,
        1_700_000_000_001,
        vec![PolicyOperationV1::ItemCreate {
            item_id,
            item_kind: ItemKind::Canonical,
            key_epoch: 1,
            descriptor: descriptor.clone(),
            current_item_revision_hash: current_hash.clone(),
            direct_slots: direct_slots(
                created.state.vault_id(),
                item_id,
                owner.principal_id(),
                1,
                1,
                AccessRole::Owner,
                ItemAccessMode::DirectOnly,
                recipient_public_key_fingerprint(&owner.descriptor.recipient_public_key),
            )?,
            witnessed_state: None,
        }],
    )?;
    created.journal.revisions.push(create.revision);
    created.state = create.state;
    let delete = prepare_with_test_signer(
        &created.state,
        &owner,
        1_700_000_000_002,
        vec![PolicyOperationV1::ItemDelete {
            item_id,
            final_descriptor_digest: descriptor.ciphertext_digest,
            final_item_revision_hash: current_hash,
            deletion_policy_sequence: 2,
        }],
    )?;
    assert!(delete.state.tombstone(&item_id).is_some());

    let recreate = prepare_with_test_signer(
        &delete.state,
        &owner,
        1_700_000_000_003,
        vec![PolicyOperationV1::ItemCreate {
            item_id,
            item_kind: ItemKind::Canonical,
            key_epoch: 1,
            descriptor: descriptor_metadata(1, 1, 0x6a)?,
            current_item_revision_hash: FixedBytes::new([0x6b; 32]),
            direct_slots: direct_slots(
                delete.state.vault_id(),
                item_id,
                owner.principal_id(),
                1,
                3,
                AccessRole::Owner,
                ItemAccessMode::DirectOnly,
                recipient_public_key_fingerprint(&owner.descriptor.recipient_public_key),
            )?,
            witnessed_state: None,
        }],
    );
    assert!(matches!(recreate, Err(error) if error.kind() == PolicyErrorKind::IdentifierReused));
    Ok(())
}

fn witnessed_policy(
    vault_id: VaultId,
    genesis_fingerprint: Digest32,
    sequence: u64,
    approvers: &[TestSigner; 2],
    witnesses: &[TestSigner; 3],
    share_indexes: [u8; 3],
    item_id: ItemId,
) -> AnyResult<WitnessPolicy> {
    let approver_descriptors = approvers
        .iter()
        .map(approver_policy_descriptor)
        .collect::<AnyResult<Vec<_>>>()?;
    let witness_descriptors = witnesses
        .iter()
        .zip(share_indexes)
        .map(|(signer, share_index)| witness_policy_descriptor(share_index, signer))
        .collect::<AnyResult<Vec<_>>>()?;
    Ok(WitnessPolicy {
        schema: 1,
        witness_policy_id: WitnessPolicyId::from_bytes([0x71; 32])?,
        revision: 1,
        predecessor_policy_digest: FixedBytes::new([0; 32]),
        vault_id,
        genesis_fingerprint,
        vault_policy_sequence: sequence,
        vault_policy_hash: FixedBytes::new([0x72; 32]),
        construction: 1,
        suite: 1,
        approver_descriptors,
        witness_descriptors,
        witness_threshold: 2,
        operation_rules: vec![OperationRule {
            operation: WitnessOperation::ReadStdout,
            eligible_approver_ids: approvers.iter().map(TestSigner::principal_id).collect(),
            approval_threshold: 2,
            allowed_request_lifetime_ms: 300_000,
            max_timeout_ms: 30_000,
            max_output_bytes: 4_096,
            max_target_count: 1,
            required_platform_assurance: PlatformAssurance::NormalizedPathOnly,
            automatic_read_targets: Vec::new(),
        }],
        review_label_set_digest: FixedBytes::new(*item_id.as_bytes()),
        direct_fallback: false,
    })
}

fn approver_policy_descriptor(signer: &TestSigner) -> AnyResult<ApproverPolicyDescriptor> {
    let mut descriptor = ApproverPolicyDescriptor {
        schema: 1,
        approver_id: signer.principal_id(),
        signing_public_key: signer.descriptor.verification_public_key.clone(),
        signing_key_fingerprint: signing_fingerprint(
            2,
            signer.principal_id(),
            &signer.descriptor.verification_public_key,
        ),
        signing_key_epoch: 1,
        status: DescriptorStatus::Active,
        approval_mode: ApprovalMode::Human,
        allowed_operations: vec![WitnessOperation::ReadStdout],
        created_at_ms: 1_700_000_000_000,
        self_signature: Signature64::new([0; 64]),
    };
    descriptor.self_signature = Signature64::new(
        signer
            .key
            .sign(&descriptor.self_signature_preimage()?)
            .to_bytes(),
    );
    Ok(descriptor)
}

fn witness_policy_descriptor(
    share_index: u8,
    signer: &TestSigner,
) -> AnyResult<WitnessPolicyDescriptor> {
    let signing_public_key = signer.descriptor.verification_public_key.clone();
    let mut descriptor = WitnessPolicyDescriptor {
        schema: 1,
        witness_id: signer.principal_id(),
        share_index,
        signing_public_key: signing_public_key.clone(),
        signing_key_fingerprint: signing_fingerprint(3, signer.principal_id(), &signing_public_key),
        signing_key_epoch: 1,
        contribution_public_key: signer.descriptor.recipient_public_key.clone(),
        contribution_key_fingerprint: recipient_public_key_fingerprint(
            &signer.descriptor.recipient_public_key,
        ),
        contribution_key_epoch: 1,
        status: DescriptorStatus::Active,
        created_at_ms: 1_700_000_000_000,
        self_signature: Signature64::new([0; 64]),
    };
    descriptor.self_signature = Signature64::new(
        signer
            .key
            .sign(&descriptor.self_signature_preimage()?)
            .to_bytes(),
    );
    Ok(descriptor)
}

fn signing_fingerprint(
    role: u8,
    principal_id: PrincipalId,
    public_key: &VerificationPublicKey32,
) -> Digest32 {
    let mut preimage = b"jury-witness-v1/signing-key/fingerprint\0\0\x01".to_vec();
    preimage.push(role);
    preimage.extend_from_slice(principal_id.as_bytes());
    preimage.extend_from_slice(&1_u64.to_be_bytes());
    preimage.extend_from_slice(public_key.as_bytes());
    FixedBytes::new(Sha256::digest(preimage).into())
}

#[allow(clippy::too_many_arguments)]
fn witnessed_state(
    vault_id: VaultId,
    genesis_fingerprint: Digest32,
    item_id: ItemId,
    sequence: u64,
    policy_id: WitnessPolicyId,
    policy_digest: Digest32,
    witnesses: &[TestSigner; 3],
    share_indexes: [u8; 3],
    mode: ItemAccessMode,
    marker_base: u8,
) -> AnyResult<WitnessedStateV1> {
    let mut slots = Vec::new();
    for (role_index, content_role) in [ContentRole::Descriptor, ContentRole::Body]
        .into_iter()
        .enumerate()
    {
        let marker = u8::try_from(role_index)?
            .saturating_mul(8)
            .saturating_add(marker_base);
        let slot_id = SlotId::from_bytes([marker; 32])?;
        let seal_id = RevisionSealId::from_bytes([marker.saturating_add(2); 32])?;
        let mut capsules = Vec::new();
        for (witness, share_index) in witnesses.iter().zip(share_indexes) {
            let mut capsule = WitnessShareCapsuleV1 {
                capsule_schema: 1,
                protocol: 1,
                construction: 1,
                vault_id,
                genesis_fingerprint: genesis_fingerprint.clone(),
                item_id,
                key_epoch: 1,
                item_access_mode: mode,
                slot_id,
                content_role,
                revision: 1,
                revision_seal_id: seal_id,
                vault_policy_sequence: sequence,
                witness_policy_id: policy_id,
                witness_policy_revision: 1,
                witness_policy_digest: policy_digest.clone(),
                threshold: 2,
                member_count: 3,
                witness_id: witness.principal_id(),
                contribution_key_fingerprint: recipient_public_key_fingerprint(
                    &witness.descriptor.recipient_public_key,
                ),
                share_index,
                context_digest: FixedBytes::new([0; 32]),
                share_commitment: FixedBytes::new([share_index; 32]),
                encapsulation: Encapsulation1120::new([marker.saturating_add(share_index); 1120]),
                ciphertext: ShareCiphertext49::new([marker.wrapping_add(share_index); 49]),
            };
            capsule.context_digest = capsule.recomputed_context_digest();
            capsules.push(capsule);
        }
        let mut slot = WitnessedSlotV1 {
            slot_schema: 1,
            slot_algorithm: 2,
            suite: 1,
            protocol: 1,
            construction: 1,
            vault_id,
            genesis_fingerprint: genesis_fingerprint.clone(),
            item_id,
            key_epoch: 1,
            item_access_mode: mode,
            slot_id,
            content_role,
            revision: 1,
            revision_seal_id: seal_id,
            vault_policy_sequence: sequence,
            witness_policy_id: policy_id,
            witness_policy_revision: 1,
            witness_policy_digest: policy_digest.clone(),
            threshold: 2,
            member_count: 3,
            capsules,
            capsule_set_digest: FixedBytes::new([0; 32]),
        };
        slot.capsule_set_digest = slot.recomputed_capsule_set_digest()?;
        slots.push(slot);
    }
    let mut state = WitnessedStateV1 {
        slots,
        digest: FixedBytes::new([0; 32]),
    };
    state.digest = state.recomputed_digest()?;
    Ok(state)
}

fn descriptor_metadata(epoch: u64, revision: u64, marker: u8) -> AnyResult<DescriptorMetadataV1> {
    Ok(DescriptorMetadataV1 {
        revision,
        revision_seal_id: RevisionSealId::from_bytes([marker; 32])?,
        nonce: Nonce12::new([marker.wrapping_add(1); 12]),
        ciphertext_length: 272,
        ciphertext_digest: Digest32::new([marker.wrapping_add(2); 32]),
        plaintext_schema: 1,
        key_epoch: epoch,
    })
}

#[allow(clippy::too_many_arguments)]
fn direct_slots(
    vault_id: jury_protocol::vault_v1::VaultId,
    item_id: ItemId,
    principal_id: PrincipalId,
    epoch: u64,
    sequence: u64,
    role: AccessRole,
    mode: ItemAccessMode,
    recipient_fingerprint: Digest32,
) -> AnyResult<Vec<DirectSlotV1>> {
    [ContentRole::Descriptor, ContentRole::Body]
        .into_iter()
        .enumerate()
        .map(|(index, content_role)| {
            let role_marker = u8::try_from(index)?.wrapping_add(0x70);
            let encapsulation_marker =
                principal_id.as_bytes()[0].wrapping_add(u8::try_from(index)?);
            Ok(DirectSlotV1 {
                slot_schema: 1,
                slot_algorithm: 1,
                suite: 1,
                kem: 0x647a,
                kdf: 1,
                aead: 3,
                vault_id,
                item_id,
                key_epoch: epoch,
                content_role,
                revision: 1,
                revision_seal_id: RevisionSealId::from_bytes([role_marker; 32])?,
                recipient_principal_id: principal_id,
                policy_sequence: sequence,
                recipient_public_key_fingerprint: recipient_fingerprint.clone(),
                access_role: role,
                item_access_mode: mode,
                encapsulation: Encapsulation1120::new([encapsulation_marker; 1120]),
                ciphertext: DirectCiphertext48::new([encapsulation_marker; 48]),
            })
        })
        .collect()
}

fn sort_direct_slots(slots: &mut [DirectSlotV1]) {
    slots.sort_by(|left, right| {
        (
            left.content_role,
            left.recipient_principal_id,
            left.canonical_bytes(),
        )
            .cmp(&(
                right.content_role,
                right.recipient_principal_id,
                right.canonical_bytes(),
            ))
    });
}
