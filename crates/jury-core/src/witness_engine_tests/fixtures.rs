use std::collections::{BTreeMap, BTreeSet};

use jury_protected::{EntropyError, ProtectedMemory, ProtectionPolicy, RandomSource};
use jury_protocol::{
    vault_v1::{
        AccessRole, ApprovalId, CancellationId, ContentRole, DescriptorMetadataV1, Digest32,
        Encapsulation1120, ItemAccessMode, ItemId, ItemKind, Nonce12, PrincipalDescriptorV1,
        PrincipalId, PrincipalKind, ReceiptId, RecipientPublicKey1216, RecoveryId, RequestId,
        RevisionSealId, RotationId, ShareCiphertext49, Signature64, SlotId, VaultId,
        WitnessPolicyId, WitnessShareCapsuleV1, WitnessedSlotV1, WitnessedStateV1,
        recipient_public_key_fingerprint, witnessed_slot_set_digest,
    },
    witness_v1::{
        ActionManifestV1, ApprovalDecisionKindV1, ApprovalDecisionV1, ApprovalModeV1,
        ApprovalTargetEntryV1, ApprovalTargetV1, CancellerRoleV1, IntendedWitnessV1,
        OperationContextV1, OutputSinkV1, PlatformAssuranceV1, PolicyMaterialBytes,
        PublicReceiptScopeV1, ReceiptAcknowledgementV1, ReceiptCompletionV1, ReceiptOutcomeV1,
        RegistrationBytes, RequestBytes, RequestCancellationV1, StdinModeV1,
        VaultPolicyCheckpointV1, WitnessDecisionKindV1, WitnessDescriptorBytes, WitnessOperationV1,
        WitnessPolicyRotationV1, WitnessReasonV1, WitnessReceiptMaterialV1, WitnessReceiptV1,
        WitnessRecoveryV1, WitnessRotationItemV1, WitnessRotationReasonV1, signing_key_fingerprint,
        witness_registration_digest,
    },
};
use sha2::{Digest as _, Sha256};

use super::*;
use crate::{
    crypto,
    identity::{
        ApproverIdentity, UnlockedIdentity, VaultPrincipalIdentity, WitnessIdentity,
        unlocked_identity_for_test,
    },
    policy::{
        ApprovalMode, ApproverPolicyDescriptor, DescriptorStatus, ItemPolicyState, OperationRule,
        PlatformAssurance, PolicyState, PrincipalPolicyState, WitnessOperation, WitnessPolicy,
        WitnessPolicyDescriptor,
    },
    witness_operations::{
        CheckpointPropagationPhase, RotationVerificationErrorKind, rotation_reason,
        verify_checkpoint_propagation, verify_witness_policy_rotation, verify_witness_recovery,
    },
    witness_receipt::verify_witness_receipt_with_policy,
    witness_validation::{RequestPolicyError, validate_request_policy},
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const NOW_MS: u64 = 1_800_000_000_000;

struct TestRandom(u64);

impl TestRandom {
    const fn new(seed: u64) -> Self {
        Self(seed)
    }
}

impl RandomSource for TestRandom {
    fn fill(&mut self, destination: &mut [u8]) -> Result<(), EntropyError> {
        for byte in destination {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            *byte = self.0 as u8;
        }
        Ok(())
    }
}

struct FixedClock {
    wall_ms: u64,
    monotonic_ms: u64,
}

impl WitnessClock for FixedClock {
    fn wall_time_ms(&self) -> u64 {
        self.wall_ms
    }

    fn monotonic_time_ms(&self) -> u64 {
        self.monotonic_ms
    }
}

struct MemoryStore {
    state: PersistedWitnessState,
    fail_before_commit_once: bool,
    fail_after_commit_once: bool,
    fail_mark_once: bool,
}

impl WitnessStateStore for MemoryStore {
    fn load(&mut self) -> Result<PersistedWitnessState, WitnessStoreError> {
        Ok(self.state.clone())
    }

    fn commit(
        &mut self,
        expected_generation: u64,
        replacement: PersistedWitnessState,
    ) -> Result<(), WitnessStoreError> {
        if self.fail_before_commit_once {
            self.fail_before_commit_once = false;
            return Err(WitnessStoreError::unavailable());
        }
        if self.state.logical.state_generation != expected_generation
            || self.state.pending_anchor.is_some()
            || replacement.logical.state_generation != expected_generation + 1
            || replacement.pending_anchor.is_none()
        {
            return Err(WitnessStoreError::unavailable());
        }
        self.state = replacement;
        if self.fail_after_commit_once {
            self.fail_after_commit_once = false;
            return Err(WitnessStoreError::unavailable());
        }
        Ok(())
    }

    fn mark_anchor_published(
        &mut self,
        candidate_digest: &Digest32,
    ) -> Result<(), WitnessStoreError> {
        if self.fail_mark_once {
            self.fail_mark_once = false;
            return Err(WitnessStoreError::unavailable());
        }
        let candidate = self
            .state
            .pending_anchor
            .take()
            .ok_or_else(WitnessStoreError::unavailable)?;
        if candidate
            .digest()
            .map_err(|_| WitnessStoreError::unavailable())?
            != *candidate_digest
        {
            return Err(WitnessStoreError::unavailable());
        }
        self.state.published_anchor = Some(candidate);
        Ok(())
    }
}

#[derive(Default)]
struct MemoryAnchor {
    value: Option<WitnessStateAnchorV1>,
    publishes: usize,
    fail_readback_once: bool,
    pending_read_failure: bool,
    reject_candidate_capacity: bool,
}

impl ExternalWitnessAnchor for MemoryAnchor {
    fn ensure_publishable(
        &mut self,
        _candidate: &WitnessStateAnchorV1,
    ) -> Result<(), WitnessAnchorError> {
        if self.reject_candidate_capacity {
            Err(WitnessAnchorError::capacity_exhausted())
        } else {
            Ok(())
        }
    }

    fn read(&mut self) -> Result<Option<WitnessStateAnchorV1>, WitnessAnchorError> {
        if self.pending_read_failure {
            self.pending_read_failure = false;
            return Err(WitnessAnchorError::unavailable());
        }
        Ok(self.value.clone())
    }

    fn compare_and_swap(
        &mut self,
        expected: Option<&WitnessStateAnchorV1>,
        candidate: &WitnessStateAnchorV1,
    ) -> Result<AnchorCompareAndSwap, WitnessAnchorError> {
        if self.value.as_ref() != expected {
            return Ok(AnchorCompareAndSwap::Conflict);
        }
        self.value = Some(candidate.clone());
        self.publishes += 1;
        if self.fail_readback_once {
            self.fail_readback_once = false;
            self.pending_read_failure = true;
        }
        Ok(AnchorCompareAndSwap::Published)
    }
}

struct Actors {
    owner: VaultPrincipalIdentity,
    approvers: [ApproverIdentity; 2],
    witnesses: [WitnessIdentity; 2],
}

struct Fixture {
    actors: Actors,
    policy: PolicyState,
    checkpoint: VaultPolicyCheckpointV1,
    request: jury_protocol::witness_v1::WitnessRequestV1,
    manifest: ActionManifestV1,
    approvals: [ApprovalDecisionV1; 2],
}

fn descriptor(identity: &UnlockedIdentity) -> TestResult<PrincipalDescriptorV1> {
    Ok(match identity {
        UnlockedIdentity::VaultPrincipal(identity) => identity.public_descriptor()?,
        UnlockedIdentity::Approver(identity) => identity.public_descriptor()?,
        UnlockedIdentity::Witness(identity) => identity.public_descriptor()?,
    })
}

fn make_identity(
    id_byte: u8,
    kind: PrincipalKind,
    random: &mut TestRandom,
) -> TestResult<UnlockedIdentity> {
    Ok(unlocked_identity_for_test(
        PrincipalId::from_bytes([id_byte; 32])?,
        kind,
        random,
    )?)
}

fn protected(bytes: &[u8]) -> TestResult<ProtectedMemory> {
    Ok(ProtectedMemory::initialize(
        bytes.len(),
        ProtectionPolicy::Strict,
        |destination| {
            destination.copy_from_slice(bytes);
            Ok::<usize, ()>(bytes.len())
        },
    )?)
}

fn approver_policy_descriptor(identity: &ApproverIdentity) -> TestResult<ApproverPolicyDescriptor> {
    let public = identity.public_descriptor()?;
    let mut descriptor = ApproverPolicyDescriptor {
        schema: 1,
        approver_id: public.principal_id,
        signing_public_key: public.verification_public_key.clone(),
        signing_key_fingerprint: signing_key_fingerprint(
            2,
            &public.principal_id,
            1,
            &public.verification_public_key,
        ),
        signing_key_epoch: 1,
        status: DescriptorStatus::Active,
        approval_mode: ApprovalMode::Human,
        allowed_operations: vec![WitnessOperation::ReadStdout],
        created_at_ms: NOW_MS - 10_000,
        self_signature: Signature64::new([0; 64]),
    };
    descriptor.self_signature =
        identity.sign_validated_approval(&descriptor.self_signature_preimage()?)?;
    Ok(descriptor)
}

fn witness_policy_descriptor(
    identity: &WitnessIdentity,
    share_index: u8,
) -> TestResult<WitnessPolicyDescriptor> {
    let public = identity.public_descriptor()?;
    let mut descriptor = WitnessPolicyDescriptor {
        schema: 1,
        witness_id: public.principal_id,
        share_index,
        signing_public_key: public.verification_public_key.clone(),
        signing_key_fingerprint: signing_key_fingerprint(
            3,
            &public.principal_id,
            1,
            &public.verification_public_key,
        ),
        signing_key_epoch: 1,
        contribution_public_key: public.recipient_public_key.clone(),
        contribution_key_fingerprint: recipient_public_key_fingerprint(
            &public.recipient_public_key,
        ),
        contribution_key_epoch: 1,
        status: DescriptorStatus::Active,
        created_at_ms: NOW_MS - 10_000,
        self_signature: Signature64::new([0; 64]),
    };
    descriptor.self_signature =
        identity.sign_validated_decision(&descriptor.self_signature_preimage()?)?;
    Ok(descriptor)
}

struct CapsuleScope<'a> {
    policy_digest: &'a Digest32,
    vault_policy_sequence: u64,
    witness_policy_revision: u64,
    key_epoch: u64,
    revision: u64,
    revision_seal_id: RevisionSealId,
}

fn witness_capsule(
    descriptor: &WitnessPolicyDescriptor,
    scope: CapsuleScope<'_>,
    random: &mut TestRandom,
) -> TestResult<WitnessShareCapsuleV1> {
    let mut capsule = WitnessShareCapsuleV1 {
        capsule_schema: 1,
        protocol: 1,
        construction: 1,
        vault_id: VaultId::from_bytes([0x01; 32])?,
        genesis_fingerprint: Digest32::new([0x02; 32]),
        item_id: ItemId::from_bytes([0x03; 32])?,
        key_epoch: scope.key_epoch,
        item_access_mode: ItemAccessMode::WitnessedOnly,
        slot_id: SlotId::from_bytes([0x05; 32])?,
        content_role: ContentRole::Body,
        revision: scope.revision,
        revision_seal_id: scope.revision_seal_id,
        vault_policy_sequence: scope.vault_policy_sequence,
        witness_policy_id: WitnessPolicyId::from_bytes([0x0a; 32])?,
        witness_policy_revision: scope.witness_policy_revision,
        witness_policy_digest: scope.policy_digest.clone(),
        threshold: 2,
        member_count: 2,
        witness_id: descriptor.witness_id,
        contribution_key_fingerprint: descriptor.contribution_key_fingerprint.clone(),
        share_index: descriptor.share_index,
        context_digest: Digest32::new([0; 32]),
        share_commitment: Digest32::new([0; 32]),
        encapsulation: Encapsulation1120::new([0; 1_120]),
        ciphertext: ShareCiphertext49::new([0; 49]),
    };
    capsule.context_digest = capsule.recomputed_context_digest();
    let mut share = [0_u8; 33];
    share[0] = descriptor.share_index;
    share[1..].fill(0x90 + descriptor.share_index);
    let mut commitment = b"jury-witness-v1/share/commitment\0\0\x01".to_vec();
    commitment.extend_from_slice(capsule.context_digest.as_bytes());
    commitment.extend_from_slice(&share);
    capsule.share_commitment = Digest32::new(Sha256::digest(commitment).into());
    let share = protected(&share)?;
    let (encapsulation, ciphertext) = crypto::seal_hpke(
        &descriptor.contribution_public_key,
        &share,
        &capsule.info_preimage(),
        &capsule.aad_preimage(),
        random,
    )?;
    capsule.encapsulation = encapsulation;
    capsule.ciphertext = ShareCiphertext49::from_slice(&ciphertext)?;
    Ok(capsule)
}

struct FixturePrincipals {
    actors: Actors,
    owner_descriptor: PrincipalDescriptorV1,
    approver_descriptors: [PrincipalDescriptorV1; 2],
    witness_descriptors: [PrincipalDescriptorV1; 2],
    approver_policy_descriptors: [ApproverPolicyDescriptor; 2],
    witness_policy_descriptors: [WitnessPolicyDescriptor; 2],
}

fn fixture_principals() -> TestResult<FixturePrincipals> {
    let mut identity_random = TestRandom::new(0x1234_5678_9abc_def0);
    let owner = make_identity(0x11, PrincipalKind::Human, &mut identity_random)?;
    let approver_1 = make_identity(0x21, PrincipalKind::Approver, &mut identity_random)?;
    let approver_2 = make_identity(0x22, PrincipalKind::Approver, &mut identity_random)?;
    let witness_1 = make_identity(0x31, PrincipalKind::Witness, &mut identity_random)?;
    let witness_2 = make_identity(0x32, PrincipalKind::Witness, &mut identity_random)?;
    let owner_descriptor = descriptor(&owner)?;
    let approver_descriptors = [descriptor(&approver_1)?, descriptor(&approver_2)?];
    let witness_descriptors = [descriptor(&witness_1)?, descriptor(&witness_2)?];
    let UnlockedIdentity::VaultPrincipal(owner) = owner else {
        return Err("owner role mismatch".into());
    };
    let UnlockedIdentity::Approver(approver_1) = approver_1 else {
        return Err("approver role mismatch".into());
    };
    let UnlockedIdentity::Approver(approver_2) = approver_2 else {
        return Err("approver role mismatch".into());
    };
    let UnlockedIdentity::Witness(witness_1) = witness_1 else {
        return Err("witness role mismatch".into());
    };
    let UnlockedIdentity::Witness(witness_2) = witness_2 else {
        return Err("witness role mismatch".into());
    };
    let actors = Actors {
        owner,
        approvers: [approver_1, approver_2],
        witnesses: [witness_1, witness_2],
    };
    let approver_policy_descriptors = [
        approver_policy_descriptor(&actors.approvers[0])?,
        approver_policy_descriptor(&actors.approvers[1])?,
    ];
    let witness_policy_descriptors = [
        witness_policy_descriptor(&actors.witnesses[0], 1)?,
        witness_policy_descriptor(&actors.witnesses[1], 2)?,
    ];
    Ok(FixturePrincipals {
        actors,
        owner_descriptor,
        approver_descriptors,
        witness_descriptors,
        approver_policy_descriptors,
        witness_policy_descriptors,
    })
}

fn fixture_witness_policy(principals: &FixturePrincipals) -> TestResult<WitnessPolicy> {
    let policy = WitnessPolicy {
        schema: 1,
        witness_policy_id: WitnessPolicyId::from_bytes([0x0a; 32])?,
        revision: 1,
        predecessor_policy_digest: Digest32::new([0; 32]),
        vault_id: VaultId::from_bytes([0x01; 32])?,
        genesis_fingerprint: Digest32::new([0x02; 32]),
        vault_policy_sequence: 1,
        vault_policy_hash: Digest32::new([0x72; 32]),
        construction: 1,
        suite: 1,
        approver_descriptors: principals.approver_policy_descriptors.to_vec(),
        witness_descriptors: principals.witness_policy_descriptors.to_vec(),
        witness_threshold: 2,
        operation_rules: vec![OperationRule {
            operation: WitnessOperation::ReadStdout,
            eligible_approver_ids: principals
                .approver_policy_descriptors
                .iter()
                .map(|descriptor| descriptor.approver_id)
                .collect(),
            approval_threshold: 2,
            allowed_request_lifetime_ms: 300_000,
            max_timeout_ms: 30_000,
            max_output_bytes: 4_096,
            max_target_count: 1,
            required_platform_assurance: PlatformAssurance::NormalizedPathOnly,
            automatic_read_targets: Vec::new(),
        }],
        review_label_set_digest: Digest32::new([0x73; 32]),
        direct_fallback: false,
    };
    policy.validate()?;
    Ok(policy)
}

fn fixture_witnessed_state(
    descriptors: &[WitnessPolicyDescriptor; 2],
    witness_policy_digest: &Digest32,
) -> TestResult<WitnessedStateV1> {
    let mut capsule_random = TestRandom::new(0x2233_4455_6677_8899);
    let capsules = descriptors
        .iter()
        .map(|descriptor| {
            witness_capsule(
                descriptor,
                CapsuleScope {
                    policy_digest: witness_policy_digest,
                    vault_policy_sequence: 1,
                    witness_policy_revision: 1,
                    key_epoch: 1,
                    revision: 1,
                    revision_seal_id: RevisionSealId::from_bytes([0x06; 32])?,
                },
                &mut capsule_random,
            )
        })
        .collect::<TestResult<Vec<_>>>()?;
    let mut slot = WitnessedSlotV1 {
        slot_schema: 1,
        slot_algorithm: 2,
        suite: 1,
        protocol: 1,
        construction: 1,
        vault_id: VaultId::from_bytes([0x01; 32])?,
        genesis_fingerprint: Digest32::new([0x02; 32]),
        item_id: ItemId::from_bytes([0x03; 32])?,
        key_epoch: 1,
        item_access_mode: ItemAccessMode::WitnessedOnly,
        slot_id: SlotId::from_bytes([0x05; 32])?,
        content_role: ContentRole::Body,
        revision: 1,
        revision_seal_id: RevisionSealId::from_bytes([0x06; 32])?,
        vault_policy_sequence: 1,
        witness_policy_id: WitnessPolicyId::from_bytes([0x0a; 32])?,
        witness_policy_revision: 1,
        witness_policy_digest: witness_policy_digest.clone(),
        threshold: 2,
        member_count: 2,
        capsules,
        capsule_set_digest: Digest32::new([0; 32]),
    };
    slot.capsule_set_digest = slot.recomputed_capsule_set_digest()?;
    Ok(WitnessedStateV1 {
        slots: vec![slot.clone()],
        digest: witnessed_slot_set_digest(std::slice::from_ref(&slot))?,
    })
}
