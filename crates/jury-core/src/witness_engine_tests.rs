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

fn fixture_policy(
    fixture_principals: &FixturePrincipals,
    witness_policy: &WitnessPolicy,
    witness_policy_digest: &Digest32,
) -> TestResult<PolicyState> {
    let witnessed_state = fixture_witnessed_state(
        &fixture_principals.witness_policy_descriptors,
        witness_policy_digest,
    )?;
    let principals = std::iter::once(fixture_principals.owner_descriptor.clone())
        .chain(fixture_principals.approver_descriptors.iter().cloned())
        .chain(fixture_principals.witness_descriptors.iter().cloned())
        .map(|descriptor| {
            (
                descriptor.principal_id,
                PrincipalPolicyState {
                    descriptor,
                    display_label: "ExamplePrincipal".to_owned(),
                },
            )
        })
        .collect::<BTreeMap<_, _>>();
    let principal_ids = principals.keys().copied().collect::<BTreeSet<_>>();
    let recipient_keys = principals
        .values()
        .map(|principal| principal.descriptor.recipient_public_key.clone())
        .collect::<BTreeSet<RecipientPublicKey1216>>();
    let verification_keys = principals
        .values()
        .map(|principal| principal.descriptor.verification_public_key.clone())
        .collect();
    let item_id = ItemId::from_bytes([0x03; 32])?;
    let items = [(
        item_id,
        ItemPolicyState {
            item_kind: ItemKind::Canonical,
            key_epoch: 1,
            descriptor: DescriptorMetadataV1 {
                revision: 1,
                revision_seal_id: RevisionSealId::from_bytes([0x40; 32])?,
                nonce: Nonce12::new([0x41; 12]),
                ciphertext_length: 1,
                ciphertext_digest: Digest32::new([0x42; 32]),
                plaintext_schema: 1,
                key_epoch: 1,
            },
            current_item_revision_hash: Digest32::new([0x43; 32]),
            grants: BTreeMap::new(),
            direct_slots: Vec::new(),
            witnessed_state: Some(witnessed_state),
        },
    )]
    .into_iter()
    .collect();
    Ok(PolicyState {
        suite: 1,
        vault_id: VaultId::from_bytes([0x01; 32])?,
        genesis_fingerprint: Digest32::new([0x02; 32]),
        sequence: 1,
        terminal_revision_hash: Digest32::new([0x72; 32]),
        revision_hashes: vec![Digest32::new([0x02; 32]), Digest32::new([0x72; 32])],
        principals: principals.clone(),
        historical_principal_descriptors: principals
            .iter()
            .map(|(id, principal)| (*id, principal.descriptor.clone()))
            .collect(),
        historical_principal_ids: principal_ids,
        historical_recipient_keys: recipient_keys,
        historical_verification_keys: verification_keys,
        owners: [fixture_principals.owner_descriptor.principal_id]
            .into_iter()
            .collect(),
        items,
        historical_item_ids: [item_id].into_iter().collect(),
        tombstones: BTreeMap::new(),
        witness_policies: [(witness_policy_digest.clone(), witness_policy.clone())]
            .into_iter()
            .collect(),
    })
}

fn fixture_checkpoint(
    principals: &FixturePrincipals,
    witness_policy: &WitnessPolicy,
    witness_policy_digest: &Digest32,
) -> TestResult<VaultPolicyCheckpointV1> {
    let (approver_set_digest, witness_set_digest) =
        witness_policy.active_descriptor_set_digests()?;
    let mut checkpoint = VaultPolicyCheckpointV1 {
        schema: 1,
        vault_id: VaultId::from_bytes([0x01; 32])?,
        genesis_fingerprint: Digest32::new([0x02; 32]),
        vault_policy_sequence: 1,
        vault_policy_hash: Digest32::new([0x72; 32]),
        witness_policy_id: WitnessPolicyId::from_bytes([0x0a; 32])?,
        witness_policy_revision: 1,
        witness_policy_digest: witness_policy_digest.clone(),
        witness_set_digest,
        approver_set_digest,
        review_label_set_digest: witness_policy.review_label_set_digest.clone(),
        predecessor_checkpoint_digest: Digest32::new([0; 32]),
        issued_at_ms: NOW_MS - 5_000,
        issuer_owner_id: principals.owner_descriptor.principal_id,
        issuer_key_fingerprint: signing_key_fingerprint(
            1,
            &principals.owner_descriptor.principal_id,
            1,
            &principals.owner_descriptor.verification_public_key,
        ),
        issuer_key_epoch: 1,
        signature: Signature64::new([0; 64]),
    };
    checkpoint.signature = principals
        .actors
        .owner
        .sign_validated_statement(&checkpoint.signature_preimage()?)?;
    Ok(checkpoint)
}

fn fixture_manifest(
    owner_descriptor: &PrincipalDescriptorV1,
    witness_policy_digest: &Digest32,
) -> TestResult<(ActionManifestV1, Digest32)> {
    let presentation_digest = Digest32::new([0x81; 32]);
    let approval_target = ApprovalTargetV1 {
        entries: vec![ApprovalTargetEntryV1 {
            item_id: ItemId::from_bytes([0x03; 32])?,
            field_id: None,
            presentation_commitment: Digest32::new([0x82; 32]),
        }],
        presentation_digest: presentation_digest.clone(),
    };
    let approval_target_digest = approval_target.digest()?;
    let manifest = ActionManifestV1 {
        schema: 1,
        request_id: RequestId::from_bytes([0x07; 32])?,
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
        vault_policy_hash: Digest32::new([0x72; 32]),
        witness_policy_id: WitnessPolicyId::from_bytes([0x0a; 32])?,
        witness_policy_revision: 1,
        witness_policy_digest: witness_policy_digest.clone(),
        requester_principal_id: owner_descriptor.principal_id,
        requested_access_role: AccessRole::Owner,
        operation: WitnessOperationV1::ReadStdout,
        operation_context: OperationContextV1::ReadStdout,
        approval_target,
        approval_target_digest: approval_target_digest.clone(),
        executable_identity: None,
        arguments: Vec::new(),
        working_directory_commitment: None,
        environment_injections: Vec::new(),
        stdin_target: None,
        stdin_mode: StdinModeV1::None,
        output_sink: OutputSinkV1::Stdout,
        output_sink_commitment: None,
        platform_assurance: PlatformAssuranceV1::NormalizedPathOnly,
        timeout_ms: 30_000,
        output_limit_bytes: 4_096,
        issued_at_ms: NOW_MS - 1_000,
        not_before_ms: None,
        expires_at_ms: NOW_MS + 299_000,
        presentation_digest: presentation_digest.clone(),
    };
    Ok((manifest, presentation_digest))
}

fn fixture_request(
    principals: &FixturePrincipals,
    checkpoint: &VaultPolicyCheckpointV1,
    manifest: &ActionManifestV1,
    witness_policy_digest: Digest32,
) -> TestResult<jury_protocol::witness_v1::WitnessRequestV1> {
    let intended_witness_set = principals
        .witness_policy_descriptors
        .iter()
        .map(|descriptor| IntendedWitnessV1 {
            witness_id: descriptor.witness_id,
            share_index: descriptor.share_index,
            signing_key_fingerprint: descriptor.signing_key_fingerprint.clone(),
            contribution_key_fingerprint: descriptor.contribution_key_fingerprint.clone(),
        })
        .collect();
    let approval_target_digest = manifest.approval_target_digest.clone();
    let mut request = jury_protocol::witness_v1::WitnessRequestV1 {
        schema: 1,
        protocol_version: 1,
        construction: 1,
        request_id: RequestId::from_bytes([0x07; 32])?,
        client_nonce: RequestId::from_bytes([0x75; 32])?,
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
        vault_policy_hash: Digest32::new([0x72; 32]),
        policy_checkpoint_digest: checkpoint.digest()?,
        witness_policy_id: WitnessPolicyId::from_bytes([0x0a; 32])?,
        witness_policy_revision: 1,
        witness_policy_digest,
        requester_principal_id: principals.owner_descriptor.principal_id,
        requester_signing_key_fingerprint: signing_key_fingerprint(
            1,
            &principals.owner_descriptor.principal_id,
            1,
            &principals.owner_descriptor.verification_public_key,
        ),
        requester_signing_key_epoch: 1,
        requested_access_role: AccessRole::Owner,
        operation: WitnessOperationV1::ReadStdout,
        approval_target_digest,
        action_manifest_digest: manifest.digest()?,
        workload_digest: manifest.workload_digest()?,
        issued_at_ms: manifest.issued_at_ms,
        not_before_ms: None,
        expires_at_ms: manifest.expires_at_ms,
        request_session_public_key: principals.owner_descriptor.recipient_public_key.clone(),
        request_session_key_fingerprint: recipient_public_key_fingerprint(
            &principals.owner_descriptor.recipient_public_key,
        ),
        intended_witness_set,
        client_signature: Signature64::new([0; 64]),
    };
    request.client_signature = principals
        .actors
        .owner
        .sign_validated_statement(&request.signature_preimage()?)?;
    Ok(request)
}

fn fixture_approvals(
    principals: &FixturePrincipals,
    request: &jury_protocol::witness_v1::WitnessRequestV1,
    manifest: &ActionManifestV1,
    presentation_digest: &Digest32,
) -> TestResult<[ApprovalDecisionV1; 2]> {
    let request_digest = request.digest()?;
    let intended_witness_set_digest = request.intended_witness_set_digest()?;
    let mut approvals = Vec::new();
    for (index, descriptor) in principals.approver_policy_descriptors.iter().enumerate() {
        let mut approval = ApprovalDecisionV1 {
            schema: 1,
            approval_id: ApprovalId::from_bytes([0x90 + index as u8; 32])?,
            request_id: request.request_id,
            request_digest: request_digest.clone(),
            action_manifest_digest: manifest.digest()?,
            presentation_digest: presentation_digest.clone(),
            witness_policy_id: request.witness_policy_id,
            witness_policy_revision: request.witness_policy_revision,
            witness_policy_digest: request.witness_policy_digest.clone(),
            approver_id: descriptor.approver_id,
            approver_key_fingerprint: descriptor.signing_key_fingerprint.clone(),
            approver_key_epoch: 1,
            approval_mode: ApprovalModeV1::Human,
            decision: ApprovalDecisionKindV1::Approve,
            reason: WitnessReasonV1::None,
            issued_at_ms: NOW_MS,
            not_before_ms: None,
            expires_at_ms: request.expires_at_ms,
            nonce: ApprovalId::from_bytes([0xa0 + index as u8; 32])?,
            intended_witness_set_digest: intended_witness_set_digest.clone(),
            signature: Signature64::new([0; 64]),
        };
        approval.signature = principals.actors.approvers[index]
            .sign_validated_approval(&approval.signature_preimage()?)?;
        approvals.push(approval);
    }
    approvals
        .try_into()
        .map_err(|_| "approval fixture count changed".into())
}

fn fixture() -> TestResult<Fixture> {
    let principals = fixture_principals()?;
    let witness_policy = fixture_witness_policy(&principals)?;
    let witness_policy_digest = witness_policy.digest()?;
    let policy = fixture_policy(&principals, &witness_policy, &witness_policy_digest)?;
    let checkpoint = fixture_checkpoint(&principals, &witness_policy, &witness_policy_digest)?;
    let (manifest, presentation_digest) =
        fixture_manifest(&principals.owner_descriptor, &witness_policy_digest)?;
    let request = fixture_request(&principals, &checkpoint, &manifest, witness_policy_digest)?;
    let approvals = fixture_approvals(&principals, &request, &manifest, &presentation_digest)?;
    Ok(Fixture {
        actors: principals.actors,
        policy,
        checkpoint,
        request,
        manifest,
        approvals,
    })
}

fn empty_store(fixture: &Fixture) -> MemoryStore {
    MemoryStore {
        state: PersistedWitnessState::empty(fixture.actors.witnesses[0].principal_id()),
        fail_before_commit_once: false,
        fail_after_commit_once: false,
        fail_mark_once: false,
    }
}

fn register_fixture(
    fixture: &Fixture,
    store: &mut MemoryStore,
    anchor: &mut MemoryAnchor,
    clock: &FixedClock,
    random: &mut TestRandom,
) -> TestResult {
    let mut engine = WitnessEngine::new(&fixture.actors.witnesses[0], store, anchor, clock, random);
    engine.register_vault(
        &fixture.policy,
        RegistrationBytes::new(vec![1, 2, 3])?,
        fixture.checkpoint.clone(),
        PolicyMaterialBytes::new(vec![4, 5, 6])?,
    )?;
    Ok(())
}

fn cancellation(fixture: &Fixture) -> TestResult<RequestCancellationV1> {
    let mut cancellation = RequestCancellationV1 {
        schema: 1,
        cancellation_id: CancellationId::from_bytes([0xc1; 32])?,
        request_signature_preimage: RequestBytes::new(fixture.request.signature_preimage()?)?,
        client_signature: fixture.request.client_signature.clone(),
        request_id: fixture.request.request_id,
        request_digest: fixture.request.digest()?,
        canceller_id: fixture.request.requester_principal_id,
        canceller_key_fingerprint: fixture.request.requester_signing_key_fingerprint.clone(),
        canceller_key_epoch: 1,
        canceller_role: CancellerRoleV1::OriginalRequester,
        issued_at_ms: NOW_MS,
        reason: WitnessReasonV1::Cancelled,
        nonce: CancellationId::from_bytes([0xc2; 32])?,
        signature: Signature64::new([0; 64]),
    };
    cancellation.signature = fixture
        .actors
        .owner
        .sign_validated_statement(&cancellation.signature_preimage()?)?;
    Ok(cancellation)
}

fn denying_approval(fixture: &Fixture, index: usize) -> TestResult<ApprovalDecisionV1> {
    let mut denial = fixture.approvals[index].clone();
    denial.decision = ApprovalDecisionKindV1::Deny;
    denial.reason = WitnessReasonV1::PolicyDenied;
    denial.signature =
        fixture.actors.approvers[index].sign_validated_approval(&denial.signature_preimage()?)?;
    Ok(denial)
}

fn resign_approval(
    fixture: &Fixture,
    index: usize,
    approval: &mut ApprovalDecisionV1,
) -> TestResult {
    approval.signature =
        fixture.actors.approvers[index].sign_validated_approval(&approval.signature_preimage()?)?;
    Ok(())
}

fn assert_approval_refused_without_state_change(
    fixture: &Fixture,
    approval: ApprovalDecisionV1,
    expected: WitnessReasonV1,
    seed: u64,
) -> TestResult {
    let mut store = empty_store(fixture);
    let mut anchor = MemoryAnchor::default();
    let clock = FixedClock {
        wall_ms: NOW_MS,
        monotonic_ms: seed,
    };
    let mut random = TestRandom::new(seed);
    register_fixture(fixture, &mut store, &mut anchor, &clock, &mut random)?;
    {
        let mut engine = WitnessEngine::new(
            &fixture.actors.witnesses[0],
            &mut store,
            &mut anchor,
            &clock,
            &mut random,
        );
        engine.reserve(&fixture.policy, fixture.request.clone(), &fixture.manifest)?;
    }
    let generation = store.state.logical.state_generation;
    let publish_count = anchor.publishes;
    {
        let mut engine = WitnessEngine::new(
            &fixture.actors.witnesses[0],
            &mut store,
            &mut anchor,
            &clock,
            &mut random,
        );
        assert_eq!(
            engine
                .decide(
                    &fixture.policy,
                    &fixture.request,
                    &fixture.manifest,
                    &[approval],
                )
                .map_err(WitnessEngineError::reason),
            Err(expected)
        );
    }
    assert_eq!(store.state.logical.state_generation, generation);
    assert_eq!(anchor.publishes, publish_count);
    assert!(
        store
            .state
            .logical
            .replay
            .values()
            .next()
            .is_some_and(|entry| {
                entry.state == ReplayStateV1::Reserved && entry.approvals.is_empty()
            })
    );
    Ok(())
}

fn signed_time_variant(
    fixture: &Fixture,
    issued_at_ms: u64,
    not_before_ms: Option<u64>,
    expires_at_ms: u64,
) -> TestResult<(
    jury_protocol::witness_v1::WitnessRequestV1,
    ActionManifestV1,
)> {
    let mut manifest = fixture.manifest.clone();
    manifest.issued_at_ms = issued_at_ms;
    manifest.not_before_ms = not_before_ms;
    manifest.expires_at_ms = expires_at_ms;
    let mut request = fixture.request.clone();
    request.issued_at_ms = issued_at_ms;
    request.not_before_ms = not_before_ms;
    request.expires_at_ms = expires_at_ms;
    request.action_manifest_digest = manifest.digest()?;
    request.workload_digest = manifest.workload_digest()?;
    request.client_signature = fixture
        .actors
        .owner
        .sign_validated_statement(&request.signature_preimage()?)?;
    Ok((request, manifest))
}

fn reserve_once(
    fixture: &Fixture,
    request: jury_protocol::witness_v1::WitnessRequestV1,
    manifest: &ActionManifestV1,
    wall_ms: u64,
    seed: u64,
) -> Result<WitnessProgress, WitnessEngineError> {
    let mut store = empty_store(fixture);
    let mut anchor = MemoryAnchor::default();
    let clock = FixedClock {
        wall_ms,
        monotonic_ms: seed,
    };
    let mut random = TestRandom::new(seed);
    register_fixture(fixture, &mut store, &mut anchor, &clock, &mut random)
        .map_err(|_| WitnessEngineError::store_unavailable())?;
    let mut engine = WitnessEngine::new(
        &fixture.actors.witnesses[0],
        &mut store,
        &mut anchor,
        &clock,
        &mut random,
    );
    engine.reserve(&fixture.policy, request, manifest)
}

fn descendant_policy_and_checkpoint(
    fixture: &Fixture,
) -> TestResult<(PolicyState, VaultPolicyCheckpointV1)> {
    descendant_policy_and_checkpoint_at_sequence(fixture, None, 2)
}

fn descendant_policy_and_checkpoint_with_replacement(
    fixture: &Fixture,
    replacement: Option<&WitnessIdentity>,
) -> TestResult<(PolicyState, VaultPolicyCheckpointV1)> {
    descendant_policy_and_checkpoint_at_sequence(fixture, replacement, 2)
}

fn descendant_policy_and_checkpoint_at_sequence(
    fixture: &Fixture,
    replacement: Option<&WitnessIdentity>,
    next_sequence: u64,
) -> TestResult<(PolicyState, VaultPolicyCheckpointV1)> {
    let prior_digest = fixture.request.witness_policy_digest.clone();
    let prior = fixture
        .policy
        .witness_policy(&prior_digest)
        .ok_or("missing prior witness policy")?;
    let mut next_witness_policy = prior.clone();
    next_witness_policy.revision = 2;
    next_witness_policy.predecessor_policy_digest = prior_digest;
    next_witness_policy.vault_policy_sequence = next_sequence;
    next_witness_policy.vault_policy_hash = Digest32::new([0x74; 32]);
    if let Some(replacement) = replacement {
        next_witness_policy.witness_descriptors[0] = witness_policy_descriptor(replacement, 1)?;
    }
    next_witness_policy.validate()?;
    let next_digest = next_witness_policy.digest()?;

    let mut capsule_random = TestRandom::new(0x8888_9999_aaaa_bbbb);
    let next_capsules = next_witness_policy
        .witness_descriptors
        .iter()
        .map(|descriptor| {
            witness_capsule(
                descriptor,
                CapsuleScope {
                    policy_digest: &next_digest,
                    vault_policy_sequence: next_sequence,
                    witness_policy_revision: 2,
                    key_epoch: 2,
                    revision: 2,
                    revision_seal_id: RevisionSealId::from_bytes([0x16; 32])?,
                },
                &mut capsule_random,
            )
        })
        .collect::<TestResult<Vec<_>>>()?;
    let mut next_slot = fixture
        .policy
        .item(&fixture.request.item_id)
        .and_then(|item| item.witnessed_state.as_ref())
        .and_then(|state| state.slots.first())
        .cloned()
        .ok_or("missing current witnessed slot")?;
    next_slot.key_epoch = 2;
    next_slot.revision = 2;
    next_slot.revision_seal_id = RevisionSealId::from_bytes([0x16; 32])?;
    next_slot.vault_policy_sequence = next_sequence;
    next_slot.witness_policy_revision = 2;
    next_slot.witness_policy_digest = next_digest.clone();
    next_slot.capsules = next_capsules;
    next_slot.capsule_set_digest = next_slot.recomputed_capsule_set_digest()?;
    let next_witnessed_state = WitnessedStateV1 {
        slots: vec![next_slot.clone()],
        digest: witnessed_slot_set_digest(std::slice::from_ref(&next_slot))?,
    };

    let mut next_policy = fixture.policy.clone();
    next_policy.sequence = next_sequence;
    next_policy.terminal_revision_hash = Digest32::new([0x74; 32]);
    next_policy
        .revision_hashes
        .push(next_policy.terminal_revision_hash.clone());
    if let Some(replacement) = replacement {
        let replacement = replacement.public_descriptor()?;
        let principal = next_policy
            .principals
            .get_mut(&replacement.principal_id)
            .ok_or("missing replaced witness principal")?;
        principal.descriptor = replacement.clone();
        next_policy
            .historical_recipient_keys
            .insert(replacement.recipient_public_key);
        next_policy
            .historical_verification_keys
            .insert(replacement.verification_public_key);
    }
    let item = next_policy
        .items
        .get_mut(&fixture.request.item_id)
        .ok_or("missing item")?;
    item.key_epoch = 2;
    item.witnessed_state = Some(next_witnessed_state);
    next_policy
        .witness_policies
        .insert(next_digest.clone(), next_witness_policy.clone());

    let (approver_set_digest, witness_set_digest) =
        next_witness_policy.active_descriptor_set_digests()?;
    let owner = fixture.actors.owner.public_descriptor()?;
    let mut checkpoint = VaultPolicyCheckpointV1 {
        schema: 1,
        vault_id: next_policy.vault_id(),
        genesis_fingerprint: next_policy.genesis_fingerprint().clone(),
        vault_policy_sequence: next_sequence,
        vault_policy_hash: Digest32::new([0x74; 32]),
        witness_policy_id: next_witness_policy.witness_policy_id,
        witness_policy_revision: 2,
        witness_policy_digest: next_digest,
        witness_set_digest,
        approver_set_digest,
        review_label_set_digest: next_witness_policy.review_label_set_digest,
        predecessor_checkpoint_digest: fixture.checkpoint.digest()?,
        issued_at_ms: NOW_MS,
        issuer_owner_id: owner.principal_id,
        issuer_key_fingerprint: signing_key_fingerprint(
            1,
            &owner.principal_id,
            1,
            &owner.verification_public_key,
        ),
        issuer_key_epoch: 1,
        signature: Signature64::new([0; 64]),
    };
    checkpoint.signature = fixture
        .actors
        .owner
        .sign_validated_statement(&checkpoint.signature_preimage()?)?;
    Ok((next_policy, checkpoint))
}

#[test]
fn response_is_stable_and_escapes_only_after_anchor_publication() -> TestResult {
    let fixture = fixture()?;
    let witness_id = fixture.actors.witnesses[0].principal_id();
    let mut store = MemoryStore {
        state: PersistedWitnessState::empty(witness_id),
        fail_before_commit_once: false,
        fail_after_commit_once: false,
        fail_mark_once: false,
    };
    let mut anchor = MemoryAnchor::default();
    let clock = FixedClock {
        wall_ms: NOW_MS,
        monotonic_ms: 42,
    };
    let mut random = TestRandom::new(0xdead_beef_0123_4567);
    {
        let mut engine = WitnessEngine::new(
            &fixture.actors.witnesses[0],
            &mut store,
            &mut anchor,
            &clock,
            &mut random,
        );
        engine.register_vault(
            &fixture.policy,
            RegistrationBytes::new(vec![1, 2, 3])?,
            fixture.checkpoint.clone(),
            PolicyMaterialBytes::new(vec![4, 5, 6])?,
        )?;
        assert_eq!(
            engine.reserve(&fixture.policy, fixture.request.clone(), &fixture.manifest)?,
            WitnessProgress::Reserved
        );
        assert_eq!(
            engine.decide(
                &fixture.policy,
                &fixture.request,
                &fixture.manifest,
                &fixture.approvals[..1],
            )?,
            WitnessProgress::Pending
        );
        let stable = engine.decide(
            &fixture.policy,
            &fixture.request,
            &fixture.manifest,
            &fixture.approvals,
        )?;
        let WitnessProgress::Stable(response) = stable else {
            return Err("expected stable response".into());
        };
        assert_eq!(response.decision.decision, WitnessDecisionKindV1::Approve);
        assert!(response.contribution.is_some());
        validate_witness_response(
            &fixture.policy,
            &fixture.checkpoint,
            &fixture.request,
            &fixture.manifest,
            &response,
        )?;
        let mut corrupted = (*response).clone();
        let contribution = corrupted
            .contribution
            .as_mut()
            .ok_or("missing contribution")?;
        let mut ciphertext = *contribution.ciphertext.as_bytes();
        ciphertext[0] ^= 1;
        contribution.ciphertext = ShareCiphertext49::from_slice(&ciphertext)?;
        assert_eq!(
            validate_witness_response(
                &fixture.policy,
                &fixture.checkpoint,
                &fixture.request,
                &fixture.manifest,
                &corrupted,
            )
            .map_err(WitnessEngineError::reason),
            Err(WitnessReasonV1::InvalidContribution)
        );
        let stable_bytes = response.canonical_bytes()?;
        let retry = engine.decide(
            &fixture.policy,
            &fixture.request,
            &fixture.manifest,
            &fixture.approvals,
        )?;
        let WitnessProgress::Stable(retry) = retry else {
            return Err("expected stable retry".into());
        };
        assert_eq!(retry.canonical_bytes()?, stable_bytes);
    }
    assert_eq!(store.state.logical.state_generation, 4);
    assert_eq!(
        store
            .state
            .logical
            .replay
            .values()
            .next()
            .ok_or("missing replay entry")?
            .approvals
            .len(),
        2
    );
    assert!(store.state.pending_anchor.is_none());
    assert_eq!(anchor.publishes, 4);
    assert_eq!(
        anchor.value.as_ref().map(|value| value.state_generation),
        Some(4)
    );
    Ok(())
}

#[test]
fn receipt_material_is_bound_to_the_request_policy_and_counted_members() -> TestResult {
    let fixture = fixture()?;
    let mut counted_approver_ids = fixture
        .approvals
        .iter()
        .map(|approval| approval.approver_id)
        .collect::<Vec<_>>();
    counted_approver_ids.sort_unstable();
    let witness_policy = fixture
        .policy
        .witness_policy(&fixture.request.witness_policy_digest)
        .ok_or("missing witness policy")?;
    let mut counted_witness_ids = witness_policy
        .witness_descriptors
        .iter()
        .map(|descriptor| descriptor.witness_id)
        .collect::<Vec<_>>();
    counted_witness_ids.sort_unstable();
    let material = WitnessReceiptMaterialV1 {
        schema: 1,
        receipt_id: ReceiptId::from_bytes([0xd1; 32])?,
        request_digest: fixture.request.digest()?,
        action_manifest_digest: fixture.manifest.digest()?,
        presentation_digest: fixture.manifest.presentation_digest.clone(),
        policy_checkpoint_digest: fixture.checkpoint.digest()?,
        witness_policy_digest: fixture.request.witness_policy_digest.clone(),
        approval_threshold: 2,
        witness_threshold: 2,
        counted_approver_ids,
        counted_witness_ids,
        reason: WitnessReasonV1::None,
        issued_at_ms: NOW_MS,
        expires_at_ms: fixture.request.expires_at_ms,
    };
    validate_receipt_material(
        &fixture.policy,
        &fixture.checkpoint,
        &fixture.request,
        &fixture.manifest,
        &material,
    )?;

    let mut wrong_member = material.clone();
    *wrong_member
        .counted_witness_ids
        .last_mut()
        .ok_or("missing counted witness")? = PrincipalId::from_bytes([0x7f; 32])?;
    assert_eq!(
        validate_receipt_material(
            &fixture.policy,
            &fixture.checkpoint,
            &fixture.request,
            &fixture.manifest,
            &wrong_member,
        )
        .map_err(WitnessEngineError::reason),
        Err(WitnessReasonV1::WrongScope)
    );

    let mut wrong_scope = material;
    wrong_scope.presentation_digest = Digest32::new([0xff; 32]);
    assert_eq!(
        validate_receipt_material(
            &fixture.policy,
            &fixture.checkpoint,
            &fixture.request,
            &fixture.manifest,
            &wrong_scope,
        )
        .map_err(WitnessEngineError::reason),
        Err(WitnessReasonV1::WrongScope)
    );
    Ok(())
}

#[test]
fn distinct_second_approve_from_one_identity_is_an_approval_conflict() -> TestResult {
    let fixture = fixture()?;
    let mut repeated = fixture.approvals[0].clone();
    repeated.approval_id = ApprovalId::from_bytes([0xe1; 32])?;
    repeated.nonce = ApprovalId::from_bytes([0xe2; 32])?;
    repeated.signature =
        fixture.actors.approvers[0].sign_validated_approval(&repeated.signature_preimage()?)?;
    let mut store = empty_store(&fixture);
    let mut anchor = MemoryAnchor::default();
    let clock = FixedClock {
        wall_ms: NOW_MS,
        monotonic_ms: 43,
    };
    let mut random = TestRandom::new(0x0123_4567_89ab_cdef);
    register_fixture(&fixture, &mut store, &mut anchor, &clock, &mut random)?;
    let progress = {
        let mut engine = WitnessEngine::new(
            &fixture.actors.witnesses[0],
            &mut store,
            &mut anchor,
            &clock,
            &mut random,
        );
        engine.reserve(&fixture.policy, fixture.request.clone(), &fixture.manifest)?;
        engine.decide(
            &fixture.policy,
            &fixture.request,
            &fixture.manifest,
            &[
                fixture.approvals[0].clone(),
                repeated,
                fixture.approvals[1].clone(),
            ],
        )?
    };
    let WitnessProgress::Stable(response) = progress else {
        return Err("expected stable denial".into());
    };
    assert_eq!(response.decision.decision, WitnessDecisionKindV1::Deny);
    assert_eq!(response.decision.reason, WitnessReasonV1::ApprovalConflict);
    assert!(response.contribution.is_none());
    assert_eq!(
        store
            .state
            .logical
            .replay
            .values()
            .next()
            .ok_or("missing replay entry")?
            .approvals
            .len(),
        3
    );
    Ok(())
}

#[test]
fn an_expired_stored_approval_stops_counting_without_poisoning_the_request() -> TestResult {
    let fixture = fixture()?;
    let mut short = fixture.approvals[0].clone();
    short.expires_at_ms = NOW_MS + 1;
    short.signature =
        fixture.actors.approvers[0].sign_validated_approval(&short.signature_preimage()?)?;
    let mut store = empty_store(&fixture);
    let mut anchor = MemoryAnchor::default();
    let initial_clock = FixedClock {
        wall_ms: NOW_MS,
        monotonic_ms: 44,
    };
    let mut random = TestRandom::new(0x1234_0000_5678_0000);
    register_fixture(
        &fixture,
        &mut store,
        &mut anchor,
        &initial_clock,
        &mut random,
    )?;
    {
        let mut engine = WitnessEngine::new(
            &fixture.actors.witnesses[0],
            &mut store,
            &mut anchor,
            &initial_clock,
            &mut random,
        );
        engine.reserve(&fixture.policy, fixture.request.clone(), &fixture.manifest)?;
        assert_eq!(
            engine.decide(
                &fixture.policy,
                &fixture.request,
                &fixture.manifest,
                &[short],
            )?,
            WitnessProgress::Pending
        );
    }

    let later_clock = FixedClock {
        wall_ms: NOW_MS + 2,
        monotonic_ms: 45,
    };
    {
        let mut engine = WitnessEngine::new(
            &fixture.actors.witnesses[0],
            &mut store,
            &mut anchor,
            &later_clock,
            &mut random,
        );
        assert_eq!(
            engine.decide(
                &fixture.policy,
                &fixture.request,
                &fixture.manifest,
                &fixture.approvals[1..],
            )?,
            WitnessProgress::Pending
        );
    }
    let retained = &store
        .state
        .logical
        .replay
        .values()
        .next()
        .ok_or("missing replay entry")?
        .approvals;
    assert_eq!(retained.len(), 1);
    assert_eq!(retained[0].approver_id, fixture.approvals[1].approver_id);

    let mut renewed = fixture.approvals[0].clone();
    renewed.approval_id = ApprovalId::from_bytes([0xe3; 32])?;
    renewed.nonce = ApprovalId::from_bytes([0xe4; 32])?;
    renewed.issued_at_ms = NOW_MS + 2;
    renewed.signature =
        fixture.actors.approvers[0].sign_validated_approval(&renewed.signature_preimage()?)?;
    let progress = {
        let mut engine = WitnessEngine::new(
            &fixture.actors.witnesses[0],
            &mut store,
            &mut anchor,
            &later_clock,
            &mut random,
        );
        engine.decide(
            &fixture.policy,
            &fixture.request,
            &fixture.manifest,
            &[renewed],
        )?
    };
    let WitnessProgress::Stable(response) = progress else {
        return Err("expected stable approval".into());
    };
    assert_eq!(response.decision.decision, WitnessDecisionKindV1::Approve);
    Ok(())
}

#[test]
fn request_time_boundaries_apply_skew_not_before_and_strict_expiry() -> TestResult {
    let fixture = fixture()?;

    let (request, manifest) = signed_time_variant(
        &fixture,
        NOW_MS + ACCEPTED_CLOCK_SKEW_MS,
        None,
        NOW_MS + ACCEPTED_CLOCK_SKEW_MS + 1,
    )?;
    assert_eq!(
        reserve_once(&fixture, request, &manifest, NOW_MS, 0x101)?,
        WitnessProgress::Reserved
    );

    let (request, manifest) = signed_time_variant(
        &fixture,
        NOW_MS + ACCEPTED_CLOCK_SKEW_MS + 1,
        None,
        NOW_MS + ACCEPTED_CLOCK_SKEW_MS + 2,
    )?;
    assert_eq!(
        reserve_once(&fixture, request, &manifest, NOW_MS, 0x102)
            .map_err(WitnessEngineError::reason),
        Err(WitnessReasonV1::NotYetValid)
    );

    let (request, manifest) = signed_time_variant(
        &fixture,
        NOW_MS - 1_000,
        Some(NOW_MS + ACCEPTED_CLOCK_SKEW_MS),
        NOW_MS + ACCEPTED_CLOCK_SKEW_MS + 1,
    )?;
    assert_eq!(
        reserve_once(&fixture, request, &manifest, NOW_MS, 0x103)?,
        WitnessProgress::Reserved
    );

    let (request, manifest) = signed_time_variant(
        &fixture,
        NOW_MS - 1_000,
        Some(NOW_MS + ACCEPTED_CLOCK_SKEW_MS + 1),
        NOW_MS + ACCEPTED_CLOCK_SKEW_MS + 2,
    )?;
    assert_eq!(
        reserve_once(&fixture, request, &manifest, NOW_MS, 0x104)
            .map_err(WitnessEngineError::reason),
        Err(WitnessReasonV1::NotYetValid)
    );

    let (request, manifest) = signed_time_variant(&fixture, NOW_MS - 1_000, None, NOW_MS + 1)?;
    assert_eq!(
        reserve_once(&fixture, request, &manifest, NOW_MS, 0x105)?,
        WitnessProgress::Reserved
    );

    let (request, manifest) = signed_time_variant(&fixture, NOW_MS - 1_000, None, NOW_MS)?;
    assert_eq!(
        reserve_once(&fixture, request, &manifest, NOW_MS, 0x106)
            .map_err(WitnessEngineError::reason),
        Err(WitnessReasonV1::Expired)
    );
    Ok(())
}

#[test]
fn forward_clock_jump_turns_a_reserved_request_into_a_stable_expiry_denial() -> TestResult {
    let fixture = fixture()?;
    let mut store = empty_store(&fixture);
    let mut anchor = MemoryAnchor::default();
    let initial_clock = FixedClock {
        wall_ms: NOW_MS,
        monotonic_ms: 48,
    };
    let mut random = TestRandom::new(0x4567_89ab_cdef_0123);
    register_fixture(
        &fixture,
        &mut store,
        &mut anchor,
        &initial_clock,
        &mut random,
    )?;
    {
        let mut engine = WitnessEngine::new(
            &fixture.actors.witnesses[0],
            &mut store,
            &mut anchor,
            &initial_clock,
            &mut random,
        );
        engine.reserve(&fixture.policy, fixture.request.clone(), &fixture.manifest)?;
    }
    let expiry_clock = FixedClock {
        wall_ms: fixture.request.expires_at_ms,
        monotonic_ms: 49,
    };
    let denied = {
        let mut engine = WitnessEngine::new(
            &fixture.actors.witnesses[0],
            &mut store,
            &mut anchor,
            &expiry_clock,
            &mut random,
        );
        engine.decide(
            &fixture.policy,
            &fixture.request,
            &fixture.manifest,
            &fixture.approvals,
        )?
    };
    let WitnessProgress::Stable(denied) = denied else {
        return Err("expected expiry denial".into());
    };
    assert_eq!(denied.decision.reason, WitnessReasonV1::Expired);
    assert!(denied.contribution.is_none());
    let retry = {
        let mut engine = WitnessEngine::new(
            &fixture.actors.witnesses[0],
            &mut store,
            &mut anchor,
            &expiry_clock,
            &mut random,
        );
        engine.decide(&fixture.policy, &fixture.request, &fixture.manifest, &[])?
    };
    let WitnessProgress::Stable(retry) = retry else {
        return Err("expected stable expiry retry".into());
    };
    assert_eq!(retry.canonical_bytes()?, denied.canonical_bytes()?);
    Ok(())
}

#[test]
fn conflicting_request_id_terminalizes_only_the_original_reservation() -> TestResult {
    let fixture = fixture()?;
    let mut conflicting = fixture.request.clone();
    conflicting.request_session_public_key = fixture.actors.witnesses[1]
        .public_descriptor()?
        .recipient_public_key;
    conflicting.request_session_key_fingerprint =
        recipient_public_key_fingerprint(&conflicting.request_session_public_key);
    conflicting.client_signature = fixture
        .actors
        .owner
        .sign_validated_statement(&conflicting.signature_preimage()?)?;
    let mut store = empty_store(&fixture);
    let mut anchor = MemoryAnchor::default();
    let clock = FixedClock {
        wall_ms: NOW_MS,
        monotonic_ms: 46,
    };
    let mut random = TestRandom::new(0x2345_6789_abcd_ef01);
    register_fixture(&fixture, &mut store, &mut anchor, &clock, &mut random)?;
    let conflict_response = {
        let mut engine = WitnessEngine::new(
            &fixture.actors.witnesses[0],
            &mut store,
            &mut anchor,
            &clock,
            &mut random,
        );
        engine.reserve(&fixture.policy, fixture.request.clone(), &fixture.manifest)?;
        let progress = engine.reserve(&fixture.policy, conflicting.clone(), &fixture.manifest)?;
        let WitnessProgress::Stable(response) = progress else {
            return Err("expected replay-conflict denial".into());
        };
        response
    };
    assert_eq!(
        conflict_response.decision.reason,
        WitnessReasonV1::ReplayConflict
    );
    assert_eq!(
        conflict_response.decision.request_digest,
        fixture.request.digest()?
    );
    assert!(conflict_response.contribution.is_none());

    let original_retry = {
        let mut engine = WitnessEngine::new(
            &fixture.actors.witnesses[0],
            &mut store,
            &mut anchor,
            &clock,
            &mut random,
        );
        engine.reserve(&fixture.policy, fixture.request.clone(), &fixture.manifest)?
    };
    let WitnessProgress::Stable(original_retry) = original_retry else {
        return Err("expected stable original denial".into());
    };
    assert_eq!(
        original_retry.canonical_bytes()?,
        conflict_response.canonical_bytes()?
    );

    let mut engine = WitnessEngine::new(
        &fixture.actors.witnesses[0],
        &mut store,
        &mut anchor,
        &clock,
        &mut random,
    );
    assert_eq!(
        engine
            .reserve(&fixture.policy, conflicting, &fixture.manifest)
            .map_err(WitnessEngineError::reason),
        Err(WitnessReasonV1::ReplayConflict)
    );
    Ok(())
}

#[test]
fn common_scope_check_rejects_each_changed_duplicate() -> TestResult {
    let fixture = fixture()?;
    assert_request_scope_mismatches(&fixture)?;
    assert_manifest_scope_mismatches(&fixture)?;
    let mut request = fixture.request.clone();
    request.protocol_version = 2;
    assert_eq!(
        validate_request_manifest(&request, &fixture.manifest).map_err(WitnessEngineError::reason),
        Err(WitnessReasonV1::UnsupportedVersion)
    );
    Ok(())
}

fn assert_wrong_scope(
    fixture: &Fixture,
    name: &str,
    change: impl FnOnce(&mut ActionManifestV1) -> TestResult,
) -> TestResult {
    let mut changed = fixture.manifest.clone();
    change(&mut changed)?;
    assert!(changed.validate_shape().is_ok(), "{name} fixture");
    assert_eq!(
        validate_request_manifest(&fixture.request, &changed).map_err(WitnessEngineError::reason),
        Err(WitnessReasonV1::WrongScope),
        "{name}"
    );
    Ok(())
}

fn assert_request_scope_mismatches(fixture: &Fixture) -> TestResult {
    assert_wrong_scope(fixture, "request ID", |manifest| {
        manifest.request_id = RequestId::from_bytes([0xd0; 32])?;
        Ok(())
    })?;
    assert_wrong_scope(fixture, "vault", |manifest| {
        manifest.vault_id = VaultId::from_bytes([0xd1; 32])?;
        Ok(())
    })?;
    assert_wrong_scope(fixture, "genesis", |manifest| {
        manifest.genesis_fingerprint = Digest32::new([0xd2; 32]);
        Ok(())
    })?;
    assert_wrong_scope(fixture, "item", |manifest| {
        let item_id = ItemId::from_bytes([0xd3; 32])?;
        manifest.item_id = item_id;
        manifest.approval_target.entries[0].item_id = item_id;
        manifest.approval_target_digest = manifest.approval_target.digest()?;
        Ok(())
    })?;
    assert_wrong_scope(fixture, "key epoch", |manifest| {
        manifest.key_epoch = 2;
        Ok(())
    })?;
    assert_wrong_scope(fixture, "access mode", |manifest| {
        manifest.item_access_mode = ItemAccessMode::Mixed;
        Ok(())
    })?;
    assert_wrong_scope(fixture, "slot", |manifest| {
        manifest.slot_id = SlotId::from_bytes([0xd4; 32])?;
        Ok(())
    })?;
    assert_wrong_scope(fixture, "content role", |manifest| {
        manifest.content_role = ContentRole::Descriptor;
        Ok(())
    })?;
    assert_wrong_scope(fixture, "revision", |manifest| {
        manifest.revision = 2;
        Ok(())
    })?;
    assert_wrong_scope(fixture, "revision seal", |manifest| {
        manifest.revision_seal_id = RevisionSealId::from_bytes([0xd5; 32])?;
        Ok(())
    })?;
    assert_wrong_scope(fixture, "policy sequence", |manifest| {
        manifest.vault_policy_sequence = 2;
        Ok(())
    })?;
    assert_wrong_scope(fixture, "policy hash", |manifest| {
        manifest.vault_policy_hash = Digest32::new([0xd6; 32]);
        Ok(())
    })?;
    assert_wrong_scope(fixture, "witness policy ID", |manifest| {
        manifest.witness_policy_id = WitnessPolicyId::from_bytes([0xd7; 32])?;
        Ok(())
    })?;
    assert_wrong_scope(fixture, "witness policy revision", |manifest| {
        manifest.witness_policy_revision = 2;
        Ok(())
    })?;
    assert_wrong_scope(fixture, "witness policy digest", |manifest| {
        manifest.witness_policy_digest = Digest32::new([0xd8; 32]);
        Ok(())
    })?;
    assert_wrong_scope(fixture, "requester", |manifest| {
        manifest.requester_principal_id = PrincipalId::from_bytes([0xd9; 32])?;
        Ok(())
    })?;
    assert_wrong_scope(fixture, "requested role", |manifest| {
        manifest.requested_access_role = AccessRole::Reader;
        Ok(())
    })?;
    Ok(())
}

fn assert_manifest_scope_mismatches(fixture: &Fixture) -> TestResult {
    assert_wrong_scope(fixture, "operation", |manifest| {
        manifest.operation = WitnessOperationV1::WritePrivateFile;
        manifest.operation_context = OperationContextV1::WritePrivateFile;
        manifest.output_sink = OutputSinkV1::PrivateFile;
        manifest.output_sink_commitment = Some(Digest32::new([0xda; 32]));
        Ok(())
    })?;
    assert_wrong_scope(fixture, "approval target", |manifest| {
        manifest.approval_target.entries[0].presentation_commitment = Digest32::new([0xdb; 32]);
        manifest.approval_target_digest = manifest.approval_target.digest()?;
        Ok(())
    })?;
    assert_wrong_scope(fixture, "issued time", |manifest| {
        manifest.issued_at_ms -= 1;
        Ok(())
    })?;
    assert_wrong_scope(fixture, "not before", |manifest| {
        manifest.not_before_ms = Some(NOW_MS);
        Ok(())
    })?;
    assert_wrong_scope(fixture, "expiry", |manifest| {
        manifest.expires_at_ms -= 1;
        Ok(())
    })?;
    assert_wrong_scope(fixture, "workload", |manifest| {
        manifest.output_limit_bytes -= 1;
        Ok(())
    })?;
    Ok(())
}

#[test]
fn committed_pending_anchor_reconciles_without_repeating_the_mutation() -> TestResult {
    let fixture = fixture()?;
    let mut store = empty_store(&fixture);
    let mut anchor = MemoryAnchor::default();
    let clock = FixedClock {
        wall_ms: NOW_MS,
        monotonic_ms: 10,
    };
    let mut random = TestRandom::new(0x1111_2222_3333_4444);
    register_fixture(&fixture, &mut store, &mut anchor, &clock, &mut random)?;
    store.fail_after_commit_once = true;
    {
        let mut engine = WitnessEngine::new(
            &fixture.actors.witnesses[0],
            &mut store,
            &mut anchor,
            &clock,
            &mut random,
        );
        assert_eq!(
            engine
                .reserve(&fixture.policy, fixture.request.clone(), &fixture.manifest)
                .map_err(WitnessEngineError::kind),
            Err(WitnessEngineErrorKind::StoreUnavailable)
        );
    }
    assert_eq!(store.state.logical.state_generation, 2);
    assert!(store.state.pending_anchor.is_some());
    assert_eq!(
        anchor.value.as_ref().map(|value| value.state_generation),
        Some(1)
    );
    {
        let mut engine = WitnessEngine::new(
            &fixture.actors.witnesses[0],
            &mut store,
            &mut anchor,
            &clock,
            &mut random,
        );
        assert_eq!(
            engine.reserve(&fixture.policy, fixture.request.clone(), &fixture.manifest)?,
            WitnessProgress::Reserved
        );
    }
    assert_eq!(store.state.logical.state_generation, 2);
    assert!(store.state.pending_anchor.is_none());
    assert_eq!(
        anchor.value.as_ref().map(|value| value.state_generation),
        Some(2)
    );
    Ok(())
}

#[test]
fn failed_database_commit_leaves_no_reservation_and_retry_commits_once() -> TestResult {
    let fixture = fixture()?;
    let mut store = empty_store(&fixture);
    let mut anchor = MemoryAnchor::default();
    let clock = FixedClock {
        wall_ms: NOW_MS,
        monotonic_ms: 25,
    };
    let mut random = TestRandom::new(0xff00_1122_3344_5566);
    register_fixture(&fixture, &mut store, &mut anchor, &clock, &mut random)?;
    let generation = store.state.logical.state_generation;
    let publish_count = anchor.publishes;
    store.fail_before_commit_once = true;
    {
        let mut engine = WitnessEngine::new(
            &fixture.actors.witnesses[0],
            &mut store,
            &mut anchor,
            &clock,
            &mut random,
        );
        assert_eq!(
            engine
                .reserve(&fixture.policy, fixture.request.clone(), &fixture.manifest)
                .map_err(WitnessEngineError::kind),
            Err(WitnessEngineErrorKind::StoreUnavailable)
        );
    }
    assert_eq!(store.state.logical.state_generation, generation);
    assert!(store.state.logical.replay.is_empty());
    assert_eq!(anchor.publishes, publish_count);
    {
        let mut engine = WitnessEngine::new(
            &fixture.actors.witnesses[0],
            &mut store,
            &mut anchor,
            &clock,
            &mut random,
        );
        assert_eq!(
            engine.reserve(&fixture.policy, fixture.request.clone(), &fixture.manifest)?,
            WitnessProgress::Reserved
        );
    }
    assert_eq!(store.state.logical.state_generation, generation + 1);
    assert_eq!(anchor.publishes, publish_count + 1);
    Ok(())
}

#[test]
fn failed_local_anchor_mark_reconciles_without_republishing() -> TestResult {
    let fixture = fixture()?;
    let mut store = empty_store(&fixture);
    let mut anchor = MemoryAnchor::default();
    let clock = FixedClock {
        wall_ms: NOW_MS,
        monotonic_ms: 26,
    };
    let mut random = TestRandom::new(0x0011_2233_4455_6677);
    register_fixture(&fixture, &mut store, &mut anchor, &clock, &mut random)?;
    store.fail_mark_once = true;
    {
        let mut engine = WitnessEngine::new(
            &fixture.actors.witnesses[0],
            &mut store,
            &mut anchor,
            &clock,
            &mut random,
        );
        assert_eq!(
            engine
                .reserve(&fixture.policy, fixture.request.clone(), &fixture.manifest)
                .map_err(WitnessEngineError::kind),
            Err(WitnessEngineErrorKind::StoreUnavailable)
        );
    }
    assert!(store.state.pending_anchor.is_some());
    let publish_count = anchor.publishes;
    {
        let mut engine = WitnessEngine::new(
            &fixture.actors.witnesses[0],
            &mut store,
            &mut anchor,
            &clock,
            &mut random,
        );
        assert_eq!(
            engine.reserve(&fixture.policy, fixture.request.clone(), &fixture.manifest)?,
            WitnessProgress::Reserved
        );
    }
    assert!(store.state.pending_anchor.is_none());
    assert_eq!(anchor.publishes, publish_count);
    Ok(())
}

#[test]
fn response_waits_for_failed_readback_and_retry_returns_the_same_bytes() -> TestResult {
    let fixture = fixture()?;
    let mut store = empty_store(&fixture);
    let mut anchor = MemoryAnchor::default();
    let clock = FixedClock {
        wall_ms: NOW_MS,
        monotonic_ms: 11,
    };
    let mut random = TestRandom::new(0x2222_3333_4444_5555);
    register_fixture(&fixture, &mut store, &mut anchor, &clock, &mut random)?;
    {
        let mut engine = WitnessEngine::new(
            &fixture.actors.witnesses[0],
            &mut store,
            &mut anchor,
            &clock,
            &mut random,
        );
        assert_eq!(
            engine.reserve(&fixture.policy, fixture.request.clone(), &fixture.manifest)?,
            WitnessProgress::Reserved
        );
    }
    anchor.fail_readback_once = true;
    {
        let mut engine = WitnessEngine::new(
            &fixture.actors.witnesses[0],
            &mut store,
            &mut anchor,
            &clock,
            &mut random,
        );
        assert_eq!(
            engine
                .decide(
                    &fixture.policy,
                    &fixture.request,
                    &fixture.manifest,
                    &fixture.approvals,
                )
                .map_err(WitnessEngineError::kind),
            Err(WitnessEngineErrorKind::AnchorUnavailable)
        );
    }
    let stored = store
        .state
        .logical
        .replay
        .values()
        .next()
        .and_then(|entry| entry.response.as_ref())
        .ok_or("missing durable response")?
        .canonical_bytes()?;
    assert!(store.state.pending_anchor.is_some());
    let publish_count = anchor.publishes;
    let retry = {
        let mut engine = WitnessEngine::new(
            &fixture.actors.witnesses[0],
            &mut store,
            &mut anchor,
            &clock,
            &mut random,
        );
        engine.decide(
            &fixture.policy,
            &fixture.request,
            &fixture.manifest,
            &fixture.approvals,
        )?
    };
    let WitnessProgress::Stable(retry) = retry else {
        return Err("expected reconciled stable response".into());
    };
    assert_eq!(retry.canonical_bytes()?, stored);
    assert_eq!(anchor.publishes, publish_count);
    assert!(store.state.pending_anchor.is_none());
    Ok(())
}

#[test]
fn denial_and_cancellation_never_create_contributions() -> TestResult {
    let fixture = fixture()?;
    let mut store = empty_store(&fixture);
    let mut anchor = MemoryAnchor::default();
    let clock = FixedClock {
        wall_ms: NOW_MS,
        monotonic_ms: 12,
    };
    let mut random = TestRandom::new(0x3333_4444_5555_6666);
    register_fixture(&fixture, &mut store, &mut anchor, &clock, &mut random)?;
    let denial = denying_approval(&fixture, 0)?;
    let denied = {
        let mut engine = WitnessEngine::new(
            &fixture.actors.witnesses[0],
            &mut store,
            &mut anchor,
            &clock,
            &mut random,
        );
        engine.reserve(&fixture.policy, fixture.request.clone(), &fixture.manifest)?;
        engine.decide(
            &fixture.policy,
            &fixture.request,
            &fixture.manifest,
            &[denial],
        )?
    };
    let WitnessProgress::Stable(denied) = denied else {
        return Err("expected denial".into());
    };
    assert_eq!(denied.decision.decision, WitnessDecisionKindV1::Deny);
    assert_eq!(denied.decision.reason, WitnessReasonV1::ApprovalDenied);
    assert!(denied.contribution.is_none());

    let second = self::fixture()?;
    let mut second_store = empty_store(&second);
    let mut second_anchor = MemoryAnchor::default();
    let mut second_random = TestRandom::new(0x4444_5555_6666_7777);
    register_fixture(
        &second,
        &mut second_store,
        &mut second_anchor,
        &clock,
        &mut second_random,
    )?;
    let cancellation = cancellation(&second)?;
    let cancelled = {
        let mut engine = WitnessEngine::new(
            &second.actors.witnesses[0],
            &mut second_store,
            &mut second_anchor,
            &clock,
            &mut second_random,
        );
        engine.cancel(&second.policy, &second.request, &cancellation)?
    };
    let CancellationProgress::Cancelled(cancelled) = cancelled else {
        return Err("expected cancellation".into());
    };
    assert_eq!(cancelled.decision.reason, WitnessReasonV1::Cancelled);
    assert!(cancelled.contribution.is_none());
    Ok(())
}

#[test]
fn cancellation_after_a_durable_approval_is_too_late_and_returns_the_same_response() -> TestResult {
    let fixture = fixture()?;
    let mut store = empty_store(&fixture);
    let mut anchor = MemoryAnchor::default();
    let clock = FixedClock {
        wall_ms: NOW_MS,
        monotonic_ms: 47,
    };
    let mut random = TestRandom::new(0x3456_789a_bcde_f012);
    register_fixture(&fixture, &mut store, &mut anchor, &clock, &mut random)?;
    let approved = {
        let mut engine = WitnessEngine::new(
            &fixture.actors.witnesses[0],
            &mut store,
            &mut anchor,
            &clock,
            &mut random,
        );
        engine.reserve(&fixture.policy, fixture.request.clone(), &fixture.manifest)?;
        let progress = engine.decide(
            &fixture.policy,
            &fixture.request,
            &fixture.manifest,
            &fixture.approvals,
        )?;
        let WitnessProgress::Stable(response) = progress else {
            return Err("expected stable approval".into());
        };
        response
    };
    let generation = store.state.logical.state_generation;
    let publish_count = anchor.publishes;
    let late = {
        let mut engine = WitnessEngine::new(
            &fixture.actors.witnesses[0],
            &mut store,
            &mut anchor,
            &clock,
            &mut random,
        );
        engine.cancel(&fixture.policy, &fixture.request, &cancellation(&fixture)?)?
    };
    let CancellationProgress::TooLate(late) = late else {
        return Err("expected cancellation-too-late outcome".into());
    };
    assert_eq!(late.canonical_bytes()?, approved.canonical_bytes()?);
    assert_eq!(store.state.logical.state_generation, generation);
    assert_eq!(anchor.publishes, publish_count);
    Ok(())
}

#[test]
fn invalid_approval_and_unsafe_clock_leave_replay_unchanged() -> TestResult {
    let fixture = fixture()?;
    let mut store = empty_store(&fixture);
    let mut anchor = MemoryAnchor::default();
    let clock = FixedClock {
        wall_ms: NOW_MS,
        monotonic_ms: 13,
    };
    let mut random = TestRandom::new(0x5555_6666_7777_8888);
    register_fixture(&fixture, &mut store, &mut anchor, &clock, &mut random)?;
    {
        let mut engine = WitnessEngine::new(
            &fixture.actors.witnesses[0],
            &mut store,
            &mut anchor,
            &clock,
            &mut random,
        );
        engine.reserve(&fixture.policy, fixture.request.clone(), &fixture.manifest)?;
    }
    let generation = store.state.logical.state_generation;
    let mut forged = fixture.approvals[0].clone();
    let mut signature = *forged.signature.as_bytes();
    signature[0] ^= 1;
    forged.signature = Signature64::new(signature);
    {
        let mut engine = WitnessEngine::new(
            &fixture.actors.witnesses[0],
            &mut store,
            &mut anchor,
            &clock,
            &mut random,
        );
        assert_eq!(
            engine
                .decide(
                    &fixture.policy,
                    &fixture.request,
                    &fixture.manifest,
                    &[forged],
                )
                .map_err(WitnessEngineError::reason),
            Err(WitnessReasonV1::InvalidSignature)
        );
    }
    assert_eq!(store.state.logical.state_generation, generation);
    assert!(
        store
            .state
            .logical
            .replay
            .values()
            .next()
            .is_some_and(|entry| {
                entry.state == ReplayStateV1::Reserved && entry.approvals.is_empty()
            })
    );

    let rollback_clock = FixedClock {
        wall_ms: NOW_MS - ACCEPTED_CLOCK_SKEW_MS - 1,
        monotonic_ms: 14,
    };
    let mut engine = WitnessEngine::new(
        &fixture.actors.witnesses[0],
        &mut store,
        &mut anchor,
        &rollback_clock,
        &mut random,
    );
    assert_eq!(
        engine
            .reserve(&fixture.policy, fixture.request.clone(), &fixture.manifest)
            .map_err(WitnessEngineError::reason),
        Err(WitnessReasonV1::UnsafeClock)
    );
    assert_eq!(store.state.logical.state_generation, generation);
    Ok(())
}

#[test]
fn validly_signed_wrong_scope_and_time_approvals_are_refused_without_mutation() -> TestResult {
    let fixture = fixture()?;
    let mut cases = Vec::new();

    let mut wrong_request = fixture.approvals[0].clone();
    wrong_request.request_id = RequestId::from_bytes([0xb1; 32])?;
    resign_approval(&fixture, 0, &mut wrong_request)?;
    cases.push((wrong_request, WitnessReasonV1::Invalid));

    let mut wrong_manifest = fixture.approvals[0].clone();
    wrong_manifest.action_manifest_digest = Digest32::new([0xb2; 32]);
    resign_approval(&fixture, 0, &mut wrong_manifest)?;
    cases.push((wrong_manifest, WitnessReasonV1::Invalid));

    let mut wrong_presentation = fixture.approvals[0].clone();
    wrong_presentation.presentation_digest = Digest32::new([0xb3; 32]);
    resign_approval(&fixture, 0, &mut wrong_presentation)?;
    cases.push((wrong_presentation, WitnessReasonV1::Invalid));

    let mut wrong_policy = fixture.approvals[0].clone();
    wrong_policy.witness_policy_digest = Digest32::new([0xb4; 32]);
    resign_approval(&fixture, 0, &mut wrong_policy)?;
    cases.push((wrong_policy, WitnessReasonV1::Invalid));

    let mut wrong_witness_set = fixture.approvals[0].clone();
    wrong_witness_set.intended_witness_set_digest = Digest32::new([0xb5; 32]);
    resign_approval(&fixture, 0, &mut wrong_witness_set)?;
    cases.push((wrong_witness_set, WitnessReasonV1::Invalid));

    let mut wrong_mode = fixture.approvals[0].clone();
    wrong_mode.approval_mode = ApprovalModeV1::Automatic;
    resign_approval(&fixture, 0, &mut wrong_mode)?;
    cases.push((wrong_mode, WitnessReasonV1::Invalid));

    let mut expired = fixture.approvals[0].clone();
    expired.issued_at_ms = NOW_MS - 100;
    expired.expires_at_ms = NOW_MS;
    resign_approval(&fixture, 0, &mut expired)?;
    cases.push((expired, WitnessReasonV1::Invalid));

    let mut future = fixture.approvals[0].clone();
    future.issued_at_ms = NOW_MS + ACCEPTED_CLOCK_SKEW_MS + 1;
    resign_approval(&fixture, 0, &mut future)?;
    cases.push((future, WitnessReasonV1::Invalid));

    let mut unauthorized = fixture.approvals[0].clone();
    unauthorized.approver_id = fixture.actors.witnesses[1].principal_id();
    cases.push((unauthorized, WitnessReasonV1::PolicyDenied));

    for (index, (approval, expected)) in cases.into_iter().enumerate() {
        assert_approval_refused_without_state_change(
            &fixture,
            approval,
            expected,
            0x500 + index as u64,
        )?;
    }
    Ok(())
}

#[test]
fn replay_compaction_waits_until_after_the_retention_horizon() -> TestResult {
    let fixture = fixture()?;
    let mut store = empty_store(&fixture);
    let mut anchor = MemoryAnchor::default();
    let clock = FixedClock {
        wall_ms: NOW_MS,
        monotonic_ms: 15,
    };
    let mut random = TestRandom::new(0x6666_7777_8888_9999);
    register_fixture(&fixture, &mut store, &mut anchor, &clock, &mut random)?;
    let cancellation = cancellation(&fixture)?;
    {
        let mut engine = WitnessEngine::new(
            &fixture.actors.witnesses[0],
            &mut store,
            &mut anchor,
            &clock,
            &mut random,
        );
        engine.cancel(&fixture.policy, &fixture.request, &cancellation)?;
    }
    let horizon = fixture.request.expires_at_ms + REPLAY_RETENTION_MS;
    let exact_clock = FixedClock {
        wall_ms: horizon,
        monotonic_ms: 16,
    };
    {
        let mut engine = WitnessEngine::new(
            &fixture.actors.witnesses[0],
            &mut store,
            &mut anchor,
            &exact_clock,
            &mut random,
        );
        assert_eq!(engine.compact_replay()?, 0);
    }
    let after_clock = FixedClock {
        wall_ms: horizon + 1,
        monotonic_ms: 17,
    };
    {
        let mut engine = WitnessEngine::new(
            &fixture.actors.witnesses[0],
            &mut store,
            &mut anchor,
            &after_clock,
            &mut random,
        );
        assert_eq!(engine.compact_replay()?, 1);
    }
    assert!(store.state.logical.replay.is_empty());
    assert_eq!(
        anchor.value.as_ref().map(|value| value.state_generation),
        Some(store.state.logical.state_generation)
    );
    Ok(())
}

#[test]
fn missing_or_divergent_external_anchor_stops_service() -> TestResult {
    let fixture = fixture()?;
    let mut store = empty_store(&fixture);
    let mut anchor = MemoryAnchor::default();
    let clock = FixedClock {
        wall_ms: NOW_MS,
        monotonic_ms: 18,
    };
    let mut random = TestRandom::new(0x7777_8888_9999_aaaa);
    register_fixture(&fixture, &mut store, &mut anchor, &clock, &mut random)?;
    anchor.value = None;
    let mut engine = WitnessEngine::new(
        &fixture.actors.witnesses[0],
        &mut store,
        &mut anchor,
        &clock,
        &mut random,
    );
    assert_eq!(
        engine
            .reserve(&fixture.policy, fixture.request.clone(), &fixture.manifest)
            .map_err(WitnessEngineError::reason),
        Err(WitnessReasonV1::AnchorConflict)
    );
    assert!(store.state.logical.replay.is_empty());
    Ok(())
}

#[test]
fn anchor_behind_and_database_behind_restores_both_stop_service() -> TestResult {
    let fixture = fixture()?;
    let mut store = empty_store(&fixture);
    let mut anchor = MemoryAnchor::default();
    let clock = FixedClock {
        wall_ms: NOW_MS,
        monotonic_ms: 23,
    };
    let mut random = TestRandom::new(0xddee_ff00_1122_3344);
    register_fixture(&fixture, &mut store, &mut anchor, &clock, &mut random)?;
    let registered_state = store.state.clone();
    let registered_anchor = anchor.value.clone().ok_or("missing registration anchor")?;
    {
        let mut engine = WitnessEngine::new(
            &fixture.actors.witnesses[0],
            &mut store,
            &mut anchor,
            &clock,
            &mut random,
        );
        engine.reserve(&fixture.policy, fixture.request.clone(), &fixture.manifest)?;
    }
    let reserved_state = store.state.clone();
    let reserved_anchor = anchor.value.clone().ok_or("missing reservation anchor")?;

    anchor.value = Some(registered_anchor.clone());
    {
        let mut engine = WitnessEngine::new(
            &fixture.actors.witnesses[0],
            &mut store,
            &mut anchor,
            &clock,
            &mut random,
        );
        assert_eq!(
            engine.compact_replay().map_err(WitnessEngineError::reason),
            Err(WitnessReasonV1::AnchorConflict)
        );
    }

    store.state = registered_state;
    anchor.value = Some(reserved_anchor);
    {
        let mut engine = WitnessEngine::new(
            &fixture.actors.witnesses[0],
            &mut store,
            &mut anchor,
            &clock,
            &mut random,
        );
        assert_eq!(
            engine.compact_replay().map_err(WitnessEngineError::reason),
            Err(WitnessReasonV1::AnchorConflict)
        );
    }

    assert_ne!(reserved_state.published_anchor, Some(registered_anchor));
    Ok(())
}

#[test]
fn restored_state_cannot_move_to_another_witness_identity() -> TestResult {
    let fixture = fixture()?;
    let mut store = empty_store(&fixture);
    let mut anchor = MemoryAnchor::default();
    let clock = FixedClock {
        wall_ms: NOW_MS,
        monotonic_ms: 24,
    };
    let mut random = TestRandom::new(0xeeff_0011_2233_4455);
    register_fixture(&fixture, &mut store, &mut anchor, &clock, &mut random)?;
    {
        let mut engine = WitnessEngine::new(
            &fixture.actors.witnesses[1],
            &mut store,
            &mut anchor,
            &clock,
            &mut random,
        );
        assert_eq!(
            engine.compact_replay().map_err(WitnessEngineError::reason),
            Err(WitnessReasonV1::RestoredStateUnsafe)
        );
    }

    let mut replacement_store = MemoryStore {
        state: PersistedWitnessState::empty(fixture.actors.witnesses[1].principal_id()),
        fail_before_commit_once: false,
        fail_after_commit_once: false,
        fail_mark_once: false,
    };
    let mut replacement_anchor = MemoryAnchor::default();
    {
        let mut engine = WitnessEngine::new(
            &fixture.actors.witnesses[1],
            &mut replacement_store,
            &mut replacement_anchor,
            &clock,
            &mut random,
        );
        engine.register_vault(
            &fixture.policy,
            RegistrationBytes::new(vec![10, 11, 12])?,
            fixture.checkpoint.clone(),
            PolicyMaterialBytes::new(vec![13, 14, 15])?,
        )?;
    }
    assert_eq!(replacement_store.state.logical.state_generation, 1);
    assert_eq!(replacement_anchor.publishes, 1);
    Ok(())
}

#[test]
fn strict_descendant_checkpoint_invalidates_old_reservations() -> TestResult {
    let fixture = fixture()?;
    let (next_policy, next_checkpoint) = descendant_policy_and_checkpoint(&fixture)?;
    let mut store = empty_store(&fixture);
    let mut anchor = MemoryAnchor::default();
    let clock = FixedClock {
        wall_ms: NOW_MS,
        monotonic_ms: 19,
    };
    let mut random = TestRandom::new(0x9999_aaaa_bbbb_cccc);
    register_fixture(&fixture, &mut store, &mut anchor, &clock, &mut random)?;
    {
        let mut engine = WitnessEngine::new(
            &fixture.actors.witnesses[0],
            &mut store,
            &mut anchor,
            &clock,
            &mut random,
        );
        engine.reserve(&fixture.policy, fixture.request.clone(), &fixture.manifest)?;
        engine.advance_checkpoint(
            &next_policy,
            next_checkpoint.clone(),
            PolicyMaterialBytes::new(vec![7, 8, 9])?,
        )?;
    }
    let entry = store
        .state
        .logical
        .replay
        .values()
        .next()
        .ok_or("missing stale replay record")?;
    assert_eq!(entry.state, ReplayStateV1::Denied);
    let response = entry.response.as_ref().ok_or("missing stale response")?;
    assert_eq!(response.decision.reason, WitnessReasonV1::StalePolicy);
    assert!(response.contribution.is_none());
    assert_eq!(
        store
            .state
            .logical
            .vaults
            .values()
            .next()
            .map(|vault| &vault.current_checkpoint),
        Some(&next_checkpoint)
    );
    assert_eq!(store.state.logical.state_generation, 3);
    assert_eq!(
        anchor.value.as_ref().map(|value| value.state_generation),
        Some(3)
    );
    Ok(())
}

#[test]
fn checkpoint_rotation_is_accepted_then_the_replaced_witness_stops_serving() -> TestResult {
    let fixture = fixture()?;
    let mut identity_random = TestRandom::new(0xbbbb_cccc_dddd_eeee);
    let replacement = make_identity(0x31, PrincipalKind::Witness, &mut identity_random)?;
    let UnlockedIdentity::Witness(replacement) = replacement else {
        return Err("replacement role mismatch".into());
    };
    let (next_policy, next_checkpoint) =
        descendant_policy_and_checkpoint_with_replacement(&fixture, Some(&replacement))?;
    let mut store = empty_store(&fixture);
    let mut anchor = MemoryAnchor::default();
    let clock = FixedClock {
        wall_ms: NOW_MS,
        monotonic_ms: 21,
    };
    let mut random = TestRandom::new(0xbbcc_ddee_ff00_1122);
    register_fixture(&fixture, &mut store, &mut anchor, &clock, &mut random)?;
    {
        let mut engine = WitnessEngine::new(
            &fixture.actors.witnesses[0],
            &mut store,
            &mut anchor,
            &clock,
            &mut random,
        );
        engine.advance_checkpoint(
            &next_policy,
            next_checkpoint.clone(),
            PolicyMaterialBytes::new(vec![7, 8, 9])?,
        )?;
    }
    assert_eq!(
        store
            .state
            .logical
            .vaults
            .values()
            .next()
            .map(|vault| &vault.current_checkpoint),
        Some(&next_checkpoint)
    );
    let mut engine = WitnessEngine::new(
        &fixture.actors.witnesses[0],
        &mut store,
        &mut anchor,
        &clock,
        &mut random,
    );
    assert_eq!(
        engine
            .reserve(&next_policy, fixture.request.clone(), &fixture.manifest)
            .map_err(WitnessEngineError::reason),
        Err(WitnessReasonV1::PolicyDenied)
    );
    Ok(())
}

#[test]
fn signed_rotation_binds_both_fresh_item_seals_and_the_new_key_period() -> TestResult {
    let fixture = fixture()?;
    let mut identity_random = TestRandom::new(0xbbbb_cccc_dddd_eeef);
    let UnlockedIdentity::Witness(replacement) =
        make_identity(0x31, PrincipalKind::Witness, &mut identity_random)?
    else {
        return Err("replacement role mismatch".into());
    };
    let (mut next, next_checkpoint) =
        descendant_policy_and_checkpoint_with_replacement(&fixture, Some(&replacement))?;
    let mut prior = fixture.policy.clone();

    let prior_item = prior
        .items
        .get_mut(&fixture.request.item_id)
        .ok_or("prior item absent")?;
    let prior_state = prior_item
        .witnessed_state
        .as_mut()
        .ok_or("prior witnessed state absent")?;
    let mut prior_descriptor_slot = prior_state
        .slots
        .first()
        .cloned()
        .ok_or("prior body slot absent")?;
    prior_descriptor_slot.slot_id = SlotId::from_bytes([0x44; 32])?;
    prior_descriptor_slot.content_role = ContentRole::Descriptor;
    prior_descriptor_slot.revision = prior_item.descriptor.revision;
    prior_descriptor_slot.revision_seal_id = prior_item.descriptor.revision_seal_id;
    prior_state.slots.insert(0, prior_descriptor_slot);
    prior_state.digest = witnessed_slot_set_digest(&prior_state.slots)?;

    let next_item = next
        .items
        .get_mut(&fixture.request.item_id)
        .ok_or("next item absent")?;
    next_item.descriptor.key_epoch = 2;
    next_item.descriptor.revision = 2;
    next_item.descriptor.revision_seal_id = RevisionSealId::from_bytes([0x46; 32])?;
    let next_state = next_item
        .witnessed_state
        .as_mut()
        .ok_or("next witnessed state absent")?;
    let mut next_descriptor_slot = next_state
        .slots
        .first()
        .cloned()
        .ok_or("next body slot absent")?;
    next_descriptor_slot.slot_id = SlotId::from_bytes([0x45; 32])?;
    next_descriptor_slot.content_role = ContentRole::Descriptor;
    next_descriptor_slot.revision = next_item.descriptor.revision;
    next_descriptor_slot.revision_seal_id = next_item.descriptor.revision_seal_id;
    next_state.slots.insert(0, next_descriptor_slot.clone());
    next_state.digest = witnessed_slot_set_digest(&next_state.slots)?;
    let next_body_slot = next_state
        .slots
        .iter()
        .find(|slot| slot.content_role == ContentRole::Body)
        .cloned()
        .ok_or("next body slot absent")?;

    let prior_policy = prior
        .witness_policy(&fixture.request.witness_policy_digest)
        .ok_or("prior witness policy absent")?;
    let next_policy_digest = next_descriptor_slot.witness_policy_digest.clone();
    let next_witness_policy = next
        .witness_policy(&next_policy_digest)
        .ok_or("next witness policy absent")?;
    let owner = fixture.actors.owner.public_descriptor()?;
    let mut rotation = WitnessPolicyRotationV1 {
        schema: 1,
        rotation_id: RotationId::from_bytes([0xd5; 32])?,
        vault_id: prior.vault_id(),
        genesis_fingerprint: prior.genesis_fingerprint().clone(),
        prior_vault_policy_sequence: prior.sequence(),
        prior_vault_policy_hash: prior.terminal_revision_hash().clone(),
        next_vault_policy_sequence: next.sequence(),
        next_vault_policy_hash: next.terminal_revision_hash().clone(),
        prior_witness_policy_id: prior_policy.witness_policy_id,
        prior_witness_policy_revision: prior_policy.revision,
        prior_witness_policy_digest: fixture.request.witness_policy_digest.clone(),
        next_witness_policy_id: next_witness_policy.witness_policy_id,
        next_witness_policy_revision: next_witness_policy.revision,
        next_witness_policy_digest: next_policy_digest,
        reason: WitnessRotationReasonV1::ContributionKey,
        affected_items: vec![WitnessRotationItemV1 {
            item_id: fixture.request.item_id,
            prior_key_epoch: 1,
            next_key_epoch: 2,
            next_descriptor_revision: next_descriptor_slot.revision,
            next_descriptor_revision_seal_id: next_descriptor_slot.revision_seal_id,
            next_descriptor_capsule_set_digest: next_descriptor_slot.capsule_set_digest.clone(),
            next_body_revision: next_body_slot.revision,
            next_body_revision_seal_id: next_body_slot.revision_seal_id,
            next_body_capsule_set_digest: next_body_slot.capsule_set_digest.clone(),
        }],
        issued_at_ms: NOW_MS,
        owner_id: owner.principal_id,
        owner_key_fingerprint: signing_key_fingerprint(
            1,
            &owner.principal_id,
            1,
            &owner.verification_public_key,
        ),
        owner_key_epoch: 1,
        signature: Signature64::new([0; 64]),
    };
    rotation.signature = fixture
        .actors
        .owner
        .sign_validated_statement(&rotation.signature_preimage()?)?;
    assert_eq!(
        verify_witness_policy_rotation(&prior, &next, &rotation)?,
        rotation.digest()?
    );

    let registration = RegistrationBytes::new(vec![0x91, 0x92])?;
    let mut recovery = WitnessRecoveryV1 {
        schema: 1,
        recovery_id: RecoveryId::from_bytes([0xfc; 32])?,
        vault_id: next.vault_id(),
        genesis_fingerprint: next.genesis_fingerprint().clone(),
        unavailable_prior_witness_id: None,
        new_witness_descriptor: WitnessDescriptorBytes::new(
            next_witness_policy.witness_descriptors[0].canonical_bytes(),
        )?,
        new_registration_digest: witness_registration_digest(&registration)?,
        prior_checkpoint_digest: fixture.checkpoint.digest()?,
        next_checkpoint_digest: next_checkpoint.digest()?,
        rotation_record_digest: rotation.digest()?,
        statement: 1,
        issued_at_ms: NOW_MS,
        owner_id: owner.principal_id,
        owner_key_fingerprint: rotation.owner_key_fingerprint.clone(),
        owner_key_epoch: 1,
        signature: Signature64::new([0; 64]),
    };
    recovery.signature = fixture
        .actors
        .owner
        .sign_validated_statement(&recovery.signature_preimage()?)?;
    let mut lower_threshold = next.clone();
    lower_threshold
        .witness_policies
        .get_mut(&rotation.next_witness_policy_digest)
        .ok_or("next witness policy absent")?
        .witness_threshold = 1;
    let unsafe_recovery = verify_witness_recovery(
        &prior,
        &lower_threshold,
        &fixture.checkpoint,
        &next_checkpoint,
        &rotation,
        &registration,
        &recovery,
    )
    .err()
    .ok_or("recovery lowered the witness threshold")?;
    assert_eq!(
        unsafe_recovery.kind(),
        RotationVerificationErrorKind::UnsafeRecovery
    );

    let mut forked_next = next.clone();
    forked_next.revision_hashes[0] = Digest32::new([0xfe; 32]);
    let fork_error = verify_witness_policy_rotation(&prior, &forked_next, &rotation)
        .err()
        .ok_or("an unrelated terminal policy snapshot verified as a descendant")?;
    assert_eq!(
        fork_error.kind(),
        RotationVerificationErrorKind::InvalidPolicyTransition
    );

    let mut added_governed_item = next.clone();
    let added_item_id = ItemId::from_bytes([0xfd; 32])?;
    let mut added_item = added_governed_item
        .item(&fixture.request.item_id)
        .cloned()
        .ok_or("next governed item absent")?;
    if let Some(state) = &mut added_item.witnessed_state {
        for slot in &mut state.slots {
            slot.item_id = added_item_id;
        }
    }
    added_governed_item.items.insert(added_item_id, added_item);
    let added_item_error = verify_witness_policy_rotation(&prior, &added_governed_item, &rotation)
        .err()
        .ok_or("a newly governed item omitted from rotation evidence verified")?;
    assert_eq!(
        added_item_error.kind(),
        RotationVerificationErrorKind::IncompleteItemRotation
    );

    let mut incomplete = rotation.clone();
    incomplete.affected_items[0].next_descriptor_capsule_set_digest = Digest32::new([0xff; 32]);
    incomplete.signature = fixture
        .actors
        .owner
        .sign_validated_statement(&incomplete.signature_preimage()?)?;
    let incomplete_error = match verify_witness_policy_rotation(&prior, &next, &incomplete) {
        Err(error) => error,
        Ok(_) => return Err("an incomplete descriptor reseal verified".into()),
    };
    assert_eq!(
        incomplete_error.kind(),
        RotationVerificationErrorKind::IncompleteItemRotation
    );

    let mut wrong_reason = rotation;
    wrong_reason.reason = WitnessRotationReasonV1::WitnessSigningKey;
    wrong_reason.signature = fixture
        .actors
        .owner
        .sign_validated_statement(&wrong_reason.signature_preimage()?)?;
    let reason_error = match verify_witness_policy_rotation(&prior, &next, &wrong_reason) {
        Err(error) => error,
        Ok(_) => return Err("a non-canonical rotation reason verified".into()),
    };
    assert_eq!(
        reason_error.kind(),
        RotationVerificationErrorKind::InvalidPolicyTransition
    );
    Ok(())
}

#[test]
fn checkpoint_gap_fork_and_downgrade_have_distinct_safe_outcomes() -> TestResult {
    let fixture = fixture()?;
    let (next_policy, next_checkpoint) = descendant_policy_and_checkpoint(&fixture)?;
    let (gap_policy, gap_checkpoint) =
        descendant_policy_and_checkpoint_at_sequence(&fixture, None, 3)?;
    let mut fork_checkpoint = next_checkpoint.clone();
    fork_checkpoint.predecessor_checkpoint_digest = Digest32::new([0xfa; 32]);
    fork_checkpoint.signature = fixture
        .actors
        .owner
        .sign_validated_statement(&fork_checkpoint.signature_preimage()?)?;
    let mut store = empty_store(&fixture);
    let mut anchor = MemoryAnchor::default();
    let clock = FixedClock {
        wall_ms: NOW_MS,
        monotonic_ms: 22,
    };
    let mut random = TestRandom::new(0xccdd_eeff_0011_2233);
    register_fixture(&fixture, &mut store, &mut anchor, &clock, &mut random)?;
    {
        let mut engine = WitnessEngine::new(
            &fixture.actors.witnesses[0],
            &mut store,
            &mut anchor,
            &clock,
            &mut random,
        );
        assert_eq!(
            engine
                .advance_checkpoint(
                    &next_policy,
                    fork_checkpoint,
                    PolicyMaterialBytes::new(vec![7])?,
                )
                .map_err(WitnessEngineError::reason),
            Err(WitnessReasonV1::CheckpointFork)
        );
        assert_eq!(
            engine
                .advance_checkpoint(
                    &gap_policy,
                    gap_checkpoint,
                    PolicyMaterialBytes::new(vec![8])?,
                )
                .map_err(WitnessEngineError::reason),
            Err(WitnessReasonV1::WitnessBehind)
        );
        engine.advance_checkpoint(
            &next_policy,
            next_checkpoint,
            PolicyMaterialBytes::new(vec![9])?,
        )?;
        assert_eq!(
            engine
                .advance_checkpoint(
                    &fixture.policy,
                    fixture.checkpoint.clone(),
                    PolicyMaterialBytes::new(vec![4, 5, 6])?,
                )
                .map_err(WitnessEngineError::reason),
            Err(WitnessReasonV1::StalePolicy)
        );
    }
    assert_eq!(store.state.logical.state_generation, 2);
    Ok(())
}

#[test]
fn rotation_reason_matches_active_descriptors_by_identity() -> TestResult {
    let fixture = fixture()?;
    let mut identity_random = TestRandom::new(0xabcd_1234_5678_90ef);
    let UnlockedIdentity::Witness(replacement) =
        make_identity(0x31, PrincipalKind::Witness, &mut identity_random)?
    else {
        return Err("replacement role mismatch".into());
    };
    let (next, _) =
        descendant_policy_and_checkpoint_with_replacement(&fixture, Some(&replacement))?;
    let mut prior_policy = fixture
        .policy
        .witness_policy(&fixture.request.witness_policy_digest)
        .cloned()
        .ok_or("prior witness policy absent")?;
    let next_item = next
        .item(&fixture.request.item_id)
        .and_then(|item| item.witnessed_state.as_ref())
        .and_then(|state| state.slots.first())
        .ok_or("next witnessed slot absent")?;
    let next_policy = next
        .witness_policy(&next_item.witness_policy_digest)
        .ok_or("next witness policy absent")?;

    let mut retired = prior_policy.witness_descriptors[0].clone();
    retired.status = DescriptorStatus::Revoked;
    retired.witness_id = PrincipalId::from_bytes([0x01; 32])?;
    retired.share_index = 32;
    prior_policy.witness_descriptors.insert(0, retired);

    assert_eq!(
        rotation_reason(&prior_policy, next_policy),
        WitnessRotationReasonV1::ContributionKey
    );
    Ok(())
}

#[test]
fn a_policy_ahead_of_the_registered_checkpoint_is_witness_behind_not_a_fork() -> TestResult {
    let fixture = fixture()?;
    let (next_policy, _) = descendant_policy_and_checkpoint(&fixture)?;
    let mut store = empty_store(&fixture);
    let mut anchor = MemoryAnchor::default();
    let clock = FixedClock {
        wall_ms: NOW_MS,
        monotonic_ms: 20,
    };
    let mut random = TestRandom::new(0xaaaa_bbbb_cccc_dddd);
    register_fixture(&fixture, &mut store, &mut anchor, &clock, &mut random)?;
    let mut engine = WitnessEngine::new(
        &fixture.actors.witnesses[0],
        &mut store,
        &mut anchor,
        &clock,
        &mut random,
    );
    assert_eq!(
        engine
            .reserve(&next_policy, fixture.request.clone(), &fixture.manifest)
            .map_err(WitnessEngineError::reason),
        Err(WitnessReasonV1::WitnessBehind)
    );
    Ok(())
}

#[test]
fn store_capacity_is_preserved_as_a_protocol_refusal() {
    let error = map_store_error(WitnessStoreError::capacity_exhausted());
    assert_eq!(
        error.kind(),
        WitnessEngineErrorKind::Refused(WitnessReasonV1::CapacityExhausted)
    );
}

#[test]
fn unpublishable_anchor_is_refused_before_local_state_commit() -> TestResult {
    let fixture = fixture()?;
    let mut store = empty_store(&fixture);
    let mut anchor = MemoryAnchor {
        reject_candidate_capacity: true,
        ..MemoryAnchor::default()
    };
    let clock = FixedClock {
        wall_ms: NOW_MS,
        monotonic_ms: 50,
    };
    let mut random = TestRandom::new(0x1234_5678_9abc_def0);
    let mut engine = WitnessEngine::new(
        &fixture.actors.witnesses[0],
        &mut store,
        &mut anchor,
        &clock,
        &mut random,
    );

    assert_eq!(
        engine
            .register_vault(
                &fixture.policy,
                RegistrationBytes::new(vec![1, 2, 3])?,
                fixture.checkpoint.clone(),
                PolicyMaterialBytes::new(vec![4, 5, 6])?,
            )
            .map_err(WitnessEngineError::reason),
        Err(WitnessReasonV1::CapacityExhausted)
    );
    assert_eq!(store.state.logical.state_generation, 0);
    assert!(store.state.logical.vaults.is_empty());
    assert!(store.state.pending_anchor.is_none());
    assert!(anchor.value.is_none());
    Ok(())
}

#[test]
fn independent_witness_acknowledgements_progress_without_a_global_freshness_claim() -> TestResult {
    let fixture = fixture()?;
    let clock = FixedClock {
        wall_ms: NOW_MS,
        monotonic_ms: 60,
    };
    let mut first_store = empty_store(&fixture);
    let mut first_anchor = MemoryAnchor::default();
    let mut first_random = TestRandom::new(0x1111_2222_3333_4444);
    let first_acknowledgement = WitnessEngine::new(
        &fixture.actors.witnesses[0],
        &mut first_store,
        &mut first_anchor,
        &clock,
        &mut first_random,
    )
    .register_vault(
        &fixture.policy,
        RegistrationBytes::new(vec![1])?,
        fixture.checkpoint.clone(),
        PolicyMaterialBytes::new(vec![2])?,
    )?;

    let proposed = verify_checkpoint_propagation(&fixture.policy, &fixture.checkpoint, &[])?;
    assert_eq!(proposed.phase, CheckpointPropagationPhase::Proposed);
    assert!(!proposed.global_freshness_claimed);
    let partial = verify_checkpoint_propagation(
        &fixture.policy,
        &fixture.checkpoint,
        std::slice::from_ref(&first_acknowledgement),
    )?;
    assert_eq!(
        partial.phase,
        CheckpointPropagationPhase::PartiallyPropagated
    );
    assert_eq!(partial.acknowledged_witness_count, 1);
    assert!(!partial.global_freshness_claimed);

    let mut second_store = MemoryStore {
        state: PersistedWitnessState::empty(fixture.actors.witnesses[1].principal_id()),
        fail_before_commit_once: false,
        fail_after_commit_once: false,
        fail_mark_once: false,
    };
    let mut second_anchor = MemoryAnchor::default();
    let mut second_random = TestRandom::new(0x5555_6666_7777_8888);
    let second_acknowledgement = WitnessEngine::new(
        &fixture.actors.witnesses[1],
        &mut second_store,
        &mut second_anchor,
        &clock,
        &mut second_random,
    )
    .register_vault(
        &fixture.policy,
        RegistrationBytes::new(vec![3])?,
        fixture.checkpoint.clone(),
        PolicyMaterialBytes::new(vec![4])?,
    )?;
    let durable = verify_checkpoint_propagation(
        &fixture.policy,
        &fixture.checkpoint,
        &[first_acknowledgement.clone(), second_acknowledgement],
    )?;
    assert_eq!(durable.phase, CheckpointPropagationPhase::DurablyAccepted);
    assert_eq!(durable.acknowledged_witness_count, 2);
    assert!(!durable.global_freshness_claimed);

    let mut forged = first_acknowledgement;
    let mut signature = *forged.exact_anchor.signature.as_bytes();
    signature[0] ^= 1;
    forged.exact_anchor.signature = Signature64::new(signature);
    forged.anchor_digest = forged.exact_anchor.digest()?;
    assert!(
        verify_checkpoint_propagation(&fixture.policy, &fixture.checkpoint, &[forged]).is_err()
    );
    Ok(())
}

fn complete_receipt(fixture: &Fixture) -> TestResult<WitnessReceiptV1> {
    let clock = FixedClock {
        wall_ms: NOW_MS,
        monotonic_ms: 70,
    };
    let mut decisions = Vec::new();
    for (index, identity) in fixture.actors.witnesses.iter().enumerate() {
        let mut store = MemoryStore {
            state: PersistedWitnessState::empty(identity.principal_id()),
            fail_before_commit_once: false,
            fail_after_commit_once: false,
            fail_mark_once: false,
        };
        let mut anchor = MemoryAnchor::default();
        let mut random = TestRandom::new(0x9000_u64.saturating_add(index as u64));
        let mut engine = WitnessEngine::new(identity, &mut store, &mut anchor, &clock, &mut random);
        engine.register_vault(
            &fixture.policy,
            RegistrationBytes::new(vec![u8::try_from(index + 1)?])?,
            fixture.checkpoint.clone(),
            PolicyMaterialBytes::new(vec![0xa0_u8.saturating_add(u8::try_from(index)?)])?,
        )?;
        engine.reserve(&fixture.policy, fixture.request.clone(), &fixture.manifest)?;
        let WitnessProgress::Stable(response) = engine.decide(
            &fixture.policy,
            &fixture.request,
            &fixture.manifest,
            &fixture.approvals,
        )?
        else {
            return Err("complete approvals did not create a stable witness response".into());
        };
        decisions.push(response.decision);
    }
    decisions.sort_unstable_by_key(|decision| decision.witness_id);
    let mut counted_approver_ids = fixture
        .approvals
        .iter()
        .map(|decision| decision.approver_id)
        .collect::<Vec<_>>();
    counted_approver_ids.sort_unstable();
    let counted_witness_ids = decisions
        .iter()
        .map(|decision| decision.witness_id)
        .collect();
    Ok(WitnessReceiptV1 {
        schema: 1,
        receipt_id: ReceiptId::from_bytes([0xe1; 32])?,
        request_signature_preimage: RequestBytes::new(fixture.request.signature_preimage()?)?,
        client_signature: fixture.request.client_signature.clone(),
        request_digest: fixture.request.digest()?,
        action_manifest_digest: fixture.manifest.digest()?,
        presentation_digest: fixture.manifest.presentation_digest.clone(),
        public_scope: PublicReceiptScopeV1::from_request(&fixture.request),
        approval_decisions: fixture.approvals.to_vec(),
        witness_decisions: decisions,
        policy_checkpoint: fixture.checkpoint.clone(),
        witness_policy_material: PolicyMaterialBytes::new(vec![1])?,
        approval_threshold: 2,
        witness_threshold: 2,
        counted_approver_ids,
        counted_witness_ids,
        outcome: ReceiptOutcomeV1::Approved,
        reason: WitnessReasonV1::None,
        issued_at_ms: NOW_MS,
        expires_at_ms: fixture.request.expires_at_ms,
        endpoint_acknowledgement: None,
        endpoint_completion: None,
    })
}

#[test]
fn complete_receipt_verification_rejects_bit_and_field_substitution_mutations() -> TestResult {
    let fixture = fixture()?;
    let receipt = complete_receipt(&fixture)?;
    let verified =
        verify_witness_receipt_with_policy(&receipt, &fixture.policy, Some(&fixture.checkpoint))?;
    assert_eq!(verified.counted_approver_ids.len(), 2);
    assert_eq!(verified.counted_witness_ids.len(), 2);
    assert!(
        verified
            .witness_generations
            .iter()
            .all(|generation| generation.state_generation >= 3)
    );
    assert!(!verified.endpoint_acknowledged);
    assert!(!verified.endpoint_completion_recorded);
    assert!(!verified.receipt_core_endpoint_authenticated);
    assert!(verified.retained_checkpoint_matched);

    let mut mutations = Vec::new();
    let mut changed_request_digest = receipt.clone();
    changed_request_digest.request_digest = Digest32::new([0xf1; 32]);
    mutations.push(changed_request_digest);
    let mut substituted_manifest = receipt.clone();
    substituted_manifest.action_manifest_digest = Digest32::new([0xf2; 32]);
    mutations.push(substituted_manifest);
    let mut substituted_scope = receipt.clone();
    substituted_scope.public_scope.item_id = ItemId::from_bytes([0xf3; 32])?;
    mutations.push(substituted_scope);
    let mut substituted_identity = receipt.clone();
    *substituted_identity
        .counted_witness_ids
        .last_mut()
        .ok_or("counted witness absent")? = PrincipalId::from_bytes([0x7f; 32])?;
    mutations.push(substituted_identity);
    let mut changed_approval_bit = receipt.clone();
    let mut approval_signature = *changed_approval_bit.approval_decisions[0]
        .signature
        .as_bytes();
    approval_signature[0] ^= 1;
    changed_approval_bit.approval_decisions[0].signature = Signature64::new(approval_signature);
    mutations.push(changed_approval_bit);
    let mut changed_generation = receipt.clone();
    changed_generation.witness_decisions[0].state_generation += 1;
    mutations.push(changed_generation);
    let mut changed_checkpoint = receipt.clone();
    let mut checkpoint_signature = *changed_checkpoint.policy_checkpoint.signature.as_bytes();
    checkpoint_signature[0] ^= 1;
    changed_checkpoint.policy_checkpoint.signature = Signature64::new(checkpoint_signature);
    mutations.push(changed_checkpoint);
    let mut false_denial = receipt.clone();
    false_denial.outcome = ReceiptOutcomeV1::Denied;
    false_denial.reason = WitnessReasonV1::PolicyDenied;
    mutations.push(false_denial);

    for mutation in mutations {
        assert!(
            verify_witness_receipt_with_policy(&mutation, &fixture.policy, None).is_err(),
            "a receipt evidence mutation verified"
        );
    }

    let owner = fixture.actors.owner.public_descriptor()?;
    let mut endpoint_records = receipt.clone();
    let mut acknowledgement = ReceiptAcknowledgementV1 {
        schema: 1,
        receipt_id: endpoint_records.receipt_id,
        receipt_core_digest: endpoint_records.core_digest()?,
        request_digest: endpoint_records.request_digest.clone(),
        endpoint_principal_id: owner.principal_id,
        endpoint_key_fingerprint: signing_key_fingerprint(
            1,
            &owner.principal_id,
            1,
            &owner.verification_public_key,
        ),
        endpoint_key_epoch: 1,
        started_at_ms: NOW_MS + 1,
        signature: Signature64::new([0; 64]),
    };
    acknowledgement.signature = fixture
        .actors
        .owner
        .sign_validated_statement(&acknowledgement.signature_preimage()?)?;
    let mut completion = ReceiptCompletionV1 {
        schema: 1,
        receipt_id: endpoint_records.receipt_id,
        receipt_core_digest: endpoint_records.core_digest()?,
        acknowledgement_digest: Some(acknowledgement.digest()?),
        endpoint_principal_id: owner.principal_id,
        endpoint_key_fingerprint: acknowledgement.endpoint_key_fingerprint.clone(),
        endpoint_key_epoch: 1,
        outcome: ReceiptOutcomeV1::Approved,
        reason: WitnessReasonV1::None,
        completed_at_ms: NOW_MS + 2,
        signature: Signature64::new([0; 64]),
    };
    completion.signature = fixture
        .actors
        .owner
        .sign_validated_statement(&completion.signature_preimage()?)?;
    endpoint_records.endpoint_acknowledgement = Some(acknowledgement);
    endpoint_records.endpoint_completion = Some(completion);
    let verified_records =
        verify_witness_receipt_with_policy(&endpoint_records, &fixture.policy, None)?;
    assert!(verified_records.endpoint_acknowledged);
    assert!(verified_records.endpoint_completion_recorded);
    assert!(verified_records.receipt_core_endpoint_authenticated);

    let mut identity_random = TestRandom::new(0xaaaa_9999_8888_7777);
    let UnlockedIdentity::Witness(replacement) =
        make_identity(0x31, PrincipalKind::Witness, &mut identity_random)?
    else {
        return Err("replacement witness role differs".into());
    };
    let (_next_policy, _next_checkpoint) =
        descendant_policy_and_checkpoint_with_replacement(&fixture, Some(&replacement))?;
    assert!(verify_witness_receipt_with_policy(&receipt, &fixture.policy, None).is_ok());
    Ok(())
}

#[test]
fn shared_request_policy_validation_rejects_role_and_lifetime_drift() -> TestResult {
    let fixture = fixture()?;

    let mut wrong_role = fixture.request.clone();
    wrong_role.requested_access_role = AccessRole::Reader;
    wrong_role.client_signature = fixture
        .actors
        .owner
        .sign_validated_statement(&wrong_role.signature_preimage()?)?;
    assert!(matches!(
        validate_request_policy(&fixture.policy, &wrong_role),
        Err(RequestPolicyError::PolicyDenied)
    ));

    let mut overlong = fixture.request.clone();
    overlong.expires_at_ms = overlong.expires_at_ms.saturating_add(1);
    overlong.client_signature = fixture
        .actors
        .owner
        .sign_validated_statement(&overlong.signature_preimage()?)?;
    assert!(matches!(
        validate_request_policy(&fixture.policy, &overlong),
        Err(RequestPolicyError::StalePolicy)
    ));
    Ok(())
}

#[test]
fn receipt_accepts_engine_compatible_skew_and_shorter_decision_expiry() -> TestResult {
    let fixture = fixture()?;
    let mut receipt = complete_receipt(&fixture)?;
    let earlier = fixture.request.issued_at_ms.saturating_sub(30_000);

    receipt.approval_decisions[0].issued_at_ms = earlier;
    receipt.approval_decisions[0].expires_at_ms = fixture.request.expires_at_ms - 1;
    receipt.approval_decisions[0].signature = fixture.actors.approvers[0]
        .sign_validated_approval(&receipt.approval_decisions[0].signature_preimage()?)?;
    receipt.witness_decisions[0].issued_at_ms = earlier;
    receipt.witness_decisions[0].expires_at_ms = fixture.request.expires_at_ms - 1;
    receipt.witness_decisions[0].signature = fixture.actors.witnesses[0]
        .sign_validated_decision(&receipt.witness_decisions[0].signature_preimage()?)?;

    verify_witness_receipt_with_policy(&receipt, &fixture.policy, None)?;
    Ok(())
}

#[test]
fn expired_denial_reports_unauthenticated_collector_reason() -> TestResult {
    let fixture = fixture()?;
    let mut receipt = complete_receipt(&fixture)?;
    let mut denial = receipt.witness_decisions.remove(0);
    denial.decision = WitnessDecisionKindV1::Deny;
    denial.reason = WitnessReasonV1::Expired;
    denial.issued_at_ms = fixture.request.expires_at_ms.saturating_add(1);
    denial.contribution_digest = None;
    denial.share_index = None;
    denial.share_commitment = None;
    denial.signature =
        fixture.actors.witnesses[0].sign_validated_decision(&denial.signature_preimage()?)?;
    receipt.witness_decisions = vec![denial];
    receipt.counted_witness_ids.clear();
    receipt.outcome = ReceiptOutcomeV1::Denied;
    receipt.reason = WitnessReasonV1::Expired;
    receipt.issued_at_ms = fixture.request.expires_at_ms.saturating_add(2);

    let verified =
        verify_witness_receipt_with_policy(&receipt, &fixture.policy, Some(&fixture.checkpoint))?;
    assert_eq!(verified.outcome, ReceiptOutcomeV1::Denied);
    assert_eq!(verified.reported_reason, WitnessReasonV1::Expired);
    assert!(!verified.receipt_core_endpoint_authenticated);
    assert!(verified.retained_checkpoint_matched);

    receipt.reason = WitnessReasonV1::Unavailable;
    let relabelled = verify_witness_receipt_with_policy(&receipt, &fixture.policy, None)?;
    assert_eq!(relabelled.reported_reason, WitnessReasonV1::Unavailable);
    assert!(!relabelled.receipt_core_endpoint_authenticated);
    Ok(())
}
