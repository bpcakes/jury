use super::*;

use std::cell::Cell;

use jury_protected::{ProtectedMemory, ProtectionPolicy};
use jury_protocol::{
    identity_v1::KdfProfile,
    vault_v1::{
        ItemFieldKind, ItemFieldV1, ItemFieldValue, RequestId, ResponseId, ShareCiphertext49,
    },
    witness_v1::{
        ActionManifestV1, ApprovalPresentationV1, ApprovalTargetEntryV1, ApprovalTargetV1,
        OperationContextV1, OutputSinkV1, PlatformAssuranceV1, StdinModeV1,
        VaultPolicyCheckpointV1, WitnessContributionEnvelopeV1, WitnessDecisionKindV1,
        WitnessDecisionV1, WitnessOperationV1, WitnessReasonV1, WitnessResponseV1,
        owner_review_label_set_digest, signing_key_fingerprint,
    },
};

use crate::access_provider::{
    AccessCompletion, AccessProviderErrorKind, ItemAccessError, ItemAccessOutcome,
    ItemAccessProvider, NeverCancelled, RevisionAccessRequest, RevisionAccessTarget,
    WitnessedAccessStatus, WitnessedItemAccessProvider,
};
use crate::domain::Capability;
use crate::identity::{IdentityCreator, UnlockedIdentity, unlock, unlocked_identity_for_test};
use crate::local_state::{CheckpointCandidate, PrincipalLocalState};
use crate::policy::{AutomaticReadTarget, PolicyCreator};
use crate::witness_client::{PreparedWitnessRequest, WitnessRequestContext, WitnessRequestCreator};
use vsss_rs::IdentifierGf256;

struct FillByte(u8);

impl RandomSource for FillByte {
    fn fill(&mut self, destination: &mut [u8]) -> Result<(), jury_protected::EntropyError> {
        destination.fill(self.0);
        Ok(())
    }
}

struct IncrementingRandom(u8);

impl RandomSource for IncrementingRandom {
    fn fill(&mut self, destination: &mut [u8]) -> Result<(), jury_protected::EntropyError> {
        destination.fill(self.0);
        self.0 = self.0.wrapping_add(1);
        Ok(())
    }
}

struct FailEntropy;

impl RandomSource for FailEntropy {
    fn fill(&mut self, _: &mut [u8]) -> Result<(), jury_protected::EntropyError> {
        Err(jury_protected::EntropyError)
    }
}

struct ZeroEntropy;

impl RandomSource for ZeroEntropy {
    fn fill(&mut self, destination: &mut [u8]) -> Result<(), jury_protected::EntropyError> {
        destination.fill(0);
        Ok(())
    }
}

struct CollisionThenOs {
    collision: [u8; 32],
    first: bool,
    os: OsRandom,
}

impl RandomSource for CollisionThenOs {
    fn fill(&mut self, destination: &mut [u8]) -> Result<(), jury_protected::EntropyError> {
        if self.first {
            self.first = false;
            destination.copy_from_slice(&self.collision);
            Ok(())
        } else {
            self.os.fill(destination)
        }
    }
}

struct RepeatId([u8; 32]);

impl RandomSource for RepeatId {
    fn fill(&mut self, destination: &mut [u8]) -> Result<(), jury_protected::EntropyError> {
        destination.copy_from_slice(&self.0);
        Ok(())
    }
}

fn assert_item_error_kind<T>(result: Result<T, ItemError>, expected: ItemErrorKind) {
    assert_eq!(
        result.map(|_| ()).map_err(|error| error.kind()),
        Err(expected)
    );
}

enum SlotOperation {
    Create,
    Replace,
}

fn item_slots(
    operations: &[PolicyOperationV1],
    expected: SlotOperation,
) -> Result<&[DirectSlotV1], Box<dyn std::error::Error>> {
    operations
        .iter()
        .find_map(|operation| match (&expected, operation) {
            (SlotOperation::Create, PolicyOperationV1::ItemCreate { direct_slots, .. })
            | (
                SlotOperation::Replace,
                PolicyOperationV1::ItemSlotsReplace { direct_slots, .. },
            ) => {
                Some(direct_slots.as_slice())
            }
            _ => None,
        })
        .ok_or_else(|| match expected {
            SlotOperation::Create => "item create operation differs".into(),
            SlotOperation::Replace => "replacement slots absent".into(),
        })
}

fn slot_for_role(
    slots: &[DirectSlotV1],
    role: ContentRole,
) -> Result<&DirectSlotV1, Box<dyn std::error::Error>> {
    slots
        .iter()
        .find(|slot| slot.content_role == role)
        .ok_or_else(|| "content role slot absent".into())
}

fn record_item_artifacts(inventory: &mut ItemArtifactInventory, envelope: &ItemEnvelopeV1) {
    inventory
        .revision_seal_ids
        .insert(envelope.descriptor.revision_seal_id);
    inventory
        .revision_seal_ids
        .insert(envelope.current_revision.revision_seal_id);
    inventory.nonces.insert(envelope.descriptor.nonce.clone());
    inventory
        .nonces
        .insert(envelope.current_revision.nonce.clone());
}

#[test]
fn item_error_is_value_free() {
    let error = ItemError::new(ItemErrorKind::AuthenticationFailed);
    assert_eq!(error.kind(), ItemErrorKind::AuthenticationFailed);
    assert_eq!(
        format!("{error:?}"),
        "ItemError { kind: AuthenticationFailed }"
    );
}

#[test]
fn runtime_shamir_split_matches_the_frozen_construction_vector()
-> Result<(), Box<dyn std::error::Error>> {
    let corpus: serde_json::Value =
        serde_json::from_str(include_str!("../../../conformance/witness-v1/vectors.json"))?;
    let vector = &corpus["construction_vector"];
    let secret = hex::decode(
        vector["revision_secret_hex"]
            .as_str()
            .ok_or("secret absent")?,
    )?;
    let seed: [u8; 32] = hex::decode(
        vector["share_rng_seed_hex"]
            .as_str()
            .ok_or("share seed absent")?,
    )?
    .try_into()
    .map_err(|_| "share seed length differs")?;
    let mut rng = ChaCha20Rng::from_seed(seed);
    let shares = Gf256::split_bytes(2, 3, &secret, &mut rng)
        .map_err(|error| format!("split frozen secret: {error:?}"))?;
    let mut expected = Vec::new();
    for share in vector["shares"].as_array().ok_or("shares absent")? {
        expected.push(hex::decode(share.as_str().ok_or("share differs")?)?);
    }
    assert_eq!(shares, expected);

    let participant_ids = [2_u8, 7, 31]
        .into_iter()
        .map(|index| IdentifierGf256(Gf256(index)));
    let explicit = Gf256::split_bytes_with_participant_ids_iter(
        2,
        3,
        &secret,
        ChaCha20Rng::from_seed(seed),
        participant_ids,
    )
    .map_err(|error| format!("split at explicit indexes: {error:?}"))?;
    assert_eq!(
        explicit
            .iter()
            .map(|share| share.first().copied())
            .collect::<Vec<_>>(),
        vec![Some(2), Some(7), Some(31)]
    );
    assert_eq!(
        Gf256::combine_bytes(&explicit[..2])
            .map_err(|error| format!("combine explicit shares: {error:?}"))?,
        secret
    );
    Ok(())
}

#[test]
fn direct_create_and_rekey_round_trip_with_revision_separation()
-> Result<(), Box<dyn std::error::Error>> {
    let protection = ProtectionPolicy::EmergencyAllowDegraded;
    let passphrase = ProtectedMemory::initialize(15, protection, |output| {
        output.copy_from_slice(b"ExamplePass1234");
        Ok::<usize, ()>(output.len())
    })?;
    let mut identities = IdentityCreator::new();
    let created = identities.create(
        PrincipalKind::Human,
        KdfProfile::PortableV1,
        1,
        &passphrase,
        |_| false,
    )?;
    let UnlockedIdentity::VaultPrincipal(owner) = unlock(&created.file, &passphrase)? else {
        return Err("owner identity role differs".into());
    };
    let mut policies = PolicyCreator::new();
    let created_policy = policies.create(&owner, 1, |_| false)?;
    let access = ItemAccessPlan {
        grants: Vec::new(),
        direct_recipient_ids: vec![owner.principal_id()],
        witness_policy_digest: None,
    };
    let state = ItemStateV1 {
        plaintext_schema: 1,
        fields: vec![ItemFieldV1 {
            name: "password".to_owned(),
            field_id: jury_protocol::vault_v1::FieldId::from_bytes([0x31; 32])?,
            value: ItemFieldValue::new(b"ExampleValue".to_vec())?,
            decoded_length: 12,
            kind: ItemFieldKind::Concealed,
            created_at_ms: 1,
            updated_at_ms: 1,
        }],
    };
    let descriptor = ItemDescriptorV1::new("ExampleItem".to_owned())?;
    let mut failing = ItemCreator::from_source(FailEntropy, protection);
    let failed_result = failing.prepare_create(
        &created_policy.state,
        &owner,
        2,
        NewItem {
            kind: ItemKind::Canonical,
            descriptor: descriptor.clone(),
            state: state.clone(),
            bucket_id: 1,
            access: access.clone(),
        },
        &ItemArtifactInventory::default(),
    );
    assert_item_error_kind(failed_result, ItemErrorKind::EntropyUnavailable);
    let mut zero = ItemCreator::from_source(ZeroEntropy, protection);
    let zero_result = zero.prepare_create(
        &created_policy.state,
        &owner,
        2,
        NewItem {
            kind: ItemKind::Canonical,
            descriptor: descriptor.clone(),
            state: state.clone(),
            bucket_id: 1,
            access: access.clone(),
        },
        &ItemArtifactInventory::default(),
    );
    assert_item_error_kind(zero_result, ItemErrorKind::RetryExhausted);
    assert_eq!(created_policy.state.item_count(), 0);
    let mut items = ItemCreator::new(protection);
    let created_item = items
        .prepare_create(
            &created_policy.state,
            &owner,
            2,
            NewItem {
                kind: ItemKind::Canonical,
                descriptor: descriptor.clone(),
                state: state.clone(),
                bucket_id: 1,
                access: access.clone(),
            },
            &ItemArtifactInventory::default(),
        )
        .map_err(|error| format!("prepare create: {error:?}"))?;
    let mut checkpoint_journal = created_policy.journal.clone();
    checkpoint_journal
        .revisions
        .push(created_item.policy.revision.clone());
    let checkpoint_candidate = CheckpointCandidate::from_validated(
        &created_item.policy.state,
        &checkpoint_journal,
        std::slice::from_ref(&created_item.envelope),
    )?;
    let local_state = PrincipalLocalState::for_vault_principal(
        &owner,
        created_item.policy.state.vault_id(),
        created_item.policy.state.genesis_fingerprint().clone(),
    )?;
    let local = local_state.initialize(&checkpoint_candidate, 3)?;
    assert_eq!(
        local.checkpoint().accepted_public_revision_hash(),
        created_item.policy.state.terminal_revision_hash()
    );
    let created_slots = item_slots(
        &created_item.policy.revision.operations,
        SlotOperation::Create,
    )?;
    let descriptor_slot = slot_for_role(created_slots, ContentRole::Descriptor)?;
    let body_slot = slot_for_role(created_slots, ContentRole::Body)?;
    let descriptor_secret = owner.open_direct_slot(descriptor_slot)?;
    let retained_body_secret = owner.open_direct_slot(body_slot)?;
    assert!(open_descriptor(&created_item.envelope, &descriptor_secret)? == descriptor);
    assert!(open_body(&created_item.envelope, &retained_body_secret)? == state);
    let mut wrong_item = created_item.envelope.clone();
    wrong_item.item_id = ItemId::from_bytes([0x5a; 32])?;
    assert_item_error_kind(
        open_body(&wrong_item, &retained_body_secret),
        ItemErrorKind::AuthenticationFailed,
    );
    let mut wrong_seal = created_item.envelope.clone();
    wrong_seal.current_revision.revision_seal_id = RevisionSealId::from_bytes([0x5b; 32])?;
    assert_item_error_kind(
        open_body(&wrong_seal, &retained_body_secret),
        ItemErrorKind::AuthenticationFailed,
    );
    verify_item_ancestry(&created_item.envelope, |principal_id| {
        (principal_id == owner.principal_id())
            .then(|| created.descriptor.verification_public_key.clone())
    })?;

    let mut collision_inventory = ItemArtifactInventory::default();
    record_item_artifacts(&mut collision_inventory, &created_item.envelope);
    let mut collision_then_success = ItemCreator::from_source(
        CollisionThenOs {
            collision: *created_item.envelope.item_id.as_bytes(),
            first: true,
            os: OsRandom,
        },
        protection,
    );
    let regenerated = collision_then_success
        .prepare_create(
            &created_item.policy.state,
            &owner,
            3,
            NewItem {
                kind: ItemKind::Canonical,
                descriptor: descriptor.clone(),
                state: state.clone(),
                bucket_id: 1,
                access: access.clone(),
            },
            &collision_inventory,
        )
        .map_err(|error| format!("collision regeneration: {error:?}"))?;
    assert_ne!(regenerated.envelope.item_id, created_item.envelope.item_id);
    let mut collision_exhaustion = ItemCreator::from_source(
        RepeatId(*created_item.envelope.item_id.as_bytes()),
        protection,
    );
    let exhausted = collision_exhaustion.prepare_create(
        &created_item.policy.state,
        &owner,
        3,
        NewItem {
            kind: ItemKind::Canonical,
            descriptor: descriptor.clone(),
            state: state.clone(),
            bucket_id: 1,
            access: access.clone(),
        },
        &collision_inventory,
    );
    assert_item_error_kind(exhausted, ItemErrorKind::RetryExhausted);
    assert_eq!(created_item.policy.state.item_count(), 1);

    let mut inventory = ItemArtifactInventory::default();
    record_item_artifacts(&mut inventory, &created_item.envelope);
    let rekeyed = items
        .prepare_rekey(
            &created_item.policy.state,
            &owner,
            3,
            &created_item.envelope,
            RekeyedItem {
                descriptor: descriptor.clone(),
                state: state.clone(),
                bucket_id: 12,
                access,
                principal_replacement: None,
                principal_registration: None,
                owner_change: None,
            },
            &inventory,
        )
        .map_err(|error| format!("prepare rekey: {error:?}"))?;
    let stale_open = open_body(&rekeyed.envelope, &retained_body_secret);
    assert_item_error_kind(stale_open, ItemErrorKind::AuthenticationFailed);
    let rekeyed_slots = item_slots(&rekeyed.policy.revision.operations, SlotOperation::Replace)?;
    let new_body_slot = slot_for_role(rekeyed_slots, ContentRole::Body)?;
    let new_body_secret = owner.open_direct_slot(new_body_slot)?;
    assert!(open_body(&rekeyed.envelope, &new_body_secret)? == state);
    assert_eq!(rekeyed.envelope.current_revision.item_revision, 2);
    assert_eq!(rekeyed.envelope.current_revision.key_epoch, 2);
    assert_eq!(rekeyed.envelope.descriptor.key_epoch, 2);
    assert_eq!(rekeyed.envelope.prior_revisions.len(), 1);

    let public_bytes = serde_json::to_vec(&rekeyed.envelope)?;
    assert!(
        !public_bytes
            .windows(11)
            .any(|window| window == b"ExampleItem")
    );
    assert!(
        !public_bytes
            .windows(12)
            .any(|window| window == b"ExampleValue")
    );

    let replaced_identity = identities.replace(
        &created.file,
        KdfProfile::PortableV1,
        4,
        &passphrase,
        |principal_id| principal_id == &owner.principal_id(),
    )?;
    let UnlockedIdentity::VaultPrincipal(next_owner) =
        unlock(&replaced_identity.replacement.file, &passphrase)?
    else {
        return Err("replacement identity role differs".into());
    };
    record_item_artifacts(&mut inventory, &rekeyed.envelope);
    let replaced = items.prepare_rekey(
        &rekeyed.policy.state,
        &owner,
        5,
        &rekeyed.envelope,
        RekeyedItem {
            descriptor: descriptor.clone(),
            state: state.clone(),
            bucket_id: 1,
            access: ItemAccessPlan {
                grants: Vec::new(),
                direct_recipient_ids: vec![next_owner.principal_id()],
                witness_policy_digest: None,
            },
            principal_replacement: Some(PrincipalReplacement {
                prior_principal_id: owner.principal_id(),
                next_descriptor: replaced_identity.replacement.descriptor.clone(),
                registration_proof_digest: FixedBytes::new([0x45; 32]),
            }),
            principal_registration: None,
            owner_change: None,
        },
        &inventory,
    )?;
    assert!(replaced.policy.state.is_owner(&next_owner.principal_id()));
    assert!(!replaced.policy.state.is_owner(&owner.principal_id()));
    assert_item_error_kind(
        open_body(&replaced.envelope, &new_body_secret),
        ItemErrorKind::AuthenticationFailed,
    );
    let replaced_slots = item_slots(&replaced.policy.revision.operations, SlotOperation::Replace)?;
    let replaced_body_slot = slot_for_role(replaced_slots, ContentRole::Body)?;
    let replaced_body_secret = next_owner.open_direct_slot(replaced_body_slot)?;
    assert!(open_body(&replaced.envelope, &replaced_body_secret)? == state);
    record_item_artifacts(&mut inventory, &replaced.envelope);
    let post_replacement_rekey = items.prepare_rekey(
        &replaced.policy.state,
        &next_owner,
        6,
        &replaced.envelope,
        RekeyedItem {
            descriptor,
            state,
            bucket_id: 1,
            access: ItemAccessPlan {
                grants: Vec::new(),
                direct_recipient_ids: vec![next_owner.principal_id()],
                witness_policy_digest: None,
            },
            principal_replacement: None,
            principal_registration: None,
            owner_change: None,
        },
        &inventory,
    )?;
    assert_eq!(
        post_replacement_rekey.envelope.current_revision.key_epoch,
        4
    );
    Ok(())
}

#[test]
fn direct_item_construction_derives_every_implicit_owner_slot()
-> Result<(), Box<dyn std::error::Error>> {
    let protection = ProtectionPolicy::EmergencyAllowDegraded;
    let owner_id = PrincipalId::from_bytes([0x31; 32])?;
    let next_owner_id = PrincipalId::from_bytes([0x32; 32])?;
    let UnlockedIdentity::VaultPrincipal(owner) = unlocked_identity_for_test(
        owner_id,
        PrincipalKind::Human,
        &mut IncrementingRandom(0x20),
    )?
    else {
        return Err("owner identity role differs".into());
    };
    let UnlockedIdentity::VaultPrincipal(next_owner) = unlocked_identity_for_test(
        next_owner_id,
        PrincipalKind::Human,
        &mut IncrementingRandom(0x80),
    )?
    else {
        return Err("next owner identity role differs".into());
    };
    let created_policy = PolicyCreator::new().create(&owner, 1, |_| false)?;
    let two_owner_policy = created_policy.state.prepare_revision(
        &owner,
        2,
        vec![
            PolicyOperationV1::PrincipalAdd {
                descriptor: next_owner.public_descriptor()?,
                display_label: "ExampleOwner".to_owned(),
                registration_proof_digest: FixedBytes::new([0x44; 32]),
            },
            PolicyOperationV1::OwnerGrant {
                principal_id: next_owner_id,
            },
        ],
    )?;
    let mut items = ItemCreator::new(protection);
    let created_item = items.prepare_create(
        &two_owner_policy.state,
        &owner,
        3,
        NewItem {
            kind: ItemKind::Canonical,
            descriptor: ItemDescriptorV1::new("ExampleItem".to_owned())?,
            state: ItemStateV1 {
                plaintext_schema: 1,
                fields: Vec::new(),
            },
            bucket_id: 1,
            access: ItemAccessPlan {
                grants: Vec::new(),
                // Callers select a direct path; the core owns the complete
                // implicit owner recipient set.
                direct_recipient_ids: vec![owner_id],
                witness_policy_digest: None,
            },
        },
        &ItemArtifactInventory::default(),
    )?;
    let slots = item_slots(
        &created_item.policy.revision.operations,
        SlotOperation::Create,
    )?;
    for expected_owner in [&owner, &next_owner] {
        let owner_slots = slots
            .iter()
            .filter(|slot| slot.recipient_principal_id == expected_owner.principal_id())
            .collect::<Vec<_>>();
        assert_eq!(owner_slots.len(), 2);
        let body_slot = owner_slots
            .into_iter()
            .find(|slot| slot.content_role == ContentRole::Body)
            .ok_or("owner body slot absent")?;
        let body_secret = expected_owner.open_direct_slot(body_slot)?;
        assert_eq!(
            open_body(&created_item.envelope, &body_secret)?
                .fields
                .len(),
            0
        );
    }

    let mut incomplete_operations = created_item.policy.revision.operations.clone();
    for operation in &mut incomplete_operations {
        if let PolicyOperationV1::ItemCreate { direct_slots, .. } = operation {
            direct_slots.retain(|slot| slot.recipient_principal_id != next_owner_id);
        }
    }
    let incomplete = two_owner_policy
        .state
        .prepare_revision(&owner, 3, incomplete_operations);
    assert!(matches!(
        incomplete,
        Err(error) if error.kind() == PolicyErrorKind::IncompleteRotation
    ));
    Ok(())
}

include!("item_tests/witnessed.rs");
