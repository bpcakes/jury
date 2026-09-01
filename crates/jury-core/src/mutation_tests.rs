use jury_protected::{EntropyError, ProtectionPolicy, RandomSource};
use jury_protocol::vault_v1::{
    Digest32, FieldId, ItemDescriptorV1, ItemFieldKind, ItemFieldV1, ItemFieldValue, ItemKind,
    ItemStateV1, PolicyOperationV1, PrincipalId, PrincipalKind, VaultFileV1, VaultHeaderV1,
};

use super::*;
use crate::domain::Capability;
use crate::identity::{UnlockedIdentity, unlocked_identity_for_test};
use crate::item::{
    ItemAccessPlan, ItemArtifactInventory, ItemCreator, NewItem, OwnerChange, RekeyedItem,
};
use crate::policy::PolicyCreator;

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
    let mut policies = PolicyCreator::from_source(CounterRandom(0x50));
    let created = policies.create(&owner, 10, |_| false)?;
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

#[test]
fn policy_dry_run_owns_the_exact_valid_commit_bytes() -> TestResult {
    let (owner, current) = fixture()?;
    let source = current.to_json_bytes()?;
    let plan = VaultMutationPlan::prepare_policy(
        &current,
        &[],
        &owner,
        20,
        vec![PolicyOperationV1::PrincipalLabelChange {
            principal_id: owner.principal_id(),
            prior_label: "owner".to_owned(),
            next_label: "primary-owner".to_owned(),
        }],
        DirectDowngradeAcknowledgement::Absent,
        MutationKind::Policy,
    )?;

    assert_eq!(current.to_json_bytes()?, source);
    assert_eq!(
        VaultFileV1::parse(plan.target_bytes())?,
        *plan.target_artifact()
    );
    assert_eq!(plan.target_policy().sequence(), 1);
    assert_eq!(
        replay_policy_with_witness_policies(&plan.target_artifact().policy, &[])?,
        *plan.target_policy()
    );
    assert_eq!(plan.precondition().policy_sequence, 0);
    assert_eq!(plan.audit_intent().operation_id, *plan.target_digest());
    assert!(plan.touched_items().is_empty());
    assert!(plan.warnings().redistribution_required);
    assert!(!format!("{plan:?}").contains("primary-owner"));
    Ok(())
}

#[test]
fn empty_and_wrong_owner_plans_are_typed_and_write_free() -> TestResult {
    let (owner, current) = fixture()?;
    let before = current.to_json_bytes()?;
    let empty = VaultMutationPlan::prepare_policy(
        &current,
        &[],
        &owner,
        20,
        Vec::new(),
        DirectDowngradeAcknowledgement::Absent,
        MutationKind::Policy,
    );
    assert!(matches!(
        empty,
        Err(error) if error.kind() == MutationErrorKind::NoChange
    ));

    let other_id = PrincipalId::from_bytes([0x22; 32])?;
    let UnlockedIdentity::VaultPrincipal(other) =
        unlocked_identity_for_test(other_id, PrincipalKind::Human, &mut CounterRandom(0x70))?
    else {
        return Err("fixture identity role differs".into());
    };
    let unauthorized = VaultMutationPlan::prepare_policy(
        &current,
        &[],
        &other,
        20,
        vec![PolicyOperationV1::PrincipalLabelChange {
            principal_id: owner.principal_id(),
            prior_label: "owner".to_owned(),
            next_label: "primary-owner".to_owned(),
        }],
        DirectDowngradeAcknowledgement::Absent,
        MutationKind::Policy,
    );
    assert!(matches!(
        unauthorized,
        Err(error) if error.kind() == MutationErrorKind::Unauthorized
    ));
    assert_eq!(current.to_json_bytes()?, before);
    Ok(())
}

#[test]
fn prepared_item_batch_publishes_policy_and_envelope_as_one_artifact() -> TestResult {
    let (owner, current) = fixture()?;
    let policy = replay_policy_with_witness_policies(&current.policy, &[])?;
    let access = ItemAccessPlan {
        grants: Vec::new(),
        direct_recipient_ids: vec![owner.principal_id()],
        witness_policy_digest: None,
    };
    let state = ItemStateV1 {
        plaintext_schema: 1,
        fields: vec![ItemFieldV1 {
            name: "token".to_owned(),
            field_id: FieldId::from_bytes([0x41; 32])?,
            value: ItemFieldValue::new(b"ExampleSecret".to_vec())?,
            decoded_length: 13,
            kind: ItemFieldKind::Concealed,
            created_at_ms: 20,
            updated_at_ms: 20,
        }],
    };
    let mut items = ItemCreator::new(ProtectionPolicy::EmergencyAllowDegraded);
    let prepared_item = items.prepare_create(
        &policy,
        &owner,
        20,
        NewItem {
            kind: ItemKind::Canonical,
            descriptor: ItemDescriptorV1::new("ExampleItem".to_owned())?,
            state,
            bucket_id: 1,
            access,
        },
        &ItemArtifactInventory::default(),
    )?;
    let item_id = prepared_item.envelope.item_id;
    let rejected_revision =
        policy.prepare_revision(&owner, 20, prepared_item.policy.revision.operations.clone())?;
    let rejected = VaultMutationPlan::from_prepared(
        &current,
        &[],
        rejected_revision,
        vec![prepared_item.envelope.clone()],
        20,
        DirectDowngradeAcknowledgement::Absent,
        MutationKind::Item,
    );
    assert!(matches!(
        rejected,
        Err(error)
            if error.kind() == MutationErrorKind::DirectDowngradeRequiresAcknowledgement
    ));
    let plan = VaultMutationPlan::prepare_item_batch(
        &current,
        &[],
        &owner,
        20,
        Vec::new(),
        vec![prepared_item],
        DirectDowngradeAcknowledgement::Acknowledged,
        MutationKind::Item,
    )?;

    assert_eq!(plan.touched_items(), &[item_id]);
    assert_eq!(plan.target_artifact().items.len(), 1);
    assert!(plan.target_policy().item(&item_id).is_some());
    assert_eq!(
        replay_policy_with_witness_policies(&plan.target_artifact().policy, &[])?,
        *plan.target_policy()
    );
    assert!(
        !plan
            .target_policy()
            .access(&item_id, &owner.principal_id(), Capability::Read)
            .carries_quorum_claim
    );
    assert!(plan.warnings().item_quorum_claim_suppressed);
    assert_eq!(
        VaultFileV1::parse(plan.target_bytes())?,
        *plan.target_artifact()
    );
    assert_eq!(
        plan.audit_intent().item.map(|item| item.item_id),
        Some(item_id)
    );

    let current_with_item = plan.target_artifact().clone();
    let current_policy = replay_policy_with_witness_policies(&current_with_item.policy, &[])?;
    let cover_state = ItemStateV1 {
        plaintext_schema: 1,
        fields: vec![ItemFieldV1 {
            name: "token".to_owned(),
            field_id: FieldId::from_bytes([0x41; 32])?,
            value: ItemFieldValue::new(b"ExampleSecret".to_vec())?,
            decoded_length: 13,
            kind: ItemFieldKind::Concealed,
            created_at_ms: 20,
            updated_at_ms: 20,
        }],
    };
    let cover_access = ItemAccessPlan {
        grants: Vec::new(),
        direct_recipient_ids: vec![owner.principal_id()],
        witness_policy_digest: None,
    };
    let cover = items.prepare_rekey(
        &current_policy,
        &owner,
        30,
        &current_with_item.items[0],
        RekeyedItem {
            descriptor: ItemDescriptorV1::new("ExampleItem".to_owned())?,
            state: cover_state,
            bucket_id: 1,
            access: cover_access,
            principal_replacement: None,
            principal_registration: None,
            owner_change: None,
        },
        &ItemArtifactInventory::from_vault(&current_with_item)?,
    )?;
    let cover_plan = VaultMutationPlan::prepare_item_batch(
        &current_with_item,
        &[],
        &owner,
        30,
        Vec::new(),
        vec![cover],
        DirectDowngradeAcknowledgement::Absent,
        MutationKind::PrivacyCover,
    )?;
    assert_eq!(
        cover_plan.target_artifact().items[0]
            .current_revision
            .bucket_id,
        1
    );
    assert_eq!(
        cover_plan.target_artifact().items[0]
            .current_revision
            .item_revision,
        2
    );
    Ok(())
}

#[test]
fn multi_item_owner_grant_and_revoke_rotate_once_with_one_owner_operation() -> TestResult {
    let (owner, current) = fixture()?;
    let UnlockedIdentity::VaultPrincipal(candidate) = unlocked_identity_for_test(
        PrincipalId::from_bytes([0x22; 32])?,
        PrincipalKind::Human,
        &mut CounterRandom(0x80),
    )?
    else {
        return Err("candidate identity role differs".into());
    };
    let candidate_descriptor = candidate.public_descriptor()?;
    let policy = replay_policy_with_witness_policies(&current.policy, &[])?;
    let state = ItemStateV1 {
        plaintext_schema: 1,
        fields: Vec::new(),
    };
    let mut items = ItemCreator::new(ProtectionPolicy::EmergencyAllowDegraded);
    let created_items = ["ExampleOne", "ExampleTwo"]
        .into_iter()
        .map(|name| -> TestResult<_> {
            Ok(items
                .prepare_create(
                    &policy,
                    &owner,
                    20,
                    NewItem {
                        kind: ItemKind::Canonical,
                        descriptor: ItemDescriptorV1::new(name.to_owned())?,
                        state: state.clone(),
                        bucket_id: 1,
                        access: ItemAccessPlan {
                            grants: Vec::new(),
                            direct_recipient_ids: vec![owner.principal_id()],
                            witness_policy_digest: None,
                        },
                    },
                    &ItemArtifactInventory::default(),
                )
                .map_err(|error| format!("prepare owner fixture item: {error:?}"))?)
        })
        .collect::<TestResult<Vec<_>>>()?;
    let item_names = created_items
        .iter()
        .zip(["ExampleOne", "ExampleTwo"])
        .map(|(item, name)| (item.envelope.item_id, name))
        .collect::<BTreeMap<_, _>>();
    let created = VaultMutationPlan::prepare_item_batch(
        &current,
        &[],
        &owner,
        20,
        Vec::new(),
        created_items,
        DirectDowngradeAcknowledgement::Acknowledged,
        MutationKind::Item,
    )?;
    let registered = VaultMutationPlan::prepare_policy(
        created.target_artifact(),
        &[],
        &owner,
        30,
        vec![PolicyOperationV1::PrincipalAdd {
            descriptor: candidate_descriptor,
            display_label: "second-owner".to_owned(),
            registration_proof_digest: Digest32::new([0x61; 32]),
        }],
        DirectDowngradeAcknowledgement::Absent,
        MutationKind::Policy,
    )?;
    let registered_vault = registered.target_artifact();
    let registered_policy = registered.target_policy();
    let inventory = ItemArtifactInventory::from_vault(registered_vault)?;
    let grant_items = registered_vault
        .items
        .iter()
        .map(|envelope| -> TestResult<_> {
            Ok(items
                .prepare_rekey_batch_component(
                    registered_policy,
                    &owner,
                    40,
                    envelope,
                    RekeyedItem {
                        descriptor: ItemDescriptorV1::new(
                            item_names
                                .get(&envelope.item_id)
                                .ok_or("item name absent")?
                                .to_string(),
                        )?,
                        state: state.clone(),
                        bucket_id: 1,
                        access: ItemAccessPlan {
                            grants: Vec::new(),
                            direct_recipient_ids: vec![
                                owner.principal_id(),
                                candidate.principal_id(),
                            ],
                            witness_policy_digest: None,
                        },
                        principal_replacement: None,
                        principal_registration: None,
                        owner_change: Some(OwnerChange::Grant(candidate.principal_id())),
                    },
                    &inventory,
                )
                .map_err(|error| format!("prepare owner grant: {error:?}"))?)
        })
        .collect::<TestResult<Vec<_>>>()?;
    let granted = VaultMutationPlan::prepare_item_component_batch(
        registered_vault,
        &[],
        &owner,
        40,
        Vec::new(),
        grant_items,
        DirectDowngradeAcknowledgement::Acknowledged,
        MutationKind::Policy,
    )?;
    assert!(granted.target_policy().is_owner(&candidate.principal_id()));
    assert_eq!(
        granted
            .target_artifact()
            .policy
            .revisions
            .last()
            .ok_or("grant revision absent")?
            .operations
            .iter()
            .filter(|operation| matches!(operation, PolicyOperationV1::OwnerGrant { .. }))
            .count(),
        1
    );
    for item in granted.target_policy().items().map(|(_, item)| item) {
        assert_eq!(item.direct_slots.len(), 4);
        assert!(item.grants.is_empty());
    }

    let granted_vault = granted.target_artifact();
    let granted_policy = granted.target_policy();
    let inventory = ItemArtifactInventory::from_vault(granted_vault)?;
    let revoke_items = granted_vault
        .items
        .iter()
        .map(|envelope| -> TestResult<_> {
            Ok(items
                .prepare_rekey_batch_component(
                    granted_policy,
                    &owner,
                    50,
                    envelope,
                    RekeyedItem {
                        descriptor: ItemDescriptorV1::new(
                            item_names
                                .get(&envelope.item_id)
                                .ok_or("item name absent")?
                                .to_string(),
                        )?,
                        state: state.clone(),
                        bucket_id: 1,
                        access: ItemAccessPlan {
                            grants: Vec::new(),
                            direct_recipient_ids: vec![owner.principal_id()],
                            witness_policy_digest: None,
                        },
                        principal_replacement: None,
                        principal_registration: None,
                        owner_change: Some(OwnerChange::Revoke(candidate.principal_id())),
                    },
                    &inventory,
                )
                .map_err(|error| format!("prepare owner revoke: {error:?}"))?)
        })
        .collect::<TestResult<Vec<_>>>()?;
    let revoked = VaultMutationPlan::prepare_item_component_batch(
        granted_vault,
        &[],
        &owner,
        50,
        Vec::new(),
        revoke_items,
        DirectDowngradeAcknowledgement::Absent,
        MutationKind::Policy,
    )?;
    assert!(!revoked.target_policy().is_owner(&candidate.principal_id()));
    assert_eq!(revoked.target_policy().owner_count(), 1);
    assert_eq!(
        revoked
            .target_artifact()
            .policy
            .revisions
            .last()
            .ok_or("revoke revision absent")?
            .operations
            .iter()
            .filter(|operation| matches!(operation, PolicyOperationV1::OwnerRevoke { .. }))
            .count(),
        1
    );
    for item in revoked.target_policy().items().map(|(_, item)| item) {
        assert_eq!(item.direct_slots.len(), 2);
        assert!(item.grants.is_empty());
    }
    Ok(())
}

#[test]
fn oversized_batch_returns_capacity_before_any_artifact_change() -> TestResult {
    let (owner, current) = fixture()?;
    let before = current.to_json_bytes()?;
    let policy = replay_policy_with_witness_policies(&current.policy, &[])?;
    let access = ItemAccessPlan {
        grants: Vec::new(),
        direct_recipient_ids: vec![owner.principal_id()],
        witness_policy_digest: None,
    };
    let state = ItemStateV1 {
        plaintext_schema: 1,
        fields: vec![ItemFieldV1 {
            name: "payload".to_owned(),
            field_id: FieldId::from_bytes([0x51; 32])?,
            value: ItemFieldValue::new(b"ExampleValue".to_vec())?,
            decoded_length: 12,
            kind: ItemFieldKind::Concealed,
            created_at_ms: 20,
            updated_at_ms: 20,
        }],
    };
    let mut items = ItemCreator::new(ProtectionPolicy::EmergencyAllowDegraded);
    let first = items.prepare_create(
        &policy,
        &owner,
        20,
        NewItem {
            kind: ItemKind::Canonical,
            descriptor: ItemDescriptorV1::new("ExampleLargeOne".to_owned())?,
            state: state.clone(),
            bucket_id: 12,
            access: access.clone(),
        },
        &ItemArtifactInventory::default(),
    )?;
    let second = items.prepare_create(
        &policy,
        &owner,
        20,
        NewItem {
            kind: ItemKind::Canonical,
            descriptor: ItemDescriptorV1::new("ExampleLargeTwo".to_owned())?,
            state,
            bucket_id: 12,
            access,
        },
        &ItemArtifactInventory::default(),
    )?;

    let result = VaultMutationPlan::prepare_item_batch(
        &current,
        &[],
        &owner,
        20,
        Vec::new(),
        vec![first, second],
        DirectDowngradeAcknowledgement::Acknowledged,
        MutationKind::Item,
    );
    assert!(matches!(
        result,
        Err(error) if error.kind() == MutationErrorKind::CapacityExhausted
    ));
    assert_eq!(current.to_json_bytes()?, before);
    Ok(())
}
use std::collections::BTreeMap;
