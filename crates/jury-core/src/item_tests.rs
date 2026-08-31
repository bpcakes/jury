use super::*;

use jury_protected::{ProtectedMemory, ProtectionPolicy};
use jury_protocol::{
    identity_v1::KdfProfile,
    vault_v1::{ItemFieldKind, ItemFieldV1, ItemFieldValue},
};

use crate::identity::{IdentityCreator, UnlockedIdentity, unlock};
use crate::policy::PolicyCreator;

struct FillByte(u8);

impl RandomSource for FillByte {
    fn fill(&mut self, destination: &mut [u8]) -> Result<(), jury_protected::EntropyError> {
        destination.fill(self.0);
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
    assert!(matches!(
        failed_result,
        Err(error) if error.kind() == ItemErrorKind::EntropyUnavailable
    ));
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
    assert!(matches!(
        zero_result,
        Err(error) if error.kind() == ItemErrorKind::RetryExhausted
    ));
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
    let created_slots = match &created_item.policy.revision.operations[0] {
        PolicyOperationV1::ItemCreate { direct_slots, .. } => direct_slots,
        _ => return Err("item create operation differs".into()),
    };
    let descriptor_slot = created_slots
        .iter()
        .find(|slot| slot.content_role == ContentRole::Descriptor)
        .ok_or("descriptor slot absent")?;
    let body_slot = created_slots
        .iter()
        .find(|slot| slot.content_role == ContentRole::Body)
        .ok_or("body slot absent")?;
    let descriptor_secret = owner.open_direct_slot(descriptor_slot)?;
    let retained_body_secret = owner.open_direct_slot(body_slot)?;
    assert!(open_descriptor(&created_item.envelope, &descriptor_secret)? == descriptor);
    assert!(open_body(&created_item.envelope, &retained_body_secret)? == state);
    let mut wrong_item = created_item.envelope.clone();
    wrong_item.item_id = ItemId::from_bytes([0x5a; 32])?;
    assert!(matches!(
        open_body(&wrong_item, &retained_body_secret),
        Err(error) if error.kind() == ItemErrorKind::AuthenticationFailed
    ));
    let mut wrong_seal = created_item.envelope.clone();
    wrong_seal.current_revision.revision_seal_id = RevisionSealId::from_bytes([0x5b; 32])?;
    assert!(matches!(
        open_body(&wrong_seal, &retained_body_secret),
        Err(error) if error.kind() == ItemErrorKind::AuthenticationFailed
    ));
    verify_item_ancestry(&created_item.envelope, |principal_id| {
        (principal_id == owner.principal_id())
            .then(|| created.descriptor.verification_public_key.clone())
    })?;

    let mut collision_inventory = ItemArtifactInventory::default();
    collision_inventory
        .revision_seal_ids
        .insert(created_item.envelope.descriptor.revision_seal_id);
    collision_inventory
        .revision_seal_ids
        .insert(created_item.envelope.current_revision.revision_seal_id);
    collision_inventory
        .nonces
        .insert(created_item.envelope.descriptor.nonce.clone());
    collision_inventory
        .nonces
        .insert(created_item.envelope.current_revision.nonce.clone());
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
    assert!(matches!(
        exhausted,
        Err(error) if error.kind() == ItemErrorKind::RetryExhausted
    ));
    assert_eq!(created_item.policy.state.item_count(), 1);

    let mut inventory = ItemArtifactInventory::default();
    inventory
        .revision_seal_ids
        .insert(created_item.envelope.descriptor.revision_seal_id);
    inventory
        .revision_seal_ids
        .insert(created_item.envelope.current_revision.revision_seal_id);
    inventory
        .nonces
        .insert(created_item.envelope.descriptor.nonce.clone());
    inventory
        .nonces
        .insert(created_item.envelope.current_revision.nonce.clone());
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
            },
            &inventory,
        )
        .map_err(|error| format!("prepare rekey: {error:?}"))?;
    let stale_open = open_body(&rekeyed.envelope, &retained_body_secret);
    assert!(matches!(
        stale_open,
        Err(error) if error.kind() == ItemErrorKind::AuthenticationFailed
    ));
    let rekeyed_slots = rekeyed
        .policy
        .revision
        .operations
        .iter()
        .find_map(|operation| match operation {
            PolicyOperationV1::ItemSlotsReplace { direct_slots, .. } => Some(direct_slots),
            _ => None,
        })
        .ok_or("replacement slots absent")?;
    let new_body_slot = rekeyed_slots
        .iter()
        .find(|slot| slot.content_role == ContentRole::Body)
        .ok_or("replacement body slot absent")?;
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
    inventory
        .revision_seal_ids
        .insert(rekeyed.envelope.descriptor.revision_seal_id);
    inventory
        .revision_seal_ids
        .insert(rekeyed.envelope.current_revision.revision_seal_id);
    inventory
        .nonces
        .insert(rekeyed.envelope.descriptor.nonce.clone());
    inventory
        .nonces
        .insert(rekeyed.envelope.current_revision.nonce.clone());
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
        },
        &inventory,
    )?;
    assert!(replaced.policy.state.is_owner(&next_owner.principal_id()));
    assert!(!replaced.policy.state.is_owner(&owner.principal_id()));
    assert!(matches!(
        open_body(&replaced.envelope, &new_body_secret),
        Err(error) if error.kind() == ItemErrorKind::AuthenticationFailed
    ));
    let replaced_slots = replaced
        .policy
        .revision
        .operations
        .iter()
        .find_map(|operation| match operation {
            PolicyOperationV1::ItemSlotsReplace { direct_slots, .. } => Some(direct_slots),
            _ => None,
        })
        .ok_or("principal replacement slots absent")?;
    let replaced_body_slot = replaced_slots
        .iter()
        .find(|slot| slot.content_role == ContentRole::Body)
        .ok_or("principal replacement body slot absent")?;
    let replaced_body_secret = next_owner.open_direct_slot(replaced_body_slot)?;
    assert!(open_body(&replaced.envelope, &replaced_body_secret)? == state);
    inventory
        .revision_seal_ids
        .insert(replaced.envelope.descriptor.revision_seal_id);
    inventory
        .revision_seal_ids
        .insert(replaced.envelope.current_revision.revision_seal_id);
    inventory
        .nonces
        .insert(replaced.envelope.descriptor.nonce.clone());
    inventory
        .nonces
        .insert(replaced.envelope.current_revision.nonce.clone());
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
fn witnessed_only_capsules_reconstruct_only_the_selected_revision_secret()
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
    let mut created_policy = policies.create(&owner, 1, |_| false)?;
    let (mut witness_policy, _, _) = crate::policy::witness_tests::frozen_policy()?;

    let mut witness_private_keys = Vec::new();
    let mut additions = Vec::new();
    for (index, descriptor) in witness_policy.witness_descriptors.iter().enumerate() {
        let marker = 0x61_u8.saturating_add(u8::try_from(index)?);
        let (private, public) =
            crypto::generate_recipient_keypair(protection, &mut FillByte(marker))?;
        assert!(public == descriptor.contribution_public_key);
        witness_private_keys.push(private);
        additions.push(principal_add(
            descriptor.witness_id,
            PrincipalKind::Witness,
            public,
            0x31_u8.saturating_add(u8::try_from(index)?),
        )?);
    }
    for (index, descriptor) in witness_policy.approver_descriptors.iter().enumerate() {
        let (_, recipient) = crypto::generate_recipient_keypair(
            protection,
            &mut FillByte(0x71_u8.saturating_add(u8::try_from(index)?)),
        )?;
        additions.push(principal_add(
            descriptor.approver_id,
            PrincipalKind::Approver,
            recipient,
            0x21_u8.saturating_add(u8::try_from(index)?),
        )?);
    }
    additions.sort_by_key(|operation| match operation {
        PolicyOperationV1::PrincipalAdd { descriptor, .. } => descriptor.principal_id,
        _ => owner.principal_id(),
    });
    let added = created_policy
        .state
        .prepare_revision(&owner, 2, additions)?;
    created_policy.journal.revisions.push(added.revision);
    witness_policy.vault_id = created_policy.state.vault_id();
    witness_policy.genesis_fingerprint = created_policy.state.genesis_fingerprint().clone();
    witness_policy.vault_policy_sequence = 2;
    let witness_digest = witness_policy.digest()?;
    let policy = crate::policy::replay_policy_with_witness_policies(
        &created_policy.journal,
        std::slice::from_ref(&witness_policy),
    )?;

    let descriptor = ItemDescriptorV1::new("ExampleWitnessedItem".to_owned())?;
    let state = ItemStateV1 {
        plaintext_schema: 1,
        fields: Vec::new(),
    };
    let mut items = ItemCreator::new(protection);
    let created_item = items.prepare_create(
        &policy,
        &owner,
        3,
        NewItem {
            kind: ItemKind::Canonical,
            descriptor: descriptor.clone(),
            state: state.clone(),
            bucket_id: 1,
            access: ItemAccessPlan {
                grants: Vec::new(),
                direct_recipient_ids: Vec::new(),
                witness_policy_digest: Some(witness_digest.clone()),
            },
        },
        &ItemArtifactInventory::default(),
    )?;
    let witnessed = created_item
        .policy
        .revision
        .operations
        .iter()
        .find_map(|operation| match operation {
            PolicyOperationV1::ItemCreate {
                direct_slots,
                witnessed_state,
                ..
            } if direct_slots.is_empty() => witnessed_state.as_ref(),
            _ => None,
        })
        .ok_or("witnessed-only slots absent")?;
    assert!(witnessed.has_item_quorum_claim(0));
    let descriptor_secret =
        reconstruct_slot_secret(&witnessed.slots[0], &witness_private_keys, protection)?;
    let body_secret =
        reconstruct_slot_secret(&witnessed.slots[1], &witness_private_keys, protection)?;
    assert!(open_descriptor(&created_item.envelope, &descriptor_secret)? == descriptor);
    assert!(open_body(&created_item.envelope, &body_secret)? == state);
    assert!(matches!(
        open_body(&created_item.envelope, &descriptor_secret),
        Err(error) if error.kind() == ItemErrorKind::AuthenticationFailed
    ));

    let partial_secret = reconstruct_slot_secret_with_count(
        &witnessed.slots[1],
        &witness_private_keys,
        protection,
        1,
    );
    assert!(partial_secret.is_err());

    let mixed = items.prepare_create(
        &policy,
        &owner,
        3,
        NewItem {
            kind: ItemKind::Canonical,
            descriptor: descriptor.clone(),
            state: state.clone(),
            bucket_id: 1,
            access: ItemAccessPlan {
                grants: Vec::new(),
                direct_recipient_ids: vec![owner.principal_id()],
                witness_policy_digest: Some(witness_digest.clone()),
            },
        },
        &ItemArtifactInventory::default(),
    )?;
    let (mixed_direct, mixed_witnessed) = mixed
        .policy
        .revision
        .operations
        .iter()
        .find_map(|operation| match operation {
            PolicyOperationV1::ItemCreate {
                direct_slots,
                witnessed_state: Some(witnessed_state),
                ..
            } => Some((direct_slots, witnessed_state)),
            _ => None,
        })
        .ok_or("mixed slots absent")?;
    assert!(!mixed_direct.is_empty());
    assert!(!mixed_witnessed.has_item_quorum_claim(mixed_direct.len()));

    let mut duplicate_operation = created_item.policy.revision.operations[0].clone();
    if let PolicyOperationV1::ItemCreate {
        witnessed_state: Some(state),
        ..
    } = &mut duplicate_operation
    {
        state.slots[0].capsules[1] = state.slots[0].capsules[0].clone();
        state.slots[0].capsule_set_digest = state.slots[0].recomputed_capsule_set_digest()?;
        state.digest = state.recomputed_digest()?;
    }
    assert!(
        jury_protocol::vault_v1::validate_policy_operation_context(
            &duplicate_operation,
            2,
            &policy.vault_id(),
            policy.genesis_fingerprint(),
        )
        .is_err()
    );

    let mut next_witness_policy = witness_policy.clone();
    next_witness_policy.revision = 2;
    next_witness_policy.predecessor_policy_digest = witness_digest;
    next_witness_policy.vault_policy_sequence = 3;
    next_witness_policy.vault_policy_hash = FixedBytes::new([0x73; 32]);
    let next_witness_digest = next_witness_policy.digest()?;
    let mut journal = created_policy.journal.clone();
    journal.revisions.push(created_item.policy.revision.clone());
    let rekey_policy = crate::policy::replay_policy_with_witness_policies(
        &journal,
        &[witness_policy, next_witness_policy],
    )?;
    let mut inventory = ItemArtifactInventory::default();
    inventory
        .revision_seal_ids
        .insert(created_item.envelope.descriptor.revision_seal_id);
    inventory
        .revision_seal_ids
        .insert(created_item.envelope.current_revision.revision_seal_id);
    inventory
        .nonces
        .insert(created_item.envelope.descriptor.nonce.clone());
    inventory
        .nonces
        .insert(created_item.envelope.current_revision.nonce.clone());
    inventory
        .slot_ids
        .extend(witnessed.slots.iter().map(|slot| slot.slot_id));
    let rekeyed = items.prepare_rekey(
        &rekey_policy,
        &owner,
        4,
        &created_item.envelope,
        RekeyedItem {
            descriptor,
            state: state.clone(),
            bucket_id: 1,
            access: ItemAccessPlan {
                grants: Vec::new(),
                direct_recipient_ids: Vec::new(),
                witness_policy_digest: Some(next_witness_digest),
            },
            principal_replacement: None,
        },
        &inventory,
    )?;
    let replacement = rekeyed
        .policy
        .revision
        .operations
        .iter()
        .find_map(|operation| match operation {
            PolicyOperationV1::ItemSlotsReplace {
                witnessed_state: Some(state),
                ..
            } => Some(state),
            _ => None,
        })
        .ok_or("witnessed replacement absent")?;
    let next_body_secret =
        reconstruct_slot_secret(&replacement.slots[1], &witness_private_keys, protection)?;
    assert!(matches!(
        open_body(&rekeyed.envelope, &body_secret),
        Err(error) if error.kind() == ItemErrorKind::AuthenticationFailed
    ));
    assert!(open_body(&rekeyed.envelope, &next_body_secret)? == state);
    Ok(())
}

fn principal_add(
    principal_id: PrincipalId,
    kind: PrincipalKind,
    recipient_public_key: RecipientPublicKey1216,
    signing_seed: u8,
) -> Result<PolicyOperationV1, Box<dyn std::error::Error>> {
    let seed = [signing_seed; 32];
    let mut descriptor = jury_protocol::vault_v1::PrincipalDescriptorV1 {
        descriptor_version: 1,
        principal_id,
        principal_kind: kind,
        recipient_public_key,
        verification_public_key: crypto::verification_public_key_bytes(&seed)?,
        self_signature: Signature64::new([0; 64]),
    };
    descriptor.self_signature = crypto::sign_bytes(&seed, &descriptor.self_signature_preimage()?)?;
    Ok(PolicyOperationV1::PrincipalAdd {
        descriptor,
        display_label: format!("Example{signing_seed}"),
        registration_proof_digest: FixedBytes::new([signing_seed; 32]),
    })
}

fn reconstruct_slot_secret(
    slot: &WitnessedSlotV1,
    private_keys: &[ProtectedMemory],
    protection: ProtectionPolicy,
) -> Result<ProtectedRevisionSecret, Box<dyn std::error::Error>> {
    reconstruct_slot_secret_with_count(slot, private_keys, protection, usize::from(slot.threshold))
}

fn reconstruct_slot_secret_with_count(
    slot: &WitnessedSlotV1,
    private_keys: &[ProtectedMemory],
    protection: ProtectionPolicy,
    count: usize,
) -> Result<ProtectedRevisionSecret, Box<dyn std::error::Error>> {
    let mut shares = Zeroizing::new(Vec::new());
    for (capsule, private) in slot.capsules.iter().zip(private_keys).take(count) {
        let share = crypto::open_hpke(
            private,
            &capsule.encapsulation,
            capsule.ciphertext.as_bytes(),
            &capsule.info_preimage(),
            &capsule.aad_preimage(),
            33,
        )?;
        let bytes = share.expose(<[u8]>::to_vec)?;
        shares.push(bytes);
    }
    let reconstructed = Zeroizing::new(
        Gf256::combine_bytes(shares.as_slice())
            .map_err(|error| format!("combine witnessed shares: {error:?}"))?,
    );
    Ok(ProtectedRevisionSecret {
        bytes: protect(&reconstructed, protection)?,
    })
}
