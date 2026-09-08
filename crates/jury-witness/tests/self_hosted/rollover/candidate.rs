use super::*;
use jury_core::{
    access_provider::{DirectItemAccessProvider, NeverCancelled},
    identity::{UnlockedIdentity, unlock},
    item::{ItemAccessPlan, ItemArtifactInventory, ItemCreator, NewItem, RekeyedItem},
    policy::{
        AutomaticReadTarget, OperationRule, PlatformAssurance, PolicyCreator, WitnessOperation,
        WitnessPolicy, replay_policy_with_witness_policies,
    },
    registration::{
        RegistrationCreator, RegistrationRoleDescriptorV1, answer_challenge,
        answer_rollover_challenge, verify_proof,
    },
    rollover::{GovernedRolloverOptions, RolloverSource},
    transfer::TransferPublicCatalogV1,
    witness_client::VaultPolicyCheckpointCreator,
};
use jury_protocol::{
    identity_v1::IdentityFileV1,
    vault_v1::{
        ContentRole, ItemDescriptorV1, ItemKind, ItemStateV1, PolicyOperationV1, VaultFileV1,
        VaultHeaderV1, WitnessPolicyId,
    },
    witness_v1::owner_review_label_set_digest,
};

pub(super) fn prepare(identity_file: &Path) -> Result<Registration, Box<dyn Error>> {
    let protection = ProtectionPolicy::Strict;
    let passphrase = ProtectedMemory::initialize(PASSPHRASE.len(), protection, |bytes| {
        bytes.copy_from_slice(PASSPHRASE);
        Ok::<_, ()>(bytes.len())
    })?;
    let primary = unlock(
        &IdentityFileV1::parse(&fs::read(identity_file)?)?,
        &passphrase,
    )?;
    let primary_id = primary.public_descriptor()?.principal_id;
    let owner_file = IdentityCreator::new().create(
        PrincipalKind::Human,
        KdfProfile::PortableV1,
        now()?,
        &passphrase,
        |_| false,
    )?;
    let UnlockedIdentity::VaultPrincipal(owner) = unlock(&owner_file.file, &passphrase)? else {
        return Err("expected fixture owner".into());
    };
    let secondary_file = IdentityCreator::new().create(
        PrincipalKind::Witness,
        KdfProfile::PortableV1,
        now()?,
        &passphrase,
        |_| false,
    )?;
    let secondary = unlock(&secondary_file.file, &passphrase)?;
    let identities = [primary, secondary];
    let mut created = PolicyCreator::new().create(&owner, now()?, |_| false)?;
    let mut proofs = Vec::new();
    for (index, identity) in identities.iter().enumerate() {
        let challenge = RegistrationCreator::new(protection).create_challenge(
            &created.state,
            &owner,
            identity.public_descriptor()?,
            now()?,
            300_000,
            Some(u8::try_from(index + 1)?),
        )?;
        let proof = answer_challenge(&created.state, identity, &challenge, now()?)?;
        verify_proof(&created.state, &owner, &challenge, &proof, now()?)?;
        proofs.push(proof);
    }
    proofs.sort_by_key(|proof| proof.candidate_principal_id);
    let additions = proofs
        .iter()
        .map(|proof| {
            Ok(PolicyOperationV1::PrincipalAdd {
                descriptor: proof.challenge.candidate_descriptor.clone(),
                display_label: format!(
                    "ExampleWitness{}",
                    if proof.candidate_principal_id == primary_id {
                        1
                    } else {
                        2
                    }
                ),
                registration_proof_digest: proof.digest()?,
            })
        })
        .collect::<Result<Vec<_>, jury_core::registration::RegistrationError>>()?;
    let admitted = created.state.prepare_revision(&owner, now()?, additions)?;
    created.journal.revisions.push(admitted.revision);
    let empty_body = || ItemStateV1 {
        plaintext_schema: 1,
        fields: Vec::new(),
    };
    let direct = ItemCreator::new(protection).prepare_create(
        &admitted.state,
        &owner,
        now()?,
        NewItem {
            kind: ItemKind::Canonical,
            descriptor: ItemDescriptorV1::new("ExampleItem".into())?,
            state: empty_body(),
            bucket_id: 1,
            access: ItemAccessPlan {
                grants: Vec::new(),
                direct_recipient_ids: vec![owner.principal_id()],
                witness_policy_digest: None,
            },
        },
        &ItemArtifactInventory::default(),
    )?;
    created.journal.revisions.push(direct.policy.revision);
    let witnesses = proofs
        .iter()
        .map(|proof| match &proof.role_descriptor {
            RegistrationRoleDescriptorV1::Witness { descriptor } => Ok(*descriptor.clone()),
            _ => Err("expected fixture witness"),
        })
        .collect::<Result<Vec<_>, _>>()?;
    let witness_policy = WitnessPolicy {
        schema: 1,
        witness_policy_id: WitnessPolicyId::from_bytes([0x21; 32])?,
        revision: 1,
        predecessor_policy_digest: Digest32::new([0; 32]),
        vault_id: direct.policy.state.vault_id(),
        genesis_fingerprint: direct.policy.state.genesis_fingerprint().clone(),
        vault_policy_sequence: direct.policy.state.sequence() + 1,
        vault_policy_hash: direct.policy.state.terminal_revision_hash().clone(),
        construction: 1,
        suite: 1,
        approver_descriptors: Vec::new(),
        witness_descriptors: witnesses,
        witness_threshold: 2,
        operation_rules: vec![OperationRule {
            operation: WitnessOperation::ReadStdout,
            eligible_approver_ids: Vec::new(),
            approval_threshold: 0,
            allowed_request_lifetime_ms: 300_000,
            max_timeout_ms: 30_000,
            max_output_bytes: 4096,
            max_target_count: 1,
            required_platform_assurance: PlatformAssurance::NormalizedPathOnly,
            automatic_read_targets: vec![AutomaticReadTarget {
                item_id: direct.envelope.item_id,
                content_role: ContentRole::Descriptor,
                field_id: None,
            }],
        }],
        review_label_set_digest: owner_review_label_set_digest(&[])?,
        direct_fallback: false,
    };
    witness_policy.validate()?;
    let policy = replay_policy_with_witness_policies(
        &created.journal,
        std::slice::from_ref(&witness_policy),
    )?;
    let initial = VaultFileV1 {
        header: VaultHeaderV1 {
            magic: "jury-vault".into(),
            version: 1,
            vault_id: policy.vault_id(),
            created_at_ms: created.journal.genesis.created_at_ms,
            suite: 1,
            policy_schema: 1,
            item_schema: 1,
            identity_schema: 1,
            genesis_fingerprint: policy.genesis_fingerprint().clone(),
        },
        policy: created.journal,
        items: vec![direct.envelope],
        suite_migration: None,
    };
    let mixed = ItemCreator::new(protection).prepare_rekey(
        &policy,
        &owner,
        now()?,
        &initial.items[0],
        RekeyedItem {
            descriptor: ItemDescriptorV1::new("ExampleItem".into())?,
            state: empty_body(),
            bucket_id: 1,
            access: ItemAccessPlan {
                grants: Vec::new(),
                direct_recipient_ids: vec![owner.principal_id()],
                witness_policy_digest: Some(witness_policy.digest()?),
            },
            principal_replacement: None,
            principal_registration: None,
            owner_change: None,
        },
        &ItemArtifactInventory::from_vault(&initial)?,
    )?;
    let mut source_vault = initial;
    source_vault.policy.revisions.push(mixed.policy.revision);
    source_vault.items[0] = mixed.envelope;
    let before = source_vault.to_json_bytes()?;
    let catalog = TransferPublicCatalogV1::new(proofs, vec![witness_policy])?;
    let source = RolloverSource::validate(&source_vault, &catalog.witness_policies)?;
    let draft = source.prepare_governed(
        &catalog,
        &owner,
        &mut DirectItemAccessProvider::new(&owner),
        GovernedRolloverOptions {
            created_at_ms: now()?,
            registration_lifetime_ms: 300_000,
            protection,
        },
        &NeverCancelled,
    )?;
    let context = source.verify_registration_draft(draft.registration_journal())?;
    let mut fresh = Vec::new();
    for (challenge, prior_role) in draft.challenges().iter().zip(draft.prior_roles()) {
        let identity = identities
            .iter()
            .find(|identity| {
                identity
                    .public_descriptor()
                    .is_ok_and(|descriptor| descriptor == challenge.candidate_descriptor)
            })
            .ok_or("missing fixture role")?;
        fresh.push(answer_rollover_challenge(
            &context,
            identity,
            challenge,
            prior_role,
            now()?,
        )?);
    }
    let prepared = draft.complete(&source, &catalog, &owner, fresh, now()?, &NeverCancelled)?;
    assert_eq!(source_vault.to_json_bytes()?, before);
    assert_eq!(prepared.vault().policy.revisions.len(), 1);
    assert_ne!(
        prepared.vault().header.vault_id,
        source_vault.header.vault_id
    );
    let policy_material = ReceiptPolicyMaterialV1 {
        schema: 1,
        journal: prepared.vault().policy.clone(),
        witness_policies: prepared.catalog().witness_policies.clone(),
    };
    let checkpoint = VaultPolicyCheckpointCreator::create(
        &policy_material.replay()?,
        Digest32::new([0; 32]),
        &owner,
        now()?,
    )?;
    let proof = prepared
        .catalog()
        .registration_proofs
        .iter()
        .find(|proof| proof.candidate_principal_id == primary_id)
        .ok_or("missing destination proof")?;
    Ok(Registration {
        policy_material,
        checkpoint,
        accepted_registration: RegistrationBytes::new(proof.to_json_bytes()?)?,
    })
}

fn now() -> Result<u64, Box<dyn Error>> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_millis()
        .try_into()?)
}
