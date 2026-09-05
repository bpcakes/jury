//! Release-mode J25 measurements selected by `scripts/check-j25-measurements`.
//!
//! Consumer: J26 release-candidate validation. Feature gated: the bounded
//! public vault and direct-item lifecycle. Defect classes: pathological scale
//! growth, count-limit bypass, unbounded resident memory, and gross timing
//! divergence between equivalent authentication failures. Delete this
//! harness when the active 0.x release leaves support or an equal replacement
//! records these exact production operations and limits.

use std::{env, error::Error, hint::black_box, time::Instant};

use jury_protected::{
    EntropyError, ProtectedMemory, ProtectionPolicy, RandomSource, RuntimeControlStatus,
};
use jury_protocol::{
    backup_v1::{
        AEAD_TAG_BYTES, BACKUP_PREFIX_BYTES, BackupFormatError, BackupHeaderV1, bucket_bytes,
    },
    identity_v1::{
        IdentityFileV1, IdentityHeaderV1, KdfProfile, ProtectionMode, ProviderKind,
        ProviderMetadata,
    },
    vault_v1::{
        AccessRole, Digest32, DirectCiphertext48, Encapsulation1120, FieldId, FixedBytes,
        FormatError, IdentityPayloadCiphertext149, ItemDescriptorV1, ItemFieldKind, ItemFieldV1,
        ItemFieldValue, ItemKind, ItemStateV1, MAX_ITEM_REVISION_PROOFS, MAX_POLICY_REVISIONS,
        Nonce12, PolicyOperationV1, PrincipalId, PrincipalKind, RecipientPublicKey1216, RecoveryId,
        RevisionSealId, RootWrapCiphertext48, Salt16, SignedItemRevisionV1, VaultFileV1,
        VaultHeaderV1, VaultId, VerificationPublicKey32,
    },
};

use crate::{
    access_provider::{DirectItemAccessProvider, NeverCancelled},
    backup::{BackupCreateRequest, BackupCreator, BackupIdentitySource, LocalStateArchive},
    crypto::{hmac_sha256, open_secret_bytes, seal, verify_hmac_sha256},
    domain::{AccessibleCatalog, AccessibleCatalogEntry, ItemId, ItemName, ItemSelector, Role},
    identity::{
        IdentityCreator, UnlockedIdentity, VaultPrincipalIdentity, unlocked_identity_for_test,
    },
    item::{
        ItemAccessPlan, ItemArtifactInventory, ItemCreator, ItemGrant, NewItem,
        PrincipalReplacement, RekeyedItem, verify_item_ancestry,
    },
    local_state::{CheckpointCandidate, PrincipalLocalState},
    mutation::{
        DirectDowngradeAcknowledgement, MutationErrorKind, MutationKind, VaultMutationPlan,
    },
    policy::{PolicyCreator, PolicyErrorKind, PolicyState, replay_policy},
    session::{ParsedVault, SessionAccessOutcome, SessionLimits},
    transfer::{TransferCreator, TransferPublicCatalogV1, ValidatedTransfer},
};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

struct DeterministicRandom(u64);

impl RandomSource for DeterministicRandom {
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

struct BuiltVault {
    owner: VaultPrincipalIdentity,
    policy: PolicyState,
    vault: VaultFileV1,
}

fn fresh_vault() -> TestResult<BuiltVault> {
    let principal_id = PrincipalId::from_bytes([0x21; 32])?;
    let UnlockedIdentity::VaultPrincipal(owner) = unlocked_identity_for_test(
        principal_id,
        PrincipalKind::Human,
        &mut DeterministicRandom(0x4a_32_35_00_00_00_01),
    )?
    else {
        return Err("measurement owner role differs".into());
    };
    let mut creator = PolicyCreator::from_source(DeterministicRandom(0x4a_32_35_00_00_00_02));
    let created = creator.create(&owner, 1, |_| false)?;
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
    Ok(BuiltVault {
        owner,
        policy: created.state,
        vault,
    })
}

fn indexed_bytes<const N: usize>(domain: u8, index: usize) -> [u8; N] {
    let mut bytes = [0_u8; N];
    bytes[0] = domain;
    let encoded = (index as u64).to_be_bytes();
    bytes[N - encoded.len()..].copy_from_slice(&encoded);
    bytes
}

fn add_principals(built: &mut BuiltVault, total: usize) -> TestResult {
    if total == 0 {
        return Err("principal measurement scale is zero".into());
    }
    let mut random = DeterministicRandom(0x4a_32_35_00_00_10_00);
    for index in 1..total {
        let principal_id = PrincipalId::from_bytes(indexed_bytes(0x71, index))?;
        let UnlockedIdentity::VaultPrincipal(candidate) =
            unlocked_identity_for_test(principal_id, PrincipalKind::Human, &mut random)?
        else {
            return Err("measurement principal role differs".into());
        };
        let prepared = built.policy.prepare_revision(
            &built.owner,
            10 + index as u64,
            vec![PolicyOperationV1::PrincipalAdd {
                descriptor: candidate.public_descriptor()?,
                display_label: format!("ExamplePrincipal{index:03}"),
                registration_proof_digest: FixedBytes::new(indexed_bytes(0x72, index)),
            }],
        )?;
        built.vault.policy.revisions.push(prepared.revision);
        built.policy = prepared.state;
    }
    Ok(())
}

fn prepare_item(
    creator: &mut ItemCreator<DeterministicRandom>,
    built: &BuiltVault,
    index: usize,
) -> TestResult<crate::item::PreparedItemMutation> {
    Ok(creator.prepare_create(
        &built.policy,
        &built.owner,
        1_000 + index as u64,
        NewItem {
            kind: ItemKind::Canonical,
            descriptor: ItemDescriptorV1::new(format!("ExampleItem{index:04}"))?,
            state: ItemStateV1 {
                plaintext_schema: 1,
                fields: Vec::new(),
            },
            bucket_id: 1,
            access: ItemAccessPlan {
                grants: Vec::new(),
                direct_recipient_ids: vec![built.owner.principal_id()],
                witness_policy_digest: None,
            },
        },
        &ItemArtifactInventory::default(),
    )?)
}

fn add_items_sequentially(built: &mut BuiltVault, total: usize) -> TestResult {
    let mut creator = ItemCreator::from_source(
        DeterministicRandom(0x4a_32_35_00_00_20_00),
        ProtectionPolicy::EmergencyAllowDegraded,
    );
    for index in 0..total {
        let prepared = prepare_item(&mut creator, built, index)?;
        built.vault.policy.revisions.push(prepared.policy.revision);
        built.policy = prepared.policy.state;
        built.vault.items.push(prepared.envelope);
    }
    built.vault.items.sort_by_key(|item| item.item_id);
    Ok(())
}

fn add_items_in_bounded_batches(built: &mut BuiltVault, total: usize) -> TestResult {
    let mut creator = ItemCreator::from_source(
        DeterministicRandom(0x4a_32_35_00_00_30_00),
        ProtectionPolicy::EmergencyAllowDegraded,
    );
    let mut envelopes = Vec::with_capacity(total);
    for batch_start in (0..total).step_by(256) {
        let batch_end = total.min(batch_start + 256);
        let mut operations = Vec::with_capacity(batch_end - batch_start);
        for index in batch_start..batch_end {
            let prepared = prepare_item(&mut creator, built, index)?;
            operations.extend(prepared.policy.revision.operations);
            envelopes.push(prepared.envelope);
        }
        let prepared =
            built
                .policy
                .prepare_revision(&built.owner, 20_000 + batch_end as u64, operations)?;
        built.vault.policy.revisions.push(prepared.revision);
        built.policy = prepared.state;
    }
    envelopes.sort_by_key(|item| item.item_id);
    built.vault.items = envelopes;
    Ok(())
}

fn measure<T>(
    case: &str,
    count: usize,
    artifact_bytes: Option<usize>,
    operation: impl FnOnce() -> TestResult<T>,
) -> TestResult<T> {
    let started = Instant::now();
    let result = operation()?;
    let elapsed = started.elapsed();
    let record = serde_json::json!({
        "schema": 1,
        "case": case,
        "count": count,
        "operation_ns": elapsed.as_nanos(),
        "artifact_bytes": artifact_bytes,
        "outcome": "accepted",
    });
    println!("J25_MEASUREMENT={record}");
    Ok(result)
}

fn measure_rejection(
    case: &str,
    count: usize,
    artifact_bytes: Option<usize>,
    operation: impl FnOnce() -> TestResult<&'static str>,
) -> TestResult {
    let started = Instant::now();
    let rejection = operation()?;
    let elapsed = started.elapsed();
    let record = serde_json::json!({
        "schema": 1,
        "case": case,
        "count": count,
        "operation_ns": elapsed.as_nanos(),
        "artifact_bytes": artifact_bytes,
        "outcome": "rejected",
        "rejection": rejection,
    });
    println!("J25_MEASUREMENT={record}");
    Ok(())
}

fn public_validation(kind: &str, count: usize) -> TestResult {
    let mut built = fresh_vault()?;
    match kind {
        "principals" => add_principals(&mut built, count)?,
        "items" => add_items_in_bounded_batches(&mut built, count)?,
        _ => return Err("unknown public-validation dimension".into()),
    }
    let bytes = built.vault.to_json_bytes()?;
    let case = format!("public-validation-{kind}-{count}");
    measure(&case, count, Some(bytes.len()), || {
        let parsed = VaultFileV1::parse(black_box(&bytes))?;
        let policy = replay_policy(&parsed.policy)?;
        let validated =
            ParsedVault::new(&policy, &parsed.policy, &parsed.items).validate_public()?;
        black_box(validated.phase());
        Ok(())
    })
}

fn policy_replay(count: usize) -> TestResult {
    let mut built = fresh_vault()?;
    for index in 0..count {
        let (prior_label, next_label) = if index % 2 == 0 {
            ("owner", "ExampleOwner")
        } else {
            ("ExampleOwner", "owner")
        };
        let prepared = built.policy.prepare_revision(
            &built.owner,
            10 + index as u64,
            vec![PolicyOperationV1::PrincipalLabelChange {
                principal_id: built.owner.principal_id(),
                prior_label: prior_label.to_owned(),
                next_label: next_label.to_owned(),
            }],
        )?;
        built.vault.policy.revisions.push(prepared.revision);
        built.policy = prepared.state;
    }
    measure(&format!("policy-replay-{count}"), count, None, || {
        black_box(replay_policy(black_box(&built.vault.policy))?);
        Ok(())
    })
}

fn next_proof(
    owner: &VaultPrincipalIdentity,
    prior: &SignedItemRevisionV1,
    revision: usize,
) -> TestResult<SignedItemRevisionV1> {
    let mut next = prior.clone();
    next.item_revision = revision as u64;
    next.previous_item_revision_hash = prior.recomputed_hash()?;
    next.timestamp_ms = 2_000 + revision as u64;
    next.revision_seal_id = RevisionSealId::from_bytes(indexed_bytes(0x81, revision))?;
    next.nonce = Nonce12::new(indexed_bytes(0x82, revision));
    next.signature = FixedBytes::new([0; 64]);
    next.signature = owner.sign_validated_statement(&next.signature_preimage())?;
    Ok(next)
}

fn item_proofs(count: usize) -> TestResult {
    let (built, envelope) = proof_envelope(count)?;
    let verification_key = built.owner.public_descriptor()?.verification_public_key;
    measure(&format!("item-proofs-{count}"), count, None, || {
        verify_item_ancestry(black_box(&envelope), |principal_id| {
            (principal_id == built.owner.principal_id()).then(|| verification_key.clone())
        })?;
        Ok(())
    })
}

fn descriptor_catalog(count: usize) -> TestResult {
    let entries = (1..=count)
        .map(|index| {
            Ok(AccessibleCatalogEntry::from_decrypted(
                ItemId::from_bytes(indexed_bytes(0x91, index))?,
                ItemName::parse(format!("ExampleItem{index:04}"))?,
                Role::Reader,
            ))
        })
        .collect::<TestResult<Vec<_>>>()?;
    measure(&format!("descriptor-catalog-{count}"), count, None, || {
        let catalog = AccessibleCatalog::try_new(black_box(entries))?;
        if catalog.entries().len() != count {
            return Err("catalog measurement count differs".into());
        }
        black_box(catalog);
        Ok(())
    })
}

fn one_item_unlock() -> TestResult {
    let mut built = fresh_vault()?;
    add_items_sequentially(&mut built, 1)?;
    let candidate = CheckpointCandidate::from_validated(
        &built.policy,
        &built.vault.policy,
        &built.vault.items,
    )?;
    let local = PrincipalLocalState::for_vault_principal(
        &built.owner,
        built.policy.vault_id(),
        built.policy.genesis_fingerprint().clone(),
    )?;
    let initialized = local.initialize(&candidate, 10)?;
    let validated = ParsedVault::new(&built.policy, &built.vault.policy, &built.vault.items)
        .validate_public()?;
    let mut session = validated.start_session(
        built.owner.principal_id(),
        initialized.checkpoint(),
        None,
        SessionLimits::new(10_000, 100_000)?,
        11,
    )?;
    let mut provider = DirectItemAccessProvider::new(&built.owner);
    let item_id = built.vault.items[0].item_id;
    measure("one-item-unlock", 1, None, || {
        if !matches!(
            session.discover_descriptor(&mut provider, item_id, None, 12, &NeverCancelled,)?,
            SessionAccessOutcome::Direct(())
        ) {
            return Err("descriptor unlock did not use direct authority".into());
        }
        let selector = ItemSelector::parse("ExampleItem0000")?;
        if !matches!(
            session.open_item(
                &mut provider,
                &selector,
                crate::domain::Capability::Read,
                None,
                13,
                &NeverCancelled,
            )?,
            SessionAccessOutcome::Direct(_)
        ) {
            return Err("body unlock did not use direct authority".into());
        }
        Ok(())
    })
}

fn initialized_session(
    built: &BuiltVault,
) -> TestResult<(
    crate::session::ValidatedPublicVault<'_>,
    crate::local_state::VerifiedLocalState,
)> {
    let candidate = CheckpointCandidate::from_validated(
        &built.policy,
        &built.vault.policy,
        &built.vault.items,
    )?;
    let local = PrincipalLocalState::for_vault_principal(
        &built.owner,
        built.policy.vault_id(),
        built.policy.genesis_fingerprint().clone(),
    )?;
    let initialized = local.initialize(&candidate, 10)?;
    let validated = ParsedVault::new(&built.policy, &built.vault.policy, &built.vault.items)
        .validate_public()?;
    Ok((validated, initialized))
}

fn ten_item_inject_preflight() -> TestResult {
    let mut built = fresh_vault()?;
    add_items_in_bounded_batches(&mut built, 10)?;
    let (validated, initialized) = initialized_session(&built)?;
    let mut session = validated.start_session(
        built.owner.principal_id(),
        initialized.checkpoint(),
        None,
        SessionLimits::new(10_000, 100_000)?,
        11,
    )?;
    let mut provider = DirectItemAccessProvider::new(&built.owner);
    for envelope in &built.vault.items {
        if !matches!(
            session.discover_descriptor(
                &mut provider,
                envelope.item_id,
                None,
                12,
                &NeverCancelled,
            )?,
            SessionAccessOutcome::Direct(())
        ) {
            return Err("preflight descriptor discovery was not direct".into());
        }
    }
    let selectors = (0..10)
        .map(|index| ItemSelector::parse(format!("ExampleItem{index:04}")))
        .collect::<Result<Vec<_>, _>>()?;
    measure("ten-item-inject-preflight", 10, None, || {
        let item_ids = session.preflight_items(black_box(&selectors), 13)?;
        if item_ids.len() != 10 {
            return Err("inject preflight item count differs".into());
        }
        black_box(item_ids);
        Ok(())
    })
}

fn register_reader(built: &mut BuiltVault, domain: u8) -> TestResult<VaultPrincipalIdentity> {
    let principal_id = PrincipalId::from_bytes(indexed_bytes(domain, 1))?;
    let UnlockedIdentity::VaultPrincipal(reader) = unlocked_identity_for_test(
        principal_id,
        PrincipalKind::Human,
        &mut DeterministicRandom(0x4a_32_35_00_00_40_00 + u64::from(domain)),
    )?
    else {
        return Err("measurement reader role differs".into());
    };
    let prepared = built.policy.prepare_revision(
        &built.owner,
        30_000 + u64::from(domain),
        vec![PolicyOperationV1::PrincipalAdd {
            descriptor: reader.public_descriptor()?,
            display_label: "ExampleReader".to_owned(),
            registration_proof_digest: Digest32::new(indexed_bytes(0xa1, usize::from(domain))),
        }],
    )?;
    built.vault.policy.revisions.push(prepared.revision);
    built.policy = prepared.state;
    Ok(reader)
}

fn empty_item_state() -> ItemStateV1 {
    ItemStateV1 {
        plaintext_schema: 1,
        fields: Vec::new(),
    }
}

fn state_with_payload(bytes: usize) -> TestResult<ItemStateV1> {
    let value = vec![0x45; bytes];
    Ok(ItemStateV1 {
        plaintext_schema: 1,
        fields: vec![ItemFieldV1 {
            name: "EXAMPLE_PAYLOAD".to_owned(),
            field_id: FieldId::from_bytes([0xb1; 32])?,
            decoded_length: u32::try_from(value.len())?,
            value: ItemFieldValue::new(value)?,
            kind: ItemFieldKind::Concealed,
            created_at_ms: 1,
            updated_at_ms: 1,
        }],
    })
}

fn add_custom_item(
    built: &mut BuiltVault,
    name: &str,
    state: ItemStateV1,
    bucket_id: u8,
    grants: Vec<ItemGrant>,
    direct_recipient_ids: Vec<PrincipalId>,
    random_seed: u64,
) -> TestResult {
    let mut creator = ItemCreator::from_source(
        DeterministicRandom(random_seed),
        ProtectionPolicy::EmergencyAllowDegraded,
    );
    let prepared = creator.prepare_create(
        &built.policy,
        &built.owner,
        40_000,
        NewItem {
            kind: ItemKind::Canonical,
            descriptor: ItemDescriptorV1::new(name.to_owned())?,
            state,
            bucket_id,
            access: ItemAccessPlan {
                grants,
                direct_recipient_ids,
                witness_policy_digest: None,
            },
        },
        &ItemArtifactInventory::default(),
    )?;
    built.vault.policy.revisions.push(prepared.policy.revision);
    built.policy = prepared.policy.state;
    built.vault.items.push(prepared.envelope);
    built.vault.items.sort_by_key(|item| item.item_id);
    Ok(())
}

fn reader_grant() -> TestResult {
    let mut built = fresh_vault()?;
    add_items_sequentially(&mut built, 1)?;
    let reader = register_reader(&mut built, 0xa2)?;
    let inventory = ItemArtifactInventory::from_vault(&built.vault)?;
    let prior = built.vault.items[0].clone();
    let owner_id = built.owner.principal_id();
    let reader_id = reader.principal_id();
    measure(
        "reader-grant",
        1,
        Some(built.vault.to_json_bytes()?.len()),
        || {
            let mut creator = ItemCreator::from_source(
                DeterministicRandom(0x4a_32_35_00_00_50_00),
                ProtectionPolicy::EmergencyAllowDegraded,
            );
            let prepared = creator.prepare_rekey(
                &built.policy,
                &built.owner,
                50_000,
                &prior,
                RekeyedItem {
                    descriptor: ItemDescriptorV1::new("ExampleItem0000".to_owned())?,
                    state: empty_item_state(),
                    bucket_id: 1,
                    access: ItemAccessPlan {
                        grants: vec![ItemGrant {
                            principal_id: reader_id,
                            role: AccessRole::Reader,
                        }],
                        direct_recipient_ids: vec![owner_id, reader_id],
                        witness_policy_digest: None,
                    },
                    principal_replacement: None,
                    principal_registration: None,
                    owner_change: None,
                },
                &inventory,
            )?;
            let plan = VaultMutationPlan::prepare_item_batch(
                &built.vault,
                &[],
                &built.owner,
                50_000,
                Vec::new(),
                vec![prepared],
                DirectDowngradeAcknowledgement::Acknowledged,
                MutationKind::Item,
            )?;
            if !plan
                .target_policy()
                .access(&prior.item_id, &reader_id, crate::domain::Capability::Read)
                .allowed
            {
                return Err("reader grant plan does not grant read access".into());
            }
            black_box(plan);
            Ok(())
        },
    )
}

fn read_revocation_reseal(case: &str, payload_bytes: usize, bucket_id: u8) -> TestResult {
    let mut built = fresh_vault()?;
    let reader = register_reader(&mut built, 0xa3)?;
    let owner_id = built.owner.principal_id();
    let reader_id = reader.principal_id();
    let state = state_with_payload(payload_bytes)?;
    add_custom_item(
        &mut built,
        "ExampleRevokedItem",
        state.clone(),
        bucket_id,
        vec![ItemGrant {
            principal_id: reader_id,
            role: AccessRole::Reader,
        }],
        vec![owner_id, reader_id],
        0x4a_32_35_00_00_60_00 + u64::from(bucket_id),
    )?;
    let inventory = ItemArtifactInventory::from_vault(&built.vault)?;
    let prior = built.vault.items[0].clone();
    let artifact_bytes = built.vault.to_json_bytes()?.len();
    measure(case, payload_bytes, Some(artifact_bytes), || {
        let mut creator = ItemCreator::from_source(
            DeterministicRandom(0x4a_32_35_00_00_70_00 + u64::from(bucket_id)),
            ProtectionPolicy::EmergencyAllowDegraded,
        );
        let prepared = creator.prepare_rekey(
            &built.policy,
            &built.owner,
            60_000,
            &prior,
            RekeyedItem {
                descriptor: ItemDescriptorV1::new("ExampleRevokedItem".to_owned())?,
                state,
                bucket_id,
                access: ItemAccessPlan {
                    grants: Vec::new(),
                    direct_recipient_ids: vec![owner_id],
                    witness_policy_digest: None,
                },
                principal_replacement: None,
                principal_registration: None,
                owner_change: None,
            },
            &inventory,
        )?;
        let plan = VaultMutationPlan::prepare_item_batch(
            &built.vault,
            &[],
            &built.owner,
            60_000,
            Vec::new(),
            vec![prepared],
            DirectDowngradeAcknowledgement::Absent,
            MutationKind::Item,
        )?;
        if plan
            .target_policy()
            .access(&prior.item_id, &reader_id, crate::domain::Capability::Read)
            .allowed
        {
            return Err("revocation plan retains reader access".into());
        }
        black_box(plan);
        Ok(())
    })
}

fn add_reader_items(
    built: &mut BuiltVault,
    reader_id: PrincipalId,
    count: usize,
) -> TestResult<std::collections::BTreeMap<jury_protocol::vault_v1::ItemId, String>> {
    let mut creator = ItemCreator::from_source(
        DeterministicRandom(0x4a_32_35_00_00_80_00),
        ProtectionPolicy::EmergencyAllowDegraded,
    );
    let mut mutations = Vec::with_capacity(count);
    let mut names = std::collections::BTreeMap::new();
    for index in 0..count {
        let name = format!("ExampleReplace{index:02}");
        let prepared = creator.prepare_create(
            &built.policy,
            &built.owner,
            70_000,
            NewItem {
                kind: ItemKind::Canonical,
                descriptor: ItemDescriptorV1::new(name.clone())?,
                state: empty_item_state(),
                bucket_id: 1,
                access: ItemAccessPlan {
                    grants: vec![ItemGrant {
                        principal_id: reader_id,
                        role: AccessRole::Reader,
                    }],
                    direct_recipient_ids: vec![built.owner.principal_id(), reader_id],
                    witness_policy_digest: None,
                },
            },
            &ItemArtifactInventory::default(),
        )?;
        names.insert(prepared.envelope.item_id, name);
        mutations.push(prepared);
    }
    let plan = VaultMutationPlan::prepare_item_batch(
        &built.vault,
        &[],
        &built.owner,
        70_000,
        Vec::new(),
        mutations,
        DirectDowngradeAcknowledgement::Acknowledged,
        MutationKind::Item,
    )?;
    built.vault = plan.target_artifact().clone();
    built.policy = plan.target_policy().clone();
    Ok(names)
}

fn multi_item_principal_replacement() -> TestResult {
    let mut built = fresh_vault()?;
    let prior = register_reader(&mut built, 0xa4)?;
    let names = add_reader_items(&mut built, prior.principal_id(), 10)?;
    let next_id = PrincipalId::from_bytes(indexed_bytes(0xa5, 1))?;
    let UnlockedIdentity::VaultPrincipal(next) = unlocked_identity_for_test(
        next_id,
        PrincipalKind::Human,
        &mut DeterministicRandom(0x4a_32_35_00_00_90_00),
    )?
    else {
        return Err("measurement replacement role differs".into());
    };
    let replacement = PrincipalReplacement {
        prior_principal_id: prior.principal_id(),
        next_descriptor: next.public_descriptor()?,
        registration_proof_digest: Digest32::new([0xa6; 32]),
    };
    let inventory = ItemArtifactInventory::from_vault(&built.vault)?;
    let artifact_bytes = built.vault.to_json_bytes()?.len();
    measure(
        "multi-item-principal-replacement",
        built.vault.items.len(),
        Some(artifact_bytes),
        || {
            let mut creator = ItemCreator::from_source(
                DeterministicRandom(0x4a_32_35_00_00_a0_00),
                ProtectionPolicy::EmergencyAllowDegraded,
            );
            let components = built
                .vault
                .items
                .iter()
                .map(|envelope| {
                    Ok(creator.prepare_rekey_batch_component(
                        &built.policy,
                        &built.owner,
                        80_000,
                        envelope,
                        RekeyedItem {
                            descriptor: ItemDescriptorV1::new(
                                names
                                    .get(&envelope.item_id)
                                    .ok_or("replacement item name absent")?
                                    .clone(),
                            )?,
                            state: empty_item_state(),
                            bucket_id: 1,
                            access: ItemAccessPlan {
                                grants: vec![ItemGrant {
                                    principal_id: next.principal_id(),
                                    role: AccessRole::Reader,
                                }],
                                direct_recipient_ids: vec![
                                    built.owner.principal_id(),
                                    next.principal_id(),
                                ],
                                witness_policy_digest: None,
                            },
                            principal_replacement: Some(replacement.clone()),
                            principal_registration: None,
                            owner_change: None,
                        },
                        &inventory,
                    )?)
                })
                .collect::<TestResult<Vec<_>>>()?;
            let plan = VaultMutationPlan::prepare_item_component_batch(
                &built.vault,
                &[],
                &built.owner,
                80_000,
                Vec::new(),
                components,
                DirectDowngradeAcknowledgement::Absent,
                MutationKind::Policy,
            )?;
            if plan
                .target_policy()
                .principal(&prior.principal_id())
                .is_some()
                || plan
                    .target_policy()
                    .principal(&next.principal_id())
                    .is_none()
            {
                return Err("principal replacement state differs".into());
            }
            black_box(plan);
            Ok(())
        },
    )
}

fn near_cap_descendant() -> TestResult<(BuiltVault, VaultFileV1)> {
    let mut built = fresh_vault()?;
    let owner_id = built.owner.principal_id();
    let state = state_with_payload(1_024 * 1_024)?;
    add_custom_item(
        &mut built,
        "ExampleNearCap",
        state.clone(),
        12,
        Vec::new(),
        vec![owner_id],
        0x4a_32_35_00_00_b0_00,
    )?;
    let local = built.vault.clone();
    let inventory = ItemArtifactInventory::from_vault(&built.vault)?;
    let mut creator = ItemCreator::from_source(
        DeterministicRandom(0x4a_32_35_00_00_b1_00),
        ProtectionPolicy::EmergencyAllowDegraded,
    );
    let prepared = creator.prepare_rekey(
        &built.policy,
        &built.owner,
        85_000,
        &built.vault.items[0],
        RekeyedItem {
            descriptor: ItemDescriptorV1::new("ExampleNearCap".to_owned())?,
            state,
            bucket_id: 12,
            access: ItemAccessPlan {
                grants: Vec::new(),
                direct_recipient_ids: vec![owner_id],
                witness_policy_digest: None,
            },
            principal_replacement: None,
            principal_registration: None,
            owner_change: None,
        },
        &inventory,
    )?;
    let plan = VaultMutationPlan::prepare_item_batch(
        &built.vault,
        &[],
        &built.owner,
        85_000,
        Vec::new(),
        vec![prepared],
        DirectDowngradeAcknowledgement::Absent,
        MutationKind::PrivacyCover,
    )?;
    built.vault = plan.target_artifact().clone();
    built.policy = plan.target_policy().clone();
    Ok((built, local))
}

fn transfer_inspect_near_cap() -> TestResult {
    let (built, _) = near_cap_descendant()?;
    let mut creator = TransferCreator::from_source(DeterministicRandom(0x4a_32_35_00_00_c0_00));
    let envelope = creator.create(
        &built.vault,
        TransferPublicCatalogV1::empty(),
        &built.owner,
        90_000,
    )?;
    let bytes = envelope.to_json_bytes()?;
    measure(
        "transfer-inspect-near-file-cap",
        1,
        Some(bytes.len()),
        || {
            let validated = ValidatedTransfer::parse(black_box(&bytes))?;
            black_box(validated.policy().sequence());
            Ok(())
        },
    )
}

fn transfer_dry_run_near_cap() -> TestResult {
    let (built, local) = near_cap_descendant()?;
    let incoming_bytes = built.vault.to_json_bytes()?.len();
    measure(
        "transfer-dry-run-near-file-cap",
        1,
        Some(incoming_bytes),
        || {
            let relation = VaultMutationPlan::preflight_transfer_import(
                black_box(&local),
                black_box(&built.vault),
                &[],
            )?;
            if relation != crate::transfer::ArtifactRelation::IncomingStrictDescendant {
                return Err("near-cap transfer relation differs".into());
            }
            Ok(())
        },
    )
}

fn divergent_transfer_refusal() -> TestResult {
    let mut built = fresh_vault()?;
    let base_vault = built.vault.clone();
    let base_policy = built.policy.clone();
    let owner_id = built.owner.principal_id();
    add_custom_item(
        &mut built,
        "ExampleLeft",
        empty_item_state(),
        1,
        Vec::new(),
        vec![owner_id],
        0x4a_32_35_00_00_d0_00,
    )?;
    let left = built.vault.clone();
    built.vault = base_vault;
    built.policy = base_policy;
    add_custom_item(
        &mut built,
        "ExampleRight",
        empty_item_state(),
        1,
        Vec::new(),
        vec![owner_id],
        0x4a_32_35_00_00_e0_00,
    )?;
    measure_rejection("divergent-transfer-refusal", 2, None, || {
        match VaultMutationPlan::preflight_transfer_import(&left, &built.vault, &[]) {
            Err(error) if error.kind() == MutationErrorKind::TransferDiverged => {
                Ok("transfer-diverged")
            }
            _ => Err("divergent transfer did not produce exact refusal".into()),
        }
    })
}

fn policy_cap_refusal() -> TestResult {
    let mut built = fresh_vault()?;
    for index in 0..MAX_POLICY_REVISIONS {
        let (prior_label, next_label) = if index % 2 == 0 {
            ("owner", "ExampleOwner")
        } else {
            ("ExampleOwner", "owner")
        };
        let prepared = built.policy.prepare_revision(
            &built.owner,
            100_000 + index as u64,
            vec![PolicyOperationV1::PrincipalLabelChange {
                principal_id: built.owner.principal_id(),
                prior_label: prior_label.to_owned(),
                next_label: next_label.to_owned(),
            }],
        )?;
        built.vault.policy.revisions.push(prepared.revision);
        built.policy = prepared.state;
    }
    measure_rejection(
        "hard-cap-refusal-policy-revisions",
        MAX_POLICY_REVISIONS + 1,
        None,
        || match built.policy.prepare_revision(
            &built.owner,
            200_000,
            vec![PolicyOperationV1::PrincipalLabelChange {
                principal_id: built.owner.principal_id(),
                prior_label: "owner".to_owned(),
                next_label: "ExampleOverflow".to_owned(),
            }],
        ) {
            Err(error) if error.kind() == PolicyErrorKind::CapacityExhausted => {
                Ok("policy-capacity-exhausted")
            }
            _ => Err("policy cap did not produce exact refusal".into()),
        },
    )
}

fn proof_envelope(
    retained_proofs: usize,
) -> TestResult<(BuiltVault, jury_protocol::vault_v1::ItemEnvelopeV1)> {
    let mut built = fresh_vault()?;
    add_items_sequentially(&mut built, 1)?;
    let mut envelope = built.vault.items[0].clone();
    let mut current = envelope.current_revision.clone();
    let mut prior_revisions = Vec::with_capacity(retained_proofs);
    for revision in 2..=retained_proofs + 1 {
        prior_revisions.push(current.clone());
        current = next_proof(&built.owner, &current, revision)?;
    }
    envelope.prior_revisions = prior_revisions;
    envelope.current_revision = current;
    Ok((built, envelope))
}

fn proof_cap_refusal() -> TestResult {
    let (mut built, envelope) = proof_envelope(MAX_ITEM_REVISION_PROOFS + 1)?;
    built.vault.items = vec![envelope];
    measure_rejection(
        "hard-cap-refusal-item-proofs",
        MAX_ITEM_REVISION_PROOFS + 1,
        None,
        || match built.vault.validate() {
            Err(FormatError::CapacityExhausted("item revision proofs")) => {
                Ok("item-proof-capacity-exhausted")
            }
            _ => Err("item proof cap did not produce exact refusal".into()),
        },
    )
}

fn total_file_cap_refusal() -> TestResult {
    let built = fresh_vault()?;
    let mut creator = ItemCreator::from_source(
        DeterministicRandom(0x4a_32_35_00_00_f0_00),
        ProtectionPolicy::EmergencyAllowDegraded,
    );
    let mut mutations = Vec::new();
    for index in 0..2 {
        mutations.push(creator.prepare_create(
            &built.policy,
            &built.owner,
            300_000,
            NewItem {
                kind: ItemKind::Canonical,
                descriptor: ItemDescriptorV1::new(format!("ExampleOversize{index}"))?,
                state: state_with_payload(1_024 * 1_024)?,
                bucket_id: 12,
                access: ItemAccessPlan {
                    grants: Vec::new(),
                    direct_recipient_ids: vec![built.owner.principal_id()],
                    witness_policy_digest: None,
                },
            },
            &ItemArtifactInventory::default(),
        )?);
    }
    measure_rejection("hard-cap-refusal-total-file", 2, None, || {
        match VaultMutationPlan::prepare_item_batch(
            &built.vault,
            &[],
            &built.owner,
            300_000,
            Vec::new(),
            mutations,
            DirectDowngradeAcknowledgement::Acknowledged,
            MutationKind::Item,
        ) {
            Err(error) if error.kind() == MutationErrorKind::CapacityExhausted => {
                Ok("total-file-capacity-exhausted")
            }
            _ => Err("total-file cap did not produce exact refusal".into()),
        }
    })
}

fn protected_passphrase() -> TestResult<ProtectedMemory> {
    const VALUE: &[u8] = b"ExampleMeasurementPass1";
    Ok(ProtectedMemory::initialize(
        VALUE.len(),
        ProtectionPolicy::Strict,
        |destination| {
            destination.copy_from_slice(VALUE);
            Ok::<usize, ()>(destination.len())
        },
    )?)
}

fn identity_kdf(profile: KdfProfile) -> TestResult {
    let passphrase = protected_passphrase()?;
    let case = match profile {
        KdfProfile::PortableV1 => "identity-kdf-portable",
        KdfProfile::HardenedV1 => "identity-kdf-hardened",
    };
    measure(case, profile.memory_kib() as usize, None, || {
        let mut creator = IdentityCreator::from_source(DeterministicRandom(
            0x4a_32_35_00_01_00_00 + u64::from(profile.tag()),
        ));
        let created = creator.create(PrincipalKind::Human, profile, 1, &passphrase, |_| false)?;
        if created.file.header.kdf_profile != profile {
            return Err("identity KDF profile differs".into());
        }
        black_box(created);
        Ok(())
    })
}

fn backup_kdf(profile: KdfProfile) -> TestResult {
    let built = fresh_vault()?;
    let candidate = CheckpointCandidate::from_validated(
        &built.policy,
        &built.vault.policy,
        &built.vault.items,
    )?;
    let local = PrincipalLocalState::for_vault_principal(
        &built.owner,
        built.policy.vault_id(),
        built.policy.genesis_fingerprint().clone(),
    )?;
    let initialized = local.initialize(&candidate, 1)?;
    let files = local.serialize(&initialized)?;
    let identity_sources = [BackupIdentitySource::VaultPrincipal {
        identity: &built.owner,
        local_state: LocalStateArchive {
            audit: files.audit(),
            checkpoint: files.checkpoint(),
            receipts: files.receipts(),
        },
    }];
    let catalog = TransferPublicCatalogV1::empty();
    let passphrase = protected_passphrase()?;
    let case = match profile {
        KdfProfile::PortableV1 => "backup-kdf-portable",
        KdfProfile::HardenedV1 => "backup-kdf-hardened",
    };
    measure(case, profile.memory_kib() as usize, None, || {
        let mut creator = BackupCreator::from_source(DeterministicRandom(
            0x4a_32_35_00_02_00_00 + u64::from(profile.tag()),
        ));
        let created = creator.create(BackupCreateRequest {
            vault: &built.vault,
            catalog: &catalog,
            identities: &identity_sources,
            profile,
            created_at_ms: 2,
            backup_passphrase: &passphrase,
        })?;
        if created.envelope().header.kdf_profile != profile {
            return Err("backup KDF profile differs".into());
        }
        black_box(created);
        Ok(())
    })
}

fn hostile_identity_kdf_header() -> TestResult {
    let mut header = IdentityHeaderV1 {
        identity_format: 1,
        principal_id: PrincipalId::from_bytes([0xc1; 32])?,
        principal_kind: PrincipalKind::Human,
        recipient_public_key: RecipientPublicKey1216::new([0xc2; 1_216]),
        verification_public_key: VerificationPublicKey32::new([0xc3; 32]),
        descriptor_fingerprint: Digest32::new([0; 32]),
        created_at_ms: 1,
        kdf_profile: KdfProfile::PortableV1,
        argon2_version: 0x13,
        memory_kib: KdfProfile::PortableV1.memory_kib(),
        passes: 3,
        lanes: 4,
        salt: Salt16::new([0xc4; 16]),
        protection_mode: ProtectionMode::Portable,
        provider_kind: ProviderKind::new(Vec::new())?,
        provider_metadata: ProviderMetadata::new(Vec::new())?,
        root_wrap_algorithm: 1,
        root_wrap_nonce: Nonce12::new([0xc5; 12]),
        payload_algorithm: 1,
        payload_nonce: Nonce12::new([0xc6; 12]),
    };
    header.descriptor_fingerprint = header.recomputed_descriptor_fingerprint()?;
    let identity = IdentityFileV1 {
        magic: "jury-identity".to_owned(),
        header,
        root_wrap_ciphertext: RootWrapCiphertext48::new([0xc7; 48]),
        payload_ciphertext: IdentityPayloadCiphertext149::new([0xc8; 149]),
    };
    let valid = String::from_utf8(identity.to_json_bytes()?)?;
    let hostile = valid.replace(
        &format!("\"memory_kib\": {}", KdfProfile::PortableV1.memory_kib()),
        "\"memory_kib\": 4294967295",
    );
    if hostile == valid {
        return Err("identity KDF header fixture was not mutated".into());
    }
    measure_rejection(
        "hostile-identity-kdf-header",
        u32::MAX as usize,
        None,
        || match IdentityFileV1::parse(black_box(hostile.as_bytes())) {
            Err(jury_protocol::identity_v1::IdentityFormatError::UnsupportedProfile) => {
                Ok("unsupported-kdf-profile")
            }
            _ => Err("hostile identity KDF header did not reject before KDF".into()),
        },
    )
}

fn backup_header_fixture() -> TestResult<BackupHeaderV1> {
    let bucket = bucket_bytes(1)?;
    Ok(BackupHeaderV1 {
        backup_format: 1,
        backup_id: RecoveryId::from_bytes([0xd1; 32])?,
        created_at_ms: 1,
        vault_id: VaultId::from_bytes([0xd2; 32])?,
        genesis_fingerprint: Digest32::new([0xd3; 32]),
        source_public_revision_hash: Digest32::new([0xd4; 32]),
        owner_principal_id: PrincipalId::from_bytes([0xd5; 32])?,
        owner_descriptor_fingerprint: Digest32::new([0xd6; 32]),
        kdf_profile: KdfProfile::PortableV1,
        argon2_version: 0x13,
        memory_kib: KdfProfile::PortableV1.memory_kib(),
        passes: 3,
        lanes: 4,
        salt: Salt16::new([0xd7; 16]),
        storage_algorithm: 1,
        nonce: Nonce12::new([0xd8; 12]),
        target_bucket_id: 1,
        payload_ciphertext_length: u32::try_from(bucket - BACKUP_PREFIX_BYTES)?,
        payload_digest: Digest32::new([0xd9; 32]),
    })
}

fn hostile_backup_kdf_header() -> TestResult {
    let mut bytes = backup_header_fixture()?.canonical_bytes()?;
    bytes[204..208].copy_from_slice(&u32::MAX.to_be_bytes());
    measure_rejection("hostile-backup-kdf-header", u32::MAX as usize, None, || {
        match BackupHeaderV1::parse(black_box(&bytes)) {
            Err(BackupFormatError::UnsupportedProfile) => Ok("unsupported-kdf-profile"),
            _ => Err("hostile backup KDF header did not reject before KDF".into()),
        }
    })
}

fn sample_mean(samples: &[f64]) -> f64 {
    samples.iter().sum::<f64>() / samples.len() as f64
}

fn sample_variance(samples: &[f64], mean: f64) -> f64 {
    samples
        .iter()
        .map(|sample| {
            let delta = sample - mean;
            delta * delta
        })
        .sum::<f64>()
        / (samples.len() - 1) as f64
}

fn absolute_welch_t(
    mean_a: f64,
    variance_a: f64,
    mean_b: f64,
    variance_b: f64,
    samples_per_class: usize,
) -> f64 {
    let standard_error =
        (variance_a / samples_per_class as f64 + variance_b / samples_per_class as f64).sqrt();
    if standard_error == 0.0 {
        if mean_a == mean_b { 0.0 } else { f64::MAX }
    } else {
        ((mean_a - mean_b) / standard_error).abs()
    }
}

fn timing_failure_comparison(
    case: &str,
    class_a: &str,
    class_b: &str,
    samples_per_class: usize,
    mut operation_a: impl FnMut() -> TestResult,
    mut operation_b: impl FnMut() -> TestResult,
) -> TestResult {
    const WARMUPS_PER_CLASS: usize = 16;
    const GROSS_DIVERGENCE_ABS_WELCH_T: f64 = 10.0;

    for _ in 0..WARMUPS_PER_CLASS {
        operation_a()?;
        operation_b()?;
    }

    let mut samples_a = Vec::with_capacity(samples_per_class);
    let mut samples_b = Vec::with_capacity(samples_per_class);
    let all_started = Instant::now();
    for index in 0..samples_per_class {
        let sample = |operation: &mut dyn FnMut() -> TestResult| -> TestResult<f64> {
            let started = Instant::now();
            operation()?;
            let nanos = u64::try_from(started.elapsed().as_nanos())?;
            Ok(nanos as f64)
        };
        if index % 2 == 0 {
            samples_a.push(sample(&mut operation_a)?);
            samples_b.push(sample(&mut operation_b)?);
        } else {
            samples_b.push(sample(&mut operation_b)?);
            samples_a.push(sample(&mut operation_a)?);
        }
    }
    let operation_ns = all_started.elapsed().as_nanos();
    let mean_a = sample_mean(&samples_a);
    let mean_b = sample_mean(&samples_b);
    let variance_a = sample_variance(&samples_a, mean_a);
    let variance_b = sample_variance(&samples_b, mean_b);
    let abs_welch_t = absolute_welch_t(mean_a, variance_a, mean_b, variance_b, samples_per_class);
    let record = serde_json::json!({
        "schema": 1,
        "case": case,
        "count": samples_per_class * 2,
        "operation_ns": operation_ns,
        "artifact_bytes": null,
        "outcome": "accepted",
        "operation_result": "authentication-failed",
        "samples_per_class": samples_per_class,
        "warmups_per_class": WARMUPS_PER_CLASS,
        "class_a": class_a,
        "class_b": class_b,
        "class_a_mean_ns": mean_a,
        "class_b_mean_ns": mean_b,
        "abs_welch_t": abs_welch_t,
        "gross_divergence_abs_welch_t": GROSS_DIVERGENCE_ABS_WELCH_T,
        "interpretation": "gross wrapper timing regression smoke; not constant-time proof",
    });
    println!("J25_MEASUREMENT={record}");
    if abs_welch_t >= GROSS_DIVERGENCE_ABS_WELCH_T {
        return Err(format!("{case} exceeded the predeclared gross timing threshold").into());
    }
    Ok(())
}

fn timing_hpke_failure_classes() -> TestResult {
    let mut built = fresh_vault()?;
    add_items_sequentially(&mut built, 1)?;
    let slot = built
        .vault
        .policy
        .revisions
        .iter()
        .flat_map(|revision| &revision.operations)
        .find_map(|operation| match operation {
            PolicyOperationV1::ItemCreate { direct_slots, .. } => direct_slots.first(),
            _ => None,
        })
        .ok_or("timing fixture direct slot is absent")?;
    let mut invalid_encapsulation = slot.clone();
    let mut encapsulation_bytes = *invalid_encapsulation.encapsulation.as_bytes();
    encapsulation_bytes[0] ^= 1;
    invalid_encapsulation.encapsulation = Encapsulation1120::new(encapsulation_bytes);
    let mut invalid_ciphertext = slot.clone();
    let mut ciphertext_bytes = *invalid_ciphertext.ciphertext.as_bytes();
    ciphertext_bytes[0] ^= 1;
    invalid_ciphertext.ciphertext = DirectCiphertext48::new(ciphertext_bytes);
    if built.owner.open_direct_slot(&invalid_encapsulation).is_ok()
        || built.owner.open_direct_slot(&invalid_ciphertext).is_ok()
    {
        return Err("HPKE timing fixture unexpectedly authenticated".into());
    }
    timing_failure_comparison(
        "timing-hpke-invalid-encapsulation-vs-ciphertext",
        "invalid-encapsulation",
        "invalid-ciphertext",
        400,
        || {
            if built
                .owner
                .open_direct_slot(black_box(&invalid_encapsulation))
                .is_ok()
            {
                return Err("invalid HPKE encapsulation authenticated".into());
            }
            Ok(())
        },
        || {
            if built
                .owner
                .open_direct_slot(black_box(&invalid_ciphertext))
                .is_ok()
            {
                return Err("invalid HPKE ciphertext authenticated".into());
            }
            Ok(())
        },
    )
}

fn timing_storage_aead_tag_positions() -> TestResult {
    const PLAINTEXT_BYTES: usize = 4 * 1_024;
    let key = ProtectedMemory::initialize(32, ProtectionPolicy::Strict, |destination| {
        destination.fill(0x91);
        Ok::<usize, ()>(destination.len())
    })?;
    let plaintext =
        ProtectedMemory::initialize(PLAINTEXT_BYTES, ProtectionPolicy::Strict, |destination| {
            destination.fill(0x92);
            Ok::<usize, ()>(destination.len())
        })?;
    let nonce = Nonce12::new([0x93; 12]);
    let mut invalid_first = seal(&key, &nonce, b"jury-j25/timing-aead", &plaintext)?;
    invalid_first[PLAINTEXT_BYTES] ^= 1;
    let mut invalid_last = invalid_first.clone();
    invalid_last[PLAINTEXT_BYTES] ^= 1;
    let last = invalid_last.len() - 1;
    invalid_last[last] ^= 1;
    timing_failure_comparison(
        "timing-storage-aead-first-vs-last-tag-byte",
        "invalid-first-tag-byte",
        "invalid-last-tag-byte",
        2_000,
        || {
            if open_secret_bytes(
                &key,
                &nonce,
                b"jury-j25/timing-aead",
                black_box(&invalid_first),
                PLAINTEXT_BYTES,
                PLAINTEXT_BYTES,
            )
            .is_ok()
            {
                return Err("invalid first AEAD tag byte authenticated".into());
            }
            Ok(())
        },
        || {
            if open_secret_bytes(
                &key,
                &nonce,
                b"jury-j25/timing-aead",
                black_box(&invalid_last),
                PLAINTEXT_BYTES,
                PLAINTEXT_BYTES,
            )
            .is_ok()
            {
                return Err("invalid last AEAD tag byte authenticated".into());
            }
            Ok(())
        },
    )
}

fn timing_hmac_tag_positions() -> TestResult {
    let key = ProtectedMemory::initialize(32, ProtectionPolicy::Strict, |destination| {
        destination.fill(0xa1);
        Ok::<usize, ()>(destination.len())
    })?;
    let message = b"jury-j25/timing-hmac/ExamplePublicMessage";
    let mut invalid_first = hmac_sha256(&key, message)?;
    invalid_first[0] ^= 1;
    let mut invalid_last = hmac_sha256(&key, message)?;
    invalid_last[31] ^= 1;
    timing_failure_comparison(
        "timing-hmac-first-vs-last-tag-byte",
        "invalid-first-tag-byte",
        "invalid-last-tag-byte",
        20_000,
        || {
            if verify_hmac_sha256(&key, message, black_box(&invalid_first)).is_ok() {
                return Err("invalid first HMAC tag byte authenticated".into());
            }
            Ok(())
        },
        || {
            if verify_hmac_sha256(&key, message, black_box(&invalid_last)).is_ok() {
                return Err("invalid last HMAC tag byte authenticated".into());
            }
            Ok(())
        },
    )
}

fn protected_memory(case: &str, bytes: usize) -> TestResult {
    let started = Instant::now();
    let mut memory =
        ProtectedMemory::initialize_supported(bytes, ProtectionPolicy::Strict, |destination| {
            destination.fill(0xe1);
            Ok::<usize, ()>(destination.len())
        })?;
    let allocation_ns = started.elapsed().as_nanos();
    let status = memory.status().clone();
    let access_started = Instant::now();
    memory.expose_mut(|value| value.fill(0))?;
    let zeroize_access_ns = access_started.elapsed().as_nanos();
    let drop_started = Instant::now();
    drop(memory);
    let drop_ns = drop_started.elapsed().as_nanos();
    let record = serde_json::json!({
        "schema": 1,
        "case": case,
        "count": bytes,
        "operation_ns": allocation_ns + zeroize_access_ns + drop_ns,
        "allocation_lock_ns": allocation_ns,
        "zeroize_access_ns": zeroize_access_ns,
        "drop_unlock_ns": drop_ns,
        "mapped_bytes": status.mapped_bytes(),
        "locked_bytes": status.locked_bytes(),
        "page_granule": status.page_granule(),
        "outcome": "accepted",
    });
    if status.memory_lock() != RuntimeControlStatus::Established
        || status.dump_exclusion() != RuntimeControlStatus::Established
        || status.fork_exclusion() != RuntimeControlStatus::Established
        || status.guard_pages() != RuntimeControlStatus::Established
        || status.canary() != RuntimeControlStatus::Established
        || status.locked_bytes() < bytes
    {
        return Err("strict protected-memory measurement was degraded".into());
    }
    println!("J25_MEASUREMENT={record}");
    Ok(())
}

fn padding_overhead() -> TestResult {
    let body = empty_item_state();
    let body_logical_bytes = body.to_canonical_bytes()?.len() + 4;
    let body_buckets = (1..=12)
        .map(|bucket_id| {
            let framed = body.frame(bucket_id)?;
            Ok(serde_json::json!({
                "bucket_id": bucket_id,
                "bucket_bytes": framed.len(),
                "logical_bytes": body_logical_bytes,
                "padding_bytes": framed.len() - body_logical_bytes,
                "ciphertext_bytes": framed.len() + AEAD_TAG_BYTES,
            }))
        })
        .collect::<TestResult<Vec<_>>>()?;
    let backup_buckets = (1..=5)
        .map(|bucket_id| {
            let bucket = bucket_bytes(bucket_id)?;
            Ok(serde_json::json!({
                "bucket_id": bucket_id,
                "bucket_bytes": bucket,
                "header_bytes": BACKUP_PREFIX_BYTES,
                "ciphertext_bytes": bucket - BACKUP_PREFIX_BYTES,
                "plaintext_capacity": bucket - BACKUP_PREFIX_BYTES - AEAD_TAG_BYTES,
            }))
        })
        .collect::<TestResult<Vec<_>>>()?;
    let record = serde_json::json!({
        "schema": 1,
        "case": "padding-overhead-all-buckets",
        "count": body_buckets.len() + backup_buckets.len(),
        "operation_ns": null,
        "measurement_kind": "exact-size-accounting",
        "outcome": "accepted",
        "body_buckets": body_buckets,
        "backup_buckets": backup_buckets,
    });
    println!("J25_MEASUREMENT={record}");
    Ok(())
}

fn cover_history(case: &str, cover_reseals: usize) -> TestResult {
    let mut built = fresh_vault()?;
    add_items_sequentially(&mut built, 1)?;
    let mut creator = ItemCreator::from_source(
        DeterministicRandom(0x4a_32_35_00_03_00_00 + cover_reseals as u64),
        ProtectionPolicy::EmergencyAllowDegraded,
    );
    for index in 0..cover_reseals {
        let inventory = ItemArtifactInventory::from_vault(&built.vault)?;
        let prepared = creator.prepare_rekey(
            &built.policy,
            &built.owner,
            400_000 + index as u64,
            &built.vault.items[0],
            RekeyedItem {
                descriptor: ItemDescriptorV1::new("ExampleItem0000".to_owned())?,
                state: empty_item_state(),
                bucket_id: 1,
                access: ItemAccessPlan {
                    grants: Vec::new(),
                    direct_recipient_ids: vec![built.owner.principal_id()],
                    witness_policy_digest: None,
                },
                principal_replacement: None,
                principal_registration: None,
                owner_change: None,
            },
            &inventory,
        )?;
        let plan = VaultMutationPlan::prepare_item_batch(
            &built.vault,
            &[],
            &built.owner,
            400_000 + index as u64,
            Vec::new(),
            vec![prepared],
            DirectDowngradeAcknowledgement::Absent,
            MutationKind::PrivacyCover,
        )?;
        built.vault = plan.target_artifact().clone();
        built.policy = plan.target_policy().clone();
    }
    if built.vault.items[0].prior_revisions.len() != cover_reseals {
        return Err("cover history proof count differs".into());
    }
    let artifact_bytes = built.vault.to_json_bytes()?.len();
    measure(case, cover_reseals, Some(artifact_bytes), || {
        let parsed = VaultFileV1::parse(&built.vault.to_json_bytes()?)?;
        let policy = replay_policy(&parsed.policy)?;
        ParsedVault::new(&policy, &parsed.policy, &parsed.items).validate_public()?;
        Ok(())
    })
}

fn process_baseline() -> TestResult {
    measure("process-baseline", 0, None, || {
        black_box(0_u8);
        Ok(())
    })
}

fn parse_scaled_case(case: &str, prefix: &str) -> TestResult<usize> {
    case.strip_prefix(prefix)
        .ok_or("measurement case prefix differs")?
        .parse::<usize>()
        .map_err(Into::into)
}

#[test]
#[ignore = "run through scripts/check-j25-measurements in a release test binary"]
fn release_measurement_case() -> TestResult {
    if cfg!(debug_assertions) {
        return Err("J25 measurements require a release test binary".into());
    }
    let case = env::var("JURY_J25_MEASUREMENT_CASE")?;
    match case.as_str() {
        "process-baseline" => process_baseline(),
        "one-item-unlock" => one_item_unlock(),
        "ten-item-inject-preflight" => ten_item_inject_preflight(),
        "reader-grant" => reader_grant(),
        "read-revocation-reseal-1kib" => {
            read_revocation_reseal("read-revocation-reseal-1kib", 1_024, 1)
        }
        "read-revocation-reseal-1mib" => {
            read_revocation_reseal("read-revocation-reseal-1mib", 1_024 * 1_024, 10)
        }
        "read-revocation-reseal-near-file-cap" => {
            read_revocation_reseal("read-revocation-reseal-near-file-cap", 1_024 * 1_024, 12)
        }
        "multi-item-principal-replacement" => multi_item_principal_replacement(),
        "transfer-inspect-near-file-cap" => transfer_inspect_near_cap(),
        "transfer-dry-run-near-file-cap" => transfer_dry_run_near_cap(),
        "divergent-transfer-refusal" => divergent_transfer_refusal(),
        "hard-cap-refusal-policy-revisions" => policy_cap_refusal(),
        "hard-cap-refusal-item-proofs" => proof_cap_refusal(),
        "hard-cap-refusal-total-file" => total_file_cap_refusal(),
        "identity-kdf-portable" => identity_kdf(KdfProfile::PortableV1),
        "identity-kdf-hardened" => identity_kdf(KdfProfile::HardenedV1),
        "backup-kdf-portable" => backup_kdf(KdfProfile::PortableV1),
        "backup-kdf-hardened" => backup_kdf(KdfProfile::HardenedV1),
        "hostile-identity-kdf-header" => hostile_identity_kdf_header(),
        "hostile-backup-kdf-header" => hostile_backup_kdf_header(),
        "timing-hpke-invalid-encapsulation-vs-ciphertext" => timing_hpke_failure_classes(),
        "timing-storage-aead-first-vs-last-tag-byte" => timing_storage_aead_tag_positions(),
        "timing-hmac-first-vs-last-tag-byte" => timing_hmac_tag_positions(),
        "protected-memory-32" => protected_memory("protected-memory-32", 32),
        "protected-memory-1mib" => protected_memory("protected-memory-1mib", 1_024 * 1_024),
        "protected-memory-16mib" => protected_memory("protected-memory-16mib", 16 * 1_024 * 1_024),
        "padding-overhead-all-buckets" => padding_overhead(),
        "cover-history-monthly-one-year" => cover_history("cover-history-monthly-one-year", 12),
        "cover-history-weekly-one-year" => cover_history("cover-history-weekly-one-year", 52),
        "cover-history-daily-one-year" => cover_history("cover-history-daily-one-year", 365),
        _ if case.starts_with("public-validation-principals-") => public_validation(
            "principals",
            parse_scaled_case(&case, "public-validation-principals-")?,
        ),
        _ if case.starts_with("public-validation-items-") => public_validation(
            "items",
            parse_scaled_case(&case, "public-validation-items-")?,
        ),
        _ if case.starts_with("policy-replay-") => {
            policy_replay(parse_scaled_case(&case, "policy-replay-")?)
        }
        _ if case.starts_with("item-proofs-") => {
            item_proofs(parse_scaled_case(&case, "item-proofs-")?)
        }
        _ if case.starts_with("descriptor-catalog-") => {
            descriptor_catalog(parse_scaled_case(&case, "descriptor-catalog-")?)
        }
        _ => Err(format!("unknown J25 measurement case: {case}").into()),
    }
}

#[test]
fn measurement_case_names_and_scaled_parser_are_exact() -> TestResult {
    assert_eq!(
        parse_scaled_case("policy-replay-4096", "policy-replay-")?,
        4_096
    );
    assert!(parse_scaled_case("policy-replay-x", "policy-replay-").is_err());
    assert!(parse_scaled_case("item-proofs-1", "policy-replay-").is_err());
    assert_eq!(absolute_welch_t(10.0, 0.0, 10.0, 0.0, 4), 0.0);
    assert_eq!(absolute_welch_t(10.0, 0.0, 11.0, 0.0, 4), f64::MAX);
    Ok(())
}
