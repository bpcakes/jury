use jury_protected::{EntropyError, ProtectedMemory, ProtectionPolicy, RandomSource};
use jury_protocol::{
    identity_v1::KdfProfile,
    vault_v1::{
        Digest32, Nonce12, PolicyOperationV1, PrincipalId, PrincipalKind, RecoveryId, Salt16,
        VaultFileV1, VaultHeaderV1, VaultId,
    },
};

use super::*;
use crate::{
    identity::{IdentityCreator, UnlockedIdentity, unlock, unlocked_identity_for_test},
    local_state::PrincipalLocalState,
    policy::{PolicyCreator, replay_policy},
    registration::{RegistrationCreator, RegistrationProofV1, answer_challenge},
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

struct CounterRandom(u8);

impl RandomSource for CounterRandom {
    fn fill(&mut self, destination: &mut [u8]) -> Result<(), EntropyError> {
        self.0 = self.0.wrapping_add(1);
        destination.fill(self.0);
        Ok(())
    }
}

fn protected_passphrase(value: &[u8]) -> TestResult<ProtectedMemory> {
    Ok(ProtectedMemory::initialize(
        value.len(),
        ProtectionPolicy::EmergencyAllowDegraded,
        |destination| {
            destination.copy_from_slice(value);
            Ok::<usize, ()>(destination.len())
        },
    )?)
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

fn register_role(
    vault: &VaultFileV1,
    owner: &VaultPrincipalIdentity,
    principal_id: PrincipalId,
    kind: PrincipalKind,
    label: &str,
    timestamp_ms: u64,
    random_seed: u8,
) -> TestResult<(VaultFileV1, UnlockedIdentity, RegistrationProofV1)> {
    let candidate =
        unlocked_identity_for_test(principal_id, kind, &mut CounterRandom(random_seed))?;
    let descriptor = candidate.public_descriptor()?;
    let policy = replay_policy(&vault.policy)?;
    let challenge = RegistrationCreator::new(ProtectionPolicy::Strict).create_challenge(
        &policy,
        owner,
        descriptor.clone(),
        timestamp_ms,
        1_000,
        (kind == PrincipalKind::Witness).then_some(7),
    )?;
    let proof = answer_challenge(&policy, &candidate, &challenge, timestamp_ms + 1)?;
    let revision = policy.prepare_revision(
        owner,
        timestamp_ms + 2,
        vec![PolicyOperationV1::PrincipalAdd {
            descriptor,
            display_label: label.to_owned(),
            registration_proof_digest: proof.digest()?,
        }],
    )?;
    let mut registered = vault.clone();
    registered.policy.revisions.push(revision.revision);
    registered.validate()?;
    Ok((registered, candidate, proof))
}

#[test]
fn owner_backup_round_trip_reseals_same_identity_and_local_state() -> TestResult {
    let (owner, vault) = fixture()?;
    let policy = replay_policy(&vault.policy)?;
    let candidate = CheckpointCandidate::from_validated(&policy, &vault.policy, &vault.items)?;
    let local = PrincipalLocalState::for_vault_principal(
        &owner,
        vault.header.vault_id,
        vault.header.genesis_fingerprint.clone(),
    )?;
    let state = local.initialize(&candidate, 11)?;
    let files = local.serialize(&state)?;
    let catalog = TransferPublicCatalogV1::empty();
    let backup_passphrase = protected_passphrase(b"ExampleBackupPassphrase")?;
    let identities = [BackupIdentitySource::VaultPrincipal {
        identity: &owner,
        local_state: LocalStateArchive {
            audit: files.audit(),
            checkpoint: files.checkpoint(),
            receipts: files.receipts(),
        },
    }];
    let created = BackupCreator::from_source(CounterRandom(0x70)).create(BackupCreateRequest {
        vault: &vault,
        catalog: &catalog,
        identities: &identities,
        profile: KdfProfile::PortableV1,
        created_at_ms: 20,
        backup_passphrase: &backup_passphrase,
    })?;
    let encoded = created.envelope().to_bytes()?;
    assert_eq!(encoded.len(), 4 * 1024 * 1024);
    assert_eq!(
        created.coverage().identity_roles,
        [RecoveryRole::VaultPrincipal]
    );
    assert!(created.coverage().checkpoints_current);
    assert!(!created.coverage().external_witness_recovery_required);
    assert!(!created.coverage().recovers_juryd_replay_state);

    let envelope = jury_protocol::backup_v1::BackupEnvelopeV1::parse(&encoded)?;
    let recovered = open(&envelope, &backup_passphrase)?;
    assert_eq!(recovered.vault(), &vault);
    assert_eq!(recovered.catalog(), &catalog);
    let owner_recovery = recovered
        .identity(RecoveryRole::VaultPrincipal)
        .ok_or("owner recovery absent")?;
    assert_eq!(owner_recovery.local_state().audit(), files.audit());
    assert_eq!(
        owner_recovery.local_state().checkpoint(),
        files.checkpoint()
    );
    assert_eq!(owner_recovery.local_state().receipts(), files.receipts());

    let new_passphrase = protected_passphrase(b"ExampleNewIdentityPassphrase")?;
    let restored = IdentityCreator::from_source(CounterRandom(0x90)).restore(
        owner_recovery.identity(),
        KdfProfile::PortableV1,
        30,
        &new_passphrase,
    )?;
    assert_eq!(restored.descriptor, owner.public_descriptor()?);
    let unlocked = unlock(&restored.file, &new_passphrase)?;
    assert!(owner_recovery.identity().matches_unlocked(&unlocked)?);
    Ok(())
}

#[test]
fn wrong_passphrase_and_tamper_fail_without_private_error_content() -> TestResult {
    let (owner, vault) = fixture()?;
    let policy = replay_policy(&vault.policy)?;
    let candidate = CheckpointCandidate::from_validated(&policy, &vault.policy, &vault.items)?;
    let local = PrincipalLocalState::for_vault_principal(
        &owner,
        vault.header.vault_id,
        vault.header.genesis_fingerprint.clone(),
    )?;
    let state = local.initialize(&candidate, 11)?;
    let files = local.serialize(&state)?;
    let passphrase = protected_passphrase(b"ExampleBackupPassphrase")?;
    let identities = [BackupIdentitySource::VaultPrincipal {
        identity: &owner,
        local_state: LocalStateArchive {
            audit: files.audit(),
            checkpoint: files.checkpoint(),
            receipts: files.receipts(),
        },
    }];
    let catalog = TransferPublicCatalogV1::empty();
    let created = BackupCreator::from_source(CounterRandom(0xa0)).create(BackupCreateRequest {
        vault: &vault,
        catalog: &catalog,
        identities: &identities,
        profile: KdfProfile::PortableV1,
        created_at_ms: 20,
        backup_passphrase: &passphrase,
    })?;
    let wrong = protected_passphrase(b"ExampleWrongPassphrase")?;
    let wrong_error = open(created.envelope(), &wrong)
        .err()
        .ok_or("wrong passphrase accepted")?;
    assert_eq!(wrong_error.kind(), BackupErrorKind::AuthenticationFailed);
    assert_eq!(
        format!("{wrong_error:?}"),
        "BackupError { kind: AuthenticationFailed }"
    );

    let mut bytes = created.envelope().to_bytes()?;
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    let tampered = jury_protocol::backup_v1::BackupEnvelopeV1::parse(&bytes)?;
    assert!(matches!(
        open(&tampered, &passphrase),
        Err(error) if error.kind() == BackupErrorKind::AuthenticationFailed
    ));
    Ok(())
}

#[test]
fn authenticated_plaintext_rejects_nonzero_bucket_padding_before_payload_parsing() -> TestResult {
    let header = BackupHeaderV1 {
        backup_format: 1,
        backup_id: RecoveryId::from_bytes([1; 32])?,
        created_at_ms: 7,
        vault_id: VaultId::from_bytes([2; 32])?,
        genesis_fingerprint: Digest32::new([3; 32]),
        source_public_revision_hash: Digest32::new([4; 32]),
        owner_principal_id: PrincipalId::from_bytes([5; 32])?,
        owner_descriptor_fingerprint: Digest32::new([6; 32]),
        kdf_profile: KdfProfile::PortableV1,
        argon2_version: 0x13,
        memory_kib: KdfProfile::PortableV1.memory_kib(),
        passes: 3,
        lanes: 4,
        salt: Salt16::new([7; 16]),
        storage_algorithm: 1,
        nonce: Nonce12::new([8; 12]),
        target_bucket_id: 1,
        payload_ciphertext_length: u32::try_from(
            jury_protocol::backup_v1::bucket_bytes(1)?
                - jury_protocol::backup_v1::BACKUP_PREFIX_BYTES,
        )?,
        payload_digest: Digest32::new([9; 32]),
    };
    let plaintext = [0, 0, 0, 1, 0xaa, 1];
    assert!(matches!(
        parse_padded_payload(
            &plaintext,
            &header,
            ProtectionPolicy::EmergencyAllowDegraded,
        ),
        Err(error) if error.kind() == BackupErrorKind::NonCanonicalPadding
    ));
    Ok(())
}

#[test]
fn creation_rejects_stale_checkpoint_and_identity_vault_mismatch_before_encryption() -> TestResult {
    let (owner, vault) = fixture()?;
    let initial_policy = replay_policy(&vault.policy)?;
    let initial_candidate =
        CheckpointCandidate::from_validated(&initial_policy, &vault.policy, &vault.items)?;
    let local = PrincipalLocalState::for_vault_principal(
        &owner,
        vault.header.vault_id,
        vault.header.genesis_fingerprint.clone(),
    )?;
    let files = local.serialize(&local.initialize(&initial_candidate, 11)?)?;
    let revision = initial_policy.prepare_revision(
        &owner,
        12,
        vec![PolicyOperationV1::PrincipalLabelChange {
            principal_id: owner.principal_id(),
            prior_label: "owner".to_owned(),
            next_label: "primary-owner".to_owned(),
        }],
    )?;
    let mut advanced = vault.clone();
    advanced.policy.revisions.push(revision.revision);
    let passphrase = protected_passphrase(b"ExampleBackupPassphrase")?;
    let owner_source = [BackupIdentitySource::VaultPrincipal {
        identity: &owner,
        local_state: LocalStateArchive {
            audit: files.audit(),
            checkpoint: files.checkpoint(),
            receipts: files.receipts(),
        },
    }];
    assert!(matches!(
        BackupCreator::from_source(CounterRandom(0xb0)).create(BackupCreateRequest {
            vault: &advanced,
            catalog: &TransferPublicCatalogV1::empty(),
            identities: &owner_source,
            profile: KdfProfile::PortableV1,
            created_at_ms: 20,
            backup_passphrase: &passphrase,
        }),
        Err(error) if error.kind() == BackupErrorKind::StaleCheckpoint
    ));

    let UnlockedIdentity::VaultPrincipal(other) = unlocked_identity_for_test(
        PrincipalId::from_bytes([0x24; 32])?,
        PrincipalKind::Human,
        &mut CounterRandom(0xc0),
    )?
    else {
        return Err("other fixture identity role differs".into());
    };
    let other_source = [BackupIdentitySource::VaultPrincipal {
        identity: &other,
        local_state: LocalStateArchive {
            audit: files.audit(),
            checkpoint: files.checkpoint(),
            receipts: files.receipts(),
        },
    }];
    assert!(matches!(
        BackupCreator::from_source(CounterRandom(0xd0)).create(BackupCreateRequest {
            vault: &vault,
            catalog: &TransferPublicCatalogV1::empty(),
            identities: &other_source,
            profile: KdfProfile::PortableV1,
            created_at_ms: 20,
            backup_passphrase: &passphrase,
        }),
        Err(error) if error.kind() == BackupErrorKind::UnauthorizedOwner
            || error.kind() == BackupErrorKind::IdentityMismatch
    ));
    Ok(())
}

#[test]
fn archive_carries_all_three_explicit_local_roles_and_authenticated_state() -> TestResult {
    let (owner, vault) = fixture()?;
    let (vault, approver, approver_proof) = register_role(
        &vault,
        &owner,
        PrincipalId::from_bytes([0x22; 32])?,
        PrincipalKind::Approver,
        "ExampleApprover",
        20,
        0x60,
    )?;
    let (vault, witness, witness_proof) = register_role(
        &vault,
        &owner,
        PrincipalId::from_bytes([0x23; 32])?,
        PrincipalKind::Witness,
        "ExampleWitness",
        30,
        0x70,
    )?;
    let UnlockedIdentity::Approver(approver) = approver else {
        return Err("approver fixture role differs".into());
    };
    let UnlockedIdentity::Witness(witness) = witness else {
        return Err("witness fixture role differs".into());
    };
    let policy = replay_policy(&vault.policy)?;
    let candidate = CheckpointCandidate::from_validated(&policy, &vault.policy, &vault.items)?;
    let owner_local = PrincipalLocalState::for_vault_principal(
        &owner,
        vault.header.vault_id,
        vault.header.genesis_fingerprint.clone(),
    )?;
    let approver_local = PrincipalLocalState::for_approver(
        &approver,
        vault.header.vault_id,
        vault.header.genesis_fingerprint.clone(),
    )?;
    let witness_local = PrincipalLocalState::for_witness(
        &witness,
        vault.header.vault_id,
        vault.header.genesis_fingerprint.clone(),
    )?;
    let owner_files = owner_local.serialize(&owner_local.initialize(&candidate, 40)?)?;
    let approver_files = approver_local.serialize(&approver_local.initialize(&candidate, 40)?)?;
    let witness_files = witness_local.serialize(&witness_local.initialize(&candidate, 40)?)?;
    let identities = [
        BackupIdentitySource::VaultPrincipal {
            identity: &owner,
            local_state: LocalStateArchive {
                audit: owner_files.audit(),
                checkpoint: owner_files.checkpoint(),
                receipts: owner_files.receipts(),
            },
        },
        BackupIdentitySource::Approver {
            identity: &approver,
            local_state: LocalStateArchive {
                audit: approver_files.audit(),
                checkpoint: approver_files.checkpoint(),
                receipts: approver_files.receipts(),
            },
        },
        BackupIdentitySource::WitnessClient {
            identity: &witness,
            local_state: LocalStateArchive {
                audit: witness_files.audit(),
                checkpoint: witness_files.checkpoint(),
                receipts: witness_files.receipts(),
            },
        },
    ];
    let catalog = TransferPublicCatalogV1::new(vec![approver_proof, witness_proof], Vec::new())?;
    let passphrase = protected_passphrase(b"ExampleAllRolesBackupPassphrase")?;
    let created = BackupCreator::from_source(CounterRandom(0x80)).create(BackupCreateRequest {
        vault: &vault,
        catalog: &catalog,
        identities: &identities,
        profile: KdfProfile::PortableV1,
        created_at_ms: 50,
        backup_passphrase: &passphrase,
    })?;
    assert_eq!(
        created.coverage().identity_roles,
        [
            RecoveryRole::VaultPrincipal,
            RecoveryRole::Approver,
            RecoveryRole::WitnessClient,
        ]
    );
    let recovered = open(created.envelope(), &passphrase)?;
    for role in [
        RecoveryRole::VaultPrincipal,
        RecoveryRole::Approver,
        RecoveryRole::WitnessClient,
    ] {
        assert!(recovered.identity(role).is_some());
    }
    assert_eq!(
        recovered
            .identity(RecoveryRole::Approver)
            .ok_or("approver recovery absent")?
            .local_state()
            .checkpoint(),
        approver_files.checkpoint()
    );
    assert_eq!(
        recovered
            .identity(RecoveryRole::WitnessClient)
            .ok_or("witness recovery absent")?
            .local_state()
            .receipts(),
        witness_files.receipts()
    );
    Ok(())
}
