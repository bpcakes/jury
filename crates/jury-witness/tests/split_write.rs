#![cfg(target_os = "linux")]

use std::{error::Error, fs, os::unix::fs::PermissionsExt as _, path::Path};

use jury_core::{
    identity::{IdentityCreator, UnlockedIdentity, WitnessIdentity, unlock},
    witness_engine::{
        AnchorCompareAndSwap, ExternalWitnessAnchor, PersistedWitnessState, WitnessAnchorError,
        WitnessClock, WitnessEngine, WitnessEngineIdentity as _, WitnessStateStore as _,
    },
};
use jury_protected::{OsRandom, ProtectedMemory, ProtectionPolicy};
use jury_protocol::{
    identity_v1::KdfProfile,
    vault_v1::{Digest32, PrincipalKind, Signature64},
    witness_v1::{WitnessStateAnchorV1, signing_key_fingerprint},
};
use jury_witness::{
    anchor::{
        AnchorCasResult, SqliteAnchorRepository, backup_anchor_database, restore_anchor_database,
    },
    persistence::{SqliteWitnessStore, backup_witness_database, restore_witness_database},
};

type TestResult = Result<(), Box<dyn Error>>;

struct DirectAnchor {
    repository: SqliteAnchorRepository,
}

impl DirectAnchor {
    fn open(
        path: &Path,
        witness_id: jury_protocol::vault_v1::PrincipalId,
    ) -> Result<Self, Box<dyn Error>> {
        Ok(Self {
            repository: SqliteAnchorRepository::open(path, witness_id)?,
        })
    }
}

impl ExternalWitnessAnchor for DirectAnchor {
    fn read(&mut self) -> Result<Option<WitnessStateAnchorV1>, WitnessAnchorError> {
        self.repository.read().map_err(|_| WitnessAnchorError)
    }

    fn compare_and_swap(
        &mut self,
        expected: Option<&WitnessStateAnchorV1>,
        candidate: &WitnessStateAnchorV1,
    ) -> Result<AnchorCompareAndSwap, WitnessAnchorError> {
        let expected_digest = expected
            .map(WitnessStateAnchorV1::digest)
            .transpose()
            .map_err(|_| WitnessAnchorError)?;
        self.repository
            .compare_and_swap(expected_digest.as_ref(), candidate)
            .map(|result| match result {
                AnchorCasResult::Applied(_) => AnchorCompareAndSwap::Published,
                AnchorCasResult::Conflict(_) => AnchorCompareAndSwap::Conflict,
            })
            .map_err(|_| WitnessAnchorError)
    }
}

struct FixedClock;

impl WitnessClock for FixedClock {
    fn wall_time_ms(&self) -> u64 {
        10
    }

    fn monotonic_time_ms(&self) -> u64 {
        10
    }
}

#[test]
fn real_sqlite_split_writes_reconcile_and_one_sided_rollbacks_fail_closed() -> TestResult {
    let directory = tempfile::tempdir()?;
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
    let identity = witness_identity()?;
    let witness_id = identity.principal_id();
    let witness_database = directory.path().join("witness.sqlite3");
    let anchor_database = directory.path().join("anchor.sqlite3");

    let mut store = SqliteWitnessStore::open(&witness_database, witness_id)?;
    let first = commit_pending(&mut store, &identity, 1)?;
    drop(store);

    check_ready(&identity, &witness_database, &anchor_database)?;
    let reconciled = SqliteWitnessStore::open(&witness_database, witness_id)?.load_validated()?;
    assert_eq!(reconciled.pending_anchor, None);
    assert_eq!(reconciled.published_anchor, Some(first.clone()));
    assert_eq!(
        SqliteAnchorRepository::open(&anchor_database, witness_id)?.read()?,
        Some(first)
    );

    let witness_backup = directory.path().join("witness-generation-1.sqlite3");
    let anchor_backup = directory.path().join("anchor-generation-1.sqlite3");
    backup_witness_database(&witness_database, &witness_backup)?;
    backup_anchor_database(&anchor_database, &anchor_backup)?;

    let mut store = SqliteWitnessStore::open(&witness_database, witness_id)?;
    let second = commit_pending(&mut store, &identity, 2)?;
    let expected = second.predecessor_anchor_digest.clone();
    SqliteAnchorRepository::open(&anchor_database, witness_id)?
        .compare_and_swap(Some(&expected), &second)?;
    drop(store);

    check_ready(&identity, &witness_database, &anchor_database)?;

    let restored_witness = directory.path().join("restored-witness.sqlite3");
    restore_witness_database(&witness_backup, &restored_witness)?;
    assert!(check_ready(&identity, &restored_witness, &anchor_database).is_err());

    let restored_anchor = directory.path().join("restored-anchor.sqlite3");
    restore_anchor_database(&anchor_backup, &restored_anchor)?;
    assert!(check_ready(&identity, &witness_database, &restored_anchor).is_err());
    Ok(())
}

fn witness_identity() -> Result<WitnessIdentity, Box<dyn Error>> {
    const PASSPHRASE: &[u8] = b"ExampleWitnessPassphrase";
    let passphrase =
        ProtectedMemory::initialize(PASSPHRASE.len(), ProtectionPolicy::Strict, |destination| {
            destination.copy_from_slice(PASSPHRASE);
            Ok::<usize, ()>(destination.len())
        })?;
    let created = IdentityCreator::new().create(
        PrincipalKind::Witness,
        KdfProfile::PortableV1,
        1,
        &passphrase,
        |_| false,
    )?;
    match unlock(&created.file, &passphrase)? {
        UnlockedIdentity::Witness(identity) => Ok(identity),
        UnlockedIdentity::VaultPrincipal(_) | UnlockedIdentity::Approver(_) => {
            Err("created identity had the wrong role".into())
        }
    }
}

fn commit_pending(
    store: &mut SqliteWitnessStore,
    identity: &WitnessIdentity,
    generation: u64,
) -> Result<WitnessStateAnchorV1, Box<dyn Error>> {
    let mut state = store.load().map_err(|_| "witness state load failed")?;
    let expected_generation = state.logical.state_generation;
    assert_eq!(generation, expected_generation + 1);
    state.logical.state_generation = generation;
    state.logical.last_accepted_wall_time_ms = generation;
    let candidate = signed_anchor(identity, &state, generation)?;
    state.pending_anchor = Some(candidate.clone());
    store
        .commit(expected_generation, state)
        .map_err(|_| "witness state commit failed")?;
    Ok(candidate)
}

fn signed_anchor(
    identity: &WitnessIdentity,
    state: &PersistedWitnessState,
    generation: u64,
) -> Result<WitnessStateAnchorV1, Box<dyn Error>> {
    let descriptor = identity.public_descriptor()?;
    let predecessor_anchor_digest = state
        .published_anchor
        .as_ref()
        .map(WitnessStateAnchorV1::digest)
        .transpose()?
        .unwrap_or_else(|| Digest32::new([0; 32]));
    let mut anchor = WitnessStateAnchorV1 {
        schema: 1,
        witness_id: descriptor.principal_id,
        witness_signing_key_fingerprint: signing_key_fingerprint(
            3,
            &descriptor.principal_id,
            1,
            &descriptor.verification_public_key,
        ),
        witness_signing_key_epoch: 1,
        state_generation: generation,
        database_state_digest: state.logical.canonical_database_state()?.digest()?,
        vault_high_watermarks: Vec::new(),
        replay_retain_through_ms: 0,
        last_accepted_wall_time_ms: generation,
        predecessor_anchor_digest,
        issued_at_ms: generation,
        signature: Signature64::new([0; 64]),
    };
    anchor.signature = identity.sign_witness_statement(&anchor.signature_preimage()?)?;
    Ok(anchor)
}

fn check_ready(
    identity: &WitnessIdentity,
    witness_database: &Path,
    anchor_database: &Path,
) -> TestResult {
    let mut store = SqliteWitnessStore::open(witness_database, identity.principal_id())?;
    let mut anchor = DirectAnchor::open(anchor_database, identity.principal_id())?;
    let mut random = OsRandom;
    WitnessEngine::new(identity, &mut store, &mut anchor, &FixedClock, &mut random)
        .check_ready()?;
    Ok(())
}
