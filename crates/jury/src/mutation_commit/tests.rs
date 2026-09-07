use std::fs;
use std::path::Path;

use jury_core::identity::{IdentityCreator, UnlockedIdentity, unlock};
use jury_core::local_state::{CheckpointCandidate, PrincipalLocalState};
use jury_core::mutation::{DirectDowngradeAcknowledgement, MutationKind, VaultMutationPlan};
use jury_core::policy::{PolicyCreator, replay_policy};
use jury_filesystem::{
    PreparedPrivateFile, PrincipalStateFile, PublicationPolicy, RepositoryLocation,
    VaultStateDirectory,
};
use jury_protected::{ProtectedMemory, ProtectionPolicy};
use jury_protocol::identity_v1::KdfProfile;
use jury_protocol::vault_v1::{PolicyOperationV1, PrincipalKind, VaultFileV1, VaultHeaderV1};

use super::*;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

struct Fixture {
    _root: tempfile::TempDir,
    repository: RepositoryLocation,
    state: VaultStateDirectory,
    local: PrincipalLocalState,
    owner: jury_core::identity::VaultPrincipalIdentity,
    vault: VaultFileV1,
    git_head: Vec<u8>,
}

fn fixture() -> TestResult<Fixture> {
    let root = tempfile::tempdir()?;
    let repository_path = root.path().join("repository");
    fs::create_dir(&repository_path)?;
    fs::create_dir(repository_path.join(".git"))?;
    let git_head = [b"ref: refs".as_slice(), b"/heads/main\n"].concat();
    fs::write(repository_path.join(".git").join("HEAD"), &git_head)?;
    let mut repository = RepositoryLocation::discover(&repository_path)?;
    repository.create_jury_directory()?;

    let protection = ProtectionPolicy::EmergencyAllowDegraded;
    let passphrase = protected(b"ExamplePass1234", protection)?;
    let mut identities = IdentityCreator::new();
    let created_identity = identities.create(
        PrincipalKind::Human,
        KdfProfile::PortableV1,
        1,
        &passphrase,
        |_| false,
    )?;
    let UnlockedIdentity::VaultPrincipal(owner) = unlock(&created_identity.file, &passphrase)?
    else {
        return Err("fixture identity role differs".into());
    };
    let mut policies = PolicyCreator::new();
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
            genesis_fingerprint: genesis_fingerprint.clone(),
        },
        policy: created.journal,
        items: Vec::new(),
        suite_migration: None,
    };
    let shared = protected(&vault.to_json_bytes()?, protection)?;
    assert_eq!(
        PreparedPrivateFile::prepare_encrypted_shared_artifact(
            &repository,
            &shared,
            PublicationPolicy::CreateNew,
        )?
        .publish()?,
        PublicationOutcome::PublishedAndSynced
    );

    let state = VaultStateDirectory::open_or_create(
        &root.path().join("state"),
        vault.header.vault_id.as_bytes(),
        vault.header.genesis_fingerprint.as_bytes(),
        &[&repository],
        &[],
    )?;
    let local = PrincipalLocalState::for_vault_principal(
        &owner,
        vault.header.vault_id,
        genesis_fingerprint,
    )?;
    let policy = replay_policy(&vault.policy)?;
    let candidate = CheckpointCandidate::from_validated(&policy, &vault.policy, &vault.items)?;
    let initialized = local.initialize(&candidate, 11)?;
    let files = local.serialize(&initialized)?;
    {
        let locked = state.try_lock()?;
        for (file, bytes) in [
            (PrincipalStateFile::Audit, files.audit()),
            (PrincipalStateFile::Checkpoint, files.checkpoint()),
            (PrincipalStateFile::Receipts, files.receipts()),
        ] {
            let bytes = protected(bytes, protection)?;
            assert_eq!(
                locked.publish(local.scope().principal_id().as_bytes(), file, &bytes)?,
                PublicationOutcome::PublishedAndSynced
            );
        }
    }
    Ok(Fixture {
        _root: root,
        repository,
        state,
        local,
        owner,
        vault,
        git_head,
    })
}

fn plan(fixture: &Fixture, next_label: &str) -> TestResult<VaultMutationPlan> {
    Ok(VaultMutationPlan::prepare_policy(
        &fixture.vault,
        &[],
        &fixture.owner,
        20,
        vec![PolicyOperationV1::PrincipalLabelChange {
            principal_id: fixture.owner.principal_id(),
            prior_label: "owner".to_owned(),
            next_label: next_label.to_owned(),
        }],
        DirectDowngradeAcknowledgement::Absent,
        MutationKind::Policy,
    )?
    .bind_repository_ancestry(fixture.repository.git_ancestry_digest()?))
}

fn protected(
    bytes: &[u8],
    policy: ProtectionPolicy,
) -> Result<ProtectedMemory, jury_protected::MemoryError> {
    let initialize = |destination: &mut [u8]| {
        destination.copy_from_slice(bytes);
        Ok::<usize, ()>(destination.len())
    };
    ProtectedMemory::initialize_supported(bytes.len(), policy, initialize)
}

fn newly_registered_approver_transfer(
    fixture: &Fixture,
) -> TestResult<(VaultMutationPlan, VaultMutationPlan, PrincipalLocalState)> {
    use jury_core::registration::{RegistrationCreator, answer_challenge, verify_proof};

    let protection = ProtectionPolicy::EmergencyAllowDegraded;
    let passphrase = protected(b"ExampleApproverPassphrase", protection)?;
    let created = IdentityCreator::new().create(
        PrincipalKind::Approver,
        KdfProfile::PortableV1,
        11,
        &passphrase,
        |_| false,
    )?;
    let identity = unlock(&created.file, &passphrase)?;
    let descriptor = identity.public_descriptor()?;
    let policy = replay_policy(&fixture.vault.policy)?;
    let challenge = RegistrationCreator::new(protection).create_challenge(
        &policy,
        &fixture.owner,
        descriptor.clone(),
        12,
        100,
        None,
    )?;
    let proof = answer_challenge(&policy, &identity, &challenge, 13)?;
    let proof_digest = verify_proof(&policy, &fixture.owner, &challenge, &proof, 14)?;
    let operation = PolicyOperationV1::PrincipalAdd {
        descriptor: descriptor.clone(),
        display_label: "ExampleApprover".to_owned(),
        registration_proof_digest: proof_digest,
    };
    let registration = |issued_at| {
        VaultMutationPlan::prepare_policy(
            &fixture.vault,
            &[],
            &fixture.owner,
            issued_at,
            vec![operation.clone()],
            DirectDowngradeAcknowledgement::Absent,
            MutationKind::Policy,
        )
    };
    let registered = registration(15)?;
    let sibling = registration(16)?;
    let sibling_plan = VaultMutationPlan::prepare_transfer_import(
        &fixture.vault,
        sibling.target_artifact(),
        &[],
        descriptor.principal_id,
        20,
    )?
    .ok_or("sibling transfer was unexpectedly identical")?
    .bind_repository_ancestry(fixture.repository.git_ancestry_digest()?);
    let plan = VaultMutationPlan::prepare_transfer_import(
        &fixture.vault,
        registered.target_artifact(),
        &[],
        descriptor.principal_id,
        20,
    )?
    .ok_or("registration transfer was unexpectedly identical")?
    .bind_repository_ancestry(fixture.repository.git_ancestry_digest()?);
    let UnlockedIdentity::Approver(identity) = identity else {
        return Err("fixture identity role differs".into());
    };
    let local = PrincipalLocalState::for_approver(
        &identity,
        fixture.vault.header.vault_id,
        fixture.vault.header.genesis_fingerprint.clone(),
    )?;
    Ok((plan, sibling_plan, local))
}

#[test]
fn newly_registered_role_transfer_retries_after_durable_intent_without_forging_old_scope()
-> TestResult {
    let fixture = fixture()?;
    let (plan, sibling_plan, local) = newly_registered_approver_transfer(&fixture)?;
    let protection = ProtectionPolicy::EmergencyAllowDegraded;
    let old_policy = replay_policy(&fixture.vault.policy)?;
    let old_candidate =
        CheckpointCandidate::from_validated(&old_policy, &fixture.vault.policy, &[])?;
    assert!(local.initialize(&old_candidate, 19).is_err());
    let initialized = local.initialize(&plan.checkpoint_candidate()?, 20)?;
    let files = local.serialize(&initialized)?;
    {
        let locked = fixture.state.try_lock()?;
        for (kind, bytes) in [
            (PrincipalStateFile::Audit, files.audit()),
            (PrincipalStateFile::Checkpoint, files.checkpoint()),
            (PrincipalStateFile::Receipts, files.receipts()),
        ] {
            let contents = protected(bytes, protection)?;
            assert_eq!(
                locked.publish(local.scope().principal_id().as_bytes(), kind, &contents)?,
                PublicationOutcome::PublishedAndSynced
            );
        }
    }
    let target =
        RepositoryMutationTarget::new(&fixture.repository, &fixture.state, &local, protection);
    let error = match target
        .inner
        .commit_with_before_shared_publish(&plan, None, || {
            Err(MutationCommitError::new(
                MutationCommitErrorKind::SharedPublicationFailed,
            ))
        }) {
        Err(error) => error,
        Ok(_) => return Err("injected publication failure was ignored".into()),
    };
    assert_eq!(
        error.kind(),
        MutationCommitErrorKind::SharedPublicationFailed
    );
    assert_eq!(
        fixture
            .repository
            .read_encrypted_shared_artifact(MAX_VAULT_BYTES)?,
        fixture.vault.to_json_bytes()?
    );
    let sibling_error = match target.commit(&sibling_plan) {
        Err(error) => error,
        Ok(_) => return Err("retained target checkpoint accepted a signed sibling".into()),
    };
    assert_eq!(
        sibling_error.kind(),
        MutationCommitErrorKind::InvalidLocalState
    );
    assert_eq!(
        fixture
            .repository
            .read_encrypted_shared_artifact(MAX_VAULT_BYTES)?,
        fixture.vault.to_json_bytes()?
    );
    assert!(matches!(
        target.commit(&plan)?,
        MutationCommitOutcome::Committed { .. }
    ));
    assert_eq!(
        fixture
            .repository
            .read_encrypted_shared_artifact(MAX_VAULT_BYTES)?,
        plan.target_bytes()
    );
    let read_state = || -> TestResult<Vec<Vec<u8>>> {
        let locked = fixture.state.try_lock()?;
        [
            PrincipalStateFile::Audit,
            PrincipalStateFile::Checkpoint,
            PrincipalStateFile::Receipts,
        ]
        .into_iter()
        .map(|kind| {
            locked
                .read(local.scope().principal_id().as_bytes(), kind)
                .map_err(Into::into)
        })
        .collect()
    };
    let published = read_state()?;
    let verified = local.verify_files(
        Some(&published[0]),
        Some(&published[1]),
        Some(&published[2]),
    )?;
    assert!(verified.contains_operation(plan.target_digest()));
    assert_eq!(verified.audit_events_after_checkpoint(), 0);
    assert_eq!(
        verified.checkpoint().accepted_public_revision_hash(),
        plan.target_policy().terminal_revision_hash()
    );
    assert!(matches!(
        target.commit(&plan)?,
        MutationCommitOutcome::Reconciled { .. }
    ));
    assert_eq!(read_state()?, published);
    Ok(())
}

#[test]
fn commit_publishes_one_valid_artifact_then_reconciles_without_replay() -> TestResult {
    let fixture = fixture()?;
    let before_shared = fixture
        .repository
        .read_encrypted_shared_artifact(MAX_VAULT_BYTES)?;
    let before_local = {
        let locked = fixture.state.try_lock()?;
        locked.read(
            fixture.local.scope().principal_id().as_bytes(),
            PrincipalStateFile::Checkpoint,
        )?
    };
    let plan = plan(&fixture, "primary-owner")?;
    assert_eq!(before_shared, fixture.vault.to_json_bytes()?);
    assert_eq!(
        fixture
            .repository
            .read_encrypted_shared_artifact(MAX_VAULT_BYTES)?,
        before_shared
    );
    let after_plan_local = {
        let locked = fixture.state.try_lock()?;
        locked.read(
            fixture.local.scope().principal_id().as_bytes(),
            PrincipalStateFile::Checkpoint,
        )?
    };
    assert_eq!(after_plan_local, before_local);

    let target = RepositoryMutationTarget::new(
        &fixture.repository,
        &fixture.state,
        &fixture.local,
        ProtectionPolicy::EmergencyAllowDegraded,
    );
    let outcome = target.commit(&plan)?;
    assert!(matches!(outcome, MutationCommitOutcome::Committed { .. }));
    assert_ne!(
        fixture
            .repository
            .read_encrypted_shared_artifact(MAX_VAULT_BYTES)?,
        before_shared
    );
    assert_eq!(
        VaultFileV1::parse(
            &fixture
                .repository
                .read_encrypted_shared_artifact(MAX_VAULT_BYTES)?
        )?,
        *plan.target_artifact()
    );
    let after_local = {
        let locked = fixture.state.try_lock()?;
        locked.read(
            fixture.local.scope().principal_id().as_bytes(),
            PrincipalStateFile::Checkpoint,
        )?
    };
    assert_ne!(after_local, before_local);
    assert!(matches!(
        target.commit(&plan)?,
        MutationCommitOutcome::Reconciled { .. }
    ));
    assert_eq!(
        fs::read(
            fixture
                ._root
                .path()
                .join("repository")
                .join(".git")
                .join("HEAD"),
        )?,
        fixture.git_head
    );
    assert!(
        !fixture
            ._root
            .path()
            .join("repository")
            .join(".git")
            .join("index")
            .exists()
    );
    Ok(())
}

#[test]
fn catalog_update_is_committed_before_the_artifact_and_reconciles() -> TestResult {
    let fixture = fixture()?;
    let plan = plan(&fixture, "primary-owner")?;
    let prior = br#"{"version":1,"role_descriptors":[],"witness_policies":[]}"#;
    let target_catalog = br#"{"version":1,"role_descriptors":["example"],"witness_policies":[]}"#;
    let update = MutationCatalogUpdate::new(None, prior, target_catalog);
    let target = RepositoryMutationTarget::new(
        &fixture.repository,
        &fixture.state,
        &fixture.local,
        ProtectionPolicy::EmergencyAllowDegraded,
    );

    assert!(matches!(
        target.commit_with_catalog(&plan, update)?,
        MutationCommitOutcome::Committed { .. }
    ));
    {
        let locked = fixture.state.try_lock()?;
        assert_eq!(
            locked.read_vault_state(VaultStateFile::PolicyCatalog)?,
            target_catalog
        );
    }
    assert_eq!(
        VaultFileV1::parse(
            &fixture
                .repository
                .read_encrypted_shared_artifact(MAX_VAULT_BYTES)?
        )?,
        *plan.target_artifact()
    );
    assert!(matches!(
        target.commit_with_catalog(&plan, update)?,
        MutationCommitOutcome::Reconciled { .. }
    ));
    Ok(())
}

#[test]
fn catalog_precondition_conflict_preserves_the_shared_artifact() -> TestResult {
    let fixture = fixture()?;
    let plan = plan(&fixture, "primary-owner")?;
    let protected = protected(
        b"different-catalog",
        ProtectionPolicy::EmergencyAllowDegraded,
    )?;
    {
        let locked = fixture.state.try_lock()?;
        assert_eq!(
            locked
                .prepare_vault_state(VaultStateFile::PolicyCatalog, &protected)?
                .publish()?,
            PublicationOutcome::PublishedAndSynced
        );
    }
    let target = RepositoryMutationTarget::new(
        &fixture.repository,
        &fixture.state,
        &fixture.local,
        ProtectionPolicy::EmergencyAllowDegraded,
    );

    let result = target.commit_with_catalog(
        &plan,
        MutationCatalogUpdate::new(
            Some(b"expected-catalog"),
            b"expected-catalog",
            b"target-catalog",
        ),
    );
    assert!(matches!(
        result,
        Err(error) if error.kind() == MutationCommitErrorKind::InvalidLocalState
    ));
    assert_eq!(
        fixture
            .repository
            .read_encrypted_shared_artifact(MAX_VAULT_BYTES)?,
        fixture.vault.to_json_bytes()?
    );
    Ok(())
}

#[test]
fn a_different_valid_commit_makes_the_preview_stale() -> TestResult {
    let fixture = fixture()?;
    let first = plan(&fixture, "first-owner")?;
    let competing = plan(&fixture, "competing-owner")?;
    let target = RepositoryMutationTarget::new(
        &fixture.repository,
        &fixture.state,
        &fixture.local,
        ProtectionPolicy::EmergencyAllowDegraded,
    );
    assert!(matches!(
        target.commit(&competing)?,
        MutationCommitOutcome::Committed { .. }
    ));
    let committed_shared = fixture
        .repository
        .read_encrypted_shared_artifact(MAX_VAULT_BYTES)?;
    let committed_checkpoint = {
        let locked = fixture.state.try_lock()?;
        locked.read(
            fixture.local.scope().principal_id().as_bytes(),
            PrincipalStateFile::Checkpoint,
        )?
    };
    let stale = target.commit(&first);
    assert!(matches!(
        stale,
        Err(error) if error.kind() == MutationCommitErrorKind::StaleArtifact
    ));
    assert_eq!(
        fixture
            .repository
            .read_encrypted_shared_artifact(MAX_VAULT_BYTES)?,
        committed_shared
    );
    let after_stale_checkpoint = {
        let locked = fixture.state.try_lock()?;
        locked.read(
            fixture.local.scope().principal_id().as_bytes(),
            PrincipalStateFile::Checkpoint,
        )?
    };
    assert_eq!(after_stale_checkpoint, committed_checkpoint);
    Ok(())
}

#[test]
fn changed_git_ancestry_refuses_an_unchanged_vault_preview() -> TestResult {
    let fixture = fixture()?;
    let plan = plan(&fixture, "primary-owner")?;
    fs::write(
        fixture
            ._root
            .path()
            .join("repository")
            .join(".git")
            .join("HEAD"),
        b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n",
    )?;
    let target = RepositoryMutationTarget::new(
        &fixture.repository,
        &fixture.state,
        &fixture.local,
        ProtectionPolicy::EmergencyAllowDegraded,
    );
    assert!(matches!(
        target.commit(&plan),
        Err(error) if error.kind() == MutationCommitErrorKind::StaleArtifact
    ));
    assert_eq!(
        fixture
            .repository
            .read_encrypted_shared_artifact(MAX_VAULT_BYTES)?,
        fixture.vault.to_json_bytes()?
    );
    Ok(())
}

#[test]
fn git_ref_movement_after_audit_intent_refuses_publication_and_retries() -> TestResult {
    let fixture = fixture()?;
    let refs = fixture
        ._root
        .path()
        .join("repository")
        .join(".git")
        .join("refs")
        .join("heads");
    fs::create_dir_all(&refs)?;
    let plan = plan(&fixture, "primary-owner")?;
    let principal = fixture.local.scope().principal_id();
    let (audit_before, checkpoint_before) = {
        let locked = fixture.state.try_lock()?;
        (
            locked.read(principal.as_bytes(), PrincipalStateFile::Audit)?,
            locked.read(principal.as_bytes(), PrincipalStateFile::Checkpoint)?,
        )
    };
    let target = RepositoryMutationTarget::new(
        &fixture.repository,
        &fixture.state,
        &fixture.local,
        ProtectionPolicy::EmergencyAllowDegraded,
    );

    let result = target
        .inner
        .commit_with_before_shared_publish(&plan, None, || {
            fs::write(
                refs.join("main"),
                b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n",
            )
            .map_err(|_| MutationCommitError::new(MutationCommitErrorKind::InvalidLocalState))
        });
    assert!(matches!(
        result,
        Err(error) if error.kind() == MutationCommitErrorKind::StaleArtifact
    ));
    assert_eq!(
        fixture
            .repository
            .read_encrypted_shared_artifact(MAX_VAULT_BYTES)?,
        fixture.vault.to_json_bytes()?
    );
    {
        let locked = fixture.state.try_lock()?;
        assert_ne!(
            locked.read(principal.as_bytes(), PrincipalStateFile::Audit)?,
            audit_before
        );
        assert_eq!(
            locked.read(principal.as_bytes(), PrincipalStateFile::Checkpoint)?,
            checkpoint_before
        );
    }

    fs::remove_file(refs.join("main"))?;
    assert!(matches!(
        target.commit(&plan)?,
        MutationCommitOutcome::Committed { .. }
    ));
    assert_eq!(
        VaultFileV1::parse(
            &fixture
                .repository
                .read_encrypted_shared_artifact(MAX_VAULT_BYTES)?
        )?,
        *plan.target_artifact()
    );
    Ok(())
}

#[test]
fn vault_lock_is_shared_across_handles_and_paths_are_redacted() -> TestResult {
    let fixture = fixture()?;
    let second = VaultStateDirectory::open_or_create(
        &fixture._root.path().join("state"),
        fixture.vault.header.vault_id.as_bytes(),
        fixture.vault.header.genesis_fingerprint.as_bytes(),
        &[&fixture.repository],
        &[Path::new("/tmp/ExampleVaultHome")],
    );
    // The excluded path above does not exist and is disjoint from the state root.
    let second = second?;
    let held = fixture.state.try_lock()?;
    assert!(matches!(second.try_lock(), Err(LockError::Busy)));
    assert!(!format!("{held:?}").contains(fixture._root.path().to_string_lossy().as_ref()));
    Ok(())
}

#[test]
fn checkpoint_failure_after_primary_is_reported_as_committed() -> TestResult {
    let fixture = fixture()?;
    let plan = plan(&fixture, "primary-owner")?;
    let target = RepositoryMutationTarget::new(
        &fixture.repository,
        &fixture.state,
        &fixture.local,
        ProtectionPolicy::EmergencyAllowDegraded,
    );
    let locked = fixture.state.try_lock()?;
    let principal = fixture.local.scope().principal_id();
    let audit = locked.read(principal.as_bytes(), PrincipalStateFile::Audit)?;
    let checkpoint = locked.read(principal.as_bytes(), PrincipalStateFile::Checkpoint)?;
    let receipts = locked.read(principal.as_bytes(), PrincipalStateFile::Receipts)?;
    let mut local_state =
        fixture
            .local
            .verify_files(Some(&audit), Some(&checkpoint), Some(&receipts))?;
    fixture
        .local
        .append_event(&mut local_state, plan.audit_intent())?;

    let checkpoint_path = fixture
        ._root
        .path()
        .join("state")
        .join(hex(fixture.vault.header.vault_id.as_bytes()))
        .join(hex(fixture.vault.header.genesis_fingerprint.as_bytes()))
        .join(hex(principal.as_bytes()))
        .join("checkpoint.json");
    fs::remove_file(&checkpoint_path)?;
    fs::create_dir(&checkpoint_path)?;

    let outcome = target.inner.finish_checkpoint(
        &plan,
        &locked,
        &mut local_state,
        PublicationOutcome::PublishedAndSynced,
        false,
        true,
    )?;
    assert!(matches!(
        outcome,
        MutationCommitOutcome::CommittedLocalRecoveryRequired {
            reason: LocalRecoveryReason::CheckpointPrepareFailed,
            ..
        }
    ));
    Ok(())
}

fn hex(bytes: &[u8; 32]) -> String {
    let mut output = String::with_capacity(64);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}
