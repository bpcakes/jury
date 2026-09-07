//! Durable repository publication for exact core mutation plans.

use std::fmt;

use jury_core::local_state::{
    CheckpointCandidate, CheckpointRelation, LocalStateErrorKind, PrincipalLocalState,
};
use jury_core::mutation::{MutationKind, MutationWarnings, VaultMutationPlan};
use jury_core::policy::replay_policy_with_witness_policies;
use jury_filesystem::{
    FilesystemError, FilesystemErrorKind, HardenedStateRoot, LockError, PreparedPrivateFile,
    PrincipalStateFile, PrivateFilePrecondition, PublicationOutcome, RepositoryLocation,
    VaultStateDirectory, VaultStateFile,
};
use jury_protected::{ProtectedMemory, ProtectionPolicy};
use jury_protocol::vault_v1::{Digest32, FixedBytes, MAX_VAULT_BYTES, VaultFileV1};
use sha2::{Digest as _, Sha256};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MutationCommitErrorKind {
    Busy,
    StaleArtifact,
    InvalidArtifact,
    InvalidLocalState,
    AuditIntentNotDurable,
    SharedPublicationFailed,
    ProtectionUnavailable,
    MissingRepositoryPrecondition,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct MutationCommitError {
    kind: MutationCommitErrorKind,
}

impl MutationCommitError {
    const fn new(kind: MutationCommitErrorKind) -> Self {
        Self { kind }
    }

    #[must_use]
    pub const fn kind(self) -> MutationCommitErrorKind {
        self.kind
    }
}

impl fmt::Debug for MutationCommitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MutationCommitError")
            .field("kind", &self.kind)
            .finish()
    }
}

impl fmt::Display for MutationCommitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.kind {
            MutationCommitErrorKind::Busy => "vault mutation lock is busy",
            MutationCommitErrorKind::StaleArtifact => "vault artifact changed after preview",
            MutationCommitErrorKind::InvalidArtifact => "vault artifact is invalid",
            MutationCommitErrorKind::InvalidLocalState => "principal local state is invalid",
            MutationCommitErrorKind::AuditIntentNotDurable => {
                "mutation audit intent was not durably published"
            }
            MutationCommitErrorKind::SharedPublicationFailed => {
                "encrypted shared artifact was not published"
            }
            MutationCommitErrorKind::ProtectionUnavailable => {
                "protected publication memory is unavailable"
            }
            MutationCommitErrorKind::MissingRepositoryPrecondition => {
                "Git-backed mutation has no repository ancestry precondition"
            }
        })
    }
}

impl std::error::Error for MutationCommitError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalRecoveryReason {
    CheckpointPrepareFailed,
    CheckpointPublishFailed,
    CheckpointParentUnsynced,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MutationCommitOutcome {
    Committed {
        shared_publication: PublicationOutcome,
        warnings: MutationWarnings,
    },
    Reconciled {
        warnings: MutationWarnings,
    },
    CommittedLocalRecoveryRequired {
        shared_publication: PublicationOutcome,
        reason: LocalRecoveryReason,
        warnings: MutationWarnings,
    },
}

#[derive(Clone, Copy)]
pub struct MutationCatalogUpdate<'a> {
    prior: Option<&'a [u8]>,
    rollback: &'a [u8],
    target: &'a [u8],
}

impl<'a> MutationCatalogUpdate<'a> {
    #[must_use]
    pub const fn new(prior: Option<&'a [u8]>, rollback: &'a [u8], target: &'a [u8]) -> Self {
        Self {
            prior,
            rollback,
            target,
        }
    }
}

/// Composes the core plan with the only two durable authorities it may change:
/// the encrypted worktree artifact and the acting principal's separate state.
pub struct RepositoryMutationTarget<'a> {
    inner: MutationCommitTarget<'a>,
}

/// Durable publication target for an explicit/global vault outside Git.
pub struct DetachedMutationTarget<'a> {
    inner: MutationCommitTarget<'a>,
}

#[derive(Clone, Copy)]
enum SharedArtifact<'a> {
    Repository(&'a RepositoryLocation),
    Detached(&'a HardenedStateRoot),
}

struct MutationCommitTarget<'a> {
    shared: SharedArtifact<'a>,
    state: &'a VaultStateDirectory,
    local: &'a PrincipalLocalState,
    protection: ProtectionPolicy,
}

impl<'a> RepositoryMutationTarget<'a> {
    #[must_use]
    pub const fn new(
        repository: &'a RepositoryLocation,
        state: &'a VaultStateDirectory,
        local: &'a PrincipalLocalState,
        protection: ProtectionPolicy,
    ) -> Self {
        Self {
            inner: MutationCommitTarget {
                shared: SharedArtifact::Repository(repository),
                state,
                local,
                protection,
            },
        }
    }

    pub fn commit(
        &self,
        plan: &VaultMutationPlan,
    ) -> Result<MutationCommitOutcome, MutationCommitError> {
        self.inner.commit(plan, None)
    }

    pub fn commit_with_catalog(
        &self,
        plan: &VaultMutationPlan,
        catalog: MutationCatalogUpdate<'_>,
    ) -> Result<MutationCommitOutcome, MutationCommitError> {
        self.inner.commit(plan, Some(catalog))
    }
}

impl<'a> DetachedMutationTarget<'a> {
    #[must_use]
    pub const fn new(
        home: &'a HardenedStateRoot,
        state: &'a VaultStateDirectory,
        local: &'a PrincipalLocalState,
        protection: ProtectionPolicy,
    ) -> Self {
        Self {
            inner: MutationCommitTarget {
                shared: SharedArtifact::Detached(home),
                state,
                local,
                protection,
            },
        }
    }

    pub fn commit(
        &self,
        plan: &VaultMutationPlan,
    ) -> Result<MutationCommitOutcome, MutationCommitError> {
        self.inner.commit(plan, None)
    }

    pub fn commit_with_catalog(
        &self,
        plan: &VaultMutationPlan,
        catalog: MutationCatalogUpdate<'_>,
    ) -> Result<MutationCommitOutcome, MutationCommitError> {
        self.inner.commit(plan, Some(catalog))
    }
}

impl SharedArtifact<'_> {
    fn preview(self) -> Result<PrivateFilePrecondition, FilesystemError> {
        match self {
            Self::Repository(repository) => repository.preview_encrypted_shared_artifact(),
            Self::Detached(home) => home.preview_private_file(std::path::Path::new("vault.json")),
        }
    }

    fn read(self, maximum_bytes: usize) -> Result<Vec<u8>, FilesystemError> {
        match self {
            Self::Repository(repository) => {
                repository.read_encrypted_shared_artifact(maximum_bytes)
            }
            Self::Detached(home) => {
                home.read_private_file(std::path::Path::new("vault.json"), maximum_bytes)
            }
        }
    }

    fn prepare(
        self,
        precondition: PrivateFilePrecondition,
        contents: &ProtectedMemory,
    ) -> Result<PreparedPrivateFile, FilesystemError> {
        let _ = self;
        PreparedPrivateFile::prepare_if_unchanged(precondition, contents, true)
    }

    const fn matches_ancestry(self, expected: Option<[u8; 32]>) -> bool {
        matches!(
            (self, expected),
            (Self::Repository(_), Some(_)) | (Self::Detached(_), None)
        )
    }

    fn ancestry_is_current(self, expected: Option<[u8; 32]>) -> Result<bool, MutationCommitError> {
        match (self, expected) {
            (Self::Repository(repository), Some(expected)) => Ok(repository
                .git_ancestry_digest()
                .map_err(map_git_ancestry_error)?
                == expected),
            (Self::Detached(_), None) => Ok(true),
            _ => Err(MutationCommitError::new(
                MutationCommitErrorKind::MissingRepositoryPrecondition,
            )),
        }
    }
}

impl MutationCommitTarget<'_> {
    fn commit(
        &self,
        plan: &VaultMutationPlan,
        catalog_update: Option<MutationCatalogUpdate<'_>>,
    ) -> Result<MutationCommitOutcome, MutationCommitError> {
        self.commit_with_before_shared_publish(plan, catalog_update, || Ok(()))
    }

    fn commit_with_before_shared_publish<F>(
        &self,
        plan: &VaultMutationPlan,
        catalog_update: Option<MutationCatalogUpdate<'_>>,
        before_shared_publish: F,
    ) -> Result<MutationCommitOutcome, MutationCommitError>
    where
        F: FnOnce() -> Result<(), MutationCommitError>,
    {
        if self.local.scope().vault_id() != plan.target_artifact().header.vault_id
            || self.local.scope().genesis_fingerprint()
                != &plan.target_artifact().header.genesis_fingerprint
            || self.local.scope().principal_id() != plan.acting_principal_id()
        {
            return Err(MutationCommitError::new(
                MutationCommitErrorKind::InvalidLocalState,
            ));
        }

        let locked = self.state.try_lock().map_err(map_lock_error)?;
        let prepared_catalog = catalog_update
            .map(|update| self.prepare_catalog_update(&locked, update))
            .transpose()?
            .flatten();
        let shared_precondition = self.shared.preview().map_err(map_shared_read_error)?;
        let current_bytes = self
            .shared
            .read(MAX_VAULT_BYTES)
            .map_err(map_shared_read_error)?;
        let current = VaultFileV1::parse(&current_bytes)
            .map_err(|_| MutationCommitError::new(MutationCommitErrorKind::InvalidArtifact))?;
        let current_policy =
            replay_policy_with_witness_policies(&current.policy, plan.witness_policies())
                .map_err(|_| MutationCommitError::new(MutationCommitErrorKind::InvalidArtifact))?;
        CheckpointCandidate::from_validated(&current_policy, &current.policy, &current.items)
            .map_err(|_| MutationCommitError::new(MutationCommitErrorKind::InvalidArtifact))?;

        let current_digest = sha256(&current_bytes);
        let is_expected = current_digest == plan.precondition().vault_digest
            && current_policy.sequence() == plan.precondition().policy_sequence
            && current_policy.terminal_revision_hash() == &plan.precondition().policy_revision_hash;
        let is_target = current_digest == *plan.target_digest()
            && current_policy.sequence() == plan.target_policy().sequence()
            && current_policy.terminal_revision_hash()
                == plan.target_policy().terminal_revision_hash();
        if !is_expected && !is_target {
            return Err(MutationCommitError::new(
                MutationCommitErrorKind::StaleArtifact,
            ));
        }
        let expected_ancestry = plan.precondition().repository_ancestry;
        if !self.shared.matches_ancestry(expected_ancestry) {
            return Err(MutationCommitError::new(
                MutationCommitErrorKind::MissingRepositoryPrecondition,
            ));
        }
        if is_expected && !self.shared.ancestry_is_current(expected_ancestry)? {
            return Err(MutationCommitError::new(
                MutationCommitErrorKind::StaleArtifact,
            ));
        }

        let principal_id = self.local.scope().principal_id();
        let audit = locked
            .read(principal_id.as_bytes(), PrincipalStateFile::Audit)
            .map_err(map_local_error)?;
        let checkpoint = locked
            .read(principal_id.as_bytes(), PrincipalStateFile::Checkpoint)
            .map_err(map_local_error)?;
        let receipts = locked
            .read(principal_id.as_bytes(), PrincipalStateFile::Receipts)
            .map_err(map_local_error)?;
        let mut local_state = self
            .local
            .verify_files(Some(&audit), Some(&checkpoint), Some(&receipts))
            .map_err(|_| MutationCommitError::new(MutationCommitErrorKind::InvalidLocalState))?;

        let current_candidate = if current_policy.principal(&principal_id).is_none()
            && plan.kind() == MutationKind::TransferImport
        {
            // A transfer may register the importing principal. Its local
            // checkpoint then starts at the authenticated target revision;
            // it cannot authenticate a scope absent from the old snapshot.
            // Exact source bytes, Git ancestry, catalog and publication checks
            // above and below remain mandatory, including on retry.
            plan.checkpoint_candidate()
                .map_err(|_| MutationCommitError::new(MutationCommitErrorKind::InvalidArtifact))?
        } else {
            CheckpointCandidate::from_validated(&current_policy, &current.policy, &current.items)
                .map_err(|_| MutationCommitError::new(MutationCommitErrorKind::InvalidArtifact))?
        };
        let current_relation = self
            .local
            .accept_candidate(
                &mut local_state,
                &current_candidate,
                plan.audit_intent().timestamp_ms,
            )
            .map_err(map_checkpoint_error)?;

        if is_target {
            if let Some(prepared) = prepared_catalog {
                publish_catalog(prepared)?;
            }
            return self.reconcile(
                plan,
                &locked,
                &mut local_state,
                current_relation == CheckpointRelation::StrictDescendant,
            );
        }

        if !local_state.contains_operation(plan.target_digest()) {
            self.local
                .append_event(&mut local_state, plan.audit_intent())
                .map_err(map_local_state_error)?;
        } else {
            self.local
                .accept_audit_tail(&mut local_state, plan.audit_intent().timestamp_ms)
                .map_err(map_local_state_error)?;
        }
        let intent_files = self
            .local
            .serialize(&local_state)
            .map_err(map_local_state_error)?;
        let protected_audit = protect(intent_files.audit(), self.protection)?;
        let prepared_audit = locked
            .prepare(
                principal_id.as_bytes(),
                PrincipalStateFile::Audit,
                &protected_audit,
            )
            .map_err(map_local_error)?;
        let target_candidate = plan
            .checkpoint_candidate()
            .map_err(|_| MutationCommitError::new(MutationCommitErrorKind::InvalidArtifact))?;
        self.local
            .accept_candidate(
                &mut local_state,
                &target_candidate,
                plan.audit_intent().timestamp_ms,
            )
            .map_err(map_checkpoint_error)?;
        let final_files = self
            .local
            .serialize(&local_state)
            .map_err(map_local_state_error)?;
        let protected_checkpoint = protect(final_files.checkpoint(), self.protection)?;
        let prepared_checkpoint = locked
            .prepare(
                principal_id.as_bytes(),
                PrincipalStateFile::Checkpoint,
                &protected_checkpoint,
            )
            .map_err(map_local_error)?;
        let protected_shared = protect(plan.target_bytes(), self.protection)?;
        let prepared_shared = self
            .shared
            .prepare(shared_precondition, &protected_shared)
            .map_err(|error| map_shared_prepare_error(&error))?;

        let audit_outcome = prepared_audit.publish().map_err(map_local_error)?;
        if audit_outcome != PublicationOutcome::PublishedAndSynced {
            return Err(MutationCommitError::new(
                MutationCommitErrorKind::AuditIntentNotDurable,
            ));
        }

        before_shared_publish()?;
        if !self.shared.ancestry_is_current(expected_ancestry)? {
            return Err(MutationCommitError::new(
                MutationCommitErrorKind::StaleArtifact,
            ));
        }

        let catalog_published = if let Some(prepared) = prepared_catalog {
            publish_catalog(prepared)?;
            true
        } else {
            false
        };
        let shared_publication = match prepared_shared.publish() {
            Ok(outcome) => outcome,
            Err(error) => {
                if catalog_published
                    && !self
                        .shared
                        .read(MAX_VAULT_BYTES)
                        .is_ok_and(|bytes| sha256(&bytes) == *plan.target_digest())
                    && let Some(update) = catalog_update
                {
                    self.restore_catalog(&locked, update)?;
                }
                return Err(map_shared_prepare_error(&error));
            }
        };
        let checkpoint_outcome = match prepared_checkpoint.publish() {
            Ok(outcome) => outcome,
            Err(_) => {
                return Ok(committed_recovery(
                    shared_publication,
                    LocalRecoveryReason::CheckpointPublishFailed,
                    plan,
                ));
            }
        };
        match checkpoint_outcome {
            PublicationOutcome::PublishedAndSynced => Ok(MutationCommitOutcome::Committed {
                shared_publication,
                warnings: plan.warnings().clone(),
            }),
            PublicationOutcome::PublishedButParentUnsynced => Ok(committed_recovery(
                shared_publication,
                LocalRecoveryReason::CheckpointParentUnsynced,
                plan,
            )),
        }
    }

    fn prepare_catalog_update(
        &self,
        locked: &jury_filesystem::LockedVaultState<'_>,
        update: MutationCatalogUpdate<'_>,
    ) -> Result<Option<PreparedPrivateFile>, MutationCommitError> {
        match locked.read_vault_state(VaultStateFile::PolicyCatalog) {
            Ok(bytes) if bytes == update.target => return Ok(None),
            Ok(bytes) if update.prior == Some(bytes.as_slice()) => {}
            Err(error)
                if error.kind() == FilesystemErrorKind::NotFound && update.prior.is_none() => {}
            Ok(_) | Err(_) => {
                return Err(MutationCommitError::new(
                    MutationCommitErrorKind::InvalidLocalState,
                ));
            }
        }
        let protected = protect(update.target, self.protection)?;
        locked
            .prepare_vault_state(VaultStateFile::PolicyCatalog, &protected)
            .map(Some)
            .map_err(map_local_error)
    }

    fn restore_catalog(
        &self,
        locked: &jury_filesystem::LockedVaultState<'_>,
        update: MutationCatalogUpdate<'_>,
    ) -> Result<(), MutationCommitError> {
        let protected = protect(update.rollback, self.protection)?;
        let prepared = locked
            .prepare_vault_state(VaultStateFile::PolicyCatalog, &protected)
            .map_err(map_local_error)?;
        publish_catalog(prepared)
    }

    fn reconcile(
        &self,
        plan: &VaultMutationPlan,
        locked: &jury_filesystem::LockedVaultState<'_>,
        local_state: &mut jury_core::local_state::VerifiedLocalState,
        mut checkpoint_changed: bool,
    ) -> Result<MutationCommitOutcome, MutationCommitError> {
        if !local_state.contains_operation(plan.target_digest()) {
            checkpoint_changed = true;
            self.local
                .append_event(local_state, plan.audit_intent())
                .map_err(map_local_state_error)?;
            let files = self
                .local
                .serialize(local_state)
                .map_err(map_local_state_error)?;
            let protected = protect(files.audit(), self.protection)?;
            let outcome = locked
                .publish(
                    self.local.scope().principal_id().as_bytes(),
                    PrincipalStateFile::Audit,
                    &protected,
                )
                .map_err(map_local_error)?;
            if outcome != PublicationOutcome::PublishedAndSynced {
                return Ok(MutationCommitOutcome::CommittedLocalRecoveryRequired {
                    shared_publication: PublicationOutcome::PublishedAndSynced,
                    reason: LocalRecoveryReason::CheckpointPrepareFailed,
                    warnings: plan.warnings().clone(),
                });
            }
        } else if local_state.audit_events_after_checkpoint() != 0 {
            checkpoint_changed = true;
            self.local
                .accept_audit_tail(local_state, plan.audit_intent().timestamp_ms)
                .map_err(map_local_state_error)?;
        }
        self.finish_checkpoint(
            plan,
            locked,
            local_state,
            PublicationOutcome::PublishedAndSynced,
            true,
            checkpoint_changed,
        )
    }

    fn finish_checkpoint(
        &self,
        plan: &VaultMutationPlan,
        locked: &jury_filesystem::LockedVaultState<'_>,
        local_state: &mut jury_core::local_state::VerifiedLocalState,
        shared_publication: PublicationOutcome,
        reconciled: bool,
        checkpoint_changed: bool,
    ) -> Result<MutationCommitOutcome, MutationCommitError> {
        let candidate = plan
            .checkpoint_candidate()
            .map_err(|_| MutationCommitError::new(MutationCommitErrorKind::InvalidArtifact))?;
        let relation = self
            .local
            .accept_candidate(local_state, &candidate, plan.audit_intent().timestamp_ms)
            .map_err(map_checkpoint_error)?;
        if reconciled && relation == CheckpointRelation::Equal && !checkpoint_changed {
            return Ok(MutationCommitOutcome::Reconciled {
                warnings: plan.warnings().clone(),
            });
        }
        let files = match self.local.serialize(local_state) {
            Ok(files) => files,
            Err(_) => {
                return Ok(committed_recovery(
                    shared_publication,
                    LocalRecoveryReason::CheckpointPrepareFailed,
                    plan,
                ));
            }
        };
        let protected = match protect(files.checkpoint(), self.protection) {
            Ok(protected) => protected,
            Err(_) => {
                return Ok(committed_recovery(
                    shared_publication,
                    LocalRecoveryReason::CheckpointPrepareFailed,
                    plan,
                ));
            }
        };
        let prepared = match locked.prepare(
            self.local.scope().principal_id().as_bytes(),
            PrincipalStateFile::Checkpoint,
            &protected,
        ) {
            Ok(prepared) => prepared,
            Err(_) => {
                return Ok(committed_recovery(
                    shared_publication,
                    LocalRecoveryReason::CheckpointPrepareFailed,
                    plan,
                ));
            }
        };
        let checkpoint_outcome = match prepared.publish() {
            Ok(outcome) => outcome,
            Err(_) => {
                return Ok(committed_recovery(
                    shared_publication,
                    LocalRecoveryReason::CheckpointPublishFailed,
                    plan,
                ));
            }
        };
        match checkpoint_outcome {
            PublicationOutcome::PublishedAndSynced if reconciled => {
                Ok(MutationCommitOutcome::Reconciled {
                    warnings: plan.warnings().clone(),
                })
            }
            PublicationOutcome::PublishedAndSynced => Ok(MutationCommitOutcome::Committed {
                shared_publication,
                warnings: plan.warnings().clone(),
            }),
            PublicationOutcome::PublishedButParentUnsynced => Ok(committed_recovery(
                shared_publication,
                LocalRecoveryReason::CheckpointParentUnsynced,
                plan,
            )),
        }
    }
}

fn committed_recovery(
    shared_publication: PublicationOutcome,
    reason: LocalRecoveryReason,
    plan: &VaultMutationPlan,
) -> MutationCommitOutcome {
    MutationCommitOutcome::CommittedLocalRecoveryRequired {
        shared_publication,
        reason,
        warnings: plan.warnings().clone(),
    }
}

fn publish_catalog(prepared: PreparedPrivateFile) -> Result<(), MutationCommitError> {
    if prepared.publish().map_err(map_local_error)? != PublicationOutcome::PublishedAndSynced {
        return Err(MutationCommitError::new(
            MutationCommitErrorKind::InvalidLocalState,
        ));
    }
    Ok(())
}

fn protect(bytes: &[u8], policy: ProtectionPolicy) -> Result<ProtectedMemory, MutationCommitError> {
    let initialize = |destination: &mut [u8]| {
        destination.copy_from_slice(bytes);
        Ok::<usize, ()>(destination.len())
    };
    let protected = ProtectedMemory::initialize_supported(bytes.len(), policy, initialize);
    protected.map_err(|_| MutationCommitError::new(MutationCommitErrorKind::ProtectionUnavailable))
}

fn sha256(bytes: &[u8]) -> Digest32 {
    FixedBytes::new(Sha256::digest(bytes).into())
}

fn map_lock_error(error: LockError) -> MutationCommitError {
    MutationCommitError::new(match error {
        LockError::Busy => MutationCommitErrorKind::Busy,
        _ => MutationCommitErrorKind::InvalidLocalState,
    })
}

fn map_shared_read_error(_: FilesystemError) -> MutationCommitError {
    MutationCommitError::new(MutationCommitErrorKind::InvalidArtifact)
}

fn map_git_ancestry_error(_: FilesystemError) -> MutationCommitError {
    MutationCommitError::new(MutationCommitErrorKind::StaleArtifact)
}

fn map_shared_prepare_error(error: &FilesystemError) -> MutationCommitError {
    use jury_filesystem::FilesystemErrorKind;
    MutationCommitError::new(match error.kind() {
        FilesystemErrorKind::IdentityChanged | FilesystemErrorKind::NotFound => {
            MutationCommitErrorKind::StaleArtifact
        }
        _ => MutationCommitErrorKind::SharedPublicationFailed,
    })
}

fn map_local_error(_: FilesystemError) -> MutationCommitError {
    MutationCommitError::new(MutationCommitErrorKind::InvalidLocalState)
}

fn map_local_state_error(error: jury_core::local_state::LocalStateError) -> MutationCommitError {
    MutationCommitError::new(match error.kind() {
        LocalStateErrorKind::ProtectionUnavailable => {
            MutationCommitErrorKind::ProtectionUnavailable
        }
        _ => MutationCommitErrorKind::InvalidLocalState,
    })
}

fn map_checkpoint_error(_: jury_core::local_state::LocalStateError) -> MutationCommitError {
    MutationCommitError::new(MutationCommitErrorKind::InvalidLocalState)
}

#[cfg(all(test, unix))]
mod tests;
