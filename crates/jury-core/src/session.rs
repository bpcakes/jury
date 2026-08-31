//! Public-first vault validation and principal-scoped partial-unlock sessions.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::marker::PhantomData;

use jury_protocol::vault_v1::{
    AccessRole, ContentRole, Digest32, ItemAccessMode, ItemDescriptorV1, ItemEnvelopeV1,
    ItemId as ProtocolItemId, ItemStateV1, PolicyJournalV1, PrincipalId, RevisionSealId, SlotId,
    VaultId, WitnessPolicyId,
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::access_provider::{
    AccessCompletion, AccessProviderError, AccessProviderErrorKind, CancellationCheck,
    ItemAccessError, ItemAccessOutcome, ItemAccessProvider, RevisionAccessRequest,
    RevisionAccessTarget, ScopedRevisionAccess, WitnessedAccessStatus,
};
use crate::domain::{
    AccessibleCatalog, AccessibleCatalogEntry, Capability, CatalogError, ItemId as DomainItemId,
    ItemName, ItemSelector, Role,
};
use crate::local_state::{CheckpointCandidate, CheckpointRelation, LocalCheckpoint};
use crate::policy::{PolicyState, WitnessOperation};

const ZERO_DIGEST: [u8; 32] = [0; 32];

/// Protocol-wide bound for an explicit aggregate operation.
pub const MAX_PREFLIGHT_ITEMS: usize = 64;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SessionPhase {
    Parsed,
    PublicValidated,
    Principal,
    WitnessPending,
    Approved,
    Denied,
    Expired,
    Stale,
    Replay,
    Unavailable,
    Cancelled,
    Failed,
    UnlockedItem,
    Locked,
    InsufficientQuorum,
}

impl SessionPhase {
    const fn is_operable(self) -> bool {
        matches!(
            self,
            Self::Principal | Self::Approved | Self::UnlockedItem | Self::WitnessPending
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionErrorKind {
    InvalidPublicState,
    ScopeMismatch,
    CheckpointConflict,
    UnknownPrincipal,
    InvalidLimits,
    ClockRegression,
    Expired,
    Cancelled,
    Unavailable,
    InvalidBinding,
    Conflict,
    CapacityExhausted,
    Locked,
    Failed,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct SessionError {
    kind: SessionErrorKind,
}

impl SessionError {
    const fn new(kind: SessionErrorKind) -> Self {
        Self { kind }
    }

    #[must_use]
    pub const fn kind(self) -> SessionErrorKind {
        self.kind
    }
}

impl fmt::Debug for SessionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionError")
            .field("kind", &self.kind)
            .finish()
    }
}

impl fmt::Display for SessionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.kind {
            SessionErrorKind::InvalidPublicState => "vault public state is invalid",
            SessionErrorKind::ScopeMismatch => "session scope differs",
            SessionErrorKind::CheckpointConflict => "vault checkpoint conflicts",
            SessionErrorKind::UnknownPrincipal => "selected principal is unavailable",
            SessionErrorKind::InvalidLimits => "session limits are invalid",
            SessionErrorKind::ClockRegression => "session clock moved backwards",
            SessionErrorKind::Expired => "session expired",
            SessionErrorKind::Cancelled => "session was cancelled",
            SessionErrorKind::Unavailable => "requested item is unavailable",
            SessionErrorKind::InvalidBinding => "witness request scope differs",
            SessionErrorKind::Conflict => "session operation conflicts",
            SessionErrorKind::CapacityExhausted => "session capacity is exhausted",
            SessionErrorKind::Locked => "session is locked",
            SessionErrorKind::Failed => "session operation failed",
        })
    }
}

impl std::error::Error for SessionError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionLimits {
    inactivity_timeout_ms: u64,
    absolute_lifetime_ms: u64,
}

impl SessionLimits {
    pub const fn new(
        inactivity_timeout_ms: u64,
        absolute_lifetime_ms: u64,
    ) -> Result<Self, SessionError> {
        if inactivity_timeout_ms == 0
            || absolute_lifetime_ms == 0
            || inactivity_timeout_ms > absolute_lifetime_ms
        {
            return Err(SessionError::new(SessionErrorKind::InvalidLimits));
        }
        Ok(Self {
            inactivity_timeout_ms,
            absolute_lifetime_ms,
        })
    }

    #[must_use]
    pub const fn inactivity_timeout_ms(self) -> u64 {
        self.inactivity_timeout_ms
    }

    #[must_use]
    pub const fn absolute_lifetime_ms(self) -> u64 {
        self.absolute_lifetime_ms
    }
}

/// Exact authenticated item revision and authority scope for one access.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RevisionToken {
    pub suite: u16,
    pub vault_id: VaultId,
    pub genesis_fingerprint: Digest32,
    pub item_id: ProtocolItemId,
    pub key_epoch: u64,
    pub content_role: ContentRole,
    pub revision: u64,
    pub revision_seal_id: RevisionSealId,
    pub policy_sequence: u64,
    pub policy_revision_hash: Digest32,
    pub principal_id: PrincipalId,
    pub access_role: AccessRole,
    pub item_access_mode: ItemAccessMode,
    pub capability: Capability,
}

impl RevisionToken {
    fn current(
        policy: &PolicyState,
        target: &RevisionAccessTarget,
        capability: Capability,
    ) -> Self {
        Self {
            suite: target.suite,
            vault_id: target.vault_id,
            genesis_fingerprint: policy.genesis_fingerprint().clone(),
            item_id: target.item_id,
            key_epoch: target.key_epoch,
            content_role: target.content_role,
            revision: target.revision,
            revision_seal_id: target.revision_seal_id,
            policy_sequence: target.policy_sequence,
            policy_revision_hash: target.policy_revision_hash.clone(),
            principal_id: target.principal_id,
            access_role: target.access_role,
            item_access_mode: target.item_access_mode,
            capability,
        }
    }
}

/// Public fields that pin one witnessed request to its exact operation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessRequestBinding {
    pub request_id: Digest32,
    pub request_digest: Digest32,
    pub action_manifest_digest: Digest32,
    pub approval_target_digest: Digest32,
    pub workload_digest: Digest32,
    pub policy_checkpoint_digest: Digest32,
    pub witness_policy_id: WitnessPolicyId,
    pub witness_policy_revision: u64,
    pub witness_policy_digest: Digest32,
    pub intended_witness_set_digest: Digest32,
    pub request_session_key_fingerprint: Digest32,
    pub slot_id: SlotId,
    pub operation: WitnessOperation,
    pub issued_at_ms: u64,
    pub not_before_ms: Option<u64>,
    pub expires_at_ms: u64,
    pub revision: RevisionToken,
}

/// A parsed vault has not yet earned any authorization-bearing state.
pub struct ParsedVault<'a> {
    policy: &'a PolicyState,
    journal: &'a PolicyJournalV1,
    envelopes: &'a [ItemEnvelopeV1],
}

impl<'a> ParsedVault<'a> {
    #[must_use]
    pub const fn new(
        policy: &'a PolicyState,
        journal: &'a PolicyJournalV1,
        envelopes: &'a [ItemEnvelopeV1],
    ) -> Self {
        Self {
            policy,
            journal,
            envelopes,
        }
    }

    #[must_use]
    pub const fn phase(&self) -> SessionPhase {
        SessionPhase::Parsed
    }

    pub fn validate_public(self) -> Result<ValidatedPublicVault<'a>, SessionError> {
        let checkpoint_candidate =
            CheckpointCandidate::from_validated(self.policy, self.journal, self.envelopes)
                .map_err(|_| SessionError::new(SessionErrorKind::InvalidPublicState))?;
        Ok(ValidatedPublicVault {
            policy: self.policy,
            envelopes: self.envelopes,
            checkpoint_candidate,
        })
    }
}

/// Signature- and ancestry-validated public state. No descriptor or body has
/// been decrypted to construct this value.
pub struct ValidatedPublicVault<'a> {
    policy: &'a PolicyState,
    envelopes: &'a [ItemEnvelopeV1],
    checkpoint_candidate: CheckpointCandidate,
}

impl<'a> ValidatedPublicVault<'a> {
    #[must_use]
    pub const fn phase(&self) -> SessionPhase {
        SessionPhase::PublicValidated
    }

    #[must_use]
    pub const fn policy(&self) -> &'a PolicyState {
        self.policy
    }

    pub fn start_session(
        &'a self,
        principal_id: PrincipalId,
        checkpoint: &LocalCheckpoint,
        witness_policy_checkpoint_digest: Option<Digest32>,
        limits: SessionLimits,
        now_ms: u64,
    ) -> Result<PrincipalVaultSession<'a>, SessionError> {
        let scope = checkpoint.scope();
        if scope.vault_id() != self.policy.vault_id()
            || scope.genesis_fingerprint() != self.policy.genesis_fingerprint()
            || scope.principal_id() != principal_id
        {
            return Err(SessionError::new(SessionErrorKind::ScopeMismatch));
        }
        if self.policy.principal(&principal_id).is_none() {
            return Err(SessionError::new(SessionErrorKind::UnknownPrincipal));
        }
        if now_ms < checkpoint.updated_at_ms() {
            return Err(SessionError::new(SessionErrorKind::ClockRegression));
        }
        if self
            .checkpoint_candidate
            .relation_to(checkpoint)
            .map_err(|_| SessionError::new(SessionErrorKind::CheckpointConflict))?
            != CheckpointRelation::Equal
            || checkpoint.accepted_public_revision_hash() != self.policy.terminal_revision_hash()
        {
            return Err(SessionError::new(SessionErrorKind::CheckpointConflict));
        }
        let absolute_expires_at_ms = now_ms
            .checked_add(limits.absolute_lifetime_ms)
            .ok_or_else(|| SessionError::new(SessionErrorKind::InvalidLimits))?;
        Ok(PrincipalVaultSession {
            public: self,
            principal_id,
            witness_policy_checkpoint_digest,
            limits,
            started_at_ms: now_ms,
            last_activity_at_ms: now_ms,
            absolute_expires_at_ms,
            phase: SessionPhase::Principal,
            catalog: AccessibleCatalog::try_new(Vec::new())
                .map_err(|_| SessionError::new(SessionErrorKind::Failed))?,
            body_metadata: BTreeMap::new(),
            pending: None,
            active_revision: None,
        })
    }

    fn envelope(&self, item_id: ProtocolItemId) -> Option<&'a ItemEnvelopeV1> {
        self.envelopes
            .iter()
            .find(|envelope| envelope.item_id == item_id)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct BodyMetadata {
    field_count: usize,
    updated_at_ms: Option<u64>,
}

struct AccessAttempt<'a> {
    item_id: ProtocolItemId,
    content_role: ContentRole,
    capability: Capability,
    binding: Option<&'a WitnessRequestBinding>,
    now_ms: u64,
    cancellation: &'a dyn CancellationCheck,
}

/// Principal capability backed exclusively by an [`ItemAccessProvider`].
pub struct PrincipalVaultSession<'a> {
    public: &'a ValidatedPublicVault<'a>,
    principal_id: PrincipalId,
    witness_policy_checkpoint_digest: Option<Digest32>,
    limits: SessionLimits,
    started_at_ms: u64,
    last_activity_at_ms: u64,
    absolute_expires_at_ms: u64,
    phase: SessionPhase,
    catalog: AccessibleCatalog,
    body_metadata: BTreeMap<ProtocolItemId, BodyMetadata>,
    pending: Option<WitnessRequestBinding>,
    active_revision: Option<RevisionToken>,
}

impl PrincipalVaultSession<'_> {
    #[must_use]
    pub const fn phase(&self) -> SessionPhase {
        self.phase
    }

    #[must_use]
    pub const fn principal_id(&self) -> PrincipalId {
        self.principal_id
    }

    #[must_use]
    pub const fn catalog(&self) -> &AccessibleCatalog {
        &self.catalog
    }

    pub fn discover_descriptor<P: ItemAccessProvider>(
        &mut self,
        provider: &mut P,
        item_id: ProtocolItemId,
        binding: Option<&WitnessRequestBinding>,
        now_ms: u64,
        cancellation: &dyn CancellationCheck,
    ) -> Result<SessionAccessOutcome<()>, SessionError> {
        if self
            .catalog
            .entries()
            .any(|entry| entry.item_id().as_bytes() == item_id.as_bytes())
        {
            self.check_live(now_ms)?;
            return Ok(SessionAccessOutcome::Direct(()));
        }
        let outcome = self.access_revision(
            provider,
            AccessAttempt {
                item_id,
                content_role: ContentRole::Descriptor,
                capability: Capability::Read,
                binding,
                now_ms,
                cancellation,
            },
            |access| access.open_descriptor(),
        )?;
        outcome.map_complete(
            |mut descriptor, authority, session| {
                let name = ItemName::parse(descriptor.name())
                    .map_err(|_| SessionError::new(SessionErrorKind::Failed));
                descriptor.clear_sensitive();
                let name = name?;
                let explanation =
                    session
                        .public
                        .policy
                        .access(&item_id, &session.principal_id, Capability::Read);
                let role = explanation
                    .effective_role
                    .map(role_from_access)
                    .ok_or_else(|| SessionError::new(SessionErrorKind::Unavailable))?;
                let mut entries = session.catalog.entries().cloned().collect::<Vec<_>>();
                entries.push(AccessibleCatalogEntry::from_decrypted(
                    domain_item_id(item_id)?,
                    name,
                    role,
                ));
                let next = AccessibleCatalog::try_new(entries).map_err(map_catalog_error)?;
                session.catalog.clear_sensitive();
                session.catalog = next;
                Ok(match authority {
                    AccessCompletion::Direct => SessionAccessOutcome::Direct(()),
                    AccessCompletion::WitnessedApproved => {
                        SessionAccessOutcome::WitnessedApproved(())
                    }
                })
            },
            self,
        )
    }

    pub fn open_item<'session, P: ItemAccessProvider>(
        &'session mut self,
        provider: &mut P,
        selector: &ItemSelector,
        capability: Capability,
        binding: Option<&WitnessRequestBinding>,
        now_ms: u64,
        cancellation: &dyn CancellationCheck,
    ) -> Result<SessionAccessOutcome<UnlockedItem<'session>>, SessionError> {
        let item_id = protocol_item_id(
            self.catalog
                .resolve(selector)
                .map_err(|_| SessionError::new(SessionErrorKind::Unavailable))?
                .item_id(),
        )?;
        let outcome = self.access_revision(
            provider,
            AccessAttempt {
                item_id,
                content_role: ContentRole::Body,
                capability,
                binding,
                now_ms,
                cancellation,
            },
            |access| access.open_body(),
        )?;
        match outcome {
            SessionAccessOutcome::Direct(state) => {
                self.record_body_metadata(item_id, &state);
                Ok(SessionAccessOutcome::Direct(UnlockedItem::new(
                    state,
                    AccessCompletion::Direct,
                    self.active_revision
                        .clone()
                        .ok_or_else(|| SessionError::new(SessionErrorKind::Failed))?,
                )))
            }
            SessionAccessOutcome::WitnessedApproved(state) => {
                self.record_body_metadata(item_id, &state);
                Ok(SessionAccessOutcome::WitnessedApproved(UnlockedItem::new(
                    state,
                    AccessCompletion::WitnessedApproved,
                    self.active_revision
                        .clone()
                        .ok_or_else(|| SessionError::new(SessionErrorKind::Failed))?,
                )))
            }
            other => Ok(other.without_complete()),
        }
    }

    pub fn preflight_items(
        &mut self,
        selectors: &[ItemSelector],
        now_ms: u64,
    ) -> Result<Vec<ProtocolItemId>, SessionError> {
        self.check_live(now_ms)?;
        if selectors.is_empty() || selectors.len() > MAX_PREFLIGHT_ITEMS {
            return Err(SessionError::new(SessionErrorKind::CapacityExhausted));
        }
        let mut seen = BTreeSet::new();
        let mut item_ids = Vec::with_capacity(selectors.len());
        for selector in selectors {
            let item_id = protocol_item_id(
                self.catalog
                    .resolve(selector)
                    .map_err(|_| SessionError::new(SessionErrorKind::Unavailable))?
                    .item_id(),
            )?;
            if !seen.insert(item_id) {
                return Err(SessionError::new(SessionErrorKind::Conflict));
            }
            item_ids.push(item_id);
        }
        self.last_activity_at_ms = now_ms;
        Ok(item_ids)
    }

    pub fn snapshot(&mut self, now_ms: u64) -> Result<SessionSnapshot, SessionError> {
        self.check_live(now_ms)?;
        let mut items = Vec::with_capacity(self.catalog.entries().len());
        for entry in self.catalog.entries() {
            let item_id = protocol_item_id(entry.item_id())?;
            let policy_item = self
                .public
                .policy
                .item(&item_id)
                .ok_or_else(|| SessionError::new(SessionErrorKind::Failed))?;
            let metadata = self.body_metadata.get(&item_id);
            let envelope = self
                .public
                .envelope(item_id)
                .ok_or_else(|| SessionError::new(SessionErrorKind::Failed))?;
            items.push(SessionItemSnapshot {
                item_id,
                name: entry.name().to_string(),
                role: entry.role(),
                key_epoch: policy_item.key_epoch,
                item_revision: envelope.current_revision.item_revision,
                field_count: metadata.map(|metadata| metadata.field_count),
                updated_at_ms: metadata.and_then(|metadata| metadata.updated_at_ms),
            });
        }
        self.last_activity_at_ms = now_ms;
        Ok(SessionSnapshot {
            schema: 1,
            vault_id: self.public.policy.vault_id(),
            policy_sequence: self.public.policy.sequence(),
            policy_revision_hash: self.public.policy.terminal_revision_hash().clone(),
            principal_id: self.principal_id,
            phase: self.phase,
            started_at_ms: self.started_at_ms,
            last_activity_at_ms: self.last_activity_at_ms,
            absolute_expires_at_ms: self.absolute_expires_at_ms,
            items,
            pending_request_digest: self
                .pending
                .as_ref()
                .map(|binding| binding.request_digest.clone()),
            active_revision: self.active_revision.clone(),
        })
    }

    /// Rechecks an unchanged public state. Any pending request or changed
    /// authenticated scope becomes stale and is wiped instead of being carried
    /// into a refreshed session.
    pub fn refresh_same(
        &mut self,
        public: &ValidatedPublicVault<'_>,
        checkpoint: &LocalCheckpoint,
        witness_policy_checkpoint_digest: Option<Digest32>,
        now_ms: u64,
    ) -> Result<(), SessionError> {
        self.check_live(now_ms)?;
        let same = self.pending.is_none()
            && public.policy.vault_id() == self.public.policy.vault_id()
            && public.policy.genesis_fingerprint() == self.public.policy.genesis_fingerprint()
            && public.policy.sequence() == self.public.policy.sequence()
            && public.policy.terminal_revision_hash()
                == self.public.policy.terminal_revision_hash()
            && checkpoint.scope().principal_id() == self.principal_id
            && checkpoint.accepted_public_revision_hash()
                == self.public.policy.terminal_revision_hash()
            && public
                .checkpoint_candidate
                .relation_to(checkpoint)
                .is_ok_and(|relation| relation == CheckpointRelation::Equal)
            && witness_policy_checkpoint_digest == self.witness_policy_checkpoint_digest;
        if !same {
            self.enter_terminal(SessionPhase::Stale);
            return Err(SessionError::new(SessionErrorKind::CheckpointConflict));
        }
        self.last_activity_at_ms = now_ms;
        self.phase = SessionPhase::Principal;
        Ok(())
    }

    pub fn cancel(&mut self) {
        self.enter_terminal(SessionPhase::Cancelled);
    }

    pub fn handle_signal(&mut self) {
        self.cancel();
    }

    pub fn lock(&mut self) {
        self.enter_terminal(SessionPhase::Locked);
    }

    fn access_revision<T, P, F>(
        &mut self,
        provider: &mut P,
        attempt: AccessAttempt<'_>,
        open: F,
    ) -> Result<SessionAccessOutcome<T>, SessionError>
    where
        T: SensitiveValue,
        P: ItemAccessProvider,
        F: for<'scope> FnOnce(&mut ScopedRevisionAccess<'scope>) -> Result<T, AccessProviderError>,
    {
        self.check_live(attempt.now_ms)?;
        if attempt.cancellation.is_cancelled() {
            self.enter_terminal(SessionPhase::Cancelled);
            return Ok(SessionAccessOutcome::Cancelled);
        }
        let envelope = self
            .public
            .envelope(attempt.item_id)
            .ok_or_else(|| SessionError::new(SessionErrorKind::Unavailable))?;
        let target = RevisionAccessTarget::current(
            self.public.policy,
            envelope,
            self.principal_id,
            attempt.content_role,
            attempt.capability,
        )
        .map_err(|error| map_target_error(error.kind()))?;
        let token = RevisionToken::current(self.public.policy, &target, attempt.capability);

        if let Some(pending) = &self.pending
            && attempt.binding != Some(pending)
        {
            self.enter_terminal(SessionPhase::Replay);
            return Ok(SessionAccessOutcome::Replay);
        }
        if let Some(binding) = attempt.binding {
            if binding.expires_at_ms <= attempt.now_ms {
                self.enter_terminal(SessionPhase::Expired);
                return Ok(SessionAccessOutcome::Expired);
            }
            if self
                .validate_witness_binding(binding, &token, attempt.now_ms)
                .is_err()
            {
                if self.pending.is_some() {
                    self.enter_terminal(SessionPhase::Replay);
                    return Ok(SessionAccessOutcome::Replay);
                }
                return Err(SessionError::new(SessionErrorKind::InvalidBinding));
            }
            if binding
                .not_before_ms
                .is_some_and(|not_before| attempt.now_ms < not_before)
            {
                self.pending = Some(binding.clone());
                self.active_revision = Some(token);
                self.phase = SessionPhase::WitnessPending;
                return Ok(SessionAccessOutcome::Pending);
            }
        }

        let request = RevisionAccessRequest {
            policy: self.public.policy,
            envelope,
            target,
            capability: attempt.capability,
            cancellation: attempt.cancellation,
        };
        let outcome = provider.access_revision(request, open);
        match outcome {
            Ok(ItemAccessOutcome::Complete {
                authority,
                mut value,
            }) => {
                let authority_matches = match authority {
                    AccessCompletion::Direct => attempt.binding.is_none() && self.pending.is_none(),
                    AccessCompletion::WitnessedApproved => attempt.binding.is_some(),
                };
                if !authority_matches {
                    value.clear_sensitive();
                    self.enter_terminal(SessionPhase::Replay);
                    return Ok(SessionAccessOutcome::Replay);
                }
                self.pending = None;
                self.active_revision = Some(token);
                self.last_activity_at_ms = attempt.now_ms;
                self.phase = match authority {
                    AccessCompletion::Direct => SessionPhase::UnlockedItem,
                    AccessCompletion::WitnessedApproved => SessionPhase::Approved,
                };
                Ok(match authority {
                    AccessCompletion::Direct => SessionAccessOutcome::Direct(value),
                    AccessCompletion::WitnessedApproved => {
                        SessionAccessOutcome::WitnessedApproved(value)
                    }
                })
            }
            Ok(ItemAccessOutcome::Witnessed(status)) => {
                if attempt.binding.is_none() {
                    self.enter_terminal(SessionPhase::Failed);
                    return Ok(SessionAccessOutcome::Failed);
                }
                Ok(self.apply_witness_status(status, attempt.binding))
            }
            Err(ItemAccessError::Provider(error)) => {
                let phase = match error.kind() {
                    AccessProviderErrorKind::Cancelled => SessionPhase::Cancelled,
                    AccessProviderErrorKind::StalePolicy => SessionPhase::Stale,
                    AccessProviderErrorKind::Unauthorized
                    | AccessProviderErrorKind::WrongPrincipal
                    | AccessProviderErrorKind::DirectSlotUnavailable => SessionPhase::Unavailable,
                    _ => SessionPhase::Failed,
                };
                self.enter_terminal(phase);
                Ok(outcome_for_phase(phase))
            }
            Err(ItemAccessError::Consumer(_)) => {
                self.enter_terminal(SessionPhase::Failed);
                Ok(SessionAccessOutcome::Failed)
            }
        }
    }

    fn validate_witness_binding(
        &self,
        binding: &WitnessRequestBinding,
        token: &RevisionToken,
        now_ms: u64,
    ) -> Result<(), SessionError> {
        let nonzero = [
            &binding.request_id,
            &binding.request_digest,
            &binding.action_manifest_digest,
            &binding.approval_target_digest,
            &binding.workload_digest,
            &binding.policy_checkpoint_digest,
            &binding.witness_policy_digest,
            &binding.intended_witness_set_digest,
            &binding.request_session_key_fingerprint,
        ]
        .into_iter()
        .all(|digest| digest.as_bytes() != &ZERO_DIGEST);
        let expected_checkpoint = self
            .witness_policy_checkpoint_digest
            .as_ref()
            .ok_or_else(|| SessionError::new(SessionErrorKind::InvalidBinding))?;
        let authority = self
            .public
            .policy
            .witness_authority(&token.item_id)
            .map_err(|_| SessionError::new(SessionErrorKind::InvalidBinding))?
            .ok_or_else(|| SessionError::new(SessionErrorKind::InvalidBinding))?;
        let rule = self
            .public
            .policy
            .witness_access_rule(&token.item_id, binding.operation)
            .map_err(|_| SessionError::new(SessionErrorKind::InvalidBinding))?;
        let intended = self
            .public
            .policy
            .intended_witness_set_digest(&token.item_id)
            .map_err(|_| SessionError::new(SessionErrorKind::InvalidBinding))?;
        let slot_matches = self
            .public
            .policy
            .item(&token.item_id)
            .and_then(|item| item.witnessed_state.as_ref())
            .is_some_and(|state| {
                state.slots.iter().any(|slot| {
                    slot.slot_id == binding.slot_id
                        && slot.content_role == token.content_role
                        && slot.revision == token.revision
                        && slot.revision_seal_id == token.revision_seal_id
                        && slot.key_epoch == token.key_epoch
                        && slot.item_access_mode == token.item_access_mode
                })
            });
        let lifetime = binding.expires_at_ms.checked_sub(binding.issued_at_ms);
        if !nonzero
            || binding.revision != *token
            || binding.policy_checkpoint_digest != *expected_checkpoint
            || binding.witness_policy_id != authority.policy_id
            || binding.witness_policy_revision != authority.policy_revision
            || binding.witness_policy_digest != authority.policy_digest
            || binding.witness_policy_id != rule.policy_id
            || binding.witness_policy_revision != rule.policy_revision
            || binding.witness_policy_digest != rule.policy_digest
            || binding.intended_witness_set_digest != intended
            || binding.issued_at_ms < self.started_at_ms
            || binding.issued_at_ms > now_ms
            || binding.expires_at_ms <= now_ms
            || binding.expires_at_ms > self.absolute_expires_at_ms
            || lifetime
                .is_none_or(|lifetime| lifetime == 0 || lifetime > rule.allowed_request_lifetime_ms)
            || binding.not_before_ms.is_some_and(|not_before| {
                not_before < binding.issued_at_ms || not_before > binding.expires_at_ms
            })
            || !matches!(
                token.item_access_mode,
                ItemAccessMode::WitnessedOnly | ItemAccessMode::Mixed
            )
            || !slot_matches
        {
            return Err(SessionError::new(SessionErrorKind::InvalidBinding));
        }
        Ok(())
    }

    fn apply_witness_status<T>(
        &mut self,
        status: WitnessedAccessStatus,
        binding: Option<&WitnessRequestBinding>,
    ) -> SessionAccessOutcome<T> {
        match status {
            WitnessedAccessStatus::Pending => {
                self.pending = binding.cloned();
                self.phase = SessionPhase::WitnessPending;
                SessionAccessOutcome::Pending
            }
            WitnessedAccessStatus::Denied => {
                self.enter_terminal(SessionPhase::Denied);
                SessionAccessOutcome::Denied
            }
            WitnessedAccessStatus::Expired => {
                self.enter_terminal(SessionPhase::Expired);
                SessionAccessOutcome::Expired
            }
            WitnessedAccessStatus::Stale => {
                self.enter_terminal(SessionPhase::Stale);
                SessionAccessOutcome::Stale
            }
            WitnessedAccessStatus::Replay => {
                self.enter_terminal(SessionPhase::Replay);
                SessionAccessOutcome::Replay
            }
            WitnessedAccessStatus::Unavailable => {
                self.enter_terminal(SessionPhase::Unavailable);
                SessionAccessOutcome::Unavailable
            }
            WitnessedAccessStatus::Cancelled => {
                self.enter_terminal(SessionPhase::Cancelled);
                SessionAccessOutcome::Cancelled
            }
            WitnessedAccessStatus::InsufficientQuorum => {
                self.enter_terminal(SessionPhase::InsufficientQuorum);
                SessionAccessOutcome::InsufficientQuorum
            }
        }
    }

    fn check_live(&mut self, now_ms: u64) -> Result<(), SessionError> {
        if !self.phase.is_operable() {
            return Err(SessionError::new(match self.phase {
                SessionPhase::Locked => SessionErrorKind::Locked,
                SessionPhase::Expired => SessionErrorKind::Expired,
                SessionPhase::Cancelled => SessionErrorKind::Cancelled,
                SessionPhase::Unavailable => SessionErrorKind::Unavailable,
                _ => SessionErrorKind::Failed,
            }));
        }
        if now_ms < self.last_activity_at_ms {
            self.enter_terminal(SessionPhase::Failed);
            return Err(SessionError::new(SessionErrorKind::ClockRegression));
        }
        if now_ms >= self.absolute_expires_at_ms
            || now_ms.saturating_sub(self.last_activity_at_ms) >= self.limits.inactivity_timeout_ms
        {
            self.enter_terminal(SessionPhase::Expired);
            return Err(SessionError::new(SessionErrorKind::Expired));
        }
        Ok(())
    }

    fn record_body_metadata(&mut self, item_id: ProtocolItemId, state: &ItemStateV1) {
        let updated_at_ms = state.fields.iter().map(|field| field.updated_at_ms).max();
        self.body_metadata.insert(
            item_id,
            BodyMetadata {
                field_count: state.fields.len(),
                updated_at_ms,
            },
        );
    }

    fn enter_terminal(&mut self, phase: SessionPhase) {
        self.catalog.clear_sensitive();
        self.body_metadata.clear();
        self.pending = None;
        self.active_revision = None;
        self.phase = phase;
    }
}

impl Drop for PrincipalVaultSession<'_> {
    fn drop(&mut self) {
        self.catalog.clear_sensitive();
        self.body_metadata.clear();
        self.pending = None;
        self.active_revision = None;
    }
}

trait SensitiveValue {
    fn clear_sensitive(&mut self);
}

impl SensitiveValue for ItemDescriptorV1 {
    fn clear_sensitive(&mut self) {
        ItemDescriptorV1::clear_sensitive(self);
    }
}

impl SensitiveValue for ItemStateV1 {
    fn clear_sensitive(&mut self) {
        ItemStateV1::clear_sensitive(self);
    }
}

pub enum SessionAccessOutcome<T> {
    Direct(T),
    WitnessedApproved(T),
    Pending,
    Denied,
    Expired,
    Stale,
    Replay,
    Unavailable,
    Cancelled,
    Failed,
    InsufficientQuorum,
}

impl<T> SessionAccessOutcome<T> {
    fn map_complete<U>(
        self,
        map: impl FnOnce(
            T,
            AccessCompletion,
            &mut PrincipalVaultSession<'_>,
        ) -> Result<SessionAccessOutcome<U>, SessionError>,
        session: &mut PrincipalVaultSession<'_>,
    ) -> Result<SessionAccessOutcome<U>, SessionError> {
        match self {
            Self::Direct(value) => map(value, AccessCompletion::Direct, session),
            Self::WitnessedApproved(value) => {
                map(value, AccessCompletion::WitnessedApproved, session)
            }
            Self::Pending => Ok(SessionAccessOutcome::Pending),
            Self::Denied => Ok(SessionAccessOutcome::Denied),
            Self::Expired => Ok(SessionAccessOutcome::Expired),
            Self::Stale => Ok(SessionAccessOutcome::Stale),
            Self::Replay => Ok(SessionAccessOutcome::Replay),
            Self::Unavailable => Ok(SessionAccessOutcome::Unavailable),
            Self::Cancelled => Ok(SessionAccessOutcome::Cancelled),
            Self::Failed => Ok(SessionAccessOutcome::Failed),
            Self::InsufficientQuorum => Ok(SessionAccessOutcome::InsufficientQuorum),
        }
    }

    fn without_complete<U>(self) -> SessionAccessOutcome<U> {
        match self {
            Self::Direct(_) | Self::WitnessedApproved(_) => unreachable!("complete outcome"),
            Self::Pending => SessionAccessOutcome::Pending,
            Self::Denied => SessionAccessOutcome::Denied,
            Self::Expired => SessionAccessOutcome::Expired,
            Self::Stale => SessionAccessOutcome::Stale,
            Self::Replay => SessionAccessOutcome::Replay,
            Self::Unavailable => SessionAccessOutcome::Unavailable,
            Self::Cancelled => SessionAccessOutcome::Cancelled,
            Self::Failed => SessionAccessOutcome::Failed,
            Self::InsufficientQuorum => SessionAccessOutcome::InsufficientQuorum,
        }
    }
}

impl<T> fmt::Debug for SessionAccessOutcome<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Direct(_) => "Direct([REDACTED])",
            Self::WitnessedApproved(_) => "WitnessedApproved([REDACTED])",
            Self::Pending => "Pending",
            Self::Denied => "Denied",
            Self::Expired => "Expired",
            Self::Stale => "Stale",
            Self::Replay => "Replay",
            Self::Unavailable => "Unavailable",
            Self::Cancelled => "Cancelled",
            Self::Failed => "Failed",
            Self::InsufficientQuorum => "InsufficientQuorum",
        })
    }
}

/// One explicitly opened body. Its plaintext is overwritten on drop and its
/// lifetime keeps the originating session mutably borrowed.
pub struct UnlockedItem<'session> {
    state: ItemStateV1,
    authority: AccessCompletion,
    revision: RevisionToken,
    _session: PhantomData<&'session mut ()>,
}

impl<'session> UnlockedItem<'session> {
    fn new(state: ItemStateV1, authority: AccessCompletion, revision: RevisionToken) -> Self {
        Self {
            state,
            authority,
            revision,
            _session: PhantomData,
        }
    }

    #[must_use]
    pub const fn state(&self) -> &ItemStateV1 {
        &self.state
    }

    #[must_use]
    pub const fn authority(&self) -> AccessCompletion {
        self.authority
    }

    #[must_use]
    pub const fn revision(&self) -> &RevisionToken {
        &self.revision
    }

    pub fn clear(&mut self) {
        self.state.clear_sensitive();
    }
}

impl fmt::Debug for UnlockedItem<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UnlockedItem")
            .field("authority", &self.authority)
            .field("revision", &self.revision)
            .field("state", &"[REDACTED]")
            .finish()
    }
}

impl Drop for UnlockedItem<'_> {
    fn drop(&mut self) {
        self.state.clear_sensitive();
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SessionItemSnapshot {
    pub item_id: ProtocolItemId,
    pub name: String,
    pub role: Role,
    pub key_epoch: u64,
    pub item_revision: u64,
    pub field_count: Option<usize>,
    pub updated_at_ms: Option<u64>,
}

impl fmt::Debug for SessionItemSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionItemSnapshot")
            .field("item_id", &self.item_id)
            .field("name", &"[REDACTED]")
            .field("role", &self.role)
            .field("key_epoch", &self.key_epoch)
            .field("item_revision", &self.item_revision)
            .field("field_count", &self.field_count)
            .field("updated_at_ms", &self.updated_at_ms)
            .finish()
    }
}

impl Drop for SessionItemSnapshot {
    fn drop(&mut self) {
        self.name.zeroize();
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SessionSnapshot {
    pub schema: u16,
    pub vault_id: VaultId,
    pub policy_sequence: u64,
    pub policy_revision_hash: Digest32,
    pub principal_id: PrincipalId,
    pub phase: SessionPhase,
    pub started_at_ms: u64,
    pub last_activity_at_ms: u64,
    pub absolute_expires_at_ms: u64,
    pub items: Vec<SessionItemSnapshot>,
    pub pending_request_digest: Option<Digest32>,
    pub active_revision: Option<RevisionToken>,
}

impl fmt::Debug for SessionSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionSnapshot")
            .field("vault_id", &self.vault_id)
            .field("policy_sequence", &self.policy_sequence)
            .field("principal_id", &self.principal_id)
            .field("phase", &self.phase)
            .field("item_count", &self.items.len())
            .field("pending_request_digest", &self.pending_request_digest)
            .field("active_revision", &self.active_revision)
            .finish()
    }
}

fn role_from_access(role: AccessRole) -> Role {
    match role {
        AccessRole::Reader => Role::Reader,
        AccessRole::Writer => Role::Writer,
        AccessRole::Owner => Role::Owner,
    }
}

fn domain_item_id(item_id: ProtocolItemId) -> Result<DomainItemId, SessionError> {
    DomainItemId::from_bytes(*item_id.as_bytes())
        .map_err(|_| SessionError::new(SessionErrorKind::InvalidPublicState))
}

fn protocol_item_id(item_id: DomainItemId) -> Result<ProtocolItemId, SessionError> {
    ProtocolItemId::from_bytes(*item_id.as_bytes())
        .map_err(|_| SessionError::new(SessionErrorKind::InvalidPublicState))
}

fn map_catalog_error(error: CatalogError) -> SessionError {
    SessionError::new(match error {
        CatalogError::TooManyEntries { .. } => SessionErrorKind::CapacityExhausted,
        CatalogError::DuplicateItemId | CatalogError::DuplicateItemName => {
            SessionErrorKind::Conflict
        }
    })
}

fn map_target_error(kind: AccessProviderErrorKind) -> SessionError {
    SessionError::new(match kind {
        AccessProviderErrorKind::Unauthorized
        | AccessProviderErrorKind::WrongPrincipal
        | AccessProviderErrorKind::DirectSlotUnavailable
        | AccessProviderErrorKind::InvalidRequest => SessionErrorKind::Unavailable,
        AccessProviderErrorKind::StalePolicy | AccessProviderErrorKind::InvalidAncestry => {
            SessionErrorKind::CheckpointConflict
        }
        AccessProviderErrorKind::Cancelled => SessionErrorKind::Cancelled,
        _ => SessionErrorKind::Failed,
    })
}

fn outcome_for_phase<T>(phase: SessionPhase) -> SessionAccessOutcome<T> {
    match phase {
        SessionPhase::Denied => SessionAccessOutcome::Denied,
        SessionPhase::Expired => SessionAccessOutcome::Expired,
        SessionPhase::Stale => SessionAccessOutcome::Stale,
        SessionPhase::Replay => SessionAccessOutcome::Replay,
        SessionPhase::Unavailable => SessionAccessOutcome::Unavailable,
        SessionPhase::Cancelled => SessionAccessOutcome::Cancelled,
        SessionPhase::InsufficientQuorum => SessionAccessOutcome::InsufficientQuorum,
        _ => SessionAccessOutcome::Failed,
    }
}

#[cfg(test)]
#[path = "session_tests.rs"]
mod tests;
