//! Mode-neutral, scoped access to one authenticated item revision.

use std::collections::BTreeMap;
use std::fmt;
use std::panic::{AssertUnwindSafe, catch_unwind};

use jury_protected::ProtectedMemory;
use jury_protocol::vault_v1::{
    AccessRole, ContentRole, Digest32, ItemAccessMode, ItemDescriptorV1, ItemEnvelopeV1, ItemId,
    ItemStateV1, PrincipalId, RevisionSealId, VaultId,
};
use jury_protocol::witness_v1::{
    ACCEPTED_CLOCK_SKEW_MS, ActionManifestV1, VaultPolicyCheckpointV1, WitnessDecisionKindV1,
    WitnessReasonV1, WitnessRequestV1, WitnessResponseV1,
};
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;
use vsss_rs::Gf256;
use zeroize::Zeroizing;

use crate::canonical::jce_v1 as jce;
use crate::crypto;
use crate::domain::Capability;
use crate::identity::{IdentityErrorKind, ProtectedRevisionSecret, VaultPrincipalIdentity};
use crate::item::{open_body, open_descriptor, verify_item_ancestry};
use crate::policy::{AccessPath, AccessReason, PolicyState};
use crate::witness_client::RequestSessionIdentity;
use crate::witness_engine::{validate_public_request, validate_witness_response};
use crate::witness_validation::operation_capability;

const SUITE: u16 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccessProviderErrorKind {
    InvalidRequest,
    InvalidAncestry,
    WrongPrincipal,
    Unauthorized,
    StalePolicy,
    InvalidSlot,
    DirectSlotUnavailable,
    EntropyUnavailable,
    Cancelled,
    ProviderFailure,
    ConsumerPanicked,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct AccessProviderError {
    kind: AccessProviderErrorKind,
}

impl AccessProviderError {
    const fn new(kind: AccessProviderErrorKind) -> Self {
        Self { kind }
    }

    #[must_use]
    pub const fn kind(self) -> AccessProviderErrorKind {
        self.kind
    }
}

impl fmt::Debug for AccessProviderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AccessProviderError")
            .field("kind", &self.kind)
            .finish()
    }
}

impl fmt::Display for AccessProviderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.kind {
            AccessProviderErrorKind::InvalidRequest => "item access request is invalid",
            AccessProviderErrorKind::InvalidAncestry => "item access ancestry is invalid",
            AccessProviderErrorKind::WrongPrincipal => "item access principal differs",
            AccessProviderErrorKind::Unauthorized => "item access is unauthorized",
            AccessProviderErrorKind::StalePolicy => "item access policy is stale",
            AccessProviderErrorKind::InvalidSlot => "item access slot is invalid",
            AccessProviderErrorKind::DirectSlotUnavailable => {
                "a direct item access slot is unavailable"
            }
            AccessProviderErrorKind::EntropyUnavailable => "item access entropy was unavailable",
            AccessProviderErrorKind::Cancelled => "item access was cancelled",
            AccessProviderErrorKind::ProviderFailure => "item access provider failed",
            AccessProviderErrorKind::ConsumerPanicked => "item access consumer panicked",
        })
    }
}

impl std::error::Error for AccessProviderError {}

pub enum ItemAccessError<E> {
    Provider(AccessProviderError),
    Consumer(E),
}

impl<E> ItemAccessError<E> {
    #[must_use]
    pub const fn provider_kind(&self) -> Option<AccessProviderErrorKind> {
        match self {
            Self::Provider(error) => Some(error.kind()),
            Self::Consumer(_) => None,
        }
    }
}

impl<E> fmt::Debug for ItemAccessError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Provider(error) => formatter.debug_tuple("Provider").field(error).finish(),
            Self::Consumer(_) => formatter.write_str("Consumer([REDACTED])"),
        }
    }
}

impl<E> fmt::Display for ItemAccessError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Provider(error) => error.fmt(formatter),
            Self::Consumer(_) => formatter.write_str("item access consumer failed"),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccessCompletion {
    Direct,
    WitnessedApproved,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WitnessedAccessStatus {
    Pending,
    Denied,
    Expired,
    Stale,
    Replay,
    Unavailable,
    Cancelled,
    InsufficientQuorum,
}

#[derive(Debug, Eq, PartialEq)]
pub enum ItemAccessOutcome<T> {
    Complete {
        authority: AccessCompletion,
        value: T,
    },
    Witnessed(WitnessedAccessStatus),
}

pub trait CancellationCheck {
    fn is_cancelled(&self) -> bool;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct NeverCancelled;

impl CancellationCheck for NeverCancelled {
    fn is_cancelled(&self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RevisionAccessTarget {
    pub suite: u16,
    pub vault_id: VaultId,
    pub item_id: ItemId,
    pub key_epoch: u64,
    pub content_role: ContentRole,
    pub revision: u64,
    pub revision_seal_id: RevisionSealId,
    pub policy_sequence: u64,
    pub policy_revision_hash: Digest32,
    pub principal_id: PrincipalId,
    pub access_role: AccessRole,
    pub item_access_mode: ItemAccessMode,
}

impl RevisionAccessTarget {
    pub fn current(
        policy: &PolicyState,
        envelope: &ItemEnvelopeV1,
        principal_id: PrincipalId,
        content_role: ContentRole,
        capability: Capability,
    ) -> Result<Self, AccessProviderError> {
        let item = policy
            .item(&envelope.item_id)
            .ok_or_else(|| AccessProviderError::new(AccessProviderErrorKind::InvalidRequest))?;
        let explanation = policy.access(&envelope.item_id, &principal_id, capability);
        if !explanation.allowed {
            return Err(AccessProviderError::new(
                AccessProviderErrorKind::Unauthorized,
            ));
        }
        let access_role = explanation
            .effective_role
            .ok_or_else(|| AccessProviderError::new(AccessProviderErrorKind::Unauthorized))?;
        let item_access_mode = item
            .access_mode()
            .ok_or_else(|| AccessProviderError::new(AccessProviderErrorKind::InvalidRequest))?;
        let (revision, revision_seal_id) = match content_role {
            ContentRole::Descriptor => (
                envelope.descriptor.revision,
                envelope.descriptor.revision_seal_id,
            ),
            ContentRole::Body => (
                envelope.current_revision.item_revision,
                envelope.current_revision.revision_seal_id,
            ),
        };
        Ok(Self {
            suite: SUITE,
            vault_id: policy.vault_id(),
            item_id: envelope.item_id,
            key_epoch: item.key_epoch,
            content_role,
            revision,
            revision_seal_id,
            policy_sequence: policy.sequence(),
            policy_revision_hash: policy.terminal_revision_hash().clone(),
            principal_id,
            access_role,
            item_access_mode,
        })
    }
}

pub struct RevisionAccessRequest<'a> {
    pub policy: &'a PolicyState,
    pub envelope: &'a ItemEnvelopeV1,
    pub target: RevisionAccessTarget,
    pub capability: Capability,
    pub cancellation: &'a dyn CancellationCheck,
}

/// Scoped plaintext operation for exactly one authenticated content role.
///
/// It deliberately has no revision-secret accessor. The borrow also cannot
/// escape the consumer call.
///
/// ```compile_fail
/// # use jury_core::access_provider::ScopedRevisionAccess;
/// fn raw_key(access: &ScopedRevisionAccess<'_>) {
///     let _ = access.secret;
/// }
/// ```
pub struct ScopedRevisionAccess<'a> {
    role: ContentRole,
    envelope: &'a ItemEnvelopeV1,
    secret: &'a ProtectedRevisionSecret,
}

impl ScopedRevisionAccess<'_> {
    pub fn open_descriptor(&self) -> Result<ItemDescriptorV1, AccessProviderError> {
        if self.role != ContentRole::Descriptor {
            return Err(AccessProviderError::new(
                AccessProviderErrorKind::InvalidRequest,
            ));
        }
        open_descriptor(self.envelope, self.secret)
            .map_err(|_| AccessProviderError::new(AccessProviderErrorKind::InvalidSlot))
    }

    pub fn open_body(&self) -> Result<ItemStateV1, AccessProviderError> {
        if self.role != ContentRole::Body {
            return Err(AccessProviderError::new(
                AccessProviderErrorKind::InvalidRequest,
            ));
        }
        open_body(self.envelope, self.secret)
            .map_err(|_| AccessProviderError::new(AccessProviderErrorKind::InvalidSlot))
    }
}

pub trait ItemAccessProvider {
    fn access_revision<T, E>(
        &mut self,
        request: RevisionAccessRequest<'_>,
        consumer: impl FnOnce(&mut ScopedRevisionAccess<'_>) -> Result<T, E>,
    ) -> Result<ItemAccessOutcome<T>, ItemAccessError<E>>;
}

/// Direct revision access backed by one unlocked vault-principal identity.
///
/// Identity decapsulation remains private; callers must use
/// [`ItemAccessProvider::access_revision`].
///
/// ```compile_fail
/// use jury_core::identity::VaultPrincipalIdentity;
/// use jury_protocol::vault_v1::DirectSlotV1;
/// fn bypass(identity: &VaultPrincipalIdentity, slot: &DirectSlotV1) {
///     let _ = identity.open_direct_slot(slot);
/// }
/// ```
///
/// Witness share release is likewise unavailable to callers.
///
/// ```compile_fail
/// use jury_core::identity::WitnessIdentity;
/// use jury_protocol::vault_v1::WitnessShareCapsuleV1;
/// fn bypass(identity: &WitnessIdentity, capsule: &WitnessShareCapsuleV1) {
///     let _ = identity.open_contribution_share(capsule);
/// }
/// ```
pub struct DirectItemAccessProvider<'a> {
    unwrapper: &'a dyn DirectSlotUnwrapper,
    #[cfg(test)]
    cleanup_probe: Option<&'a dyn Fn()>,
}

impl<'a> DirectItemAccessProvider<'a> {
    #[must_use]
    pub const fn new(identity: &'a VaultPrincipalIdentity) -> Self {
        Self {
            unwrapper: identity,
            #[cfg(test)]
            cleanup_probe: None,
        }
    }

    #[cfg(test)]
    const fn with_test_unwrapper(
        unwrapper: &'a dyn DirectSlotUnwrapper,
        cleanup_probe: &'a dyn Fn(),
    ) -> Self {
        Self {
            unwrapper,
            cleanup_probe: Some(cleanup_probe),
        }
    }
}

impl ItemAccessProvider for DirectItemAccessProvider<'_> {
    fn access_revision<T, E>(
        &mut self,
        request: RevisionAccessRequest<'_>,
        consumer: impl FnOnce(&mut ScopedRevisionAccess<'_>) -> Result<T, E>,
    ) -> Result<ItemAccessOutcome<T>, ItemAccessError<E>> {
        #[cfg(test)]
        let _cleanup = CleanupGuard(self.cleanup_probe);
        let slot = preflight_direct(self.unwrapper.principal_id(), &request)
            .map_err(ItemAccessError::Provider)?;
        if request.cancellation.is_cancelled() {
            return Err(ItemAccessError::Provider(AccessProviderError::new(
                AccessProviderErrorKind::Cancelled,
            )));
        }
        let secret = self
            .unwrapper
            .open_direct_slot(slot)
            .map_err(|kind| ItemAccessError::Provider(AccessProviderError::new(kind)))?;
        if request.cancellation.is_cancelled() {
            return Err(ItemAccessError::Provider(AccessProviderError::new(
                AccessProviderErrorKind::Cancelled,
            )));
        }
        let mut scoped = ScopedRevisionAccess {
            role: request.target.content_role,
            envelope: request.envelope,
            secret: &secret,
        };
        let consumed = catch_unwind(AssertUnwindSafe(|| consumer(&mut scoped))).map_err(|_| {
            ItemAccessError::Provider(AccessProviderError::new(
                AccessProviderErrorKind::ConsumerPanicked,
            ))
        })?;
        let value = consumed.map_err(ItemAccessError::Consumer)?;
        Ok(ItemAccessOutcome::Complete {
            authority: AccessCompletion::Direct,
            value,
        })
    }
}

include!("access_provider/witnessed.rs");

fn preflight_direct<'a>(
    principal_id: PrincipalId,
    request: &'a RevisionAccessRequest<'_>,
) -> Result<&'a jury_protocol::vault_v1::DirectSlotV1, AccessProviderError> {
    let target = &request.target;
    if target.suite != SUITE
        || target.vault_id != request.policy.vault_id()
        || target.item_id != request.envelope.item_id
        || target.principal_id != principal_id
    {
        return Err(AccessProviderError::new(
            if target.principal_id != principal_id {
                AccessProviderErrorKind::WrongPrincipal
            } else {
                AccessProviderErrorKind::InvalidRequest
            },
        ));
    }
    if target.policy_sequence != request.policy.sequence()
        || target.policy_revision_hash != *request.policy.terminal_revision_hash()
    {
        return Err(AccessProviderError::new(
            AccessProviderErrorKind::StalePolicy,
        ));
    }
    verify_item_ancestry(request.envelope, |principal_id| {
        request.policy.verification_key(&principal_id)
    })
    .map_err(|_| AccessProviderError::new(AccessProviderErrorKind::InvalidAncestry))?;
    let item = request
        .policy
        .item(&target.item_id)
        .ok_or_else(|| AccessProviderError::new(AccessProviderErrorKind::InvalidRequest))?;
    let current_hash = request
        .envelope
        .current_revision
        .recomputed_hash()
        .map_err(|_| AccessProviderError::new(AccessProviderErrorKind::InvalidAncestry))?;
    if item.key_epoch != target.key_epoch
        || item.descriptor != request.envelope.descriptor
        || item.current_item_revision_hash != current_hash
        || item.access_mode() != Some(target.item_access_mode)
    {
        return Err(AccessProviderError::new(
            AccessProviderErrorKind::InvalidAncestry,
        ));
    }
    let explanation =
        request
            .policy
            .access(&target.item_id, &target.principal_id, request.capability);
    if !explanation.allowed
        || explanation.effective_role != Some(target.access_role)
        || explanation.reason != AccessReason::Allowed
    {
        return Err(AccessProviderError::new(
            AccessProviderErrorKind::Unauthorized,
        ));
    }
    if !matches!(explanation.path, AccessPath::Direct | AccessPath::Mixed) {
        return Err(AccessProviderError::new(
            AccessProviderErrorKind::DirectSlotUnavailable,
        ));
    }
    let (revision, seal_id) = match target.content_role {
        ContentRole::Descriptor => (
            request.envelope.descriptor.revision,
            request.envelope.descriptor.revision_seal_id,
        ),
        ContentRole::Body => (
            request.envelope.current_revision.item_revision,
            request.envelope.current_revision.revision_seal_id,
        ),
    };
    if target.revision != revision || target.revision_seal_id != seal_id {
        return Err(AccessProviderError::new(
            AccessProviderErrorKind::InvalidRequest,
        ));
    }
    let mut matches = item.direct_slots.iter().filter(|slot| {
        slot.recipient_principal_id == target.principal_id
            && slot.content_role == target.content_role
    });
    let slot = matches
        .next()
        .ok_or_else(|| AccessProviderError::new(AccessProviderErrorKind::DirectSlotUnavailable))?;
    if matches.next().is_some()
        || slot.vault_id != target.vault_id
        || slot.item_id != target.item_id
        || slot.key_epoch != target.key_epoch
        || slot.revision != target.revision
        || slot.revision_seal_id != target.revision_seal_id
        // The slot records the role at the time its revision secret was
        // issued. Current policy remains the authorization source, so a
        // reader/writer-only policy change can retain the same current seals.
        || !matches!(slot.access_role, AccessRole::Reader | AccessRole::Writer | AccessRole::Owner)
        || slot.item_access_mode != target.item_access_mode
        || slot.policy_sequence == 0
        || slot.policy_sequence > target.policy_sequence
        || slot.slot_schema != 1
        || slot.slot_algorithm != 1
        || slot.suite != SUITE
        || slot.kem != 0x647a
        || slot.kdf != 1
        || slot.aead != 3
    {
        return Err(AccessProviderError::new(
            AccessProviderErrorKind::InvalidSlot,
        ));
    }
    Ok(slot)
}

trait DirectSlotUnwrapper {
    fn principal_id(&self) -> PrincipalId;

    fn open_direct_slot(
        &self,
        slot: &jury_protocol::vault_v1::DirectSlotV1,
    ) -> Result<ProtectedRevisionSecret, AccessProviderErrorKind>;
}

impl DirectSlotUnwrapper for VaultPrincipalIdentity {
    fn principal_id(&self) -> PrincipalId {
        VaultPrincipalIdentity::principal_id(self)
    }

    fn open_direct_slot(
        &self,
        slot: &jury_protocol::vault_v1::DirectSlotV1,
    ) -> Result<ProtectedRevisionSecret, AccessProviderErrorKind> {
        VaultPrincipalIdentity::open_direct_slot(self, slot)
            .map_err(|error| map_identity_error(error.kind()))
    }
}

fn map_identity_error(kind: IdentityErrorKind) -> AccessProviderErrorKind {
    match kind {
        IdentityErrorKind::AuthenticationFailed | IdentityErrorKind::Format => {
            AccessProviderErrorKind::InvalidSlot
        }
        _ => AccessProviderErrorKind::ProviderFailure,
    }
}

#[cfg(test)]
struct CleanupGuard<'a>(Option<&'a dyn Fn()>);

#[cfg(test)]
impl Drop for CleanupGuard<'_> {
    fn drop(&mut self) {
        if let Some(probe) = self.0 {
            probe();
        }
    }
}

#[cfg(test)]
#[path = "access_provider_tests.rs"]
mod tests;
