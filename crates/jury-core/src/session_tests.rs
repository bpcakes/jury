use std::cell::Cell;
use std::error::Error;

use jury_protected::{ProtectedMemory, ProtectionPolicy};
use jury_protocol::{
    identity_v1::KdfProfile,
    vault_v1::{
        AccessRole, ContentRole, Digest32, FixedBytes, ItemFieldKind, ItemFieldV1, ItemFieldValue,
        ItemKind, ItemStateV1, PolicyOperationV1, PrincipalDescriptorV1, PrincipalKind,
        RecipientPublicKey1216, Signature64,
    },
};

use super::*;
use crate::access_provider::{DirectItemAccessProvider, NeverCancelled};
use crate::crypto;
use crate::entropy::RandomSource;
use crate::identity::{IdentityCreator, UnlockedIdentity, VaultPrincipalIdentity, unlock};
use crate::item::{ItemAccessPlan, ItemArtifactInventory, ItemCreator, ItemGrant, NewItem};
use crate::local_state::{PrincipalLocalState, VerifiedLocalState};
use crate::policy::{PolicyCreator, replay_policy_with_witness_policies};

fn session_error_kind<T>(result: Result<T, SessionError>) -> SessionErrorKind {
    match result {
        Ok(_) => panic!("session operation unexpectedly succeeded"),
        Err(error) => error.kind(),
    }
}

struct DirectFixture {
    owner: VaultPrincipalIdentity,
    policy: PolicyState,
    journal: PolicyJournalV1,
    envelope: ItemEnvelopeV1,
    local: VerifiedLocalState,
}

fn direct_fixture() -> Result<DirectFixture, Box<dyn Error>> {
    let protection = ProtectionPolicy::EmergencyAllowDegraded;
    let passphrase = ProtectedMemory::initialize(15, protection, |output| {
        output.copy_from_slice(b"ExamplePass1234");
        Ok::<usize, ()>(output.len())
    })?;
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
        return Err("ExamplePrincipal role differs".into());
    };
    let mut policies = PolicyCreator::new();
    let created_policy = policies.create(&owner, 2, |_| false)?;
    let body = ItemStateV1 {
        plaintext_schema: 1,
        fields: vec![ItemFieldV1 {
            name: "EXAMPLE_FIELD".to_owned(),
            field_id: jury_protocol::vault_v1::FieldId::from_bytes([0x31; 32])?,
            value: ItemFieldValue::new(b"ExampleValue".to_vec())?,
            decoded_length: 12,
            kind: ItemFieldKind::Concealed,
            created_at_ms: 3,
            updated_at_ms: 4,
        }],
    };
    let mut items = ItemCreator::new(protection);
    let created_item = items.prepare_create(
        &created_policy.state,
        &owner,
        3,
        NewItem {
            kind: ItemKind::Canonical,
            descriptor: ItemDescriptorV1::new("ExampleItem".to_owned())?,
            state: body,
            bucket_id: 1,
            access: ItemAccessPlan {
                grants: Vec::new(),
                direct_recipient_ids: vec![owner.principal_id()],
                witness_policy_digest: None,
            },
        },
        &ItemArtifactInventory::default(),
    )?;
    let mut journal = created_policy.journal;
    journal.revisions.push(created_item.policy.revision);
    let policy = created_item.policy.state;
    let envelope = created_item.envelope;
    let candidate =
        CheckpointCandidate::from_validated(&policy, &journal, std::slice::from_ref(&envelope))?;
    let local_keys = PrincipalLocalState::for_vault_principal(
        &owner,
        policy.vault_id(),
        policy.genesis_fingerprint().clone(),
    )?;
    let local = local_keys.initialize(&candidate, 4)?;
    Ok(DirectFixture {
        owner,
        policy,
        journal,
        envelope,
        local,
    })
}

struct CountingProvider<'a> {
    inner: DirectItemAccessProvider<'a>,
    descriptor_calls: Cell<usize>,
    body_calls: Cell<usize>,
}

impl<'a> CountingProvider<'a> {
    fn new(identity: &'a VaultPrincipalIdentity) -> Self {
        Self {
            inner: DirectItemAccessProvider::new(identity),
            descriptor_calls: Cell::new(0),
            body_calls: Cell::new(0),
        }
    }
}

impl ItemAccessProvider for CountingProvider<'_> {
    fn access_revision<T, E>(
        &mut self,
        request: RevisionAccessRequest<'_>,
        consumer: impl FnOnce(&mut ScopedRevisionAccess<'_>) -> Result<T, E>,
    ) -> Result<ItemAccessOutcome<T>, ItemAccessError<E>> {
        match request.target.content_role {
            ContentRole::Descriptor => self
                .descriptor_calls
                .set(self.descriptor_calls.get().saturating_add(1)),
            ContentRole::Body => self.body_calls.set(self.body_calls.get().saturating_add(1)),
        }
        self.inner.access_revision(request, consumer)
    }
}

#[test]
fn public_open_discovers_only_descriptors_and_body_open_is_explicit() -> Result<(), Box<dyn Error>>
{
    let fixture = direct_fixture()?;
    let envelopes = [fixture.envelope.clone()];
    let mut inconsistent = fixture.policy.clone();
    inconsistent
        .items
        .get_mut(&fixture.envelope.item_id)
        .ok_or("ExampleItem policy absent")?
        .key_epoch += 1;
    assert_eq!(
        session_error_kind(
            ParsedVault::new(&inconsistent, &fixture.journal, &envelopes).validate_public()
        ),
        SessionErrorKind::InvalidPublicState
    );
    let validated =
        ParsedVault::new(&fixture.policy, &fixture.journal, &envelopes).validate_public()?;
    assert_eq!(validated.phase(), SessionPhase::PublicValidated);
    let limits = SessionLimits::new(100, 1_000)?;
    let mut session = validated.start_session(
        fixture.owner.principal_id(),
        fixture.local.checkpoint(),
        None,
        limits,
        10,
    )?;
    let mut provider = CountingProvider::new(&fixture.owner);

    let empty = serde_json::to_string(&session.snapshot(11)?)?;
    assert!(!empty.contains("ExampleItem"));
    assert!(!empty.contains("ExampleValue"));
    assert_eq!(provider.body_calls.get(), 0);

    assert!(matches!(
        session.discover_descriptor(
            &mut provider,
            fixture.envelope.item_id,
            None,
            12,
            &NeverCancelled,
        )?,
        SessionAccessOutcome::Direct(())
    ));
    assert_eq!(provider.descriptor_calls.get(), 1);
    assert_eq!(provider.body_calls.get(), 0);
    let descriptor_only = session.snapshot(13)?;
    let descriptor_json = serde_json::to_string(&descriptor_only)?;
    assert!(descriptor_json.contains("ExampleItem"));
    assert!(!descriptor_json.contains("ExampleValue"));
    assert_eq!(descriptor_only.items[0].field_count, None);
    assert!(!format!("{descriptor_only:?}").contains("ExampleItem"));

    {
        let opened = session.open_item(
            &mut provider,
            &ItemSelector::parse("ExampleItem")?,
            Capability::Read,
            None,
            14,
            &NeverCancelled,
        )?;
        let SessionAccessOutcome::Direct(mut guard) = opened else {
            return Err("direct body did not open".into());
        };
        assert_eq!(provider.body_calls.get(), 1);
        assert_eq!(guard.state().fields[0].value.as_bytes(), b"ExampleValue");
        assert!(!format!("{guard:?}").contains("ExampleValue"));
        guard.clear();
        assert!(guard.state().fields.is_empty());
    }
    let opened_snapshot = session.snapshot(15)?;
    assert_eq!(opened_snapshot.items[0].field_count, Some(1));
    assert_eq!(opened_snapshot.items[0].updated_at_ms, Some(4));
    assert!(!serde_json::to_string(&opened_snapshot)?.contains("ExampleValue"));
    Ok(())
}

#[test]
fn uniform_lookup_bounds_and_lock_cleanup_hold() -> Result<(), Box<dyn Error>> {
    let fixture = direct_fixture()?;
    let envelopes = [fixture.envelope.clone()];
    let validated =
        ParsedVault::new(&fixture.policy, &fixture.journal, &envelopes).validate_public()?;
    let mut session = validated.start_session(
        fixture.owner.principal_id(),
        fixture.local.checkpoint(),
        None,
        SessionLimits::new(100, 1_000)?,
        10,
    )?;
    let mut provider = DirectItemAccessProvider::new(&fixture.owner);
    session.discover_descriptor(
        &mut provider,
        fixture.envelope.item_id,
        None,
        11,
        &NeverCancelled,
    )?;

    let inaccessible = session
        .open_item(
            &mut provider,
            &ItemSelector::parse("ExampleHidden")?,
            Capability::Read,
            None,
            12,
            &NeverCancelled,
        )
        .map(|_| ());
    let nonexistent = session
        .open_item(
            &mut provider,
            &ItemSelector::parse("ExampleMissing")?,
            Capability::Read,
            None,
            12,
            &NeverCancelled,
        )
        .map(|_| ());
    assert_eq!(inaccessible, nonexistent);
    assert_eq!(
        session_error_kind(inaccessible),
        SessionErrorKind::Unavailable
    );
    assert_eq!(
        session_error_kind(session.preflight_items(&[], 12)),
        SessionErrorKind::CapacityExhausted
    );
    let duplicate = [
        ItemSelector::parse("ExampleItem")?,
        ItemSelector::parse("ExampleItem")?,
    ];
    assert_eq!(
        session_error_kind(session.preflight_items(&duplicate, 12)),
        SessionErrorKind::Conflict
    );

    session.lock();
    assert_eq!(session.phase(), SessionPhase::Locked);
    assert_eq!(session.catalog().entries().len(), 0);
    assert_eq!(
        session_error_kind(session.snapshot(13)),
        SessionErrorKind::Locked
    );
    Ok(())
}

struct ScopedFixture {
    reader: VaultPrincipalIdentity,
    policy: PolicyState,
    journal: PolicyJournalV1,
    envelopes: Vec<ItemEnvelopeV1>,
    visible_item_id: ProtocolItemId,
    hidden_item_id: ProtocolItemId,
    local: VerifiedLocalState,
}

fn scoped_fixture() -> Result<ScopedFixture, Box<dyn Error>> {
    let protection = ProtectionPolicy::EmergencyAllowDegraded;
    let passphrase = ProtectedMemory::initialize(15, protection, |output| {
        output.copy_from_slice(b"ExamplePass1234");
        Ok::<usize, ()>(output.len())
    })?;
    let mut identities = IdentityCreator::new();
    let created_owner = identities.create(
        PrincipalKind::Human,
        KdfProfile::PortableV1,
        1,
        &passphrase,
        |_| false,
    )?;
    let created_reader = identities.create(
        PrincipalKind::Machine,
        KdfProfile::PortableV1,
        2,
        &passphrase,
        |_| false,
    )?;
    let UnlockedIdentity::VaultPrincipal(owner) = unlock(&created_owner.file, &passphrase)? else {
        return Err("ExampleOwner role differs".into());
    };
    let UnlockedIdentity::VaultPrincipal(reader) = unlock(&created_reader.file, &passphrase)?
    else {
        return Err("ExampleReader role differs".into());
    };
    let mut policies = PolicyCreator::new();
    let mut created_policy = policies.create(&owner, 3, |_| false)?;
    let registered = created_policy.state.prepare_revision(
        &owner,
        4,
        vec![PolicyOperationV1::PrincipalAdd {
            descriptor: reader.public_descriptor()?,
            display_label: "ExampleReader".to_owned(),
            registration_proof_digest: Digest32::new([0x45; 32]),
        }],
    )?;
    created_policy.journal.revisions.push(registered.revision);

    let mut items = ItemCreator::new(protection);
    let visible = items.prepare_create(
        &registered.state,
        &owner,
        5,
        NewItem {
            kind: ItemKind::Canonical,
            descriptor: ItemDescriptorV1::new("ExampleVisible".to_owned())?,
            state: ItemStateV1 {
                plaintext_schema: 1,
                fields: Vec::new(),
            },
            bucket_id: 1,
            access: ItemAccessPlan {
                grants: vec![ItemGrant {
                    principal_id: reader.principal_id(),
                    role: AccessRole::Reader,
                }],
                direct_recipient_ids: vec![reader.principal_id()],
                witness_policy_digest: None,
            },
        },
        &ItemArtifactInventory::default(),
    )?;
    created_policy
        .journal
        .revisions
        .push(visible.policy.revision);
    let visible_item_id = visible.envelope.item_id;
    let hidden = items.prepare_create(
        &visible.policy.state,
        &owner,
        6,
        NewItem {
            kind: ItemKind::Canonical,
            descriptor: ItemDescriptorV1::new("ExampleHiddenActual".to_owned())?,
            state: ItemStateV1 {
                plaintext_schema: 1,
                fields: Vec::new(),
            },
            bucket_id: 1,
            access: ItemAccessPlan {
                grants: Vec::new(),
                direct_recipient_ids: vec![owner.principal_id()],
                witness_policy_digest: None,
            },
        },
        &ItemArtifactInventory::default(),
    )?;
    created_policy
        .journal
        .revisions
        .push(hidden.policy.revision);
    let hidden_item_id = hidden.envelope.item_id;
    let policy = hidden.policy.state;
    let envelopes = vec![visible.envelope, hidden.envelope];
    let candidate =
        CheckpointCandidate::from_validated(&policy, &created_policy.journal, &envelopes)?;
    let local_keys = PrincipalLocalState::for_vault_principal(
        &reader,
        policy.vault_id(),
        policy.genesis_fingerprint().clone(),
    )?;
    let local = local_keys.initialize(&candidate, 7)?;
    Ok(ScopedFixture {
        reader,
        policy,
        journal: created_policy.journal,
        envelopes,
        visible_item_id,
        hidden_item_id,
        local,
    })
}

#[test]
fn inaccessible_descriptors_never_reach_the_provider_or_snapshot() -> Result<(), Box<dyn Error>> {
    let fixture = scoped_fixture()?;
    let parsed = ParsedVault::new(&fixture.policy, &fixture.journal, &fixture.envelopes);
    assert_eq!(parsed.phase(), SessionPhase::Parsed);
    let validated = parsed.validate_public()?;
    let mut session = validated.start_session(
        fixture.reader.principal_id(),
        fixture.local.checkpoint(),
        None,
        SessionLimits::new(100, 1_000)?,
        10,
    )?;
    let mut provider = CountingProvider::new(&fixture.reader);
    session.discover_descriptor(
        &mut provider,
        fixture.visible_item_id,
        None,
        11,
        &NeverCancelled,
    )?;
    assert_eq!(
        session_error_kind(session.discover_descriptor(
            &mut provider,
            fixture.hidden_item_id,
            None,
            12,
            &NeverCancelled,
        )),
        SessionErrorKind::Unavailable
    );
    assert_eq!(provider.descriptor_calls.get(), 1);
    assert_eq!(provider.body_calls.get(), 0);
    let json = serde_json::to_string(&session.snapshot(13)?)?;
    assert!(json.contains("ExampleVisible"));
    assert!(!json.contains("ExampleHiddenActual"));
    Ok(())
}

#[test]
fn inactivity_absolute_expiry_cancellation_and_refresh_failure_are_terminal()
-> Result<(), Box<dyn Error>> {
    let fixture = direct_fixture()?;
    let envelopes = [fixture.envelope.clone()];
    let validated =
        ParsedVault::new(&fixture.policy, &fixture.journal, &envelopes).validate_public()?;
    let limits = SessionLimits::new(10, 20)?;

    let mut inactive = validated.start_session(
        fixture.owner.principal_id(),
        fixture.local.checkpoint(),
        None,
        limits,
        100,
    )?;
    assert_eq!(
        session_error_kind(inactive.snapshot(110)),
        SessionErrorKind::Expired
    );
    assert_eq!(inactive.phase(), SessionPhase::Expired);

    let mut cancelled = validated.start_session(
        fixture.owner.principal_id(),
        fixture.local.checkpoint(),
        None,
        limits,
        100,
    )?;
    cancelled.handle_signal();
    assert_eq!(cancelled.phase(), SessionPhase::Cancelled);
    assert_eq!(cancelled.catalog().entries().len(), 0);

    let mut stale = validated.start_session(
        fixture.owner.principal_id(),
        fixture.local.checkpoint(),
        None,
        limits,
        100,
    )?;
    assert_eq!(
        session_error_kind(stale.refresh_same(
            &validated,
            fixture.local.checkpoint(),
            Some(Digest32::new([0x81; 32])),
            101,
        )),
        SessionErrorKind::CheckpointConflict
    );
    assert_eq!(stale.phase(), SessionPhase::Stale);
    Ok(())
}

struct FillByte(u8);

impl RandomSource for FillByte {
    fn fill(&mut self, destination: &mut [u8]) -> Result<(), jury_protected::EntropyError> {
        destination.fill(self.0);
        Ok(())
    }
}

fn principal_add(
    principal_id: PrincipalId,
    kind: PrincipalKind,
    recipient_public_key: RecipientPublicKey1216,
    signing_seed: u8,
) -> Result<PolicyOperationV1, Box<dyn Error>> {
    let seed = [signing_seed; 32];
    let mut descriptor = PrincipalDescriptorV1 {
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

struct MixedFixture {
    direct: DirectFixture,
    checkpoint_digest: Digest32,
}

fn mixed_fixture() -> Result<MixedFixture, Box<dyn Error>> {
    let protection = ProtectionPolicy::EmergencyAllowDegraded;
    let passphrase = ProtectedMemory::initialize(15, protection, |output| {
        output.copy_from_slice(b"ExamplePass1234");
        Ok::<usize, ()>(output.len())
    })?;
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
        return Err("ExamplePrincipal role differs".into());
    };
    let mut policies = PolicyCreator::new();
    let mut created_policy = policies.create(&owner, 2, |_| false)?;
    let (mut witness_policy, _, _) = crate::policy::witness_tests::frozen_policy()?;

    let mut additions = Vec::new();
    for (index, descriptor) in witness_policy.witness_descriptors.iter().enumerate() {
        let marker = 0x61_u8.saturating_add(u8::try_from(index)?);
        let (_, public) = crypto::generate_recipient_keypair(protection, &mut FillByte(marker))?;
        assert_eq!(public, descriptor.contribution_public_key);
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
        .prepare_revision(&owner, 3, additions)?;
    created_policy.journal.revisions.push(added.revision);
    witness_policy.vault_id = created_policy.state.vault_id();
    witness_policy.genesis_fingerprint = created_policy.state.genesis_fingerprint().clone();
    witness_policy.vault_policy_sequence = 2;
    let witness_digest = witness_policy.digest()?;
    let policy = replay_policy_with_witness_policies(
        &created_policy.journal,
        std::slice::from_ref(&witness_policy),
    )?;

    let mut items = ItemCreator::new(protection);
    let created_item = items.prepare_create(
        &policy,
        &owner,
        4,
        NewItem {
            kind: ItemKind::Canonical,
            descriptor: ItemDescriptorV1::new("ExampleMixedItem".to_owned())?,
            state: ItemStateV1 {
                plaintext_schema: 1,
                fields: Vec::new(),
            },
            bucket_id: 1,
            access: ItemAccessPlan {
                grants: Vec::new(),
                direct_recipient_ids: vec![owner.principal_id()],
                witness_policy_digest: Some(witness_digest),
            },
        },
        &ItemArtifactInventory::default(),
    )?;
    let mut journal = created_policy.journal;
    journal.revisions.push(created_item.policy.revision);
    let policy = created_item.policy.state;
    let envelope = created_item.envelope;
    let candidate =
        CheckpointCandidate::from_validated(&policy, &journal, std::slice::from_ref(&envelope))?;
    let local_keys = PrincipalLocalState::for_vault_principal(
        &owner,
        policy.vault_id(),
        policy.genesis_fingerprint().clone(),
    )?;
    let local = local_keys.initialize(&candidate, 5)?;
    Ok(MixedFixture {
        direct: DirectFixture {
            owner,
            policy,
            journal,
            envelope,
            local,
        },
        checkpoint_digest: Digest32::new([0xc1; 32]),
    })
}

fn binding_for(
    fixture: &MixedFixture,
    content_role: ContentRole,
    issued_at_ms: u64,
    expires_at_ms: u64,
) -> Result<WitnessRequestBinding, Box<dyn Error>> {
    let target = RevisionAccessTarget::current(
        &fixture.direct.policy,
        &fixture.direct.envelope,
        fixture.direct.owner.principal_id(),
        content_role,
        Capability::Read,
    )?;
    let revision = RevisionToken::current(&fixture.direct.policy, &target, Capability::Read);
    let item = fixture
        .direct
        .policy
        .item(&fixture.direct.envelope.item_id)
        .ok_or("mixed item absent")?;
    let slot = item
        .witnessed_state
        .as_ref()
        .and_then(|state| {
            state
                .slots
                .iter()
                .find(|slot| slot.content_role == content_role)
        })
        .ok_or("witnessed slot absent")?;
    let authority = fixture
        .direct
        .policy
        .witness_authority(&fixture.direct.envelope.item_id)?
        .ok_or("witness authority absent")?;
    Ok(WitnessRequestBinding {
        request_id: Digest32::new([0x91; 32]),
        request_digest: Digest32::new([0x92; 32]),
        action_manifest_digest: Digest32::new([0x93; 32]),
        approval_target_digest: Digest32::new([0x94; 32]),
        workload_digest: Digest32::new([0x95; 32]),
        policy_checkpoint_digest: fixture.checkpoint_digest.clone(),
        witness_policy_id: authority.policy_id,
        witness_policy_revision: authority.policy_revision,
        witness_policy_digest: authority.policy_digest,
        intended_witness_set_digest: fixture
            .direct
            .policy
            .intended_witness_set_digest(&fixture.direct.envelope.item_id)?,
        request_session_key_fingerprint: Digest32::new([0x96; 32]),
        slot_id: slot.slot_id,
        operation: WitnessOperation::ReadStdout,
        issued_at_ms,
        not_before_ms: None,
        expires_at_ms,
        revision,
    })
}

struct StatusProvider {
    status: WitnessedAccessStatus,
    calls: usize,
}

impl ItemAccessProvider for StatusProvider {
    fn access_revision<T, E>(
        &mut self,
        _: RevisionAccessRequest<'_>,
        _: impl FnOnce(&mut ScopedRevisionAccess<'_>) -> Result<T, E>,
    ) -> Result<ItemAccessOutcome<T>, ItemAccessError<E>> {
        self.calls = self.calls.saturating_add(1);
        Ok(ItemAccessOutcome::Witnessed(self.status))
    }
}

struct ApprovedProvider<'a>(DirectItemAccessProvider<'a>);

impl ItemAccessProvider for ApprovedProvider<'_> {
    fn access_revision<T, E>(
        &mut self,
        request: RevisionAccessRequest<'_>,
        consumer: impl FnOnce(&mut ScopedRevisionAccess<'_>) -> Result<T, E>,
    ) -> Result<ItemAccessOutcome<T>, ItemAccessError<E>> {
        match self.0.access_revision(request, consumer)? {
            ItemAccessOutcome::Complete { value, .. } => Ok(ItemAccessOutcome::Complete {
                authority: AccessCompletion::WitnessedApproved,
                value,
            }),
            ItemAccessOutcome::Witnessed(status) => Ok(ItemAccessOutcome::Witnessed(status)),
        }
    }
}

#[test]
fn witnessed_matrix_pins_requests_and_never_falls_back_to_direct() -> Result<(), Box<dyn Error>> {
    let fixture = mixed_fixture()?;
    let envelopes = [fixture.direct.envelope.clone()];
    let validated = ParsedVault::new(&fixture.direct.policy, &fixture.direct.journal, &envelopes)
        .validate_public()?;
    let limits = SessionLimits::new(1_000, 10_000)?;
    let selector = ItemSelector::parse("ExampleMixedItem")?;
    let binding = binding_for(&fixture, ContentRole::Body, 11, 100)?;

    for (status, expected) in [
        (WitnessedAccessStatus::Denied, SessionPhase::Denied),
        (WitnessedAccessStatus::Expired, SessionPhase::Expired),
        (WitnessedAccessStatus::Stale, SessionPhase::Stale),
        (WitnessedAccessStatus::Replay, SessionPhase::Replay),
        (
            WitnessedAccessStatus::Unavailable,
            SessionPhase::Unavailable,
        ),
        (WitnessedAccessStatus::Cancelled, SessionPhase::Cancelled),
        (
            WitnessedAccessStatus::InsufficientQuorum,
            SessionPhase::InsufficientQuorum,
        ),
    ] {
        let mut session = validated.start_session(
            fixture.direct.owner.principal_id(),
            fixture.direct.local.checkpoint(),
            Some(fixture.checkpoint_digest.clone()),
            limits,
            10,
        )?;
        let mut direct = DirectItemAccessProvider::new(&fixture.direct.owner);
        session.discover_descriptor(
            &mut direct,
            fixture.direct.envelope.item_id,
            None,
            11,
            &NeverCancelled,
        )?;
        let mut provider = StatusProvider { status, calls: 0 };
        let outcome = session.open_item(
            &mut provider,
            &selector,
            Capability::Read,
            Some(&binding),
            12,
            &NeverCancelled,
        )?;
        assert!(matches!(
            (status, outcome),
            (WitnessedAccessStatus::Denied, SessionAccessOutcome::Denied)
                | (
                    WitnessedAccessStatus::Expired,
                    SessionAccessOutcome::Expired
                )
                | (WitnessedAccessStatus::Stale, SessionAccessOutcome::Stale)
                | (WitnessedAccessStatus::Replay, SessionAccessOutcome::Replay)
                | (
                    WitnessedAccessStatus::Unavailable,
                    SessionAccessOutcome::Unavailable
                )
                | (
                    WitnessedAccessStatus::Cancelled,
                    SessionAccessOutcome::Cancelled
                )
                | (
                    WitnessedAccessStatus::InsufficientQuorum,
                    SessionAccessOutcome::InsufficientQuorum
                )
        ));
        assert_eq!(session.phase(), expected);
        assert_eq!(session.catalog().entries().len(), 0);
        assert_eq!(provider.calls, 1);
    }

    let mut pending = validated.start_session(
        fixture.direct.owner.principal_id(),
        fixture.direct.local.checkpoint(),
        Some(fixture.checkpoint_digest.clone()),
        limits,
        10,
    )?;
    let mut direct = DirectItemAccessProvider::new(&fixture.direct.owner);
    pending.discover_descriptor(
        &mut direct,
        fixture.direct.envelope.item_id,
        None,
        11,
        &NeverCancelled,
    )?;
    let mut pending_provider = StatusProvider {
        status: WitnessedAccessStatus::Pending,
        calls: 0,
    };
    assert!(matches!(
        pending.open_item(
            &mut pending_provider,
            &selector,
            Capability::Read,
            Some(&binding),
            12,
            &NeverCancelled,
        )?,
        SessionAccessOutcome::Pending
    ));
    assert_eq!(pending.phase(), SessionPhase::WitnessPending);
    assert_eq!(pending_provider.calls, 1);

    let mut substituted = binding.clone();
    substituted.action_manifest_digest = Digest32::new([0xa1; 32]);
    assert!(matches!(
        pending.open_item(
            &mut pending_provider,
            &selector,
            Capability::Read,
            Some(&substituted),
            13,
            &NeverCancelled,
        )?,
        SessionAccessOutcome::Replay
    ));
    assert_eq!(pending.phase(), SessionPhase::Replay);
    assert_eq!(pending_provider.calls, 1);

    let expiring_binding = binding_for(&fixture, ContentRole::Body, 11, 13)?;
    let mut expiring = validated.start_session(
        fixture.direct.owner.principal_id(),
        fixture.direct.local.checkpoint(),
        Some(fixture.checkpoint_digest.clone()),
        limits,
        10,
    )?;
    let mut direct = DirectItemAccessProvider::new(&fixture.direct.owner);
    expiring.discover_descriptor(
        &mut direct,
        fixture.direct.envelope.item_id,
        None,
        11,
        &NeverCancelled,
    )?;
    let mut pending_provider = StatusProvider {
        status: WitnessedAccessStatus::Pending,
        calls: 0,
    };
    expiring.open_item(
        &mut pending_provider,
        &selector,
        Capability::Read,
        Some(&expiring_binding),
        12,
        &NeverCancelled,
    )?;
    let expired = expiring.open_item(
        &mut pending_provider,
        &selector,
        Capability::Read,
        Some(&expiring_binding),
        13,
        &NeverCancelled,
    )?;
    assert!(matches!(expired, SessionAccessOutcome::Expired));
    drop(expired);
    assert_eq!(expiring.phase(), SessionPhase::Expired);
    assert_eq!(pending_provider.calls, 1);

    let mut refreshing = validated.start_session(
        fixture.direct.owner.principal_id(),
        fixture.direct.local.checkpoint(),
        Some(fixture.checkpoint_digest.clone()),
        limits,
        10,
    )?;
    let mut direct = DirectItemAccessProvider::new(&fixture.direct.owner);
    refreshing.discover_descriptor(
        &mut direct,
        fixture.direct.envelope.item_id,
        None,
        11,
        &NeverCancelled,
    )?;
    refreshing.open_item(
        &mut pending_provider,
        &selector,
        Capability::Read,
        Some(&binding),
        12,
        &NeverCancelled,
    )?;
    assert_eq!(
        session_error_kind(refreshing.refresh_same(
            &validated,
            fixture.direct.local.checkpoint(),
            Some(fixture.checkpoint_digest.clone()),
            13,
        )),
        SessionErrorKind::CheckpointConflict
    );
    assert_eq!(refreshing.phase(), SessionPhase::Stale);
    assert_eq!(refreshing.catalog().entries().len(), 0);

    let mut broadened = binding.clone();
    broadened.revision.capability = Capability::Write;
    let mut broadening = validated.start_session(
        fixture.direct.owner.principal_id(),
        fixture.direct.local.checkpoint(),
        Some(fixture.checkpoint_digest.clone()),
        limits,
        10,
    )?;
    let mut direct = DirectItemAccessProvider::new(&fixture.direct.owner);
    broadening.discover_descriptor(
        &mut direct,
        fixture.direct.envelope.item_id,
        None,
        11,
        &NeverCancelled,
    )?;
    let mut broadening_provider = StatusProvider {
        status: WitnessedAccessStatus::Pending,
        calls: 0,
    };
    assert_eq!(
        session_error_kind(broadening.open_item(
            &mut broadening_provider,
            &selector,
            Capability::Read,
            Some(&broadened),
            12,
            &NeverCancelled,
        )),
        SessionErrorKind::InvalidBinding
    );
    assert_eq!(broadening_provider.calls, 0);

    let mut no_fallback = validated.start_session(
        fixture.direct.owner.principal_id(),
        fixture.direct.local.checkpoint(),
        Some(fixture.checkpoint_digest.clone()),
        limits,
        10,
    )?;
    let mut direct = DirectItemAccessProvider::new(&fixture.direct.owner);
    no_fallback.discover_descriptor(
        &mut direct,
        fixture.direct.envelope.item_id,
        None,
        11,
        &NeverCancelled,
    )?;
    let mut pending_provider = StatusProvider {
        status: WitnessedAccessStatus::Pending,
        calls: 0,
    };
    no_fallback.open_item(
        &mut pending_provider,
        &selector,
        Capability::Read,
        Some(&binding),
        12,
        &NeverCancelled,
    )?;
    let fallback = no_fallback.open_item(
        &mut direct,
        &selector,
        Capability::Read,
        Some(&binding),
        13,
        &NeverCancelled,
    )?;
    assert!(matches!(fallback, SessionAccessOutcome::Replay));
    drop(fallback);
    assert_eq!(no_fallback.phase(), SessionPhase::Replay);

    let mut approved = validated.start_session(
        fixture.direct.owner.principal_id(),
        fixture.direct.local.checkpoint(),
        Some(fixture.checkpoint_digest.clone()),
        limits,
        10,
    )?;
    let mut direct = DirectItemAccessProvider::new(&fixture.direct.owner);
    approved.discover_descriptor(
        &mut direct,
        fixture.direct.envelope.item_id,
        None,
        11,
        &NeverCancelled,
    )?;
    let mut provider = ApprovedProvider(DirectItemAccessProvider::new(&fixture.direct.owner));
    {
        let outcome = approved.open_item(
            &mut provider,
            &selector,
            Capability::Read,
            Some(&binding),
            12,
            &NeverCancelled,
        )?;
        let SessionAccessOutcome::WitnessedApproved(guard) = outcome else {
            return Err("witness approval did not open the body".into());
        };
        assert_eq!(guard.authority(), AccessCompletion::WitnessedApproved);
        assert_eq!(guard.revision(), &binding.revision);
    }
    assert_eq!(approved.phase(), SessionPhase::Approved);
    Ok(())
}
