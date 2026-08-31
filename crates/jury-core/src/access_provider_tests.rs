use std::cell::Cell;
use std::error::Error;

use jury_protected::{ProtectedMemory, ProtectionPolicy};
use jury_protocol::{
    identity_v1::KdfProfile,
    vault_v1::{
        AccessRole, ContentRole, Digest32, DirectCiphertext48, ItemAccessMode, ItemDescriptorV1,
        ItemId, ItemKind, ItemStateV1, PrincipalId, RevisionSealId,
    },
};

use super::*;
use crate::identity::{IdentityCreator, UnlockedIdentity, unlock};
use crate::item::{ItemAccessPlan, ItemArtifactInventory, ItemCreator, NewItem};
use crate::policy::PolicyCreator;

struct CreatedDirectItem {
    owner: VaultPrincipalIdentity,
    policy: PolicyState,
    envelope: ItemEnvelopeV1,
    descriptor: ItemDescriptorV1,
    body: ItemStateV1,
}

fn create_direct_item() -> Result<CreatedDirectItem, Box<dyn Error>> {
    let protection = ProtectionPolicy::EmergencyAllowDegraded;
    let passphrase = ProtectedMemory::initialize(15, protection, |output| {
        output.copy_from_slice(b"ExamplePass1234");
        Ok::<usize, ()>(output.len())
    })?;
    let mut identities = IdentityCreator::new();
    let created_identity = identities.create(
        jury_protocol::vault_v1::PrincipalKind::Human,
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
    let descriptor = ItemDescriptorV1::new("ExampleItem".to_owned())?;
    let body = ItemStateV1 {
        plaintext_schema: 1,
        fields: Vec::new(),
    };
    let mut items = ItemCreator::new(protection);
    let created_item = items.prepare_create(
        &created_policy.state,
        &owner,
        3,
        NewItem {
            kind: ItemKind::Canonical,
            descriptor: descriptor.clone(),
            state: body.clone(),
            bucket_id: 1,
            access: ItemAccessPlan {
                grants: Vec::new(),
                direct_recipient_ids: vec![owner.principal_id()],
                witness_policy_digest: None,
            },
        },
        &ItemArtifactInventory::default(),
    )?;
    Ok(CreatedDirectItem {
        owner,
        policy: created_item.policy.state,
        envelope: created_item.envelope,
        descriptor,
        body,
    })
}

fn request<'a>(
    item: &'a CreatedDirectItem,
    target: RevisionAccessTarget,
    cancellation: &'a dyn CancellationCheck,
) -> RevisionAccessRequest<'a> {
    RevisionAccessRequest {
        policy: &item.policy,
        envelope: &item.envelope,
        target,
        capability: Capability::Read,
        cancellation,
    }
}

fn provider_error<T, E>(
    result: &Result<ItemAccessOutcome<T>, ItemAccessError<E>>,
) -> Option<AccessProviderErrorKind> {
    result
        .as_ref()
        .err()
        .and_then(ItemAccessError::provider_kind)
}

fn assert_rejected(
    provider: &mut DirectItemAccessProvider<'_>,
    item: &CreatedDirectItem,
    target: RevisionAccessTarget,
    expected: AccessProviderErrorKind,
) {
    let result =
        provider.access_revision(request(item, target, &NeverCancelled), |_| Ok::<(), ()>(()));
    assert_eq!(provider_error(&result), Some(expected));
}

struct CancelAfterDecapsulation(Cell<u8>);

impl CancellationCheck for CancelAfterDecapsulation {
    fn is_cancelled(&self) -> bool {
        let checks = self.0.get();
        self.0.set(checks.saturating_add(1));
        checks > 0
    }
}

struct FailingUnwrapper {
    principal_id: PrincipalId,
    failure: AccessProviderErrorKind,
}

impl DirectSlotUnwrapper for FailingUnwrapper {
    fn principal_id(&self) -> PrincipalId {
        self.principal_id
    }

    fn open_direct_slot(
        &self,
        _: &jury_protocol::vault_v1::DirectSlotV1,
    ) -> Result<ProtectedRevisionSecret, AccessProviderErrorKind> {
        Err(self.failure)
    }
}

struct ScriptedWitnessedProvider(WitnessedAccessStatus);

impl ItemAccessProvider for ScriptedWitnessedProvider {
    fn access_revision<T, E>(
        &mut self,
        _: RevisionAccessRequest<'_>,
        _: impl FnOnce(&mut ScopedRevisionAccess<'_>) -> Result<T, E>,
    ) -> Result<ItemAccessOutcome<T>, ItemAccessError<E>> {
        Ok(ItemAccessOutcome::Witnessed(self.0))
    }
}

#[test]
fn direct_provider_scopes_revision_access_and_rejects_substitution() -> Result<(), Box<dyn Error>> {
    let item = create_direct_item()?;
    let owner_id = item.owner.principal_id();
    let body_target = RevisionAccessTarget::current(
        &item.policy,
        &item.envelope,
        owner_id,
        ContentRole::Body,
        Capability::Read,
    )?;
    let descriptor_target = RevisionAccessTarget::current(
        &item.policy,
        &item.envelope,
        owner_id,
        ContentRole::Descriptor,
        Capability::Read,
    )?;
    let cleanup_count = Cell::new(0_u8);
    let cleanup = || cleanup_count.set(cleanup_count.get().saturating_add(1));
    let mut provider = DirectItemAccessProvider::with_test_unwrapper(&item.owner, &cleanup);

    let opened_body = provider.access_revision(
        request(&item, body_target.clone(), &NeverCancelled),
        |access| access.open_body(),
    );
    let Ok(ItemAccessOutcome::Complete {
        authority,
        value: opened_body,
    }) = opened_body
    else {
        panic!("body access did not complete");
    };
    assert_eq!(authority, AccessCompletion::Direct);
    assert!(opened_body == item.body);
    assert_eq!(cleanup_count.get(), 1);

    let opened_descriptor = provider.access_revision(
        request(&item, descriptor_target.clone(), &NeverCancelled),
        |access| access.open_descriptor(),
    );
    let Ok(ItemAccessOutcome::Complete {
        authority,
        value: opened_descriptor,
    }) = opened_descriptor
    else {
        panic!("descriptor access did not complete");
    };
    assert_eq!(authority, AccessCompletion::Direct);
    assert!(opened_descriptor == item.descriptor);
    assert_eq!(cleanup_count.get(), 2);

    let wrong_role_open = provider.access_revision(
        request(&item, body_target.clone(), &NeverCancelled),
        |access| access.open_descriptor(),
    );
    assert!(matches!(
        wrong_role_open,
        Err(ItemAccessError::Consumer(error))
            if error.kind() == AccessProviderErrorKind::InvalidRequest
    ));
    assert_eq!(cleanup_count.get(), 3);

    let mut wrong = body_target.clone();
    wrong.principal_id = PrincipalId::from_bytes([0x31; 32])?;
    assert_rejected(
        &mut provider,
        &item,
        wrong,
        AccessProviderErrorKind::WrongPrincipal,
    );
    let mut wrong = body_target.clone();
    wrong.access_role = AccessRole::Reader;
    assert_rejected(
        &mut provider,
        &item,
        wrong,
        AccessProviderErrorKind::Unauthorized,
    );
    let mut wrong = body_target.clone();
    wrong.item_id = ItemId::from_bytes([0x32; 32])?;
    assert_rejected(
        &mut provider,
        &item,
        wrong,
        AccessProviderErrorKind::InvalidRequest,
    );
    let mut wrong = body_target.clone();
    wrong.key_epoch += 1;
    assert_rejected(
        &mut provider,
        &item,
        wrong,
        AccessProviderErrorKind::InvalidAncestry,
    );
    let mut wrong = body_target.clone();
    wrong.policy_sequence += 1;
    assert_rejected(
        &mut provider,
        &item,
        wrong,
        AccessProviderErrorKind::StalePolicy,
    );
    let mut wrong = body_target.clone();
    wrong.policy_revision_hash = Digest32::new([0x33; 32]);
    assert_rejected(
        &mut provider,
        &item,
        wrong,
        AccessProviderErrorKind::StalePolicy,
    );
    let mut wrong = body_target.clone();
    wrong.revision += 1;
    assert_rejected(
        &mut provider,
        &item,
        wrong,
        AccessProviderErrorKind::InvalidRequest,
    );
    let mut wrong = body_target.clone();
    wrong.revision_seal_id = RevisionSealId::from_bytes([0x35; 32])?;
    assert_rejected(
        &mut provider,
        &item,
        wrong,
        AccessProviderErrorKind::InvalidRequest,
    );
    let mut wrong = body_target.clone();
    wrong.suite += 1;
    assert_rejected(
        &mut provider,
        &item,
        wrong,
        AccessProviderErrorKind::InvalidRequest,
    );
    let mut wrong = body_target.clone();
    wrong.item_access_mode = ItemAccessMode::Mixed;
    assert_rejected(
        &mut provider,
        &item,
        wrong,
        AccessProviderErrorKind::InvalidAncestry,
    );

    let mut corrupted = CreatedDirectItem {
        owner: item.owner,
        policy: item.policy.clone(),
        envelope: item.envelope.clone(),
        descriptor: item.descriptor,
        body: item.body,
    };
    let slot = corrupted
        .policy
        .items
        .get_mut(&corrupted.envelope.item_id)
        .and_then(|policy_item| {
            policy_item
                .direct_slots
                .iter_mut()
                .find(|slot| slot.content_role == ContentRole::Body)
        })
        .ok_or("body slot absent")?;
    slot.ciphertext = DirectCiphertext48::new([0x34; 48]);
    let mut provider = DirectItemAccessProvider::new(&corrupted.owner);
    assert_rejected(
        &mut provider,
        &corrupted,
        body_target,
        AccessProviderErrorKind::InvalidSlot,
    );
    Ok(())
}

#[test]
fn direct_provider_cleans_up_on_error_cancellation_panic_and_provider_failure()
-> Result<(), Box<dyn Error>> {
    let item = create_direct_item()?;
    let target = RevisionAccessTarget::current(
        &item.policy,
        &item.envelope,
        item.owner.principal_id(),
        ContentRole::Body,
        Capability::Read,
    )?;
    let cleanup_count = Cell::new(0_u8);
    let cleanup = || cleanup_count.set(cleanup_count.get().saturating_add(1));
    let mut provider = DirectItemAccessProvider::with_test_unwrapper(&item.owner, &cleanup);

    let consumer_error = provider
        .access_revision(request(&item, target.clone(), &NeverCancelled), |_| {
            Err::<(), _>("ExampleConsumerError")
        });
    assert!(matches!(consumer_error, Err(ItemAccessError::Consumer(_))));
    assert_eq!(cleanup_count.get(), 1);
    assert_eq!(format!("{consumer_error:?}"), "Err(Consumer([REDACTED]))");

    let cancellation = CancelAfterDecapsulation(Cell::new(0));
    let callback_called = Cell::new(false);
    let cancelled = provider.access_revision(request(&item, target.clone(), &cancellation), |_| {
        callback_called.set(true);
        Ok::<(), ()>(())
    });
    assert_eq!(
        provider_error(&cancelled),
        Some(AccessProviderErrorKind::Cancelled)
    );
    assert!(!callback_called.get());
    assert_eq!(cancellation.0.get(), 2);
    assert_eq!(cleanup_count.get(), 2);

    let panicked = provider.access_revision(
        request(&item, target.clone(), &NeverCancelled),
        |_| -> Result<(), ()> { panic!("ExampleConsumerPanic") },
    );
    assert_eq!(
        provider_error(&panicked),
        Some(AccessProviderErrorKind::ConsumerPanicked)
    );
    assert_eq!(cleanup_count.get(), 3);

    for failure in [
        AccessProviderErrorKind::ProviderFailure,
        AccessProviderErrorKind::EntropyUnavailable,
    ] {
        let unwrapper = FailingUnwrapper {
            principal_id: item.owner.principal_id(),
            failure,
        };
        let mut failing = DirectItemAccessProvider::with_test_unwrapper(&unwrapper, &cleanup);
        let result = failing
            .access_revision(request(&item, target.clone(), &NeverCancelled), |_| {
                Ok::<(), ()>(())
            });
        assert_eq!(provider_error(&result), Some(failure));
    }
    assert_eq!(cleanup_count.get(), 5);
    Ok(())
}

#[test]
fn witnessed_states_use_the_same_boundary_without_running_a_consumer() -> Result<(), Box<dyn Error>>
{
    let item = create_direct_item()?;
    let target = RevisionAccessTarget::current(
        &item.policy,
        &item.envelope,
        item.owner.principal_id(),
        ContentRole::Body,
        Capability::Read,
    )?;
    let statuses = [
        WitnessedAccessStatus::Pending,
        WitnessedAccessStatus::Denied,
        WitnessedAccessStatus::Expired,
        WitnessedAccessStatus::Stale,
        WitnessedAccessStatus::Replay,
        WitnessedAccessStatus::Unavailable,
        WitnessedAccessStatus::Cancelled,
        WitnessedAccessStatus::InsufficientQuorum,
    ];
    for status in statuses {
        let consumer_called = Cell::new(false);
        let mut provider = ScriptedWitnessedProvider(status);
        let result =
            provider.access_revision(request(&item, target.clone(), &NeverCancelled), |_| {
                consumer_called.set(true);
                Ok::<(), ()>(())
            });
        assert!(matches!(
            result,
            Ok(ItemAccessOutcome::Witnessed(actual)) if actual == status
        ));
        assert!(!consumer_called.get());
    }
    Ok(())
}
