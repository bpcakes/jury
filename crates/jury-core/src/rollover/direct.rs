use std::collections::BTreeSet;

use jury_protected::ProtectionPolicy;
use jury_protocol::{
    rollover_v1::{BootstrapGrantV1, BootstrapItemV1, BootstrapManifestV1, BootstrapPrincipalV1},
    vault_v1::{
        ContentRole, Digest32, DirectSlotV1, ItemDescriptorV1, ItemEnvelopeV1, ItemId, ItemStateV1,
        PolicyJournalV1, PolicyOperationV1, PrincipalKind, RolloverId, Signature64,
        SignedPolicyRevisionV1, SignedRolloverV1, SourceAttestationV1, VaultFileV1, VaultHeaderV1,
    },
};
use sha2::{Digest as _, Sha256};

#[cfg(test)]
mod tests;

use super::{RolloverError, RolloverErrorKind, RolloverSource};
use crate::{
    access_provider::{
        CancellationCheck, DirectItemAccessProvider, ItemAccessOutcome, ItemAccessProvider,
        RevisionAccessRequest, RevisionAccessTarget,
    },
    domain::{Capability, NativeIdGenerator},
    identity::VaultPrincipalIdentity,
    item::{ItemAccessPlan, ItemArtifactInventory, ItemCreator, ItemGrant, NewItem},
    policy::{PolicyCreator, PolicyState, replay_policy},
};

fn invalid() -> RolloverError {
    RolloverError::new(RolloverErrorKind::InvalidDestination)
}

fn failed() -> RolloverError {
    RolloverError::new(RolloverErrorKind::PreparationFailed)
}

/// A verified direct-only bootstrap. Publication, backup and explicit local
/// trust are still required. This value makes no witness-readiness claim.
pub struct PreparedDirectRollover {
    vault: VaultFileV1,
}

impl PreparedDirectRollover {
    #[must_use]
    pub const fn vault(&self) -> &VaultFileV1 {
        &self.vault
    }
}

impl RolloverSource<'_> {
    /// Copy all active direct-only state using fresh item and field identifiers
    /// and fresh encryption material. The source is never mutated. Governed
    /// items and role identities require the separate witnessed workflow.
    pub fn prepare_direct(
        &self,
        owner: &VaultPrincipalIdentity,
        timestamp_ms: u64,
        protection: ProtectionPolicy,
        cancellation: &dyn CancellationCheck,
    ) -> Result<PreparedDirectRollover, RolloverError> {
        let suite = jury_protocol::hpke_context::VaultSuite::from_id(self.policy.suite())
            .ok_or_else(invalid)?;
        self.prepare_direct_for_suite(suite, owner, timestamp_ms, protection, cancellation)
    }

    pub fn prepare_direct_migration(
        &self,
        destination_suite: jury_protocol::hpke_context::VaultSuite,
        owner: &VaultPrincipalIdentity,
        timestamp_ms: u64,
        protection: ProtectionPolicy,
        cancellation: &dyn CancellationCheck,
    ) -> Result<PreparedDirectRollover, RolloverError> {
        self.require_migration(destination_suite)?;
        self.prepare_direct_for_suite(
            destination_suite,
            owner,
            timestamp_ms,
            protection,
            cancellation,
        )
    }

    fn prepare_direct_for_suite(
        &self,
        suite: jury_protocol::hpke_context::VaultSuite,
        owner: &VaultPrincipalIdentity,
        timestamp_ms: u64,
        protection: ProtectionPolicy,
        cancellation: &dyn CancellationCheck,
    ) -> Result<PreparedDirectRollover, RolloverError> {
        self.require_direct()?;
        if !self.policy.is_owner(&owner.principal_id())
            || self
                .policy
                .principal(&owner.principal_id())
                .map(|p| &p.descriptor)
                != Some(&owner.public_descriptor().map_err(|_| failed())?)
        {
            return Err(RolloverError::new(RolloverErrorKind::Unauthorized));
        }
        let source_time = self
            .vault
            .policy
            .revisions
            .last()
            .map_or(self.vault.policy.genesis.created_at_ms, |revision| {
                revision.timestamp_ms
            });
        if timestamp_ms < source_time || cancellation.is_cancelled() {
            return Err(failed());
        }
        let created = PolicyCreator::new()
            .create_for_suite(suite, owner, timestamp_ms, |id| {
                *id == self.vault.header.vault_id
            })
            .map_err(|_| failed())?;
        // A private encryption context at sequence zero. Principal membership
        // is copied for slot resolution, then the entire batch is replayed
        // against the actual signed genesis before returning an artifact.
        let mut context = self.policy.clone();
        context.suite = suite.id();
        context.vault_id = created.state.vault_id();
        context.genesis_fingerprint = created.state.genesis_fingerprint().clone();
        context.sequence = 0;
        context.terminal_revision_hash = created.state.terminal_revision_hash().clone();
        context.revision_hashes = created.state.revision_hashes.clone();
        context.items.clear();
        context.tombstones.clear();
        context.witness_policies.clear();
        let mut inventory = ItemArtifactInventory::from_vault(self.vault).map_err(|_| failed())?;
        let mut creator = ItemCreator::new(protection);
        let mut provider = DirectItemAccessProvider::new(owner);
        let mut item_operations = Vec::new();
        let mut envelopes = Vec::new();
        let mut entries = Vec::new();
        let mut source_envelopes = self.vault.items.iter().collect::<Vec<_>>();
        source_envelopes.sort_by_key(|envelope| envelope.item_id);
        for source_envelope in source_envelopes {
            if cancellation.is_cancelled() {
                return Err(failed());
            }
            let item_id = source_envelope.item_id;
            let source_item = self.policy.item(&item_id).ok_or_else(failed)?;
            let mut plaintext = OpenedItem::default();
            plaintext.descriptor = Some(open_part(
                &mut provider,
                &self.policy,
                source_envelope,
                owner,
                ContentRole::Descriptor,
                cancellation,
                |access| access.open_descriptor(),
            )?);
            plaintext.state = Some(open_part(
                &mut provider,
                &self.policy,
                source_envelope,
                owner,
                ContentRole::Body,
                cancellation,
                |access| access.open_body(),
            )?);
            let state = plaintext.state.as_mut().ok_or_else(failed)?;
            let mut reserved_fields = state
                .fields
                .iter()
                .map(|field| field.field_id)
                .collect::<Vec<_>>();
            for field in &mut state.fields {
                field.field_id = creator
                    .generate_field_id(&reserved_fields)
                    .map_err(|_| failed())?;
                reserved_fields.push(field.field_id);
            }
            let access = ItemAccessPlan {
                grants: source_item
                    .grants
                    .iter()
                    .map(|(id, role)| ItemGrant {
                        principal_id: *id,
                        role: *role,
                    })
                    .collect(),
                direct_recipient_ids: direct_recipients(&source_item.direct_slots),
                witness_policy_digest: None,
            };
            let input = NewItem {
                kind: source_item.item_kind,
                descriptor: plaintext.descriptor.take().ok_or_else(failed)?,
                state: plaintext.state.take().ok_or_else(failed)?,
                bucket_id: source_envelope.current_revision.bucket_id,
                access: access.clone(),
            };
            let staged = creator
                .stage_create(&context, owner, timestamp_ms, input, &mut inventory)
                .map_err(|_| failed())?;
            context
                .historical_item_ids
                .insert(staged.envelope().item_id);
            if staged.witness_slot_ids().is_some() {
                return Err(failed());
            }
            entries.push(BootstrapItemV1 {
                source_item_id: item_id,
                destination_item_id: staged.envelope().item_id,
                item_kind: source_item.item_kind,
                descriptor: staged.envelope().descriptor.clone(),
                initial_item_revision_hash: staged
                    .envelope()
                    .current_revision
                    .recomputed_hash()
                    .map_err(|_| failed())?,
                direct_slot_set_digest: direct_digest(staged.direct_slots())?,
                grants: grants(&self.policy, item_id)?,
                witnessed: None,
            });
            let component = creator
                .finish_create(&context, staged, access)
                .map_err(|_| failed())?;
            item_operations.extend(component.operations);
            envelopes.push(component.envelope);
        }
        entries.sort_by_key(|entry| entry.source_item_id);
        envelopes.sort_by_key(|envelope| envelope.item_id);
        let manifest = BootstrapManifestV1 {
            version: 2,
            source_suite: Some(self.vault.header.suite),
            destination_suite: suite.id(),
            destination_vault_id: context.vault_id(),
            created_at_ms: timestamp_ms,
            acting_owner_principal_id: owner.principal_id(),
            principals: principals(&self.policy)?,
            items: entries,
            witness_policies: Vec::new(),
        };
        let generated = NativeIdGenerator::new()
            .generate_item_id(|_| false)
            .map_err(|_| failed())?;
        let mut statement = SignedRolloverV1 {
            rollover_format: 1,
            rollover_id: RolloverId::from_bytes(*generated.as_bytes()).map_err(|_| failed())?,
            source_vault_id: self.vault.header.vault_id,
            source_genesis_fingerprint: self.policy.genesis_fingerprint().clone(),
            terminal_source_revision_hash: self.policy.terminal_revision_hash().clone(),
            destination_vault_id: context.vault_id(),
            destination_suite: suite.id(),
            bootstrap_manifest_digest: manifest.digest().map_err(|_| failed())?,
            bootstrap_manifest: Some(manifest),
            acting_owner_principal_id: owner.principal_id(),
            signature: Signature64::new([0; 64]),
        };
        statement.signature = owner
            .sign_validated_statement(&statement.signature_preimage())
            .map_err(|_| failed())?;
        let mut operations = principal_operations(&self.policy, &statement)?;
        operations.extend(item_operations);
        let mut genesis = created.journal.genesis;
        genesis.source_attestation = Some(SourceAttestationV1::Rollover {
            statement: Box::new(statement),
        });
        genesis.owner_signature = owner
            .sign_validated_statement(&genesis.signature_preimage().map_err(|_| failed())?)
            .map_err(|_| failed())?;
        let mut journal = PolicyJournalV1 {
            genesis,
            revisions: Vec::new(),
        };
        let initial = replay_policy(&journal).map_err(|_| failed())?;
        let revision = if operations.is_empty() {
            if !journal.genesis.permits_empty_rollover_bootstrap() {
                return Err(failed());
            }
            let mut state = initial.clone();
            state.sequence = 1;
            let mut revision = SignedPolicyRevisionV1 {
                vault_id: state.vault_id(),
                sequence: 1,
                previous_revision_hash: initial.terminal_revision_hash().clone(),
                timestamp_ms,
                author_principal_id: owner.principal_id(),
                operations,
                resulting_policy_state_hash: state.normalized_state_hash().map_err(|_| failed())?,
                signature: Signature64::new([0; 64]),
            };
            revision.signature = owner
                .sign_validated_statement(&revision.signature_preimage().map_err(|_| failed())?)
                .map_err(|_| failed())?;
            revision
        } else {
            initial
                .prepare_revision(owner, timestamp_ms, operations)
                .map_err(|_| failed())?
                .revision
        };
        journal.revisions.push(revision);
        let mut vault = VaultFileV1 {
            header: VaultHeaderV1 {
                magic: "jury-vault".to_owned(),
                version: 1,
                vault_id: initial.vault_id(),
                created_at_ms: timestamp_ms,
                suite: suite.id(),
                policy_schema: 1,
                item_schema: 1,
                identity_schema: 1,
                genesis_fingerprint: initial.genesis_fingerprint().clone(),
            },
            policy: journal,
            items: envelopes,
            suite_migration: None,
        };
        super::migration::attach(&mut vault, owner)?;
        self.verify_fresh_direct_destination(&vault)?;
        if cancellation.is_cancelled() {
            return Err(failed());
        }
        Ok(PreparedDirectRollover { vault })
    }

    /// Validate a newly constructed direct bootstrap against this exact source.
    /// Later destination revisions require historical bootstrap verification.
    /// This authenticates provenance and public state, not plaintext equality
    /// or external source trust/freshness.
    pub fn verify_fresh_direct_destination(
        &self,
        vault: &VaultFileV1,
    ) -> Result<(), RolloverError> {
        if vault.policy.revisions.len() != 1 {
            return Err(invalid());
        }
        self.verify_direct_destination(vault, &[], true)
    }

    /// Validate the signed bootstrap after ordinary destination mutations.
    /// Current artifacts are fully authenticated, but deleted initial bodies
    /// need not be retained. This proves public provenance, not historical
    /// plaintext equivalence or source freshness.
    pub fn verify_historical_direct_destination(
        &self,
        vault: &VaultFileV1,
        catalog: &crate::transfer::TransferPublicCatalogV1,
    ) -> Result<(), RolloverError> {
        let current = RolloverSource::validate(vault, &catalog.witness_policies)?;
        catalog.to_json_bytes().map_err(|_| invalid())?;
        catalog
            .validate_for_policy(vault, &current.policy)
            .map_err(|_| invalid())?;
        self.verify_direct_destination(vault, &catalog.witness_policies, false)
    }

    fn verify_direct_destination(
        &self,
        vault: &VaultFileV1,
        witness_policies: &[crate::policy::WitnessPolicy],
        fresh: bool,
    ) -> Result<(), RolloverError> {
        self.require_direct()?;
        self.verify_source_authorization(&vault.policy.genesis)?;
        RolloverSource::validate(vault, witness_policies)?;
        let bootstrap = super::bootstrap_state(vault, witness_policies)?;
        let Some(SourceAttestationV1::Rollover { statement }) =
            &vault.policy.genesis.source_attestation
        else {
            return Err(invalid());
        };
        let manifest = statement.bootstrap_manifest.as_ref().ok_or_else(invalid)?;
        if manifest.digest().map_err(|_| invalid())? != statement.bootstrap_manifest_digest
            || manifest.principals != principals(&self.policy)?
            || bootstrap.principals != self.policy.principals
            || bootstrap.owners != self.policy.owners
            || !bootstrap.tombstones.is_empty()
            || manifest.items.len() != self.policy.items.len()
            || manifest.items.len() != bootstrap.items.len()
            || !manifest.witness_policies.is_empty()
        {
            return Err(invalid());
        }
        let revision = &vault.policy.revisions[0];
        if revision.author_principal_id != statement.acting_owner_principal_id
            || revision.timestamp_ms != manifest.created_at_ms
        {
            return Err(invalid());
        }
        let mut expected_operations = principal_operations(&self.policy, statement)?;
        for entry in &manifest.items {
            let source = self
                .policy
                .item(&entry.source_item_id)
                .ok_or_else(invalid)?;
            let item = bootstrap
                .item(&entry.destination_item_id)
                .ok_or_else(invalid)?;
            if self.policy.item_id_was_used(&entry.destination_item_id)
                || item.item_kind != source.item_kind
                || entry.item_kind != item.item_kind
                || item.key_epoch != 1
                || item.grants != source.grants
                || entry.descriptor != item.descriptor
                || entry.initial_item_revision_hash != item.current_item_revision_hash
                || entry.direct_slot_set_digest != direct_digest(&item.direct_slots)?
                || entry.grants != grants(&self.policy, entry.source_item_id)?
                || entry.grants != grants(&bootstrap, entry.destination_item_id)?
                || entry.witnessed.is_some()
            {
                return Err(invalid());
            }
            if fresh {
                super::verify_fresh_envelope(vault, entry, statement, manifest.created_at_ms)?;
            }
            expected_operations.push(PolicyOperationV1::ItemCreate {
                item_id: entry.destination_item_id,
                item_kind: item.item_kind,
                key_epoch: 1,
                descriptor: item.descriptor.clone(),
                current_item_revision_hash: item.current_item_revision_hash.clone(),
                direct_slots: item.direct_slots.clone(),
                witnessed_state: None,
            });
        }
        if revision.operations != expected_operations {
            return Err(invalid());
        }
        let source_inventory =
            ItemArtifactInventory::from_vault(self.vault).map_err(|_| invalid())?;
        let destination_inventory =
            ItemArtifactInventory::from_vault(vault).map_err(|_| invalid())?;
        if fresh && !source_inventory.is_disjoint(&destination_inventory) {
            return Err(invalid());
        }
        Ok(())
    }

    fn require_direct(&self) -> Result<(), RolloverError> {
        if self
            .policy
            .items
            .values()
            .any(|item| item.witnessed_state.is_some())
            || self.policy.principals.values().any(|principal| {
                matches!(
                    principal.descriptor.principal_kind,
                    PrincipalKind::Approver | PrincipalKind::Witness
                )
            })
        {
            return Err(RolloverError::new(RolloverErrorKind::UnsupportedTopology));
        }
        Ok(())
    }
}

pub(super) fn principals(policy: &PolicyState) -> Result<Vec<BootstrapPrincipalV1>, RolloverError> {
    policy
        .principals()
        .map(|(id, principal)| {
            Ok(BootstrapPrincipalV1 {
                principal_id: *id,
                unsigned_descriptor_digest: Digest32::new(
                    Sha256::digest(
                        principal
                            .descriptor
                            .self_signature_preimage()
                            .map_err(|_| invalid())?,
                    )
                    .into(),
                ),
                display_label: principal.display_label.clone(),
                owner: policy.is_owner(id),
            })
        })
        .collect()
}

pub(super) fn direct_recipients(
    slots: &[DirectSlotV1],
) -> Vec<jury_protocol::vault_v1::PrincipalId> {
    slots
        .iter()
        .map(|slot| slot.recipient_principal_id)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

pub(super) fn grants(
    policy: &PolicyState,
    item_id: ItemId,
) -> Result<Vec<BootstrapGrantV1>, RolloverError> {
    let item = policy.item(&item_id).ok_or_else(invalid)?;
    let direct = direct_recipients(&item.direct_slots)
        .into_iter()
        .collect::<BTreeSet<_>>();
    policy
        .effective_reader_ids(&item_id)
        .into_iter()
        .map(|id| {
            Ok(BootstrapGrantV1 {
                principal_id: id,
                role: policy.effective_role(&item_id, &id).ok_or_else(invalid)?,
                direct: direct.contains(&id),
            })
        })
        .collect()
}

pub(super) fn direct_digest(slots: &[DirectSlotV1]) -> Result<Digest32, RolloverError> {
    let mut bytes = Vec::new();
    crate::canonical::list_bytes(
        &mut bytes,
        &slots
            .iter()
            .map(DirectSlotV1::canonical_bytes)
            .collect::<Vec<_>>(),
    )
    .map_err(|_| invalid())?;
    Ok(Digest32::new(Sha256::digest(bytes).into()))
}

pub(super) fn principal_operations(
    policy: &PolicyState,
    statement: &SignedRolloverV1,
) -> Result<Vec<PolicyOperationV1>, RolloverError> {
    let mut operations = Vec::new();
    let bridge_digest = Digest32::new(Sha256::digest(statement.signature_preimage()).into());
    for (id, principal) in policy.principals() {
        if *id == statement.acting_owner_principal_id {
            if principal.display_label != "owner" {
                operations.push(PolicyOperationV1::PrincipalLabelChange {
                    principal_id: *id,
                    prior_label: "owner".to_owned(),
                    next_label: principal.display_label.clone(),
                });
            }
        } else {
            operations.push(PolicyOperationV1::PrincipalAdd {
                descriptor: principal.descriptor.clone(),
                display_label: principal.display_label.clone(),
                registration_proof_digest: bridge_digest.clone(),
            });
            if policy.is_owner(id) {
                operations.push(PolicyOperationV1::OwnerGrant { principal_id: *id });
            }
        }
    }
    Ok(operations)
}

#[derive(Default)]
pub(super) struct OpenedItem {
    pub(super) descriptor: Option<ItemDescriptorV1>,
    pub(super) state: Option<ItemStateV1>,
}

impl Drop for OpenedItem {
    fn drop(&mut self) {
        if let Some(descriptor) = &mut self.descriptor {
            descriptor.clear_sensitive();
        }
        if let Some(state) = &mut self.state {
            state.clear_sensitive();
        }
    }
}

pub(super) fn open_part<T>(
    provider: &mut impl ItemAccessProvider,
    policy: &PolicyState,
    envelope: &ItemEnvelopeV1,
    owner: &VaultPrincipalIdentity,
    role: ContentRole,
    cancellation: &dyn CancellationCheck,
    consumer: impl FnOnce(
        &mut crate::access_provider::ScopedRevisionAccess<'_>,
    ) -> Result<T, crate::access_provider::AccessProviderError>,
) -> Result<T, RolloverError> {
    let access_failed = || RolloverError::new(RolloverErrorKind::AccessFailed);
    let target = RevisionAccessTarget::current(
        policy,
        envelope,
        owner.principal_id(),
        role,
        Capability::Administer,
    )
    .map_err(|_| access_failed())?;
    let outcome = provider
        .access_revision(
            RevisionAccessRequest {
                policy,
                envelope,
                target,
                capability: Capability::Administer,
                cancellation,
            },
            consumer,
        )
        .map_err(|_| access_failed())?;
    match outcome {
        ItemAccessOutcome::Complete { value, .. } => Ok(value),
        ItemAccessOutcome::Witnessed(_) => Err(access_failed()),
    }
}
