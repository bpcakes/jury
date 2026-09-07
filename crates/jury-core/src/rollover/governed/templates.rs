use super::*;
use crate::witness_approval::{
    OwnerReviewLabelCreator, OwnerReviewLabelInput, ReviewLabelSubject, verify_owner_review_label,
};
use jury_protocol::witness_v1::{OwnerReviewLabelV1, PresentationSubjectV1};

pub(super) struct PolicyTemplate {
    pub(super) source: WitnessPolicy,
    pub(super) destination: WitnessPolicy,
    pub(super) labels: Vec<OwnerReviewLabelV1>,
}

pub(super) struct ScopeRemapping<'a> {
    pub(super) entries: &'a [BootstrapItemV1],
    pub(super) fields: &'a BTreeMap<(ItemId, FieldId), FieldId>,
}

pub(super) fn ensure_label_lifetime<'a>(
    labels: impl IntoIterator<Item = &'a OwnerReviewLabelV1>,
    issued_at_ms: u64,
    lifetime_ms: u64,
) -> Result<(), RolloverError> {
    let deadline = issued_at_ms.checked_add(lifetime_ms).ok_or_else(failed)?;
    if labels
        .into_iter()
        .any(|label| label.expires_at_ms.is_some_and(|expiry| expiry <= deadline))
    {
        return Err(RolloverError::new(RolloverErrorKind::ReviewLabelLifetime));
    }
    Ok(())
}

pub(super) fn initial_templates(
    source: &RolloverSource<'_>,
    context: &PolicyState,
) -> Result<BTreeMap<Digest32, PolicyTemplate>, RolloverError> {
    let mut templates = BTreeMap::new();
    let mut reserved_ids = source
        .policy
        .witness_policies
        .values()
        .map(|policy| policy.witness_policy_id)
        .collect::<BTreeSet<_>>();
    for item in source.policy.items.values() {
        let Some(witnessed) = &item.witnessed_state else {
            continue;
        };
        let slot = witnessed.slots.first().ok_or_else(source_invalid)?;
        if templates.contains_key(&slot.witness_policy_digest) {
            continue;
        }
        let prior = source
            .policy
            .witness_policy(&slot.witness_policy_digest)
            .ok_or_else(source_invalid)?;
        let id = NativeIdGenerator::new()
            .generate_item_id(|id| {
                WitnessPolicyId::from_bytes(*id.as_bytes())
                    .map_or(true, |id| reserved_ids.contains(&id))
            })
            .map_err(|_| failed())?;
        let id = WitnessPolicyId::from_bytes(*id.as_bytes()).map_err(|_| failed())?;
        reserved_ids.insert(id);
        let mut destination = prior.clone();
        destination.suite = context.suite();
        destination.witness_policy_id = id;
        destination.vault_id = context.vault_id();
        destination.genesis_fingerprint = context.genesis_fingerprint().clone();
        destination.vault_policy_sequence = 1;
        destination.vault_policy_hash = context.genesis_fingerprint().clone();
        destination.revision = 1;
        destination.predecessor_policy_digest = Digest32::new([0; 32]);
        templates.insert(
            slot.witness_policy_digest.clone(),
            PolicyTemplate {
                source: prior.clone(),
                destination,
                labels: Vec::new(),
            },
        );
    }
    Ok(templates)
}

pub(super) fn public_targets<'a>(
    catalog: &TransferPublicCatalogV1,
    policies: impl IntoIterator<Item = &'a WitnessPolicy>,
) -> BTreeSet<(ItemId, Option<FieldId>)> {
    let mut targets = BTreeSet::new();
    for policy in policies {
        targets.extend(policy.operation_rules.iter().flat_map(|rule| {
            rule.automatic_read_targets
                .iter()
                .map(|target| (target.item_id, target.field_id))
        }));
        for label in catalog
            .review_label_sets
            .iter()
            .filter(|set| set.digest == policy.review_label_set_digest)
            .flat_map(|set| &set.labels)
        {
            if let Some(item) = label.item_id {
                targets.insert((item, label.field_id));
            }
        }
    }
    targets
}

pub(super) fn remap(
    source: &RolloverSource<'_>,
    catalog: &TransferPublicCatalogV1,
    context: &PolicyState,
    owner: &VaultPrincipalIdentity,
    mapping: ScopeRemapping<'_>,
    templates: &mut BTreeMap<Digest32, PolicyTemplate>,
    timestamp_ms: u64,
) -> Result<(), RolloverError> {
    let ScopeRemapping { entries, fields } = mapping;
    let items = entries
        .iter()
        .map(|entry| (entry.source_item_id, entry.destination_item_id))
        .collect::<BTreeMap<_, _>>();
    let mut label_ids = catalog
        .review_label_sets
        .iter()
        .flat_map(|set| set.labels.iter().map(|label| label.label_id))
        .collect::<BTreeSet<_>>();
    let mut creator = OwnerReviewLabelCreator::new();
    for template in templates.values_mut() {
        for rule in &mut template.destination.operation_rules {
            for target in &mut rule.automatic_read_targets {
                let prior_item = target.item_id;
                if let Some(next_item) = items.get(&prior_item) {
                    target.item_id = *next_item;
                    if let Some(field) = target.field_id {
                        target.field_id = Some(
                            *fields
                                .get(&(prior_item, field))
                                .ok_or_else(source_invalid)?,
                        );
                    }
                }
            }
            rule.automatic_read_targets.sort_unstable();
        }
        let empty =
            jury_protocol::witness_v1::owner_review_label_set_digest(&[]).map_err(|_| invalid())?;
        let source_labels = catalog
            .review_label_sets
            .iter()
            .find(|set| set.digest == template.source.review_label_set_digest);
        if source_labels.is_none() && template.source.review_label_set_digest != empty {
            return Err(source_invalid());
        }
        for label in source_labels.into_iter().flat_map(|set| &set.labels) {
            verify_owner_review_label(
                &source.policy,
                label,
                template.source.vault_policy_sequence,
                timestamp_ms,
            )
            .map_err(|_| source_invalid())?;
            let subject = remapped_subject(label, &items, fields)?;
            let fresh = creator
                .create(
                    OwnerReviewLabelInput {
                        policy: context,
                        owner,
                        label_revision: 1,
                        subject,
                        public_label: label.public_label.clone(),
                        target_policy_sequence: 1,
                        issued_at_ms: timestamp_ms,
                        expires_at_ms: label.expires_at_ms,
                    },
                    |id| label_ids.contains(id),
                )
                .map_err(|_| failed())?;
            label_ids.insert(fresh.label_id);
            template.labels.push(fresh);
        }
        template.labels.sort_by_key(|label| label.label_id);
        template.destination.review_label_set_digest =
            jury_protocol::witness_v1::owner_review_label_set_digest(&template.labels)
                .map_err(|_| invalid())?;
    }
    Ok(())
}

fn remapped_subject(
    label: &OwnerReviewLabelV1,
    items: &BTreeMap<ItemId, ItemId>,
    fields: &BTreeMap<(ItemId, FieldId), FieldId>,
) -> Result<ReviewLabelSubject, RolloverError> {
    Ok(match label.subject_kind {
        PresentationSubjectV1::Item => {
            let prior = label.item_id.ok_or_else(source_invalid)?;
            ReviewLabelSubject::Item(items.get(&prior).copied().unwrap_or(prior))
        }
        PresentationSubjectV1::Field => {
            let prior_item = label.item_id.ok_or_else(source_invalid)?;
            let prior_field = label.field_id.ok_or_else(source_invalid)?;
            ReviewLabelSubject::Field {
                item_id: items.get(&prior_item).copied().unwrap_or(prior_item),
                field_id: if items.contains_key(&prior_item) {
                    *fields
                        .get(&(prior_item, prior_field))
                        .ok_or_else(source_invalid)?
                } else {
                    prior_field
                },
            }
        }
        PresentationSubjectV1::WorkingDirectory => ReviewLabelSubject::WorkingDirectory(
            label
                .subject_commitment
                .clone()
                .ok_or_else(source_invalid)?,
        ),
        PresentationSubjectV1::OutputSink => ReviewLabelSubject::OutputSink(
            label
                .subject_commitment
                .clone()
                .ok_or_else(source_invalid)?,
        ),
    })
}

pub(super) fn bind_final_genesis(
    templates: &mut BTreeMap<Digest32, PolicyTemplate>,
    initial: &PolicyState,
    owner: &VaultPrincipalIdentity,
) -> Result<(), RolloverError> {
    for template in templates.values_mut() {
        template.destination.genesis_fingerprint = initial.genesis_fingerprint().clone();
        template.destination.vault_policy_hash = initial.genesis_fingerprint().clone();
        for label in &mut template.labels {
            label.genesis_fingerprint = initial.genesis_fingerprint().clone();
            label.signature = owner
                .sign_validated_statement(&label.signature_preimage().map_err(|_| invalid())?)
                .map_err(|_| failed())?;
        }
        template.destination.review_label_set_digest =
            jury_protocol::witness_v1::owner_review_label_set_digest(&template.labels)
                .map_err(|_| invalid())?;
    }
    Ok(())
}
