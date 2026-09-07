use super::*;
use crate::witness_approval::verify_owner_review_label;
use jury_protocol::witness_v1::OwnerReviewLabelV1;

// Public readers cannot identify equal concealed values. They can require a
// bijection between the public field scopes and preserve every field's set of
// policy-rule and review-label uses. Grouping by the complete use pattern also
// detects merging distinct source fields into one newly over-authorized field.
#[derive(Default)]
struct PublicScopes {
    fields: BTreeMap<(ItemId, FieldId), Vec<Vec<u8>>>,
    other: Vec<Vec<u8>>,
}

impl PublicScopes {
    fn add_with_inactive(
        &mut self,
        item: Option<ItemId>,
        field: Option<FieldId>,
        token: Vec<u8>,
        inactive: &BTreeSet<ItemId>,
    ) -> Result<(), RolloverError> {
        if item.is_some_and(|item| inactive.contains(&item)) {
            // Inactive item/field IDs stay exact; they are not part of the
            // bijective renaming of scopes on active items.
            self.add(
                item,
                None,
                serde_json::to_vec(&(field, token)).map_err(|_| invalid())?,
            )
        } else {
            self.add(item, field, token)
        }
    }

    fn add(
        &mut self,
        item: Option<ItemId>,
        field: Option<FieldId>,
        token: Vec<u8>,
    ) -> Result<(), RolloverError> {
        if let Some(field) = field {
            self.fields
                .entry((item.ok_or_else(invalid)?, field))
                .or_default()
                .push(token);
        } else {
            self.other
                .push(serde_json::to_vec(&(item, token)).map_err(|_| invalid())?);
        }
        Ok(())
    }

    fn canonical_patterns(&self) -> Vec<(ItemId, Vec<Vec<u8>>)> {
        let mut patterns = self
            .fields
            .iter()
            .map(|((item, _), uses)| {
                let mut uses = uses.clone();
                uses.sort();
                (*item, uses)
            })
            .collect::<Vec<_>>();
        patterns.sort();
        patterns
    }
}

pub(super) fn verify(
    source: &RolloverSource<'_>,
    source_catalog: &TransferPublicCatalogV1,
    initial: &PolicyState,
    manifest: &BootstrapManifestV1,
    catalog: &TransferPublicCatalogV1,
    now_ms: u64,
) -> Result<(), RolloverError> {
    let items = manifest
        .items
        .iter()
        .map(|entry| (entry.source_item_id, entry.destination_item_id))
        .collect::<BTreeMap<_, _>>();
    let mut active = BTreeMap::new();
    for item in source.policy.items.values() {
        if let Some(witnessed) = &item.witnessed_state {
            let slot = witnessed.slots.first().ok_or_else(invalid)?;
            if active
                .insert(
                    (slot.witness_policy_id, slot.witness_policy_revision),
                    slot.witness_policy_digest.clone(),
                )
                .is_some_and(|prior| prior != slot.witness_policy_digest)
            {
                return Err(invalid());
            }
        }
    }
    if active.len() != manifest.witness_policies.len() {
        return Err(invalid());
    }
    let targets = super::super::templates::public_targets(
        source_catalog,
        active
            .values()
            .filter_map(|digest| source.policy.witness_policy(digest)),
    );
    let inactive = targets
        .iter()
        .filter_map(|(item, _)| (!items.contains_key(item)).then_some(*item))
        .collect::<BTreeSet<_>>();
    if (manifest.version == 1 && !inactive.is_empty())
        || items.values().any(|item| inactive.contains(item))
    {
        return Err(invalid());
    }
    let remapped_item = |item: ItemId| -> Result<ItemId, RolloverError> {
        items
            .get(&item)
            .copied()
            .or_else(|| inactive.contains(&item).then_some(item))
            .ok_or_else(invalid)
    };
    let mut old_scopes = PublicScopes::default();
    let mut new_scopes = PublicScopes::default();
    let old_label_ids = source_catalog
        .review_label_sets
        .iter()
        .flat_map(|set| set.labels.iter().map(|label| label.label_id))
        .collect::<BTreeSet<_>>();
    let mut used_label_sets = BTreeSet::new();
    for entry in &manifest.witness_policies {
        let mut matches = active.iter().filter(|((id, revision), _)| {
            *id == entry.source_policy_id
                && entry
                    .source_policy_revision
                    .is_none_or(|expected| expected == *revision)
        });
        let ((_, source_revision), digest) = matches.next().ok_or_else(invalid)?;
        if matches.next().is_some() {
            return Err(invalid());
        }
        let prior = source.policy.witness_policy(digest).ok_or_else(invalid)?;
        let next = catalog
            .witness_policies
            .iter()
            .find(|policy| policy.witness_policy_id == entry.destination_policy_id)
            .ok_or_else(invalid)?;
        if source
            .policy
            .witness_policies
            .values()
            .any(|policy| policy.witness_policy_id == next.witness_policy_id)
        {
            return Err(invalid());
        }
        if next.suite != initial.suite()
            || next.genesis_fingerprint != *initial.genesis_fingerprint()
            || next.vault_policy_hash != *initial.genesis_fingerprint()
            || next.vault_id != initial.vault_id()
            || next.revision != 1
            || next.vault_policy_sequence != 1
            || next.predecessor_policy_digest != Digest32::new([0; 32])
        {
            return Err(invalid());
        }
        let mut normalized = next.clone();
        normalized.suite = prior.suite;
        normalized.witness_policy_id = prior.witness_policy_id;
        normalized.vault_id = prior.vault_id;
        normalized.genesis_fingerprint = prior.genesis_fingerprint.clone();
        normalized.vault_policy_sequence = prior.vault_policy_sequence;
        normalized.vault_policy_hash = prior.vault_policy_hash.clone();
        normalized.revision = prior.revision;
        normalized.predecessor_policy_digest = prior.predecessor_policy_digest.clone();
        normalized.review_label_set_digest = prior.review_label_set_digest.clone();
        let mut expected = prior.clone();
        for rule in &mut normalized.operation_rules {
            rule.automatic_read_targets.clear();
        }
        for rule in &mut expected.operation_rules {
            rule.automatic_read_targets.clear();
        }
        if normalized != expected {
            return Err(invalid());
        }
        for (policy, scopes, remap) in [
            (prior, &mut old_scopes, true),
            (next, &mut new_scopes, false),
        ] {
            for rule in &policy.operation_rules {
                for target in &rule.automatic_read_targets {
                    let item = if remap {
                        remapped_item(target.item_id)?
                    } else {
                        target.item_id
                    };
                    let token = serde_json::to_vec(&(
                        "automatic",
                        entry.source_policy_id,
                        source_revision,
                        rule.operation,
                        target.content_role,
                    ))
                    .map_err(|_| invalid())?;
                    scopes.add_with_inactive(Some(item), target.field_id, token, &inactive)?;
                }
            }
        }
        let prior_labels = labels(source_catalog, &prior.review_label_set_digest)?;
        let next_labels = labels(catalog, &next.review_label_set_digest)?;
        if super::super::super::witness_intent_digest(next, next_labels)? != entry.intent_digest {
            return Err(invalid());
        }
        if catalog
            .review_label_sets
            .iter()
            .any(|set| set.digest == next.review_label_set_digest)
        {
            used_label_sets.insert(next.review_label_set_digest.clone());
        }
        for label in prior_labels {
            verify_owner_review_label(&source.policy, label, prior.vault_policy_sequence, now_ms)
                .map_err(|_| invalid())?;
            add_label_scope(
                &mut old_scopes,
                entry.source_policy_id,
                *source_revision,
                label,
                label.item_id.map(remapped_item).transpose()?,
                &inactive,
            )?;
        }
        for label in next_labels {
            verify_owner_review_label(initial, label, 1, now_ms).map_err(|_| invalid())?;
            if old_label_ids.contains(&label.label_id)
                || label.label_revision != 1
                || label.issued_at_ms != manifest.created_at_ms
                || label.issuer_owner_id != manifest.acting_owner_principal_id
            {
                return Err(invalid());
            }
            add_label_scope(
                &mut new_scopes,
                entry.source_policy_id,
                *source_revision,
                label,
                label.item_id,
                &inactive,
            )?;
        }
    }
    if used_label_sets
        != catalog
            .review_label_sets
            .iter()
            .map(|set| set.digest.clone())
            .collect()
    {
        return Err(invalid());
    }
    if !scopes_preserved(old_scopes, new_scopes) {
        return Err(invalid());
    }
    Ok(())
}

fn scopes_preserved(mut prior: PublicScopes, mut next: PublicScopes) -> bool {
    if prior.fields.keys().any(|key| next.fields.contains_key(key)) {
        return false;
    }
    prior.other.sort();
    next.other.sort();
    prior.other == next.other && prior.canonical_patterns() == next.canonical_patterns()
}

fn labels<'a>(
    catalog: &'a TransferPublicCatalogV1,
    digest: &Digest32,
) -> Result<&'a [OwnerReviewLabelV1], RolloverError> {
    if let Some(set) = catalog
        .review_label_sets
        .iter()
        .find(|set| &set.digest == digest)
    {
        return Ok(&set.labels);
    }
    if jury_protocol::witness_v1::owner_review_label_set_digest(&[]).map_err(|_| invalid())?
        == *digest
    {
        return Ok(&[]);
    }
    Err(invalid())
}

fn add_label_scope(
    scopes: &mut PublicScopes,
    policy_id: WitnessPolicyId,
    policy_revision: u64,
    label: &OwnerReviewLabelV1,
    item: Option<ItemId>,
    inactive: &BTreeSet<ItemId>,
) -> Result<(), RolloverError> {
    let token = serde_json::to_vec(&(
        "label",
        policy_id,
        policy_revision,
        label.subject_kind,
        label.public_label.as_bytes(),
        label.expires_at_ms,
        &label.subject_commitment,
    ))
    .map_err(|_| invalid())?;
    scopes.add_with_inactive(item, label.field_id, token, inactive)
}

#[cfg(test)]
mod tests {
    use super::*;
    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn scopes(entries: &[(u8, u8, &[u8])]) -> Result<PublicScopes, Box<dyn std::error::Error>> {
        let mut scopes = PublicScopes::default();
        for (item, field, usage) in entries {
            scopes.add(
                Some(ItemId::from_bytes([*item; 32])?),
                Some(FieldId::from_bytes([*field; 32])?),
                usage.to_vec(),
            )?;
        }
        Ok(scopes)
    }

    #[test]
    fn public_field_scopes_allow_renaming_but_reject_merged_authority() -> TestResult {
        let prior = [
            (1, 2, b"ExampleRuleA".as_slice()),
            (1, 3, b"ExampleRuleB".as_slice()),
        ];
        assert!(scopes_preserved(
            scopes(&prior)?,
            scopes(&[(1, 5, b"ExampleRuleB"), (1, 4, b"ExampleRuleA")])?
        ));
        // Folding both fields into one would let both rules authorize one
        // value even though each source value had only one authorization path.
        assert!(!scopes_preserved(
            scopes(&prior)?,
            scopes(&[(1, 4, b"ExampleRuleA"), (1, 4, b"ExampleRuleB")])?
        ));
        assert!(!scopes_preserved(
            scopes(&prior)?,
            scopes(&[(1, 2, b"ExampleRuleA"), (1, 5, b"ExampleRuleB")])?
        ));
        assert!(!scopes_preserved(
            scopes(&prior)?,
            scopes(&[(1, 4, b"ExampleRuleA"), (6, 5, b"ExampleRuleB")])?
        ));
        assert!(!scopes_preserved(
            scopes(&prior)?,
            scopes(&[(1, 4, b"ExampleRuleA")])?
        ));
        Ok(())
    }
}
