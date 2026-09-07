fn preflight_owner_change_labels(
    context: &VaultPrincipalContext,
    timestamp: u64,
) -> Result<(), CliError> {
    for policy in context.policy.active_witness_policies().map_err(|_| invalid_vault())? {
        let labels = context.catalog.review_label_sets.iter()
            .find(|set| set.digest == policy.review_label_set_digest)
            .ok_or_else(invalid_policy_catalog)?;
        for label in &labels.labels {
            require_owner_label_unexpired(label.expires_at_ms, timestamp)?;
        }
    }
    Ok(())
}

fn require_owner_label_unexpired(expiry: Option<u64>, timestamp: u64) -> Result<(), CliError> {
    if expiry.is_some_and(|expiry| expiry <= timestamp) {
        return Err(CliError::new(
            CliErrorKind::Conflict,
            "owner-change-label-expired",
            "an active public review label has expired; replace its policy and labels before changing owners",
        ));
    }
    Ok(())
}

fn prepare_owner_change_policies(
    context: &mut VaultPrincipalContext,
    timestamp: u64,
) -> Result<BTreeMap<Digest32, Digest32>, CliError> {
    use jury_core::witness_approval::{
        OwnerReviewLabelCreator, OwnerReviewLabelInput, ReviewLabelSubject,
    };
    use jury_protocol::witness_v1::PresentationSubjectV1;
    let active = context
        .policy
        .active_witness_policies()
        .map_err(|_| invalid_vault())?
        .into_iter()
        .cloned()
        .collect::<Vec<_>>();
    if active.is_empty() {
        return Ok(BTreeMap::new());
    }
    let sequence = context
        .policy
        .sequence()
        .checked_add(1)
        .ok_or_else(invalid_vault)?;
    let mut creator = OwnerReviewLabelCreator::new();
    let mut used_labels = context
        .catalog
        .review_label_sets
        .iter()
        .flat_map(|set| set.labels.iter().map(|label| label.label_id))
        .collect::<BTreeSet<_>>();
    let mut successors = BTreeMap::new();
    let mut successor_policies = Vec::with_capacity(active.len());
    for prior in active {
        let prior_digest = prior.digest().map_err(|_| invalid_policy_catalog())?;
        let labels = context
            .catalog
            .review_label_sets
            .iter()
            .find(|set| set.digest == prior.review_label_set_digest)
            .ok_or_else(invalid_policy_catalog)?
            .labels
            .clone();
        let mut replacements = Vec::with_capacity(labels.len());
        for label in labels {
            require_owner_label_unexpired(label.expires_at_ms, timestamp)?;
            let subject = match label.subject_kind {
                PresentationSubjectV1::Item => {
                    ReviewLabelSubject::Item(label.item_id.ok_or_else(invalid_policy_catalog)?)
                }
                PresentationSubjectV1::Field => ReviewLabelSubject::Field {
                    item_id: label.item_id.ok_or_else(invalid_policy_catalog)?,
                    field_id: label.field_id.ok_or_else(invalid_policy_catalog)?,
                },
                PresentationSubjectV1::WorkingDirectory => ReviewLabelSubject::WorkingDirectory(
                    label
                        .subject_commitment
                        .ok_or_else(invalid_policy_catalog)?,
                ),
                PresentationSubjectV1::OutputSink => ReviewLabelSubject::OutputSink(
                    label
                        .subject_commitment
                        .ok_or_else(invalid_policy_catalog)?,
                ),
            };
            let replacement = creator
                .create(
                    OwnerReviewLabelInput {
                        policy: &context.policy,
                        owner: &context.identity,
                        label_revision: 1,
                        subject,
                        public_label: label.public_label,
                        target_policy_sequence: sequence,
                        issued_at_ms: timestamp,
                        expires_at_ms: label.expires_at_ms,
                    },
                    |id| used_labels.contains(id),
                )
                .map_err(|_| invalid_policy_catalog())?;
            used_labels.insert(replacement.label_id);
            replacements.push(replacement);
        }
        let label_set =
            ReviewLabelSetV1::new(replacements).map_err(|_| invalid_policy_catalog())?;
        let mut next = prior;
        next.revision = next
            .revision
            .checked_add(1)
            .ok_or_else(invalid_policy_catalog)?;
        next.predecessor_policy_digest = prior_digest.clone();
        next.vault_policy_sequence = sequence;
        next.vault_policy_hash = context.policy.terminal_revision_hash().clone();
        next.review_label_set_digest = label_set.digest.clone();
        next.validate().map_err(|_| invalid_policy_catalog())?;
        let next_digest = next.digest().map_err(|_| invalid_policy_catalog())?;
        add_catalog_review_label_set(&mut context.catalog, label_set)?;
        successor_policies.push(next);
        successors.insert(prior_digest, next_digest);
    }
    add_catalog_witness_policies(&mut context.catalog, &context.policy, &successor_policies)?;
    context.policy = replay_policy_with_witness_policies(
        &context.vault.policy,
        &context.catalog.witness_policies,
    )
    .map_err(|_| invalid_policy_catalog())?;
    Ok(successors)
}
