use super::*;

impl RolloverSource<'_> {
    /// Prepare every active source item through administrative access and
    /// fix a fresh destination genesis. Existing role-policy settings remain
    /// signed source settings; fresh registration proofs separately establish
    /// possession for this new lineage. A field-scoped read approval does not
    /// authorize copying an entire item. No source mutation or publication occurs.
    pub fn prepare_governed(
        &self,
        catalog: &TransferPublicCatalogV1,
        owner: &VaultPrincipalIdentity,
        provider: &mut impl ItemAccessProvider,
        options: GovernedRolloverOptions,
        cancellation: &dyn CancellationCheck,
    ) -> Result<GovernedRolloverDraft, RolloverError> {
        let suite = jury_protocol::hpke_context::VaultSuite::from_id(self.policy.suite())
            .ok_or_else(invalid)?;
        self.prepare_governed_for_suite(suite, catalog, owner, provider, options, cancellation)
    }

    pub fn prepare_governed_migration(
        &self,
        suite: jury_protocol::hpke_context::VaultSuite,
        catalog: &TransferPublicCatalogV1,
        owner: &VaultPrincipalIdentity,
        provider: &mut impl ItemAccessProvider,
        options: GovernedRolloverOptions,
        cancellation: &dyn CancellationCheck,
    ) -> Result<GovernedRolloverDraft, RolloverError> {
        self.require_migration(suite)?;
        self.prepare_governed_for_suite(suite, catalog, owner, provider, options, cancellation)
    }

    fn prepare_governed_for_suite(
        &self,
        suite: jury_protocol::hpke_context::VaultSuite,
        catalog: &TransferPublicCatalogV1,
        owner: &VaultPrincipalIdentity,
        provider: &mut impl ItemAccessProvider,
        options: GovernedRolloverOptions,
        cancellation: &dyn CancellationCheck,
    ) -> Result<GovernedRolloverDraft, RolloverError> {
        let GovernedRolloverOptions {
            created_at_ms: timestamp_ms,
            registration_lifetime_ms: challenge_lifetime_ms,
            protection,
        } = options;
        roles::validate_source_catalog(self, catalog)?;
        if !self.policy.is_owner(&owner.principal_id())
            || self
                .policy
                .principal(&owner.principal_id())
                .map(|entry| &entry.descriptor)
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
        if roles::active_proofs(catalog, &self.policy).is_empty() {
            return Err(source_invalid());
        }
        let created = PolicyCreator::new()
            .create_for_suite(suite, owner, timestamp_ms, |id| {
                *id == self.vault.header.vault_id
            })
            .map_err(|_| failed())?;
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
        let mut templates = templates::initial_templates(self, &context)?;
        // Refuse before invoking the source access provider or spending approvals.
        templates::ensure_label_lifetime(
            catalog
                .review_label_sets
                .iter()
                .filter(|set| {
                    templates
                        .values()
                        .any(|template| template.source.review_label_set_digest == set.digest)
                })
                .flat_map(|set| &set.labels),
            timestamp_ms,
            challenge_lifetime_ms,
        )?;
        let public_targets =
            templates::public_targets(catalog, templates.values().map(|template| &template.source));
        context
            .historical_item_ids
            .extend(public_targets.iter().map(|(item, _)| *item));
        for template in templates.values() {
            context.witness_policies.insert(
                template.destination.digest().map_err(|_| failed())?,
                template.destination.clone(),
            );
        }
        let mut creator = ItemCreator::new(protection);
        let mut inventory = ItemArtifactInventory::from_vault(self.vault).map_err(|_| failed())?;
        let mut fields = BTreeMap::new();
        let mut entries = Vec::new();
        let mut staged_items = Vec::new();
        let mut source_envelopes = self.vault.items.iter().collect::<Vec<_>>();
        source_envelopes.sort_by_key(|envelope| envelope.item_id);
        for envelope in source_envelopes {
            if cancellation.is_cancelled() {
                return Err(failed());
            }
            let item = self
                .policy
                .item(&envelope.item_id)
                .ok_or_else(source_invalid)?;
            let mut plaintext = OpenedItem::default();
            plaintext.descriptor = Some(open_part(
                provider,
                &self.policy,
                envelope,
                owner,
                ContentRole::Descriptor,
                cancellation,
                |access| access.open_descriptor(),
            )?);
            plaintext.state = Some(open_part(
                provider,
                &self.policy,
                envelope,
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
            reserved_fields.extend(public_targets.iter().filter_map(|(item, field)| {
                (*item == envelope.item_id).then_some(*field).flatten()
            }));
            reserved_fields.sort_unstable();
            reserved_fields.dedup();
            let prior_fields = reserved_fields.clone();
            for field in &mut state.fields {
                let prior = field.field_id;
                field.field_id = creator
                    .generate_field_id(&reserved_fields)
                    .map_err(|_| failed())?;
                reserved_fields.push(field.field_id);
                fields.insert((envelope.item_id, prior), field.field_id);
            }
            // A public reference to a removed field stays inert. Give it a
            // distinct new scope ID without adding a plaintext field.
            for prior in prior_fields {
                if let std::collections::btree_map::Entry::Vacant(entry) =
                    fields.entry((envelope.item_id, prior))
                {
                    let next = creator
                        .generate_field_id(&reserved_fields)
                        .map_err(|_| failed())?;
                    reserved_fields.push(next);
                    entry.insert(next);
                }
            }
            let template = item
                .witnessed_state
                .as_ref()
                .map(|state| {
                    templates
                        .get(
                            &state
                                .slots
                                .first()
                                .ok_or_else(source_invalid)?
                                .witness_policy_digest,
                        )
                        .ok_or_else(source_invalid)
                })
                .transpose()?;
            let access = ItemAccessPlan {
                grants: item
                    .grants
                    .iter()
                    .map(|(principal_id, role)| ItemGrant {
                        principal_id: *principal_id,
                        role: *role,
                    })
                    .collect(),
                direct_recipient_ids: direct_recipients(&item.direct_slots),
                witness_policy_digest: template
                    .map(|template| template.destination.digest().map_err(|_| failed()))
                    .transpose()?,
            };
            let staged = creator
                .stage_create(
                    &context,
                    owner,
                    timestamp_ms,
                    NewItem {
                        kind: item.item_kind,
                        descriptor: plaintext.descriptor.take().ok_or_else(failed)?,
                        state: plaintext.state.take().ok_or_else(failed)?,
                        bucket_id: envelope.current_revision.bucket_id,
                        access: access.clone(),
                    },
                    &mut inventory,
                )
                .map_err(|_| failed())?;
            let witnessed = match (template, staged.witness_slot_ids()) {
                (Some(template), Some([descriptor_slot_id, body_slot_id])) => {
                    Some(BootstrapWitnessedItemV1 {
                        policy_id: template.destination.witness_policy_id,
                        descriptor_slot_id,
                        body_slot_id,
                    })
                }
                (None, None) => None,
                _ => return Err(failed()),
            };
            context
                .historical_item_ids
                .insert(staged.envelope().item_id);
            entries.push(BootstrapItemV1 {
                source_item_id: envelope.item_id,
                destination_item_id: staged.envelope().item_id,
                item_kind: item.item_kind,
                descriptor: staged.envelope().descriptor.clone(),
                initial_item_revision_hash: staged
                    .envelope()
                    .current_revision
                    .recomputed_hash()
                    .map_err(|_| failed())?,
                direct_slot_set_digest: direct_digest(staged.direct_slots())?,
                grants: grants(&self.policy, envelope.item_id)?,
                witnessed,
            });
            staged_items.push((staged, access));
        }
        templates::remap(
            self,
            catalog,
            &context,
            owner,
            templates::ScopeRemapping {
                entries: &entries,
                fields: &fields,
            },
            &mut templates,
            timestamp_ms,
        )?;
        let mut witness_entries = templates
            .values()
            .map(|template| {
                Ok(BootstrapWitnessPolicyV1 {
                    source_policy_id: template.source.witness_policy_id,
                    source_policy_revision: Some(template.source.revision),
                    destination_policy_id: template.destination.witness_policy_id,
                    intent_digest: super::super::witness_intent_digest(
                        &template.destination,
                        &template.labels,
                    )?,
                })
            })
            .collect::<Result<Vec<_>, RolloverError>>()?;
        witness_entries.sort_by_key(|entry| (entry.source_policy_id, entry.source_policy_revision));
        let manifest = BootstrapManifestV1 {
            version: 2,
            source_suite: Some(self.vault.header.suite),
            destination_suite: suite.id(),
            destination_vault_id: context.vault_id(),
            created_at_ms: timestamp_ms,
            acting_owner_principal_id: owner.principal_id(),
            principals: principals(&self.policy)?,
            items: entries,
            witness_policies: witness_entries,
        };
        let id = NativeIdGenerator::new()
            .generate_item_id(|_| false)
            .map_err(|_| failed())?;
        let mut statement = SignedRolloverV1 {
            rollover_format: 1,
            rollover_id: RolloverId::from_bytes(*id.as_bytes()).map_err(|_| failed())?,
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
        let mut journal = created.journal;
        journal.genesis.source_attestation = Some(SourceAttestationV1::Rollover {
            statement: Box::new(statement),
        });
        journal.genesis.owner_signature = owner
            .sign_validated_statement(&journal.genesis.signature_preimage().map_err(|_| failed())?)
            .map_err(|_| failed())?;
        self.verify_source_authorization(&journal.genesis)?;
        let initial = replay_policy(&journal).map_err(|_| failed())?;
        context.genesis_fingerprint = initial.genesis_fingerprint().clone();
        context.terminal_revision_hash = initial.genesis_fingerprint().clone();
        context.revision_hashes = initial.revision_hashes.clone();
        templates::bind_final_genesis(&mut templates, &initial, owner)?;
        context.witness_policies.clear();
        let mut policies = Vec::new();
        let mut labels = BTreeMap::new();
        let manifest = match &journal.genesis.source_attestation {
            Some(SourceAttestationV1::Rollover { statement }) => {
                statement.bootstrap_manifest.as_ref().ok_or_else(failed)?
            }
            _ => return Err(failed()),
        };
        for (entry, (_, access)) in manifest.items.iter().zip(&mut staged_items) {
            if let Some(witnessed) = &entry.witnessed {
                let template = templates
                    .values()
                    .find(|template| template.destination.witness_policy_id == witnessed.policy_id)
                    .ok_or_else(failed)?;
                access.witness_policy_digest =
                    Some(template.destination.digest().map_err(|_| failed())?);
            }
        }
        for template in templates.into_values() {
            let entry = manifest
                .witness_policies
                .iter()
                .find(|entry| entry.destination_policy_id == template.destination.witness_policy_id)
                .ok_or_else(failed)?;
            if super::super::witness_intent_digest(&template.destination, &template.labels)?
                != entry.intent_digest
            {
                return Err(failed());
            }
            context.witness_policies.insert(
                template.destination.digest().map_err(|_| failed())?,
                template.destination.clone(),
            );
            policies.push(template.destination);
            let set = ReviewLabelSetV1::new(template.labels).map_err(|_| failed())?;
            labels.insert(set.digest.clone(), set);
        }
        let (challenges, prior_roles) = roles::fresh_challenges(
            &initial,
            owner,
            catalog,
            &self.policy,
            timestamp_ms,
            challenge_lifetime_ms,
            protection,
        )?;
        if cancellation.is_cancelled() {
            return Err(failed());
        }
        Ok(GovernedRolloverDraft {
            protection,
            journal,
            context,
            creator,
            staged: staged_items,
            policies,
            labels: labels.into_values().collect(),
            challenges,
            prior_roles,
        })
    }
}
