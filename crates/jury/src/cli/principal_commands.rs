use super::*;

pub(super) fn principal_list(
    cli: &Cli,
    environment: &Environment,
    current: &Path,
) -> Result<CommandOutput, CliError> {
    let home = selected_home(cli, environment, current)?;
    let bytes = read_vault(&home)?;
    let vault = VaultFileV1::parse(&bytes).map_err(|_| invalid_vault())?;
    let catalog = load_policy_catalog_for_vault(environment, &home, &vault)?;
    let policy = replay_policy_with_witness_policies(&vault.policy, &catalog.witness_policies)
        .map_err(|_| invalid_vault())?;
    CheckpointCandidate::from_validated(&policy, &vault.policy, &vault.items)
        .map_err(|_| invalid_vault())?;
    let principals = policy
        .principals()
        .map(|(principal_id, principal)| {
            let fingerprint: [u8; 32] = Sha256::digest(
                principal
                    .descriptor
                    .fingerprint_preimage()
                    .map_err(|_| invalid_vault())?,
            )
            .into();
            Ok(serde_json::json!({
                "principal_id": hex(principal_id.as_bytes()),
                "fingerprint": hex(&fingerprint),
                "kind": principal_kind(principal.descriptor.principal_kind),
                "label": principal.display_label,
                "owner": policy.is_owner(principal_id),
                "effective_item_count": principal_effective_item_count(&policy, principal_id),
            }))
        })
        .collect::<Result<Vec<_>, CliError>>()?;
    Ok(CommandOutput::Safe {
        operation: "principal-list",
        fields: serde_json::json!({
            "vault_id": hex(vault.header.vault_id.as_bytes()),
            "count": principals.len(),
            "principals": principals,
            "item_names_disclosed": false,
        }),
        lines: vec![
            format!("Active principals: {}", policy.principal_count()),
            "Public metadata only; inaccessible item names are not displayed.".to_owned(),
        ],
    })
}

pub(super) fn principal_challenge(
    cli: &Cli,
    arguments: &PrincipalChallengeArgs,
    environment: &Environment,
    current: &Path,
    protection: ProtectionPolicy,
) -> Result<CommandOutput, CliError> {
    let descriptor = read_principal_descriptor(&arguments.from)?;
    let context = load_vault_principal(cli, environment, current, protection)?;
    if !context.policy.is_owner(&context.identity.principal_id()) {
        return Err(access_denied());
    }
    let witness_share_index = match (descriptor.principal_kind, arguments.witness_share_index) {
        (PrincipalKind::Witness, Some(index)) => Some(index),
        (PrincipalKind::Witness, None) => {
            return Err(CliError::new(
                CliErrorKind::InvalidArguments,
                "witness-share-index-required",
                "witness registration requires an explicit stable share index",
            ));
        }
        (_, Some(_)) => {
            return Err(CliError::new(
                CliErrorKind::InvalidArguments,
                "witness-share-index-not-applicable",
                "a witness share index applies only to witness identities",
            ));
        }
        (_, None) => None,
    };
    let mut creator = RegistrationCreator::new(protection);
    let challenge = creator
        .create_challenge(
            &context.policy,
            &context.identity,
            descriptor.clone(),
            timestamp_ms()?,
            REGISTRATION_CHALLENGE_LIFETIME_MS,
            witness_share_index,
        )
        .map_err(|error| map_registration_error(error.kind()))?;
    let bytes = challenge
        .to_json_bytes()
        .map_err(|error| map_registration_error(error.kind()))?;
    let publication = write_private_file(
        &context.home,
        &arguments.out,
        &bytes,
        arguments.overwrite,
        protection,
    )?;
    let fingerprint = principal_fingerprint(&descriptor)?;
    Ok(CommandOutput::Safe {
        operation: "principal-challenge",
        fields: serde_json::json!({
            "candidate_principal_id": hex(descriptor.principal_id.as_bytes()),
            "candidate_fingerprint": hex(&fingerprint),
            "candidate_kind": principal_kind(descriptor.principal_kind),
            "witness_share_index": witness_share_index,
            "challenge_digest": hex(challenge.digest().map_err(|error| map_registration_error(error.kind()))?.as_bytes()),
            "expires_at_ms": challenge.expires_at_ms,
            "sink": "hardened-private-file",
            "durability": durability(publication),
        }),
        lines: vec![
            format!("Candidate: {}", hex(descriptor.principal_id.as_bytes())),
            format!("Fingerprint: {}", grouped(&hex(&fingerprint))),
            format!("Expires at: {} ms", challenge.expires_at_ms),
        ],
    })
}

pub(super) fn principal_add(
    cli: &Cli,
    arguments: &PrincipalAddArgs,
    environment: &Environment,
    current: &Path,
    protection: ProtectionPolicy,
) -> Result<CommandOutput, CliError> {
    validate_initial_roles(&arguments.readers, &arguments.writers)?;
    if (!arguments.readers.is_empty() || !arguments.writers.is_empty())
        && !arguments.acknowledge_direct_access
    {
        return Err(direct_access_acknowledgement_required());
    }
    let descriptor = read_principal_descriptor(&arguments.from)?;
    let proof_bytes = read_public_file(&arguments.proof, MAX_REGISTRATION_FILE_BYTES)
        .map_err(map_filesystem_error)?;
    let proof = RegistrationProofV1::parse(&proof_bytes)
        .map_err(|error| map_registration_error(error.kind()))?;
    if proof.challenge.candidate_descriptor != descriptor {
        return Err(CliError::new(
            CliErrorKind::InvalidArguments,
            "registration-candidate-mismatch",
            "the registration proof does not match the selected public descriptor",
        ));
    }
    let mut context = load_vault_principal(cli, environment, current, protection)?;
    if !context.policy.is_owner(&context.identity.principal_id()) {
        return Err(access_denied());
    }
    let timestamp = timestamp_ms()?;
    let proof_digest = verify_proof(
        &context.policy,
        &context.identity,
        &proof.challenge,
        &proof,
        timestamp,
    )
    .map_err(|error| map_registration_error(error.kind()))?;
    let label = default_principal_label(&descriptor);
    if !matches!(
        proof.role_descriptor,
        RegistrationRoleDescriptorV1::VaultPrincipal
    ) {
        context
            .catalog
            .add_role_descriptor(&proof.role_descriptor)?;
    }
    if arguments.readers.is_empty() && arguments.writers.is_empty() {
        return finish_policy_mutation(
            context,
            vec![PolicyOperationV1::PrincipalAdd {
                descriptor: descriptor.clone(),
                display_label: label.clone(),
                registration_proof_digest: proof_digest.clone(),
            }],
            timestamp,
            "principal-add",
            arguments.dry_run,
            protection,
        );
    }
    if !matches!(
        descriptor.principal_kind,
        PrincipalKind::Human | PrincipalKind::Machine
    ) {
        return Err(CliError::new(
            CliErrorKind::InvalidArguments,
            "principal-kind-cannot-read-items",
            "approver and witness identities cannot receive vault-item roles",
        ));
    }

    let requested = arguments
        .readers
        .iter()
        .map(|item| (item.clone(), AccessRole::Reader))
        .chain(
            arguments
                .writers
                .iter()
                .map(|item| (item.clone(), AccessRole::Writer)),
        )
        .collect::<BTreeMap<_, _>>();
    let mut accessible = accessible_items_by_name(&context)?;
    if requested.keys().any(|item| !accessible.contains_key(item)) {
        return Err(item_unavailable());
    }
    let inventory = ItemArtifactInventory::from_vault(&context.vault)
        .map_err(|error| map_item_error(error.kind()))?;
    let registration = PrincipalRegistration {
        descriptor: descriptor.clone(),
        display_label: label,
        registration_proof_digest: proof_digest,
    };
    let mut creator = ItemCreator::new(protection);
    let mut prepared = Vec::with_capacity(requested.len());
    for (item, role) in requested {
        let accessible_item = accessible.remove(&item).ok_or_else(item_unavailable)?;
        let envelope = &context.vault.items[accessible_item.envelope_index];
        let state = open_item_body(&context, &accessible_item, Capability::Administer)?;
        let mut access = retained_access_plan(&context.policy, envelope)?;
        access.grants.push(ItemGrant {
            principal_id: descriptor.principal_id,
            role,
        });
        access.grants.sort_by_key(|grant| grant.principal_id);
        if !access.direct_recipient_ids.is_empty() {
            access.direct_recipient_ids.push(descriptor.principal_id);
            access.direct_recipient_ids.sort_unstable();
            access.direct_recipient_ids.dedup();
        }
        prepared.push(
            creator
                .prepare_rekey(
                    &context.policy,
                    &context.identity,
                    timestamp,
                    envelope,
                    RekeyedItem {
                        descriptor: accessible_item.descriptor,
                        state,
                        bucket_id: envelope.current_revision.bucket_id,
                        access,
                        principal_replacement: None,
                        principal_registration: Some(registration.clone()),
                        owner_change: None,
                    },
                    &inventory,
                )
                .map_err(|error| map_item_error(error.kind()))?,
        );
    }
    finish_item_batch_mutation(
        context,
        prepared,
        Vec::new(),
        MutationFinishOptions {
            operation: "principal-add",
            dry_run: arguments.dry_run,
            acknowledgement: DirectDowngradeAcknowledgement::Acknowledged,
            kind: MutationKind::Policy,
            protection,
        },
    )
}

pub(super) fn principal_label(
    cli: &Cli,
    arguments: &PrincipalLabelArgs,
    environment: &Environment,
    current: &Path,
    protection: ProtectionPolicy,
) -> Result<CommandOutput, CliError> {
    if arguments.label.is_empty() || arguments.label.len() > MAX_PUBLIC_LABEL_BYTES {
        return Err(CliError::new(
            CliErrorKind::InvalidArguments,
            "invalid-principal-label",
            "principal labels must be nonempty and within the public label bound",
        ));
    }
    let principal_id = parse_principal_id(&arguments.principal)?;
    let context = load_vault_principal(cli, environment, current, protection)?;
    if !context.policy.is_owner(&context.identity.principal_id()) {
        return Err(access_denied());
    }
    let prior_label = context
        .policy
        .principal(&principal_id)
        .ok_or_else(|| {
            CliError::new(
                CliErrorKind::NotFound,
                "principal-not-found",
                "the selected principal is not active",
            )
        })?
        .display_label
        .clone();
    let timestamp = timestamp_ms()?;
    finish_policy_mutation(
        context,
        vec![PolicyOperationV1::PrincipalLabelChange {
            principal_id,
            prior_label,
            next_label: arguments.label.clone(),
        }],
        timestamp,
        "principal-label",
        arguments.dry_run,
        protection,
    )
}

pub(super) fn principal_replace(
    cli: &Cli,
    arguments: &PrincipalReplaceArgs,
    environment: &Environment,
    current: &Path,
    protection: ProtectionPolicy,
) -> Result<CommandOutput, CliError> {
    let prior_principal_id = parse_principal_id(&arguments.principal)?;
    let descriptor = read_principal_descriptor(&arguments.from)?;
    let proof_bytes = read_public_file(&arguments.proof, MAX_REGISTRATION_FILE_BYTES)
        .map_err(map_filesystem_error)?;
    let proof = RegistrationProofV1::parse(&proof_bytes)
        .map_err(|error| map_registration_error(error.kind()))?;
    if proof.challenge.candidate_descriptor != descriptor {
        return Err(CliError::new(
            CliErrorKind::InvalidArguments,
            "registration-candidate-mismatch",
            "the registration proof does not match the selected public descriptor",
        ));
    }
    let mut context = load_vault_principal(cli, environment, current, protection)?;
    require_owner(&context)?;
    if prior_principal_id == context.identity.principal_id() {
        return Err(CliError::new(
            CliErrorKind::Conflict,
            "acting-principal-replacement-refused",
            "replace the acting principal with a different remaining owner identity",
        ));
    }
    let prior = grantable_principal(&context.policy, &prior_principal_id)?;
    if prior.descriptor.principal_kind != descriptor.principal_kind {
        return Err(CliError::new(
            CliErrorKind::InvalidArguments,
            "principal-kind-mismatch",
            "principal replacement requires the same identity role",
        ));
    }
    refuse_active_witness_role_rotation(&context, &prior_principal_id)?;
    let timestamp = timestamp_ms()?;
    let proof_digest = verify_proof(
        &context.policy,
        &context.identity,
        &proof.challenge,
        &proof,
        timestamp,
    )
    .map_err(|error| map_registration_error(error.kind()))?;
    if !matches!(
        proof.role_descriptor,
        RegistrationRoleDescriptorV1::VaultPrincipal
    ) {
        context
            .catalog
            .add_role_descriptor(&proof.role_descriptor)?;
    }
    let affected = context
        .policy
        .items()
        .filter_map(|(item_id, item)| {
            (context.policy.is_owner(&prior_principal_id)
                || item.grants.contains_key(&prior_principal_id))
            .then_some(*item_id)
        })
        .collect::<BTreeSet<_>>();
    let replacement = PrincipalReplacement {
        prior_principal_id,
        next_descriptor: descriptor.clone(),
        registration_proof_digest: proof_digest.clone(),
    };
    if affected.is_empty() {
        return finish_policy_mutation(
            context,
            vec![PolicyOperationV1::PrincipalReplace {
                prior_principal_id,
                next_descriptor: descriptor,
                registration_proof_digest: proof_digest,
            }],
            timestamp,
            "principal-replace",
            arguments.dry_run,
            protection,
        );
    }
    let accessible = all_admin_items(&context)?;
    let inventory = ItemArtifactInventory::from_vault(&context.vault)
        .map_err(|error| map_item_error(error.kind()))?;
    let mut creator = ItemCreator::new(protection);
    let mut prepared = Vec::with_capacity(affected.len());
    for accessible in accessible {
        let envelope = &context.vault.items[accessible.envelope_index];
        if !affected.contains(&envelope.item_id) {
            continue;
        }
        let state = open_item_body(&context, &accessible, Capability::Administer)?;
        let mut access = retained_access_plan(&context.policy, envelope)?;
        for grant in &mut access.grants {
            if grant.principal_id == prior_principal_id {
                grant.principal_id = descriptor.principal_id;
            }
        }
        for recipient in &mut access.direct_recipient_ids {
            if *recipient == prior_principal_id {
                *recipient = descriptor.principal_id;
            }
        }
        access.grants.sort_by_key(|grant| grant.principal_id);
        access.direct_recipient_ids.sort_unstable();
        prepared.push(
            creator
                .prepare_rekey_batch_component(
                    &context.policy,
                    &context.identity,
                    timestamp,
                    envelope,
                    RekeyedItem {
                        descriptor: accessible.descriptor,
                        state,
                        bucket_id: envelope.current_revision.bucket_id,
                        access,
                        principal_replacement: Some(replacement.clone()),
                        principal_registration: None,
                        owner_change: None,
                    },
                    &inventory,
                )
                .map_err(|error| map_item_error(error.kind()))?,
        );
    }
    finish_item_component_batch_mutation(
        context,
        prepared,
        Vec::new(),
        timestamp,
        MutationFinishOptions {
            operation: "principal-replace",
            dry_run: arguments.dry_run,
            acknowledgement: DirectDowngradeAcknowledgement::Absent,
            kind: MutationKind::Policy,
            protection,
        },
    )
}

pub(super) fn principal_remove(
    cli: &Cli,
    arguments: &PrincipalRemoveArgs,
    environment: &Environment,
    current: &Path,
    protection: ProtectionPolicy,
) -> Result<CommandOutput, CliError> {
    let principal_id = parse_principal_id(&arguments.principal)?;
    let context = load_vault_principal(cli, environment, current, protection)?;
    require_owner(&context)?;
    grantable_principal(&context.policy, &principal_id)?;
    if context.policy.is_owner(&principal_id) {
        return Err(CliError::new(
            CliErrorKind::Conflict,
            "owner-removal-refused",
            "revoke owner authority with a different owner before removing the principal",
        ));
    }
    refuse_active_witness_role_rotation(&context, &principal_id)?;
    let affected = context
        .policy
        .items()
        .filter_map(|(item_id, item)| item.grants.contains_key(&principal_id).then_some(*item_id))
        .collect::<BTreeSet<_>>();
    if !affected.is_empty() && !arguments.revoke_all {
        return Err(CliError::new(
            CliErrorKind::Conflict,
            "principal-still-has-access",
            "principal removal requires --revoke-all while item grants remain",
        ));
    }
    let remove = PolicyOperationV1::PrincipalRemove {
        principal_id,
        removal_reason: RemovalReason::Retirement,
    };
    let timestamp = timestamp_ms()?;
    if affected.is_empty() {
        return finish_policy_mutation(
            context,
            vec![remove],
            timestamp,
            "principal-remove",
            arguments.dry_run,
            protection,
        );
    }
    let accessible = all_admin_items(&context)?;
    let inventory = ItemArtifactInventory::from_vault(&context.vault)
        .map_err(|error| map_item_error(error.kind()))?;
    let mut creator = ItemCreator::new(protection);
    let mut prepared = Vec::with_capacity(affected.len());
    for accessible in accessible {
        let envelope = &context.vault.items[accessible.envelope_index];
        if !affected.contains(&envelope.item_id) {
            continue;
        }
        let state = open_item_body(&context, &accessible, Capability::Administer)?;
        let mut access = retained_access_plan(&context.policy, envelope)?;
        access
            .grants
            .retain(|grant| grant.principal_id != principal_id);
        access
            .direct_recipient_ids
            .retain(|recipient| *recipient != principal_id);
        prepared.push(
            creator
                .prepare_rekey(
                    &context.policy,
                    &context.identity,
                    timestamp,
                    envelope,
                    RekeyedItem {
                        descriptor: accessible.descriptor,
                        state,
                        bucket_id: envelope.current_revision.bucket_id,
                        access,
                        principal_replacement: None,
                        principal_registration: None,
                        owner_change: None,
                    },
                    &inventory,
                )
                .map_err(|error| map_item_error(error.kind()))?,
        );
    }
    finish_item_batch_mutation(
        context,
        prepared,
        vec![remove],
        MutationFinishOptions {
            operation: "principal-remove",
            dry_run: arguments.dry_run,
            acknowledgement: DirectDowngradeAcknowledgement::Absent,
            kind: MutationKind::Policy,
            protection,
        },
    )
}

fn refuse_active_witness_role_rotation(
    context: &VaultPrincipalContext,
    principal_id: &PrincipalId,
) -> Result<(), CliError> {
    let participates = context.policy.items().any(|(_, item)| {
        item.witnessed_state.as_ref().is_some_and(|state| {
            state.slots.iter().any(|slot| {
                context.catalog.witness_policies.iter().any(|policy| {
                    policy.digest().ok().as_ref() == Some(&slot.witness_policy_digest)
                        && (policy
                            .approver_descriptors
                            .iter()
                            .any(|descriptor| descriptor.approver_id == *principal_id)
                            || policy
                                .witness_descriptors
                                .iter()
                                .any(|descriptor| descriptor.witness_id == *principal_id))
                })
            })
        })
    });
    if participates {
        return Err(CliError::new(
            CliErrorKind::Conflict,
            "witnessed-role-rotation-required",
            "this principal participates in an active witnessed policy; rotate the witnessed policy and item slots before replacing or removing it",
        ));
    }
    Ok(())
}

pub(super) fn principal_owner_change(
    cli: &Cli,
    arguments: &PrincipalTargetArgs,
    grant: bool,
    environment: &Environment,
    current: &Path,
    protection: ProtectionPolicy,
) -> Result<CommandOutput, CliError> {
    let principal_id = parse_principal_id(&arguments.principal)?;
    let context = load_vault_principal(cli, environment, current, protection)?;
    require_owner(&context)?;
    let principal = grantable_principal(&context.policy, &principal_id)?;
    if grant
        && !arguments.acknowledge_direct_access
        && context.policy.items().any(|(_, item)| {
            !item.direct_slots.is_empty()
                && !item
                    .direct_slots
                    .iter()
                    .any(|slot| slot.recipient_principal_id == principal_id)
        })
    {
        return Err(direct_access_acknowledgement_required());
    }
    if principal.descriptor.principal_kind != PrincipalKind::Human {
        return Err(CliError::new(
            CliErrorKind::InvalidArguments,
            "human-owner-required",
            "only human vault principals may receive owner authority",
        ));
    }
    if grant == context.policy.is_owner(&principal_id) {
        return Err(CliError::new(
            CliErrorKind::Conflict,
            "no-change",
            "the requested mutation makes no change",
        ));
    }
    if !grant
        && (principal_id == context.identity.principal_id() || context.policy.owner_count() <= 1)
    {
        return Err(CliError::new(
            CliErrorKind::Conflict,
            "owner-revocation-refused",
            "self-revocation and last-owner revocation require a different remaining owner",
        ));
    }
    let timestamp = timestamp_ms()?;
    let operation = if grant {
        PolicyOperationV1::OwnerGrant { principal_id }
    } else {
        PolicyOperationV1::OwnerRevoke { principal_id }
    };
    if context.policy.item_count() == 0 {
        return finish_policy_mutation(
            context,
            vec![operation],
            timestamp,
            if grant {
                "principal-grant-owner"
            } else {
                "principal-revoke-owner"
            },
            arguments.dry_run,
            protection,
        );
    }
    let accessible = all_admin_items(&context)?;
    let inventory = ItemArtifactInventory::from_vault(&context.vault)
        .map_err(|error| map_item_error(error.kind()))?;
    let mut creator = ItemCreator::new(protection);
    let mut prepared = Vec::with_capacity(accessible.len());
    for accessible in accessible {
        let envelope = &context.vault.items[accessible.envelope_index];
        let state = open_item_body(&context, &accessible, Capability::Administer)?;
        let mut access = retained_access_plan(&context.policy, envelope)?;
        if grant {
            access
                .grants
                .retain(|entry| entry.principal_id != principal_id);
            if !access.direct_recipient_ids.is_empty() {
                access.direct_recipient_ids.push(principal_id);
                access.direct_recipient_ids.sort_unstable();
                access.direct_recipient_ids.dedup();
            }
        } else {
            access
                .direct_recipient_ids
                .retain(|recipient| *recipient != principal_id);
        }
        prepared.push(
            creator
                .prepare_rekey_batch_component(
                    &context.policy,
                    &context.identity,
                    timestamp,
                    envelope,
                    RekeyedItem {
                        descriptor: accessible.descriptor,
                        state,
                        bucket_id: envelope.current_revision.bucket_id,
                        access,
                        principal_replacement: None,
                        principal_registration: None,
                        owner_change: Some(if grant {
                            OwnerChange::Grant(principal_id)
                        } else {
                            OwnerChange::Revoke(principal_id)
                        }),
                    },
                    &inventory,
                )
                .map_err(|error| map_item_error(error.kind()))?,
        );
    }
    finish_item_component_batch_mutation(
        context,
        prepared,
        Vec::new(),
        timestamp,
        MutationFinishOptions {
            operation: if grant {
                "principal-grant-owner"
            } else {
                "principal-revoke-owner"
            },
            dry_run: arguments.dry_run,
            acknowledgement: if arguments.acknowledge_direct_access {
                DirectDowngradeAcknowledgement::Acknowledged
            } else {
                DirectDowngradeAcknowledgement::Absent
            },
            kind: MutationKind::Policy,
            protection,
        },
    )
}

pub(super) fn read_principal_descriptor(path: &Path) -> Result<PrincipalDescriptorV1, CliError> {
    let bytes =
        read_public_file(path, MAX_REGISTRATION_FILE_BYTES).map_err(map_filesystem_error)?;
    let descriptor: PrincipalDescriptorV1 =
        serde_json::from_slice(&bytes).map_err(|_| invalid_principal_descriptor())?;
    if serde_json::to_vec(&descriptor).ok().as_deref() != Some(bytes.as_slice()) {
        return Err(invalid_principal_descriptor());
    }
    Ok(descriptor)
}

pub(super) fn principal_fingerprint(
    descriptor: &PrincipalDescriptorV1,
) -> Result<[u8; 32], CliError> {
    Ok(Sha256::digest(
        descriptor
            .fingerprint_preimage()
            .map_err(|_| invalid_principal_descriptor())?,
    )
    .into())
}

pub(super) fn default_principal_label(descriptor: &PrincipalDescriptorV1) -> String {
    let principal_id = hex(descriptor.principal_id.as_bytes());
    format!(
        "{}-{}",
        principal_kind(descriptor.principal_kind),
        &principal_id[..12]
    )
}

pub(super) fn validate_initial_roles(
    readers: &[String],
    writers: &[String],
) -> Result<(), CliError> {
    let mut selections = readers
        .iter()
        .map(|item| (item, AccessRole::Reader))
        .chain(writers.iter().map(|item| (item, AccessRole::Writer)))
        .collect::<Vec<_>>();
    for (item, _) in &selections {
        ItemSelector::parse((*item).clone()).map_err(|_| invalid_item_selector())?;
    }
    selections.sort_by(|left, right| left.0.as_bytes().cmp(right.0.as_bytes()));
    if selections.windows(2).any(|pair| pair[0].0 == pair[1].0) {
        return Err(CliError::new(
            CliErrorKind::InvalidArguments,
            "duplicate-initial-role",
            "an initial item role is duplicated or contradictory",
        ));
    }
    Ok(())
}

pub(super) fn principal_effective_item_count(
    policy: &PolicyState,
    principal_id: &PrincipalId,
) -> usize {
    policy
        .items()
        .filter(|(item_id, _)| {
            policy
                .access(item_id, principal_id, Capability::Read)
                .allowed
        })
        .count()
}
