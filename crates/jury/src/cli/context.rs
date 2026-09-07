mod catalog;
pub(super) use catalog::PolicyCatalogV1;

use super::*;

pub(super) fn discover_accessible_items(
    context: &VaultPrincipalContext,
) -> Result<Vec<AccessibleItem>, CliError> {
    discover_accessible_items_in(&context.vault, &context.policy, &context.identity)
}

pub(super) fn discover_accessible_items_in(
    vault: &VaultFileV1,
    policy: &PolicyState,
    identity: &VaultPrincipalIdentity,
) -> Result<Vec<AccessibleItem>, CliError> {
    let mut provider = DirectItemAccessProvider::new(identity);
    let mut items = Vec::new();
    for (envelope_index, envelope) in vault.items.iter().enumerate() {
        let target = match RevisionAccessTarget::current(
            policy,
            envelope,
            identity.principal_id(),
            ContentRole::Descriptor,
            Capability::Read,
        ) {
            Ok(target) => target,
            Err(error)
                if matches!(
                    error.kind(),
                    AccessProviderErrorKind::Unauthorized
                        | AccessProviderErrorKind::DirectSlotUnavailable
                ) =>
            {
                continue;
            }
            Err(_) => return Err(invalid_vault()),
        };
        let request = RevisionAccessRequest {
            policy,
            envelope,
            target,
            capability: Capability::Read,
            cancellation: &NeverCancelled,
        };
        match provider.access_revision(request, |access| access.open_descriptor()) {
            Ok(ItemAccessOutcome::Complete {
                value: descriptor, ..
            }) => items.push(AccessibleItem {
                envelope_index,
                descriptor,
            }),
            Ok(ItemAccessOutcome::Witnessed(_)) => {}
            Err(ItemAccessError::Provider(error))
                if matches!(
                    error.kind(),
                    AccessProviderErrorKind::Unauthorized
                        | AccessProviderErrorKind::DirectSlotUnavailable
                ) => {}
            Err(_) => return Err(invalid_vault()),
        }
    }
    let mut names = BTreeSet::new();
    if items
        .iter()
        .any(|item| !names.insert(item.descriptor.name().to_owned()))
    {
        return Err(invalid_vault());
    }
    Ok(items)
}

pub(super) fn accessible_items_by_name(
    context: &VaultPrincipalContext,
) -> Result<BTreeMap<String, AccessibleItem>, CliError> {
    Ok(discover_accessible_items(context)?
        .into_iter()
        .map(|item| (item.descriptor.name().to_owned(), item))
        .collect())
}

pub(super) fn all_admin_items(
    context: &VaultPrincipalContext,
) -> Result<Vec<AccessibleItem>, CliError> {
    let accessible = discover_accessible_items(context)?;
    if accessible.len() != context.policy.item_count() {
        Err(invalid_vault())
    } else {
        Ok(accessible)
    }
}

pub(super) fn selected_accessible_item(
    context: &VaultPrincipalContext,
    item: &str,
) -> Result<AccessibleItem, CliError> {
    ItemSelector::parse(item.to_owned()).map_err(|_| invalid_item_selector())?;
    accessible_items_by_name(context)?
        .remove(item)
        .ok_or_else(item_unavailable)
}

pub(super) fn open_item_body(
    context: &VaultPrincipalContext,
    accessible: &AccessibleItem,
    capability: Capability,
) -> Result<ItemStateV1, CliError> {
    let envelope = &context.vault.items[accessible.envelope_index];
    let target = RevisionAccessTarget::current(
        &context.policy,
        envelope,
        context.identity.principal_id(),
        ContentRole::Body,
        capability,
    )
    .map_err(|error| match error.kind() {
        AccessProviderErrorKind::Unauthorized | AccessProviderErrorKind::DirectSlotUnavailable => {
            access_denied()
        }
        _ => invalid_vault(),
    })?;
    let request = RevisionAccessRequest {
        policy: &context.policy,
        envelope,
        target,
        capability,
        cancellation: &NeverCancelled,
    };
    let mut provider = DirectItemAccessProvider::new(&context.identity);
    match provider.access_revision(request, |access| access.open_body()) {
        Ok(ItemAccessOutcome::Complete { value, .. }) => Ok(value),
        Ok(ItemAccessOutcome::Witnessed(_)) => Err(access_denied()),
        Err(ItemAccessError::Provider(error))
            if matches!(
                error.kind(),
                AccessProviderErrorKind::Unauthorized
                    | AccessProviderErrorKind::DirectSlotUnavailable
            ) =>
        {
            Err(access_denied())
        }
        Err(_) => Err(invalid_vault()),
    }
}

pub(super) enum PrincipalStateProbe {
    Existing {
        state: VaultStateDirectory,
        audit: Vec<u8>,
        checkpoint: Vec<u8>,
        receipts: Vec<u8>,
    },
    Absent,
}

pub(super) fn read_policy_catalog(
    state: &VaultStateDirectory,
) -> Result<PolicyCatalogV1, CliError> {
    match state.read_vault_state(VaultStateFile::PolicyCatalog) {
        Ok(bytes) => PolicyCatalogV1::parse_local(&bytes).map_err(|_| invalid_policy_catalog()),
        Err(error) if error.kind() == FilesystemErrorKind::NotFound => Ok(PolicyCatalogV1::empty()),
        Err(error) => Err(map_filesystem_error(error)),
    }
}

pub(super) fn probe_principal_state(
    state_root: &Path,
    vault: &VaultFileV1,
    principal_id: &PrincipalId,
    repositories: &[&RepositoryLocation],
) -> Result<PrincipalStateProbe, CliError> {
    let state = match VaultStateDirectory::open_existing(
        state_root,
        vault.header.vault_id.as_bytes(),
        vault.header.genesis_fingerprint.as_bytes(),
        repositories,
    ) {
        Ok(state) => state,
        Err(error) if error.kind() == FilesystemErrorKind::NotFound => {
            return Ok(PrincipalStateProbe::Absent);
        }
        Err(error) => return Err(map_filesystem_error(error)),
    };
    let audit = state.read_principal_state(principal_id.as_bytes(), PrincipalStateFile::Audit);
    let checkpoint =
        state.read_principal_state(principal_id.as_bytes(), PrincipalStateFile::Checkpoint);
    let receipts =
        state.read_principal_state(principal_id.as_bytes(), PrincipalStateFile::Receipts);
    let missing = [&audit, &checkpoint, &receipts]
        .iter()
        .filter(
            |result| matches!(result, Err(error) if error.kind() == FilesystemErrorKind::NotFound),
        )
        .count();
    if missing == 3 {
        return Ok(PrincipalStateProbe::Absent);
    }
    if missing != 0 {
        return Err(local_state_error());
    }
    Ok(PrincipalStateProbe::Existing {
        state,
        audit: audit.map_err(map_filesystem_error)?,
        checkpoint: checkpoint.map_err(map_filesystem_error)?,
        receipts: receipts.map_err(map_filesystem_error)?,
    })
}

pub(super) struct PrincipalStateInitialization<'a> {
    pub(super) state_root: &'a Path,
    pub(super) home: &'a VaultHomeLocation,
    pub(super) vault: &'a VaultFileV1,
    pub(super) local: &'a PrincipalLocalState,
    pub(super) candidate: &'a CheckpointCandidate,
    pub(super) principal_id: &'a PrincipalId,
    pub(super) timestamp: u64,
    pub(super) protection: ProtectionPolicy,
}

pub(super) fn initialize_principal_state(
    initialization: PrincipalStateInitialization<'_>,
) -> Result<VaultStateDirectory, CliError> {
    let PrincipalStateInitialization {
        state_root,
        home,
        vault,
        local,
        candidate,
        principal_id,
        timestamp,
        protection,
    } = initialization;
    let repositories = repository_refs(home);
    let exclusions = detached_paths(home);
    let state = VaultStateDirectory::open_or_create(
        state_root,
        vault.header.vault_id.as_bytes(),
        vault.header.genesis_fingerprint.as_bytes(),
        &repositories,
        &exclusions,
    )
    .map_err(map_filesystem_error)?;
    let initialized = local
        .initialize(candidate, timestamp)
        .map_err(|_| local_state_error())?;
    let files = local
        .serialize(&initialized)
        .map_err(|_| local_state_error())?;
    let audit = protect(files.audit(), protection)?;
    let checkpoint = protect(files.checkpoint(), protection)?;
    let receipts = protect(files.receipts(), protection)?;
    let locked = state.try_lock().map_err(|_| local_state_error())?;
    let prepared = [
        locked
            .prepare(principal_id.as_bytes(), PrincipalStateFile::Audit, &audit)
            .map_err(map_filesystem_error)?,
        locked
            .prepare(
                principal_id.as_bytes(),
                PrincipalStateFile::Checkpoint,
                &checkpoint,
            )
            .map_err(map_filesystem_error)?,
        locked
            .prepare(
                principal_id.as_bytes(),
                PrincipalStateFile::Receipts,
                &receipts,
            )
            .map_err(map_filesystem_error)?,
    ];
    for file in prepared {
        if file.publish().map_err(map_filesystem_error)? != PublicationOutcome::PublishedAndSynced {
            return Err(local_state_error());
        }
    }
    drop(locked);
    Ok(state)
}

pub(super) fn advance_principal_checkpoint(
    state: &VaultStateDirectory,
    local: &PrincipalLocalState,
    candidate: &CheckpointCandidate,
    principal_id: &PrincipalId,
    timestamp: u64,
    protection: ProtectionPolicy,
) -> Result<(), CliError> {
    let locked = state.try_lock().map_err(|_| local_state_error())?;
    let audit = locked
        .read(principal_id.as_bytes(), PrincipalStateFile::Audit)
        .map_err(map_filesystem_error)?;
    let checkpoint = locked
        .read(principal_id.as_bytes(), PrincipalStateFile::Checkpoint)
        .map_err(map_filesystem_error)?;
    let receipts = locked
        .read(principal_id.as_bytes(), PrincipalStateFile::Receipts)
        .map_err(map_filesystem_error)?;
    let mut verified = local
        .verify_files(Some(&audit), Some(&checkpoint), Some(&receipts))
        .map_err(|_| local_state_error())?;
    let had_audit_tail = verified.audit_events_after_checkpoint() != 0;
    if had_audit_tail {
        local
            .accept_audit_tail(&mut verified, timestamp)
            .map_err(|_| local_state_error())?;
    }
    let relation = local
        .accept_candidate(&mut verified, candidate, timestamp)
        .map_err(|_| checkpoint_conflict())?;
    if relation == CheckpointRelation::Equal && !had_audit_tail {
        return Ok(());
    }
    let files = local
        .serialize(&verified)
        .map_err(|_| local_state_error())?;
    let checkpoint = protect(files.checkpoint(), protection)?;
    let prepared = locked
        .prepare(
            principal_id.as_bytes(),
            PrincipalStateFile::Checkpoint,
            &checkpoint,
        )
        .map_err(map_filesystem_error)?;
    if prepared.publish().map_err(map_filesystem_error)? != PublicationOutcome::PublishedAndSynced {
        return Err(local_state_error());
    }
    Ok(())
}

pub(super) fn load_vault_principal(
    cli: &Cli,
    environment: &Environment,
    current: &Path,
    protection: ProtectionPolicy,
) -> Result<VaultPrincipalContext, CliError> {
    load_vault_principal_with_passphrase(cli, environment, current, protection)
        .map(|(context, _passphrase)| context)
}

pub(super) fn load_vault_principal_with_passphrase(
    cli: &Cli,
    environment: &Environment,
    current: &Path,
    protection: ProtectionPolicy,
) -> Result<(VaultPrincipalContext, secret_input::CapturedPassphrase), CliError> {
    let (context, passphrase) = load_principal_context_with_passphrase(
        cli,
        environment,
        current,
        protection,
        PrincipalRegistration::VaultPrincipal,
    )?;
    let UnlockedIdentity::VaultPrincipal(identity) = context.identity else {
        return Err(vault_principal_required());
    };
    Ok((
        PrincipalContext {
            home: context.home,
            vault: context.vault,
            policy: context.policy,
            catalog_before: context.catalog_before,
            catalog_before_bytes: context.catalog_before_bytes,
            catalog: context.catalog,
            identity,
            state: context.state,
            local: context.local,
            protection_degraded: context.protection_degraded,
        },
        passphrase,
    ))
}

enum PrincipalRegistration<'a> {
    VaultPrincipal,
    Transfer(&'a ValidatedTransfer),
}

pub(super) fn load_transfer_principal(
    cli: &Cli,
    environment: &Environment,
    current: &Path,
    protection: ProtectionPolicy,
    transfer: &ValidatedTransfer,
) -> Result<PrincipalContext<UnlockedIdentity>, CliError> {
    load_principal_context_with_passphrase(
        cli,
        environment,
        current,
        protection,
        PrincipalRegistration::Transfer(transfer),
    )
    .map(|(context, _passphrase)| context)
}

pub(super) fn principal_local_state(
    identity: &UnlockedIdentity,
    vault: &VaultFileV1,
) -> Result<PrincipalLocalState, CliError> {
    let vault_id = vault.header.vault_id;
    let genesis = vault.header.genesis_fingerprint.clone();
    match identity {
        UnlockedIdentity::VaultPrincipal(identity) => {
            PrincipalLocalState::for_vault_principal(identity, vault_id, genesis)
        }
        UnlockedIdentity::Approver(identity) => {
            PrincipalLocalState::for_approver(identity, vault_id, genesis)
        }
        UnlockedIdentity::Witness(identity) => {
            PrincipalLocalState::for_witness(identity, vault_id, genesis)
        }
    }
    .map_err(|_| local_state_error())
}

const fn vault_principal_required() -> CliError {
    CliError::new(
        CliErrorKind::InvalidIdentity,
        "vault-principal-required",
        "the selected command requires a vault-principal identity",
    )
}

fn load_principal_context_with_passphrase(
    cli: &Cli,
    environment: &Environment,
    current: &Path,
    protection: ProtectionPolicy,
    registration: PrincipalRegistration<'_>,
) -> Result<
    (
        PrincipalContext<UnlockedIdentity>,
        secret_input::CapturedPassphrase,
    ),
    CliError,
> {
    let home = selected_home(cli, environment, current)?;
    let bytes = read_vault(&home)?;
    let vault = VaultFileV1::parse(&bytes).map_err(|_| invalid_vault())?;
    let state_root = resolve_linux_state_root(
        environment.jury_state_home.as_deref(),
        environment.xdg_state_home.as_deref(),
        environment.user_home.as_deref(),
    )
    .map_err(|_| filesystem_error())?;
    validate_detached_separation(&state_root, &home)?;
    let early_repositories = repository_refs(&home);
    let (catalog, catalog_before_bytes) = match VaultStateDirectory::open_existing(
        &state_root,
        vault.header.vault_id.as_bytes(),
        vault.header.genesis_fingerprint.as_bytes(),
        &early_repositories,
    ) {
        Ok(state) => match state.read_vault_state(VaultStateFile::PolicyCatalog) {
            Ok(bytes) => (
                PolicyCatalogV1::parse_local(&bytes).map_err(|_| invalid_policy_catalog())?,
                Some(bytes),
            ),
            Err(error) if error.kind() == FilesystemErrorKind::NotFound => {
                (PolicyCatalogV1::empty(), None)
            }
            Err(error) => return Err(map_filesystem_error(error)),
        },
        Err(error) if error.kind() == FilesystemErrorKind::NotFound => {
            (PolicyCatalogV1::empty(), None)
        }
        Err(error) => return Err(map_filesystem_error(error)),
    };
    let policy = replay_policy_with_witness_policies(&vault.policy, &catalog.witness_policies)
        .map_err(|_| invalid_vault())?;
    let candidate = CheckpointCandidate::from_validated(&policy, &vault.policy, &vault.items)
        .map_err(|_| invalid_vault())?;

    let (selector, _) = selected_identity(cli, None, environment)?;
    validate_explicit_identity_separation(&selector, &home)?;
    let identity_root = identity_root(environment)?;
    validate_detached_separation(&identity_root, &home)?;
    let repositories = repository_refs(&home);
    let root = HardenedStateRoot::open_existing(&identity_root, &repositories)
        .map_err(map_filesystem_error)?;
    let identity_bytes = selector
        .read(&root, &repositories, MAX_IDENTITY_FILE_BYTES)
        .map_err(map_filesystem_error)?;
    let identity_file = IdentityFileV1::parse(&identity_bytes).map_err(|_| invalid_identity())?;
    if let Some(expected) = &cli.expected_genesis
        && decode_presented_hex_32(expected).as_ref()
            != Some(vault.header.genesis_fingerprint.as_bytes())
    {
        return Err(CliError::new(
            CliErrorKind::Conflict,
            "genesis-fingerprint-mismatch",
            "the externally expected genesis differs from the selected vault",
        ));
    }
    let probe = probe_principal_state(
        &state_root,
        &vault,
        &identity_file.header.principal_id,
        &repositories,
    )?;
    if matches!(&probe, PrincipalStateProbe::Absent) {
        confirm_expected_genesis(cli, &vault)?;
    }
    let passphrase = secret_input::capture_named_or_environment(
        protection,
        cli.passphrase_stdin,
        false,
        "Identity passphrase",
        environment.identity_passphrase(),
    )
    .map_err(map_secret_error)?;
    let protection_degraded = passphrase.protection_degraded();
    let identity = unlock(&identity_file, passphrase.memory())
        .map_err(|error| map_identity_error(error.kind()))?;
    if matches!(registration, PrincipalRegistration::VaultPrincipal)
        && !matches!(&identity, UnlockedIdentity::VaultPrincipal(_))
    {
        return Err(vault_principal_required());
    }
    let descriptor = identity
        .public_descriptor()
        .map_err(|_| invalid_identity())?;
    // A signed descendant can introduce this role. Retained local state and
    // ancestry are still checked against the current vault before publication.
    let registration_policy = match registration {
        PrincipalRegistration::VaultPrincipal => &policy,
        PrincipalRegistration::Transfer(transfer) => transfer.policy(),
    };
    if registration_policy
        .principal(&descriptor.principal_id)
        .is_none_or(|principal| principal.descriptor != descriptor)
    {
        return Err(CliError::new(
            CliErrorKind::AuthenticationFailed,
            "identity-not-registered",
            "the selected identity is not active in this vault",
        ));
    }
    let candidate = match registration {
        PrincipalRegistration::Transfer(transfer)
            if policy.principal(&descriptor.principal_id).is_none() =>
        {
            // This principal's history begins at its signed registration, not
            // at an older snapshot in which it did not exist. A retry retains
            // this authenticated target checkpoint until exact publication.
            CheckpointCandidate::from_validated(
                transfer.policy(),
                &transfer.vault().policy,
                &transfer.vault().items,
            )
            .map_err(|_| invalid_vault())?
        }
        _ => candidate,
    };
    let local = principal_local_state(&identity, &vault)?;
    let principal_id = descriptor.principal_id;
    let (state, verified) = match probe {
        PrincipalStateProbe::Existing {
            state,
            audit,
            checkpoint,
            receipts,
        } => {
            let verified = local
                .verify_files(Some(&audit), Some(&checkpoint), Some(&receipts))
                .map_err(|_| local_state_error())?;
            (state, verified)
        }
        PrincipalStateProbe::Absent => {
            let state = initialize_principal_state(PrincipalStateInitialization {
                state_root: &state_root,
                home: &home,
                vault: &vault,
                local: &local,
                candidate: &candidate,
                principal_id: &principal_id,
                timestamp: timestamp_ms()?,
                protection,
            })?;
            let verified = local
                .initialize(&candidate, timestamp_ms()?)
                .map_err(|_| local_state_error())?;
            (state, verified)
        }
    };
    let relation = candidate
        .relation_to(verified.checkpoint())
        .map_err(|_| checkpoint_conflict())?;
    match relation {
        CheckpointRelation::Equal if verified.audit_events_after_checkpoint() == 0 => {}
        CheckpointRelation::Equal | CheckpointRelation::StrictDescendant => {
            advance_principal_checkpoint(
                &state,
                &local,
                &candidate,
                &principal_id,
                timestamp_ms()?,
                protection,
            )?
        }
        CheckpointRelation::Divergent => return Err(checkpoint_conflict()),
    }
    Ok((
        PrincipalContext {
            home,
            vault,
            policy,
            catalog_before: catalog.clone(),
            catalog_before_bytes,
            catalog,
            identity,
            state,
            local,
            protection_degraded,
        },
        passphrase,
    ))
}

include!("context/catalog_mutation.rs");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn witness_catalog_batch_failure_is_atomic_and_readding_is_a_noop()
    -> Result<(), Box<dyn std::error::Error>> {
        let material: jury_core::witness_receipt::ReceiptPolicyMaterialV1 = serde_json::from_slice(
            include_bytes!("../../tests/fixtures/witness-policy-status/policy.json"),
        )?;
        let policy = material.replay()?;
        let existing = material
            .witness_policies
            .first()
            .ok_or("missing policy")?
            .clone();
        let mut staged = existing.clone();
        staged.revision += 1;
        staged.predecessor_policy_digest = existing.digest()?;
        staged.vault_policy_sequence += 1;
        let mut catalog = PolicyCatalogV1::empty();
        catalog.witness_policies = vec![existing.clone(), staged.clone()];
        let before = catalog.clone();
        add_catalog_witness_policy(&mut catalog, &policy, &existing)?;
        assert_eq!(catalog, before, "an exact retry pruned a staged successor");
        let mut invalid = staged.clone();
        invalid.revision = 0;
        catalog.witness_policies = vec![existing];
        let before = catalog.clone();
        assert!(add_catalog_witness_policies(&mut catalog, &policy, &[staged, invalid]).is_err());
        assert_eq!(
            catalog, before,
            "a failed batch retained its first addition"
        );
        Ok(())
    }

    #[test]
    fn local_catalog_requires_explicit_collections() -> Result<(), CliError> {
        let bytes = br#"{"version":1,"role_descriptors":[],"registration_proofs":[],"witness_policies":[],"review_label_sets":[]}"#;
        let catalog = PolicyCatalogV1::parse_local(bytes)?;
        assert_eq!(policy_catalog_json_bytes(&catalog)?, bytes);
        for field in ["registration_proofs", "review_label_sets"] {
            let mut old: serde_json::Value =
                serde_json::from_slice(bytes).map_err(|_| invalid_policy_catalog())?;
            old.as_object_mut()
                .ok_or_else(invalid_policy_catalog)?
                .remove(field);
            let old = serde_json::to_vec(&old).map_err(|_| invalid_policy_catalog())?;
            assert!(serde_json::from_slice::<PolicyCatalogV1>(&old).is_err());
            assert!(PolicyCatalogV1::parse_local(&old).is_err());
        }
        Ok(())
    }

    #[test]
    fn local_catalog_parser_rejects_malformed_noncanonical_and_unknown_input() {
        for bytes in [
            b"{".as_slice(),
            br#" {"version":1,"role_descriptors":[],"registration_proofs":[],"witness_policies":[],"review_label_sets":[]}"#,
            br#"{"version":1,"role_descriptors":[],"registration_proofs":[],"witness_policies":[],"review_label_sets":[],"unknown":true}"#,
            br#"{"version":2,"role_descriptors":[],"registration_proofs":[],"witness_policies":[],"review_label_sets":[]}"#,
        ] {
            assert!(PolicyCatalogV1::parse_local(bytes).is_err());
        }
    }
}
