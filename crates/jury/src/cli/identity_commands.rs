use super::*;

pub(super) fn identity_init(
    cli: &Cli,
    arguments: &IdentityInitArgs,
    environment: &Environment,
    current: &Path,
    protection: ProtectionPolicy,
) -> Result<CommandOutput, CliError> {
    let home = selected_home(cli, environment, current)?;
    let (selector, display_name) = selected_identity(cli, arguments.name.as_deref(), environment)?;
    validate_explicit_identity_separation(&selector, &home)?;
    let identity_root = identity_root(environment)?;
    validate_detached_separation(&identity_root, &home)?;
    let repositories = repository_refs(&home);
    let exclusions = detached_paths(&home);
    let root =
        HardenedStateRoot::open_or_create_excluding(&identity_root, &repositories, &exclusions)
            .map_err(map_filesystem_error)?;

    let passphrase =
        secret_input::capture(protection, cli.passphrase_stdin, true).map_err(map_secret_error)?;
    let mut creator = IdentityCreator::new();
    let created = creator
        .create(
            arguments.kind.into(),
            arguments.kdf_profile.into(),
            timestamp_ms()?,
            passphrase.memory(),
            |_| false,
        )
        .map_err(|error| map_identity_error(error.kind()))?;
    let bytes = created
        .file
        .to_json_bytes()
        .map_err(|_| invalid_identity())?;
    let protected = protect(&bytes, protection)?;
    let publication = selector
        .prepare(
            &root,
            &repositories,
            &protected,
            PublicationPolicy::CreateNew,
        )
        .map_err(map_filesystem_error)?
        .publish()
        .map_err(map_filesystem_error)?;
    Ok(CommandOutput::IdentityCreated {
        identity: display_name,
        principal_id: hex(created.descriptor.principal_id.as_bytes()),
        fingerprint: hex(created.file.header.descriptor_fingerprint.as_bytes()),
        kind: principal_kind(created.file.header.principal_kind),
        kdf_profile: kdf_profile(created.file.header.kdf_profile),
        protection_degraded: passphrase.protection_degraded(),
        durability: durability(publication),
    })
}

pub(super) fn identity_status(
    cli: &Cli,
    arguments: &IdentityStatusArgs,
    environment: &Environment,
    current: &Path,
) -> Result<CommandOutput, CliError> {
    let home = selected_home(cli, environment, current)?;
    let (selector, display_name) = selected_identity(cli, arguments.name.as_deref(), environment)?;
    validate_explicit_identity_separation(&selector, &home)?;
    let identity_root = identity_root(environment)?;
    validate_detached_separation(&identity_root, &home)?;
    let repositories = repository_refs(&home);
    let root = HardenedStateRoot::open_existing(&identity_root, &repositories)
        .map_err(map_filesystem_error)?;
    let bytes = selector
        .read(&root, &repositories, MAX_IDENTITY_FILE_BYTES)
        .map_err(map_filesystem_error)?;
    let identity = IdentityFileV1::parse(&bytes).map_err(|_| invalid_identity())?;
    Ok(CommandOutput::IdentityStatus {
        identity: display_name,
        principal_id: hex(identity.header.principal_id.as_bytes()),
        fingerprint: hex(identity.header.descriptor_fingerprint.as_bytes()),
        kind: principal_kind(identity.header.principal_kind),
        kdf_profile: kdf_profile(identity.header.kdf_profile),
        memory_kib: identity.header.memory_kib,
        passes: identity.header.passes,
        lanes: identity.header.lanes,
        stronger_profile_available: identity.header.kdf_profile == KdfProfile::PortableV1,
    })
}

pub(super) fn identity_list(
    cli: &Cli,
    environment: &Environment,
    current: &Path,
) -> Result<CommandOutput, CliError> {
    let home = selected_home(cli, environment, current)?;
    let identity_root = identity_root(environment)?;
    validate_detached_separation(&identity_root, &home)?;
    let repositories = repository_refs(&home);
    let root = match HardenedStateRoot::open_existing(&identity_root, &repositories) {
        Ok(root) => root,
        Err(error) if error.kind() == FilesystemErrorKind::NotFound => {
            return Ok(CommandOutput::IdentityList {
                identities: Vec::new(),
            });
        }
        Err(error) => return Err(map_filesystem_error(error)),
    };
    let mut identities = Vec::new();
    for name in list_named_identities(&root).map_err(map_filesystem_error)? {
        let selector = IdentitySelector::select(Some(name.as_str()), None).map_err(|_| {
            CliError::new(
                CliErrorKind::InvalidIdentity,
                "invalid-identity",
                "a named identity is invalid",
            )
        })?;
        let bytes = selector
            .read(&root, &repositories, MAX_IDENTITY_FILE_BYTES)
            .map_err(map_filesystem_error)?;
        let identity = IdentityFileV1::parse(&bytes).map_err(|_| invalid_identity())?;
        identities.push(IdentitySummary {
            name: name.as_str().to_owned(),
            principal_id: hex(identity.header.principal_id.as_bytes()),
            fingerprint: hex(identity.header.descriptor_fingerprint.as_bytes()),
            kind: principal_kind(identity.header.principal_kind),
            kdf_profile: kdf_profile(identity.header.kdf_profile),
        });
    }
    Ok(CommandOutput::IdentityList { identities })
}

pub(super) fn identity_passphrase_change(
    cli: &Cli,
    arguments: &IdentityPassphraseChangeArgs,
    environment: &Environment,
    current: &Path,
    protection: ProtectionPolicy,
) -> Result<CommandOutput, CliError> {
    if arguments.allow_kdf_downgrade && arguments.kdf_profile != Some(KdfProfileArg::Portable) {
        return Err(CliError::new(
            CliErrorKind::InvalidArguments,
            "invalid-kdf-downgrade-selection",
            "KDF downgrade approval requires an explicit portable profile",
        ));
    }
    let home = selected_home(cli, environment, current)?;
    let (selector, display_name) = selected_identity(cli, None, environment)?;
    validate_explicit_identity_separation(&selector, &home)?;
    let identity_root = identity_root(environment)?;
    validate_detached_separation(&identity_root, &home)?;
    let repositories = repository_refs(&home);
    let root = HardenedStateRoot::open_existing(&identity_root, &repositories)
        .map_err(map_filesystem_error)?;
    let bytes = selector
        .read(&root, &repositories, MAX_IDENTITY_FILE_BYTES)
        .map_err(map_filesystem_error)?;
    let identity = IdentityFileV1::parse(&bytes).map_err(|_| invalid_identity())?;
    let resulting_profile = arguments
        .kdf_profile
        .map(KdfProfile::from)
        .unwrap_or(identity.header.kdf_profile);

    let old =
        secret_input::capture(protection, cli.passphrase_stdin, false).map_err(map_secret_error)?;
    let new =
        secret_input::capture(protection, cli.passphrase_stdin, true).map_err(map_secret_error)?;
    let replacement = IdentityCreator::new()
        .change_passphrase(
            &identity,
            old.memory(),
            new.memory(),
            resulting_profile,
            arguments.allow_kdf_downgrade,
        )
        .map_err(|error| map_identity_error(error.kind()))?;
    let replacement_bytes = replacement
        .to_json_bytes()
        .map_err(|_| invalid_identity())?;
    let protected = protect(&replacement_bytes, protection)?;
    let publication = selector
        .prepare(
            &root,
            &repositories,
            &protected,
            PublicationPolicy::ReplaceExisting,
        )
        .map_err(map_filesystem_error)?
        .publish()
        .map_err(map_filesystem_error)?;
    Ok(CommandOutput::IdentityPassphraseChanged {
        identity: display_name,
        principal_id: hex(replacement.header.principal_id.as_bytes()),
        fingerprint: hex(replacement.header.descriptor_fingerprint.as_bytes()),
        kdf_profile: kdf_profile(replacement.header.kdf_profile),
        protection_degraded: old.protection_degraded() || new.protection_degraded(),
        durability: durability(publication),
    })
}

pub(super) const MAX_REGISTRATION_FILE_BYTES: usize = 16 * 1024;
pub(super) const REGISTRATION_CHALLENGE_LIFETIME_MS: u64 = 15 * 60 * 1_000;

pub(super) struct UnlockedIdentityContext {
    home: VaultHomeLocation,
    identity: UnlockedIdentity,
    protection_degraded: bool,
}

pub(super) fn unlock_selected_identity(
    cli: &Cli,
    environment: &Environment,
    current: &Path,
    protection: ProtectionPolicy,
) -> Result<UnlockedIdentityContext, CliError> {
    let home = selected_home(cli, environment, current)?;
    let (selector, _) = selected_identity(cli, None, environment)?;
    validate_explicit_identity_separation(&selector, &home)?;
    let identity_root = identity_root(environment)?;
    validate_detached_separation(&identity_root, &home)?;
    let repositories = repository_refs(&home);
    let root = HardenedStateRoot::open_existing(&identity_root, &repositories)
        .map_err(map_filesystem_error)?;
    let bytes = selector
        .read(&root, &repositories, MAX_IDENTITY_FILE_BYTES)
        .map_err(map_filesystem_error)?;
    let file = IdentityFileV1::parse(&bytes).map_err(|_| invalid_identity())?;
    let passphrase =
        secret_input::capture(protection, cli.passphrase_stdin, false).map_err(map_secret_error)?;
    let protection_degraded = passphrase.protection_degraded();
    let identity =
        unlock(&file, passphrase.memory()).map_err(|error| map_identity_error(error.kind()))?;
    Ok(UnlockedIdentityContext {
        home,
        identity,
        protection_degraded,
    })
}

pub(super) fn identity_public(
    cli: &Cli,
    arguments: &IdentityPublicArgs,
    environment: &Environment,
    current: &Path,
    protection: ProtectionPolicy,
) -> Result<CommandOutput, CliError> {
    let unlocked = unlock_selected_identity(cli, environment, current, protection)?;
    let descriptor = unlocked
        .identity
        .public_descriptor()
        .map_err(|error| map_identity_error(error.kind()))?;
    let bytes = serde_json::to_vec(&descriptor).map_err(|_| invalid_identity())?;
    let publication = write_private_file(
        &unlocked.home,
        &arguments.out,
        &bytes,
        arguments.overwrite,
        protection,
    )?;
    let fingerprint: [u8; 32] = Sha256::digest(
        descriptor
            .fingerprint_preimage()
            .map_err(|_| invalid_identity())?,
    )
    .into();
    Ok(CommandOutput::Safe {
        operation: "identity-public",
        fields: serde_json::json!({
            "principal_id": hex(descriptor.principal_id.as_bytes()),
            "fingerprint": hex(&fingerprint),
            "kind": principal_kind(descriptor.principal_kind),
            "sink": "hardened-private-file",
            "durability": durability(publication),
            "protection_degraded": unlocked.protection_degraded,
            "label_verified": false,
        }),
        lines: vec![
            format!(
                "Public descriptor: {}",
                hex(descriptor.principal_id.as_bytes())
            ),
            format!("Fingerprint: {}", grouped(&hex(&fingerprint))),
            format!("Durability: {}", durability(publication)),
        ],
    })
}

pub(super) fn identity_prove(
    cli: &Cli,
    arguments: &IdentityProveArgs,
    environment: &Environment,
    current: &Path,
    protection: ProtectionPolicy,
) -> Result<CommandOutput, CliError> {
    let challenge_bytes = read_public_file(&arguments.challenge, MAX_REGISTRATION_FILE_BYTES)
        .map_err(map_filesystem_error)?;
    let challenge = RegistrationChallengeV1::parse(&challenge_bytes)
        .map_err(|error| map_registration_error(error.kind()))?;
    let unlocked = unlock_selected_identity(cli, environment, current, protection)?;
    let vault_bytes = read_vault(&unlocked.home)?;
    let vault = VaultFileV1::parse(&vault_bytes).map_err(|_| invalid_vault())?;
    let catalog = load_policy_catalog_for_vault(environment, &unlocked.home, &vault)?;
    let policy = replay_policy_with_witness_policies(&vault.policy, &catalog.witness_policies)
        .map_err(|_| invalid_vault())?;
    CheckpointCandidate::from_validated(&policy, &vault.policy, &vault.items)
        .map_err(|_| invalid_vault())?;
    let proof = answer_challenge(&policy, &unlocked.identity, &challenge, timestamp_ms()?)
        .map_err(|error| map_registration_error(error.kind()))?;
    let proof_bytes = proof
        .to_json_bytes()
        .map_err(|error| map_registration_error(error.kind()))?;
    let publication = write_private_file(
        &unlocked.home,
        &arguments.out,
        &proof_bytes,
        arguments.overwrite,
        protection,
    )?;
    Ok(CommandOutput::Safe {
        operation: "identity-prove",
        fields: serde_json::json!({
            "principal_id": hex(proof.candidate_principal_id.as_bytes()),
            "challenge_digest": hex(proof.challenge_digest.as_bytes()),
            "sink": "hardened-private-file",
            "durability": durability(publication),
            "recovered_response_disclosed": false,
            "protection_degraded": unlocked.protection_degraded,
        }),
        lines: vec![
            format!(
                "Registration proof: {}",
                hex(proof.candidate_principal_id.as_bytes())
            ),
            "Recovered response disclosed: false".to_owned(),
            format!("Durability: {}", durability(publication)),
        ],
    })
}
