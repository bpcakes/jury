use super::*;

pub(super) fn mutation_output(
    operation: &'static str,
    item: Option<String>,
    context: &VaultPrincipalContext,
    plan: &VaultMutationPlan,
    dry_run: bool,
    outcome: Option<&MutationCommitOutcome>,
) -> CommandOutput {
    let local_recovery_required = matches!(
        outcome,
        Some(MutationCommitOutcome::CommittedLocalRecoveryRequired { .. })
    );
    CommandOutput::Mutation {
        operation,
        item,
        item_id: (plan.touched_items().len() == 1).then(|| hex(plan.touched_items()[0].as_bytes())),
        previous_revision: hex(context.policy.terminal_revision_hash().as_bytes()),
        current_revision: hex(plan.target_policy().terminal_revision_hash().as_bytes()),
        dry_run,
        committed: outcome.is_some(),
        local_recovery_required,
        redistribution_recommended: plan.warnings().redistribution_required,
        pending_requests_invalidated: plan.warnings().pending_witness_requests_invalidated,
        item_quorum_claim_suppressed: plan.warnings().item_quorum_claim_suppressed,
        warnings: if operation == "policy-require-witnessed" {
            vec![
                "distribute the exact public policy material and checkpoint; freshness exists only per verified witness acknowledgement",
            ]
        } else {
            Vec::new()
        },
    }
}

pub(super) fn selected_home(
    cli: &Cli,
    environment: &Environment,
    current: &Path,
) -> Result<VaultHomeLocation, CliError> {
    resolve_vault_home(
        current,
        cli.home.clone(),
        cli.global_home,
        environment.jury_home.as_deref(),
        environment.xdg_data_home.as_deref(),
        environment.user_home.as_deref(),
    )
    .map_err(|error| match error {
        crate::home::HomeSelectionError::Ambiguous
        | crate::home::HomeSelectionError::InvalidPath => CliError::new(
            CliErrorKind::InvalidArguments,
            "invalid-home-selection",
            "vault home selection is invalid",
        ),
        crate::home::HomeSelectionError::UnsupportedPlatform => CliError::new(
            CliErrorKind::UnsupportedPlatform,
            "unsupported-platform",
            "native vault homes currently support Linux only",
        ),
        crate::home::HomeSelectionError::MissingUserHome
        | crate::home::HomeSelectionError::Repository => filesystem_error(),
    })
}

pub(super) fn selected_identity(
    cli: &Cli,
    command_name: Option<&str>,
    environment: &Environment,
) -> Result<(IdentitySelector, String), CliError> {
    if command_name.is_some() && (cli.identity.is_some() || cli.identity_file.is_some()) {
        return Err(CliError::new(
            CliErrorKind::InvalidArguments,
            "ambiguous-identity-selection",
            "identity selection is ambiguous",
        ));
    }
    let (name, file) = if command_name.is_some() {
        (command_name, None)
    } else if cli.identity.is_some() || cli.identity_file.is_some() {
        (cli.identity.as_deref(), cli.identity_file.clone())
    } else {
        let name = environment
            .jury_identity
            .as_deref()
            .map(|value| {
                value.to_str().ok_or_else(|| {
                    CliError::new(
                        CliErrorKind::InvalidArguments,
                        "invalid-identity-selection",
                        "identity selection is invalid",
                    )
                })
            })
            .transpose()?;
        let file = environment.jury_identity_file.as_ref().map(PathBuf::from);
        (name, file)
    };
    let display = name.unwrap_or(if file.is_some() {
        "explicit-file"
    } else {
        "default"
    });
    let selector = IdentitySelector::select(name, file).map_err(|_| {
        CliError::new(
            CliErrorKind::InvalidArguments,
            "invalid-identity-selection",
            "identity selection is invalid",
        )
    })?;
    Ok((selector, display.to_owned()))
}

pub(super) fn identity_root(environment: &Environment) -> Result<PathBuf, CliError> {
    resolve_identity_root(
        environment.jury_identity_home.as_deref(),
        environment.xdg_data_home.as_deref(),
        environment.user_home.as_deref(),
    )
    .map_err(|_| filesystem_error())
}

pub(super) fn validate_explicit_identity_separation(
    selector: &IdentitySelector,
    home: &VaultHomeLocation,
) -> Result<(), CliError> {
    let IdentitySelector::ExplicitFile(path) = selector else {
        return Ok(());
    };
    let Some(vault) = home.detached_path() else {
        return Ok(());
    };
    let parent = path.parent().ok_or_else(filesystem_error)?;
    if overlaps(parent, vault) {
        Err(containment_error())
    } else {
        Ok(())
    }
}

pub(super) fn validate_detached_separation(
    identity_root: &Path,
    home: &VaultHomeLocation,
) -> Result<(), CliError> {
    if home
        .detached_path()
        .is_some_and(|vault| overlaps(identity_root, vault))
    {
        Err(containment_error())
    } else {
        Ok(())
    }
}

pub(super) fn overlaps(left: &Path, right: &Path) -> bool {
    left == right || left.starts_with(right) || right.starts_with(left)
}

pub(super) fn repository_refs(home: &VaultHomeLocation) -> Vec<&RepositoryLocation> {
    home.repository().into_iter().collect()
}

pub(super) fn detached_paths(home: &VaultHomeLocation) -> Vec<&Path> {
    home.detached_path().into_iter().collect()
}

pub(super) fn prepare_new_vault(
    home: &mut VaultHomeLocation,
    contents: &ProtectedMemory,
) -> Result<PreparedPrivateFile, CliError> {
    match home {
        VaultHomeLocation::Repository { repository } => {
            repository
                .create_jury_directory()
                .map_err(map_filesystem_error)?;
            repository
                .ensure_vault_attributes()
                .map_err(map_filesystem_error)?;
            PreparedPrivateFile::prepare_encrypted_shared_artifact(
                repository,
                contents,
                PublicationPolicy::CreateNew,
            )
            .map_err(map_filesystem_error)
        }
        VaultHomeLocation::Detached { path, .. } => {
            let root =
                HardenedStateRoot::open_or_create(path, &[]).map_err(map_filesystem_error)?;
            PreparedPrivateFile::prepare_state(
                &root,
                Path::new("vault.json"),
                contents,
                PublicationPolicy::CreateNew,
            )
            .map_err(map_filesystem_error)
        }
    }
}

pub(super) fn read_vault(home: &VaultHomeLocation) -> Result<Vec<u8>, CliError> {
    match home {
        VaultHomeLocation::Repository { repository } => repository
            .read_encrypted_shared_artifact(MAX_VAULT_BYTES)
            .map_err(map_filesystem_error),
        VaultHomeLocation::Detached { path, .. } => HardenedStateRoot::open_existing(path, &[])
            .and_then(|root| root.read_private_file(Path::new("vault.json"), MAX_VAULT_BYTES))
            .map_err(map_filesystem_error),
    }
}

pub(super) fn load_policy_catalog_for_vault(
    environment: &Environment,
    home: &VaultHomeLocation,
    vault: &VaultFileV1,
) -> Result<PolicyCatalogV1, CliError> {
    let state_root = resolve_linux_state_root(
        environment.jury_state_home.as_deref(),
        environment.xdg_state_home.as_deref(),
        environment.user_home.as_deref(),
    )
    .map_err(|_| filesystem_error())?;
    validate_detached_separation(&state_root, home)?;
    match VaultStateDirectory::open_existing(
        &state_root,
        vault.header.vault_id.as_bytes(),
        vault.header.genesis_fingerprint.as_bytes(),
        &repository_refs(home),
    ) {
        Ok(state) => read_policy_catalog(&state),
        Err(error) if error.kind() == FilesystemErrorKind::NotFound => Ok(PolicyCatalogV1::empty()),
        Err(error) => Err(map_filesystem_error(error)),
    }
}

pub(super) fn protect(bytes: &[u8], policy: ProtectionPolicy) -> Result<ProtectedMemory, CliError> {
    let initialize = |destination: &mut [u8]| {
        destination[..bytes.len()].copy_from_slice(bytes);
        Ok::<usize, ()>(bytes.len())
    };
    let capacity = bytes.len().max(1);
    let result = ProtectedMemory::initialize_supported(capacity, policy, initialize);
    result.map_err(|_| {
        CliError::new(
            CliErrorKind::ProtectionUnavailable,
            "protection-unavailable",
            "required protected memory is unavailable",
        )
    })
}

pub(super) fn timestamp_ms() -> Result<u64, CliError> {
    let milliseconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| local_state_error())?
        .as_millis();
    u64::try_from(milliseconds).map_err(|_| local_state_error())
}

pub(super) fn map_secret_error(error: secret_input::SecretInputError) -> CliError {
    use secret_input::SecretInputError;
    match error {
        SecretInputError::NonInteractiveRequiresOptIn => CliError::new(
            CliErrorKind::InvalidArguments,
            "passphrase-input-opt-in-required",
            "non-terminal passphrase input requires --passphrase-stdin",
        ),
        SecretInputError::ConfirmationMismatch => CliError::new(
            CliErrorKind::AuthenticationFailed,
            "passphrase-confirmation-mismatch",
            "passphrase confirmation differs",
        ),
        SecretInputError::InputTooLong => CliError::new(
            CliErrorKind::InvalidArguments,
            "passphrase-too-long",
            "passphrase input exceeds its byte bound",
        ),
        SecretInputError::InputUnavailable | SecretInputError::TerminalUnavailable => {
            CliError::new(
                CliErrorKind::ProtectionUnavailable,
                "passphrase-input-unavailable",
                "protected passphrase input is unavailable",
            )
        }
        SecretInputError::ProtectionUnavailable => CliError::new(
            CliErrorKind::ProtectionUnavailable,
            "protection-unavailable",
            "required protected memory is unavailable",
        ),
    }
}

pub(super) fn map_identity_error(kind: jury_core::identity::IdentityErrorKind) -> CliError {
    use jury_core::identity::IdentityErrorKind;
    match kind {
        IdentityErrorKind::AuthenticationFailed => CliError::new(
            CliErrorKind::AuthenticationFailed,
            "identity-authentication-failed",
            "identity authentication failed",
        ),
        IdentityErrorKind::InvalidPassphrase => CliError::new(
            CliErrorKind::InvalidArguments,
            "invalid-passphrase-profile",
            "passphrase does not meet the exact profile",
        ),
        IdentityErrorKind::ProtectionUnavailable | IdentityErrorKind::ResourceUnavailable => {
            CliError::new(
                CliErrorKind::ProtectionUnavailable,
                "protection-unavailable",
                "required protected memory is unavailable",
            )
        }
        IdentityErrorKind::KdfDowngrade => CliError::new(
            CliErrorKind::InvalidArguments,
            "kdf-downgrade-acknowledgement-required",
            "hardened-to-portable KDF downgrade requires explicit approval",
        ),
        _ => invalid_identity(),
    }
}

pub(super) fn map_item_error(kind: jury_core::item::ItemErrorKind) -> CliError {
    use jury_core::item::ItemErrorKind;
    match kind {
        ItemErrorKind::Unauthorized => access_denied(),
        ItemErrorKind::InvalidInput => CliError::new(
            CliErrorKind::InvalidArguments,
            "invalid-item-operation",
            "the item operation is invalid",
        ),
        ItemErrorKind::CapacityExhausted => CliError::new(
            CliErrorKind::Conflict,
            "capacity-exhausted",
            "the vault has reached a hard item capacity",
        ),
        ItemErrorKind::ProtectionUnavailable | ItemErrorKind::EntropyUnavailable => CliError::new(
            CliErrorKind::ProtectionUnavailable,
            "protection-unavailable",
            "required protected memory or entropy is unavailable",
        ),
        _ => invalid_vault(),
    }
}

pub(super) fn map_mutation_error(kind: jury_core::mutation::MutationErrorKind) -> CliError {
    use jury_core::mutation::MutationErrorKind;
    match kind {
        MutationErrorKind::Unauthorized => access_denied(),
        MutationErrorKind::DirectDowngradeRequiresAcknowledgement => CliError::new(
            CliErrorKind::InvalidArguments,
            "direct-access-acknowledgement-required",
            "this mutation requires explicit direct-access acknowledgement",
        ),
        MutationErrorKind::CapacityExhausted => CliError::new(
            CliErrorKind::Conflict,
            "capacity-exhausted",
            "the vault has reached a hard mutation capacity",
        ),
        MutationErrorKind::NoChange => CliError::new(
            CliErrorKind::Conflict,
            "no-change",
            "the requested mutation makes no change",
        ),
        MutationErrorKind::TransferBehind => CliError::new(
            CliErrorKind::Conflict,
            "transfer-behind",
            "the incoming transfer is behind retained local state",
        ),
        MutationErrorKind::TransferDiverged => CliError::new(
            CliErrorKind::Conflict,
            "transfer-diverged",
            "the incoming transfer diverges from retained local state",
        ),
        MutationErrorKind::TransferDowngrade => CliError::new(
            CliErrorKind::Conflict,
            "transfer-authority-downgrade",
            "the incoming transfer introduces unilateral direct access or weakens witnessed authority",
        ),
        _ => invalid_vault(),
    }
}

pub(super) fn map_registration_error(kind: RegistrationErrorKind) -> CliError {
    match kind {
        RegistrationErrorKind::Unauthorized => access_denied(),
        RegistrationErrorKind::WrongCandidate => CliError::new(
            CliErrorKind::InvalidArguments,
            "registration-candidate-mismatch",
            "the registration artifact targets a different identity",
        ),
        RegistrationErrorKind::Expired => CliError::new(
            CliErrorKind::Conflict,
            "registration-challenge-expired",
            "the registration challenge is expired or not yet valid",
        ),
        RegistrationErrorKind::EntropyUnavailable
        | RegistrationErrorKind::ProtectionUnavailable => CliError::new(
            CliErrorKind::ProtectionUnavailable,
            "protection-unavailable",
            "required protected memory or entropy is unavailable",
        ),
        RegistrationErrorKind::AuthenticationFailed => CliError::new(
            CliErrorKind::AuthenticationFailed,
            "registration-authentication-failed",
            "the registration artifact failed authentication",
        ),
        RegistrationErrorKind::InvalidArtifact | RegistrationErrorKind::InvalidDescriptor => {
            invalid_principal_descriptor()
        }
    }
}

pub(super) fn map_mutation_commit_error(
    kind: crate::mutation_commit::MutationCommitErrorKind,
) -> CliError {
    use crate::mutation_commit::MutationCommitErrorKind;
    match kind {
        MutationCommitErrorKind::Busy | MutationCommitErrorKind::StaleArtifact => CliError::new(
            CliErrorKind::Conflict,
            "mutation-conflict",
            "the vault changed or is busy; prepare the operation again",
        ),
        MutationCommitErrorKind::InvalidLocalState => local_state_error(),
        MutationCommitErrorKind::ProtectionUnavailable => CliError::new(
            CliErrorKind::ProtectionUnavailable,
            "protection-unavailable",
            "required protected memory is unavailable",
        ),
        _ => filesystem_error(),
    }
}

pub(super) fn parse_principal_id(value: &str) -> Result<PrincipalId, CliError> {
    let bytes = decode_hex_32(value).ok_or_else(|| {
        CliError::new(
            CliErrorKind::InvalidArguments,
            "invalid-principal-id",
            "principal IDs must be canonical lowercase hexadecimal",
        )
    })?;
    PrincipalId::from_bytes(bytes).map_err(|_| {
        CliError::new(
            CliErrorKind::InvalidArguments,
            "invalid-principal-id",
            "principal IDs must be canonical lowercase hexadecimal",
        )
    })
}

pub(super) fn decode_hex_32(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64 {
        return None;
    }
    let mut output = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = decode_hex_nibble(pair[0])?;
        let low = decode_hex_nibble(pair[1])?;
        output[index] = (high << 4) | low;
    }
    (output.iter().any(|byte| *byte != 0)).then_some(output)
}

pub(super) fn decode_presented_hex_32(value: &str) -> Option<[u8; 32]> {
    let mut normalized = String::with_capacity(64);
    for character in value.chars() {
        if character == '-' || character.is_ascii_whitespace() {
            continue;
        }
        if normalized.len() == 64 {
            return None;
        }
        normalized.push(character);
    }
    decode_hex_32(&normalized)
}

pub(super) const fn decode_hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

pub(super) fn map_filesystem_error(error: FilesystemError) -> CliError {
    match error.kind() {
        FilesystemErrorKind::NotFound => CliError::new(
            CliErrorKind::NotFound,
            "not-found",
            "the selected state does not exist",
        ),
        FilesystemErrorKind::AlreadyExists => CliError::new(
            CliErrorKind::Conflict,
            "already-exists",
            "the selected destination already exists",
        ),
        FilesystemErrorKind::Containment | FilesystemErrorKind::Alias => containment_error(),
        FilesystemErrorKind::IdentityChanged => CliError::new(
            CliErrorKind::Conflict,
            "state-changed",
            "the selected state changed during the operation",
        ),
        _ => filesystem_error(),
    }
}

pub(super) const fn invalid_identity() -> CliError {
    CliError::new(
        CliErrorKind::InvalidIdentity,
        "invalid-identity",
        "the selected identity is invalid",
    )
}

pub(super) const fn invalid_principal_descriptor() -> CliError {
    CliError::new(
        CliErrorKind::InvalidArguments,
        "invalid-principal-artifact",
        "the principal registration artifact is invalid",
    )
}

pub(super) const fn invalid_vault() -> CliError {
    CliError::new(
        CliErrorKind::InvalidVault,
        "invalid-vault",
        "the selected vault public state is invalid",
    )
}

pub(super) const fn invalid_policy_catalog() -> CliError {
    CliError::new(
        CliErrorKind::InvalidVault,
        "invalid-policy-catalog",
        "the local public witness-policy catalog is invalid or incomplete",
    )
}

pub(super) const fn invalid_policy_membership() -> CliError {
    CliError::new(
        CliErrorKind::InvalidArguments,
        "invalid-policy-membership",
        "the selected approver, witness, or direct member set is invalid",
    )
}

pub(super) const fn invalid_quorum() -> CliError {
    CliError::new(
        CliErrorKind::InvalidArguments,
        "impossible-quorum",
        "the selected quorum cannot be satisfied by distinct active members",
    )
}

pub(super) const fn invalid_policy_controls() -> CliError {
    CliError::new(
        CliErrorKind::InvalidArguments,
        "invalid-witness-policy-controls",
        "the witnessed operation, lifetime, or workload controls are invalid",
    )
}

pub(super) const fn filesystem_error() -> CliError {
    CliError::new(
        CliErrorKind::Filesystem,
        "filesystem-error",
        "the selected filesystem state is unavailable",
    )
}

pub(super) const fn containment_error() -> CliError {
    CliError::new(
        CliErrorKind::InvalidArguments,
        "private-state-overlap",
        "private identity or local state overlaps the selected vault home",
    )
}

pub(super) const fn local_state_error() -> CliError {
    CliError::new(
        CliErrorKind::LocalState,
        "local-state-error",
        "principal local state could not be initialized",
    )
}

pub(super) const fn checkpoint_conflict() -> CliError {
    CliError::new(
        CliErrorKind::Conflict,
        "checkpoint-conflict",
        "the selected vault does not equal the accepted local checkpoint",
    )
}

pub(super) const fn access_denied() -> CliError {
    CliError::new(
        CliErrorKind::AccessDenied,
        "access-denied",
        "the selected identity is not authorized for this operation",
    )
}

pub(super) const fn direct_access_acknowledgement_required() -> CliError {
    CliError::new(
        CliErrorKind::InvalidArguments,
        "direct-access-acknowledgement-required",
        "direct access is unilateral and requires explicit acknowledgement",
    )
}

pub(super) const fn invalid_item_selector() -> CliError {
    CliError::new(
        CliErrorKind::InvalidArguments,
        "invalid-item-selector",
        "the item selector is invalid",
    )
}

pub(super) const fn invalid_field_selector() -> CliError {
    CliError::new(
        CliErrorKind::InvalidArguments,
        "invalid-field-selector",
        "the item or field selector is invalid",
    )
}

pub(super) const fn item_unavailable() -> CliError {
    CliError::new(
        CliErrorKind::AccessDenied,
        "item-unavailable",
        "the requested item is unavailable to the selected identity",
    )
}

pub(super) const fn field_unavailable() -> CliError {
    CliError::new(
        CliErrorKind::NotFound,
        "field-unavailable",
        "the requested field is unavailable in the selected accessible item",
    )
}

pub(super) const fn invalid_template() -> CliError {
    CliError::new(
        CliErrorKind::InvalidArguments,
        "invalid-template",
        "the bounded injection template is invalid",
    )
}

pub(super) const fn principal_kind(kind: PrincipalKind) -> &'static str {
    match kind {
        PrincipalKind::Human => "human",
        PrincipalKind::Machine => "machine",
        PrincipalKind::Approver => "approver",
        PrincipalKind::Witness => "witness",
    }
}

pub(super) const fn kdf_profile(profile: KdfProfile) -> &'static str {
    match profile {
        KdfProfile::PortableV1 => "portable-v1",
        KdfProfile::HardenedV1 => "hardened-v1",
    }
}

pub(super) const fn field_kind(kind: ItemFieldKind) -> &'static str {
    match kind {
        ItemFieldKind::Text => "text",
        ItemFieldKind::Concealed => "concealed",
    }
}

pub(super) const fn access_role(role: AccessRole) -> &'static str {
    match role {
        AccessRole::Reader => "reader",
        AccessRole::Writer => "writer",
        AccessRole::Owner => "owner",
    }
}

pub(super) const fn access_role_argument(role: AccessRoleArg) -> AccessRole {
    match role {
        AccessRoleArg::Reader => AccessRole::Reader,
        AccessRoleArg::Writer => AccessRole::Writer,
    }
}

pub(super) const fn access_path(path: AccessPath) -> &'static str {
    match path {
        AccessPath::Direct => "direct",
        AccessPath::Witnessed => "witnessed",
        AccessPath::Mixed => "mixed",
        AccessPath::Unavailable => "unavailable",
    }
}

pub(super) const fn item_access_mode(mode: ItemAccessMode) -> &'static str {
    match mode {
        ItemAccessMode::DirectOnly => "direct-only",
        ItemAccessMode::WitnessedOnly => "witnessed-only",
        ItemAccessMode::Mixed => "mixed",
    }
}

pub(super) const fn required_capability(required: RequiredCapabilityArg) -> Capability {
    match required {
        RequiredCapabilityArg::Read => Capability::Read,
        RequiredCapabilityArg::Write => Capability::Write,
        RequiredCapabilityArg::Owner => Capability::Administer,
    }
}

pub(super) const fn capability_name(capability: Capability) -> &'static str {
    match capability {
        Capability::Read => "read",
        Capability::Write => "write",
        Capability::Administer => "owner",
    }
}

pub(super) const fn home_source(source: HomeSource) -> &'static str {
    match source {
        HomeSource::Explicit => "explicit",
        HomeSource::GlobalFlag => "global-flag",
        HomeSource::Environment => "environment",
        HomeSource::Repository => "repository",
        HomeSource::PlatformDefault => "platform-default",
    }
}

pub(super) const fn durability(outcome: PublicationOutcome) -> &'static str {
    match outcome {
        PublicationOutcome::PublishedAndSynced => "published-and-synced",
        PublicationOutcome::PublishedButParentUnsynced => "published-parent-unsynced",
        PublicationOutcome::PublishedButTemporaryCleanupFailed => {
            "published-temporary-cleanup-failed"
        }
    }
}

pub(super) fn hex(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(64);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

pub(super) fn grouped(fingerprint: &str) -> String {
    let mut grouped = String::with_capacity(fingerprint.len() + fingerprint.len() / 8);
    for (index, character) in fingerprint.chars().enumerate() {
        if index != 0 && index % 8 == 0 {
            grouped.push('-');
        }
        grouped.push(character);
    }
    grouped
}

#[cfg(test)]
mod tests {
    use super::decode_presented_hex_32;

    #[test]
    fn presented_fingerprint_accepts_display_grouping_and_whitespace() {
        let raw = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let grouped = "01234567-89abcdef-01234567-89abcdef\n 01234567-89abcdef-01234567-89abcdef";
        assert_eq!(
            decode_presented_hex_32(raw),
            decode_presented_hex_32(grouped)
        );
        assert!(decode_presented_hex_32("01234567_not_hex").is_none());
    }
}
