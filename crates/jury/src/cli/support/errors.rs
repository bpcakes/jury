use super::*;

pub(in crate::cli) fn map_secret_error(error: secret_input::SecretInputError) -> CliError {
    use secret_input::SecretInputError;
    match error {
        SecretInputError::NonInteractiveRequiresOptIn => CliError::new(
            CliErrorKind::InvalidArguments,
            "passphrase-input-opt-in-required",
            "supply every passphrase and confirmation on stdin in prompt order with --passphrase-stdin; this overrides all inherited passphrase variables",
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
        SecretInputError::InputExhausted => CliError::new(
            CliErrorKind::InvalidArguments,
            "passphrase-input-incomplete",
            "stdin ended before every required passphrase and confirmation was supplied; supply the complete sequence documented in docs/recovery.md",
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

pub(in crate::cli) fn map_identity_error(kind: jury_core::identity::IdentityErrorKind) -> CliError {
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

pub(in crate::cli) fn map_item_error(kind: jury_core::item::ItemErrorKind) -> CliError {
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

pub(in crate::cli) fn map_mutation_error(kind: jury_core::mutation::MutationErrorKind) -> CliError {
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

pub(in crate::cli) fn map_registration_error(kind: RegistrationErrorKind) -> CliError {
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

pub(in crate::cli) fn map_mutation_commit_error(
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

pub(in crate::cli) fn map_filesystem_error(error: FilesystemError) -> CliError {
    map_filesystem_error_kind(error.kind())
}

pub(super) fn map_filesystem_error_kind(kind: FilesystemErrorKind) -> CliError {
    match kind {
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
        FilesystemErrorKind::Permission => CliError::new(
            CliErrorKind::Filesystem,
            "unsafe-filesystem-permissions",
            "check current-user ownership and permissions: use mode 0600 for private files and 0700 for private directories; input files must not be group/world-writable",
        ),
        FilesystemErrorKind::LinkOrWrongType => CliError::new(
            CliErrorKind::Filesystem,
            "unsafe-filesystem-type",
            "use a regular file and real parent directories; symbolic links and special files are not accepted",
        ),
        FilesystemErrorKind::HardLinkOrSize | FilesystemErrorKind::Capacity => CliError::new(
            CliErrorKind::Filesystem,
            "filesystem-link-or-capacity-limit",
            "use a file with one hard link and keep its size within this operation's documented bound",
        ),
        FilesystemErrorKind::Nul | FilesystemErrorKind::Traversal => CliError::new(
            CliErrorKind::InvalidArguments,
            "invalid-filesystem-path",
            "use an absolute direct path without NUL bytes or parent traversal components",
        ),
        FilesystemErrorKind::Unsupported => CliError::new(
            CliErrorKind::UnsupportedPlatform,
            "filesystem-capability-unsupported",
            "the selected filesystem lacks a required atomic or durability capability",
        ),
        _ => filesystem_error(),
    }
}
