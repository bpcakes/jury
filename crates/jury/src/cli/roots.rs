//! CLI root selection and its value-free diagnostic contract.

use super::*;

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
    .map_err(|error| {
        home_selection_error(
            error,
            "invalid-home-selection",
            "vault home selection is invalid; check --home, --global, JURY_HOME and the platform home variables",
        )
    })
}

pub(super) fn identity_root(environment: &Environment) -> Result<PathBuf, CliError> {
    resolve_identity_root(
        environment.jury_identity_home.as_deref(),
        environment.xdg_data_home.as_deref(),
        environment.user_home.as_deref(),
    )
    .map_err(|error| home_selection_error(error, "invalid-identity-selection",
        "identity root selection is invalid; check JURY_IDENTITY_HOME and the platform home variables"))
}

fn home_selection_error(
    error: crate::home::HomeSelectionError,
    code: &'static str,
    message: &'static str,
) -> CliError {
    use crate::home::HomeSelectionError;
    match error {
        HomeSelectionError::Ambiguous
        | HomeSelectionError::InvalidPath
        | HomeSelectionError::MissingUserHome => {
            CliError::new(CliErrorKind::InvalidArguments, code, message)
        }
        HomeSelectionError::UnsupportedPlatform => CliError::new(
            CliErrorKind::UnsupportedPlatform,
            "unsupported-platform",
            "native roots support Linux and macOS",
        ),
        HomeSelectionError::Repository => filesystem_error(),
    }
}

fn map_state_path_error(error: jury_filesystem::StatePathError) -> CliError {
    use jury_filesystem::StatePathError;
    match error {
        StatePathError::MissingHome
        | StatePathError::NotAbsolute
        | StatePathError::Nul
        | StatePathError::Traversal => CliError::new(
            CliErrorKind::InvalidArguments,
            "invalid-state-selection",
            "state root selection is invalid; check JURY_STATE_HOME and the platform home variables",
        ),
        StatePathError::Unsupported => CliError::new(
            CliErrorKind::UnsupportedPlatform,
            "unsupported-platform",
            "native state roots support Linux and macOS",
        ),
    }
}

pub(super) fn state_root(environment: &Environment) -> Result<PathBuf, CliError> {
    jury_filesystem::resolve_platform_state_root(
        environment.jury_state_home.as_deref(),
        environment.xdg_state_home.as_deref(),
        environment.user_home.as_deref(),
    )
    .map_err(map_state_path_error)
}
