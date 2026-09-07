use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CliErrorKind {
    InvalidArguments,
    UnsupportedPlatform,
    NotFound,
    Conflict,
    InvalidIdentity,
    AuthenticationFailed,
    AccessDenied,
    InvalidVault,
    ProtectionUnavailable,
    Filesystem,
    LocalState,
    Process,
    Interrupted(u8),
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CliError {
    kind: CliErrorKind,
    code: &'static str,
    message: &'static str,
}

impl CliError {
    /// A parser failure without reflecting user-supplied argument values.
    #[must_use]
    pub const fn invalid_command_arguments() -> Self {
        Self::new(
            CliErrorKind::InvalidArguments,
            "invalid-arguments",
            "invalid command arguments; run jury --help or jury <command> --help for usage",
        )
    }

    pub(in crate::cli) const fn new(
        kind: CliErrorKind,
        code: &'static str,
        message: &'static str,
    ) -> Self {
        Self {
            kind,
            code,
            message,
        }
    }

    pub(in crate::cli) const fn kind(self) -> CliErrorKind {
        self.kind
    }

    #[cfg(test)]
    pub(in crate::cli) const fn code(self) -> &'static str {
        self.code
    }

    #[must_use]
    pub const fn exit_code(self) -> u8 {
        match self.kind {
            CliErrorKind::InvalidArguments | CliErrorKind::UnsupportedPlatform => 2,
            CliErrorKind::NotFound => 3,
            CliErrorKind::Conflict => 4,
            CliErrorKind::AuthenticationFailed => 5,
            CliErrorKind::AccessDenied => 6,
            CliErrorKind::Interrupted(signal) => 128 + signal,
            CliErrorKind::InvalidIdentity
            | CliErrorKind::InvalidVault
            | CliErrorKind::ProtectionUnavailable
            | CliErrorKind::Filesystem
            | CliErrorKind::LocalState
            | CliErrorKind::Process => 1,
        }
    }

    pub fn write(self, json: bool) {
        if json {
            let _ = writeln!(
                std::io::stderr().lock(),
                "{}",
                serde_json::json!({
                    "ok": false,
                    "error": {"code": self.code, "message": self.message},
                    "maturity": "pre-alpha",
                    "review_status": "externally-unreviewed",
                    "real_secrets_supported": false
                })
            );
        } else {
            let mut stderr = std::io::stderr().lock();
            let _ = writeln!(stderr, "{PRE_ALPHA_WARNING}");
            let _ = writeln!(stderr, "jury: {} ({})", self.message, self.code);
        }
    }
}

impl fmt::Debug for CliError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CliError")
            .field("kind", &self.kind)
            .field("code", &self.code)
            .finish()
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message)
    }
}

impl std::error::Error for CliError {}
