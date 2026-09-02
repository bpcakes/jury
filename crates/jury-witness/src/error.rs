use std::fmt;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdapterErrorKind {
    InvalidConfiguration,
    InvalidCredential,
    InvalidIdentity,
    InvalidPolicyMaterial,
    InvalidState,
    DatabaseUnavailable,
    AnchorUnavailable,
    AuthenticationFailed,
    Conflict,
    CapacityExhausted,
    TargetExists,
    Io,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct AdapterError {
    kind: AdapterErrorKind,
}

impl AdapterError {
    #[must_use]
    pub const fn new(kind: AdapterErrorKind) -> Self {
        Self { kind }
    }

    #[must_use]
    pub const fn kind(self) -> AdapterErrorKind {
        self.kind
    }
}

impl fmt::Debug for AdapterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AdapterError")
            .field("kind", &self.kind)
            .finish()
    }
}

impl fmt::Display for AdapterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.kind {
            AdapterErrorKind::InvalidConfiguration => "adapter configuration is invalid",
            AdapterErrorKind::InvalidCredential => "adapter credential is invalid",
            AdapterErrorKind::InvalidIdentity => "witness identity is invalid",
            AdapterErrorKind::InvalidPolicyMaterial => "public policy material is invalid",
            AdapterErrorKind::InvalidState => "persisted witness state is invalid",
            AdapterErrorKind::DatabaseUnavailable => "witness database is unavailable",
            AdapterErrorKind::AnchorUnavailable => "external anchor is unavailable",
            AdapterErrorKind::AuthenticationFailed => "transport authentication failed",
            AdapterErrorKind::Conflict => "adapter state conflicts",
            AdapterErrorKind::CapacityExhausted => "adapter capacity is exhausted",
            AdapterErrorKind::TargetExists => "destination already exists",
            AdapterErrorKind::Io => "adapter I/O failed",
        })
    }
}

impl std::error::Error for AdapterError {}
