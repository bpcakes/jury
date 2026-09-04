use std::fmt;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentityErrorKind {
    Format,
    InvalidPassphrase,
    EntropyUnavailable,
    RetryExhausted,
    ResourceUnavailable,
    ProtectionUnavailable,
    ProviderFailure,
    AuthenticationFailed,
    KeyCollision,
    KdfDowngrade,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct IdentityError {
    kind: IdentityErrorKind,
}

impl IdentityError {
    #[must_use]
    pub const fn kind(self) -> IdentityErrorKind {
        self.kind
    }

    pub(super) const fn new(kind: IdentityErrorKind) -> Self {
        Self { kind }
    }
}

impl fmt::Debug for IdentityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IdentityError")
            .field("kind", &self.kind)
            .finish()
    }
}

impl fmt::Display for IdentityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.kind {
            IdentityErrorKind::Format => "identity format is invalid",
            IdentityErrorKind::InvalidPassphrase => "passphrase does not meet the exact profile",
            IdentityErrorKind::EntropyUnavailable => "operating-system entropy was unavailable",
            IdentityErrorKind::RetryExhausted => "identity generation exhausted its retry bound",
            IdentityErrorKind::ResourceUnavailable => {
                "identity protection resources are unavailable"
            }
            IdentityErrorKind::ProtectionUnavailable => {
                "required private-memory protection is unavailable"
            }
            IdentityErrorKind::ProviderFailure => "identity cryptographic provider failed",
            IdentityErrorKind::AuthenticationFailed => "identity authentication failed",
            IdentityErrorKind::KeyCollision => "identity key generation collided",
            IdentityErrorKind::KdfDowngrade => "identity KDF downgrade requires explicit approval",
        })
    }
}

impl std::error::Error for IdentityError {}
