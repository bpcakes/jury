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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ConfigurationConstraint {
    Document,
    Schema,
    Tls,
    Limits,
    DatabasePath,
    AuthorityLabels,
    AuthoritySeparation,
    DistinctFiles,
    CaFile,
    PrivateFile,
    CredentialBytes,
}

impl ConfigurationConstraint {
    const fn message(self) -> &'static str {
        match self {
            Self::Document => {
                "configuration document must be an absolute regular file no larger than 128 KiB with the required JSON fields and types; see deploy/juryd examples"
            }
            Self::Schema => "configuration schema must be 1",
            Self::Tls => {
                "configure both TLS certificate and private key files, or explicitly select insecure loopback with a loopback listen address"
            }
            Self::Limits => {
                "transport limits are outside supported bounds: request bytes 1024..=18874368, concurrency 1..=1024, rate 1..=10000, burst between rate and 100000, timeouts 100..=60000 ms with shutdown grace at least request timeout; anchor request bytes must be 1048576"
            }
            Self::DatabasePath => {
                "database path must be absolute with a file name and an existing directory parent"
            }
            Self::AuthorityLabels => {
                "authority labels must be distinct within a boundary and contain 3..=128 ASCII letters, digits, dots, underscores, colons or hyphens"
            }
            Self::AuthoritySeparation => {
                "database, external anchor and anchor-write authority labels must be separate; assign distinct administration, backup, restore and failure-domain labels"
            }
            Self::DistinctFiles => {
                "identity, passphrase, TLS key and credential paths must resolve to distinct existing files; credential values must also differ"
            }
            Self::CaFile => {
                "external anchor CA certificate must be a readable bounded regular file at an absolute path"
            }
            Self::PrivateFile => {
                "private material must be readable at an absolute path, owned by the current user, a regular file with one hard link and no group/world permissions (use mode 0600), within its size limit; symlinks are not allowed"
            }
            Self::CredentialBytes => {
                "credential must contain 32..=256 ASCII letters, digits, underscores or hyphens, optionally followed by CR/LF"
            }
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct AdapterError {
    kind: AdapterErrorKind,
    configuration_constraint: Option<ConfigurationConstraint>,
}

impl AdapterError {
    #[must_use]
    pub const fn new(kind: AdapterErrorKind) -> Self {
        Self {
            kind,
            configuration_constraint: None,
        }
    }

    pub(crate) const fn configuration(constraint: ConfigurationConstraint) -> Self {
        Self {
            kind: AdapterErrorKind::InvalidConfiguration,
            configuration_constraint: Some(constraint),
        }
    }

    pub(crate) const fn credential(constraint: ConfigurationConstraint) -> Self {
        Self {
            kind: AdapterErrorKind::InvalidCredential,
            configuration_constraint: Some(constraint),
        }
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
            .field("configuration_constraint", &self.configuration_constraint)
            .finish()
    }
}

impl fmt::Display for AdapterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(constraint) = self.configuration_constraint {
            return formatter.write_str(constraint.message());
        }
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
