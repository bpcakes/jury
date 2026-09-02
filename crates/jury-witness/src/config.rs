use std::{
    collections::BTreeSet,
    fs,
    net::SocketAddr,
    path::{Path, PathBuf},
};

use jury_protocol::vault_v1::PrincipalId;
use serde::{Deserialize, Serialize, de::DeserializeOwned};

use crate::{
    AdapterError, AdapterErrorKind,
    credentials::{load_digest, validate_private_regular_file},
};

const MAX_CONFIG_BYTES: usize = 128 * 1024;
const MAX_REQUEST_BYTES: usize = 18 * 1024 * 1024;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    pub certificate_file: Option<PathBuf>,
    pub private_key_file: Option<PathBuf>,
    #[serde(default)]
    pub allow_insecure_loopback: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "provider", rename_all = "kebab-case", deny_unknown_fields)]
pub enum IdentityProviderConfig {
    SoftwareFile {
        identity_file: PathBuf,
        passphrase_file: PathBuf,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityBoundary {
    pub administration_authority: String,
    pub backup_authority: String,
    pub restore_authority: String,
    pub failure_domain: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DatabaseConfig {
    pub path: PathBuf,
    pub authority: AuthorityBoundary,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteAnchorConfig {
    pub base_url: String,
    pub ca_certificate_file: PathBuf,
    pub write_credential_file: PathBuf,
    pub write_authority: String,
    pub authority: AuthorityBoundary,
    #[serde(default)]
    pub allow_insecure_loopback: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TransportLimits {
    pub maximum_request_bytes: usize,
    pub maximum_concurrency: usize,
    pub requests_per_second: u32,
    pub burst_requests: u32,
    pub request_timeout_ms: u64,
    pub shutdown_grace_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessServiceConfig {
    pub schema: u16,
    pub witness_id: PrincipalId,
    pub listen: SocketAddr,
    pub tls: TlsConfig,
    pub identity: IdentityProviderConfig,
    pub database: DatabaseConfig,
    pub external_anchor: RemoteAnchorConfig,
    pub client_credential_file: PathBuf,
    pub operator_credential_file: PathBuf,
    pub limits: TransportLimits,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AnchorServiceConfig {
    pub schema: u16,
    pub witness_id: PrincipalId,
    pub listen: SocketAddr,
    pub tls: TlsConfig,
    pub database: DatabaseConfig,
    pub write_credential_file: PathBuf,
    pub write_authority: String,
    pub limits: TransportLimits,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WitnessDatabaseCommandConfig {
    pub witness_id: PrincipalId,
    pub database: DatabaseConfig,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnchorDatabaseCommandConfig {
    pub witness_id: PrincipalId,
    pub database: DatabaseConfig,
}

impl WitnessServiceConfig {
    pub fn load(path: &Path) -> Result<Self, AdapterError> {
        let config: Self = load_json(path)?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), AdapterError> {
        if self.schema != 1 {
            return invalid();
        }
        validate_tls(&self.tls, self.listen)?;
        validate_limits(&self.limits)?;
        validate_database_path(&self.database.path)?;
        validate_boundary(&self.database.authority)?;
        validate_boundary(&self.external_anchor.authority)?;
        validate_label(&self.external_anchor.write_authority)?;
        validate_identity(&self.identity)?;
        validate_private_regular_file(&self.client_credential_file)?;
        validate_private_regular_file(&self.operator_credential_file)?;
        validate_private_regular_file(&self.external_anchor.write_credential_file)?;
        jury_filesystem::read_public_file(&self.external_anchor.ca_certificate_file, 1024 * 1024)
            .map_err(|_| AdapterError::new(AdapterErrorKind::InvalidConfiguration))?;
        let IdentityProviderConfig::SoftwareFile {
            identity_file,
            passphrase_file,
        } = &self.identity;
        let mut private_material = vec![
            &self.client_credential_file,
            &self.operator_credential_file,
            &self.external_anchor.write_credential_file,
            identity_file,
            passphrase_file,
        ];
        if let Some(private_key) = &self.tls.private_key_file {
            private_material.push(private_key);
        }
        require_distinct_files(&private_material)?;
        let client = load_digest(&self.client_credential_file)?;
        let operator = load_digest(&self.operator_credential_file)?;
        let anchor = load_digest(&self.external_anchor.write_credential_file)?;
        if client == operator || client == anchor || operator == anchor {
            return invalid();
        }
        validate_separation(self)?;
        Ok(())
    }

    pub fn load_database_command(
        path: &Path,
    ) -> Result<WitnessDatabaseCommandConfig, AdapterError> {
        let config: Self = load_json(path)?;
        if config.schema != 1 {
            return invalid();
        }
        validate_database_path(&config.database.path)?;
        validate_boundary(&config.database.authority)?;
        Ok(WitnessDatabaseCommandConfig {
            witness_id: config.witness_id,
            database: config.database,
        })
    }
}

impl AnchorServiceConfig {
    pub fn load(path: &Path) -> Result<Self, AdapterError> {
        let config: Self = load_json(path)?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), AdapterError> {
        if self.schema != 1 {
            return invalid();
        }
        validate_tls(&self.tls, self.listen)?;
        validate_limits(&self.limits)?;
        validate_database_path(&self.database.path)?;
        validate_boundary(&self.database.authority)?;
        validate_label(&self.write_authority)?;
        validate_private_regular_file(&self.write_credential_file)?;
        if let Some(private_key) = &self.tls.private_key_file {
            require_distinct_files(&[&self.write_credential_file, private_key])?;
        }
        if boundary_labels(&self.database.authority).contains(&self.write_authority.as_str()) {
            return invalid();
        }
        Ok(())
    }

    pub fn load_database_command(path: &Path) -> Result<AnchorDatabaseCommandConfig, AdapterError> {
        let config: Self = load_json(path)?;
        if config.schema != 1 {
            return invalid();
        }
        validate_database_path(&config.database.path)?;
        validate_boundary(&config.database.authority)?;
        Ok(AnchorDatabaseCommandConfig {
            witness_id: config.witness_id,
            database: config.database,
        })
    }
}

fn validate_separation(config: &WitnessServiceConfig) -> Result<(), AdapterError> {
    let database = boundary_labels(&config.database.authority);
    let anchor = boundary_labels(&config.external_anchor.authority);
    if database.iter().any(|label| anchor.contains(label))
        || database.contains(&config.external_anchor.write_authority.as_str())
        || anchor.contains(&config.external_anchor.write_authority.as_str())
        || config.database.authority.failure_domain
            == config.external_anchor.authority.failure_domain
    {
        return invalid();
    }
    Ok(())
}

fn boundary_labels(boundary: &AuthorityBoundary) -> BTreeSet<&str> {
    BTreeSet::from([
        boundary.administration_authority.as_str(),
        boundary.backup_authority.as_str(),
        boundary.restore_authority.as_str(),
        boundary.failure_domain.as_str(),
    ])
}

fn validate_boundary(boundary: &AuthorityBoundary) -> Result<(), AdapterError> {
    for label in [
        &boundary.administration_authority,
        &boundary.backup_authority,
        &boundary.restore_authority,
        &boundary.failure_domain,
    ] {
        validate_label(label)?;
    }
    if boundary_labels(boundary).len() != 4 {
        return invalid();
    }
    Ok(())
}

fn validate_label(label: &str) -> Result<(), AdapterError> {
    if !(3..=128).contains(&label.len())
        || !label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
    {
        return invalid();
    }
    Ok(())
}

fn validate_tls(tls: &TlsConfig, listen: SocketAddr) -> Result<(), AdapterError> {
    match (&tls.certificate_file, &tls.private_key_file) {
        (Some(certificate), Some(private_key)) if !tls.allow_insecure_loopback => {
            jury_filesystem::read_public_file(certificate, 1024 * 1024)
                .map_err(|_| AdapterError::new(AdapterErrorKind::InvalidConfiguration))?;
            validate_private_regular_file(private_key)
        }
        (None, None) if tls.allow_insecure_loopback && listen.ip().is_loopback() => Ok(()),
        _ => invalid(),
    }
}

fn validate_limits(limits: &TransportLimits) -> Result<(), AdapterError> {
    if !(1024..=MAX_REQUEST_BYTES).contains(&limits.maximum_request_bytes)
        || !(1..=1024).contains(&limits.maximum_concurrency)
        || !(1..=10_000).contains(&limits.requests_per_second)
        || limits.burst_requests < limits.requests_per_second
        || limits.burst_requests > 100_000
        || !(100..=60_000).contains(&limits.request_timeout_ms)
        || !(100..=60_000).contains(&limits.shutdown_grace_ms)
    {
        return invalid();
    }
    Ok(())
}

fn validate_identity(identity: &IdentityProviderConfig) -> Result<(), AdapterError> {
    match identity {
        IdentityProviderConfig::SoftwareFile {
            identity_file,
            passphrase_file,
        } => {
            validate_private_regular_file(identity_file)?;
            validate_private_regular_file(passphrase_file)?;
            require_distinct_files(&[identity_file, passphrase_file])
        }
    }
}

fn validate_database_path(path: &Path) -> Result<(), AdapterError> {
    if !path.is_absolute() || path.file_name().is_none() {
        return invalid();
    }
    let parent = path
        .parent()
        .ok_or_else(|| AdapterError::new(AdapterErrorKind::InvalidConfiguration))?;
    let metadata = fs::symlink_metadata(parent)
        .map_err(|_| AdapterError::new(AdapterErrorKind::InvalidConfiguration))?;
    if !metadata.is_dir() {
        return invalid();
    }
    Ok(())
}

fn require_distinct_files(paths: &[&PathBuf]) -> Result<(), AdapterError> {
    let canonical = paths
        .iter()
        .map(|path| {
            fs::canonicalize(path)
                .map_err(|_| AdapterError::new(AdapterErrorKind::InvalidConfiguration))
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    if canonical.len() != paths.len() {
        return invalid();
    }
    Ok(())
}

fn load_json<T: DeserializeOwned>(path: &Path) -> Result<T, AdapterError> {
    if !path.is_absolute() {
        return invalid();
    }
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| AdapterError::new(AdapterErrorKind::InvalidConfiguration))?;
    if !metadata.is_file() || metadata.len() > MAX_CONFIG_BYTES as u64 {
        return invalid();
    }
    let bytes =
        fs::read(path).map_err(|_| AdapterError::new(AdapterErrorKind::InvalidConfiguration))?;
    serde_json::from_slice(&bytes)
        .map_err(|_| AdapterError::new(AdapterErrorKind::InvalidConfiguration))
}

fn invalid<T>() -> Result<T, AdapterError> {
    Err(AdapterError::new(AdapterErrorKind::InvalidConfiguration))
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    use super::*;

    fn boundary(prefix: &str, failure_domain: &str) -> AuthorityBoundary {
        AuthorityBoundary {
            administration_authority: format!("{prefix}-admin"),
            backup_authority: format!("{prefix}-backup"),
            restore_authority: format!("{prefix}-restore"),
            failure_domain: failure_domain.to_owned(),
        }
    }

    fn config() -> WitnessServiceConfig {
        WitnessServiceConfig {
            schema: 1,
            witness_id: PrincipalId::from_bytes([7; 32]).expect("nonzero fixture id"),
            listen: SocketAddr::from(([127, 0, 0, 1], 8443)),
            tls: TlsConfig {
                certificate_file: None,
                private_key_file: None,
                allow_insecure_loopback: true,
            },
            identity: IdentityProviderConfig::SoftwareFile {
                identity_file: PathBuf::from("/identity"),
                passphrase_file: PathBuf::from("/passphrase"),
            },
            database: DatabaseConfig {
                path: PathBuf::from("/db/witness.sqlite3"),
                authority: boundary("witness-db", "witness-host"),
            },
            external_anchor: RemoteAnchorConfig {
                base_url: "https://anchor.example.invalid".to_owned(),
                ca_certificate_file: PathBuf::from("/anchor-ca"),
                write_credential_file: PathBuf::from("/anchor-token"),
                write_authority: "witness-anchor-writer".to_owned(),
                authority: boundary("anchor-db", "anchor-host"),
                allow_insecure_loopback: false,
            },
            client_credential_file: PathBuf::from("/client-token"),
            operator_credential_file: PathBuf::from("/operator-token"),
            limits: TransportLimits {
                maximum_request_bytes: 1024,
                maximum_concurrency: 1,
                requests_per_second: 1,
                burst_requests: 1,
                request_timeout_ms: 100,
                shutdown_grace_ms: 100,
            },
        }
    }

    #[test]
    fn database_and_anchor_authorities_must_be_independent() {
        let baseline = config();
        assert_eq!(validate_separation(&baseline), Ok(()));

        let mut shared_admin = baseline.clone();
        shared_admin
            .external_anchor
            .authority
            .administration_authority = shared_admin
            .database
            .authority
            .administration_authority
            .clone();
        assert!(validate_separation(&shared_admin).is_err());

        let mut shared_failure_domain = baseline.clone();
        shared_failure_domain
            .external_anchor
            .authority
            .failure_domain = shared_failure_domain
            .database
            .authority
            .failure_domain
            .clone();
        assert!(validate_separation(&shared_failure_domain).is_err());

        let mut shared_writer = baseline;
        shared_writer.external_anchor.write_authority =
            shared_writer.database.authority.backup_authority.clone();
        assert!(validate_separation(&shared_writer).is_err());
    }

    #[test]
    fn database_commands_do_not_require_service_private_material() {
        let fixture = tempfile::tempdir().expect("fixture");
        fs::set_permissions(fixture.path(), fs::Permissions::from_mode(0o700))
            .expect("private fixture");
        let mut config = config();
        config.database.path = fixture.path().join("witness.sqlite3");
        let config_path = fixture.path().join("witness.json");
        fs::write(
            &config_path,
            serde_json::to_vec(&config).expect("serialize config"),
        )
        .expect("write config");

        let command = WitnessServiceConfig::load_database_command(&config_path)
            .expect("database projection does not touch private files");
        assert_eq!(command.witness_id, config.witness_id);
        assert_eq!(command.database, config.database);
        assert!(WitnessServiceConfig::load(&config_path).is_err());
    }
}
