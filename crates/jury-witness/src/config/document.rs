use std::{fs, path::Path};

use serde::de::DeserializeOwned;

use crate::{AdapterError, error::ConfigurationConstraint};

pub(super) const MAX_CONFIG_BYTES: usize = 128 * 1024;

pub(super) fn load_json<T: DeserializeOwned>(path: &Path) -> Result<T, AdapterError> {
    if !path.is_absolute() {
        return Err(
            AdapterError::configuration(ConfigurationConstraint::Document)
                .with_configuration_path(path),
        );
    }
    let metadata = fs::symlink_metadata(path).map_err(|_| {
        AdapterError::configuration(ConfigurationConstraint::Document).with_configuration_path(path)
    })?;
    if !metadata.is_file() || metadata.len() > MAX_CONFIG_BYTES as u64 {
        return Err(
            AdapterError::configuration(ConfigurationConstraint::Document)
                .with_configuration_path(path),
        );
    }
    let bytes = fs::read(path).map_err(|_| {
        AdapterError::configuration(ConfigurationConstraint::Document).with_configuration_path(path)
    })?;
    let mut deserializer = serde_json::Deserializer::from_slice(&bytes);
    let value = serde_path_to_error::deserialize(&mut deserializer).map_err(|error| {
        AdapterError::configuration_parse(path, schema_path(error.path()), error.inner())
    })?;
    // serde_path_to_error deserializes one value, not a complete document.
    deserializer
        .end()
        .map_err(|error| AdapterError::configuration_parse(path, None, &error))?;
    Ok(value)
}

fn schema_path(path: &serde_path_to_error::Path) -> Option<String> {
    // Paths also contain input-controlled map keys and enum values. Emit only
    // known schema names, taking a safe parent prefix for unknown/new fields.
    // Adding a schema field never permits its contents into diagnostics.
    const FIELDS: &[&str] = &[
        "schema",
        "witness_id",
        "listen",
        "tls",
        "identity",
        "database",
        "external_anchor",
        "client_credential_file",
        "operator_credential_file",
        "limits",
        "certificate_file",
        "private_key_file",
        "allow_insecure_loopback",
        "provider",
        "identity_file",
        "passphrase_file",
        "path",
        "authority",
        "administration_authority",
        "backup_authority",
        "restore_authority",
        "failure_domain",
        "base_url",
        "ca_certificate_file",
        "write_credential_file",
        "write_authority",
        "maximum_request_bytes",
        "maximum_concurrency",
        "requests_per_second",
        "burst_requests",
        "request_timeout_ms",
        "shutdown_grace_ms",
    ];
    let mut fields = Vec::new();
    for segment in path {
        let serde_path_to_error::Segment::Map { key } = segment else {
            break;
        };
        let Some(field) = FIELDS.iter().find(|field| **field == key) else {
            break;
        };
        fields.push(*field);
    }
    (!fields.is_empty()).then(|| fields.join("."))
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use crate::config::{AnchorServiceConfig, WitnessServiceConfig};

    use super::*;

    type TestResult = Result<(), Box<dyn Error>>;

    #[test]
    fn diagnostics_do_not_reflect_rejected_values_or_unknown_keys() -> TestResult {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("ExampleConfig.json");
        for document in [
            r#"{"schema":"x, expected ExampleSecret"}"#,
            r#"{"schema":"unknown field `ExampleSecret`"}"#,
            r#"{"schema":"missing field `ExampleSecret`"}"#,
            r#"{"ExampleSecret":true}"#,
            r#"{"tls":{"ExampleSecret":true}}"#,
            r#"{"tls":{"allow_insecure_loopback":"x, expected ExampleSecret"}}"#,
        ] {
            fs::write(&path, document)?;
            let error = load_json::<AnchorServiceConfig>(&path)
                .err()
                .ok_or("invalid document was accepted")?;
            // Both operator output and Debug must exclude rejected input.
            assert!(!error.to_string().contains("ExampleSecret"));
            assert!(!format!("{error:?}").contains("ExampleSecret"));
            assert_eq!(error.kind(), crate::AdapterErrorKind::InvalidConfiguration);
            assert!(error.to_string().contains(path.to_string_lossy().as_ref()));
        }
        Ok(())
    }

    #[test]
    fn document_requires_end_of_input_and_preserves_duplicate_rejection() -> TestResult {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("ExampleConfig.json");
        let document = include_str!("../../../../deploy/juryd/anchor.example.json");
        fs::write(&path, format!("{document}\n\t \r"))?;
        let baseline = load_json::<AnchorServiceConfig>(&path)?;
        assert_eq!(baseline.schema, 1);
        for suffix in [" garbage", r#"{"schema":99}"#, " null"] {
            fs::write(&path, format!("{document}{suffix}"))?;
            assert!(load_json::<AnchorServiceConfig>(&path).is_err());
        }
        let duplicate = document.replacen('{', "{\"schema\":1,", 1);
        fs::write(&path, duplicate)?;
        assert!(load_json::<AnchorServiceConfig>(&path).is_err());
        Ok(())
    }

    #[test]
    fn enum_values_are_not_diagnostic_schema_paths() -> TestResult {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("ExampleConfig.json");
        fs::write(&path, r#"{"identity":{"provider":"ExampleSecret"}}"#)?;
        let error = load_json::<WitnessServiceConfig>(&path)
            .err()
            .ok_or("unsupported identity provider was accepted")?;
        assert!(!error.to_string().contains("ExampleSecret"));
        assert!(!format!("{error:?}").contains("ExampleSecret"));
        assert!(error.to_string().contains("at `identity.provider`"));
        Ok(())
    }
}
