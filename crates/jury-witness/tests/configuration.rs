use std::{error::Error, fs, os::unix::fs::PermissionsExt as _, process::Command};

use serde_json::Value;

type TestResult = Result<(), Box<dyn Error>>;

const CONFIGS: [(&str, &str); 2] = [
    (
        "database",
        include_str!("../../../deploy/juryd/witness.example.json"),
    ),
    (
        "anchor",
        include_str!("../../../deploy/juryd/anchor.example.json"),
    ),
];

#[test]
fn malformed_configuration_never_initializes_a_database() -> TestResult {
    for (service, example) in CONFIGS {
        let directory = tempfile::tempdir()?;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
        let database = directory.path().join("ExampleDatabase.sqlite3");
        let path = directory.path().join("ExampleConfig.json");
        let mut config: Value = serde_json::from_str(example)?;
        config["database"]["path"] = serde_json::to_value(&database)?;
        let document = serde_json::to_string(&config)?;
        for suffix in [" garbage", r#"{"schema":99}"#, " null"] {
            fs::write(&path, format!("{document}{suffix}"))?;
            let result = Command::new(env!("CARGO_BIN_EXE_juryd"))
                .args([service, "init", "--config"])
                .arg(&path)
                .output()?;
            assert!(!result.status.success());
            assert!(result.stdout.is_empty());
            assert!(String::from_utf8(result.stderr)?.contains("malformed JSON"));
            assert!(!database.exists());
        }
        // The same configuration with legal trailing whitespace must work.
        fs::write(&path, format!("{document}\n\t \r"))?;
        let result = Command::new(env!("CARGO_BIN_EXE_juryd"))
            .args([service, "init", "--config"])
            .arg(&path)
            .output()?;
        assert!(result.status.success(), "{service} init failed");
        assert!(database.is_file());
    }
    Ok(())
}

#[test]
fn daemon_stderr_keeps_values_out_of_configuration_diagnostics() -> TestResult {
    for (service, _) in CONFIGS {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("ExampleConfig.json");
        for document in [
            r#"{"schema":"x, expected ExampleSecret"}"#,
            r#"{"schema":"unknown field `ExampleSecret`"}"#,
            r#"{"schema":"missing field `ExampleSecret`"}"#,
            r#"{"ExampleSecret":"ExampleSecret"}"#,
            r#"{"tls":{"allow_insecure_loopback":"x, expected ExampleSecret"}}"#,
        ] {
            fs::write(&path, document)?;
            let result = Command::new(env!("CARGO_BIN_EXE_juryd"))
                .args([service, "init", "--config"])
                .arg(&path)
                .output()?;
            assert!(!result.status.success());
            assert!(result.stdout.is_empty());
            let diagnostic = String::from_utf8(result.stderr)?;
            assert!(!diagnostic.contains("ExampleSecret"));
            assert!(diagnostic.contains("JSON fields or values"));
            assert!(diagnostic.contains(path.to_string_lossy().as_ref()));
            assert!(diagnostic.contains("line 1, column"));
            if document.contains("allow_insecure_loopback") {
                assert!(diagnostic.contains("at `tls.allow_insecure_loopback`"));
            } else if document.contains("schema") {
                assert!(diagnostic.contains("at `schema`"));
            }
        }
    }
    Ok(())
}
