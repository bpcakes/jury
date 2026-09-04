#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restricted_env_parser_rejects_substitution_reserved_and_duplicates()
    -> Result<(), Box<dyn std::error::Error>> {
        assert!(decode_env_literal(b"$VALUE").is_err());
        assert!(decode_env_literal(b"`command`").is_err());
        assert!(bytes_to_environment(b"value\0suffix").is_err());
        assert!(validate_environment_name("JURY_HOME").is_err());
        assert!(validate_environment_name("BAD-NAME").is_err());
        assert!(is_reserved_execution_environment(
            b"JURY_IDENTITY_PASSPHRASE"
        ));
        Ok(())
    }

    #[test]
    fn command_preflight_rejects_missing_directories_and_non_executables()
    -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        let missing_directory = temporary.path().join("missing");
        assert!(
            normalize_command(
                vec![OsString::from("/bin/true")],
                &missing_directory,
                temporary.path(),
            )
            .is_err()
        );

        let non_executable = temporary.path().join("not-executable");
        std::fs::write(&non_executable, b"fixture")?;
        std::fs::set_permissions(&non_executable, std::fs::Permissions::from_mode(0o600))?;
        assert!(
            normalize_command(
                vec![non_executable.into_os_string()],
                temporary.path(),
                temporary.path(),
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn manifest_normalization_is_independent_of_mapping_order()
    -> Result<(), Box<dyn std::error::Error>> {
        let current = std::env::current_dir()?;
        let environment = |name: &str, field: &str| -> Result<EnvironmentBinding, CliError> {
            Ok(EnvironmentBinding {
                name: name.to_owned(),
                source: EnvironmentSource::Field(parse_field_reference(field)?),
            })
        };
        let file = |name: &str, field: &str| -> Result<FileBinding, CliError> {
            Ok(FileBinding {
                name: name.to_owned(),
                source: parse_field_reference(field)?,
            })
        };
        let first = prepare_execution(
            ExecutionMode::Transparent,
            vec![OsString::from("/bin/true")],
            None,
            &current,
            vec![
                environment("Z_VALUE", "ExampleItem.Second")?,
                environment("A_VALUE", "ExampleItem.First")?,
            ],
            vec![
                file("Z_FILE", "ExampleItem.Second")?,
                file("A_FILE", "ExampleItem.First")?,
            ],
            None,
            None,
            0,
        )?;
        let second = prepare_execution(
            ExecutionMode::Transparent,
            vec![OsString::from("/bin/true")],
            None,
            &current,
            vec![
                environment("A_VALUE", "ExampleItem.First")?,
                environment("Z_VALUE", "ExampleItem.Second")?,
            ],
            vec![
                file("A_FILE", "ExampleItem.First")?,
                file("Z_FILE", "ExampleItem.Second")?,
            ],
            None,
            None,
            0,
        )?;
        assert_eq!(first.manifest_digest, second.manifest_digest);
        Ok(())
    }

    #[test]
    fn manifest_digest_changes_for_every_public_action_dimension()
    -> Result<(), Box<dyn std::error::Error>> {
        let executable_path = std::fs::canonicalize("/bin/true")?;
        let current = std::env::current_dir()?;
        let alternate_directory = tempfile::tempdir()?;
        let command = |arguments: &[&str], working_directory: &Path| {
            Ok::<_, std::io::Error>(NormalizedCommand {
                arguments: arguments.iter().map(OsString::from).collect(),
                working_directory: working_directory.to_path_buf(),
                working_directory_handle: File::open(working_directory)?,
                executable_path: executable_path.clone(),
                executable: File::open(&executable_path)?,
            })
        };
        let baseline_command = command(&["true"], &current)?;
        let baseline = manifest_digest(
            ExecutionMode::Transparent,
            &baseline_command,
            &[],
            &[],
            None,
            None,
            0,
        )?;
        let argument_changed = manifest_digest(
            ExecutionMode::Transparent,
            &command(&["true", "argument"], &current)?,
            &[],
            &[],
            None,
            None,
            0,
        )?;
        let directory_changed = manifest_digest(
            ExecutionMode::Transparent,
            &command(&["true"], alternate_directory.path())?,
            &[],
            &[],
            None,
            None,
            0,
        )?;
        let alternate_executable_path = std::fs::canonicalize("/bin/false")?;
        let executable_changed_command = NormalizedCommand {
            arguments: vec![OsString::from("false")],
            working_directory: current.clone(),
            working_directory_handle: File::open(&current)?,
            executable: File::open(&alternate_executable_path)?,
            executable_path: alternate_executable_path,
        };
        let executable_changed = manifest_digest(
            ExecutionMode::Transparent,
            &executable_changed_command,
            &[],
            &[],
            None,
            None,
            0,
        )?;
        let reference = parse_field_reference("ExampleItem.ExampleField")?;
        let env = [EnvironmentBinding {
            name: "TOKEN".to_owned(),
            source: EnvironmentSource::Field(reference.clone()),
        }];
        let environment_changed = manifest_digest(
            ExecutionMode::Transparent,
            &baseline_command,
            &env,
            &[],
            None,
            None,
            0,
        )?;
        let files = [FileBinding {
            name: "TOKEN_FILE".to_owned(),
            source: reference.clone(),
        }];
        let file_changed = manifest_digest(
            ExecutionMode::Transparent,
            &baseline_command,
            &[],
            &files,
            None,
            None,
            0,
        )?;
        let stdin_changed = manifest_digest(
            ExecutionMode::Transparent,
            &baseline_command,
            &[],
            &[],
            Some(&reference),
            None,
            0,
        )?;
        let mode_changed = manifest_digest(
            ExecutionMode::Brokered,
            &baseline_command,
            &[],
            &[],
            None,
            Some(Duration::from_secs(5)),
            1_024,
        )?;
        let timeout_changed = manifest_digest(
            ExecutionMode::Brokered,
            &baseline_command,
            &[],
            &[],
            None,
            Some(Duration::from_secs(6)),
            1_024,
        )?;
        let output_limit_changed = manifest_digest(
            ExecutionMode::Brokered,
            &baseline_command,
            &[],
            &[],
            None,
            Some(Duration::from_secs(5)),
            2_048,
        )?;
        let all = BTreeSet::from([
            baseline,
            argument_changed,
            directory_changed,
            executable_changed,
            environment_changed,
            file_changed,
            stdin_changed,
            mode_changed,
            timeout_changed,
            output_limit_changed,
        ]);
        assert_eq!(all.len(), 10);
        Ok(())
    }
}
