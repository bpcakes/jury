use super::*;

fn create_repository(path: &Path) -> TestResult {
    fs::create_dir(path)?;
    assert!(
        Command::new("git")
            .args(["init", "--quiet"])
            .arg(path)
            .status()?
            .success()
    );
    Ok(())
}

#[test]
fn initialization_diagnoses_missing_identity_without_reflecting_selectors() -> TestResult {
    let temporary = tempfile::tempdir()?;
    let repository = temporary.path().join("repository");
    let data = temporary.path().join("data");
    let state = temporary.path().join("state");
    create_repository(&repository)?;
    let identities = data.join("jury/identities");
    let explicit_home = temporary.path().join("external-identity");
    fs::create_dir(&explicit_home)?;
    fs::set_permissions(&explicit_home, fs::Permissions::from_mode(0o700))?;
    let explicit = explicit_home.join("ExamplePrivateIdentity.json");
    let explicit = explicit.to_str().ok_or("invalid identity path")?;

    for root_exists in [false, true] {
        if root_exists {
            fs::create_dir_all(&identities)?;
            for path in [&data, &data.join("jury"), &identities] {
                fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
            }
        }
        for command in [vec!["init"], vec!["vault", "init"]] {
            for (selector, environment) in [
                (vec![], vec![]),
                (vec!["--identity", "ExamplePrivateIdentity"], vec![]),
                (vec![], vec![("JURY_IDENTITY", "ExamplePrivateIdentity")]),
                (vec!["--identity-file", explicit], vec![]),
                (vec![], vec![("JURY_IDENTITY_FILE", explicit)]),
            ] {
                let explicit_selected = selector.contains(&"--identity-file")
                    || environment
                        .iter()
                        .any(|(name, _)| *name == "JURY_IDENTITY_FILE");
                let output = jury_command(&repository, &data, &state)
                    .arg("--json")
                    .args(&selector)
                    .args(&command)
                    .envs(environment)
                    .stdin(Stdio::null())
                    .output()?;
                assert_eq!(output.status.code(), Some(3));
                assert!(output.stdout.is_empty());
                let error: serde_json::Value = serde_json::from_slice(&output.stderr)?;
                assert_eq!(error["error"]["code"], "not-found");
                let message = error["error"]["message"]
                    .as_str()
                    .ok_or("missing diagnostic")?;
                assert!(message.contains("jury identity init"));
                assert!(message.contains("home selection"));
                assert!(message.contains("jury vault init"));
                assert!(message.starts_with(if !root_exists {
                    "the identity storage home does not exist"
                } else if explicit_selected {
                    "the selected identity file does not exist"
                } else {
                    "the selected identity does not exist"
                }));
                assert!(!message.contains("ExamplePrivateIdentity"));
                assert!(!message.contains(temporary.path().to_str().ok_or("invalid test path")?));
            }
        }
    }
    assert!(!data.join("jury/vaults").exists());
    assert!(!state.exists());
    Ok(())
}

#[test]
fn initialization_keeps_permission_and_corruption_failures_distinct() -> TestResult {
    let temporary = tempfile::tempdir()?;
    let repository = temporary.path().join("repository");
    let data = temporary.path().join("data");
    let state = temporary.path().join("state");
    create_repository(&repository)?;
    let identities = data.join("jury/identities");
    fs::create_dir_all(&identities)?;
    for path in [&data, &data.join("jury"), &identities] {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    let identity = identities.join("default.identity.json");
    fs::write(&identity, b"{}")
        .and_then(|()| fs::set_permissions(&identity, fs::Permissions::from_mode(0o600)))?;

    for (mode, expected) in [
        (0o755, "unsafe-filesystem-permissions"),
        (0o700, "invalid-identity"),
    ] {
        fs::set_permissions(&identities, fs::Permissions::from_mode(mode))?;
        for command in [vec!["init"], vec!["vault", "init"]] {
            let output = jury_command(&repository, &data, &state)
                .arg("--json")
                .args(command)
                .stdin(Stdio::null())
                .output()?;
            assert_eq!(output.status.code(), Some(1));
            assert!(output.stdout.is_empty());
            let error: serde_json::Value = serde_json::from_slice(&output.stderr)?;
            assert_eq!(error["error"]["code"], expected);
            assert!(
                !error["error"]["message"]
                    .as_str()
                    .ok_or("missing diagnostic")?
                    .contains("jury identity init")
            );
        }
    }
    assert!(!data.join("jury/vaults").exists());
    assert!(!state.exists());
    Ok(())
}

#[test]
fn named_identity_setup_guidance_leads_to_a_working_vault() -> TestResult {
    let temporary = tempfile::tempdir()?;
    let repository = temporary.path().join("repository");
    let data = temporary.path().join("data");
    let state = temporary.path().join("state");
    create_repository(&repository)?;
    let environment = [("JURY_IDENTITY", "ExamplePrincipal")];
    let missing = run_with_environment(
        &repository,
        &data,
        &state,
        &["--json", "init"],
        b"",
        &environment,
    )?;
    assert_eq!(missing.status.code(), Some(3));
    success_json(run_with_environment(
        &repository,
        &data,
        &state,
        &[
            "--json",
            "--passphrase-stdin",
            "--allow-degraded-protection",
            "identity",
            "init",
        ],
        b"ExamplePass1234\nExamplePass1234\n",
        &environment,
    )?)?;
    let created = success_json(run_with_environment(
        &repository,
        &data,
        &state,
        &[
            "--json",
            "--passphrase-stdin",
            "--allow-degraded-protection",
            "init",
        ],
        b"ExamplePass1234\n",
        &environment,
    )?)?;
    assert_eq!(created["operation"], "vault-init");
    assert_eq!(created["local_state"], "initialized");
    let status = success_json(run(
        &repository,
        &data,
        &state,
        &["--json", "vault", "status"],
        b"",
    )?)?;
    assert_eq!(status["vault_id"], created["vault_id"]);
    assert_eq!(status["owner_count"], 1);
    assert!(
        data.join("jury/identities/ExamplePrincipal.identity.json")
            .is_file()
    );
    assert!(!data.join("jury/identities/default.identity.json").exists());
    Ok(())
}

pub(super) fn create_visible_item(paths: NativePaths<'_>) -> TestResult {
    for (arguments, input) in [
        (
            vec!["item", "create", "ExampleVisibleItem", "--allow-direct"],
            b"OwnerPassphrase1234\n".as_slice(),
        ),
        (
            vec![
                "field",
                "set",
                "ExampleVisibleItem",
                "ExampleVisibleField",
                "--value-stdin",
            ],
            b"OwnerPassphrase1234\nExampleVisibleValue".as_slice(),
        ),
    ] {
        let arguments = [
            vec![
                "--json",
                "--passphrase-stdin",
                "--allow-degraded-protection",
            ],
            arguments,
        ]
        .concat();
        success_json(run(
            paths.repository,
            paths.data,
            paths.state,
            &arguments,
            input,
        )?)?;
    }
    Ok(())
}

pub(super) fn assert_witnessed_item_discovery(
    paths: NativePaths<'_>,
    hidden_id: &str,
    witnessed: bool,
) -> TestResult {
    for (arguments, operation, collection) in [
        (vec!["item", "list"], "item-list", "items"),
        (vec!["access", "list", "--me"], "access-list-me", "items"),
        (vec!["field", "list"], "field-list", "fields"),
        (vec!["vault", "field", "list"], "field-list", "fields"),
    ] {
        let arguments = [
            vec![
                "--json",
                "--passphrase-stdin",
                "--allow-degraded-protection",
            ],
            arguments,
        ]
        .concat();
        let output = run(
            paths.repository,
            paths.data,
            paths.state,
            &arguments,
            b"OwnerPassphrase1234\n",
        )?;
        assert!(output.status.success(), "catalog listing failed");
        let text = String::from_utf8(output.stdout)?;
        let value: serde_json::Value = serde_json::from_str(&text)?;
        assert_eq!(value["operation"], operation);
        assert_eq!(value["count"], if witnessed { 1 } else { 2 });
        let entries = value[collection].as_array().ok_or("missing catalog")?;
        assert_eq!(entries.len(), if witnessed { 1 } else { 2 });
        assert!(
            entries
                .iter()
                .any(|item| item["item"] == "ExampleVisibleItem")
        );
        assert_eq!(
            entries
                .iter()
                .any(|item| item["item"] == "ExampleWitnessedItem"),
            !witnessed
        );
        assert!(!text.contains("ExampleVisibleValue"));
        assert!(!text.contains("ExampleFieldValue"));
        if witnessed {
            assert!(!text.contains(hidden_id));
            assert!(!text.contains("ExampleField\""));
        }
        let expected_keys = if collection == "items" {
            vec![
                "count",
                "inaccessible_items_disclosed",
                "items",
                "ok",
                "operation",
                "principal_id",
            ]
        } else {
            vec![
                "count",
                "fields",
                "inaccessible_items_disclosed",
                "ok",
                "operation",
            ]
        };
        assert_eq!(
            value
                .as_object()
                .ok_or("missing object")?
                .keys()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            expected_keys
        );
    }
    Ok(())
}
