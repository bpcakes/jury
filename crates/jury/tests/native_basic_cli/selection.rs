use super::*;

#[test]
fn invalid_root_overrides_have_actionable_value_free_errors() -> TestResult {
    let native = NativeHome::new()?;
    native.initialize()?;
    for (variable, code, arguments) in [
        (
            "JURY_IDENTITY_HOME",
            "invalid-identity-selection",
            ["identity", "list"],
        ),
        (
            "JURY_STATE_HOME",
            "invalid-state-selection",
            ["vault", "status"],
        ),
    ] {
        for value in ["", "ExampleRelative", "/Example/../Other"] {
            // Linux retains its existing empty-override fallbacks.
            if cfg!(target_os = "linux") && value.is_empty() {
                continue;
            }
            let output = native
                .command()
                .env(variable, value)
                .arg("--json")
                .args(arguments)
                .output()?;
            assert_eq!(output.status.code(), Some(2));
            assert!(output.stdout.is_empty());
            let error: Value = serde_json::from_slice(&output.stderr)?;
            assert_eq!(error["error"]["code"], code);
            let message = error["error"]["message"]
                .as_str()
                .ok_or("missing error message")?;
            assert!(message.contains(variable));
            if !value.is_empty() {
                assert!(!message.contains(value));
            }
        }
    }
    Ok(())
}

#[test]
fn missing_home_has_selection_errors_and_explicit_roots_still_work() -> TestResult {
    let native = NativeHome::new()?;
    native.initialize()?;
    for (arguments, code) in [
        (
            vec![
                "--home",
                text(&native.data().join("vaults/default"))?,
                "identity",
                "list",
            ],
            "invalid-identity-selection",
        ),
        (
            vec!["--global", "vault", "status"],
            "invalid-home-selection",
        ),
        (
            vec![
                "--home",
                text(&native.data().join("vaults/default"))?,
                "vault",
                "status",
            ],
            "invalid-state-selection",
        ),
    ] {
        let output = native
            .command()
            .env_remove("HOME")
            .arg("--json")
            .args(arguments)
            .output()?;
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        let error: Value = serde_json::from_slice(&output.stderr)?;
        assert_eq!(error["error"]["code"], code);
    }
    let output = native
        .command()
        .env_remove("HOME")
        .env("JURY_HOME", native.data().join("vaults/default"))
        .env("JURY_IDENTITY_HOME", native.data().join("identities"))
        .env("JURY_STATE_HOME", native.state())
        .args(["--json", "vault", "status"])
        .output()?;
    success(output)?;
    // JURY_HOME remains a selector with empty-value fallback on both systems.
    let expected = native.run(&["vault", "status"], b"")?;
    let actual = success(
        native
            .command()
            .env("JURY_HOME", "")
            .args(["--json", "vault", "status"])
            .output()?,
    )?;
    assert_eq!(actual, expected);
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn empty_linux_overrides_keep_default_roots() -> TestResult {
    let native = NativeHome::new()?;
    native.initialize()?;
    for (variable, arguments) in [
        ("JURY_STATE_HOME", ["vault", "status"]),
        ("JURY_IDENTITY_HOME", ["identity", "list"]),
    ] {
        let expected = native.run(&arguments, b"")?;
        let actual = success(
            native
                .command()
                .env(variable, "")
                .arg("--json")
                .args(arguments)
                .output()?,
        )?;
        assert_eq!(actual, expected);
    }
    Ok(())
}

#[cfg(target_os = "macos")]
#[test]
fn shared_application_parent_cannot_be_a_vault_home() -> TestResult {
    let native = NativeHome::new()?;
    native.initialize()?;
    let base = native.data();
    // A plausible vault at the shared parent must not make nested private
    // identities or state acceptable. Use a copy of a real initialized vault.
    fs::copy(
        base.join("vaults/default/vault.json"),
        base.join("vault.json"),
    )?;
    for arguments in [["identity", "list"], ["vault", "status"]] {
        let output = native
            .command()
            .args(["--json", "--home", text(&base)?])
            .args(arguments)
            .output()?;
        assert!(!output.status.success());
        let error: Value = serde_json::from_slice(&output.stderr)?;
        assert_eq!(error["error"]["code"], "private-state-overlap");
    }
    Ok(())
}

#[test]
fn invalid_vault_home_names_inputs_without_echoing_path_bytes() -> TestResult {
    use std::os::unix::ffi::OsStringExt as _;
    let native = NativeHome::new()?;
    let mut bytes = b"ExamplePrivateRelative-".to_vec();
    bytes.extend(vec![0xff; 2048]);
    let path = std::ffi::OsString::from_vec(bytes);
    for explicit in [false, true] {
        let mut command = native.command();
        command.arg("--json");
        if explicit {
            command.arg("--home").arg(&path);
        } else {
            command.env("JURY_HOME", &path);
        }
        let output = command.args(["vault", "status"]).output()?;
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        let error: Value = serde_json::from_slice(&output.stderr)?;
        assert_eq!(error["error"]["code"], "invalid-home-selection");
        let message = error["error"]["message"]
            .as_str()
            .ok_or("missing message")?;
        assert!(message.contains("--home") && message.contains("JURY_HOME"));
        assert!(!message.contains("ExamplePrivateRelative"));
        assert!(!message.contains('�'));
    }
    Ok(())
}
