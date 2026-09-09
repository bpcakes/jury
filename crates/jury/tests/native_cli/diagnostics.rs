use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt as _;

use super::*;

#[test]
fn parser_errors_follow_json_contract_without_reflecting_values() -> TestResult {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path();
    let cases = [
        vec!["--json", "ExampleInvalidCommand"],
        vec!["--json"],
        vec!["--json", "--identity"],
        vec![
            "--json",
            "--home",
            "/ExampleHome",
            "--global",
            "vault",
            "status",
        ],
        vec![
            "run",
            "--json",
            "--timeout",
            "ExampleInvalidTimeout",
            "--",
            "/bin/true",
        ],
        vec!["--json", "--ExampleUnknownOption"],
    ];
    for arguments in cases {
        let output = jury_command(root, root, root).args(arguments).output()?;
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        let value: serde_json::Value = serde_json::from_slice(&output.stderr)?;
        assert_eq!(value["ok"], false);
        assert_eq!(value["error"]["code"], "invalid-arguments");
        assert!(value.get("maturity").is_none());
        assert!(value.get("review_status").is_none());
        assert!(value.get("real_secrets_supported").is_none());
        assert!(!String::from_utf8_lossy(&output.stderr).contains("Example"));
    }
    let output = jury_command(root, root, root)
        .args([
            OsString::from("--json"),
            OsString::from_vec(b"ExampleInvalid\xff".to_vec()),
        ])
        .output()?;
    assert_eq!(output.status.code(), Some(2));
    let value: serde_json::Value = serde_json::from_slice(&output.stderr)?;
    assert_eq!(value["error"]["code"], "invalid-arguments");
    assert!(!String::from_utf8_lossy(&output.stderr).contains("Example"));

    Ok(())
}

#[test]
fn child_flags_do_not_select_json_and_domain_errors_stay_structured() -> TestResult {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path();
    let child_flag = jury_command(root, root, root)
        .args(["run", "--timeout", "invalid", "--", "/bin/true", "--json"])
        .output()?;
    assert_eq!(child_flag.status.code(), Some(2));
    assert!(child_flag.stdout.is_empty());
    assert!(serde_json::from_slice::<serde_json::Value>(&child_flag.stderr).is_err());

    let domain_error = jury_command(root, root, root)
        .args(["--json", "--home", "relative", "vault", "status"])
        .output()?;
    assert!(!domain_error.status.success());
    assert!(domain_error.stdout.is_empty());
    let value: serde_json::Value = serde_json::from_slice(&domain_error.stderr)?;
    assert_eq!(value["ok"], false);
    assert!(value.get("maturity").is_none());
    assert!(value.get("review_status").is_none());
    assert!(value.get("real_secrets_supported").is_none());
    Ok(())
}

#[test]
fn explicit_help_and_version_remain_plain_information() -> TestResult {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path();
    for arguments in [
        vec!["--json", "--help"],
        vec!["--json", "--version"],
        vec!["exec", "--help"],
        vec!["run", "--help"],
    ] {
        let is_help = arguments.contains(&"--help");
        let output = jury_command(root, root, root).args(arguments).output()?;
        assert!(output.status.success());
        assert!(output.stderr.is_empty());
        assert!(!output.stdout.is_empty());
        assert!(serde_json::from_slice::<serde_json::Value>(&output.stdout).is_err());
        if is_help {
            let help = String::from_utf8(output.stdout)?;
            assert!(help.contains("Linux"));
            assert!(!help.contains("PRE-ALPHA"));
            assert!(!help.contains("externally unreviewed"));
            assert!(!help.contains("do not use with real secrets"));
        }
    }
    Ok(())
}

#[test]
fn overwrite_help_describes_replacement_and_concurrent_change_checks() -> TestResult {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path();
    for (command, expected) in [
        (
            ["transfer", "export", "--help"],
            "Replace an existing transfer file if it has not changed during export",
        ),
        (
            ["principal", "challenge", "--help"],
            "Replace an existing challenge file, even if its contents differ",
        ),
        (
            ["request", "execute", "--help"],
            "Replace an existing private output file, even if its contents differ",
        ),
    ] {
        let output = jury_command(root, root, root).args(command).output()?;
        assert!(output.status.success());
        assert!(output.stderr.is_empty());
        let help = String::from_utf8(output.stdout)?;
        let help = help.split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(help.contains("--overwrite"));
        assert!(help.contains(expected), "{command:?}: {help}");
        assert!(!help.contains("identical"));
    }
    Ok(())
}

#[test]
fn json_is_a_standalone_flag_without_release_banner_metadata() -> TestResult {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path();
    for invalid_flag in ["--json=true", "--json=false", "--json=ExamplePrivateValue"] {
        let output = jury_command(root, root, root)
            .args([invalid_flag, "identity", "list"])
            .output()?;
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        let value: serde_json::Value = serde_json::from_slice(&output.stderr)?;
        assert_eq!(value["error"]["code"], "invalid-arguments");
        assert!(!String::from_utf8_lossy(&output.stderr).contains("ExamplePrivateValue"));
    }
    let identities = root.join("jury/identities");
    fs::create_dir_all(&identities)?;
    fs::set_permissions(root.join("jury"), fs::Permissions::from_mode(0o700))?;
    fs::set_permissions(&identities, fs::Permissions::from_mode(0o700))?;
    let output = jury_command(root, root, root)
        .args(["--json", "--global", "identity", "list"])
        .output()?;
    let value = success_json(output)?;
    assert!(value.get("maturity").is_none());
    assert!(value.get("review_status").is_none());
    assert!(value.get("real_secrets_supported").is_none());
    Ok(())
}

#[test]
fn parser_exit_status_survives_unwritable_stderr() -> TestResult {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path();
    let output = jury_command(root, root, root)
        .args(["--json", "ExampleInvalidCommand"])
        .stderr(fs::File::open("/dev/null")?)
        .output()?;
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    Ok(())
}
