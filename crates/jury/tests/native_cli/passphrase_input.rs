use super::*;

const VALUE: &[u8] = b"ExampleFieldValue\nwith an exact trailing newline\n";
const OWNER: &str = "ExamplePass1234";
const OTHER: &str = "ExampleOtherPassphrase";
const BACKUP: &str = "ExampleBackupPassphrase";

fn fixture(root: &Path) -> TestResult {
    let repository = root.join("repository");
    fs::create_dir(&repository)?;
    fs::create_dir(root.join("private"))?;
    fs::set_permissions(root.join("private"), fs::Permissions::from_mode(0o700))?;
    assert!(
        Command::new("git")
            .args(["init", "--quiet"])
            .arg(&repository)
            .status()?
            .success()
    );
    let paths = NativePaths {
        repository: &repository,
        data: &root.join("data"),
        state: &root.join("state"),
    };
    initialize_identity(paths)?;
    initialize_vault(paths)?;
    create_direct_item(paths)?;
    Ok(())
}

fn invoke(root: &Path, args: &[&str], input: &[u8], env: &[(&str, &str)]) -> TestResult<Output> {
    let result = run_with_environment(
        &root.join("repository"),
        &root.join("data"),
        &root.join("state"),
        args,
        input,
        env,
    )?;
    for private in [OWNER.as_bytes(), OTHER.as_bytes(), BACKUP.as_bytes(), VALUE] {
        for output in [&result.stdout, &result.stderr] {
            assert!(
                !output.windows(private.len()).any(|bytes| bytes == private),
                "private input appeared in CLI metadata"
            );
        }
    }
    if !result.status.success() {
        eprintln!(
            "safe CLI diagnostic: {}",
            String::from_utf8_lossy(&result.stderr)
        );
    }
    Ok(result)
}

#[test]
fn strict_passphrase_capture_reports_established_protection() -> TestResult {
    let temporary = tempfile::tempdir()?;
    let repository = temporary.path().join("repository");
    fs::create_dir(&repository)?;
    fs::create_dir(repository.join(".git"))?;
    fs::write(repository.join(".git/HEAD"), b"ref: refs/heads/main\n")?;
    // Capture and its irreversible process controls run inside the CLI child.
    let created = success_json(run(
        &repository,
        &temporary.path().join("data"),
        &temporary.path().join("state"),
        &["--json", "--passphrase-stdin", "identity", "init"],
        b"ExamplePass1234\nExamplePass1234\n",
    )?)?;
    assert_eq!(created["protection_degraded"], false);
    Ok(())
}

#[test]
fn non_terminal_passphrase_requires_explicit_opt_in() -> TestResult {
    use std::io::Seek as _;

    let temporary = tempfile::tempdir()?;
    let repository = temporary.path().join("repository");
    fs::create_dir(&repository)?;
    fs::create_dir(repository.join(".git"))?;
    fs::write(
        repository.join(".git").join("HEAD"),
        [b"ref: refs".as_slice(), b"/heads/main\n"].concat(),
    )?;
    let output = run(
        &repository,
        &temporary.path().join("data"),
        &temporary.path().join("state"),
        &["--json", "--allow-degraded-protection", "identity", "init"],
        // The pipe is non-terminal even when empty. Opt-in must be checked
        // before attempting a read, so no passphrase delivery is expected.
        b"",
    )?;
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let error: serde_json::Value = serde_json::from_slice(&output.stderr)?;
    assert_eq!(error["error"]["code"], "passphrase-input-opt-in-required");

    // A populated non-terminal source must remain unread. Cloned File handles
    // share a cursor, making premature reads observable without a pipe race.
    let mut input = tempfile::tempfile()?;
    input.write_all(b"ExamplePass1234\nExamplePass1234\n")?;
    input.rewind()?;
    let output = jury_command(
        &repository,
        &temporary.path().join("data"),
        &temporary.path().join("state"),
    )
    .args(["--json", "--allow-degraded-protection", "identity", "init"])
    .stdin(input.try_clone()?)
    .output()?;
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let error: serde_json::Value = serde_json::from_slice(&output.stderr)?;
    assert_eq!(error["error"]["code"], "passphrase-input-opt-in-required");
    assert_eq!(input.stream_position()?, 0, "input read before opt-in");
    Ok(())
}

#[test]
fn explicit_passphrase_stdin_preserves_field_bytes_with_inherited_sources() -> TestResult {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path();
    fixture(root)?;
    let mutation = [
        "--json",
        "--allow-degraded-protection",
        "--passphrase-stdin",
        "vault",
        "field",
        "set",
        "ExampleItem",
        "ExampleField",
        "--value-stdin",
    ];
    let input = [format!("{OWNER}\n").as_bytes(), VALUE].concat();
    // Equal, different, and absent environment values must all leave the same
    // exact field bytes after explicit stdin selection, on creation and update.
    for (index, environment) in [Some(OWNER), Some(OTHER), None].into_iter().enumerate() {
        let env = environment.map(|value| [("JURY_IDENTITY_PASSPHRASE", value)]);
        assert!(
            invoke(
                root,
                &mutation,
                &input,
                env.as_ref().map_or(&[], |value| value.as_slice())
            )?
            .status
            .success()
        );
        let out = root.join("private").join(format!("field-{index}"));
        let out_arg = out.to_str().ok_or("non-UTF-8 output path")?;
        assert!(
            invoke(
                root,
                &[
                    "--json",
                    "--allow-degraded-protection",
                    "read",
                    "ExampleItem",
                    "ExampleField",
                    "--direct",
                    "--out",
                    out_arg
                ],
                b"",
                &[("JURY_IDENTITY_PASSPHRASE", OWNER)]
            )?
            .status
            .success()
        );
        assert!(
            fs::read(out)? == VALUE,
            "the passphrase line changed the stored field bytes"
        );
    }
    // Explicit invalid input must not fall back to a valid inherited identity.
    let before = fs::read(root.join("repository/.jury/vault.json"))?;
    let refused = invoke(
        root,
        &mutation,
        format!("{OTHER}\nExampleReplacement").as_bytes(),
        &[("JURY_IDENTITY_PASSPHRASE", OWNER)],
    )?;
    assert!(!refused.status.success());
    assert!(refused.stdout.is_empty());
    let error: serde_json::Value = serde_json::from_slice(&refused.stderr)?;
    assert_eq!(error["error"]["code"], "identity-authentication-failed");
    assert!(
        fs::read(root.join("repository/.jury/vault.json"))? == before,
        "failed authentication mutated the vault"
    );

    // Environment-only input remains supported and consumes no field bytes.
    let without_flag = mutation
        .into_iter()
        .filter(|arg| *arg != "--passphrase-stdin")
        .collect::<Vec<_>>();
    assert!(
        invoke(
            root,
            &without_flag,
            VALUE,
            &[("JURY_IDENTITY_PASSPHRASE", OWNER)]
        )?
        .status
        .success()
    );
    let out = root.join("private/environment-only-field");
    assert!(
        invoke(
            root,
            &[
                "--json",
                "--allow-degraded-protection",
                "--passphrase-stdin",
                "read",
                "ExampleItem",
                "ExampleField",
                "--direct",
                "--out",
                out.to_str().ok_or("non-UTF-8 output")?
            ],
            format!("{OWNER}\n").as_bytes(),
            &[]
        )?
        .status
        .success()
    );
    assert!(
        fs::read(out)? == VALUE,
        "environment-only input consumed field bytes"
    );
    Ok(())
}

#[test]
fn explicit_stdin_owns_backup_and_restored_identity_prompts() -> TestResult {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path();
    fixture(root)?;
    let environment = [
        ("JURY_IDENTITY_PASSPHRASE", OTHER),
        ("JURY_BACKUP_PASSPHRASE", OTHER),
        ("JURY_NEW_PASSPHRASE", OTHER),
    ];
    let backup = root.join("private/ExampleVault.backup");
    let backup_arg = backup.to_str().ok_or("non-UTF-8 backup")?;
    let incomplete_backup = root.join("private/incomplete.backup");
    let incomplete = invoke(
        root,
        &[
            "--json",
            "--allow-degraded-protection",
            "--passphrase-stdin",
            "backup",
            "create",
            "--out",
            incomplete_backup.to_str().ok_or("non-UTF-8 backup")?,
        ],
        format!("{OWNER}\n").as_bytes(),
        &environment,
    )?;
    assert!(incomplete.stdout.is_empty());
    let error: serde_json::Value = serde_json::from_slice(&incomplete.stderr)?;
    assert_eq!(incomplete.status.code(), Some(2));
    assert_eq!(error["error"]["code"], "passphrase-input-incomplete");
    assert!(
        !incomplete_backup.exists(),
        "incomplete stdin published a backup"
    );
    assert!(
        invoke(
            root,
            &[
                "--json",
                "--allow-degraded-protection",
                "--passphrase-stdin",
                "backup",
                "create",
                "--out",
                backup_arg
            ],
            format!("{OWNER}\n{BACKUP}\n{BACKUP}\n").as_bytes(),
            &environment
        )?
        .status
        .success()
    );
    // Verify without inherited sources to prove which passphrase sealed it.
    assert!(
        invoke(
            root,
            &[
                "--json",
                "--allow-degraded-protection",
                "--passphrase-stdin",
                "backup",
                "verify",
                "--in",
                backup_arg
            ],
            format!("{BACKUP}\n{OWNER}\n").as_bytes(),
            &[]
        )?
        .status
        .success()
    );
    let status = success_json(invoke(root, &["--json", "vault", "status"], b"", &[])?)?;
    let genesis = status["genesis_fingerprint"]
        .as_str()
        .ok_or("missing source genesis")?;
    let recovery = root.join("recovery");
    fs::create_dir(&recovery)?;
    fs::set_permissions(&recovery, fs::Permissions::from_mode(0o700))?;
    for parent in ["vault-parent", "identity-parent", "state-parent"] {
        fs::create_dir(recovery.join(parent))?;
        fs::set_permissions(recovery.join(parent), fs::Permissions::from_mode(0o700))?;
    }
    let home = recovery.join("vault-parent/vault");
    let identity = recovery.join("identity-parent/owner.identity");
    let state = recovery.join("state-parent/state");
    let descriptor = root.join("private/owner.public.json");
    assert!(
        invoke(
            root,
            &[
                "--json",
                "--allow-degraded-protection",
                "--passphrase-stdin",
                "--home",
                home.to_str().ok_or("non-UTF-8 home")?,
                "--expected-genesis",
                genesis,
                "backup",
                "restore",
                "--in",
                backup_arg,
                "--identity-out",
                identity.to_str().ok_or("non-UTF-8 identity")?,
                "--state-out",
                state.to_str().ok_or("non-UTF-8 state")?
            ],
            format!("{BACKUP}\n{OWNER}\n{OWNER}\n").as_bytes(),
            &environment
        )?
        .status
        .success()
    );
    assert!(
        invoke(
            root,
            &[
                "--json",
                "--allow-degraded-protection",
                "--passphrase-stdin",
                "--identity-file",
                identity.to_str().ok_or("non-UTF-8 identity")?,
                "identity",
                "public",
                "--out",
                descriptor.to_str().ok_or("non-UTF-8 descriptor")?
            ],
            format!("{OWNER}\n").as_bytes(),
            &[]
        )?
        .status
        .success()
    );
    Ok(())
}
#[cfg(target_os = "linux")]
#[test]
fn passphrase_read_leaves_exact_inherited_stdin_for_exec_child() -> TestResult {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path();
    fixture(root)?;
    assert!(
        invoke(
            root,
            &[
                "--json",
                "--allow-degraded-protection",
                "--passphrase-stdin",
                "vault",
                "field",
                "set",
                "ExampleItem",
                "ExampleField",
                "--value-stdin",
            ],
            &[format!("{OWNER}\n").as_bytes(), VALUE].concat(),
            &[]
        )?
        .status
        .success()
    );
    let env_file = root.join("private/child.env");
    fs::write(&env_file, b"TOKEN={{ExampleItem.ExampleField}}\n")?;
    fs::set_permissions(&env_file, fs::Permissions::from_mode(0o600))?;
    // The suffix fits in std's input buffer and would be lost on child inheritance.
    // No secret field is printed by cat.
    let payload = (0..4096)
        .map(|index| (index % 251) as u8)
        .collect::<Vec<_>>();
    let result = invoke(
        root,
        &[
            "--allow-degraded-protection",
            "--passphrase-stdin",
            "exec",
            "--direct",
            "--env-file",
            env_file.to_str().ok_or("non-UTF-8 environment path")?,
            "--",
            "/bin/cat",
        ],
        &[format!("{OWNER}\n").as_bytes(), &payload].concat(),
        &[("JURY_IDENTITY_PASSPHRASE", OTHER)],
    )?;
    assert!(result.status.success());
    assert!(
        result.stdout == payload,
        "passphrase reading consumed or changed child stdin"
    );
    Ok(())
}
