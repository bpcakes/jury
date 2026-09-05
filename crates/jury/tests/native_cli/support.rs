use super::*;

pub(super) type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

pub(super) fn run(
    repository: &Path,
    data: &Path,
    state: &Path,
    arguments: &[&str],
    input: &[u8],
) -> TestResult<Output> {
    run_with_environment(repository, data, state, arguments, input, &[])
}

pub(super) fn jury_command(repository: &Path, data: &Path, state: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_jury"));
    command
        .current_dir(repository)
        .env_clear()
        .env("HOME", data)
        .env("XDG_DATA_HOME", data)
        .env("XDG_STATE_HOME", state);
    command
}

pub(super) fn run_with_environment(
    repository: &Path,
    data: &Path,
    state: &Path,
    arguments: &[&str],
    input: &[u8],
    extra_environment: &[(&str, &str)],
) -> TestResult<Output> {
    let mut command = jury_command(repository, data, state);
    command.envs(extra_environment.iter().copied());
    let mut child = command
        .args(arguments)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let write_result = child
        .stdin
        .take()
        .ok_or("child standard input is unavailable")?
        .write_all(input);
    let output = child.wait_with_output()?;
    // Early rejection may close stdin before the parent finishes writing.
    // Reap the child and preserve its response for the caller's assertions.
    // A successful command or any other write error still fails the helper.
    if let Err(error) = write_result {
        if output.status.success() || error.kind() != std::io::ErrorKind::BrokenPipe {
            return Err(error.into());
        }
    }
    if !output.status.success() {
        eprintln!("jury test command failed: {arguments:?}");
    }
    Ok(output)
}

pub(super) fn success_json(output: Output) -> TestResult<serde_json::Value> {
    if !output.status.success() {
        return Err(format!(
            "command failed: status={:?}, stdout={:?}, stderr={:?}",
            output.status.code(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    assert!(output.stderr.is_empty());
    Ok(serde_json::from_slice(&output.stdout)?)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn register_role_principal(
    repository: &Path,
    data: &Path,
    state: &Path,
    artifacts: &Path,
    name: &str,
    kind: &str,
    witness_share_index: Option<u8>,
    passphrase: &str,
    owner_passphrase: &str,
) -> TestResult<serde_json::Value> {
    let identity_input = format!("{passphrase}\n{passphrase}\n");
    let identity = success_json(run(
        repository,
        data,
        state,
        &[
            "--json",
            "--passphrase-stdin",
            "--allow-degraded-protection",
            "identity",
            "init",
            "--name",
            name,
            "--kind",
            kind,
        ],
        identity_input.as_bytes(),
    )?)?;
    let descriptor = artifacts.join(format!("{name}-descriptor.json"));
    let challenge = artifacts.join(format!("{name}-challenge.json"));
    let proof = artifacts.join(format!("{name}-proof.json"));
    success_json(run(
        repository,
        data,
        state,
        &[
            "--json",
            "--identity",
            name,
            "--passphrase-stdin",
            "--allow-degraded-protection",
            "identity",
            "public",
            "--out",
            descriptor.to_str().ok_or("non-UTF-8 descriptor path")?,
        ],
        format!("{passphrase}\n").as_bytes(),
    )?)?;
    let mut challenge_arguments = vec![
        "--json",
        "--passphrase-stdin",
        "--allow-degraded-protection",
        "principal",
        "challenge",
        "--from",
        descriptor.to_str().ok_or("non-UTF-8 descriptor path")?,
        "--out",
        challenge.to_str().ok_or("non-UTF-8 challenge path")?,
    ];
    let witness_share_index_text = witness_share_index.map(|index| index.to_string());
    if let Some(index) = witness_share_index_text.as_deref() {
        challenge_arguments.extend(["--witness-share-index", index]);
    }
    success_json(run(
        repository,
        data,
        state,
        &challenge_arguments,
        format!("{owner_passphrase}\n").as_bytes(),
    )?)?;
    success_json(run(
        repository,
        data,
        state,
        &[
            "--json",
            "--identity",
            name,
            "--passphrase-stdin",
            "--allow-degraded-protection",
            "identity",
            "prove",
            "--challenge",
            challenge.to_str().ok_or("non-UTF-8 challenge path")?,
            "--out",
            proof.to_str().ok_or("non-UTF-8 proof path")?,
        ],
        format!("{passphrase}\n").as_bytes(),
    )?)?;
    let added = success_json(run(
        repository,
        data,
        state,
        &[
            "--json",
            "--passphrase-stdin",
            "--allow-degraded-protection",
            "principal",
            "add",
            "--from",
            descriptor.to_str().ok_or("non-UTF-8 descriptor path")?,
            "--proof",
            proof.to_str().ok_or("non-UTF-8 proof path")?,
        ],
        format!("{owner_passphrase}\n").as_bytes(),
    )?)?;
    assert_eq!(added["operation"], "principal-add");
    assert_eq!(added["vault_changed"], true);
    Ok(identity)
}
