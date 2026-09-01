use std::os::fd::AsRawFd as _;
use std::thread;
use std::time::{Duration, Instant};

use rustix::io::{FdFlags, fcntl_getfd, fcntl_setfd};
use rustix::process::{Pid, Signal, kill_process};

use super::*;

fn assert_recorded_processes_absent(path: &Path) -> TestResult {
    let recorded = fs::read_to_string(path)?;
    let process_ids = recorded
        .lines()
        .map(str::parse::<u32>)
        .collect::<Result<Vec<_>, _>>()?;
    assert!(!process_ids.is_empty());
    for process_id in process_ids {
        assert!(
            !Path::new("/proc").join(process_id.to_string()).exists(),
            "owned process {process_id} survived Jury"
        );
    }
    Ok(())
}

fn assert_tree_does_not_contain(root: &Path, needle: &[u8]) -> TestResult {
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            assert_tree_does_not_contain(&entry.path(), needle)?;
        } else if file_type.is_file() {
            let bytes = fs::read(entry.path())?;
            assert!(!bytes.windows(needle.len()).any(|window| window == needle));
        }
    }
    Ok(())
}

pub(super) fn exercise_successful_execution(
    temporary: &Path,
    repository: &Path,
    data: &Path,
    state: &Path,
) -> TestResult {
    let concealed_set = success_json(run(
        repository,
        data,
        state,
        &[
            "--json",
            "--passphrase-stdin",
            "--allow-degraded-protection",
            "vault",
            "field",
            "set",
            "ExampleItem",
            "ExampleSecret",
            "--concealed",
            "--value-stdin",
        ],
        b"ExamplePass1234\nConcealedValue",
    )?)?;
    assert_eq!(concealed_set["operation"], "field-set");
    assert!(!concealed_set.to_string().contains("ConcealedValue"));

    let binary_set = success_json(run(
        repository,
        data,
        state,
        &[
            "--json",
            "--passphrase-stdin",
            "--allow-degraded-protection",
            "vault",
            "field",
            "set",
            "ExampleItem",
            "ExampleBinary",
            "--value-stdin",
        ],
        b"ExamplePass1234\n\xff\x01\x02\x03",
    )?)?;
    assert_eq!(binary_set["operation"], "field-set");

    let exec_environment = temporary.join("exec.env");
    fs::write(
        &exec_environment,
        b"PUBLIC={{ExampleItem.ExampleField}}\nSECRET={{ExampleItem.ExampleSecret}}\nLITERAL=literal\n",
    )?;
    fs::set_permissions(&exec_environment, fs::Permissions::from_mode(0o644))?;
    let executed = run(
        repository,
        data,
        state,
        &[
            "--passphrase-stdin",
            "--allow-degraded-protection",
            "exec",
            "--env-file",
            exec_environment.to_str().ok_or("non-UTF-8 env path")?,
            "--stdin",
            "ExampleItem.ExampleField",
            "--",
            "/bin/sh",
            "-c",
            "parent_args=$(tr '\\0' '\\n' </proc/$PPID/cmdline); child_args=$(tr '\\0' '\\n' </proc/self/cmdline); case \"$parent_args$child_args\" in *\"$SECRET\"*) exit 91;; esac; read value; printf '%s|%s|%s|%s' \"$PUBLIC\" \"$SECRET\" \"$value\" \"$LITERAL\"; printf '%s' \"$SECRET\" >&2; exit 37",
        ],
        b"ExamplePass1234\n",
    )?;
    assert!(
        !executed
            .stderr
            .windows("ConcealedValue".len())
            .any(|window| window == b"ConcealedValue")
    );
    assert!(
        !executed
            .stderr
            .windows("ExampleValue".len())
            .any(|window| window == b"ExampleValue")
    );
    assert_eq!(
        executed.status.code(),
        Some(37),
        "value-free exec diagnostic: {}",
        String::from_utf8_lossy(&executed.stderr)
    );
    assert_eq!(
        executed.stdout,
        b"ExampleValue|[REDACTED]|ExampleValue|literal"
    );
    assert_eq!(executed.stderr, b"[REDACTED]");
    assert!(
        !executed
            .stdout
            .windows("ConcealedValue".len())
            .any(|window| window == b"ConcealedValue")
    );

    let brokered = success_json(run(
        repository,
        data,
        state,
        &[
            "--json",
            "--passphrase-stdin",
            "--allow-degraded-protection",
            "run",
            "--env",
            "TOKEN=ExampleItem.ExampleSecret",
            "--file",
            "TOKEN_FILE=ExampleItem.ExampleSecret",
            "--stdin",
            "ExampleItem.ExampleField",
            "--timeout",
            "5",
            "--",
            "/bin/sh",
            "-c",
            "printf '%s|' \"$TOKEN\"; cat \"$TOKEN_FILE\"; printf '|'; cat; printf '|core=%s' \"$(ulimit -c)\"",
        ],
        b"ExamplePass1234\n",
    )?)?;
    assert_eq!(brokered["operation"], "run");
    assert_eq!(brokered["exit_code"], 0);
    assert_eq!(brokered["exit_signal"], serde_json::Value::Null);
    assert_eq!(
        brokered["stdout"],
        "[REDACTED]|[REDACTED]|ExampleValue|core=0"
    );
    assert_eq!(brokered["stderr"], "");
    assert_eq!(brokered["authorized_child_may_retain_plaintext"], true);
    assert_eq!(brokered["local_audit_recorded"], true);
    assert!(!brokered.to_string().contains("ConcealedValue"));

    let binary_delivery = success_json(run(
        repository,
        data,
        state,
        &[
            "--json",
            "--passphrase-stdin",
            "--allow-degraded-protection",
            "run",
            "--file",
            "BINARY_FILE=ExampleItem.ExampleBinary",
            "--stdin",
            "ExampleItem.ExampleBinary",
            "--timeout",
            "5",
            "--",
            "/bin/sh",
            "-c",
            "/usr/bin/od -An -v -tx1 \"$BINARY_FILE\"; /usr/bin/od -An -v -tx1",
        ],
        b"ExamplePass1234\n",
    )?)?;
    assert_eq!(binary_delivery["stdout"], " ff 01 02 03\n ff 01 02 03\n");
    assert_eq!(binary_delivery["stdout_truncated"], false);
    Ok(())
}

fn assert_atomic_preflight(
    temporary: &Path,
    repository: &Path,
    data: &Path,
    state: &Path,
) -> TestResult {
    let no_spawn_marker = temporary.join("atomic-no-spawn-marker");
    let denied_execution = run(
        repository,
        data,
        state,
        &[
            "--json",
            "--passphrase-stdin",
            "--allow-degraded-protection",
            "run",
            "--env",
            "PUBLIC=ExampleItem.ExampleField",
            "--env",
            "DENIED=MissingItem.ExampleField",
            "--timeout",
            "5",
            "--",
            "/usr/bin/touch",
            no_spawn_marker
                .to_str()
                .ok_or("non-UTF-8 no-spawn marker path")?,
        ],
        b"ExamplePass1234\n",
    )?;
    assert_eq!(denied_execution.status.code(), Some(6));
    assert!(denied_execution.stdout.is_empty());
    assert!(!no_spawn_marker.exists());
    assert!(
        !denied_execution
            .stderr
            .windows("ExampleValue".len())
            .any(|window| window == b"ExampleValue")
    );
    assert!(
        !denied_execution
            .stderr
            .windows("ConcealedValue".len())
            .any(|window| window == b"ConcealedValue")
    );
    let denied_execution_error: serde_json::Value =
        serde_json::from_slice(&denied_execution.stderr)?;
    assert_eq!(denied_execution_error["error"]["code"], "item-unavailable");

    let invalid_environment_marker = temporary.join("invalid-environment-marker");
    let invalid_environment = run(
        repository,
        data,
        state,
        &[
            "--json",
            "--passphrase-stdin",
            "--allow-degraded-protection",
            "run",
            "--env",
            "BINARY=ExampleItem.ExampleBinary",
            "--timeout",
            "5",
            "--",
            "/usr/bin/touch",
            invalid_environment_marker
                .to_str()
                .ok_or("non-UTF-8 invalid-environment marker path")?,
        ],
        b"ExamplePass1234\n",
    )?;
    assert_eq!(invalid_environment.status.code(), Some(2));
    assert!(invalid_environment.stdout.is_empty());
    assert!(!invalid_environment_marker.exists());
    let invalid_environment_error: serde_json::Value =
        serde_json::from_slice(&invalid_environment.stderr)?;
    assert_eq!(
        invalid_environment_error["error"]["code"],
        "environment-value-invalid"
    );
    Ok(())
}

fn assert_execution_sandbox(
    temporary: &Path,
    repository: &Path,
    data: &Path,
    state: &Path,
) -> TestResult {
    let stripped_environment = run_with_environment(
        repository,
        data,
        state,
        &[
            "--passphrase-stdin",
            "--allow-degraded-protection",
            "exec",
            "--",
            "/bin/sh",
            "-c",
            "test -z \"${JURY_SENTINEL+x}\" && test \"$CUSTOM_INHERITED\" = inherited",
        ],
        b"ExamplePass1234\n",
        &[
            ("JURY_SENTINEL", "reserved-value"),
            ("CUSTOM_INHERITED", "inherited"),
        ],
    )?;
    assert_eq!(stripped_environment.status.code(), Some(0));
    assert!(stripped_environment.stdout.is_empty());
    assert!(stripped_environment.stderr.is_empty());

    let inherited_descriptor_path = temporary.join("inherited-descriptor");
    let inherited_descriptor = fs::File::create(&inherited_descriptor_path)?;
    let descriptor_number = inherited_descriptor.as_raw_fd();
    let mut descriptor_flags = fcntl_getfd(&inherited_descriptor)?;
    descriptor_flags.remove(FdFlags::CLOEXEC);
    fcntl_setfd(&inherited_descriptor, descriptor_flags)?;
    let descriptor_probe = format!("test ! -e /proc/self/fd/{descriptor_number}");
    let descriptor_scrubbed = run(
        repository,
        data,
        state,
        &[
            "--passphrase-stdin",
            "--allow-degraded-protection",
            "exec",
            "--",
            "/bin/sh",
            "-c",
            &descriptor_probe,
        ],
        b"ExamplePass1234\n",
    )?;
    assert_eq!(descriptor_scrubbed.status.code(), Some(0));
    assert!(descriptor_scrubbed.stdout.is_empty());
    assert!(descriptor_scrubbed.stderr.is_empty());
    Ok(())
}

fn assert_output_limit_and_timeout(
    temporary: &Path,
    repository: &Path,
    data: &Path,
    state: &Path,
) -> TestResult {
    let capped = success_json(run(
        repository,
        data,
        state,
        &[
            "--json",
            "--passphrase-stdin",
            "--allow-degraded-protection",
            "run",
            "--output-limit",
            "16",
            "--timeout",
            "5",
            "--",
            "/usr/bin/printf",
            "abcdefghijklmnopqrstuvwxyz",
        ],
        b"ExamplePass1234\n",
    )?)?;
    assert_eq!(capped["stdout"], "abcdefghijklmnop");
    assert_eq!(capped["stdout_truncated"], true);
    assert_eq!(capped["stderr_truncated"], false);

    let timeout_processes = temporary.join("timeout-processes");
    let timeout_started = Instant::now();
    let timed_out = run(
        repository,
        data,
        state,
        &[
            "--json",
            "--passphrase-stdin",
            "--allow-degraded-protection",
            "run",
            "--timeout",
            "1",
            "--",
            "/bin/sh",
            "-c",
            "printf '%s\\n' \"$$\" >\"$1\"; sleep 30 & printf '%s\\n' \"$!\" >>\"$1\"; wait",
            "jury-timeout-probe",
            timeout_processes
                .to_str()
                .ok_or("non-UTF-8 timeout process path")?,
        ],
        b"ExamplePass1234\n",
    )?;
    assert!(timeout_started.elapsed() < Duration::from_secs(30));
    assert_eq!(timed_out.status.code(), Some(1));
    assert!(timed_out.stdout.is_empty());
    let timeout_error: serde_json::Value = serde_json::from_slice(&timed_out.stderr)?;
    assert_eq!(timeout_error["error"]["code"], "process-timeout");
    assert_recorded_processes_absent(&timeout_processes)?;
    Ok(())
}

fn assert_signal_cleanup(
    temporary: &Path,
    repository: &Path,
    data: &Path,
    state: &Path,
) -> TestResult {
    let signal_processes = temporary.join("signal-processes");
    let signal_processes_text = signal_processes
        .to_str()
        .ok_or("non-UTF-8 signal process path")?;
    let mut signal_command = jury_command(repository, data, state);
    let mut signal_parent = signal_command
        .args([
            "--passphrase-stdin",
            "--allow-degraded-protection",
            "exec",
            "--",
            "/bin/sh",
            "-c",
            "printf '%s\\n' \"$$\" >\"$1\"; sleep 30 & printf '%s\\n' \"$!\" >>\"$1\"; wait",
            "jury-signal-probe",
            signal_processes_text,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    signal_parent
        .stdin
        .take()
        .ok_or("signal parent stdin is unavailable")?
        .write_all(b"ExamplePass1234\n")?;
    let signal_deadline = Instant::now() + Duration::from_secs(30);
    while !signal_processes.exists() && Instant::now() < signal_deadline {
        thread::sleep(Duration::from_millis(20));
    }
    if !signal_processes.exists() {
        signal_parent.kill()?;
        let _ = signal_parent.wait();
        return Err("signal test child did not start".into());
    }
    let signal_parent_pid = Pid::from_raw(i32::try_from(signal_parent.id())?)
        .ok_or("invalid signal parent process ID")?;
    kill_process(signal_parent_pid, Signal::TERM)?;
    let signal_output = signal_parent.wait_with_output()?;
    assert!(
        !signal_output
            .stderr
            .windows("ExampleValue".len())
            .any(|window| window == b"ExampleValue")
    );
    assert!(
        !signal_output
            .stderr
            .windows("ConcealedValue".len())
            .any(|window| window == b"ConcealedValue")
    );
    assert_eq!(signal_output.status.code(), Some(143));
    assert_recorded_processes_absent(&signal_processes)?;
    Ok(())
}

fn assert_no_plaintext_residue(
    temporary: &Path,
    repository: &Path,
    data: &Path,
    state: &Path,
) -> TestResult {
    assert_tree_does_not_contain(temporary, b"ConcealedValue")?;
    assert_tree_does_not_contain(temporary, b"ExampleValue")?;

    let fields = success_json(run(
        repository,
        data,
        state,
        &[
            "--json",
            "--passphrase-stdin",
            "--allow-degraded-protection",
            "vault",
            "field",
            "list",
        ],
        b"ExamplePass1234\n",
    )?)?;
    assert_eq!(fields["operation"], "field-list");
    assert_eq!(fields["count"], 3);
    assert_eq!(fields["fields"][0]["item"], "ExampleItem");
    assert_eq!(fields["fields"][0]["field"], "ExampleBinary");
    assert_eq!(fields["fields"][1]["field"], "ExampleField");
    assert_eq!(fields["fields"][2]["field"], "ExampleSecret");
    assert!(!fields.to_string().contains("ExampleValue"));
    Ok(())
}

pub(super) fn exercise_adversarial_execution(
    temporary: &Path,
    repository: &Path,
    data: &Path,
    state: &Path,
) -> TestResult {
    assert_atomic_preflight(temporary, repository, data, state)?;
    assert_execution_sandbox(temporary, repository, data, state)?;
    assert_output_limit_and_timeout(temporary, repository, data, state)?;
    assert_signal_cleanup(temporary, repository, data, state)?;
    assert_no_plaintext_residue(temporary, repository, data, state)
}
