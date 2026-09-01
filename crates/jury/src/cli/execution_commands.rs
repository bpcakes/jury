use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{Seek as _, SeekFrom, Write as _};
use std::os::fd::{AsRawFd as _, RawFd};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command as ProcessCommand, Stdio};
use std::time::Duration;

use jury_process::{
    BoundedProcessOutput, OwnedProcessObserver, OwnedProcessOutputStream, OwnedProcessTreeError,
    OwnedProcessTreeOptions, ProcessOutputLimits, ProcessOutputOverflowPolicy,
    ProcessOutputRedaction, ProcessSignal, run_owned_process_tree_with_options,
};
use jury_protected::{ProtectedMemory, StreamingRedactor};
use rustix::fs::{MemfdFlags, Mode, SealFlags, fchmod, fcntl_add_seals, memfd_create};
use rustix::io::{FdFlags, fcntl_getfd, fcntl_setfd};
use signal_hook::consts::signal::{SIGHUP, SIGINT, SIGQUIT, SIGTERM, SIGUSR1, SIGUSR2};
use signal_hook::iterator::Signals;

use super::*;

const MAX_EXEC_ARGUMENTS: usize = 4_096;
const MAX_EXEC_ARGUMENT_BYTES: usize = 1024 * 1024;
const MAX_EXEC_ARGUMENT_LEN: usize = 128 * 1024 - 1;
const MAX_EXEC_BINDINGS: usize = 1_024;
const MAX_EXEC_FILES: usize = 128;
const MAX_EXEC_ITEMS: usize = 10;
const MAX_ENV_FILE_BYTES: usize = 1024 * 1024;
const MAX_ENV_NAME_BYTES: usize = 128;
const MAX_ENV_TOTAL_BYTES: usize = 16 * 1024 * 1024;
const MAX_ENV_VALUE_BYTES: usize = 128 * 1024 - MAX_ENV_NAME_BYTES - 2;
const MAX_BROKER_TIMEOUT_SECONDS: u64 = 24 * 60 * 60;
const MAX_BROKER_OUTPUT_BYTES: usize = 1024 * 1024;

const BROKER_ENV_ALLOWLIST: &[&str] = &[
    "PATH",
    "HOME",
    "USER",
    "LOGNAME",
    "SHELL",
    "TMPDIR",
    "TEMP",
    "TMP",
    "LANG",
    "LC_ALL",
    "LC_COLLATE",
    "LC_CTYPE",
    "LC_MESSAGES",
    "LC_MONETARY",
    "LC_NUMERIC",
    "LC_TIME",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExecutionMode {
    Transparent,
    Brokered,
}

impl ExecutionMode {
    const fn operation(self) -> &'static str {
        match self {
            Self::Transparent => "exec",
            Self::Brokered => "run",
        }
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct FieldReference {
    item: String,
    field: String,
}

enum EnvironmentSource {
    Literal(Zeroizing<Vec<u8>>),
    Field(FieldReference),
}

struct EnvironmentBinding {
    name: String,
    source: EnvironmentSource,
}

#[derive(Clone)]
struct FileBinding {
    name: String,
    source: FieldReference,
}

struct NormalizedCommand {
    arguments: Vec<OsString>,
    working_directory: PathBuf,
    working_directory_handle: File,
    executable_path: PathBuf,
    executable: File,
}

struct PreparedExecution {
    mode: ExecutionMode,
    command: NormalizedCommand,
    environment: Vec<EnvironmentBinding>,
    files: Vec<FileBinding>,
    stdin: Option<FieldReference>,
    timeout: Option<Duration>,
    output_limit: usize,
    manifest_digest: Digest32,
}

struct ResolvedField {
    value: ProtectedMemory,
    concealed: bool,
}

struct ResolvedExecution {
    values: BTreeMap<FieldReference, ResolvedField>,
    item_ids: Vec<jury_protocol::vault_v1::ItemId>,
}

struct AnonymousFieldFile {
    name: String,
    file: File,
}

pub(super) fn transparent_exec(
    cli: &Cli,
    arguments: &ExecArgs,
    environment: &Environment,
    current: &Path,
    protection: ProtectionPolicy,
) -> Result<CommandOutput, CliError> {
    if cli.json {
        return Err(CliError::new(
            CliErrorKind::InvalidArguments,
            "exec-json-unsupported",
            "transparent exec streams raw child output and does not support --json",
        ));
    }
    let prepared = prepare_transparent(arguments, current)?;
    execute_prepared(cli, environment, current, protection, prepared)
}

pub(super) fn brokered_run(
    cli: &Cli,
    arguments: &RunArgs,
    environment: &Environment,
    current: &Path,
    protection: ProtectionPolicy,
) -> Result<CommandOutput, CliError> {
    let prepared = prepare_brokered(arguments, current)?;
    execute_prepared(cli, environment, current, protection, prepared)
}

pub(super) fn internal_exec(arguments: &InternalExecArgs) -> Result<CommandOutput, CliError> {
    if arguments.executable_fd < 3
        || arguments.working_directory_fd < 3
        || arguments.keep_fds.iter().any(|descriptor| *descriptor < 3)
        || arguments.command.is_empty()
    {
        return Err(invalid_execution_arguments());
    }
    let mut keep_fds = arguments.keep_fds.clone();
    keep_fds.push(arguments.executable_fd);
    keep_fds.sort_unstable();
    keep_fds.dedup();
    close_fds::CloseFdsBuilder::new()
        .keep_fds(&keep_fds)
        .threadsafe(true)
        .cloexecfrom(3);

    let executable = format!("/proc/self/fd/{}", arguments.executable_fd);
    let working_directory = format!("/proc/self/fd/{}", arguments.working_directory_fd);
    let mut command = ProcessCommand::new(executable);
    command
        .arg0(&arguments.command[0])
        .args(&arguments.command[1..])
        .current_dir(working_directory);
    let _error = command.exec();
    Err(CliError::new(
        CliErrorKind::Process,
        "process-exec-failed",
        "the validated child executable could not start",
    ))
}

fn prepare_transparent(
    arguments: &ExecArgs,
    current: &Path,
) -> Result<PreparedExecution, CliError> {
    let environment = arguments
        .env_file
        .as_deref()
        .map(parse_env_file)
        .transpose()?
        .unwrap_or_default();
    let files = parse_file_bindings(&arguments.files, false)?;
    let stdin = arguments
        .stdin
        .as_deref()
        .map(parse_field_reference)
        .transpose()?;
    prepare_execution(
        ExecutionMode::Transparent,
        arguments.command.clone(),
        arguments.cwd.as_deref(),
        current,
        environment,
        files,
        stdin,
        None,
        0,
    )
}

fn prepare_brokered(arguments: &RunArgs, current: &Path) -> Result<PreparedExecution, CliError> {
    if arguments.timeout == 0 || arguments.timeout > MAX_BROKER_TIMEOUT_SECONDS {
        return Err(invalid_execution_arguments());
    }
    if arguments.output_limit == 0 || arguments.output_limit > MAX_BROKER_OUTPUT_BYTES {
        return Err(invalid_execution_arguments());
    }
    let environment = arguments
        .env
        .iter()
        .map(|mapping| parse_field_mapping(mapping, true))
        .collect::<Result<Vec<_>, _>>()?;
    let files = parse_file_bindings(&arguments.files, true)?;
    let stdin = arguments
        .stdin
        .as_deref()
        .map(parse_field_reference)
        .transpose()?;
    prepare_execution(
        ExecutionMode::Brokered,
        arguments.command.clone(),
        arguments.cwd.as_deref(),
        current,
        environment,
        files,
        stdin,
        Some(Duration::from_secs(arguments.timeout)),
        arguments.output_limit,
    )
}

#[allow(clippy::too_many_arguments)]
fn prepare_execution(
    mode: ExecutionMode,
    arguments: Vec<OsString>,
    requested_directory: Option<&Path>,
    current: &Path,
    mut environment: Vec<EnvironmentBinding>,
    mut files: Vec<FileBinding>,
    stdin: Option<FieldReference>,
    timeout: Option<Duration>,
    output_limit: usize,
) -> Result<PreparedExecution, CliError> {
    validate_command(&arguments)?;
    validate_binding_destinations(mode, &environment, &files)?;
    environment.sort_by(|left, right| left.name.as_bytes().cmp(right.name.as_bytes()));
    files.sort_by(|left, right| left.name.as_bytes().cmp(right.name.as_bytes()));
    let command = normalize_command(arguments, requested_directory.unwrap_or(current), current)?;
    let manifest_digest = manifest_digest(
        mode,
        &command,
        &environment,
        &files,
        stdin.as_ref(),
        timeout,
        output_limit,
    )?;
    Ok(PreparedExecution {
        mode,
        command,
        environment,
        files,
        stdin,
        timeout,
        output_limit,
        manifest_digest,
    })
}

fn execute_prepared(
    cli: &Cli,
    environment: &Environment,
    current: &Path,
    protection: ProtectionPolicy,
    prepared: PreparedExecution,
) -> Result<CommandOutput, CliError> {
    let context = load_vault_principal(cli, environment, current, protection)?;
    let operation_id = random_operation_id()?;
    let resolved = match resolve_fields(&context, &prepared, protection) {
        Ok(resolved) => resolved,
        Err(error) => {
            let outcome = if error.kind() == CliErrorKind::AccessDenied {
                AuditOutcome::Denied
            } else {
                AuditOutcome::Failed(jury_core::local_state::AuditFailureStage::Authorization)
            };
            let _ = append_operational_audit_outcome(
                &context,
                AuditAction::ExecuteOrInject,
                &[],
                operation_id,
                outcome,
                protection,
            );
            return Err(error);
        }
    };
    run_resolved(&context, prepared, resolved, operation_id, protection)
}

fn resolve_fields(
    context: &VaultPrincipalContext,
    prepared: &PreparedExecution,
    protection: ProtectionPolicy,
) -> Result<ResolvedExecution, CliError> {
    let references = execution_references(prepared);
    if references.len() > MAX_EXEC_BINDINGS {
        return Err(invalid_execution_arguments());
    }
    let item_names = references
        .iter()
        .map(|reference| reference.item.clone())
        .collect::<BTreeSet<_>>();
    if item_names.len() > MAX_EXEC_ITEMS {
        return Err(invalid_execution_arguments());
    }
    let mut accessible = accessible_items_by_name(context)?;
    if item_names.iter().any(|name| !accessible.contains_key(name)) {
        return Err(item_unavailable());
    }

    let mut values = BTreeMap::new();
    let mut item_ids = Vec::new();
    let mut total_value_bytes = 0_usize;
    for item_name in item_names {
        let item = accessible.remove(&item_name).ok_or_else(item_unavailable)?;
        let item_id = context.vault.items[item.envelope_index].item_id;
        let mut state = open_item_body(context, &item, Capability::Read)?;
        for reference in references
            .iter()
            .filter(|reference| reference.item == item_name)
        {
            let Some(field) = state
                .fields
                .iter()
                .find(|field| field.name == reference.field)
            else {
                state.clear_sensitive();
                return Err(field_unavailable());
            };
            total_value_bytes = match total_value_bytes.checked_add(field.value.len()) {
                Some(total) if total <= MAX_ENV_TOTAL_BYTES => total,
                _ => {
                    state.clear_sensitive();
                    return Err(invalid_execution_arguments());
                }
            };
            let value = match protect(field.value.as_bytes(), protection) {
                Ok(value) => value,
                Err(error) => {
                    state.clear_sensitive();
                    return Err(error);
                }
            };
            values.insert(
                reference.clone(),
                ResolvedField {
                    value,
                    concealed: field.kind == ItemFieldKind::Concealed,
                },
            );
        }
        state.clear_sensitive();
        item_ids.push(item_id);
    }
    Ok(ResolvedExecution { values, item_ids })
}

fn run_resolved(
    context: &VaultPrincipalContext,
    prepared: PreparedExecution,
    mut resolved: ResolvedExecution,
    operation_id: Digest32,
    protection: ProtectionPolicy,
) -> Result<CommandOutput, CliError> {
    let redactor = StreamingRedactor::from_protected_values(
        resolved
            .values
            .values()
            .filter(|field| field.concealed)
            .map(|field| &field.value),
    )
    .map_err(|_| redaction_error())?;
    let environment_values = resolved_environment(&prepared.environment, &resolved.values)?;
    let anonymous_files = prepare_anonymous_files(&prepared.files, &resolved.values)?;
    let stdin = prepared
        .stdin
        .as_ref()
        .map(|reference| {
            resolved
                .values
                .remove(reference)
                .map(|field| field.value)
                .ok_or_else(field_unavailable)
        })
        .transpose()?;
    let mut signals = Signals::new([SIGHUP, SIGINT, SIGQUIT, SIGTERM, SIGUSR1, SIGUSR2])
        .map_err(|_| process_setup_error())?;

    clear_cloexec(&prepared.command.executable)?;
    clear_cloexec(&prepared.command.working_directory_handle)?;
    let executable_fd = prepared.command.executable.as_raw_fd();
    let working_directory_fd = prepared.command.working_directory_handle.as_raw_fd();
    let mut command = helper_command(
        &prepared,
        executable_fd,
        working_directory_fd,
        &anonymous_files,
    )?;
    apply_environment(
        &mut command,
        prepared.mode,
        &environment_values,
        &anonymous_files,
    );
    command
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else if prepared.mode == ExecutionMode::Transparent {
            Stdio::inherit()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut observer = ExecutionObserver::new(prepared.mode, &mut signals);
    let mut options = prepared.timeout.map_or_else(
        OwnedProcessTreeOptions::unbounded,
        OwnedProcessTreeOptions::bounded,
    );
    options.limits = if prepared.mode == ExecutionMode::Transparent {
        ProcessOutputLimits {
            stdout: 0,
            stderr: 0,
        }
    } else {
        ProcessOutputLimits {
            stdout: prepared.output_limit,
            stderr: prepared.output_limit,
        }
    };
    options.overflow_policy = ProcessOutputOverflowPolicy::Truncate;
    options.redaction = Some(ProcessOutputRedaction::new(redactor));
    options.stdin = stdin;

    // Keep the pinned executable, protected values, and anonymous files alive
    // until the complete owned process group is terminal.
    let process_result = run_owned_process_tree_with_options(&mut command, options, &mut observer);
    drop(environment_values);
    let outcome = match &process_result {
        Ok(_) => AuditOutcome::Success,
        Err(error) if error.is_cancellation() => AuditOutcome::Cancelled,
        Err(_) => AuditOutcome::Failed(jury_core::local_state::AuditFailureStage::Execution),
    };
    let local_audit_recorded = append_operational_audit_outcome(
        context,
        AuditAction::ExecuteOrInject,
        &resolved.item_ids,
        operation_id,
        outcome,
        protection,
    )
    .is_ok();
    let output =
        process_result.map_err(|error| map_process_error(error, observer.output_failed))?;
    let status = output.portable_status();
    let stdout = output.stdout.unwrap_or(BoundedProcessOutput {
        bytes: Vec::new(),
        truncated: false,
        complete: true,
    });
    let stderr = output.stderr.unwrap_or(BoundedProcessOutput {
        bytes: Vec::new(),
        truncated: false,
        complete: true,
    });
    Ok(CommandOutput::Execution {
        operation: prepared.mode.operation(),
        manifest_digest: hex(prepared.manifest_digest.as_bytes()),
        exit_code: status.code,
        exit_signal: status.signal,
        stdout: stdout.bytes,
        stderr: stderr.bytes,
        stdout_truncated: stdout.truncated,
        stderr_truncated: stderr.truncated,
        streamed: prepared.mode == ExecutionMode::Transparent,
        protection_degraded: context.protection_degraded,
        local_audit_recorded,
    })
}

fn execution_references(prepared: &PreparedExecution) -> BTreeSet<FieldReference> {
    prepared
        .environment
        .iter()
        .filter_map(|binding| match &binding.source {
            EnvironmentSource::Literal(_) => None,
            EnvironmentSource::Field(reference) => Some(reference.clone()),
        })
        .chain(prepared.files.iter().map(|binding| binding.source.clone()))
        .chain(prepared.stdin.iter().cloned())
        .collect()
}

fn resolved_environment(
    bindings: &[EnvironmentBinding],
    values: &BTreeMap<FieldReference, ResolvedField>,
) -> Result<Vec<(String, Zeroizing<String>)>, CliError> {
    let mut resolved = Vec::with_capacity(bindings.len());
    let mut total_bytes = 0_usize;
    for binding in bindings {
        let value = match &binding.source {
            EnvironmentSource::Literal(value) => bytes_to_environment(value)?,
            EnvironmentSource::Field(reference) => {
                let field = values.get(reference).ok_or_else(field_unavailable)?;
                field
                    .value
                    .expose(bytes_to_environment)
                    .map_err(|_| protection_error())??
            }
        };
        total_bytes = total_bytes
            .checked_add(binding.name.len())
            .and_then(|total| total.checked_add(value.len()))
            .ok_or_else(invalid_execution_arguments)?;
        if total_bytes > MAX_ENV_TOTAL_BYTES {
            return Err(invalid_execution_arguments());
        }
        resolved.push((binding.name.clone(), value));
    }
    Ok(resolved)
}

fn bytes_to_environment(bytes: &[u8]) -> Result<Zeroizing<String>, CliError> {
    if bytes.len() > MAX_ENV_VALUE_BYTES {
        return Err(invalid_execution_arguments());
    }
    if bytes.contains(&0) {
        return Err(CliError::new(
            CliErrorKind::InvalidArguments,
            "environment-value-invalid",
            "one selected environment value contains NUL",
        ));
    }
    let text = std::str::from_utf8(bytes).map_err(|_| {
        CliError::new(
            CliErrorKind::InvalidArguments,
            "environment-value-invalid",
            "one selected environment value is not valid UTF-8",
        )
    })?;
    Ok(Zeroizing::new(text.to_owned()))
}

fn prepare_anonymous_files(
    bindings: &[FileBinding],
    values: &BTreeMap<FieldReference, ResolvedField>,
) -> Result<Vec<AnonymousFieldFile>, CliError> {
    let mut prepared = Vec::with_capacity(bindings.len());
    let mut total_bytes = 0_usize;
    for binding in bindings {
        let field = values.get(&binding.source).ok_or_else(field_unavailable)?;
        total_bytes = total_bytes
            .checked_add(field.value.len())
            .ok_or_else(invalid_execution_arguments)?;
        if total_bytes > MAX_ENV_TOTAL_BYTES {
            return Err(invalid_execution_arguments());
        }
        let descriptor = memfd_create(
            "jury-field",
            MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING,
        )
        .map_err(|_| process_setup_error())?;
        let mut file = File::from(descriptor);
        fchmod(&file, Mode::RUSR).map_err(|_| process_setup_error())?;
        field
            .value
            .expose(|bytes| file.write_all(bytes))
            .map_err(|_| protection_error())?
            .map_err(|_| process_setup_error())?;
        file.seek(SeekFrom::Start(0))
            .map_err(|_| process_setup_error())?;
        fcntl_add_seals(
            &file,
            SealFlags::SHRINK | SealFlags::GROW | SealFlags::WRITE | SealFlags::SEAL,
        )
        .map_err(|_| process_setup_error())?;
        clear_cloexec(&file)?;
        prepared.push(AnonymousFieldFile {
            name: binding.name.clone(),
            file,
        });
    }
    Ok(prepared)
}

fn clear_cloexec(file: &File) -> Result<(), CliError> {
    let mut flags = fcntl_getfd(file).map_err(|_| process_setup_error())?;
    flags.remove(FdFlags::CLOEXEC);
    fcntl_setfd(file, flags).map_err(|_| process_setup_error())
}

fn helper_command(
    prepared: &PreparedExecution,
    executable_fd: RawFd,
    working_directory_fd: RawFd,
    files: &[AnonymousFieldFile],
) -> Result<ProcessCommand, CliError> {
    // This adapter is Linux-only and already requires procfs for pinned target
    // and anonymous-file delivery. Re-exec the running image through procfs so
    // replacing Jury's pathname cannot substitute a different descriptor-
    // scrubbing helper between validation and spawn.
    let mut command = ProcessCommand::new("/proc/self/exe");
    command
        .arg("internal-exec")
        .arg("--executable-fd")
        .arg(executable_fd.to_string())
        .arg("--working-directory-fd")
        .arg(working_directory_fd.to_string());
    for descriptor in files.iter().map(|file| file.file.as_raw_fd()) {
        command.arg("--keep-fd").arg(descriptor.to_string());
    }
    command.arg("--").args(&prepared.command.arguments);
    Ok(command)
}

fn apply_environment(
    command: &mut ProcessCommand,
    mode: ExecutionMode,
    values: &[(String, Zeroizing<String>)],
    files: &[AnonymousFieldFile],
) {
    match mode {
        ExecutionMode::Transparent => {
            for (name, _) in env::vars_os() {
                if is_reserved_execution_environment(name.as_os_str().as_bytes()) {
                    command.env_remove(name);
                }
            }
        }
        ExecutionMode::Brokered => {
            command.env_clear();
            for name in BROKER_ENV_ALLOWLIST {
                if let Some(value) = env::var_os(name) {
                    command.env(name, value);
                }
            }
        }
    }
    for (name, value) in values {
        command.env(name, value.as_str());
    }
    for file in files {
        command.env(
            &file.name,
            format!("/proc/self/fd/{}", file.file.as_raw_fd()),
        );
    }
}

fn is_reserved_execution_environment(name: &[u8]) -> bool {
    name.starts_with(b"JURY_")
}

struct ExecutionObserver<'a> {
    mode: ExecutionMode,
    signals: &'a mut Signals,
    output_failed: bool,
}

impl<'a> ExecutionObserver<'a> {
    const fn new(mode: ExecutionMode, signals: &'a mut Signals) -> Self {
        Self {
            mode,
            signals,
            output_failed: false,
        }
    }
}

impl OwnedProcessObserver for ExecutionObserver<'_> {
    fn cancelled(&mut self) -> bool {
        self.output_failed
    }

    fn output(&mut self, stream: OwnedProcessOutputStream, bytes: &[u8]) {
        if self.mode != ExecutionMode::Transparent || self.output_failed {
            return;
        }
        let result = match stream {
            OwnedProcessOutputStream::Stdout => {
                let mut output = std::io::stdout().lock();
                output.write_all(bytes).and_then(|()| output.flush())
            }
            OwnedProcessOutputStream::Stderr => {
                let mut output = std::io::stderr().lock();
                output.write_all(bytes).and_then(|()| output.flush())
            }
        };
        self.output_failed |= result.is_err();
    }

    fn signal(&mut self) -> Option<ProcessSignal> {
        self.signals.pending().find_map(|signal| match signal {
            SIGHUP => Some(ProcessSignal::Hangup),
            SIGINT => Some(ProcessSignal::Interrupt),
            SIGQUIT => Some(ProcessSignal::Quit),
            SIGTERM => Some(ProcessSignal::Terminate),
            SIGUSR1 => Some(ProcessSignal::User1),
            SIGUSR2 => Some(ProcessSignal::User2),
            _ => None,
        })
    }
}

fn parse_env_file(path: &Path) -> Result<Vec<EnvironmentBinding>, CliError> {
    if path == Path::new("-") {
        return Err(invalid_env_file());
    }
    let bytes = read_public_file(path, MAX_ENV_FILE_BYTES).map_err(map_filesystem_error)?;
    let text = std::str::from_utf8(&bytes).map_err(|_| invalid_env_file())?;
    if bytes.contains(&0) {
        return Err(invalid_env_file());
    }
    let mut bindings = Vec::new();
    let mut names = BTreeSet::new();
    let mut total_bytes = 0_usize;
    for raw_line in text.split('\n') {
        let line = raw_line.strip_suffix('\r').unwrap_or(raw_line);
        let trimmed = line.trim_start_matches([' ', '\t']);
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let (name, raw_value) = line.split_once('=').ok_or_else(invalid_env_file)?;
        validate_environment_name(name)?;
        if !names.insert(name.to_owned()) || bindings.len() >= MAX_EXEC_BINDINGS {
            return Err(invalid_env_file());
        }
        let source = if raw_value.starts_with("{{") && raw_value.ends_with("}}") {
            EnvironmentSource::Field(parse_field_reference(&raw_value[2..raw_value.len() - 2])?)
        } else {
            EnvironmentSource::Literal(decode_env_literal(raw_value.as_bytes())?)
        };
        let value_len = match &source {
            EnvironmentSource::Literal(value) => value.len(),
            EnvironmentSource::Field(_) => raw_value.len(),
        };
        total_bytes = total_bytes
            .checked_add(name.len())
            .and_then(|total| total.checked_add(value_len))
            .ok_or_else(invalid_env_file)?;
        if total_bytes > MAX_ENV_TOTAL_BYTES {
            return Err(invalid_env_file());
        }
        bindings.push(EnvironmentBinding {
            name: name.to_owned(),
            source,
        });
    }
    Ok(bindings)
}

fn decode_env_literal(raw: &[u8]) -> Result<Zeroizing<Vec<u8>>, CliError> {
    if raw.iter().any(|byte| matches!(byte, b'$' | b'`')) {
        return Err(invalid_env_file());
    }
    match raw.first() {
        Some(b'\'') => {
            if raw.len() < 2
                || raw.last() != Some(&b'\'')
                || raw[1..raw.len() - 1]
                    .iter()
                    .any(|byte| *byte == b'\'' || byte.is_ascii_control())
            {
                return Err(invalid_env_file());
            }
            Ok(Zeroizing::new(raw[1..raw.len() - 1].to_vec()))
        }
        Some(b'"') => {
            if raw.len() < 2 || raw.last() != Some(&b'"') {
                return Err(invalid_env_file());
            }
            decode_escaped_env(&raw[1..raw.len() - 1], true)
        }
        _ => decode_escaped_env(raw, false),
    }
}

fn decode_escaped_env(raw: &[u8], quoted: bool) -> Result<Zeroizing<Vec<u8>>, CliError> {
    let mut decoded = Zeroizing::new(Vec::with_capacity(raw.len()));
    let mut index = 0;
    while index < raw.len() {
        let byte = raw[index];
        if byte == b'\\' {
            let escaped = raw.get(index + 1).copied().ok_or_else(invalid_env_file)?;
            let value = match escaped {
                b'\\' => b'\\',
                b'n' => b'\n',
                b'r' => b'\r',
                b't' => b'\t',
                b'"' if quoted => b'"',
                b' ' | b'#' | b'\'' | b'"' if !quoted => escaped,
                _ => return Err(invalid_env_file()),
            };
            decoded.push(value);
            index += 2;
            continue;
        }
        if byte.is_ascii_control()
            || (!quoted && matches!(byte, b' ' | b'#' | b'\'' | b'"'))
            || (quoted && byte == b'"')
        {
            return Err(invalid_env_file());
        }
        decoded.push(byte);
        index += 1;
    }
    Ok(decoded)
}

fn parse_file_bindings(values: &[String], brokered: bool) -> Result<Vec<FileBinding>, CliError> {
    if values.len() > MAX_EXEC_FILES {
        return Err(invalid_execution_arguments());
    }
    values
        .iter()
        .map(|mapping| {
            let (name, reference) = split_mapping(mapping)?;
            validate_mapping_name(name, brokered)?;
            Ok(FileBinding {
                name: name.to_owned(),
                source: parse_field_reference(reference)?,
            })
        })
        .collect()
}

fn parse_field_mapping(value: &str, brokered: bool) -> Result<EnvironmentBinding, CliError> {
    let (name, reference) = split_mapping(value)?;
    validate_mapping_name(name, brokered)?;
    Ok(EnvironmentBinding {
        name: name.to_owned(),
        source: EnvironmentSource::Field(parse_field_reference(reference)?),
    })
}

fn split_mapping(value: &str) -> Result<(&str, &str), CliError> {
    let (name, reference) = value
        .split_once('=')
        .ok_or_else(invalid_execution_arguments)?;
    if name.is_empty() || reference.is_empty() || reference.contains('=') {
        return Err(invalid_execution_arguments());
    }
    Ok((name, reference))
}

fn parse_field_reference(value: &str) -> Result<FieldReference, CliError> {
    let (item, field) = value
        .split_once('.')
        .ok_or_else(invalid_execution_arguments)?;
    if item.is_empty() || field.is_empty() || field.contains('.') {
        return Err(invalid_execution_arguments());
    }
    FieldSelector::parse(item.to_owned(), field.to_owned())
        .map_err(|_| invalid_execution_arguments())?;
    Ok(FieldReference {
        item: item.to_owned(),
        field: field.to_owned(),
    })
}

fn validate_binding_destinations(
    mode: ExecutionMode,
    environment: &[EnvironmentBinding],
    files: &[FileBinding],
) -> Result<(), CliError> {
    if environment.len().saturating_add(files.len()) > MAX_EXEC_BINDINGS {
        return Err(invalid_execution_arguments());
    }
    let mut names = BTreeSet::new();
    for name in environment
        .iter()
        .map(|binding| binding.name.as_str())
        .chain(files.iter().map(|binding| binding.name.as_str()))
    {
        validate_mapping_name(name, mode == ExecutionMode::Brokered)?;
        if !names.insert(name) {
            return Err(invalid_execution_arguments());
        }
    }
    Ok(())
}

fn validate_mapping_name(name: &str, brokered: bool) -> Result<(), CliError> {
    validate_environment_name(name)?;
    if is_reserved_execution_environment(name.as_bytes())
        || (brokered && BROKER_ENV_ALLOWLIST.contains(&name))
    {
        return Err(invalid_execution_arguments());
    }
    Ok(())
}

fn validate_environment_name(name: &str) -> Result<(), CliError> {
    let mut bytes = name.as_bytes().iter().copied();
    let Some(first) = bytes.next() else {
        return Err(invalid_execution_arguments());
    };
    if name.len() > MAX_ENV_NAME_BYTES
        || !(first == b'_' || first.is_ascii_alphabetic())
        || bytes.any(|byte| !(byte == b'_' || byte.is_ascii_alphanumeric()))
        || name.starts_with("JURY_")
    {
        return Err(invalid_execution_arguments());
    }
    Ok(())
}

fn validate_command(arguments: &[OsString]) -> Result<(), CliError> {
    if arguments.is_empty() || arguments[0].is_empty() || arguments.len() > MAX_EXEC_ARGUMENTS {
        return Err(invalid_execution_arguments());
    }
    let mut total = 0_usize;
    for argument in arguments {
        let bytes = argument.as_os_str().as_bytes();
        if bytes.len() > MAX_EXEC_ARGUMENT_LEN || bytes.contains(&0) {
            return Err(invalid_execution_arguments());
        }
        total = total
            .checked_add(bytes.len())
            .ok_or_else(invalid_execution_arguments)?;
        if total > MAX_EXEC_ARGUMENT_BYTES {
            return Err(invalid_execution_arguments());
        }
    }
    Ok(())
}

fn normalize_command(
    arguments: Vec<OsString>,
    requested_directory: &Path,
    current: &Path,
) -> Result<NormalizedCommand, CliError> {
    let requested_directory = if requested_directory.is_absolute() {
        requested_directory.to_path_buf()
    } else {
        current.join(requested_directory)
    };
    let working_directory =
        std::fs::canonicalize(requested_directory).map_err(|_| invalid_execution_path())?;
    let working_directory_handle =
        File::open(&working_directory).map_err(|_| invalid_execution_path())?;
    if !working_directory_handle
        .metadata()
        .map_err(|_| invalid_execution_path())?
        .is_dir()
    {
        return Err(invalid_execution_path());
    }
    let executable_path = resolve_executable_path(&arguments[0], &working_directory)?;
    let executable_path =
        std::fs::canonicalize(executable_path).map_err(|_| invalid_execution_path())?;
    let executable = File::open(&executable_path).map_err(|_| invalid_execution_path())?;
    let metadata = executable
        .metadata()
        .map_err(|_| invalid_execution_path())?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o111 == 0 {
        return Err(invalid_execution_path());
    }
    Ok(NormalizedCommand {
        arguments,
        working_directory,
        working_directory_handle,
        executable_path,
        executable,
    })
}

fn resolve_executable_path(
    argument: &OsStr,
    working_directory: &Path,
) -> Result<PathBuf, CliError> {
    let path = Path::new(argument);
    if argument.as_bytes().contains(&b'/') {
        return Ok(if path.is_absolute() {
            path.to_path_buf()
        } else {
            working_directory.join(path)
        });
    }
    let search = env::var_os("PATH").ok_or_else(invalid_execution_path)?;
    for directory in env::split_paths(&search) {
        let candidate = if directory.as_os_str().is_empty() {
            working_directory.join(path)
        } else {
            directory.join(path)
        };
        if candidate
            .metadata()
            .is_ok_and(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
        {
            return Ok(candidate);
        }
    }
    Err(invalid_execution_path())
}

fn manifest_digest(
    mode: ExecutionMode,
    command: &NormalizedCommand,
    environment: &[EnvironmentBinding],
    files: &[FileBinding],
    stdin: Option<&FieldReference>,
    timeout: Option<Duration>,
    output_limit: usize,
) -> Result<Digest32, CliError> {
    let metadata = command
        .executable
        .metadata()
        .map_err(|_| invalid_execution_path())?;
    let mut digest = Sha256::new();
    digest.update(b"jury-v1/execution-manifest\0");
    digest.update([match mode {
        ExecutionMode::Transparent => 1,
        ExecutionMode::Brokered => 2,
    }]);
    digest.update(metadata.dev().to_be_bytes());
    digest.update(metadata.ino().to_be_bytes());
    digest.update(metadata.mode().to_be_bytes());
    digest.update(metadata.len().to_be_bytes());
    update_digest_bytes(&mut digest, command.executable_path.as_os_str().as_bytes())?;
    update_digest_bytes(
        &mut digest,
        command.working_directory.as_os_str().as_bytes(),
    )?;
    let working_directory_metadata = command
        .working_directory_handle
        .metadata()
        .map_err(|_| invalid_execution_path())?;
    digest.update(working_directory_metadata.dev().to_be_bytes());
    digest.update(working_directory_metadata.ino().to_be_bytes());
    digest.update(working_directory_metadata.mode().to_be_bytes());
    for argument in &command.arguments {
        digest.update([0x10]);
        update_digest_bytes(&mut digest, argument.as_os_str().as_bytes())?;
    }
    for binding in environment {
        digest.update([0x20]);
        update_digest_bytes(&mut digest, binding.name.as_bytes())?;
        match &binding.source {
            EnvironmentSource::Literal(value) => {
                digest.update([0x01]);
                digest.update(Sha256::digest(value.as_slice()));
            }
            EnvironmentSource::Field(reference) => {
                digest.update([0x02]);
                update_reference_digest(&mut digest, reference)?;
            }
        }
    }
    for binding in files {
        digest.update([0x30]);
        update_digest_bytes(&mut digest, binding.name.as_bytes())?;
        update_reference_digest(&mut digest, &binding.source)?;
    }
    digest.update([0x40]);
    if let Some(reference) = stdin {
        update_reference_digest(&mut digest, reference)?;
    }
    digest.update([0x50]);
    match timeout {
        Some(timeout) => {
            digest.update([0x01]);
            digest.update(timeout.as_secs().to_be_bytes());
            digest.update(timeout.subsec_nanos().to_be_bytes());
        }
        None => digest.update([0x00]),
    }
    digest.update(
        u64::try_from(output_limit)
            .map_err(|_| invalid_execution_arguments())?
            .to_be_bytes(),
    );
    Ok(Digest32::new(digest.finalize().into()))
}

fn update_reference_digest(
    digest: &mut Sha256,
    reference: &FieldReference,
) -> Result<(), CliError> {
    update_digest_bytes(digest, reference.item.as_bytes())?;
    update_digest_bytes(digest, reference.field.as_bytes())
}

fn update_digest_bytes(digest: &mut Sha256, bytes: &[u8]) -> Result<(), CliError> {
    let length = u32::try_from(bytes.len()).map_err(|_| invalid_execution_arguments())?;
    digest.update(length.to_be_bytes());
    digest.update(bytes);
    Ok(())
}

fn map_process_error(error: OwnedProcessTreeError, output_failed: bool) -> CliError {
    if output_failed {
        return CliError::new(
            CliErrorKind::Process,
            "process-output-failed",
            "child output could not be delivered safely",
        );
    }
    match error {
        OwnedProcessTreeError::TimedOut => CliError::new(
            CliErrorKind::Process,
            "process-timeout",
            "the brokered process tree timed out and was terminated",
        ),
        OwnedProcessTreeError::Stdin => CliError::new(
            CliErrorKind::Process,
            "process-stdin-failed",
            "the selected stdin value could not be delivered completely",
        ),
        OwnedProcessTreeError::Cancelled | OwnedProcessTreeError::CancelledBeforeStart => {
            CliError::new(
                CliErrorKind::Process,
                "process-cancelled",
                "the process tree was cancelled and terminated",
            )
        }
        _ => CliError::new(
            CliErrorKind::Process,
            "process-failed",
            "the process tree failed or could not be cleaned up safely",
        ),
    }
}

const fn invalid_execution_arguments() -> CliError {
    CliError::new(
        CliErrorKind::InvalidArguments,
        "invalid-execution-request",
        "the execution request is invalid or exceeds a supported bound",
    )
}

const fn invalid_env_file() -> CliError {
    CliError::new(
        CliErrorKind::InvalidArguments,
        "invalid-env-file",
        "the restricted execution environment file is invalid",
    )
}

const fn invalid_execution_path() -> CliError {
    CliError::new(
        CliErrorKind::InvalidArguments,
        "invalid-execution-path",
        "the executable or working directory is unavailable or invalid",
    )
}

const fn process_setup_error() -> CliError {
    CliError::new(
        CliErrorKind::Process,
        "process-setup-failed",
        "the protected process delivery channel could not be prepared",
    )
}

const fn redaction_error() -> CliError {
    CliError::new(
        CliErrorKind::InvalidArguments,
        "redaction-setup-failed",
        "the selected concealed values exceed streaming redaction bounds",
    )
}

const fn protection_error() -> CliError {
    CliError::new(
        CliErrorKind::ProtectionUnavailable,
        "protection-unavailable",
        "required protected memory is unavailable",
    )
}

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
