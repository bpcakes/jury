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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExecutionAuthority {
    Direct,
    WitnessedApproved,
}

impl ExecutionAuthority {
    const fn label(self) -> &'static str {
        match self {
            Self::Direct => "direct-unilateral",
            Self::WitnessedApproved => "witnessed-approved",
        }
    }

    const fn is_governed(self) -> bool {
        matches!(self, Self::WitnessedApproved)
    }
}

struct ExecutionEvidence {
    authority: ExecutionAuthority,
    receipt: Option<String>,
    receipt_digest: Option<String>,
    receipt_nonclaim: Option<&'static str>,
}

impl ExecutionEvidence {
    const fn direct() -> Self {
        Self {
            authority: ExecutionAuthority::Direct,
            receipt: None,
            receipt_digest: None,
            receipt_nonclaim: None,
        }
    }
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
    if !arguments.direct {
        return execute_witnessed_prepared(
            cli,
            environment,
            current,
            protection,
            prepared,
            WitnessExecutionFiles {
                checkpoint: arguments.checkpoint.as_deref(),
                request_out: arguments.request_out.as_deref(),
                receipt: arguments.receipt.as_deref(),
                approvals: &arguments.approvals,
                witnesses: &arguments.witnesses,
                allow_insecure_loopback: arguments.allow_insecure_loopback,
                wait_seconds: arguments.wait_seconds,
            },
        );
    }
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
    if !arguments.direct {
        return execute_witnessed_prepared(
            cli,
            environment,
            current,
            protection,
            prepared,
            WitnessExecutionFiles {
                checkpoint: arguments.checkpoint.as_deref(),
                request_out: arguments.request_out.as_deref(),
                receipt: arguments.receipt.as_deref(),
                approvals: &arguments.approvals,
                witnesses: &arguments.witnesses,
                allow_insecure_loopback: arguments.allow_insecure_loopback,
                wait_seconds: arguments.wait_seconds,
            },
        );
    }
    execute_prepared(cli, environment, current, protection, prepared)
}

struct WitnessExecutionFiles<'a> {
    checkpoint: Option<&'a Path>,
    request_out: Option<&'a Path>,
    receipt: Option<&'a Path>,
    approvals: &'a [PathBuf],
    witnesses: &'a [String],
    allow_insecure_loopback: bool,
    wait_seconds: u64,
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
    run_resolved(
        &context,
        prepared,
        resolved,
        operation_id,
        protection,
        ExecutionEvidence::direct(),
    )
}

include!("execution_commands/witnessed.rs");

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
    evidence: ExecutionEvidence,
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
        evidence.authority,
        &environment_values,
        &anonymous_files,
    );
    command
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else if prepared.mode == ExecutionMode::Transparent && !evidence.authority.is_governed() {
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

    if prepared.mode == ExecutionMode::Transparent {
        eprintln!("Authority: {}", evidence.authority.label());
        if let Some(receipt) = &evidence.receipt {
            eprintln!("Receipt: {receipt}");
        }
        if let Some(nonclaim) = evidence.receipt_nonclaim {
            eprintln!("{nonclaim}");
        }
    }

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
    let output = process_result.map_err(map_process_error)?;
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
        authority: evidence.authority.label(),
        receipt: evidence.receipt,
        receipt_digest: evidence.receipt_digest,
        receipt_nonclaim: evidence.receipt_nonclaim,
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
    authority: ExecutionAuthority,
    values: &[(String, Zeroizing<String>)],
    files: &[AnonymousFieldFile],
) {
    match (authority, mode) {
        (ExecutionAuthority::WitnessedApproved, _) => {
            command.env_clear();
        }
        (ExecutionAuthority::Direct, ExecutionMode::Transparent) => {
            for (name, _) in env::vars_os() {
                if is_reserved_execution_environment(name.as_os_str().as_bytes()) {
                    command.env_remove(name);
                }
            }
        }
        (ExecutionAuthority::Direct, ExecutionMode::Brokered) => {
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
}

impl<'a> ExecutionObserver<'a> {
    const fn new(mode: ExecutionMode, signals: &'a mut Signals) -> Self {
        Self { mode, signals }
    }
}

impl OwnedProcessObserver for ExecutionObserver<'_> {
    fn output(&mut self, stream: OwnedProcessOutputStream, bytes: &[u8]) -> std::io::Result<()> {
        if self.mode != ExecutionMode::Transparent {
            return Ok(());
        }
        match stream {
            OwnedProcessOutputStream::Stdout => {
                let mut output = std::io::stdout().lock();
                output.write_all(bytes).and_then(|()| output.flush())
            }
            OwnedProcessOutputStream::Stderr => {
                let mut output = std::io::stderr().lock();
                output.write_all(bytes).and_then(|()| output.flush())
            }
        }
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

include!("execution_commands/support.rs");

include!("execution_commands/tests.rs");
