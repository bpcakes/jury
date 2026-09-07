use super::*;

pub(super) fn resolved_environment(
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

pub(super) fn bytes_to_environment(bytes: &[u8]) -> Result<Zeroizing<String>, CliError> {
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

pub(super) fn prepare_anonymous_files(
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

pub(super) fn clear_cloexec(file: &File) -> Result<(), CliError> {
    let mut flags = fcntl_getfd(file).map_err(|_| process_setup_error())?;
    flags.remove(FdFlags::CLOEXEC);
    fcntl_setfd(file, flags).map_err(|_| process_setup_error())
}

pub(super) fn helper_command(
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

pub(super) fn apply_environment(
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

pub(super) fn is_reserved_execution_environment(name: &[u8]) -> bool {
    name.starts_with(b"JURY_")
}
