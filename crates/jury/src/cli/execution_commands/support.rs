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

fn map_process_error(error: OwnedProcessTreeError) -> CliError {
    match error {
        OwnedProcessTreeError::Output => CliError::new(
            CliErrorKind::Process,
            "process-output-failed",
            "child output could not be delivered safely",
        ),
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

const fn witnessed_execution_arguments_required() -> CliError {
    CliError::new(
        CliErrorKind::InvalidArguments,
        "witnessed-execution-arguments-required",
        "governed execution requires --checkpoint, --request-out, --receipt, and the exact --witness set; use --direct only for visible unilateral access",
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
