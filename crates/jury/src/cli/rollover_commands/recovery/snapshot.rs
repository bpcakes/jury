use super::*;

const MAX_SNAPSHOT_BYTES: usize = 64 * 1024;
const MAX_LOCAL_BYTES: usize = 32 * 1024 * 1024;

/// Runtime recovery control: durable byte hashes and caller-selected paths
/// prevent a partial publication from regenerating a different candidate.
/// Payload copies live beside the private backup, never in the vault home.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::cli::rollover_commands) struct Snapshot {
    version: u16,
    out: PathBuf,
    backup_out: PathBuf,
    transfer_out: PathBuf,
    state_root: PathBuf,
    prefix: String,
    pub(in crate::cli::rollover_commands) source_digest: Digest32,
    vault_digest: Digest32,
    hashes: BTreeMap<String, Digest32>,
    pub(in crate::cli::rollover_commands) registration_checkpoint: Option<VaultPolicyCheckpointV1>,
}

pub(in crate::cli::rollover_commands) struct SavedOutputs {
    pub(super) backup: Vec<u8>,
    pub(super) transfer: Vec<u8>,
    pub(super) audit: Vec<u8>,
    pub(super) checkpoint: Vec<u8>,
    pub(super) receipts: Vec<u8>,
}

impl Snapshot {
    pub(in crate::cli::rollover_commands) fn create(
        request: &RolloverPublication<'_>,
    ) -> Result<Self, CliError> {
        let hashes = payloads(request)
            .into_iter()
            .map(|(name, bytes)| (name.into(), sha256_digest(bytes)))
            .collect();
        let value = Self {
            version: 1,
            out: request.arguments.out.clone(),
            backup_out: request.arguments.backup_out.clone(),
            transfer_out: request.arguments.transfer_out.clone(),
            state_root: request.targets.state_root.clone(),
            prefix: format!(
                ".jury-rollover-{}",
                hex(request.vault.header.vault_id.as_bytes())
            ),
            source_digest: sha256_digest(request.source_bytes),
            vault_digest: sha256_digest(request.vault_bytes),
            hashes,
            registration_checkpoint: request.registration.checkpoint().cloned(),
        };
        value.bytes()?;
        Ok(value)
    }

    pub(in crate::cli::rollover_commands) fn save(
        &self,
        root: &HardenedStateRoot,
        request: &RolloverPublication<'_>,
    ) -> Result<(), CliError> {
        for (name, bytes) in payloads(request) {
            let name = self.name(name);
            let target = request
                .targets
                .backup_root
                .preview_private_file(Path::new(&name))
                .map_err(map_filesystem_error)?;
            if target.destination_exists() {
                return Err(incomplete_rollover());
            }
            let prepared = PreparedPrivateFile::prepare_bounded_private_bytes_if_unchanged(
                target,
                bytes,
                bytes.len(),
                false,
            )
            .map_err(map_filesystem_error)?;
            require_synced(prepared.publish().map_err(map_filesystem_error)?)?;
            if request
                .targets
                .backup_root
                .read_private_file(Path::new(&name), bytes.len())
                .map_err(map_filesystem_error)?
                != bytes
            {
                return Err(incomplete_rollover());
            }
        }
        registration::publish_private(root, PENDING_OUTPUTS, &self.bytes()?, request.protection)
    }

    pub(in crate::cli::rollover_commands) fn read(
        root: &HardenedStateRoot,
    ) -> Result<Self, CliError> {
        Self::read_if_present(root)?.ok_or_else(incomplete_rollover)
    }

    pub(super) fn read_if_present(root: &HardenedStateRoot) -> Result<Option<Self>, CliError> {
        let Some(bytes) = read_primary_or_cleanup(root, PENDING_OUTPUTS, MAX_SNAPSHOT_BYTES)?
        else {
            return Ok(None);
        };
        let snapshot: Self = serde_json::from_slice(&bytes).map_err(|_| incomplete_rollover())?;
        if snapshot.version != 1
            || snapshot.bytes()? != bytes
            || snapshot
                .hashes
                .keys()
                .map(String::as_str)
                .collect::<Vec<_>>()
                != ["audit", "backup", "checkpoint", "receipts", "transfer"]
        {
            return Err(incomplete_rollover());
        }
        Ok(Some(snapshot))
    }

    pub(in crate::cli::rollover_commands) fn validate_paths(
        &self,
        arguments: &VaultRolloverArgs,
        state_root: &Path,
    ) -> Result<(), CliError> {
        if self.out != arguments.out
            || self.backup_out != arguments.backup_out
            || self.transfer_out != arguments.transfer_out
            || self.state_root != state_root
        {
            return Err(rollover_target_error());
        }
        Ok(())
    }

    pub(in crate::cli::rollover_commands) fn read_vault(
        &self,
        root: &HardenedStateRoot,
    ) -> Result<Vec<u8>, CliError> {
        let bytes = match read_primary_or_cleanup(root, PENDING_ROLLOVER, MAX_VAULT_BYTES)? {
            Some(bytes) => bytes,
            None => root
                .read_private_file(Path::new("vault.json"), MAX_VAULT_BYTES)
                .map_err(map_filesystem_error)?,
        };
        let vault = VaultFileV1::parse(&bytes).map_err(|_| invalid_vault())?;
        if sha256_digest(&bytes) != self.vault_digest
            || self.prefix != format!(".jury-rollover-{}", hex(vault.header.vault_id.as_bytes()))
        {
            return Err(incomplete_rollover());
        }
        Ok(bytes)
    }

    pub(in crate::cli::rollover_commands) fn load(
        &self,
        backup_root: &HardenedStateRoot,
        state: &VaultStateDirectory,
        principal: PrincipalId,
        arguments: &VaultRolloverArgs,
    ) -> Result<SavedOutputs, CliError> {
        let locked = state.try_lock().map_err(|_| local_state_error())?;
        Ok(SavedOutputs {
            backup: self.read_payload(backup_root, "backup", MAX_BACKUP_ENVELOPE_BYTES, || {
                read_private_file(&arguments.backup_out, MAX_BACKUP_ENVELOPE_BYTES)
                    .map_err(map_filesystem_error)
            })?,
            transfer: self.read_payload(backup_root, "transfer", MAX_TRANSFER_BYTES, || {
                read_public_file(&arguments.transfer_out, MAX_TRANSFER_BYTES)
                    .map_err(map_filesystem_error)
            })?,
            audit: self.read_payload(backup_root, "audit", MAX_LOCAL_BYTES, || {
                locked
                    .read(principal.as_bytes(), PrincipalStateFile::Audit)
                    .map_err(map_filesystem_error)
            })?,
            checkpoint: self.read_payload(backup_root, "checkpoint", MAX_LOCAL_BYTES, || {
                locked
                    .read(principal.as_bytes(), PrincipalStateFile::Checkpoint)
                    .map_err(map_filesystem_error)
            })?,
            receipts: self.read_payload(backup_root, "receipts", MAX_LOCAL_BYTES, || {
                locked
                    .read(principal.as_bytes(), PrincipalStateFile::Receipts)
                    .map_err(map_filesystem_error)
            })?,
        })
    }

    pub(in crate::cli::rollover_commands) fn finish(
        &self,
        root: &HardenedStateRoot,
        request: &RolloverPublication<'_>,
    ) -> Result<(), CliError> {
        for (name, bytes) in payloads(request) {
            cleanup(&request.targets.backup_root, &self.name(name), bytes)?;
        }
        cleanup(root, PENDING_ROLLOVER, request.vault_bytes)?;
        // Last reader-consumed guard: recovery after earlier cleanup can use
        // exact, already published outputs in place of removed staging files.
        cleanup(root, PENDING_OUTPUTS, &self.bytes()?)
    }

    fn bytes(&self) -> Result<Vec<u8>, CliError> {
        let bytes = serde_json::to_vec(self).map_err(|_| incomplete_rollover())?;
        if bytes.len() > MAX_SNAPSHOT_BYTES {
            return Err(incomplete_rollover());
        }
        Ok(bytes)
    }

    fn name(&self, suffix: &str) -> String {
        format!("{}.{}.pending", self.prefix, suffix)
    }

    fn read_payload(
        &self,
        root: &HardenedStateRoot,
        suffix: &str,
        limit: usize,
        fallback: impl FnOnce() -> Result<Vec<u8>, CliError>,
    ) -> Result<Vec<u8>, CliError> {
        let bytes = match read_primary_or_cleanup(root, &self.name(suffix), limit)? {
            Some(bytes) => bytes,
            None => fallback()?,
        };
        if self.hashes.get(suffix) != Some(&sha256_digest(&bytes)) {
            return Err(incomplete_rollover());
        }
        Ok(bytes)
    }
}

fn payloads<'a>(request: &'a RolloverPublication<'_>) -> [(&'static str, &'a [u8]); 5] {
    [
        ("backup", request.backup_bytes),
        ("transfer", request.transfer_bytes),
        ("audit", request.files.audit()),
        ("checkpoint", request.files.checkpoint()),
        ("receipts", request.files.receipts()),
    ]
}

fn cleanup_name(name: &str) -> String {
    match name {
        PENDING_ROLLOVER => PENDING_ROLLOVER_CLEANUP.into(),
        PENDING_OUTPUTS => PENDING_OUTPUTS_CLEANUP.into(),
        _ => format!("{name}.cleanup"),
    }
}

fn read_primary_or_cleanup(
    root: &HardenedStateRoot,
    name: &str,
    limit: usize,
) -> Result<Option<Vec<u8>>, CliError> {
    let mut found = None;
    for path in [name.to_owned(), cleanup_name(name)] {
        match root.read_private_file(Path::new(&path), limit) {
            Ok(bytes) => {
                if found.as_ref().is_some_and(|prior| prior != &bytes) {
                    return Err(incomplete_rollover());
                }
                found = Some(bytes);
            }
            Err(error) if error.kind() == FilesystemErrorKind::NotFound => {}
            Err(error) => return Err(map_filesystem_error(error)),
        }
    }
    Ok(found)
}

fn cleanup(root: &HardenedStateRoot, name: &str, bytes: &[u8]) -> Result<(), CliError> {
    if read_primary_or_cleanup(root, name, bytes.len())?.is_none() {
        if root
            .confirm_private_cleanup_absent(Path::new(name), Path::new(&cleanup_name(name)))
            .map_err(map_filesystem_error)?
            != PrivateFileCleanupOutcome::RemovedAndSynced
        {
            return Err(incomplete_rollover());
        }
        return Ok(());
    }
    let outcome = root
        .cleanup_private_file_if_exact(Path::new(name), Path::new(&cleanup_name(name)), bytes)
        .map_err(map_filesystem_error)?;
    if outcome != PrivateFileCleanupOutcome::RemovedAndSynced {
        return Err(incomplete_rollover());
    }
    Ok(())
}
