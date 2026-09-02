use std::{
    fs, io,
    os::unix::fs::{MetadataExt as _, PermissionsExt as _},
    path::{Component, Path},
    time::Duration,
};

use jury_core::witness_engine::{PersistedWitnessState, WitnessStateStore, WitnessStoreError};
use jury_protocol::vault_v1::{Digest32, PrincipalId};
use rusqlite::{
    Connection, OpenFlags, OptionalExtension as _, TransactionBehavior, backup::Backup,
    limits::Limit, params,
};
use serde::Serialize;
use tempfile::NamedTempFile;

use crate::{AdapterError, AdapterErrorKind};

const SCHEMA_VERSION: i64 = 1;
const MAX_PERSISTED_WITNESS_STATE_BYTES: usize = 64 * 1024 * 1024;
const MAX_SQLITE_ROW_BYTES: i32 = 65 * 1024 * 1024;
pub(crate) const WITNESS_DATABASE_KIND: &str = "jury-witness-state-v1";
pub(crate) const ANCHOR_DATABASE_KIND: &str = "jury-external-anchor-v1";

pub struct SqliteWitnessStore {
    connection: Connection,
    witness_id: PrincipalId,
}

impl SqliteWitnessStore {
    pub fn initialize(path: &Path, witness_id: PrincipalId) -> Result<(), AdapterError> {
        let initial = PersistedWitnessState::empty(witness_id);
        let initial_json = encode_persisted_state(&initial).map_err(map_codec_adapter_error)?;
        initialize_managed_database(path, WITNESS_DATABASE_KIND, move |connection| {
            connection
                .execute(
                    "INSERT INTO witness_state(singleton, generation, state_json) \
                     VALUES (1, 0, ?1)",
                    params![initial_json],
                )
                .map_err(database_unavailable)?;
            Ok(())
        })
    }

    pub fn open(path: &Path, witness_id: PrincipalId) -> Result<Self, AdapterError> {
        let connection = open_managed_database(path, WITNESS_DATABASE_KIND)?;
        let store = Self {
            connection,
            witness_id,
        };
        store
            .load_validated()
            .map_err(|_| AdapterError::new(AdapterErrorKind::InvalidState))?;
        Ok(store)
    }

    pub fn load_validated(&self) -> Result<PersistedWitnessState, AdapterError> {
        load_witness_state(&self.connection, self.witness_id)
    }
}

impl WitnessStateStore for SqliteWitnessStore {
    fn load(&mut self) -> Result<PersistedWitnessState, WitnessStoreError> {
        self.load_validated().map_err(map_adapter_store_error)
    }

    fn commit(
        &mut self,
        expected_generation: u64,
        replacement: PersistedWitnessState,
    ) -> Result<(), WitnessStoreError> {
        if replacement.logical.witness_id != self.witness_id
            || replacement.logical.state_generation != expected_generation.saturating_add(1)
            || replacement.pending_anchor.is_none()
        {
            return Err(WitnessStoreError::unavailable());
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| WitnessStoreError::unavailable())?;
        let current =
            load_witness_state(&transaction, self.witness_id).map_err(map_adapter_store_error)?;
        if current.logical.state_generation != expected_generation
            || current.pending_anchor.is_some()
        {
            return Err(WitnessStoreError::unavailable());
        }
        let state_json = encode_persisted_state(&replacement).map_err(map_codec_store_error)?;
        let replacement_generation = i64::try_from(replacement.logical.state_generation)
            .map_err(|_| WitnessStoreError::unavailable())?;
        let expected_generation =
            i64::try_from(expected_generation).map_err(|_| WitnessStoreError::unavailable())?;
        let changed = transaction
            .execute(
                "UPDATE witness_state SET generation = ?1, state_json = ?2 \
                 WHERE singleton = 1 AND generation = ?3",
                params![replacement_generation, state_json, expected_generation],
            )
            .map_err(|_| WitnessStoreError::unavailable())?;
        if changed != 1 {
            return Err(WitnessStoreError::unavailable());
        }
        transaction
            .commit()
            .map_err(|_| WitnessStoreError::unavailable())
    }

    fn mark_anchor_published(
        &mut self,
        candidate_digest: &Digest32,
    ) -> Result<(), WitnessStoreError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| WitnessStoreError::unavailable())?;
        let mut current =
            load_witness_state(&transaction, self.witness_id).map_err(map_adapter_store_error)?;
        let candidate = current
            .pending_anchor
            .take()
            .ok_or_else(WitnessStoreError::unavailable)?;
        if candidate
            .digest()
            .map_err(|_| WitnessStoreError::unavailable())?
            != *candidate_digest
        {
            return Err(WitnessStoreError::unavailable());
        }
        current.published_anchor = Some(candidate);
        let state_json = encode_persisted_state(&current).map_err(map_codec_store_error)?;
        let generation = i64::try_from(current.logical.state_generation)
            .map_err(|_| WitnessStoreError::unavailable())?;
        let changed = transaction
            .execute(
                "UPDATE witness_state SET state_json = ?1 \
                 WHERE singleton = 1 AND generation = ?2",
                params![state_json, generation],
            )
            .map_err(|_| WitnessStoreError::unavailable())?;
        if changed != 1 {
            return Err(WitnessStoreError::unavailable());
        }
        transaction
            .commit()
            .map_err(|_| WitnessStoreError::unavailable())
    }
}

pub fn backup_witness_database(source: &Path, destination: &Path) -> Result<(), AdapterError> {
    backup_managed_database(source, destination, WITNESS_DATABASE_KIND)
}

pub fn restore_witness_database(backup: &Path, destination: &Path) -> Result<(), AdapterError> {
    restore_managed_database(backup, destination, WITNESS_DATABASE_KIND)
}

pub(crate) fn open_managed_database(
    path: &Path,
    expected_kind: &str,
) -> Result<Connection, AdapterError> {
    validate_destination_path(path, false)?;
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(database_unavailable)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(|_| AdapterError::new(AdapterErrorKind::DatabaseUnavailable))?;
    configure_connection(&connection, "WAL")?;
    validate_database(&connection, expected_kind)?;
    Ok(connection)
}

pub(crate) fn initialize_managed_database(
    path: &Path,
    expected_kind: &str,
    seed: impl FnOnce(&Connection) -> Result<(), AdapterError>,
) -> Result<(), AdapterError> {
    validate_destination_path(path, true)?;
    if path.exists() {
        return Err(AdapterError::new(AdapterErrorKind::TargetExists));
    }
    let parent = path
        .parent()
        .ok_or_else(|| AdapterError::new(AdapterErrorKind::InvalidConfiguration))?;
    let temporary = NamedTempFile::new_in(parent)
        .map_err(|_| AdapterError::new(AdapterErrorKind::DatabaseUnavailable))?;
    fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o600))
        .map_err(|_| AdapterError::new(AdapterErrorKind::DatabaseUnavailable))?;
    let mut connection = Connection::open_with_flags(
        temporary.path(),
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(database_unavailable)?;
    configure_connection(&connection, "DELETE")?;
    initialize_schema(&mut connection, expected_kind)?;
    seed(&connection)?;
    validate_database(&connection, expected_kind)?;
    drop(connection);
    temporary
        .as_file()
        .sync_all()
        .map_err(|_| AdapterError::new(AdapterErrorKind::DatabaseUnavailable))?;
    persist_without_overwrite(temporary, path)?;
    sync_parent(path)
}

fn configure_connection(connection: &Connection, journal_mode: &str) -> Result<(), AdapterError> {
    connection
        .set_limit(Limit::SQLITE_LIMIT_LENGTH, MAX_SQLITE_ROW_BYTES)
        .map_err(database_unavailable)?;
    connection
        .busy_timeout(Duration::from_secs(5))
        .map_err(database_unavailable)?;
    connection
        .pragma_update(None, "foreign_keys", true)
        .map_err(database_unavailable)?;
    connection
        .pragma_update(None, "synchronous", "FULL")
        .map_err(database_unavailable)?;
    connection
        .pragma_update(None, "journal_mode", journal_mode)
        .map_err(database_unavailable)?;
    Ok(())
}

fn initialize_schema(connection: &mut Connection, expected_kind: &str) -> Result<(), AdapterError> {
    let version: i64 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(database_unavailable)?;
    match version {
        0 => {
            let transaction = connection
                .transaction_with_behavior(TransactionBehavior::Exclusive)
                .map_err(database_unavailable)?;
            transaction
                .execute_batch(
                    "CREATE TABLE jury_metadata (\
                         singleton INTEGER PRIMARY KEY CHECK (singleton = 1),\
                         database_kind TEXT NOT NULL\
                     );\
                     CREATE TABLE witness_state (\
                         singleton INTEGER PRIMARY KEY CHECK (singleton = 1),\
                         generation INTEGER NOT NULL CHECK (generation >= 0),\
                         state_json BLOB NOT NULL\
                     );\
                     CREATE TABLE anchors (\
                         witness_id BLOB PRIMARY KEY CHECK (length(witness_id) = 32),\
                         generation INTEGER NOT NULL CHECK (generation > 0),\
                         digest BLOB NOT NULL CHECK (length(digest) = 32),\
                         anchor_json BLOB NOT NULL\
                     );",
                )
                .map_err(database_unavailable)?;
            transaction
                .execute(
                    "INSERT INTO jury_metadata(singleton, database_kind) VALUES (1, ?1)",
                    params![expected_kind],
                )
                .map_err(database_unavailable)?;
            transaction
                .pragma_update(None, "user_version", SCHEMA_VERSION)
                .map_err(database_unavailable)?;
            transaction.commit().map_err(database_unavailable)
        }
        _ => Err(AdapterError::new(AdapterErrorKind::InvalidState)),
    }
}

pub(crate) fn validate_database(
    connection: &Connection,
    expected_kind: &str,
) -> Result<(), AdapterError> {
    let version: i64 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(database_unavailable)?;
    let kind: Option<String> = connection
        .query_row(
            "SELECT database_kind FROM jury_metadata WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(database_unavailable)?;
    let quick_check: String = connection
        .query_row("PRAGMA quick_check", [], |row| row.get(0))
        .map_err(database_unavailable)?;
    if version != SCHEMA_VERSION || kind.as_deref() != Some(expected_kind) || quick_check != "ok" {
        return Err(AdapterError::new(AdapterErrorKind::InvalidState));
    }
    Ok(())
}

fn load_witness_state(
    connection: &Connection,
    witness_id: PrincipalId,
) -> Result<PersistedWitnessState, AdapterError> {
    let serialized_length: i64 = connection
        .query_row(
            "SELECT length(state_json) FROM witness_state WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .map_err(database_unavailable)?;
    validate_state_length(serialized_length)?;
    let (generation, state_json): (i64, Vec<u8>) = connection
        .query_row(
            "SELECT generation, state_json FROM witness_state \
             WHERE singleton = 1 AND length(state_json) <= ?1",
            params![MAX_PERSISTED_WITNESS_STATE_BYTES as i64],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(database_unavailable)?;
    let state: PersistedWitnessState = serde_json::from_slice(&state_json)
        .map_err(|_| AdapterError::new(AdapterErrorKind::InvalidState))?;
    let generation =
        u64::try_from(generation).map_err(|_| AdapterError::new(AdapterErrorKind::InvalidState))?;
    if state.logical.witness_id != witness_id || state.logical.state_generation != generation {
        return Err(AdapterError::new(AdapterErrorKind::InvalidState));
    }
    state
        .logical
        .canonical_database_state()
        .map_err(|_| AdapterError::new(AdapterErrorKind::InvalidState))?;
    Ok(state)
}

fn validate_state_length(serialized_length: i64) -> Result<(), AdapterError> {
    let serialized_length = usize::try_from(serialized_length)
        .map_err(|_| AdapterError::new(AdapterErrorKind::InvalidState))?;
    if serialized_length > MAX_PERSISTED_WITNESS_STATE_BYTES {
        return Err(AdapterError::new(AdapterErrorKind::CapacityExhausted));
    }
    Ok(())
}

pub(crate) fn backup_managed_database(
    source: &Path,
    destination: &Path,
    expected_kind: &str,
) -> Result<(), AdapterError> {
    validate_existing_private_file(source)?;
    validate_destination_path(destination, true)?;
    if destination.exists() {
        return Err(AdapterError::new(AdapterErrorKind::TargetExists));
    }
    let source = Connection::open_with_flags(
        source,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(database_unavailable)?;
    validate_database(&source, expected_kind)?;
    let parent = destination
        .parent()
        .ok_or_else(|| AdapterError::new(AdapterErrorKind::InvalidConfiguration))?;
    let temporary = NamedTempFile::new_in(parent)
        .map_err(|_| AdapterError::new(AdapterErrorKind::DatabaseUnavailable))?;
    {
        let mut target = Connection::open(temporary.path()).map_err(database_unavailable)?;
        let backup = Backup::new(&source, &mut target).map_err(database_unavailable)?;
        backup
            .run_to_completion(128, Duration::from_millis(10), None)
            .map_err(database_unavailable)?;
    }
    temporary
        .as_file()
        .sync_all()
        .map_err(|_| AdapterError::new(AdapterErrorKind::DatabaseUnavailable))?;
    persist_without_overwrite(temporary, destination)?;
    sync_parent(destination)
}

pub(crate) fn restore_managed_database(
    backup: &Path,
    destination: &Path,
    expected_kind: &str,
) -> Result<(), AdapterError> {
    validate_existing_private_file(backup)?;
    validate_destination_path(destination, true)?;
    if destination.exists() {
        return Err(AdapterError::new(AdapterErrorKind::TargetExists));
    }
    let source = Connection::open_with_flags(
        backup,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(database_unavailable)?;
    validate_database(&source, expected_kind)?;
    drop(source);

    let parent = destination
        .parent()
        .ok_or_else(|| AdapterError::new(AdapterErrorKind::InvalidConfiguration))?;
    let mut temporary = NamedTempFile::new_in(parent)
        .map_err(|_| AdapterError::new(AdapterErrorKind::DatabaseUnavailable))?;
    let mut input = fs::File::open(backup)
        .map_err(|_| AdapterError::new(AdapterErrorKind::DatabaseUnavailable))?;
    io::copy(&mut input, temporary.as_file_mut())
        .map_err(|_| AdapterError::new(AdapterErrorKind::DatabaseUnavailable))?;
    temporary
        .as_file()
        .sync_all()
        .map_err(|_| AdapterError::new(AdapterErrorKind::DatabaseUnavailable))?;
    let restored = Connection::open_with_flags(
        temporary.path(),
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(database_unavailable)?;
    validate_database(&restored, expected_kind)?;
    drop(restored);
    persist_without_overwrite(temporary, destination)?;
    sync_parent(destination)
}

fn persist_without_overwrite(
    temporary: NamedTempFile,
    destination: &Path,
) -> Result<(), AdapterError> {
    temporary.persist_noclobber(destination).map_err(|error| {
        if error.error.kind() == io::ErrorKind::AlreadyExists {
            AdapterError::new(AdapterErrorKind::TargetExists)
        } else {
            AdapterError::new(AdapterErrorKind::DatabaseUnavailable)
        }
    })?;
    fs::set_permissions(destination, fs::Permissions::from_mode(0o600))
        .map_err(|_| AdapterError::new(AdapterErrorKind::DatabaseUnavailable))
}

fn sync_parent(path: &Path) -> Result<(), AdapterError> {
    let parent = path
        .parent()
        .ok_or_else(|| AdapterError::new(AdapterErrorKind::InvalidConfiguration))?;
    fs::File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| AdapterError::new(AdapterErrorKind::DatabaseUnavailable))
}

fn validate_destination_path(path: &Path, may_be_absent: bool) -> Result<(), AdapterError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(AdapterError::new(AdapterErrorKind::InvalidConfiguration));
    }
    let parent = path
        .parent()
        .ok_or_else(|| AdapterError::new(AdapterErrorKind::InvalidConfiguration))?;
    let parent_metadata = fs::symlink_metadata(parent)
        .map_err(|_| AdapterError::new(AdapterErrorKind::InvalidConfiguration))?;
    if !parent_metadata.file_type().is_dir()
        || parent_metadata.permissions().mode() & 0o077 != 0
        || parent_metadata.uid() != rustix::process::geteuid().as_raw()
    {
        return Err(AdapterError::new(AdapterErrorKind::InvalidConfiguration));
    }
    if path.exists() {
        validate_existing_private_file(path)?;
    } else if !may_be_absent {
        return Err(AdapterError::new(AdapterErrorKind::DatabaseUnavailable));
    }
    Ok(())
}

fn validate_existing_private_file(path: &Path) -> Result<(), AdapterError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| AdapterError::new(AdapterErrorKind::DatabaseUnavailable))?;
    if !metadata.file_type().is_file()
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o077 != 0
        || metadata.uid() != rustix::process::geteuid().as_raw()
    {
        return Err(AdapterError::new(AdapterErrorKind::InvalidConfiguration));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StateCodecError {
    Invalid,
    CapacityExhausted,
}

struct BoundedJsonWriter {
    bytes: Vec<u8>,
    maximum_bytes: usize,
    capacity_exhausted: bool,
}

impl BoundedJsonWriter {
    fn new(maximum_bytes: usize) -> Self {
        Self {
            bytes: Vec::new(),
            maximum_bytes,
            capacity_exhausted: false,
        }
    }
}

impl io::Write for BoundedJsonWriter {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        let remaining = self.maximum_bytes.saturating_sub(self.bytes.len());
        if input.len() > remaining {
            self.capacity_exhausted = true;
            return Err(io::Error::other(
                "serialized witness state exceeds capacity",
            ));
        }
        self.bytes.extend_from_slice(input);
        Ok(input.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn encode_persisted_state(state: &PersistedWitnessState) -> Result<Vec<u8>, StateCodecError> {
    encode_json_bounded(state, MAX_PERSISTED_WITNESS_STATE_BYTES)
}

fn encode_json_bounded(
    value: &impl Serialize,
    maximum_bytes: usize,
) -> Result<Vec<u8>, StateCodecError> {
    let mut writer = BoundedJsonWriter::new(maximum_bytes);
    match serde_json::to_writer(&mut writer, value) {
        Ok(()) => Ok(writer.bytes),
        Err(_) if writer.capacity_exhausted => Err(StateCodecError::CapacityExhausted),
        Err(_) => Err(StateCodecError::Invalid),
    }
}

const fn map_codec_adapter_error(error: StateCodecError) -> AdapterError {
    match error {
        StateCodecError::Invalid => AdapterError::new(AdapterErrorKind::InvalidState),
        StateCodecError::CapacityExhausted => {
            AdapterError::new(AdapterErrorKind::CapacityExhausted)
        }
    }
}

const fn map_codec_store_error(error: StateCodecError) -> WitnessStoreError {
    match error {
        StateCodecError::Invalid => WitnessStoreError::unavailable(),
        StateCodecError::CapacityExhausted => WitnessStoreError::capacity_exhausted(),
    }
}

const fn map_adapter_store_error(error: AdapterError) -> WitnessStoreError {
    match error.kind() {
        AdapterErrorKind::CapacityExhausted => WitnessStoreError::capacity_exhausted(),
        _ => WitnessStoreError::unavailable(),
    }
}

fn database_unavailable(_: rusqlite::Error) -> AdapterError {
    AdapterError::new(AdapterErrorKind::DatabaseUnavailable)
}

#[cfg(test)]
mod tests {
    use std::{error::Error, fs, os::unix::fs::PermissionsExt as _};

    use jury_core::witness_engine::WitnessStateStore as _;
    use jury_protocol::{
        vault_v1::{Digest32, PrincipalId, Signature64},
        witness_v1::WitnessStateAnchorV1,
    };

    use super::*;

    type TestResult = Result<(), Box<dyn Error>>;

    fn anchor(witness_id: PrincipalId, generation: u64) -> WitnessStateAnchorV1 {
        WitnessStateAnchorV1 {
            schema: 1,
            witness_id,
            witness_signing_key_fingerprint: Digest32::new([2; 32]),
            witness_signing_key_epoch: 1,
            state_generation: generation,
            database_state_digest: Digest32::new([3; 32]),
            vault_high_watermarks: Vec::new(),
            replay_retain_through_ms: 0,
            last_accepted_wall_time_ms: 1,
            predecessor_anchor_digest: Digest32::new([0; 32]),
            issued_at_ms: 1,
            signature: Signature64::new([4; 64]),
        }
    }

    #[test]
    fn witness_store_commits_and_marks_one_pending_candidate() -> TestResult {
        let directory = tempfile::tempdir()?;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
        let path = directory.path().join("witness.sqlite3");
        let witness_id = PrincipalId::from_bytes([1; 32])?;
        SqliteWitnessStore::initialize(&path, witness_id)?;
        let mut store = SqliteWitnessStore::open(&path, witness_id)?;
        let mut replacement = PersistedWitnessState::empty(witness_id);
        replacement.logical.state_generation = 1;
        let candidate = anchor(witness_id, 1);
        let digest = candidate.digest()?;
        replacement.pending_anchor = Some(candidate.clone());

        store
            .commit(0, replacement)
            .map_err(|_| "store commit failed")?;
        assert_eq!(
            store
                .load()
                .map_err(|_| "store load failed")?
                .pending_anchor,
            Some(candidate.clone())
        );
        store
            .mark_anchor_published(&digest)
            .map_err(|_| "store mark failed")?;
        let published = store.load().map_err(|_| "store load failed")?;
        assert_eq!(published.pending_anchor, None);
        assert_eq!(published.published_anchor, Some(candidate));
        assert_eq!(published.logical.state_generation, 1);
        Ok(())
    }

    #[test]
    fn backup_and_restore_are_validated_atomic_and_no_clobber() -> TestResult {
        let directory = tempfile::tempdir()?;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
        let source = directory.path().join("source.sqlite3");
        let backup = directory.path().join("backup.sqlite3");
        let restored = directory.path().join("restored.sqlite3");
        let witness_id = PrincipalId::from_bytes([5; 32])?;
        SqliteWitnessStore::initialize(&source, witness_id)?;

        backup_witness_database(&source, &backup)?;
        assert_eq!(
            backup_witness_database(&source, &backup)
                .err()
                .ok_or("backup overwrite should fail")?
                .kind(),
            AdapterErrorKind::TargetExists
        );
        restore_witness_database(&backup, &restored)?;
        assert_eq!(
            SqliteWitnessStore::open(&restored, witness_id)?
                .load_validated()?
                .logical
                .state_generation,
            0
        );
        assert_eq!(
            restore_witness_database(&backup, &restored)
                .err()
                .ok_or("restore overwrite should fail")?
                .kind(),
            AdapterErrorKind::TargetExists
        );
        Ok(())
    }

    #[test]
    fn initialization_and_open_are_distinct_lifecycle_operations() -> TestResult {
        let directory = tempfile::tempdir()?;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
        let path = directory.path().join("witness.sqlite3");
        let witness_id = PrincipalId::from_bytes([9; 32])?;

        assert!(SqliteWitnessStore::open(&path, witness_id).is_err());
        assert!(!path.exists());
        SqliteWitnessStore::initialize(&path, witness_id)?;
        assert_eq!(
            SqliteWitnessStore::initialize(&path, witness_id)
                .err()
                .ok_or("reinitialization should fail")?
                .kind(),
            AdapterErrorKind::TargetExists
        );
        assert_eq!(
            SqliteWitnessStore::open(&path, witness_id)?
                .load_validated()?
                .logical
                .state_generation,
            0
        );
        Ok(())
    }

    #[test]
    fn persisted_state_encoding_and_loading_have_hard_byte_caps() -> TestResult {
        let compact =
            encode_json_bounded(&vec!["abcd"], 16).map_err(|_| "small state should serialize")?;
        assert_eq!(compact, br#"["abcd"]"#);
        assert_eq!(
            encode_json_bounded(&vec!["abcd"], 7),
            Err(StateCodecError::CapacityExhausted)
        );
        assert_eq!(
            validate_state_length((MAX_PERSISTED_WITNESS_STATE_BYTES + 1) as i64)
                .err()
                .ok_or("oversized persisted state should fail before loading")?
                .kind(),
            AdapterErrorKind::CapacityExhausted
        );
        Ok(())
    }
}
