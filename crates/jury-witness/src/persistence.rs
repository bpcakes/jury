use std::{
    ffi::OsString,
    fs, io,
    os::unix::ffi::OsStrExt as _,
    os::unix::fs::{MetadataExt as _, PermissionsExt as _},
    path::{Component, Path, PathBuf},
    time::{Duration, Instant},
};

use jury_core::witness_engine::{PersistedWitnessState, WitnessStateStore, WitnessStoreError};
use jury_protocol::vault_v1::{Digest32, PrincipalId};
use jury_protocol::{vault_v1::VaultId, witness_v1::ReplayStateV1};
use rusqlite::{
    Connection, OpenFlags, OptionalExtension as _, TransactionBehavior, backup::Backup,
    limits::Limit, params,
};
use serde::Serialize;
use tempfile::NamedTempFile;

use self::state_codec::{encode_persisted_state, map_codec_adapter_error, map_codec_store_error};
use crate::{AdapterError, AdapterErrorKind};

mod state_codec;

const SCHEMA_VERSION: i64 = 1;
const MAX_PERSISTED_WITNESS_STATE_BYTES: usize = 64 * 1024 * 1024;
const MAX_SQLITE_ROW_BYTES: i32 = 65 * 1024 * 1024;
const MAXIMUM_SQLITE_BUSY_TIMEOUT: Duration = Duration::from_secs(5);
pub(crate) const WITNESS_DATABASE_KIND: &str = "jury-witness-state-v1";
pub(crate) const ANCHOR_DATABASE_KIND: &str = "jury-external-anchor-v1";

include!("persistence/implementation.rs");
include!("persistence/tests.rs");
