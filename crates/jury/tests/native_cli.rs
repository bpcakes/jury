#![cfg(target_os = "linux")]

use std::fs;
use std::io::Write as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::process::{Command, Output, Stdio};

use jury_core::witness_receipt::ReceiptPolicyMaterialV1;
use jury_protocol::{
    vault_v1::{PolicyOperationV1, VaultFileV1},
    witness_v1::PolicyMaterialBytes,
};

use self::support::*;

#[path = "native_cli/additional.rs"]
mod native_cli_additional;

#[path = "native_cli/backup.rs"]
mod native_cli_backup;

#[path = "native_cli/execution.rs"]
mod native_cli_execution;

#[path = "native_cli/main_flow.rs"]
mod native_cli_main_flow;

#[path = "native_cli/plaintext.rs"]
mod native_cli_plaintext;

#[path = "native_cli/transfer.rs"]
mod native_cli_transfer;

#[path = "native_cli/witnessed.rs"]
mod native_cli_witnessed;

#[path = "native_cli/support.rs"]
mod support;

include!("native_cli/setup.rs");
include!("native_cli/access.rs");
