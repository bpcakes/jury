use std::path::PathBuf;

use clap::{Args, Subcommand};

use super::KdfProfileArg;

#[derive(Debug, Subcommand)]
pub enum BackupCommand {
    /// Create independently protected owner recovery material.
    #[command(
        long_about = "Create independently protected recovery material. Anyone with the backup passphrase can recover the included owner identity and every current direct-access item. A backup is more sensitive than a transfer artifact."
    )]
    Create(BackupCreateArgs),
    /// Report authenticated local creation, verification, and drill readiness.
    Status,
    /// Fully decrypt and validate one owner-only backup without restoring it.
    Verify(BackupVerifyArgs),
    /// Restore into the selected absent vault home and absent identity path.
    Restore(BackupRestoreArgs),
    /// Perform a real restore and direct-access validation in explicit absent paths.
    Drill(BackupDrillArgs),
}

#[derive(Debug, Args)]
pub struct BackupCreateArgs {
    /// Create this owner-only backup file.
    #[arg(long, value_name = "FILE")]
    pub out: PathBuf,
    /// Replace an existing regular owner-only backup destination.
    #[arg(long)]
    pub overwrite: bool,
    #[arg(long = "kdf-profile", value_enum, default_value_t = KdfProfileArg::Portable)]
    pub kdf_profile: KdfProfileArg,
    /// Deliberately permit the backup passphrase to equal the current identity passphrase.
    #[arg(long)]
    pub reuse_identity_passphrase: bool,
    /// Include one explicitly selected approver identity and its local state.
    #[arg(long, value_name = "FILE")]
    pub approver_identity_file: Option<PathBuf>,
    /// Include one explicitly selected witness-client identity and its local state.
    #[arg(long, value_name = "FILE")]
    pub witness_identity_file: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct BackupVerifyArgs {
    #[arg(long = "in", value_name = "FILE")]
    pub input: PathBuf,
}

#[derive(Debug, Args)]
pub struct BackupRestoreArgs {
    #[arg(long = "in", value_name = "FILE")]
    pub input: PathBuf,
    /// Create the restored owner identity at this absent absolute path.
    #[arg(
        long,
        value_name = "ABSENT_PATH",
        conflicts_with = "reuse_identity",
        required_unless_present = "reuse_identity"
    )]
    pub identity_out: Option<PathBuf>,
    /// Reuse an existing exact identity after private-material comparison.
    #[arg(long, value_name = "PATH", conflicts_with = "identity_out")]
    pub reuse_identity: Option<PathBuf>,
    /// Install authenticated local state below this separate state root.
    #[arg(long, value_name = "PATH")]
    pub state_out: Option<PathBuf>,
    /// Create an included approver identity at this absent absolute path.
    #[arg(long, value_name = "ABSENT_PATH")]
    pub approver_identity_out: Option<PathBuf>,
    /// Create an included witness-client identity at this absent absolute path.
    #[arg(long, value_name = "ABSENT_PATH")]
    pub witness_identity_out: Option<PathBuf>,
    #[arg(long = "identity-kdf-profile", value_enum, default_value_t = KdfProfileArg::Portable)]
    pub identity_kdf_profile: KdfProfileArg,
}

#[derive(Debug, Args)]
pub struct BackupDrillArgs {
    #[arg(long = "in", value_name = "FILE")]
    pub input: PathBuf,
    /// Create the restored detached vault at this absent absolute path.
    #[arg(long, value_name = "ABSENT_PATH")]
    pub vault_out: PathBuf,
    /// Create the restored owner identity at this absent absolute path.
    #[arg(long, value_name = "ABSENT_PATH")]
    pub identity_out: PathBuf,
    /// Install drill-local state below this separate absent state root.
    #[arg(long, value_name = "ABSENT_PATH")]
    pub state_out: PathBuf,
    /// Create an included approver identity at this absent absolute path.
    #[arg(long, value_name = "ABSENT_PATH")]
    pub approver_identity_out: Option<PathBuf>,
    /// Create an included witness-client identity at this absent absolute path.
    #[arg(long, value_name = "ABSENT_PATH")]
    pub witness_identity_out: Option<PathBuf>,
    #[arg(long = "identity-kdf-profile", value_enum, default_value_t = KdfProfileArg::Portable)]
    pub identity_kdf_profile: KdfProfileArg,
}
