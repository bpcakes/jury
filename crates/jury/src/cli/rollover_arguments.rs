use super::*;

#[derive(Debug, Args)]
pub struct VaultMigrateSuiteArgs {
    /// Explicit destination cryptographic suite. The supported transition is 1 to 2.
    #[arg(long, value_parser = clap::value_parser!(u16).range(2..=2))]
    pub to: u16,
    #[command(flatten)]
    pub rollover: VaultRolloverArgs,
}

#[derive(Debug, Args)]
pub struct VaultRolloverArgs {
    /// Absolute detached destination home; must be absent unless resuming.
    #[arg(long, value_name = "DIRECTORY")]
    pub out: PathBuf,
    /// Owner-only backup file in a separate private directory; absent unless resuming.
    #[arg(long, value_name = "FILE")]
    pub backup_out: PathBuf,
    /// Public transfer file for explicit redistribution; absent unless resuming.
    #[arg(long, value_name = "FILE")]
    pub transfer_out: PathBuf,
    /// Validate the complete preparation without publishing destinations.
    #[arg(long)]
    pub dry_run: bool,
    /// Resume the exact durably saved candidate without new source requests or role challenges.
    #[arg(long, conflicts_with = "dry_run")]
    pub resume: bool,
    /// Explicitly trust the generated new lineage for this local owner.
    #[arg(long, required_unless_present = "dry_run")]
    pub adopt_new_lineage: bool,
    #[arg(long, value_enum, default_value_t = KdfProfileArg::Portable)]
    pub backup_kdf_profile: KdfProfileArg,
    /// Deliberately permit the backup and identity passphrases to match.
    #[arg(long)]
    pub reuse_identity_passphrase: bool,
    /// Destination witness operator endpoint: ID,URL,PRIVATE_OPERATOR_TOKEN[,CA_PEM].
    #[arg(long, value_name = "ENDPOINT")]
    pub destination_witness: Vec<String>,
    /// Permit explicitly configured literal loopback HTTP witness endpoints.
    #[arg(long)]
    pub allow_insecure_loopback: bool,
    /// Absent private directory for the unpublished journal, challenges and returned proofs.
    #[arg(long, value_name = "DIRECTORY")]
    pub registration_dir: Option<PathBuf>,
    /// Time to wait for destination role proofs; challenge validity is separately 24 hours.
    #[arg(long, default_value_t = 300, value_parser = clap::value_parser!(u64).range(1..=86400))]
    pub registration_wait_seconds: u64,
    /// Explicitly use the owner's direct slot for mixed source items.
    #[arg(long)]
    pub direct_source: bool,
    /// Exact descriptor/body Recovery authorization entries for governed source items.
    #[arg(long, value_name = "FILE")]
    pub administrative_access: Option<PathBuf>,
}
