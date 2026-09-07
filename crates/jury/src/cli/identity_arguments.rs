use super::*;

#[derive(Debug, Args)]
pub struct IdentityInitArgs {
    /// Named identity destination below the identity root.
    #[arg(long, value_name = "NAME")]
    pub name: Option<String>,

    #[arg(long, value_enum, default_value_t = PrincipalKindArg::Human)]
    pub kind: PrincipalKindArg,

    #[arg(long = "kdf-profile", value_enum, default_value_t = KdfProfileArg::Portable)]
    pub kdf_profile: KdfProfileArg,
}

#[derive(Debug, Args)]
pub struct IdentityStatusArgs {
    /// Named identity below the identity root.
    #[arg(long, value_name = "NAME")]
    pub name: Option<String>,
}

#[derive(Debug, Args)]
pub struct IdentityPassphraseChangeArgs {
    /// Select the resulting KDF profile; omission retains the current profile.
    #[arg(long = "kdf-profile", value_enum)]
    pub kdf_profile: Option<KdfProfileArg>,

    /// Explicitly permit hardened-to-portable KDF downgrade.
    #[arg(long, requires = "kdf_profile")]
    pub allow_kdf_downgrade: bool,
}

#[derive(Debug, Args)]
pub struct IdentityPublicArgs {
    /// Create the public descriptor at this absolute path.
    #[arg(long, value_name = "FILE")]
    pub out: PathBuf,

    /// Replace an existing regular owner-only destination.
    #[arg(long)]
    pub overwrite: bool,
}

#[derive(Debug, Args)]
pub struct IdentityProveArgs {
    /// Owner-created registration challenge artifact.
    #[arg(long, value_name = "FILE")]
    pub challenge: PathBuf,

    /// Authenticate this unpublished rollover journal against the selected source vault.
    #[arg(long, value_name = "FILE", requires = "expected_rollover_genesis")]
    pub rollover_draft: Option<PathBuf>,

    /// Explicitly expected fingerprint of the new, unpublished genesis.
    #[arg(long, value_name = "FINGERPRINT", requires = "rollover_draft")]
    pub expected_rollover_genesis: Option<String>,

    /// Create the public proof at this absolute path.
    #[arg(long, value_name = "FILE")]
    pub out: PathBuf,

    /// Replace an existing regular owner-only destination.
    #[arg(long)]
    pub overwrite: bool,
}
