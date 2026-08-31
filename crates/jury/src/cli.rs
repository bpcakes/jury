//! Native Linux command-line boundary.

use std::env;
use std::ffi::OsString;
use std::fmt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use clap::{Args, Parser, Subcommand, ValueEnum};
use jury_core::identity::{IdentityCreator, UnlockedIdentity, unlock};
use jury_core::local_state::{CheckpointCandidate, PrincipalLocalState};
use jury_core::policy::{PolicyCreator, replay_policy};
use jury_filesystem::{
    FilesystemError, FilesystemErrorKind, HardenedStateRoot, IdentitySelector, PreparedPrivateFile,
    PrincipalStateFile, PublicationOutcome, PublicationPolicy, RepositoryLocation,
    VaultStateDirectory, resolve_linux_state_root,
};
use jury_protected::{ProtectedMemory, ProtectionPolicy};
use jury_protocol::identity_v1::{IdentityFileV1, KdfProfile, MAX_IDENTITY_FILE_BYTES};
use jury_protocol::vault_v1::{
    MAX_ITEMS, MAX_POLICY_REVISIONS, MAX_VAULT_BYTES, PrincipalKind, VaultFileV1, VaultHeaderV1,
};

use crate::home::{HomeSource, VaultHomeLocation, resolve_identity_root, resolve_vault_home};
use crate::secret_input;

const PRE_ALPHA_WARNING: &str = "PRE-ALPHA: do not use with real secrets";

#[derive(Debug, Parser)]
#[command(
    name = "jury",
    version,
    about = jury_core::PRODUCT_TAGLINE,
    long_about = jury_core::PRODUCT_TAGLINE,
    after_help = "Native Linux support only. PRE-ALPHA: do not use with real secrets."
)]
pub struct Cli {
    /// Emit stable JSON instead of human-readable output.
    #[arg(long, global = true)]
    pub json: bool,

    /// Select one absolute detached vault home.
    #[arg(
        long,
        global = true,
        value_name = "PATH",
        conflicts_with = "global_home"
    )]
    pub home: Option<PathBuf>,

    /// Select the Linux global vault home.
    #[arg(long = "global", global = true)]
    pub global_home: bool,

    /// Select one named identity.
    #[arg(
        long,
        global = true,
        value_name = "NAME",
        conflicts_with = "identity_file"
    )]
    pub identity: Option<String>,

    /// Select one absolute identity file.
    #[arg(long, global = true, value_name = "PATH")]
    pub identity_file: Option<PathBuf>,

    /// Read passphrase lines from standard input when it is not a terminal.
    #[arg(long, global = true)]
    pub passphrase_stdin: bool,

    /// Continue when optional OS memory protections are unavailable.
    #[arg(long, global = true)]
    pub allow_degraded_protection: bool,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Manage portable local identities.
    Identity {
        #[command(subcommand)]
        command: IdentityCommand,
    },
    /// Initialize a vault using the selected identity.
    Init(VaultInitArgs),
    /// Inspect or initialize the selected vault.
    Vault {
        #[command(subcommand)]
        command: VaultCommand,
    },
}

#[derive(Debug, Subcommand)]
pub enum IdentityCommand {
    /// Create one portable passphrase-protected identity.
    Init(IdentityInitArgs),
    /// Inspect the bounded public identity header without unlocking it.
    Status(IdentityStatusArgs),
}

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

#[derive(Debug, Args, Default)]
pub struct VaultInitArgs {}

#[derive(Debug, Subcommand)]
pub enum VaultCommand {
    /// Create one empty encrypted vault owned by the selected human identity.
    Init(VaultInitArgs),
    /// Validate and inspect public vault state without unlocking an identity.
    Status,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, ValueEnum)]
pub enum PrincipalKindArg {
    #[default]
    Human,
    Machine,
    Approver,
    Witness,
}

impl From<PrincipalKindArg> for PrincipalKind {
    fn from(value: PrincipalKindArg) -> Self {
        match value {
            PrincipalKindArg::Human => Self::Human,
            PrincipalKindArg::Machine => Self::Machine,
            PrincipalKindArg::Approver => Self::Approver,
            PrincipalKindArg::Witness => Self::Witness,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, ValueEnum)]
pub enum KdfProfileArg {
    #[default]
    Portable,
    Hardened,
}

impl From<KdfProfileArg> for KdfProfile {
    fn from(value: KdfProfileArg) -> Self {
        match value {
            KdfProfileArg::Portable => Self::PortableV1,
            KdfProfileArg::Hardened => Self::HardenedV1,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CommandOutput {
    IdentityCreated {
        identity: String,
        principal_id: String,
        fingerprint: String,
        kind: &'static str,
        kdf_profile: &'static str,
        protection_degraded: bool,
        durability: &'static str,
    },
    IdentityStatus {
        identity: String,
        principal_id: String,
        fingerprint: String,
        kind: &'static str,
        kdf_profile: &'static str,
        memory_kib: u32,
        passes: u32,
        lanes: u32,
        stronger_profile_available: bool,
    },
    VaultCreated {
        home_source: &'static str,
        vault_id: String,
        genesis_fingerprint: String,
        owner_principal_id: String,
        local_state: &'static str,
        durability: &'static str,
    },
    VaultStatus {
        home_source: &'static str,
        vault_id: String,
        genesis_fingerprint: String,
        policy_sequence: u64,
        current_revision: String,
        principal_count: usize,
        owner_count: usize,
        item_count: usize,
        artifact_bytes: usize,
    },
}

impl CommandOutput {
    pub fn write(&self, json: bool) {
        if json {
            println!("{}", self.json_value());
        } else {
            self.write_human();
        }
    }

    fn json_value(&self) -> serde_json::Value {
        match self {
            Self::IdentityCreated {
                identity,
                principal_id,
                fingerprint,
                kind,
                kdf_profile,
                protection_degraded,
                durability,
            } => serde_json::json!({
                "ok": true,
                "operation": "identity-init",
                "identity": identity,
                "principal_id": principal_id,
                "fingerprint": fingerprint,
                "kind": kind,
                "kdf_profile": kdf_profile,
                "protection_degraded": protection_degraded,
                "durability": durability,
                "maturity": "pre-alpha"
            }),
            Self::IdentityStatus {
                identity,
                principal_id,
                fingerprint,
                kind,
                kdf_profile,
                memory_kib,
                passes,
                lanes,
                stronger_profile_available,
            } => serde_json::json!({
                "ok": true,
                "operation": "identity-status",
                "identity": identity,
                "principal_id": principal_id,
                "fingerprint": fingerprint,
                "kind": kind,
                "kdf_profile": kdf_profile,
                "memory_kib": memory_kib,
                "passes": passes,
                "lanes": lanes,
                "stronger_profile_available": stronger_profile_available,
                "public_fields_authenticated": false,
                "private_payload_verified": false,
                "protection_mode": "portable",
                "maturity": "pre-alpha"
            }),
            Self::VaultCreated {
                home_source,
                vault_id,
                genesis_fingerprint,
                owner_principal_id,
                local_state,
                durability,
            } => serde_json::json!({
                "ok": true,
                "operation": "vault-init",
                "home_source": home_source,
                "vault_id": vault_id,
                "genesis_fingerprint": genesis_fingerprint,
                "owner_principal_id": owner_principal_id,
                "policy_sequence": 0,
                "item_count": 0,
                "local_state": local_state,
                "durability": durability,
                "backup_required": true,
                "maturity": "pre-alpha"
            }),
            Self::VaultStatus {
                home_source,
                vault_id,
                genesis_fingerprint,
                policy_sequence,
                current_revision,
                principal_count,
                owner_count,
                item_count,
                artifact_bytes,
            } => serde_json::json!({
                "ok": true,
                "operation": "vault-status",
                "home_source": home_source,
                "vault_id": vault_id,
                "genesis_fingerprint": genesis_fingerprint,
                "policy_sequence": policy_sequence,
                "current_revision": current_revision,
                "principal_count": principal_count,
                "owner_count": owner_count,
                "item_count": item_count,
                "artifact_bytes": artifact_bytes,
                "capacity": {
                    "artifact_bytes": {"used": artifact_bytes, "maximum": MAX_VAULT_BYTES},
                    "policy_revisions": {"used": policy_sequence, "maximum": MAX_POLICY_REVISIONS},
                    "items": {"used": item_count, "maximum": MAX_ITEMS}
                },
                "public_validation": "valid",
                "identity_unlocked": false,
                "maturity": "pre-alpha"
            }),
        }
    }

    fn write_human(&self) {
        println!("{PRE_ALPHA_WARNING}");
        match self {
            Self::IdentityCreated {
                identity,
                principal_id,
                fingerprint,
                kind,
                kdf_profile,
                protection_degraded,
                durability,
            } => {
                println!("Identity created: {identity}");
                println!("Principal: {principal_id}");
                println!("Fingerprint: {}", grouped(fingerprint));
                println!("Kind: {kind}");
                println!("KDF profile: {kdf_profile}");
                println!("Protection degraded: {protection_degraded}");
                println!("Durability: {durability}");
            }
            Self::IdentityStatus {
                identity,
                principal_id,
                fingerprint,
                kind,
                kdf_profile,
                memory_kib,
                passes,
                lanes,
                stronger_profile_available,
            } => {
                println!("Identity: {identity}");
                println!("Principal: {principal_id}");
                println!("Fingerprint: {}", grouped(fingerprint));
                println!("Kind: {kind}");
                println!("KDF: {kdf_profile}; {memory_kib} KiB; {passes} passes; {lanes} lanes");
                println!("Stronger profile available: {stronger_profile_available}");
                println!("Public fields authenticated: false (unlock not performed)");
            }
            Self::VaultCreated {
                home_source,
                vault_id,
                genesis_fingerprint,
                owner_principal_id,
                local_state,
                durability,
            } => {
                println!("Vault created ({home_source})");
                println!("Vault ID: {vault_id}");
                println!("Genesis fingerprint: {}", grouped(genesis_fingerprint));
                println!("Owner principal: {owner_principal_id}");
                println!("Local state: {local_state}");
                println!("Durability: {durability}");
                println!("Create an owner backup before storing any real data.");
            }
            Self::VaultStatus {
                home_source,
                vault_id,
                genesis_fingerprint,
                policy_sequence,
                current_revision,
                principal_count,
                owner_count,
                item_count,
                artifact_bytes,
            } => {
                println!("Vault status: valid public state ({home_source})");
                println!("Vault ID: {vault_id}");
                println!("Genesis fingerprint: {}", grouped(genesis_fingerprint));
                println!("Policy sequence: {policy_sequence}");
                println!("Current revision: {}", grouped(current_revision));
                println!(
                    "Principals: {principal_count}; owners: {owner_count}; items: {item_count}"
                );
                println!("Capacity: {artifact_bytes}/{MAX_VAULT_BYTES} artifact bytes");
                println!("Identity unlocked: false");
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CliErrorKind {
    InvalidArguments,
    UnsupportedPlatform,
    NotFound,
    Conflict,
    InvalidIdentity,
    AuthenticationFailed,
    InvalidVault,
    ProtectionUnavailable,
    Filesystem,
    LocalState,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CliError {
    kind: CliErrorKind,
    code: &'static str,
    message: &'static str,
}

impl CliError {
    const fn new(kind: CliErrorKind, code: &'static str, message: &'static str) -> Self {
        Self {
            kind,
            code,
            message,
        }
    }

    #[must_use]
    pub const fn exit_code(self) -> u8 {
        match self.kind {
            CliErrorKind::InvalidArguments | CliErrorKind::UnsupportedPlatform => 2,
            CliErrorKind::NotFound => 3,
            CliErrorKind::Conflict => 4,
            CliErrorKind::AuthenticationFailed => 5,
            CliErrorKind::InvalidIdentity
            | CliErrorKind::InvalidVault
            | CliErrorKind::ProtectionUnavailable
            | CliErrorKind::Filesystem
            | CliErrorKind::LocalState => 1,
        }
    }

    pub fn write(self, json: bool) {
        if json {
            eprintln!(
                "{}",
                serde_json::json!({
                    "ok": false,
                    "error": {"code": self.code, "message": self.message},
                    "maturity": "pre-alpha"
                })
            );
        } else {
            eprintln!("jury: {} ({})", self.message, self.code);
        }
    }
}

impl fmt::Debug for CliError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CliError")
            .field("kind", &self.kind)
            .field("code", &self.code)
            .finish()
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message)
    }
}

impl std::error::Error for CliError {}

pub fn execute(cli: Cli) -> Result<CommandOutput, CliError> {
    if !cfg!(target_os = "linux") {
        return Err(CliError::new(
            CliErrorKind::UnsupportedPlatform,
            "unsupported-platform",
            "native vault commands currently support Linux only",
        ));
    }
    let environment = Environment::capture();
    let current = env::current_dir().map_err(|_| filesystem_error())?;
    let protection = if cli.allow_degraded_protection {
        ProtectionPolicy::EmergencyAllowDegraded
    } else {
        ProtectionPolicy::Strict
    };
    match &cli.command {
        Command::Identity {
            command: IdentityCommand::Init(arguments),
        } => identity_init(&cli, arguments, &environment, &current, protection),
        Command::Identity {
            command: IdentityCommand::Status(arguments),
        } => identity_status(&cli, arguments, &environment, &current),
        Command::Init(arguments) => vault_init(&cli, arguments, &environment, &current, protection),
        Command::Vault {
            command: VaultCommand::Init(arguments),
        } => vault_init(&cli, arguments, &environment, &current, protection),
        Command::Vault {
            command: VaultCommand::Status,
        } => vault_status(&cli, &environment, &current),
    }
}

fn identity_init(
    cli: &Cli,
    arguments: &IdentityInitArgs,
    environment: &Environment,
    current: &Path,
    protection: ProtectionPolicy,
) -> Result<CommandOutput, CliError> {
    let home = selected_home(cli, environment, current)?;
    let (selector, display_name) = selected_identity(cli, arguments.name.as_deref(), environment)?;
    validate_explicit_identity_separation(&selector, &home)?;
    let identity_root = identity_root(environment)?;
    validate_detached_separation(&identity_root, &home)?;
    let repositories = repository_refs(&home);
    let exclusions = detached_paths(&home);
    let root =
        HardenedStateRoot::open_or_create_excluding(&identity_root, &repositories, &exclusions)
            .map_err(map_filesystem_error)?;

    let passphrase =
        secret_input::capture(protection, cli.passphrase_stdin, true).map_err(map_secret_error)?;
    let mut creator = IdentityCreator::new();
    let created = creator
        .create(
            arguments.kind.into(),
            arguments.kdf_profile.into(),
            timestamp_ms()?,
            passphrase.memory(),
            |_| false,
        )
        .map_err(|error| map_identity_error(error.kind()))?;
    let bytes = created
        .file
        .to_json_bytes()
        .map_err(|_| invalid_identity())?;
    let protected = protect(&bytes, protection)?;
    let publication = selector
        .prepare(
            &root,
            &repositories,
            &protected,
            PublicationPolicy::CreateNew,
        )
        .map_err(map_filesystem_error)?
        .publish()
        .map_err(map_filesystem_error)?;
    Ok(CommandOutput::IdentityCreated {
        identity: display_name,
        principal_id: hex(created.descriptor.principal_id.as_bytes()),
        fingerprint: hex(created.file.header.descriptor_fingerprint.as_bytes()),
        kind: principal_kind(created.file.header.principal_kind),
        kdf_profile: kdf_profile(created.file.header.kdf_profile),
        protection_degraded: passphrase.protection_degraded(),
        durability: durability(publication),
    })
}

fn identity_status(
    cli: &Cli,
    arguments: &IdentityStatusArgs,
    environment: &Environment,
    current: &Path,
) -> Result<CommandOutput, CliError> {
    let home = selected_home(cli, environment, current)?;
    let (selector, display_name) = selected_identity(cli, arguments.name.as_deref(), environment)?;
    validate_explicit_identity_separation(&selector, &home)?;
    let identity_root = identity_root(environment)?;
    validate_detached_separation(&identity_root, &home)?;
    let repositories = repository_refs(&home);
    let root = HardenedStateRoot::open_existing(&identity_root, &repositories)
        .map_err(map_filesystem_error)?;
    let bytes = selector
        .read(&root, &repositories, MAX_IDENTITY_FILE_BYTES)
        .map_err(map_filesystem_error)?;
    let identity = IdentityFileV1::parse(&bytes).map_err(|_| invalid_identity())?;
    Ok(CommandOutput::IdentityStatus {
        identity: display_name,
        principal_id: hex(identity.header.principal_id.as_bytes()),
        fingerprint: hex(identity.header.descriptor_fingerprint.as_bytes()),
        kind: principal_kind(identity.header.principal_kind),
        kdf_profile: kdf_profile(identity.header.kdf_profile),
        memory_kib: identity.header.memory_kib,
        passes: identity.header.passes,
        lanes: identity.header.lanes,
        stronger_profile_available: identity.header.kdf_profile == KdfProfile::PortableV1,
    })
}

fn vault_init(
    cli: &Cli,
    _: &VaultInitArgs,
    environment: &Environment,
    current: &Path,
    protection: ProtectionPolicy,
) -> Result<CommandOutput, CliError> {
    let mut home = selected_home(cli, environment, current)?;
    let (selector, _) = selected_identity(cli, None, environment)?;
    validate_explicit_identity_separation(&selector, &home)?;
    let identity_root = identity_root(environment)?;
    validate_detached_separation(&identity_root, &home)?;
    let identity_bytes = {
        let repositories = repository_refs(&home);
        let root = HardenedStateRoot::open_existing(&identity_root, &repositories)
            .map_err(map_filesystem_error)?;
        selector
            .read(&root, &repositories, MAX_IDENTITY_FILE_BYTES)
            .map_err(map_filesystem_error)?
    };
    let identity_file = IdentityFileV1::parse(&identity_bytes).map_err(|_| invalid_identity())?;
    let passphrase =
        secret_input::capture(protection, cli.passphrase_stdin, false).map_err(map_secret_error)?;
    let UnlockedIdentity::VaultPrincipal(owner) = unlock(&identity_file, passphrase.memory())
        .map_err(|error| map_identity_error(error.kind()))?
    else {
        return Err(CliError::new(
            CliErrorKind::InvalidIdentity,
            "owner-identity-required",
            "vault initialization requires a human owner identity",
        ));
    };
    if identity_file.header.principal_kind != PrincipalKind::Human {
        return Err(CliError::new(
            CliErrorKind::InvalidIdentity,
            "human-owner-required",
            "vault initialization requires a human owner identity",
        ));
    }

    let created_at_ms = timestamp_ms()?;
    let created_policy = PolicyCreator::new()
        .create(&owner, created_at_ms, |_| false)
        .map_err(|_| invalid_vault())?;
    let genesis_fingerprint = created_policy
        .journal
        .genesis
        .recomputed_fingerprint()
        .map_err(|_| invalid_vault())?;
    let vault = VaultFileV1 {
        header: VaultHeaderV1 {
            magic: "jury-vault".to_owned(),
            version: 1,
            vault_id: created_policy.journal.genesis.vault_id,
            created_at_ms,
            suite: 1,
            policy_schema: 1,
            item_schema: 1,
            identity_schema: 1,
            genesis_fingerprint: genesis_fingerprint.clone(),
        },
        policy: created_policy.journal,
        items: Vec::new(),
        suite_migration: None,
    };
    let vault_bytes = vault.to_json_bytes().map_err(|_| invalid_vault())?;
    let protected_vault = protect(&vault_bytes, protection)?;
    let prepared_shared = prepare_new_vault(&mut home, &protected_vault)?;

    let state_root = resolve_linux_state_root(
        environment.jury_state_home.as_deref(),
        environment.xdg_state_home.as_deref(),
        environment.user_home.as_deref(),
    )
    .map_err(|_| {
        CliError::new(
            CliErrorKind::Filesystem,
            "state-home-unavailable",
            "the separate local-state home is unavailable",
        )
    })?;
    let repositories = repository_refs(&home);
    let exclusions = detached_paths(&home);
    let state = VaultStateDirectory::open_or_create(
        &state_root,
        vault.header.vault_id.as_bytes(),
        vault.header.genesis_fingerprint.as_bytes(),
        &repositories,
        &exclusions,
    )
    .map_err(map_filesystem_error)?;
    let local = PrincipalLocalState::for_vault_principal(
        &owner,
        vault.header.vault_id,
        genesis_fingerprint.clone(),
    )
    .map_err(|_| local_state_error())?;
    let policy = replay_policy(&vault.policy).map_err(|_| invalid_vault())?;
    let candidate = CheckpointCandidate::from_validated(&policy, &vault.policy, &vault.items)
        .map_err(|_| invalid_vault())?;
    let initialized = local
        .initialize(&candidate, created_at_ms)
        .map_err(|_| local_state_error())?;
    let files = local
        .serialize(&initialized)
        .map_err(|_| local_state_error())?;
    let protected_audit = protect(files.audit(), protection)?;
    let protected_checkpoint = protect(files.checkpoint(), protection)?;
    let protected_receipts = protect(files.receipts(), protection)?;
    let locked = state.try_lock().map_err(|_| local_state_error())?;
    let prepared_audit = locked
        .prepare(
            owner.principal_id().as_bytes(),
            PrincipalStateFile::Audit,
            &protected_audit,
        )
        .map_err(map_filesystem_error)?;
    let prepared_checkpoint = locked
        .prepare(
            owner.principal_id().as_bytes(),
            PrincipalStateFile::Checkpoint,
            &protected_checkpoint,
        )
        .map_err(map_filesystem_error)?;
    let prepared_receipts = locked
        .prepare(
            owner.principal_id().as_bytes(),
            PrincipalStateFile::Receipts,
            &protected_receipts,
        )
        .map_err(map_filesystem_error)?;

    let shared_outcome = prepared_shared.publish().map_err(map_filesystem_error)?;
    let mut local_complete = true;
    for prepared in [prepared_audit, prepared_checkpoint, prepared_receipts] {
        match prepared.publish() {
            Ok(PublicationOutcome::PublishedAndSynced) => {}
            Ok(_) | Err(_) => local_complete = false,
        }
    }
    Ok(CommandOutput::VaultCreated {
        home_source: home_source(home.source()),
        vault_id: hex(vault.header.vault_id.as_bytes()),
        genesis_fingerprint: hex(vault.header.genesis_fingerprint.as_bytes()),
        owner_principal_id: hex(owner.principal_id().as_bytes()),
        local_state: if local_complete {
            "initialized"
        } else {
            "recovery-required"
        },
        durability: durability(shared_outcome),
    })
}

fn vault_status(
    cli: &Cli,
    environment: &Environment,
    current: &Path,
) -> Result<CommandOutput, CliError> {
    let home = selected_home(cli, environment, current)?;
    let bytes = read_vault(&home)?;
    let vault = VaultFileV1::parse(&bytes).map_err(|_| invalid_vault())?;
    let policy = replay_policy(&vault.policy).map_err(|_| invalid_vault())?;
    CheckpointCandidate::from_validated(&policy, &vault.policy, &vault.items)
        .map_err(|_| invalid_vault())?;
    Ok(CommandOutput::VaultStatus {
        home_source: home_source(home.source()),
        vault_id: hex(vault.header.vault_id.as_bytes()),
        genesis_fingerprint: hex(vault.header.genesis_fingerprint.as_bytes()),
        policy_sequence: policy.sequence(),
        current_revision: hex(policy.terminal_revision_hash().as_bytes()),
        principal_count: policy.principal_count(),
        owner_count: policy.owner_count(),
        item_count: policy.item_count(),
        artifact_bytes: bytes.len(),
    })
}

fn selected_home(
    cli: &Cli,
    environment: &Environment,
    current: &Path,
) -> Result<VaultHomeLocation, CliError> {
    resolve_vault_home(
        current,
        cli.home.clone(),
        cli.global_home,
        environment.jury_home.as_deref(),
        environment.xdg_data_home.as_deref(),
        environment.user_home.as_deref(),
    )
    .map_err(|error| match error {
        crate::home::HomeSelectionError::Ambiguous
        | crate::home::HomeSelectionError::InvalidPath => CliError::new(
            CliErrorKind::InvalidArguments,
            "invalid-home-selection",
            "vault home selection is invalid",
        ),
        crate::home::HomeSelectionError::UnsupportedPlatform => CliError::new(
            CliErrorKind::UnsupportedPlatform,
            "unsupported-platform",
            "native vault homes currently support Linux only",
        ),
        crate::home::HomeSelectionError::MissingUserHome
        | crate::home::HomeSelectionError::Repository => filesystem_error(),
    })
}

fn selected_identity(
    cli: &Cli,
    command_name: Option<&str>,
    environment: &Environment,
) -> Result<(IdentitySelector, String), CliError> {
    if command_name.is_some() && (cli.identity.is_some() || cli.identity_file.is_some()) {
        return Err(CliError::new(
            CliErrorKind::InvalidArguments,
            "ambiguous-identity-selection",
            "identity selection is ambiguous",
        ));
    }
    let (name, file) = if command_name.is_some() {
        (command_name, None)
    } else if cli.identity.is_some() || cli.identity_file.is_some() {
        (cli.identity.as_deref(), cli.identity_file.clone())
    } else {
        let name = environment
            .jury_identity
            .as_deref()
            .map(|value| {
                value.to_str().ok_or_else(|| {
                    CliError::new(
                        CliErrorKind::InvalidArguments,
                        "invalid-identity-selection",
                        "identity selection is invalid",
                    )
                })
            })
            .transpose()?;
        let file = environment.jury_identity_file.as_ref().map(PathBuf::from);
        (name, file)
    };
    let display = name.unwrap_or(if file.is_some() {
        "explicit-file"
    } else {
        "default"
    });
    let selector = IdentitySelector::select(name, file).map_err(|_| {
        CliError::new(
            CliErrorKind::InvalidArguments,
            "invalid-identity-selection",
            "identity selection is invalid",
        )
    })?;
    Ok((selector, display.to_owned()))
}

fn identity_root(environment: &Environment) -> Result<PathBuf, CliError> {
    resolve_identity_root(
        environment.jury_identity_home.as_deref(),
        environment.xdg_data_home.as_deref(),
        environment.user_home.as_deref(),
    )
    .map_err(|_| filesystem_error())
}

fn validate_explicit_identity_separation(
    selector: &IdentitySelector,
    home: &VaultHomeLocation,
) -> Result<(), CliError> {
    let IdentitySelector::ExplicitFile(path) = selector else {
        return Ok(());
    };
    let Some(vault) = home.detached_path() else {
        return Ok(());
    };
    let parent = path.parent().ok_or_else(filesystem_error)?;
    if overlaps(parent, vault) {
        Err(containment_error())
    } else {
        Ok(())
    }
}

fn validate_detached_separation(
    identity_root: &Path,
    home: &VaultHomeLocation,
) -> Result<(), CliError> {
    if home
        .detached_path()
        .is_some_and(|vault| overlaps(identity_root, vault))
    {
        Err(containment_error())
    } else {
        Ok(())
    }
}

fn overlaps(left: &Path, right: &Path) -> bool {
    left == right || left.starts_with(right) || right.starts_with(left)
}

fn repository_refs(home: &VaultHomeLocation) -> Vec<&RepositoryLocation> {
    home.repository().into_iter().collect()
}

fn detached_paths(home: &VaultHomeLocation) -> Vec<&Path> {
    home.detached_path().into_iter().collect()
}

fn prepare_new_vault(
    home: &mut VaultHomeLocation,
    contents: &ProtectedMemory,
) -> Result<PreparedPrivateFile, CliError> {
    match home {
        VaultHomeLocation::Repository { repository } => {
            repository
                .create_jury_directory()
                .map_err(map_filesystem_error)?;
            repository
                .ensure_vault_attributes()
                .map_err(map_filesystem_error)?;
            PreparedPrivateFile::prepare_encrypted_shared_artifact(
                repository,
                contents,
                PublicationPolicy::CreateNew,
            )
            .map_err(map_filesystem_error)
        }
        VaultHomeLocation::Detached { path, .. } => {
            let root =
                HardenedStateRoot::open_or_create(path, &[]).map_err(map_filesystem_error)?;
            PreparedPrivateFile::prepare_state(
                &root,
                Path::new("vault.json"),
                contents,
                PublicationPolicy::CreateNew,
            )
            .map_err(map_filesystem_error)
        }
    }
}

fn read_vault(home: &VaultHomeLocation) -> Result<Vec<u8>, CliError> {
    match home {
        VaultHomeLocation::Repository { repository } => repository
            .read_encrypted_shared_artifact(MAX_VAULT_BYTES)
            .map_err(map_filesystem_error),
        VaultHomeLocation::Detached { path, .. } => HardenedStateRoot::open_existing(path, &[])
            .and_then(|root| root.read_private_file(Path::new("vault.json"), MAX_VAULT_BYTES))
            .map_err(map_filesystem_error),
    }
}

fn protect(bytes: &[u8], policy: ProtectionPolicy) -> Result<ProtectedMemory, CliError> {
    let initialize = |destination: &mut [u8]| {
        destination.copy_from_slice(bytes);
        Ok::<usize, ()>(bytes.len())
    };
    let result = if bytes.len() > jury_protected::MAX_PROTECTED_BYTES {
        ProtectedMemory::initialize_large(bytes.len(), policy, initialize)
    } else {
        ProtectedMemory::initialize(bytes.len(), policy, initialize)
    };
    result.map_err(|_| {
        CliError::new(
            CliErrorKind::ProtectionUnavailable,
            "protection-unavailable",
            "required protected memory is unavailable",
        )
    })
}

fn timestamp_ms() -> Result<u64, CliError> {
    let milliseconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| local_state_error())?
        .as_millis();
    u64::try_from(milliseconds).map_err(|_| local_state_error())
}

fn map_secret_error(error: secret_input::SecretInputError) -> CliError {
    use secret_input::SecretInputError;
    match error {
        SecretInputError::NonInteractiveRequiresOptIn => CliError::new(
            CliErrorKind::InvalidArguments,
            "passphrase-input-opt-in-required",
            "non-terminal passphrase input requires --passphrase-stdin",
        ),
        SecretInputError::ConfirmationMismatch => CliError::new(
            CliErrorKind::AuthenticationFailed,
            "passphrase-confirmation-mismatch",
            "passphrase confirmation differs",
        ),
        SecretInputError::InputTooLong => CliError::new(
            CliErrorKind::InvalidArguments,
            "passphrase-too-long",
            "passphrase input exceeds its byte bound",
        ),
        SecretInputError::InputUnavailable | SecretInputError::TerminalUnavailable => {
            CliError::new(
                CliErrorKind::ProtectionUnavailable,
                "passphrase-input-unavailable",
                "protected passphrase input is unavailable",
            )
        }
        SecretInputError::ProtectionUnavailable => CliError::new(
            CliErrorKind::ProtectionUnavailable,
            "protection-unavailable",
            "required protected memory is unavailable",
        ),
    }
}

fn map_identity_error(kind: jury_core::identity::IdentityErrorKind) -> CliError {
    use jury_core::identity::IdentityErrorKind;
    match kind {
        IdentityErrorKind::AuthenticationFailed => CliError::new(
            CliErrorKind::AuthenticationFailed,
            "identity-authentication-failed",
            "identity authentication failed",
        ),
        IdentityErrorKind::InvalidPassphrase => CliError::new(
            CliErrorKind::InvalidArguments,
            "invalid-passphrase-profile",
            "passphrase does not meet the exact profile",
        ),
        IdentityErrorKind::ProtectionUnavailable | IdentityErrorKind::ResourceUnavailable => {
            CliError::new(
                CliErrorKind::ProtectionUnavailable,
                "protection-unavailable",
                "required protected memory is unavailable",
            )
        }
        _ => invalid_identity(),
    }
}

fn map_filesystem_error(error: FilesystemError) -> CliError {
    match error.kind() {
        FilesystemErrorKind::NotFound => CliError::new(
            CliErrorKind::NotFound,
            "not-found",
            "the selected state does not exist",
        ),
        FilesystemErrorKind::AlreadyExists => CliError::new(
            CliErrorKind::Conflict,
            "already-exists",
            "the selected destination already exists",
        ),
        FilesystemErrorKind::Containment | FilesystemErrorKind::Alias => containment_error(),
        FilesystemErrorKind::IdentityChanged => CliError::new(
            CliErrorKind::Conflict,
            "state-changed",
            "the selected state changed during the operation",
        ),
        _ => filesystem_error(),
    }
}

const fn invalid_identity() -> CliError {
    CliError::new(
        CliErrorKind::InvalidIdentity,
        "invalid-identity",
        "the selected identity is invalid",
    )
}

const fn invalid_vault() -> CliError {
    CliError::new(
        CliErrorKind::InvalidVault,
        "invalid-vault",
        "the selected vault public state is invalid",
    )
}

const fn filesystem_error() -> CliError {
    CliError::new(
        CliErrorKind::Filesystem,
        "filesystem-error",
        "the selected filesystem state is unavailable",
    )
}

const fn containment_error() -> CliError {
    CliError::new(
        CliErrorKind::InvalidArguments,
        "private-state-overlap",
        "private identity or local state overlaps the selected vault home",
    )
}

const fn local_state_error() -> CliError {
    CliError::new(
        CliErrorKind::LocalState,
        "local-state-error",
        "principal local state could not be initialized",
    )
}

const fn principal_kind(kind: PrincipalKind) -> &'static str {
    match kind {
        PrincipalKind::Human => "human",
        PrincipalKind::Machine => "machine",
        PrincipalKind::Approver => "approver",
        PrincipalKind::Witness => "witness",
    }
}

const fn kdf_profile(profile: KdfProfile) -> &'static str {
    match profile {
        KdfProfile::PortableV1 => "portable-v1",
        KdfProfile::HardenedV1 => "hardened-v1",
    }
}

const fn home_source(source: HomeSource) -> &'static str {
    match source {
        HomeSource::Explicit => "explicit",
        HomeSource::GlobalFlag => "global-flag",
        HomeSource::Environment => "environment",
        HomeSource::Repository => "repository",
        HomeSource::PlatformDefault => "platform-default",
    }
}

const fn durability(outcome: PublicationOutcome) -> &'static str {
    match outcome {
        PublicationOutcome::PublishedAndSynced => "published-and-synced",
        PublicationOutcome::PublishedButParentUnsynced => "published-parent-unsynced",
        PublicationOutcome::PublishedButTemporaryCleanupFailed => {
            "published-temporary-cleanup-failed"
        }
    }
}

fn hex(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(64);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn grouped(fingerprint: &str) -> String {
    let mut grouped = String::with_capacity(fingerprint.len() + fingerprint.len() / 8);
    for (index, character) in fingerprint.chars().enumerate() {
        if index != 0 && index % 8 == 0 {
            grouped.push('-');
        }
        grouped.push(character);
    }
    grouped
}

struct Environment {
    jury_home: Option<OsString>,
    jury_identity_home: Option<OsString>,
    jury_identity: Option<OsString>,
    jury_identity_file: Option<OsString>,
    jury_state_home: Option<OsString>,
    xdg_data_home: Option<OsString>,
    xdg_state_home: Option<OsString>,
    user_home: Option<OsString>,
}

impl Environment {
    fn capture() -> Self {
        Self {
            jury_home: env::var_os("JURY_HOME"),
            jury_identity_home: env::var_os("JURY_IDENTITY_HOME"),
            jury_identity: env::var_os("JURY_IDENTITY"),
            jury_identity_file: env::var_os("JURY_IDENTITY_FILE"),
            jury_state_home: env::var_os("JURY_STATE_HOME"),
            xdg_data_home: env::var_os("XDG_DATA_HOME"),
            xdg_state_home: env::var_os("XDG_STATE_HOME"),
            user_home: env::var_os("HOME"),
        }
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser as _;

    use super::*;

    #[test]
    fn parser_rejects_ambiguous_home_and_identity_flags() {
        assert!(
            Cli::try_parse_from(["jury", "--home", "/tmp/v", "--global", "vault", "status"])
                .is_err()
        );
        assert!(
            Cli::try_parse_from([
                "jury",
                "--identity",
                "one",
                "--identity-file",
                "/tmp/identity.json",
                "identity",
                "status"
            ])
            .is_err()
        );
    }

    #[test]
    fn help_preserves_active_scope_and_warning() -> Result<(), Box<dyn std::error::Error>> {
        let error = match Cli::try_parse_from(["jury", "--help"]) {
            Ok(_) => return Err("help unexpectedly parsed as a command".into()),
            Err(error) => error,
        };
        let help = error.to_string();
        assert!(help.contains("Native Linux support only"));
        assert!(help.contains("PRE-ALPHA"));
        assert!(!help.contains("managed service"));
        assert!(!help.contains("semantic merge"));
        assert!(!help.contains("rollover"));
        Ok(())
    }

    #[test]
    fn grouped_fingerprint_is_stable() {
        assert_eq!(grouped("0011223344556677"), "00112233-44556677");
    }
}
