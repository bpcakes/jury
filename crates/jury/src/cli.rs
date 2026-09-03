//! Native Linux command-line boundary.

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::ffi::OsString;
use std::fmt;
use std::io::{IsTerminal as _, Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use clap::{Args, Parser, Subcommand, ValueEnum};
use jury_core::access_provider::{
    AccessProviderErrorKind, DirectItemAccessProvider, ItemAccessError, ItemAccessOutcome,
    ItemAccessProvider, NeverCancelled, RevisionAccessRequest, RevisionAccessTarget,
};
use jury_core::domain::{Capability, FieldSelector, ItemSelector};
use jury_core::identity::{IdentityCreator, UnlockedIdentity, VaultPrincipalIdentity, unlock};
use jury_core::item::{
    ItemAccessPlan, ItemArtifactInventory, ItemCreator, ItemGrant, NewItem, OwnerChange,
    PrincipalRegistration, PrincipalReplacement, RekeyedItem,
};
use jury_core::local_state::{
    AuditAction, AuditEventDraft, AuditItemScope, AuditOutcome, CheckpointCandidate,
    CheckpointRelation, PrincipalLocalState, ReceiptUpdate, TransferReceipt,
};
use jury_core::mutation::{DirectDowngradeAcknowledgement, MutationKind, VaultMutationPlan};
use jury_core::policy::{
    AccessPath, DescriptorStatus, OperationRule, PlatformAssurance, PolicyCreator, PolicyState,
    WitnessOperation, WitnessPolicy, replay_policy, replay_policy_with_witness_policies,
};
use jury_core::registration::{
    RegistrationChallengeV1, RegistrationCreator, RegistrationErrorKind, RegistrationProofV1,
    RegistrationRoleDescriptorV1, answer_challenge, verify_proof,
};
use jury_core::transfer::{
    ArtifactRelation, TransferCreator, TransferPublicCatalogV1, ValidatedTransfer,
    compare_artifacts, item_deltas,
};
use jury_core::{
    witness_operations::verify_checkpoint_propagation,
    witness_receipt::{ReceiptPolicyMaterialV1, VerifiedWitnessReceipt, verify_witness_receipt},
};
use jury_filesystem::{
    FilesystemError, FilesystemErrorKind, HardenedStateRoot, IdentitySelector, LockedVaultState,
    PreparedPrivateFile, PreparedPublicFile, PrincipalStateFile, PublicationOutcome,
    PublicationPolicy, RepositoryLocation, VaultStateDirectory, VaultStateFile,
    list_named_identities, preview_public_file, read_public_file, resolve_linux_state_root,
};
use jury_protected::{OsRandom, ProtectedMemory, ProtectionPolicy, RandomSource};
use jury_protocol::identity_v1::{IdentityFileV1, KdfProfile, MAX_IDENTITY_FILE_BYTES};
use jury_protocol::transfer_v1::MAX_TRANSFER_BYTES;
use jury_protocol::vault_v1::{
    AccessRole, ContentRole, Digest32, ItemAccessMode, ItemDescriptorV1, ItemEnvelopeV1,
    ItemFieldKind, ItemFieldV1, ItemFieldValue, ItemKind, ItemStateV1, MAX_FIELD_VALUE_BYTES,
    MAX_ITEM_REVISION_PROOFS, MAX_ITEMS, MAX_POLICY_REVISIONS, MAX_PUBLIC_LABEL_BYTES,
    MAX_VAULT_BYTES, PolicyOperationV1, PrincipalDescriptorV1, PrincipalId, PrincipalKind,
    RemovalReason, VaultFileV1, VaultHeaderV1, WitnessPolicyId,
};
use jury_protocol::witness_v1::{
    MAX_RECEIPT_JSON_BYTES, PolicyMaterialBytes, VaultPolicyCheckpointV1,
    WitnessCheckpointAcknowledgementV1, WitnessReceiptV1,
};
use sha2::{Digest as _, Sha256};
use zeroize::{Zeroize as _, Zeroizing};

use crate::home::{HomeSource, VaultHomeLocation, resolve_identity_root, resolve_vault_home};
use crate::mutation_commit::{
    DetachedMutationTarget, MutationCatalogUpdate, MutationCommitOutcome, RepositoryMutationTarget,
};
use crate::secret_input;

pub use self::argument_values::*;
pub use self::dispatch::execute;
pub use self::output::{CliError, CliErrorKind, CommandOutput, FieldSummary, IdentitySummary};
use self::{
    access_commands::*, context::*, environment::*, execution_commands::*, identity_commands::*,
    item_commands::*, mutation_commands::*, policy_commands::*, principal_commands::*,
    receipt_commands::*, support::*, template_commands::*, transfer_commands::*, transfer_state::*,
    trust_confirmation::*, vault_commands::*, witness_commands::*,
};

mod access_commands;
mod argument_values;
mod context;
mod dispatch;
mod environment;
mod execution_commands;
mod identity_commands;
mod item_commands;
mod mutation_commands;
mod output;
mod policy_commands;
mod principal_commands;
mod receipt_commands;
mod support;
mod template_commands;
mod transfer_commands;
mod transfer_state;
mod trust_confirmation;
mod vault_commands;
mod witness_commands;

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

    /// Pin the expected vault genesis for non-interactive first private use.
    #[arg(long, global = true, value_name = "FINGERPRINT")]
    pub expected_genesis: Option<String>,

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
    /// Manage registered vault principals and owner authority.
    Principal {
        #[command(subcommand)]
        command: PrincipalCommand,
    },
    /// Inspect and change item-scoped principal access.
    Access {
        #[command(subcommand)]
        command: AccessCommand,
    },
    /// Create encrypted item compartments.
    Item {
        #[command(subcommand)]
        command: ItemCommand,
    },
    /// Configure direct and witnessed item authority.
    Policy {
        #[command(subcommand)]
        command: PolicyCommand,
    },
    /// Reseal unchanged item state to provide bounded privacy cover.
    Privacy {
        #[command(subcommand)]
        command: PrivacyCommand,
    },
    /// Inspect bounded public lineage capacity.
    History {
        #[command(subcommand)]
        command: HistoryCommand,
    },
    /// Export, inspect, and import authenticated portable ciphertext.
    Transfer {
        #[command(subcommand)]
        command: TransferCommand,
    },
    /// Inspect or independently verify a witnessed-decision receipt offline.
    Receipt {
        #[command(subcommand)]
        command: ReceiptCommand,
    },
    /// Inspect independently collected witness operational evidence offline.
    Witness {
        #[command(subcommand)]
        command: WitnessCommand,
    },
    /// Resolve one field to an explicitly selected private sink.
    Read(ReadArgs),
    /// Resolve a bounded template to an explicitly selected private sink.
    Inject(InjectArgs),
    /// Transparently execute a command with atomic Jury field injection.
    #[command(
        long_about = "Transparently execute a command after every Jury field reference resolves atomically. Output is streamed after redaction and the exact child status is returned. PRE-ALPHA: do not use with real secrets.",
        after_help = "Native Linux only. An authorized child can copy or retain every plaintext value it receives."
    )]
    Exec(ExecArgs),
    /// Run a command through a cleaned, bounded Jury broker.
    #[command(
        long_about = "Run a command through Jury's cleaned, timeout-bounded, output-bounded broker after every field reference resolves atomically. PRE-ALPHA: do not use with real secrets.",
        after_help = "Native Linux only. An authorized child can copy or retain every plaintext value it receives."
    )]
    Run(RunArgs),
    #[command(hide = true)]
    InternalExec(InternalExecArgs),
}

#[derive(Debug, Subcommand)]
pub enum IdentityCommand {
    /// Create one portable passphrase-protected identity.
    Init(IdentityInitArgs),
    /// List canonical named identities without unlocking them.
    List,
    /// Inspect the bounded public identity header without unlocking it.
    Status(IdentityStatusArgs),
    /// Export the selected identity's signed public descriptor.
    Public(IdentityPublicArgs),
    /// Answer an authenticated registration challenge without exposing it.
    Prove(IdentityProveArgs),
    /// Change identity storage credentials.
    Passphrase {
        #[command(subcommand)]
        command: IdentityPassphraseCommand,
    },
}

#[derive(Debug, Subcommand)]
pub enum IdentityPassphraseCommand {
    /// Re-encrypt the same private identity payload under a new passphrase.
    Change(IdentityPassphraseChangeArgs),
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

    /// Create the public proof at this absolute path.
    #[arg(long, value_name = "FILE")]
    pub out: PathBuf,

    /// Replace an existing regular owner-only destination.
    #[arg(long)]
    pub overwrite: bool,
}

#[derive(Debug, Args, Default)]
pub struct VaultInitArgs {}

#[derive(Debug, Subcommand)]
pub enum VaultCommand {
    /// Create one empty encrypted vault owned by the selected human identity.
    Init(VaultInitArgs),
    /// Validate and inspect public vault state without unlocking an identity.
    Status,
    /// Manage fields inside accessible encrypted items.
    Field {
        #[command(subcommand)]
        command: FieldCommand,
    },
    /// Resolve one field to an explicitly selected private sink.
    Read(ReadArgs),
    /// Verify the selected principal's authenticated local activity evidence.
    Audit {
        #[command(subcommand)]
        command: AuditCommand,
    },
}

#[derive(Debug, Subcommand)]
pub enum FieldCommand {
    /// List fields only from items accessible to the selected identity.
    List(FieldListArgs),
    /// Create or replace one field using protected standard input.
    Set(FieldSetArgs),
    /// Remove one field from an accessible item.
    Remove(FieldRemoveArgs),
}

#[derive(Debug, Args)]
pub struct FieldListArgs {
    /// Optional canonical item name; omission lists all accessible fields.
    #[arg(value_name = "ITEM")]
    pub item: Option<String>,
}

#[derive(Debug, Args)]
pub struct FieldSetArgs {
    #[arg(value_name = "ITEM")]
    pub item: String,
    #[arg(value_name = "FIELD")]
    pub field: String,
    /// Mark this value for output redaction when later used by process commands.
    #[arg(long)]
    pub concealed: bool,
    /// Read the field value from standard input; required for non-terminal use.
    #[arg(long)]
    pub value_stdin: bool,
    /// Prepare and authenticate the exact mutation without writing it.
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Debug, Args)]
pub struct FieldRemoveArgs {
    #[arg(value_name = "ITEM")]
    pub item: String,
    #[arg(value_name = "FIELD")]
    pub field: String,
    /// Prepare and authenticate the exact mutation without writing it.
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Debug, Args)]
pub struct ReadArgs {
    #[arg(value_name = "ITEM")]
    pub item: String,
    #[arg(value_name = "FIELD")]
    pub field: String,
    /// Atomically create a private file instead of writing to the terminal.
    #[arg(long, value_name = "FILE", conflicts_with = "reveal")]
    pub out: Option<PathBuf>,
    /// Permit raw terminal/stdout output. Never valid with `--json`.
    #[arg(long)]
    pub reveal: bool,
    /// Replace an existing private output file.
    #[arg(long, requires = "out")]
    pub overwrite: bool,
}

#[derive(Debug, Args)]
pub struct InjectArgs {
    /// Bounded UTF-8 template containing `{{Item.Field}}` references.
    #[arg(long, value_name = "FILE")]
    pub template: PathBuf,
    /// Atomically create the resolved private output file.
    #[arg(long, value_name = "FILE", conflicts_with = "reveal")]
    pub out: Option<PathBuf>,
    /// Permit resolved output on the terminal/stdout. Never valid with `--json`.
    #[arg(long)]
    pub reveal: bool,
    /// Replace an existing private output file.
    #[arg(long, requires = "out")]
    pub overwrite: bool,
}

#[derive(Debug, Args)]
pub struct ExecArgs {
    /// Restricted dotenv file containing literal or `{{Item.Field}}` values.
    #[arg(long, value_name = "FILE")]
    pub env_file: Option<PathBuf>,
    /// Replace inherited stdin with one exact `Item.Field` value.
    #[arg(long, value_name = "ITEM.FIELD")]
    pub stdin: Option<String>,
    /// Expose one field through a sealed anonymous file named by an env var.
    #[arg(long = "file", value_name = "VAR=ITEM.FIELD")]
    pub files: Vec<String>,
    /// Run from this existing directory; defaults to the current directory.
    #[arg(long, value_name = "DIRECTORY")]
    pub cwd: Option<PathBuf>,
    /// Exact command and non-secret arguments; `--` is required.
    #[arg(last = true, required = true, allow_hyphen_values = true)]
    pub command: Vec<OsString>,
}

#[derive(Debug, Args)]
pub struct RunArgs {
    /// Inject one field as `VAR=Item.Field`; may be repeated.
    #[arg(long = "env", value_name = "VAR=ITEM.FIELD")]
    pub env: Vec<String>,
    /// Expose one field through a sealed anonymous file named by an env var.
    #[arg(long = "file", value_name = "VAR=ITEM.FIELD")]
    pub files: Vec<String>,
    /// Deliver one exact `Item.Field` value on child stdin.
    #[arg(long, value_name = "ITEM.FIELD")]
    pub stdin: Option<String>,
    /// Run from this existing directory; defaults to the current directory.
    #[arg(long, value_name = "DIRECTORY")]
    pub cwd: Option<PathBuf>,
    /// Terminate the complete process tree after this many seconds.
    #[arg(long, value_name = "SECONDS", default_value_t = 1_800)]
    pub timeout: u64,
    /// Retain at most this many post-redaction bytes per output stream.
    #[arg(long, value_name = "BYTES", default_value_t = 1_048_576)]
    pub output_limit: usize,
    /// Exact command and non-secret arguments; `--` is required.
    #[arg(last = true, required = true, allow_hyphen_values = true)]
    pub command: Vec<OsString>,
}

#[derive(Debug, Args)]
pub struct InternalExecArgs {
    #[arg(long, hide = true)]
    pub executable_fd: i32,
    #[arg(long, hide = true)]
    pub working_directory_fd: i32,
    #[arg(long = "keep-fd", hide = true)]
    pub keep_fds: Vec<i32>,
    #[arg(last = true, required = true, allow_hyphen_values = true, hide = true)]
    pub command: Vec<OsString>,
}

#[derive(Debug, Subcommand)]
pub enum AuditCommand {
    /// Verify this identity's local Jury v1 audit/checkpoint/receipt state.
    Verify,
}

#[derive(Debug, Subcommand)]
pub enum HistoryCommand {
    /// Report value-free public capacity usage and remaining headroom.
    Status,
}

#[derive(Debug, Subcommand)]
pub enum TransferCommand {
    /// Export the exact validated shared ciphertext artifact.
    Export(TransferExportArgs),
    /// Inspect and optionally compare a transfer without mutating state.
    Inspect(TransferInspectArgs),
    /// Import identical state or an authority-preserving authenticated strict descendant.
    Import(TransferImportArgs),
    /// Compare current state with this identity's last local export receipt.
    Status,
}

#[derive(Debug, Subcommand)]
pub enum ReceiptCommand {
    /// Parse bounded receipt metadata without claiming that its evidence verifies.
    Inspect(ReceiptInspectArgs),
    /// Verify all embedded public evidence without network access or an identity.
    Verify(ReceiptVerifyArgs),
}

#[derive(Debug, Args)]
pub struct ReceiptInspectArgs {
    #[arg(value_name = "RECEIPT")]
    pub receipt: PathBuf,
}

#[derive(Debug, Args)]
pub struct ReceiptVerifyArgs {
    #[arg(value_name = "RECEIPT")]
    pub receipt: PathBuf,
    /// Pin an independently retained exact policy checkpoint.
    #[arg(long, value_name = "CHECKPOINT")]
    pub checkpoint: Option<PathBuf>,
}

#[derive(Debug, Subcommand)]
pub enum WitnessCommand {
    /// Export the exact public journal and witnessed-policy catalog for distribution.
    PolicyMaterial(WitnessPolicyMaterialArgs),
    /// Classify one checkpoint as proposed, partial, or durably accepted.
    PolicyStatus(WitnessPolicyStatusArgs),
}

#[derive(Debug, Args)]
pub struct WitnessPolicyMaterialArgs {
    /// Create this public JSON file; existing paths are never replaced.
    #[arg(long, value_name = "FILE")]
    pub output: PathBuf,
}

#[derive(Debug, Args)]
pub struct WitnessPolicyStatusArgs {
    /// Complete owner-signed public policy material for the checkpoint.
    #[arg(long, value_name = "POLICY_MATERIAL")]
    pub policy_material: PathBuf,
    #[arg(long, value_name = "CHECKPOINT")]
    pub checkpoint: PathBuf,
    /// Per-witness acknowledgement or accepted-response file; may be repeated.
    #[arg(long = "acknowledgement", value_name = "ACKNOWLEDGEMENT")]
    pub acknowledgements: Vec<PathBuf>,
}

#[derive(Debug, Args)]
pub struct TransferExportArgs {
    #[arg(long, value_name = "FILE")]
    pub out: PathBuf,
    #[arg(long)]
    pub overwrite: bool,
}

#[derive(Debug, Args)]
pub struct TransferInspectArgs {
    #[arg(long = "in", value_name = "FILE")]
    pub input: PathBuf,
    #[arg(long)]
    pub against_current: bool,
    #[arg(long)]
    pub me: bool,
}

#[derive(Debug, Args)]
pub struct TransferImportArgs {
    #[arg(long = "in", value_name = "FILE")]
    pub input: PathBuf,
    #[arg(long)]
    pub dry_run: bool,
    /// Permit a first installation when this identity has no effective item access.
    #[arg(long)]
    pub allow_no_access: bool,
}

#[derive(Debug, Subcommand)]
pub enum ItemCommand {
    /// Create an empty item with explicit initial access.
    Create(ItemCreateArgs),
}

#[derive(Debug, Args)]
pub struct ItemCreateArgs {
    #[arg(value_name = "ITEM")]
    pub item: String,
    /// Initial reader principal; may be repeated.
    #[arg(long = "reader", value_name = "PRINCIPAL")]
    pub readers: Vec<String>,
    /// Initial writer principal; may be repeated.
    #[arg(long = "writer", value_name = "PRINCIPAL")]
    pub writers: Vec<String>,
    /// Create direct slots and acknowledge unilateral access semantics.
    #[arg(long)]
    pub allow_direct: bool,
    /// Prepare and authenticate the exact mutation without writing it.
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Debug, Subcommand)]
pub enum PrincipalCommand {
    List,
    Challenge(PrincipalChallengeArgs),
    Add(PrincipalAddArgs),
    Replace(PrincipalReplaceArgs),
    Label(PrincipalLabelArgs),
    Remove(PrincipalRemoveArgs),
    GrantOwner(PrincipalTargetArgs),
    RevokeOwner(PrincipalTargetArgs),
}

#[derive(Debug, Args)]
pub struct PrincipalChallengeArgs {
    #[arg(long, value_name = "PUBLIC_DESCRIPTOR")]
    pub from: PathBuf,
    #[arg(long, value_name = "CHALLENGE")]
    pub out: PathBuf,
    /// Assign the witness's stable protocol share coordinate in 1..=32.
    #[arg(
        long = "witness-share-index",
        value_name = "INDEX",
        value_parser = clap::value_parser!(u8).range(1..=32)
    )]
    pub witness_share_index: Option<u8>,
    #[arg(long)]
    pub overwrite: bool,
}

#[derive(Debug, Args)]
pub struct PrincipalAddArgs {
    #[arg(long, value_name = "PUBLIC_DESCRIPTOR")]
    pub from: PathBuf,
    #[arg(long, value_name = "PROOF")]
    pub proof: PathBuf,
    #[arg(long = "reader", value_name = "ITEM")]
    pub readers: Vec<String>,
    #[arg(long = "writer", value_name = "ITEM")]
    pub writers: Vec<String>,
    /// Acknowledge unilateral direct access for initial item grants.
    #[arg(long)]
    pub acknowledge_direct_access: bool,
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Debug, Args)]
pub struct PrincipalReplaceArgs {
    #[arg(value_name = "PRINCIPAL")]
    pub principal: String,
    #[arg(long, value_name = "PUBLIC_DESCRIPTOR")]
    pub from: PathBuf,
    #[arg(long, value_name = "PROOF")]
    pub proof: PathBuf,
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Debug, Args)]
pub struct PrincipalLabelArgs {
    #[arg(value_name = "PRINCIPAL")]
    pub principal: String,
    #[arg(long, value_name = "LABEL")]
    pub label: String,
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Debug, Args)]
pub struct PrincipalRemoveArgs {
    #[arg(value_name = "PRINCIPAL")]
    pub principal: String,
    #[arg(long)]
    pub revoke_all: bool,
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Debug, Args)]
pub struct PrincipalTargetArgs {
    #[arg(value_name = "PRINCIPAL")]
    pub principal: String,
    /// Acknowledge any new unilateral direct slots created by owner grant.
    #[arg(long)]
    pub acknowledge_direct_access: bool,
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Debug, Subcommand)]
pub enum AccessCommand {
    List(AccessListArgs),
    Matrix,
    Explain(AccessExplainArgs),
    Check(AccessExplainArgs),
    Grant(AccessGrantArgs),
    Change(AccessChangeArgs),
    Revoke(AccessRevokeArgs),
}

#[derive(Debug, Args)]
pub struct AccessListArgs {
    #[arg(value_name = "ITEM", conflicts_with = "me")]
    pub item: Option<String>,
    #[arg(long, required_unless_present = "item")]
    pub me: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum RequiredCapabilityArg {
    Read,
    Write,
    Owner,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum AccessRoleArg {
    Reader,
    Writer,
}

#[derive(Debug, Args)]
pub struct AccessExplainArgs {
    #[arg(value_name = "ITEM")]
    pub item: String,
    #[arg(long, value_enum)]
    pub require: Option<RequiredCapabilityArg>,
}

#[derive(Debug, Args)]
pub struct AccessGrantArgs {
    #[arg(value_name = "ITEM")]
    pub item: Option<String>,
    #[arg(long, value_name = "PRINCIPAL")]
    pub principal: String,
    #[arg(long, value_enum, requires = "item")]
    pub role: Option<AccessRoleArg>,
    #[arg(long = "reader", value_name = "ITEM")]
    pub readers: Vec<String>,
    #[arg(long = "writer", value_name = "ITEM")]
    pub writers: Vec<String>,
    /// Acknowledge unilateral direct access for the new recipient.
    #[arg(long)]
    pub acknowledge_direct_access: bool,
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Debug, Args)]
pub struct AccessChangeArgs {
    #[arg(value_name = "ITEM")]
    pub item: String,
    #[arg(long, value_name = "PRINCIPAL")]
    pub principal: String,
    #[arg(long, value_enum)]
    pub role: AccessRoleArg,
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Debug, Args)]
pub struct AccessRevokeArgs {
    #[arg(value_name = "ITEM")]
    pub item: String,
    #[arg(long, value_name = "PRINCIPAL")]
    pub principal: String,
    #[arg(long)]
    pub dry_run: bool,
}

include!("cli/policy_args.rs");

#[cfg(test)]
#[path = "cli/tests.rs"]
mod tests;
