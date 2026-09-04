#[derive(Debug, Subcommand)]
pub enum RequestCommand {
    /// Create one signed public request artifact for exact review.
    Create(RequestCreateArgs),
    /// Validate and render one complete request artifact.
    Inspect(RequestArtifactArgs),
    /// Report the current local phase of one request artifact.
    Status(RequestArtifactArgs),
    /// Execute a request while retaining its fresh session key in memory.
    Execute(RequestExecuteArgs),
    /// Sign cancellation intent for one exact request.
    Cancel(RequestCancelArgs),
}
#[derive(Debug, Args)]
pub struct RequestCreateArgs {
    /// Exact owner-published non-secret item review label.
    #[arg(
        long,
        value_name = "PUBLIC_LABEL",
        conflicts_with = "item_id",
        required_unless_present = "item_id"
    )]
    pub item: Option<String>,
    /// Opaque item ID, intended for explicitly configured automatic rules.
    #[arg(long, value_name = "ITEM_ID", conflicts_with = "item")]
    pub item_id: Option<String>,
    /// Exact owner-published non-secret field review label.
    #[arg(
        long,
        value_name = "PUBLIC_LABEL",
        conflicts_with = "field_id",
        required_unless_present = "field_id"
    )]
    pub field: Option<String>,
    /// Opaque field ID, intended for explicitly configured automatic rules.
    #[arg(long, value_name = "FIELD_ID", conflicts_with = "field")]
    pub field_id: Option<String>,
    #[arg(long, value_name = "CHECKPOINT")]
    pub checkpoint: PathBuf,
    #[arg(long, value_name = "FILE")]
    pub out: PathBuf,
}

#[derive(Debug, Args)]
pub struct RequestArtifactArgs {
    #[arg(value_name = "REQUEST")]
    pub request: PathBuf,
}

#[derive(Debug, Args)]
pub struct RequestExecuteArgs {
    /// Exact owner-published non-secret item review label.
    #[arg(
        long,
        value_name = "PUBLIC_LABEL",
        conflicts_with = "item_id",
        required_unless_present = "item_id"
    )]
    pub item: Option<String>,
    /// Opaque item ID, intended for explicitly configured automatic rules.
    #[arg(long, value_name = "ITEM_ID", conflicts_with = "item")]
    pub item_id: Option<String>,
    /// Exact owner-published non-secret field review label.
    #[arg(
        long,
        value_name = "PUBLIC_LABEL",
        conflicts_with = "field_id",
        required_unless_present = "field_id"
    )]
    pub field: Option<String>,
    /// Opaque field ID, intended for explicitly configured automatic rules.
    #[arg(long, value_name = "FIELD_ID", conflicts_with = "field")]
    pub field_id: Option<String>,
    #[arg(long, value_name = "CHECKPOINT")]
    pub checkpoint: PathBuf,
    /// Atomically publish the reviewable request while this process retains its session key.
    #[arg(long, value_name = "FILE")]
    pub request_out: PathBuf,
    /// Create the contribution-free public decision receipt here on success.
    #[arg(long, value_name = "FILE")]
    pub receipt: PathBuf,
    /// Expected approval file; may be created asynchronously after the request appears.
    #[arg(long = "approval", value_name = "FILE")]
    pub approvals: Vec<PathBuf>,
    /// Witness endpoint as WITNESS_ID,BASE_URL,CREDENTIAL_FILE[,CA_CERTIFICATE].
    #[arg(long = "witness", value_name = "ENDPOINT", required = true)]
    pub witnesses: Vec<String>,
    /// Permit literal-IP loopback HTTP endpoints for local testing.
    #[arg(long)]
    pub allow_insecure_loopback: bool,
    /// Maximum seconds to wait for the declared approval files.
    #[arg(long, value_name = "SECONDS", default_value_t = 300)]
    pub wait_seconds: u64,
    /// Atomically create a private output file instead of revealing stdout.
    #[arg(long, value_name = "FILE", conflicts_with = "reveal")]
    pub out: Option<PathBuf>,
    /// Permit raw field bytes on stdout. Never valid with `--json`.
    #[arg(long)]
    pub reveal: bool,
    #[arg(long, requires = "out")]
    pub overwrite: bool,
}

#[derive(Debug, Args)]
pub struct RequestCancelArgs {
    #[arg(value_name = "REQUEST")]
    pub request: PathBuf,
    #[arg(long, value_name = "FILE")]
    pub out: PathBuf,
    /// Witness endpoint as WITNESS_ID,BASE_URL,CREDENTIAL_FILE[,CA_CERTIFICATE].
    #[arg(long = "witness", value_name = "ENDPOINT", required = true)]
    pub witnesses: Vec<String>,
    /// Permit literal-IP loopback HTTP endpoints for local testing.
    #[arg(long)]
    pub allow_insecure_loopback: bool,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum ApprovalReasonArg {
    PolicyDenied,
    WrongScope,
    WrongOperation,
    WorkloadExceeded,
}

#[derive(Debug, Args)]
pub struct ApproveArgs {
    #[arg(value_name = "REQUEST")]
    pub request: PathBuf,
    /// Sign a denial instead of an approval.
    #[arg(long)]
    pub deny: bool,
    /// Stable public denial reason; valid only with `--deny`.
    #[arg(long, value_enum, requires = "deny")]
    pub reason: Option<ApprovalReasonArg>,
    /// Create this public signed-decision file.
    #[arg(long, value_name = "FILE")]
    pub out: PathBuf,
}

#[derive(Debug, Args)]
pub struct WitnessCheckpointArgs {
    /// Opaque public identifier of an item using the current witnessed policy.
    #[arg(long, value_name = "ITEM_ID")]
    pub item_id: String,
    /// Prior checkpoint in the same chain; omit only for the first checkpoint.
    #[arg(long, value_name = "CHECKPOINT")]
    pub predecessor: Option<PathBuf>,
    /// Create this public JSON file; existing paths are never replaced.
    #[arg(long, value_name = "FILE")]
    pub output: PathBuf,
}
