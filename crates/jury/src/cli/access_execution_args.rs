#[derive(Debug, Args)]
pub struct ReadArgs {
    /// Private item name in `--direct` mode, or an exact public review label otherwise.
    #[arg(value_name = "ITEM", conflicts_with = "item_id")]
    pub item: Option<String>,
    /// Private field name in `--direct` mode, or an exact public review label otherwise.
    #[arg(value_name = "FIELD", conflicts_with = "field_id")]
    pub field: Option<String>,
    /// Opaque item ID for a governed automatic-read rule.
    #[arg(long, value_name = "ITEM_ID", conflicts_with = "item")]
    pub item_id: Option<String>,
    /// Opaque field ID for a governed automatic-read rule.
    #[arg(long, value_name = "FIELD_ID", conflicts_with = "field")]
    pub field_id: Option<String>,
    /// Atomically create a private file instead of writing to the terminal.
    #[arg(long, value_name = "FILE", conflicts_with = "reveal")]
    pub out: Option<PathBuf>,
    /// Permit raw terminal/stdout output. Never valid with `--json`.
    #[arg(long)]
    pub reveal: bool,
    /// Replace an existing private output file.
    #[arg(long, requires = "out")]
    pub overwrite: bool,
    /// Use a unilateral direct recipient slot instead of governed witnessed authority.
    #[arg(long)]
    pub direct: bool,
    #[arg(long, value_name = "CHECKPOINT", conflicts_with = "direct")]
    pub checkpoint: Option<PathBuf>,
    #[arg(long, value_name = "FILE", conflicts_with = "direct")]
    pub request_out: Option<PathBuf>,
    #[arg(long, value_name = "FILE", conflicts_with = "direct")]
    pub receipt: Option<PathBuf>,
    #[arg(long = "approval", value_name = "FILE", conflicts_with = "direct")]
    pub approvals: Vec<PathBuf>,
    #[arg(long = "witness", value_name = "ENDPOINT", conflicts_with = "direct")]
    pub witnesses: Vec<String>,
    #[arg(long, conflicts_with = "direct")]
    pub allow_insecure_loopback: bool,
    #[arg(
        long,
        value_name = "SECONDS",
        default_value_t = 300,
        conflicts_with = "direct"
    )]
    pub wait_seconds: u64,
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
    /// Use unilateral direct recipient slots instead of governed witnessed authority.
    #[arg(long)]
    pub direct: bool,
    #[arg(long, value_name = "CHECKPOINT", conflicts_with = "direct")]
    pub checkpoint: Option<PathBuf>,
    #[arg(long, value_name = "FILE", conflicts_with = "direct")]
    pub request_out: Option<PathBuf>,
    #[arg(long, value_name = "FILE", conflicts_with = "direct")]
    pub receipt: Option<PathBuf>,
    #[arg(long = "approval", value_name = "FILE", conflicts_with = "direct")]
    pub approvals: Vec<PathBuf>,
    #[arg(long = "witness", value_name = "ENDPOINT", conflicts_with = "direct")]
    pub witnesses: Vec<String>,
    #[arg(long, conflicts_with = "direct")]
    pub allow_insecure_loopback: bool,
    #[arg(
        long,
        value_name = "SECONDS",
        default_value_t = 300,
        conflicts_with = "direct"
    )]
    pub wait_seconds: u64,
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
    /// Use unilateral direct recipient slots instead of governed witnessed authority.
    #[arg(long)]
    pub direct: bool,
    #[arg(long, value_name = "CHECKPOINT", conflicts_with = "direct")]
    pub checkpoint: Option<PathBuf>,
    #[arg(long, value_name = "FILE", conflicts_with = "direct")]
    pub request_out: Option<PathBuf>,
    #[arg(long, value_name = "FILE", conflicts_with = "direct")]
    pub receipt: Option<PathBuf>,
    #[arg(long = "approval", value_name = "FILE", conflicts_with = "direct")]
    pub approvals: Vec<PathBuf>,
    #[arg(long = "witness", value_name = "ENDPOINT", conflicts_with = "direct")]
    pub witnesses: Vec<String>,
    #[arg(long, conflicts_with = "direct")]
    pub allow_insecure_loopback: bool,
    #[arg(
        long,
        value_name = "SECONDS",
        default_value_t = 300,
        conflicts_with = "direct"
    )]
    pub wait_seconds: u64,
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
    /// Use unilateral direct recipient slots instead of governed witnessed authority.
    #[arg(long)]
    pub direct: bool,
    #[arg(long, value_name = "CHECKPOINT", conflicts_with = "direct")]
    pub checkpoint: Option<PathBuf>,
    #[arg(long, value_name = "FILE", conflicts_with = "direct")]
    pub request_out: Option<PathBuf>,
    #[arg(long, value_name = "FILE", conflicts_with = "direct")]
    pub receipt: Option<PathBuf>,
    #[arg(long = "approval", value_name = "FILE", conflicts_with = "direct")]
    pub approvals: Vec<PathBuf>,
    #[arg(long = "witness", value_name = "ENDPOINT", conflicts_with = "direct")]
    pub witnesses: Vec<String>,
    #[arg(long, conflicts_with = "direct")]
    pub allow_insecure_loopback: bool,
    #[arg(
        long,
        value_name = "SECONDS",
        default_value_t = 300,
        conflicts_with = "direct"
    )]
    pub wait_seconds: u64,
}
