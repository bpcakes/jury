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
    /// Current owner-signed checkpoint JSON accepted by the selected witnesses; required unless --direct.
    #[arg(long, value_name = "CHECKPOINT", conflicts_with = "direct")]
    pub checkpoint: Option<PathBuf>,
    /// Required unless --direct: publish a fresh request here and keep this process running while another terminal approves it.
    #[arg(long, value_name = "FILE", conflicts_with = "direct")]
    pub request_out: Option<PathBuf>,
    /// Required unless --direct: create a public receipt at this absent path after successful witnessed access.
    #[arg(long, value_name = "FILE", conflicts_with = "direct")]
    pub receipt: Option<PathBuf>,
    /// Signed approval file; repeat for each approver. Files may appear while this command waits.
    #[arg(long = "approval", value_name = "FILE", conflicts_with = "direct")]
    pub approvals: Vec<PathBuf>,
    /// WITNESS_ID,BASE_URL,CREDENTIAL_FILE[,CA_CERTIFICATE]; repeat for each witness.
    /// Credential files are owner-only; HTTPS requires an explicit CA certificate.
    #[arg(long = "witness", value_name = "ENDPOINT", conflicts_with = "direct")]
    pub witnesses: Vec<String>,
    /// Permit literal-IP loopback HTTP for synthetic local testing.
    #[arg(long, conflicts_with = "direct")]
    pub allow_insecure_loopback: bool,
    /// Wait up to 0..=900 seconds for approval files; request expiry can end the wait sooner.
    #[arg(
        long,
        value_name = "SECONDS",
        default_value_t = 300,
        value_parser = clap::value_parser!(u64).range(0..=900),
        conflicts_with = "direct"
    )]
    pub wait_seconds: u64,
}
#[derive(Debug, Args)]
pub struct InjectArgs {
    /// Bounded UTF-8 template containing `{{Item/Field}}` references.
    /// Legacy Item.Field shorthand is accepted only when neither name contains a dot.
    /// Other public labels use a JSON pair: `{{["item label","field label"]}}`.
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
    /// Current owner-signed checkpoint JSON accepted by the selected witnesses; required unless --direct.
    #[arg(long, value_name = "CHECKPOINT", conflicts_with = "direct")]
    pub checkpoint: Option<PathBuf>,
    /// Required unless --direct: publish a fresh request here and keep this process running while another terminal approves it.
    #[arg(long, value_name = "FILE", conflicts_with = "direct")]
    pub request_out: Option<PathBuf>,
    /// Required unless --direct: create a public receipt at this absent path after successful witnessed access.
    #[arg(long, value_name = "FILE", conflicts_with = "direct")]
    pub receipt: Option<PathBuf>,
    /// Signed approval file; repeat for each approver. Files may appear while this command waits.
    #[arg(long = "approval", value_name = "FILE", conflicts_with = "direct")]
    pub approvals: Vec<PathBuf>,
    /// WITNESS_ID,BASE_URL,CREDENTIAL_FILE[,CA_CERTIFICATE]; repeat for each witness.
    /// Credential files are owner-only; HTTPS requires an explicit CA certificate.
    #[arg(long = "witness", value_name = "ENDPOINT", conflicts_with = "direct")]
    pub witnesses: Vec<String>,
    /// Permit literal-IP loopback HTTP for synthetic local testing.
    #[arg(long, conflicts_with = "direct")]
    pub allow_insecure_loopback: bool,
    /// Wait up to 0..=900 seconds for approval files; request expiry can end the wait sooner.
    #[arg(
        long,
        value_name = "SECONDS",
        default_value_t = 300,
        value_parser = clap::value_parser!(u64).range(0..=900),
        conflicts_with = "direct"
    )]
    pub wait_seconds: u64,
}

#[derive(Debug, Args)]
pub struct ExecArgs {
    /// Restricted dotenv file containing literal or `{{Item/Field}}` values.
    /// Legacy Item.Field shorthand is accepted only when neither name contains a dot.
    /// Other public labels use a JSON pair: `{{["item label","field label"]}}`.
    #[arg(long, value_name = "FILE")]
    pub env_file: Option<PathBuf>,
    /// Replace inherited stdin with `Item/Field` or `["item label","field label"]`.
    #[arg(long, value_name = "REFERENCE")]
    pub stdin: Option<String>,
    /// Expose one field through a sealed anonymous file named by an env var.
    /// Reference: Item/Field or a JSON pair of exact public labels.
    #[arg(long = "file", value_name = "VAR=REFERENCE")]
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
    /// Current owner-signed checkpoint JSON accepted by the selected witnesses; required unless --direct.
    #[arg(long, value_name = "CHECKPOINT", conflicts_with = "direct")]
    pub checkpoint: Option<PathBuf>,
    /// Required unless --direct: publish a fresh request here and keep this process running while another terminal approves it.
    #[arg(long, value_name = "FILE", conflicts_with = "direct")]
    pub request_out: Option<PathBuf>,
    /// Required unless --direct: create a public receipt at this absent path after successful witnessed access.
    #[arg(long, value_name = "FILE", conflicts_with = "direct")]
    pub receipt: Option<PathBuf>,
    /// Signed approval file; repeat for each approver. Files may appear while this command waits.
    #[arg(long = "approval", value_name = "FILE", conflicts_with = "direct")]
    pub approvals: Vec<PathBuf>,
    /// WITNESS_ID,BASE_URL,CREDENTIAL_FILE[,CA_CERTIFICATE]; repeat for each witness.
    /// Credential files are owner-only; HTTPS requires an explicit CA certificate.
    #[arg(long = "witness", value_name = "ENDPOINT", conflicts_with = "direct")]
    pub witnesses: Vec<String>,
    /// Permit literal-IP loopback HTTP for synthetic local testing.
    #[arg(long, conflicts_with = "direct")]
    pub allow_insecure_loopback: bool,
    /// Wait up to 0..=900 seconds for approval files; request expiry can end the wait sooner.
    #[arg(
        long,
        value_name = "SECONDS",
        default_value_t = 300,
        value_parser = clap::value_parser!(u64).range(0..=900),
        conflicts_with = "direct"
    )]
    pub wait_seconds: u64,
}

#[derive(Debug, Args)]
pub struct RunArgs {
    /// Inject one field as `VAR=Item/Field`; may be repeated.
    /// Legacy Item.Field shorthand is accepted only when neither name contains a dot.
    /// Other public labels use `VAR=["item label","field label"]`.
    #[arg(long = "env", value_name = "VAR=REFERENCE")]
    pub env: Vec<String>,
    /// Expose one field through a sealed anonymous file named by an env var.
    /// Reference: Item/Field or a JSON pair of exact public labels.
    #[arg(long = "file", value_name = "VAR=REFERENCE")]
    pub files: Vec<String>,
    /// Deliver `Item/Field` or `["item label","field label"]` on child stdin.
    #[arg(long, value_name = "REFERENCE")]
    pub stdin: Option<String>,
    /// Run from this existing directory; defaults to the current directory.
    #[arg(long, value_name = "DIRECTORY")]
    pub cwd: Option<PathBuf>,
    /// Terminate the complete process tree after 1..=86400 seconds. Defaults to 1800 seconds, reduced to the witnessed policy limit when smaller.
    #[arg(long, value_name = "SECONDS")]
    pub timeout: Option<u64>,
    /// Retain at most this many post-redaction bytes per output stream.
    #[arg(long, value_name = "BYTES", default_value_t = 1_048_576)]
    pub output_limit: usize,
    /// Exact command and non-secret arguments; `--` is required.
    #[arg(last = true, required = true, allow_hyphen_values = true)]
    pub command: Vec<OsString>,
    /// Use unilateral direct recipient slots instead of governed witnessed authority.
    #[arg(long)]
    pub direct: bool,
    /// Current owner-signed checkpoint JSON accepted by the selected witnesses; required unless --direct.
    #[arg(long, value_name = "CHECKPOINT", conflicts_with = "direct")]
    pub checkpoint: Option<PathBuf>,
    /// Required unless --direct: publish a fresh request here and keep this process running while another terminal approves it.
    #[arg(long, value_name = "FILE", conflicts_with = "direct")]
    pub request_out: Option<PathBuf>,
    /// Required unless --direct: create a public receipt at this absent path after successful witnessed access.
    #[arg(long, value_name = "FILE", conflicts_with = "direct")]
    pub receipt: Option<PathBuf>,
    /// Signed approval file; repeat for each approver. Files may appear while this command waits.
    #[arg(long = "approval", value_name = "FILE", conflicts_with = "direct")]
    pub approvals: Vec<PathBuf>,
    /// WITNESS_ID,BASE_URL,CREDENTIAL_FILE[,CA_CERTIFICATE]; repeat for each witness.
    /// Credential files are owner-only; HTTPS requires an explicit CA certificate.
    #[arg(long = "witness", value_name = "ENDPOINT", conflicts_with = "direct")]
    pub witnesses: Vec<String>,
    /// Permit literal-IP loopback HTTP for synthetic local testing.
    #[arg(long, conflicts_with = "direct")]
    pub allow_insecure_loopback: bool,
    /// Wait up to 0..=900 seconds for approval files; request expiry can end the wait sooner.
    #[arg(
        long,
        value_name = "SECONDS",
        default_value_t = 300,
        value_parser = clap::value_parser!(u64).range(0..=900),
        conflicts_with = "direct"
    )]
    pub wait_seconds: u64,
}
