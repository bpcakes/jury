
#[derive(Debug, Subcommand)]
pub enum PolicyCommand {
    Require {
        #[command(subcommand)]
        command: PolicyRequireCommand,
    },
    Allow {
        #[command(subcommand)]
        command: PolicyAllowCommand,
    },
    Status(PolicyItemArgs),
    Explain(PolicyItemArgs),
}

#[derive(Debug, Subcommand)]
pub enum PolicyRequireCommand {
    Witnessed(PolicyRequireWitnessedArgs),
}

#[derive(Debug, Subcommand)]
pub enum PolicyAllowCommand {
    Direct(PolicyAllowDirectArgs),
}

#[derive(Debug, Args)]
pub struct PolicyItemArgs {
    #[arg(long, value_name = "ITEM")]
    pub item: String,
}

#[derive(Debug, Args)]
pub struct PolicyRequireWitnessedArgs {
    #[arg(long, value_name = "ITEM")]
    pub item: String,
    #[arg(long = "approver", value_name = "PRINCIPAL")]
    pub approvers: Vec<String>,
    #[arg(long = "witness", value_name = "PRINCIPAL", required = true)]
    pub witnesses: Vec<String>,
    #[arg(long, value_name = "COUNT")]
    pub approvals: u16,
    #[arg(long, value_name = "COUNT")]
    pub witness_quorum: u16,
    #[arg(long = "operation", value_name = "OPERATION", required = true)]
    pub operations: Vec<String>,
    /// Deliberately publish this non-secret item label for human approval.
    #[arg(long, value_name = "PUBLIC_LABEL")]
    pub review_label: Option<String>,
    /// Publish FIELD=PUBLIC_LABEL for a field that humans may approve.
    #[arg(long = "field-review-label", value_name = "FIELD=PUBLIC_LABEL")]
    pub field_review_labels: Vec<String>,
    /// Permit automatic read-stdout only for this exact private field; may be repeated.
    #[arg(long = "automatic-read", value_name = "FIELD")]
    pub automatic_read_fields: Vec<String>,
    #[arg(long, value_name = "SECONDS")]
    pub request_lifetime: u64,
    #[arg(long, value_name = "DIGEST")]
    pub workload: Option<String>,
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Debug, Args)]
pub struct PolicyAllowDirectArgs {
    #[arg(long, value_name = "ITEM")]
    pub item: String,
    #[arg(long = "principal", value_name = "PRINCIPAL", required = true)]
    pub principals: Vec<String>,
    /// Authenticated acknowledgement that direct access is unilateral.
    #[arg(long)]
    pub acknowledge_direct_access: bool,
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Debug, Subcommand)]
pub enum PrivacyCommand {
    Cover(PrivacyCoverArgs),
}

#[derive(Debug, Args)]
pub struct PrivacyCoverArgs {
    #[arg(long, value_name = "ITEM")]
    pub item: String,
    #[arg(long)]
    pub dry_run: bool,
}
