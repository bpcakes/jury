
#[derive(Debug, Subcommand)]
pub enum PolicyCommand {
    /// Require witnessed authority for an item and its declared operations.
    Require {
        #[command(subcommand)]
        command: PolicyRequireCommand,
    },
    /// Allow explicit direct authority for an item.
    Allow {
        #[command(subcommand)]
        command: PolicyAllowCommand,
    },
    /// Show the configured authority policy for one resolved item.
    Status(PolicyItemArgs),
    /// Explain the configured authority policy for one resolved item.
    Explain(PolicyItemArgs),
}

#[derive(Debug, Subcommand)]
pub enum PolicyRequireCommand {
    /// Require named approvers and witnesses before declared operations can proceed.
    Witnessed(PolicyRequireWitnessedArgs),
}

#[derive(Debug, Subcommand)]
pub enum PolicyAllowCommand {
    /// Allow listed principals to use direct access to an item.
    Direct(PolicyAllowDirectArgs),
}

#[derive(Debug, Args)]
pub struct PolicyItemArgs {
    /// Resolved item name whose authority policy to show or explain.
    #[arg(long, value_name = "ITEM")]
    pub item: String,
}

#[derive(Debug, Args)]
pub struct PolicyRequireWitnessedArgs {
    /// Resolved item name that will require witnessed authority.
    #[arg(long, value_name = "ITEM")]
    pub item: String,
    /// Active approver ID whose descriptor permits every declared operation; may be repeated.
    #[arg(long = "approver", value_name = "PRINCIPAL")]
    pub approvers: Vec<String>,
    /// Active witness principal ID; provide at least two unique values.
    #[arg(long = "witness", value_name = "PRINCIPAL", required = true)]
    pub witnesses: Vec<String>,
    /// Required approver signatures: 1..=approver count and --review-label, or 0 only for automatic read-stdout with --automatic-read and no approvers or review labels.
    #[arg(long, value_name = "COUNT")]
    pub approvals: u16,
    /// Required witness acknowledgements: 2..=the number of --witness values.
    #[arg(long, value_name = "COUNT")]
    pub witness_quorum: u16,
    /// Governed operation: read-stdout, write-private-file, template-injection, child-environment, child-stdin, item-mutation, backup, recovery, or administrative-rekey; may be repeated.
    #[arg(long = "operation", value_name = "OPERATION", required = true)]
    pub operations: Vec<String>,
    /// Non-secret item label required when --approvals is at least 1.
    #[arg(long, value_name = "PUBLIC_LABEL")]
    pub review_label: Option<String>,
    /// Non-secret FIELD=PUBLIC_LABEL mapping required for governed field-touching operations.
    #[arg(long = "field-review-label", value_name = "FIELD=PUBLIC_LABEL")]
    pub field_review_labels: Vec<String>,
    /// Permit automatic read-stdout only for this exact private field; may be repeated.
    #[arg(long = "automatic-read", value_name = "FIELD")]
    pub automatic_read_fields: Vec<String>,
    /// Request lifetime in seconds (1..=900); each operation timeout is limited to this lifetime and never exceeds 30 seconds.
    #[arg(long, value_name = "SECONDS")]
    pub request_lifetime: u64,
    /// Validate the exact witnessed policy without committing it.
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Debug, Args)]
pub struct PolicyAllowDirectArgs {
    /// Resolved item name that will allow direct access.
    #[arg(long, value_name = "ITEM")]
    pub item: String,
    /// Active human or machine principal that already has read access to ITEM; may be repeated.
    #[arg(long = "principal", value_name = "PRINCIPAL", required = true)]
    pub principals: Vec<String>,
    /// Authenticated acknowledgement that direct access is unilateral.
    #[arg(long)]
    pub acknowledge_direct_access: bool,
    /// Validate the direct-access policy without committing it.
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
