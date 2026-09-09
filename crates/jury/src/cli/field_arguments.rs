use super::*;

#[derive(Debug, Subcommand)]
pub enum FieldCommand {
    /// List fields from directly accessible items; witnessed-only items are not disclosed.
    List(FieldListArgs),
    /// Create or replace one field using protected standard input.
    Set(FieldSetArgs),
    /// Remove one field from an accessible item.
    Remove(FieldRemoveArgs),
}

#[derive(Debug, Args)]
pub struct FieldListArgs {
    /// Optional item name; omission lists all directly accessible fields.
    #[arg(value_name = "ITEM")]
    pub item: Option<String>,
}

#[derive(Debug, Args)]
pub struct FieldSetArgs {
    /// Resolved item whose field is created or replaced.
    #[arg(value_name = "ITEM")]
    pub item: String,
    /// Exact field name to create or replace.
    #[arg(value_name = "FIELD")]
    pub field: String,
    /// Conceal this field in child output (default for new fields; updates preserve the kind).
    /// Concealed values require at least four bytes.
    #[arg(long, conflicts_with = "unconcealed")]
    pub concealed: bool,
    /// Allow this field's bytes in child output; the stored field remains encrypted.
    #[arg(long)]
    pub unconcealed: bool,
    /// Read the field value from standard input; required for non-terminal use.
    /// Terminal entry is hidden, with or without this flag. Ctrl-D finishes immediately;
    /// Enter adds a newline to the value. Ctrl-C cancels without saving.
    #[arg(long)]
    pub value_stdin: bool,
    /// Prepare and authenticate the exact mutation without writing it.
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Debug, Args)]
pub struct FieldRemoveArgs {
    /// Resolved item whose field is removed.
    #[arg(value_name = "ITEM")]
    pub item: String,
    /// Exact field name to remove.
    #[arg(value_name = "FIELD")]
    pub field: String,
    /// Prepare and authenticate the exact mutation without writing it.
    #[arg(long)]
    pub dry_run: bool,
}
