//! Shared presentation for the initial `jury` command.

#![forbid(unsafe_code)]

pub mod cli;
pub mod home;
pub mod mutation_commit;
mod secret_input;

/// Render the short command introduction.
#[must_use]
pub fn help_text(version: &str) -> String {
    format!(
        "{name} {version}\n{tagline}\n\n\
         Native Linux CLI. Run `jury --help` for commands.\n",
        name = jury_core::PRODUCT_NAME,
        tagline = jury_core::PRODUCT_TAGLINE,
    )
}

#[cfg(test)]
mod tests {
    use super::help_text;

    #[test]
    fn help_names_the_product_and_platform() {
        let help = help_text("0.1.0");

        assert!(help.contains("Jury 0.1.0"));
        assert!(help.contains("Native Linux CLI"));
    }
}
