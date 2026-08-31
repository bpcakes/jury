//! Shared presentation for the initial `jury` command.

#![forbid(unsafe_code)]

pub mod cli;
pub mod home;
pub mod mutation_commit;
mod secret_input;

/// Render command help without implying that security features are available.
#[must_use]
pub fn help_text(version: &str) -> String {
    format!(
        "{name} {version}\n{tagline}\n\n\
         WARNING: {maturity}.\n\n\
         Native Linux CLI. Run `jury --help` for commands.\n",
        name = jury_core::PRODUCT_NAME,
        tagline = jury_core::PRODUCT_TAGLINE,
        maturity = jury_core::MATURITY,
    )
}

#[cfg(test)]
mod tests {
    use super::help_text;

    #[test]
    fn help_is_explicitly_non_production() {
        let help = help_text("0.1.0");

        assert!(help.contains("Jury 0.1.0"));
        assert!(help.contains("do not use with real secrets"));
        assert!(help.contains("Native Linux CLI"));
    }
}
