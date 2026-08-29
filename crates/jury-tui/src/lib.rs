//! Keyboard-first terminal interface boundary for Jury.

#![forbid(unsafe_code)]

/// Message returned until an interactive interface exists.
#[must_use]
pub fn unavailable_message() -> String {
    format!(
        "{} TUI is not implemented ({})",
        jury_core::PRODUCT_NAME,
        jury_core::MATURITY
    )
}

#[cfg(test)]
mod tests {
    use super::unavailable_message;

    #[test]
    fn warning_names_the_product_and_maturity() {
        let message = unavailable_message();

        assert!(message.contains("Jury"));
        assert!(message.contains("pre-alpha"));
    }
}
