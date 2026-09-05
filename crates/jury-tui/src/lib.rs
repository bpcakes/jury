//! Keyboard-first terminal interface boundary for Jury.

#![forbid(unsafe_code)]

use jury_protected::ProtectionStatus;

/// Renders the protection fact without converting emergency mode into a
/// transient notification that callers can miss.
#[must_use]
pub fn protection_status_line(status: &ProtectionStatus) -> String {
    protection_message(status.is_degraded()).to_owned()
}

fn protection_message(degraded: bool) -> &'static str {
    if degraded {
        "PROTECTION DEGRADED — emergency override is active"
    } else {
        "Protection controls established"
    }
}

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
    use super::{protection_message, unavailable_message};

    #[test]
    fn warning_names_the_product_and_maturity() {
        let message = unavailable_message();

        assert!(message.contains("Jury"));
        assert!(message.contains("pre-alpha"));
    }

    #[test]
    fn degraded_protection_remains_prominent() {
        // Test presentation only; jury-protected tests establish which native
        // control outcomes produce the degradation fact supplied here.
        let rendered = protection_message(true);
        assert!(rendered.contains("PROTECTION DEGRADED"));
        assert!(rendered.contains("emergency override"));
    }

    #[test]
    fn established_protection_is_not_rendered_as_emergency() {
        assert_eq!(protection_message(false), "Protection controls established");
    }
}
