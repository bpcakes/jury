//! Keyboard-first terminal interface boundary for Jury.

#![forbid(unsafe_code)]

use jury_protected::{ProtectionPolicy, ProtectionStatus};

/// Renders the protection fact without converting emergency mode into a
/// transient notification that callers can miss.
#[must_use]
pub fn protection_status_line(status: &ProtectionStatus) -> String {
    protection_message(status.policy(), status.is_degraded()).to_owned()
}

fn protection_message(policy: ProtectionPolicy, degraded: bool) -> &'static str {
    match (policy, degraded) {
        (ProtectionPolicy::Strict, false) => "Protection controls established",
        (ProtectionPolicy::Strict, true) => "PROTECTION DEGRADED — protection checks did not pass",
        (ProtectionPolicy::EmergencyAllowDegraded, false) => {
            "Protection controls established — emergency override is enabled"
        }
        (ProtectionPolicy::EmergencyAllowDegraded, true) => {
            "PROTECTION DEGRADED — emergency override is enabled"
        }
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
    use jury_protected::ProtectionPolicy;

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
        let rendered = protection_message(ProtectionPolicy::EmergencyAllowDegraded, true);
        assert!(rendered.contains("PROTECTION DEGRADED"));
        assert!(rendered.contains("emergency override"));
    }

    #[test]
    fn established_protection_is_not_rendered_as_emergency() {
        assert_eq!(
            protection_message(ProtectionPolicy::Strict, false),
            "Protection controls established"
        );
    }

    #[test]
    fn strict_degradation_does_not_claim_an_emergency_override() {
        let rendered = protection_message(ProtectionPolicy::Strict, true);
        assert!(rendered.contains("PROTECTION DEGRADED"));
        assert!(!rendered.contains("emergency override"));
    }

    #[test]
    fn established_controls_do_not_hide_the_emergency_policy() {
        let rendered = protection_message(ProtectionPolicy::EmergencyAllowDegraded, false);
        assert!(rendered.contains("Protection controls established"));
        assert!(rendered.contains("emergency override"));
        assert!(!rendered.contains("PROTECTION DEGRADED"));
    }
}
