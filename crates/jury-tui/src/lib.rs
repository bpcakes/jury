//! Keyboard-first terminal interface boundary for Jury.

#![forbid(unsafe_code)]

use jury_protected::ProtectionStatus;

/// Renders the protection fact without converting emergency mode into a
/// transient notification that callers can miss.
#[must_use]
pub fn protection_status_line(status: &ProtectionStatus) -> String {
    if status.is_degraded() {
        "PROTECTION DEGRADED — emergency override is active".to_owned()
    } else {
        "Protection controls established".to_owned()
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
    use jury_protected::{ProtectedMemory, ProtectionPolicy};

    use super::{protection_status_line, unavailable_message};

    #[test]
    fn warning_names_the_product_and_maturity() {
        let message = unavailable_message();

        assert!(message.contains("Jury"));
        assert!(message.contains("pre-alpha"));
    }

    #[test]
    fn degraded_protection_remains_prominent() -> Result<(), Box<dyn std::error::Error>> {
        // Exercise a real unavailable control. Emergency policy can be fully
        // established when the host already suppresses cores; it is not itself
        // evidence of degradation. Only this test in this binary allocates.
        #[cfg(unix)]
        let previous = rlimit::getrlimit(rlimit::Resource::MEMLOCK)?;
        #[cfg(unix)]
        rlimit::setrlimit(rlimit::Resource::MEMLOCK, 0, previous.1)?;
        let memory = ProtectedMemory::initialize(
            16,
            ProtectionPolicy::EmergencyAllowDegraded,
            |destination| {
                destination.fill(0xa5);
                Ok::<usize, ()>(destination.len())
            },
        );
        #[cfg(unix)]
        rlimit::setrlimit(rlimit::Resource::MEMLOCK, previous.0, previous.1)?;
        let memory = memory?;
        #[cfg(unix)]
        assert_eq!(
            memory.status().memory_lock(),
            jury_protected::RuntimeControlStatus::Failed
        );
        assert!(memory.status().is_degraded());
        let rendered = protection_status_line(memory.status());
        assert!(rendered.contains("PROTECTION DEGRADED"));
        assert!(rendered.contains("emergency override"));
        Ok(())
    }
}
