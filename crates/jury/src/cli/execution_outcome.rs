use jury_core::local_state::{AuditFailureStage, AuditOutcome};
use jury_process::OwnedProcessTreeError;

use super::{CliError, CliErrorKind};

pub(super) fn process_audit_outcome<T>(result: &Result<T, OwnedProcessTreeError>) -> AuditOutcome {
    match result {
        Ok(_) => AuditOutcome::Success,
        Err(error) if error.is_cancellation() => AuditOutcome::Cancelled,
        Err(_) => AuditOutcome::Failed(AuditFailureStage::Execution),
    }
}

pub(super) fn map_process_error(error: OwnedProcessTreeError) -> CliError {
    match error {
        OwnedProcessTreeError::Output => CliError::new(
            CliErrorKind::Process,
            "process-output-failed",
            "child output could not be delivered safely",
        ),
        OwnedProcessTreeError::TimedOut => CliError::new(
            CliErrorKind::Process,
            "process-timeout",
            "the brokered process tree timed out and was terminated",
        ),
        OwnedProcessTreeError::Stdin => CliError::new(
            CliErrorKind::Process,
            "process-stdin-failed",
            "the selected stdin value could not be delivered completely",
        ),
        OwnedProcessTreeError::Cancelled | OwnedProcessTreeError::CancelledBeforeStart => {
            CliError::new(
                CliErrorKind::Process,
                "process-cancelled",
                "the process tree was cancelled and terminated",
            )
        }
        _ => CliError::new(
            CliErrorKind::Process,
            "process-failed",
            "the process tree failed or could not be cleaned up safely",
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compound_failures_never_claim_successful_termination_or_a_cancelled_audit()
    -> Result<(), Box<dyn std::error::Error>> {
        for primary in [
            OwnedProcessTreeError::TimedOut,
            OwnedProcessTreeError::Cancelled,
            OwnedProcessTreeError::Stdin,
            OwnedProcessTreeError::Output,
        ] {
            let result: Result<(), _> = Err(OwnedProcessTreeError::CleanupAfterFailure(Box::new(
                primary,
            )));
            assert_eq!(
                process_audit_outcome(&result),
                AuditOutcome::Failed(AuditFailureStage::Execution)
            );
            let error = map_process_error(result.err().ok_or("fixture must be an error")?);
            assert_eq!(error.code(), "process-failed");
            assert_eq!(error.kind(), CliErrorKind::Process);
            assert_eq!(error.exit_code(), 1);
            assert_eq!(
                error.to_string(),
                "the process tree failed or could not be cleaned up safely"
            );
        }
        Ok(())
    }

    #[test]
    fn ordinary_cancellation_timeout_and_success_keep_their_distinct_outcomes()
    -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(
            process_audit_outcome(&Ok::<(), OwnedProcessTreeError>(())),
            AuditOutcome::Success
        );
        for (error, code, outcome) in [
            (
                OwnedProcessTreeError::Cancelled,
                "process-cancelled",
                AuditOutcome::Cancelled,
            ),
            (
                OwnedProcessTreeError::CancelledBeforeStart,
                "process-cancelled",
                AuditOutcome::Cancelled,
            ),
            (
                OwnedProcessTreeError::TimedOut,
                "process-timeout",
                AuditOutcome::Failed(AuditFailureStage::Execution),
            ),
        ] {
            let result: Result<(), _> = Err(error);
            assert_eq!(process_audit_outcome(&result), outcome);
            assert_eq!(
                map_process_error(result.err().ok_or("fixture must be an error")?).code(),
                code
            );
        }
        Ok(())
    }
}
