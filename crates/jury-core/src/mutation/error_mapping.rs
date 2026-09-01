use super::*;

pub(super) fn map_current_format_error(error: FormatError) -> MutationError {
    MutationError::new(if is_capacity(error) {
        MutationErrorKind::CapacityExhausted
    } else {
        MutationErrorKind::InvalidCurrentState
    })
}

pub(super) fn map_target_format_error(error: FormatError) -> MutationError {
    MutationError::new(if is_capacity(error) {
        MutationErrorKind::CapacityExhausted
    } else {
        MutationErrorKind::InvalidPlan
    })
}

const fn is_capacity(error: FormatError) -> bool {
    matches!(
        error,
        FormatError::ArtifactTooLarge | FormatError::CapacityExhausted(_)
    )
}

pub(super) fn map_replay_error(kind: PolicyErrorKind, current: bool) -> MutationError {
    MutationError::new(match kind {
        PolicyErrorKind::CapacityExhausted => MutationErrorKind::CapacityExhausted,
        PolicyErrorKind::Unauthorized | PolicyErrorKind::InvalidRole if !current => {
            MutationErrorKind::Unauthorized
        }
        _ if current => MutationErrorKind::InvalidCurrentState,
        _ => MutationErrorKind::InvalidPlan,
    })
}

pub(super) fn map_policy_error(error: crate::policy::PolicyError) -> MutationError {
    MutationError::new(match error.kind() {
        PolicyErrorKind::CapacityExhausted => MutationErrorKind::CapacityExhausted,
        PolicyErrorKind::Unauthorized | PolicyErrorKind::InvalidRole => {
            MutationErrorKind::Unauthorized
        }
        _ => MutationErrorKind::InvalidPlan,
    })
}
