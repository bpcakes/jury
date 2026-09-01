//! Owner-signed policy creation, replay, and access evaluation.
//!
//! Policy replay consumes only public authenticated state. Item and field names
//! never enter this module.

mod replay;
mod state;
mod witness;
mod witness_v1_bridge;

#[cfg(test)]
mod model_tests;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod vector_tests;
#[cfg(test)]
pub(crate) mod witness_tests;

pub use replay::{CreatedPolicy, PolicyCreator, PreparedPolicyRevision, replay_policy};
pub use state::{
    AccessExplanation, AccessPath, AccessReason, ItemPolicyState, PolicyError, PolicyErrorKind,
    PolicyState, PrincipalPolicyState, TombstoneState, WitnessAuthority,
};
pub(crate) use witness::signing_key_fingerprint;
pub use witness::{
    ApprovalMode, ApproverPolicyDescriptor, AutomaticReadTarget, DescriptorStatus, OperationRule,
    PlatformAssurance, WitnessAccessRule, WitnessOperation, WitnessPolicy, WitnessPolicyDescriptor,
    replay_policy_with_witness_policies,
};
pub(crate) use witness_v1_bridge::{
    approval_mode_tag, core_operation, operation_tag, platform_assurance_tag,
    protocol_approval_mode,
};
