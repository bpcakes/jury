use jury_core::policy::{PolicyState, WitnessPolicy, replay_policy_with_witness_policies};
use jury_protocol::{vault_v1::PolicyJournalV1, witness_v1::PolicyMaterialBytes};
use serde::{Deserialize, Serialize};

use crate::{AdapterError, AdapterErrorKind};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PublicPolicyMaterialV1 {
    pub schema: u16,
    pub journal: PolicyJournalV1,
    pub witness_policies: Vec<WitnessPolicy>,
}

impl PublicPolicyMaterialV1 {
    pub fn encode(&self) -> Result<PolicyMaterialBytes, AdapterError> {
        self.replay()?;
        let encoded = serde_json::to_vec(self)
            .map_err(|_| AdapterError::new(AdapterErrorKind::InvalidPolicyMaterial))?;
        PolicyMaterialBytes::new(encoded)
            .map_err(|_| AdapterError::new(AdapterErrorKind::CapacityExhausted))
    }

    pub fn decode(encoded: &PolicyMaterialBytes) -> Result<Self, AdapterError> {
        let material: Self = serde_json::from_slice(encoded.as_bytes())
            .map_err(|_| AdapterError::new(AdapterErrorKind::InvalidPolicyMaterial))?;
        if material.schema != 1
            || serde_json::to_vec(&material).ok().as_deref() != Some(encoded.as_bytes())
        {
            return Err(AdapterError::new(AdapterErrorKind::InvalidPolicyMaterial));
        }
        material.replay()?;
        Ok(material)
    }

    pub fn replay(&self) -> Result<PolicyState, AdapterError> {
        if self.schema != 1 {
            return Err(AdapterError::new(AdapterErrorKind::InvalidPolicyMaterial));
        }
        replay_policy_with_witness_policies(&self.journal, &self.witness_policies)
            .map_err(|_| AdapterError::new(AdapterErrorKind::InvalidPolicyMaterial))
    }
}
