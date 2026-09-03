use jury_core::{policy::PolicyState, witness_receipt::ReceiptPolicyMaterialV1};
use jury_protocol::witness_v1::PolicyMaterialBytes;
use serde::{Deserialize, Serialize};

use crate::{AdapterError, AdapterErrorKind};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct PublicPolicyMaterialV1(ReceiptPolicyMaterialV1);

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
        if serde_json::to_vec(&material).ok().as_deref() != Some(encoded.as_bytes()) {
            return Err(AdapterError::new(AdapterErrorKind::InvalidPolicyMaterial));
        }
        material.replay()?;
        Ok(material)
    }

    pub fn replay(&self) -> Result<PolicyState, AdapterError> {
        self.0
            .replay()
            .map_err(|_| AdapterError::new(AdapterErrorKind::InvalidPolicyMaterial))
    }
}
