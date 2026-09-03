use jury_core::{policy::PolicyState, witness_receipt::ReceiptPolicyMaterialV1};
use jury_protocol::witness_v1::PolicyMaterialBytes;
use serde::{Deserialize, Serialize};

use crate::{AdapterError, AdapterErrorKind};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct PublicPolicyMaterialV1(ReceiptPolicyMaterialV1);

impl PublicPolicyMaterialV1 {
    pub fn encode(&self) -> Result<PolicyMaterialBytes, AdapterError> {
        self.0.encode().map_err(|error| {
            AdapterError::new(match error.kind() {
                jury_core::witness_receipt::ReceiptVerificationErrorKind::CapacityExhausted => {
                    AdapterErrorKind::CapacityExhausted
                }
                _ => AdapterErrorKind::InvalidPolicyMaterial,
            })
        })
    }

    pub fn decode(encoded: &PolicyMaterialBytes) -> Result<Self, AdapterError> {
        ReceiptPolicyMaterialV1::decode(encoded)
            .map(Self)
            .map_err(|_| AdapterError::new(AdapterErrorKind::InvalidPolicyMaterial))
    }

    pub fn replay(&self) -> Result<PolicyState, AdapterError> {
        self.0
            .replay()
            .map_err(|_| AdapterError::new(AdapterErrorKind::InvalidPolicyMaterial))
    }
}
