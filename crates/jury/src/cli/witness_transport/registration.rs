use super::*;
use jury_protocol::witness_v1::{RegistrationBytes, WitnessCheckpointAcknowledgementV1};

#[derive(Serialize)]
struct RegistrationPayload<'a> {
    policy_material: &'a ReceiptPolicyMaterialV1,
    accepted_registration: &'a RegistrationBytes,
    checkpoint: &'a VaultPolicyCheckpointV1,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RegistrationResponse {
    status: String,
    durability: String,
    global_freshness_claimed: bool,
    acknowledgement: WitnessCheckpointAcknowledgementV1,
}

impl WitnessEndpointClient {
    /// The configured credential must be the witness operator credential.
    /// Returns one authenticated exact-checkpoint acknowledgement; all required
    /// endpoints must still be checked together before declaring readiness.
    pub(in crate::cli) fn register_vault(
        &self,
        material: &ReceiptPolicyMaterialV1,
        registration: &RegistrationBytes,
        checkpoint: &VaultPolicyCheckpointV1,
    ) -> Result<WitnessCheckpointAcknowledgementV1, WitnessTransportError> {
        let invalid = || WitnessTransportError::new(WitnessTransportErrorKind::InvalidResponse);
        let policy = material.replay().map_err(|_| invalid())?;
        jury_core::witness_operations::verify_checkpoint_propagation(&policy, checkpoint, &[])
            .map_err(|_| invalid())?;
        let response = self.post_response(
            self.register_url.clone(),
            &RegistrationPayload {
                policy_material: material,
                accepted_registration: registration,
                checkpoint,
            },
        )?;
        let response: RegistrationResponse = bounded_json(response)?;
        if response.status != "accepted"
            || response.durability != "witness-database-and-external-anchor-readback"
            || response.global_freshness_claimed
            || response.acknowledgement.witness_id != self.witness_id
        {
            return Err(invalid());
        }
        jury_core::witness_operations::verify_checkpoint_propagation(
            &policy,
            checkpoint,
            std::slice::from_ref(&response.acknowledgement),
        )
        .map_err(|_| invalid())?;
        Ok(response.acknowledgement)
    }
}
