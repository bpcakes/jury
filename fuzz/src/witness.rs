use jury_protocol::{vault_v1::Signature64, witness_v1::*};

use crate::{identical, require};

#[cfg(test)]
pub(crate) const ALL_ACCEPTED_PATHS: u32 = (1 << 17) - 1;

pub fn exercise(data: &[u8]) -> usize {
    coverage(data).count_ones() as usize
}

pub(crate) fn coverage(data: &[u8]) -> u32 {
    let mut accepted = 0;
    macro_rules! canonical_round_trip {
        ($type:ty, $method:ident, $bit:expr) => {
            if let Ok(value) = serde_json::from_slice::<$type>(data) {
                if let Ok(canonical) = value.$method() {
                    let json = require(serde_json::to_vec(&value));
                    let again: $type = require(serde_json::from_slice(&json));
                    identical(&canonical, &require(again.$method()));
                    accepted |= $bit;
                }
            }
        };
    }
    canonical_round_trip!(ActionManifestV1, canonical_body, 1 << 0);
    canonical_round_trip!(WitnessRequestV1, canonical_bytes, 1 << 1);
    canonical_round_trip!(ApprovalDecisionV1, canonical_bytes, 1 << 2);
    canonical_round_trip!(RequestCancellationV1, canonical_bytes, 1 << 3);
    canonical_round_trip!(VaultPolicyCheckpointV1, canonical_bytes, 1 << 4);
    canonical_round_trip!(WitnessDecisionV1, canonical_bytes, 1 << 5);
    canonical_round_trip!(WitnessResponseV1, canonical_bytes, 1 << 6);
    canonical_round_trip!(WitnessStateAnchorV1, canonical_bytes, 1 << 7);
    canonical_round_trip!(WitnessDatabaseStateV1, canonical_body, 1 << 8);
    canonical_round_trip!(WitnessPolicyRotationV1, canonical_bytes, 1 << 9);
    canonical_round_trip!(WitnessRecoveryV1, canonical_bytes, 1 << 10);
    canonical_round_trip!(OwnerReviewLabelV1, canonical_bytes, 1 << 11);
    canonical_round_trip!(ReceiptAcknowledgementV1, canonical_bytes, 1 << 12);
    canonical_round_trip!(ReceiptCompletionV1, canonical_bytes, 1 << 13);
    canonical_round_trip!(WitnessReceiptMaterialV1, canonical_bytes, 1 << 14);
    if let Ok(receipt) = WitnessReceiptV1::parse_json(data) {
        let bytes = require(receipt.to_json_bytes());
        let again = require(WitnessReceiptV1::parse_json(&bytes));
        identical(&bytes, &require(again.to_json_bytes()));
        accepted |= 1 << 15;
    }
    if let Ok(request) = WitnessRequestV1::from_signature_preimage(data, Signature64::new([0; 64]))
    {
        identical(data, &require(request.signature_preimage()));
        accepted |= 1 << 16;
    }
    accepted
}
