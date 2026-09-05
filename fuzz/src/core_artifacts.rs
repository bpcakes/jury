use jury_core::{
    registration::{RegistrationChallengeV1, RegistrationProofV1},
    transfer::{TransferPublicCatalogV1, ValidatedTransfer},
    witness_receipt::ReceiptPolicyMaterialV1,
};
use jury_protocol::witness_v1::PolicyMaterialBytes;
use jury_witness::policy_material::PublicPolicyMaterialV1;

use crate::{identical, require};

#[cfg(test)]
pub(crate) const ALL_ACCEPTED_PATHS: u8 = 0b11_1111;

pub fn exercise(data: &[u8]) -> usize {
    coverage(data).count_ones() as usize
}

pub(crate) fn coverage(data: &[u8]) -> u8 {
    let mut accepted = 0;
    macro_rules! round_trip {
        ($type:ty, $bit:expr) => {
            if let Ok(value) = <$type>::parse(data) {
                let encoded = require(value.to_json_bytes());
                let again = require(<$type>::parse(&encoded));
                identical(&encoded, &require(again.to_json_bytes()));
                accepted |= $bit;
            }
        };
    }
    round_trip!(RegistrationChallengeV1, 1 << 0);
    round_trip!(RegistrationProofV1, 1 << 1);
    round_trip!(TransferPublicCatalogV1, 1 << 2);
    if let Ok(transfer) = ValidatedTransfer::parse(data) {
        require(ValidatedTransfer::parse(&require(
            transfer.envelope().to_json_bytes(),
        )));
        accepted |= 1 << 3;
    }
    if data.len() <= 16 * 1024 * 1024 {
        if let Ok(encoded) = PolicyMaterialBytes::new(data.to_vec()) {
            if let Ok(material) = ReceiptPolicyMaterialV1::decode(&encoded) {
                identical(data, require(material.encode()).as_bytes());
                accepted |= 1 << 4;
            }
            if let Ok(material) = PublicPolicyMaterialV1::decode(&encoded) {
                identical(data, require(material.encode()).as_bytes());
                accepted |= 1 << 5;
            }
        }
    }
    accepted
}
