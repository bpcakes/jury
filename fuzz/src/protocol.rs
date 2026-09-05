use jury_protocol::{
    backup_v1::{BackupEnvelopeV1, BackupHeaderV1},
    identity_v1::IdentityFileV1,
    transfer_v1::{ParsedTransferEnvelopeV1, TransferEnvelopeV1},
    vault_v1::{ItemDescriptorV1, ItemStateV1, VaultFileV1},
};

use crate::{identical, require};

#[cfg(test)]
pub(crate) const ALL_ACCEPTED_PATHS: u16 = (1 << 9) - 1;

/// Returns the number of accepted parser paths, allowing seed tests to reject
/// a corpus that exercises rejection only. No cryptographic unlock occurs here.
pub fn exercise(data: &[u8]) -> usize {
    coverage(data).count_ones() as usize
}

pub(crate) fn coverage(data: &[u8]) -> u16 {
    let mut accepted = 0;
    macro_rules! json_round_trip {
        ($type:ty, $bit:expr) => {
            if let Ok(value) = <$type>::parse(data) {
                let encoded = require(value.to_json_bytes());
                let again = require(<$type>::parse(&encoded));
                identical(&encoded, &require(again.to_json_bytes()));
                accepted |= $bit;
            }
        };
    }
    json_round_trip!(VaultFileV1, 1 << 0);
    json_round_trip!(IdentityFileV1, 1 << 1);
    json_round_trip!(TransferEnvelopeV1, 1 << 2);
    if let Ok(value) = ParsedTransferEnvelopeV1::parse(data) {
        let (envelope, vault) = value.into_parts();
        require(vault.validate());
        require(ParsedTransferEnvelopeV1::parse(&require(
            envelope.to_json_bytes(),
        )));
        accepted |= 1 << 3;
    }
    if let Ok(header) = BackupHeaderV1::parse(data) {
        identical(data, &require(header.canonical_bytes()));
        accepted |= 1 << 4;
    }
    if let Ok(envelope) = BackupEnvelopeV1::parse(data) {
        identical(data, &require(envelope.to_bytes()));
        accepted |= 1 << 5;
    }
    if let Ok(mut descriptor) = ItemDescriptorV1::decode(data) {
        identical(data, &descriptor.encode());
        descriptor.clear_sensitive();
        accepted |= 1 << 6;
    }
    if let Ok(mut body) = ItemStateV1::parse_canonical(data) {
        identical(data, &require(body.to_canonical_bytes()));
        body.clear_sensitive();
        accepted |= 1 << 7;
    }
    // Exercise each frozen bucket, including invalid IDs, without constructing
    // a padded allocation for rejected lengths.
    for bucket in 0..=13 {
        if let Ok(mut body) = ItemStateV1::parse_framed(bucket, data) {
            identical(data, &require(body.frame(bucket)));
            body.clear_sensitive();
            accepted |= 1 << 8;
        }
    }
    accepted
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_seeds_reach_vault_descriptor_and_body_oracles() {
        let vault = include_bytes!("../../conformance/vault-v1/example-vault.json");
        assert!(exercise(vault) >= 1);
        let descriptor = require(ItemDescriptorV1::new("ExampleSecret".to_owned()));
        assert_eq!(exercise(&descriptor.encode()), 1);
        let body = ItemStateV1 {
            plaintext_schema: 1,
            fields: Vec::new(),
        };
        assert_eq!(exercise(&require(body.to_canonical_bytes())), 1);
        assert_eq!(exercise(&require(body.frame(1))), 1);
    }

    #[test]
    fn malformed_corpus_and_seed_mutations_do_not_panic() {
        for bytes in [
            b"".as_slice(),
            b"{",
            b"[]",
            b"<<<<<<< ExampleVault\n",
            &[0xff; 282],
        ] {
            assert_eq!(exercise(bytes), 0);
        }
        let descriptor = require(ItemDescriptorV1::new("ExampleSecret".to_owned())).encode();
        for offset in 0..descriptor.len() {
            let mut bytes = descriptor;
            bytes[offset] ^= 0x80;
            exercise(&bytes);
        }
    }
}
