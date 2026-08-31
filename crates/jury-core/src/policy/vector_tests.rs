use std::collections::{BTreeMap, BTreeSet};
use std::io;

use jury_protocol::vault_v1::{
    AccessRole, ContentRole, DescriptorMetadataV1, Digest32, DirectSlotV1, FixedBytes,
    ItemAccessMode, ItemId, ItemKind, Nonce12, PrincipalDescriptorV1, PrincipalId, PrincipalKind,
    RecipientPublicKey1216, RevisionSealId, Signature64, VaultId, VerificationPublicKey32,
};
use serde_json::Value;

use super::state::{ItemPolicyState, PolicyState, PrincipalPolicyState, TombstoneState};

type AnyResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn failure(message: &'static str) -> io::Error {
    io::Error::other(message)
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take<const N: usize>(&mut self) -> AnyResult<[u8; N]> {
        let end = self
            .offset
            .checked_add(N)
            .ok_or_else(|| failure("cursor overflow"))?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(|| failure("truncated vector"))?
            .try_into()?;
        self.offset = end;
        Ok(value)
    }

    fn u8(&mut self) -> AnyResult<u8> {
        Ok(self.take::<1>()?[0])
    }

    fn u16(&mut self) -> AnyResult<u16> {
        Ok(u16::from_be_bytes(self.take()?))
    }

    fn u32(&mut self) -> AnyResult<u32> {
        Ok(u32::from_be_bytes(self.take()?))
    }

    fn u64(&mut self) -> AnyResult<u64> {
        Ok(u64::from_be_bytes(self.take()?))
    }

    fn bytes(&mut self) -> AnyResult<&'a [u8]> {
        let length = usize::try_from(self.u32()?)?;
        let end = self
            .offset
            .checked_add(length)
            .ok_or_else(|| failure("cursor overflow"))?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(|| failure("truncated bytes field"))?;
        self.offset = end;
        Ok(value)
    }

    fn done(&self) -> AnyResult {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(failure("trailing vector bytes").into())
        }
    }
}

fn principal_kind(tag: u8) -> AnyResult<PrincipalKind> {
    match tag {
        1 => Ok(PrincipalKind::Human),
        2 => Ok(PrincipalKind::Machine),
        3 => Ok(PrincipalKind::Approver),
        4 => Ok(PrincipalKind::Witness),
        _ => Err(failure("unknown principal kind").into()),
    }
}

fn item_kind(tag: u8) -> AnyResult<ItemKind> {
    match tag {
        1 => Ok(ItemKind::Canonical),
        2 => Ok(ItemKind::Legacy),
        _ => Err(failure("unknown item kind").into()),
    }
}

fn access_mode(tag: u8) -> AnyResult<ItemAccessMode> {
    match tag {
        1 => Ok(ItemAccessMode::DirectOnly),
        2 => Ok(ItemAccessMode::WitnessedOnly),
        3 => Ok(ItemAccessMode::Mixed),
        _ => Err(failure("unknown access mode").into()),
    }
}

fn access_role(tag: u8) -> AnyResult<AccessRole> {
    match tag {
        1 => Ok(AccessRole::Reader),
        2 => Ok(AccessRole::Writer),
        3 => Ok(AccessRole::Owner),
        _ => Err(failure("unknown access role").into()),
    }
}

fn content_role(tag: u8) -> AnyResult<ContentRole> {
    match tag {
        1 => Ok(ContentRole::Descriptor),
        2 => Ok(ContentRole::Body),
        _ => Err(failure("unknown content role").into()),
    }
}

fn parse_principal(bytes: &[u8]) -> AnyResult<PrincipalDescriptorV1> {
    let mut cursor = Cursor::new(bytes);
    let descriptor = PrincipalDescriptorV1 {
        descriptor_version: cursor.u16()?,
        principal_id: PrincipalId::from_bytes(cursor.take()?)?,
        principal_kind: principal_kind(cursor.u8()?)?,
        recipient_public_key: RecipientPublicKey1216::new(cursor.take()?),
        verification_public_key: VerificationPublicKey32::new(cursor.take()?),
        self_signature: Signature64::new(cursor.take()?),
    };
    cursor.done()?;
    Ok(descriptor)
}

fn parse_descriptor(cursor: &mut Cursor<'_>) -> AnyResult<DescriptorMetadataV1> {
    Ok(DescriptorMetadataV1 {
        revision: cursor.u64()?,
        revision_seal_id: RevisionSealId::from_bytes(cursor.take()?)?,
        nonce: Nonce12::new(cursor.take()?),
        ciphertext_length: cursor.u32()?,
        ciphertext_digest: FixedBytes::new(cursor.take()?),
        plaintext_schema: cursor.u8()?,
        key_epoch: cursor.u64()?,
    })
}

fn parse_direct_slot(bytes: &[u8]) -> AnyResult<DirectSlotV1> {
    let mut cursor = Cursor::new(bytes);
    let slot = DirectSlotV1 {
        slot_schema: cursor.u8()?,
        slot_algorithm: cursor.u8()?,
        suite: cursor.u16()?,
        kem: cursor.u16()?,
        kdf: cursor.u16()?,
        aead: cursor.u16()?,
        vault_id: VaultId::from_bytes(cursor.take()?)?,
        item_id: ItemId::from_bytes(cursor.take()?)?,
        key_epoch: cursor.u64()?,
        content_role: content_role(cursor.u8()?)?,
        revision: cursor.u64()?,
        revision_seal_id: RevisionSealId::from_bytes(cursor.take()?)?,
        recipient_principal_id: PrincipalId::from_bytes(cursor.take()?)?,
        policy_sequence: cursor.u64()?,
        recipient_public_key_fingerprint: FixedBytes::new(cursor.take()?),
        access_role: access_role(cursor.u8()?)?,
        item_access_mode: access_mode(cursor.u8()?)?,
        encapsulation: FixedBytes::new(cursor.take()?),
        ciphertext: FixedBytes::new(cursor.take()?),
    };
    cursor.done()?;
    Ok(slot)
}

#[test]
fn normalized_state_hash_matches_the_frozen_j01a_vector() -> AnyResult {
    let corpus: Value = serde_json::from_str(include_str!(
        "../../../../docs/security/vectors/jury-v1-suite.json"
    ))?;
    let vector = &corpus["preimages"]["normalized_policy_state"];
    let encoded = vector["hex"]
        .as_str()
        .ok_or_else(|| failure("missing normalized state vector"))?;
    let preimage = hex::decode(encoded)?;
    let prefix = b"jury-v1/policy-state/hash\0\0\x01";
    if !preimage.starts_with(prefix) {
        return Err(failure("wrong normalized state prefix").into());
    }
    let mut cursor = Cursor::new(&preimage[prefix.len()..]);
    let suite = cursor.u16()?;
    let vault_id = VaultId::from_bytes(cursor.take()?)?;
    let sequence = cursor.u64()?;

    let principal_count = usize::try_from(cursor.u32()?)?;
    let mut principals = BTreeMap::new();
    for _ in 0..principal_count {
        let descriptor = parse_principal(cursor.bytes()?)?;
        principals.insert(
            descriptor.principal_id,
            PrincipalPolicyState {
                descriptor,
                display_label: "ExamplePrincipal".to_owned(),
            },
        );
    }
    let owner_count = usize::try_from(cursor.u32()?)?;
    let mut owners = BTreeSet::new();
    for _ in 0..owner_count {
        owners.insert(PrincipalId::from_bytes(cursor.take()?)?);
    }

    let item_count = usize::try_from(cursor.u32()?)?;
    let mut items = BTreeMap::new();
    for _ in 0..item_count {
        let item_id = ItemId::from_bytes(cursor.take()?)?;
        let kind = item_kind(cursor.u8()?)?;
        let mode = access_mode(cursor.u8()?)?;
        let key_epoch = cursor.u64()?;
        let descriptor = parse_descriptor(&mut cursor)?;
        let current_item_revision_hash = Digest32::new(cursor.take()?);
        items.insert(
            item_id,
            (
                mode,
                ItemPolicyState {
                    item_kind: kind,
                    key_epoch,
                    descriptor,
                    current_item_revision_hash,
                    grants: BTreeMap::new(),
                    direct_slots: Vec::new(),
                    witnessed_state: None,
                },
            ),
        );
    }

    let tombstone_count = usize::try_from(cursor.u32()?)?;
    let mut tombstones = BTreeMap::new();
    for _ in 0..tombstone_count {
        tombstones.insert(
            ItemId::from_bytes(cursor.take()?)?,
            TombstoneState {
                deletion_policy_sequence: cursor.u64()?,
                final_descriptor_digest: Digest32::new(cursor.take()?),
                final_item_revision_hash: Digest32::new(cursor.take()?),
            },
        );
    }

    let grant_count = usize::try_from(cursor.u32()?)?;
    for _ in 0..grant_count {
        let item_id = ItemId::from_bytes(cursor.take()?)?;
        let principal_id = PrincipalId::from_bytes(cursor.take()?)?;
        let role = access_role(cursor.u8()?)?;
        items
            .get_mut(&item_id)
            .ok_or_else(|| failure("grant for unknown item"))?
            .1
            .grants
            .insert(principal_id, role);
    }
    let slot_count = usize::try_from(cursor.u32()?)?;
    for _ in 0..slot_count {
        let slot = parse_direct_slot(&cursor.take::<1365>()?)?;
        items
            .get_mut(&slot.item_id)
            .ok_or_else(|| failure("slot for unknown item"))?
            .1
            .direct_slots
            .push(slot);
    }
    if cursor.u8()? != 0 {
        return Err(failure("direct J01A vector unexpectedly has witnessed state").into());
    }
    let revision_count = usize::try_from(cursor.u32()?)?;
    for _ in 0..revision_count {
        let item_id = ItemId::from_bytes(cursor.take()?)?;
        let expected = Digest32::new(cursor.take()?);
        if items
            .get(&item_id)
            .is_none_or(|(_, item)| item.current_item_revision_hash != expected)
        {
            return Err(failure("expected item revision differs").into());
        }
    }
    cursor.done()?;

    let items = items
        .into_iter()
        .map(|(item_id, (expected_mode, item))| {
            if item.access_mode() != Some(expected_mode) {
                Err(failure("item mode differs"))
            } else {
                Ok((item_id, item))
            }
        })
        .collect::<Result<BTreeMap<_, _>, _>>()?;
    let historical_principal_ids = principals.keys().copied().collect();
    let historical_recipient_keys = principals
        .values()
        .map(|principal| principal.descriptor.recipient_public_key.clone())
        .collect();
    let historical_verification_keys = principals
        .values()
        .map(|principal| principal.descriptor.verification_public_key.clone())
        .collect();
    let historical_principal_descriptors = principals
        .iter()
        .map(|(id, principal)| (*id, principal.descriptor.clone()))
        .collect();
    let historical_item_ids = items
        .keys()
        .copied()
        .chain(tombstones.keys().copied())
        .collect();
    let state = PolicyState {
        suite,
        vault_id,
        genesis_fingerprint: FixedBytes::new([0; 32]),
        sequence,
        terminal_revision_hash: FixedBytes::new([0; 32]),
        principals,
        historical_principal_descriptors,
        historical_principal_ids,
        historical_recipient_keys,
        historical_verification_keys,
        owners,
        items,
        historical_item_ids,
        tombstones,
        witness_policies: BTreeMap::new(),
    };
    let expected_hash: [u8; 32] = hex::decode(
        vector["sha256"]
            .as_str()
            .ok_or_else(|| failure("missing normalized state hash"))?,
    )?
    .try_into()
    .map_err(|_| failure("wrong normalized state hash length"))?;
    assert_eq!(
        state.normalized_state_hash()?,
        FixedBytes::new(expected_hash)
    );
    Ok(())
}
