use std::error::Error;
use std::io;

use jury_protocol::vault_v1::{
    AccessRole, ByteStringError, ContentRole, DescriptorCiphertext272, DescriptorMetadataV1,
    Digest32, DirectCiphertext48, DirectSlotV1, Encapsulation1120, FieldId, FixedBytes,
    FormatError, ItemAccessMode, ItemCiphertext, ItemDescriptorV1, ItemEnvelopeV1, ItemFieldKind,
    ItemFieldV1, ItemFieldValue, ItemId, ItemKind, ItemStateV1, MAX_FIELD_VALUE_BYTES,
    MAX_VAULT_BYTES, Nonce12, PlaintextError, PolicyGenesisV1, PolicyJournalV1, PolicyOperationV1,
    PrincipalDescriptorV1, PrincipalId, PrincipalKind, RecipientPublicKey1216, RevisionSealId,
    ShareCiphertext49, Signature64, SignedItemRevisionV1, SignedPolicyRevisionV1, SlotId,
    VaultFileV1, VaultHeaderV1, VaultId, VerificationPublicKey32, WitnessPolicyId,
    WitnessShareCapsuleV1, WitnessedSlotV1, WitnessedStateV1, item_body_aad, item_descriptor_aad,
};
use serde_json::Value;
use sha2::{Digest as _, Sha256};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

fn failure(message: &'static str) -> io::Error {
    io::Error::other(message)
}

fn hex_value<'a>(value: &'a Value, field: &str) -> TestResult<&'a str> {
    value[field]
        .as_str()
        .ok_or_else(|| failure("missing vector hex").into())
}

fn direct_corpus() -> TestResult<Value> {
    Ok(serde_json::from_str(include_str!(
        "../../../docs/security/vectors/jury-v1-suite.json"
    ))?)
}

fn witness_corpus() -> TestResult<Value> {
    Ok(serde_json::from_str(include_str!(
        "../../../conformance/witness-v1/vectors.json"
    ))?)
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take<const N: usize>(&mut self) -> TestResult<[u8; N]> {
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

    fn u8(&mut self) -> TestResult<u8> {
        Ok(self.take::<1>()?[0])
    }

    fn u16(&mut self) -> TestResult<u16> {
        Ok(u16::from_be_bytes(self.take()?))
    }

    fn u32(&mut self) -> TestResult<u32> {
        Ok(u32::from_be_bytes(self.take()?))
    }

    fn u64(&mut self) -> TestResult<u64> {
        Ok(u64::from_be_bytes(self.take()?))
    }

    fn done(&self) -> TestResult {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(failure("trailing vector bytes").into())
        }
    }
}

fn content_role(tag: u8) -> TestResult<ContentRole> {
    match tag {
        1 => Ok(ContentRole::Descriptor),
        2 => Ok(ContentRole::Body),
        _ => Err(failure("unknown content role").into()),
    }
}

fn access_role(tag: u8) -> TestResult<AccessRole> {
    match tag {
        1 => Ok(AccessRole::Reader),
        2 => Ok(AccessRole::Writer),
        3 => Ok(AccessRole::Owner),
        _ => Err(failure("unknown access role").into()),
    }
}

fn access_mode(tag: u8) -> TestResult<ItemAccessMode> {
    match tag {
        1 => Ok(ItemAccessMode::DirectOnly),
        2 => Ok(ItemAccessMode::WitnessedOnly),
        3 => Ok(ItemAccessMode::Mixed),
        _ => Err(failure("unknown access mode").into()),
    }
}

fn parse_direct_slot(bytes: &[u8]) -> TestResult<DirectSlotV1> {
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

fn parse_principal_descriptor(bytes: &[u8]) -> TestResult<PrincipalDescriptorV1> {
    let mut cursor = Cursor::new(bytes);
    let descriptor_version = cursor.u16()?;
    let principal_id = PrincipalId::from_bytes(cursor.take()?)?;
    let principal_kind = match cursor.u8()? {
        1 => PrincipalKind::Human,
        2 => PrincipalKind::Machine,
        3 => PrincipalKind::Approver,
        4 => PrincipalKind::Witness,
        _ => return Err(failure("unknown principal kind").into()),
    };
    let descriptor = PrincipalDescriptorV1 {
        descriptor_version,
        principal_id,
        principal_kind,
        recipient_public_key: FixedBytes::new(cursor.take()?),
        verification_public_key: FixedBytes::new(cursor.take()?),
        self_signature: FixedBytes::new(cursor.take()?),
    };
    cursor.done()?;
    Ok(descriptor)
}

fn jce_fields<'a>(preimage: &'a [u8], domain: &str) -> TestResult<&'a [u8]> {
    let prefix_length = domain.len() + 3;
    let prefix = preimage
        .get(..prefix_length)
        .ok_or_else(|| failure("truncated JCE1 prefix"))?;
    let mut expected = domain.as_bytes().to_vec();
    expected.extend_from_slice(b"\0\0\x01");
    if prefix != expected {
        return Err(failure("wrong JCE1 prefix").into());
    }
    Ok(&preimage[prefix_length..])
}

fn parse_capsule(bytes: &[u8]) -> TestResult<WitnessShareCapsuleV1> {
    let mut cursor = Cursor::new(bytes);
    let capsule = WitnessShareCapsuleV1 {
        capsule_schema: cursor.u16()?,
        protocol: cursor.u16()?,
        construction: cursor.u16()?,
        vault_id: VaultId::from_bytes(cursor.take()?)?,
        genesis_fingerprint: FixedBytes::new(cursor.take()?),
        item_id: ItemId::from_bytes(cursor.take()?)?,
        key_epoch: cursor.u64()?,
        item_access_mode: access_mode(cursor.u8()?)?,
        slot_id: SlotId::from_bytes(cursor.take()?)?,
        content_role: content_role(cursor.u8()?)?,
        revision: cursor.u64()?,
        revision_seal_id: RevisionSealId::from_bytes(cursor.take()?)?,
        vault_policy_sequence: cursor.u64()?,
        witness_policy_id: WitnessPolicyId::from_bytes(cursor.take()?)?,
        witness_policy_revision: cursor.u64()?,
        witness_policy_digest: FixedBytes::new(cursor.take()?),
        threshold: cursor.u8()?,
        member_count: cursor.u8()?,
        witness_id: PrincipalId::from_bytes(cursor.take()?)?,
        contribution_key_fingerprint: FixedBytes::new(cursor.take()?),
        share_index: cursor.u8()?,
        context_digest: FixedBytes::new(cursor.take()?),
        share_commitment: FixedBytes::new(cursor.take()?),
        encapsulation: FixedBytes::new(cursor.take()?),
        ciphertext: FixedBytes::new(cursor.take()?),
    };
    cursor.done()?;
    Ok(capsule)
}

fn parse_witnessed_slot(bytes: &[u8]) -> TestResult<WitnessedSlotV1> {
    let mut cursor = Cursor::new(bytes);
    let slot_schema = cursor.u8()?;
    let slot_algorithm = cursor.u8()?;
    let suite = cursor.u16()?;
    let protocol = cursor.u16()?;
    let construction = cursor.u16()?;
    let vault_id = VaultId::from_bytes(cursor.take()?)?;
    let genesis_fingerprint = FixedBytes::new(cursor.take()?);
    let item_id = ItemId::from_bytes(cursor.take()?)?;
    let key_epoch = cursor.u64()?;
    let item_access_mode = access_mode(cursor.u8()?)?;
    let slot_id = SlotId::from_bytes(cursor.take()?)?;
    let content_role = content_role(cursor.u8()?)?;
    let revision = cursor.u64()?;
    let revision_seal_id = RevisionSealId::from_bytes(cursor.take()?)?;
    let vault_policy_sequence = cursor.u64()?;
    let witness_policy_id = WitnessPolicyId::from_bytes(cursor.take()?)?;
    let witness_policy_revision = cursor.u64()?;
    let witness_policy_digest = FixedBytes::new(cursor.take()?);
    let threshold = cursor.u8()?;
    let member_count = cursor.u8()?;
    let capsule_count = cursor.u32()?;
    let mut capsules = Vec::new();
    for _ in 0..capsule_count {
        let length = usize::try_from(cursor.u32()?)?;
        let end = cursor
            .offset
            .checked_add(length)
            .ok_or_else(|| failure("capsule length overflow"))?;
        let capsule = cursor
            .bytes
            .get(cursor.offset..end)
            .ok_or_else(|| failure("truncated capsule"))?;
        capsules.push(parse_capsule(capsule)?);
        cursor.offset = end;
    }
    let capsule_set_digest = FixedBytes::new(cursor.take()?);
    cursor.done()?;
    Ok(WitnessedSlotV1 {
        slot_schema,
        slot_algorithm,
        suite,
        protocol,
        construction,
        vault_id,
        genesis_fingerprint,
        item_id,
        key_epoch,
        item_access_mode,
        slot_id,
        content_role,
        revision,
        revision_seal_id,
        vault_policy_sequence,
        witness_policy_id,
        witness_policy_revision,
        witness_policy_digest,
        threshold,
        member_count,
        capsules,
        capsule_set_digest,
    })
}

fn example_vault() -> TestResult<VaultFileV1> {
    let vault_id = VaultId::from_bytes([0x11; 32])?;
    let owner = PrincipalDescriptorV1 {
        descriptor_version: 1,
        principal_id: PrincipalId::from_bytes([0x22; 32])?,
        principal_kind: PrincipalKind::Human,
        recipient_public_key: RecipientPublicKey1216::new([0x33; 1_216]),
        verification_public_key: VerificationPublicKey32::new([0x44; 32]),
        self_signature: Signature64::new([0x55; 64]),
    };
    let genesis = PolicyGenesisV1 {
        vault_id,
        policy_sequence: 0,
        previous_policy_hash: Digest32::new([0; 32]),
        created_at_ms: 1_700_000_000_000,
        suite: 1,
        owner,
        source_attestation: None,
        item_inventory: Vec::new(),
        direct_grants: Vec::new(),
        owner_signature: Signature64::new([0x66; 64]),
    };
    let fingerprint = genesis.recomputed_fingerprint()?;
    Ok(VaultFileV1 {
        header: VaultHeaderV1 {
            magic: "jury-vault".to_owned(),
            version: 1,
            vault_id,
            created_at_ms: genesis.created_at_ms,
            suite: 1,
            policy_schema: 1,
            item_schema: 1,
            identity_schema: 1,
            genesis_fingerprint: fingerprint,
        },
        policy: PolicyJournalV1 {
            genesis,
            revisions: Vec::new(),
        },
        items: Vec::new(),
        suite_migration: None,
    })
}

fn example_vault_with_item() -> TestResult<VaultFileV1> {
    let mut vault = example_vault()?;
    let item_id = ItemId::from_bytes([0x77; 32])?;
    let descriptor_ciphertext = DescriptorCiphertext272::new([0xa1; 272]);
    let body_ciphertext = ItemCiphertext::new(vec![0xb2; 4_112])?;
    let descriptor = DescriptorMetadataV1 {
        revision: 1,
        revision_seal_id: RevisionSealId::from_bytes([0xc3; 32])?,
        nonce: Nonce12::new([0xd4; 12]),
        ciphertext_length: 272,
        ciphertext_digest: digest(descriptor_ciphertext.as_bytes()),
        plaintext_schema: 1,
        key_epoch: 1,
    };
    let current_revision = SignedItemRevisionV1 {
        vault_id: vault.header.vault_id,
        item_id,
        item_revision: 1,
        previous_item_revision_hash: Digest32::new([0; 32]),
        key_epoch: 1,
        policy_sequence: 0,
        author_principal_id: vault.policy.genesis.owner.principal_id,
        timestamp_ms: vault.header.created_at_ms,
        revision_seal_id: RevisionSealId::from_bytes([0xe5; 32])?,
        nonce: Nonce12::new([0xf6; 12]),
        ciphertext_length: 4_112,
        ciphertext_digest: digest(body_ciphertext.as_bytes()),
        plaintext_schema: 1,
        bucket_id: 1,
        signature: Signature64::new([0x17; 64]),
    };
    vault.items.push(ItemEnvelopeV1 {
        item_id,
        descriptor,
        descriptor_ciphertext,
        prior_revisions: Vec::new(),
        current_revision,
        body_ciphertext,
    });
    Ok(vault)
}

fn direct_policy_vault() -> TestResult<VaultFileV1> {
    let corpus = direct_corpus()?;
    let mut slots = ["descriptor", "body"]
        .into_iter()
        .map(|role| {
            let bytes = hex::decode(hex_value(
                &corpus["encodings"]["direct_slots"][role],
                "hex",
            )?)?;
            parse_direct_slot(&bytes)
        })
        .collect::<TestResult<Vec<_>>>()?;
    slots.sort_by_key(|slot| slot.content_role);

    let descriptor_bytes = hex::decode(hex_value(
        &corpus["encodings"]["descriptor_metadata"],
        "hex",
    )?)?;
    let mut descriptor_cursor = Cursor::new(&descriptor_bytes);
    let descriptor = DescriptorMetadataV1 {
        revision: descriptor_cursor.u64()?,
        revision_seal_id: RevisionSealId::from_bytes(descriptor_cursor.take()?)?,
        nonce: FixedBytes::new(descriptor_cursor.take()?),
        ciphertext_length: descriptor_cursor.u32()?,
        ciphertext_digest: FixedBytes::new(descriptor_cursor.take()?),
        plaintext_schema: descriptor_cursor.u8()?,
        key_epoch: descriptor_cursor.u64()?,
    };
    descriptor_cursor.done()?;

    let mut vault = example_vault()?;
    vault.policy.genesis.vault_id = slots[0].vault_id;
    vault.header.vault_id = slots[0].vault_id;
    vault.header.genesis_fingerprint = vault.policy.genesis.recomputed_fingerprint()?;
    vault.policy.revisions.push(SignedPolicyRevisionV1 {
        vault_id: vault.header.vault_id,
        sequence: 1,
        previous_revision_hash: vault.header.genesis_fingerprint.clone(),
        timestamp_ms: vault.header.created_at_ms + 1,
        author_principal_id: vault.policy.genesis.owner.principal_id,
        operations: vec![PolicyOperationV1::ItemCreate {
            item_id: slots[0].item_id,
            item_kind: ItemKind::Canonical,
            key_epoch: 1,
            descriptor,
            current_item_revision_hash: FixedBytes::new([0x91; 32]),
            direct_slots: slots,
            witnessed_state: None,
        }],
        resulting_policy_state_hash: FixedBytes::new([0x92; 32]),
        signature: Signature64::new([0x93; 64]),
    });
    Ok(vault)
}

fn digest(bytes: &[u8]) -> Digest32 {
    FixedBytes::new(Sha256::digest(bytes).into())
}

#[test]
fn direct_slot_matches_the_bound_j01a_bytes() -> TestResult {
    let corpus = direct_corpus()?;
    let vector = &corpus["encodings"]["direct_slots"]["descriptor"];
    let expected = hex::decode(hex_value(vector, "hex")?)?;
    let slot = parse_direct_slot(&expected)?;

    assert_eq!(slot.canonical_bytes(), expected);
    let info_name = hex_value(vector, "info_preimage")?;
    let aad_name = hex_value(vector, "aad_preimage")?;
    assert_eq!(
        slot.info_preimage(),
        hex::decode(hex_value(&corpus["preimages"][info_name], "hex")?)?
    );
    assert_eq!(
        slot.aad_preimage(),
        hex::decode(hex_value(&corpus["preimages"][aad_name], "hex")?)?
    );
    Ok(())
}

#[test]
fn shared_format_builders_match_the_bound_j01a_bytes() -> TestResult {
    let corpus = direct_corpus()?;
    let descriptor_bytes = hex::decode(hex_value(
        &corpus["encodings"]["principal_descriptor_owner"],
        "hex",
    )?)?;
    let descriptor = parse_principal_descriptor(&descriptor_bytes)?;
    assert_eq!(descriptor.canonical_bytes(), descriptor_bytes);
    assert_eq!(
        descriptor.fingerprint_preimage()?,
        hex::decode(hex_value(
            &corpus["preimages"]["principal_descriptor_owner_fingerprint"],
            "hex",
        )?)?
    );
    assert_eq!(
        descriptor.self_signature_preimage()?,
        hex::decode(hex_value(
            &corpus["preimages"]["principal_descriptor_owner_self_signature"],
            "hex",
        )?)?
    );

    let descriptor_aad = hex::decode(hex_value(
        &corpus["preimages"]["item_descriptor_aad"],
        "hex",
    )?)?;
    let mut descriptor_fields = Cursor::new(jce_fields(
        &descriptor_aad,
        "jury-vault-v1-item-descriptor",
    )?);
    assert_eq!(descriptor_fields.u8()?, 1);
    let vault_id = descriptor_fields.take()?;
    let item_id = descriptor_fields.take()?;
    let key_epoch = descriptor_fields.u64()?;
    let revision = descriptor_fields.u64()?;
    let seal_id = descriptor_fields.take()?;
    descriptor_fields.done()?;
    assert_eq!(
        item_descriptor_aad(&vault_id, &item_id, key_epoch, revision, &seal_id),
        descriptor_aad
    );

    let body_aad = hex::decode(hex_value(&corpus["preimages"]["item_body_aad"], "hex")?)?;
    let mut body_fields = Cursor::new(jce_fields(&body_aad, "jury-vault-v1-item-body")?);
    assert_eq!(body_fields.u8()?, 1);
    let vault_id = body_fields.take()?;
    let item_id = body_fields.take()?;
    let key_epoch = body_fields.u64()?;
    let revision = body_fields.u64()?;
    let seal_id = body_fields.take()?;
    let bucket_id = body_fields.u8()?;
    body_fields.done()?;
    assert_eq!(
        item_body_aad(
            &vault_id, &item_id, key_epoch, revision, &seal_id, bucket_id,
        ),
        body_aad
    );
    Ok(())
}

#[test]
fn witnessed_slot_and_state_match_the_bound_j19_bytes() -> TestResult {
    let corpus = witness_corpus()?;
    let construction = &corpus["construction_vector"];
    let expected = hex::decode(hex_value(construction, "witnessed_slot_hex")?)?;
    let slot = parse_witnessed_slot(&expected)?;

    assert_eq!(slot.canonical_bytes()?, expected);
    assert_eq!(
        slot.recomputed_capsule_set_digest()?.as_bytes(),
        &hex::decode(hex_value(construction, "capsule_set_digest_hex")?)?.as_slice()
    );
    assert_eq!(
        slot.recomputed_digest()?.as_bytes(),
        &hex::decode(hex_value(construction, "witnessed_slot_digest_hex")?)?.as_slice()
    );
    for (capsule, vector) in slot.capsules.iter().zip(
        construction["capsules"]
            .as_array()
            .ok_or_else(|| failure("capsules are not an array"))?,
    ) {
        assert_eq!(
            capsule.context_preimage(),
            hex::decode(hex_value(vector, "context_preimage_hex")?)?
        );
        assert_eq!(
            capsule.info_preimage(),
            hex::decode(hex_value(vector, "info_hex")?)?
        );
        assert_eq!(
            capsule.aad_preimage(),
            hex::decode(hex_value(vector, "aad_hex")?)?
        );
    }
    let state = WitnessedStateV1 {
        slots: vec![slot.clone()],
        digest: FixedBytes::new(
            hex::decode(hex_value(construction, "witnessed_state_digest_hex")?)?
                .try_into()
                .map_err(|_| failure("witnessed-state digest length"))?,
        ),
    };
    assert_eq!(state.recomputed_digest()?, state.digest);
    assert!(!state.has_item_quorum_claim(0));
    let mut complete_state = state;
    let mut descriptor_slot = slot;
    descriptor_slot.content_role = ContentRole::Descriptor;
    complete_state.slots.insert(0, descriptor_slot);
    assert!(complete_state.has_item_quorum_claim(0));
    assert!(!complete_state.has_item_quorum_claim(1));
    Ok(())
}

#[test]
fn vault_json_has_one_bounded_byte_stable_form() -> TestResult {
    let vault = example_vault()?;
    let bytes = vault.to_json_bytes()?;
    assert!(bytes.ends_with(b"\n"));
    assert_eq!(
        bytes,
        include_bytes!("../../../conformance/vault-v1/example-vault.json")
    );
    assert_eq!(VaultFileV1::parse(&bytes)?, vault);

    let mut alternate_whitespace = vec![b'\n'];
    alternate_whitespace.extend_from_slice(&bytes);
    assert_eq!(
        VaultFileV1::parse(&alternate_whitespace),
        Err(FormatError::NonCanonicalJson)
    );

    let mut with_local_state: Value = serde_json::from_slice(&bytes)?;
    with_local_state["checkpoint"] = Value::String("local state is forbidden".to_owned());
    assert_eq!(
        VaultFileV1::parse(&serde_json::to_vec_pretty(&with_local_state)?),
        Err(FormatError::InvalidJson)
    );
    Ok(())
}

#[test]
fn malformed_public_input_fails_before_format_use() -> TestResult {
    let bytes = example_vault()?.to_json_bytes()?;
    let conflict = b"<<<<<<< ours\n{}\n=======\n{}\n>>>>>>> theirs\n";
    assert_eq!(
        VaultFileV1::parse(conflict),
        Err(FormatError::ConflictMarker)
    );

    let duplicate_magic = std::str::from_utf8(&bytes)?.replace(
        "\"magic\": \"jury-vault\",",
        "\"magic\": \"jury-vault\",\n    \"magic\": \"jury-vault\",",
    );
    assert_eq!(
        VaultFileV1::parse(duplicate_magic.as_bytes()),
        Err(FormatError::InvalidJson)
    );
    assert_eq!(
        VaultFileV1::parse(b"{\"header\":"),
        Err(FormatError::InvalidJson)
    );

    let vectors: Value =
        serde_json::from_str(include_str!("../../../conformance/vault-v1/vectors.json"))?;
    assert_eq!(
        hex::encode(Sha256::digest(&bytes)),
        hex_value(&vectors, "artifact_sha256")?
    );
    for case in vectors["negative_cases"]
        .as_array()
        .ok_or_else(|| failure("negative cases are not an array"))?
    {
        let mutation = case["mutation"]
            .as_str()
            .ok_or_else(|| failure("missing mutation"))?;
        let expected = case["expected"]
            .as_str()
            .ok_or_else(|| failure("missing expected result"))?;
        let mutated = mutate_artifact(&bytes, mutation)?;
        let actual = match VaultFileV1::parse(&mutated) {
            Ok(_) => "accepted",
            Err(FormatError::NonCanonicalJson) => "non-canonical",
            Err(FormatError::ConflictMarker) => "conflict-marker",
            Err(_) => "invalid",
        };
        assert_eq!(actual, expected, "mutation {mutation}");
    }
    Ok(())
}

fn mutate_artifact(bytes: &[u8], mutation: &str) -> TestResult<Vec<u8>> {
    if mutation == "alternate-whitespace" {
        let mut output = vec![b'\n'];
        output.extend_from_slice(bytes);
        return Ok(output);
    }
    if mutation == "conflict-marker" {
        return Ok(b"<<<<<<< ours\n{}\n=======\n{}\n>>>>>>> theirs\n".to_vec());
    }
    if mutation == "truncated" {
        return Ok(bytes[..bytes.len() / 2].to_vec());
    }

    let mut value: Value = serde_json::from_slice(bytes)?;
    match mutation {
        "wrong-magic" => value["header"]["magic"] = Value::String("jig-vault".to_owned()),
        "unknown-version" => value["header"]["version"] = Value::from(2),
        "unknown-suite" => value["header"]["suite"] = Value::from(2),
        "local-state-field" => {
            value["checkpoint"] = Value::String("installation-local".to_owned());
        }
        _ => return Err(failure("unknown fixture mutation").into()),
    }
    let mut output = serde_json::to_vec_pretty(&value)?;
    output.push(b'\n');
    Ok(output)
}

#[test]
fn fixed_binary_json_rejects_alternate_base64() -> TestResult {
    let bytes = DirectCiphertext48::new([0x7a; 48]);
    let encoded = serde_json::to_string(&bytes)?;
    assert_eq!(serde_json::from_str::<DirectCiphertext48>(&encoded)?, bytes);
    assert!(serde_json::from_str::<DirectCiphertext48>("\"eg\"").is_err());
    assert!(serde_json::from_str::<Encapsulation1120>("\"\"").is_err());
    assert!(serde_json::from_str::<ShareCiphertext49>("\"%%%%\"").is_err());
    Ok(())
}

#[test]
fn encrypted_plaintext_formats_are_bounded_and_canonical() -> TestResult {
    let descriptor = ItemDescriptorV1::new("ExampleVault".to_owned())?;
    let encoded_descriptor = descriptor.encode();
    assert_eq!(
        ItemDescriptorV1::decode(&encoded_descriptor)?.name(),
        "ExampleVault"
    );
    let mut bad_padding = encoded_descriptor;
    bad_padding[255] = 1;
    assert!(matches!(
        ItemDescriptorV1::decode(&bad_padding),
        Err(PlaintextError::DescriptorPadding)
    ));

    let state = ItemStateV1 {
        plaintext_schema: 1,
        fields: vec![
            ItemFieldV1 {
                name: "account".to_owned(),
                field_id: FieldId::from_bytes([0x71; 32])?,
                value: ItemFieldValue::new(b"ExamplePrincipal".to_vec())?,
                decoded_length: 16,
                kind: ItemFieldKind::Text,
                created_at_ms: 10,
                updated_at_ms: 10,
            },
            ItemFieldV1 {
                name: "token".to_owned(),
                field_id: FieldId::from_bytes([0x72; 32])?,
                value: ItemFieldValue::new(b"ExampleSecret".to_vec())?,
                decoded_length: 13,
                kind: ItemFieldKind::Concealed,
                created_at_ms: 10,
                updated_at_ms: 11,
            },
        ],
    };
    let canonical = state.to_canonical_bytes()?;
    let parsed = ItemStateV1::parse_canonical(&canonical)?;
    assert!(parsed == state);
    let framed = state.frame(1)?;
    assert_eq!(framed.len(), 4_096);
    assert!(ItemStateV1::parse_framed(1, &framed)? == state);

    let mut bad_frame = framed;
    bad_frame[4_095] = 1;
    assert!(matches!(
        ItemStateV1::parse_framed(1, &bad_frame),
        Err(PlaintextError::BodyPadding)
    ));
    let mut alternate = canonical;
    alternate.push(b' ');
    assert!(matches!(
        ItemStateV1::parse_canonical(&alternate),
        Err(PlaintextError::NonCanonicalJson)
    ));

    let mut duplicate = state;
    duplicate.fields[1].field_id = duplicate.fields[0].field_id;
    assert_eq!(duplicate.validate(), Err(PlaintextError::DuplicateField));
    Ok(())
}

#[test]
fn artifact_bounds_and_duplicate_state_fail_closed() -> TestResult {
    let vault = example_vault_with_item()?;
    vault.validate()?;

    let mut duplicate_item = vault.clone();
    duplicate_item.items.push(duplicate_item.items[0].clone());
    assert!(matches!(
        duplicate_item.validate(),
        Err(FormatError::Invalid("items are not canonical"))
    ));

    let mut duplicate_nonce = vault.clone();
    duplicate_nonce.items[0].current_revision.nonce =
        duplicate_nonce.items[0].descriptor.nonce.clone();
    assert!(matches!(
        duplicate_nonce.validate(),
        Err(FormatError::Invalid("nonce is reused"))
    ));

    let mut duplicate_seal = vault.clone();
    duplicate_seal.items[0].current_revision.revision_seal_id =
        duplicate_seal.items[0].descriptor.revision_seal_id;
    assert!(matches!(
        duplicate_seal.validate(),
        Err(FormatError::Invalid("revision seal is reused"))
    ));

    let mut revision_gap = vault;
    let repeated_revision = revision_gap.items[0].current_revision.clone();
    revision_gap.items[0]
        .prior_revisions
        .push(repeated_revision);
    assert!(matches!(
        revision_gap.validate(),
        Err(FormatError::Invalid("item revision ancestry differs"))
    ));

    assert_eq!(
        VaultFileV1::parse(&vec![b' '; MAX_VAULT_BYTES + 1]),
        Err(FormatError::ArtifactTooLarge)
    );
    assert_eq!(
        ItemFieldValue::new(vec![0; MAX_FIELD_VALUE_BYTES + 1]),
        Err(ByteStringError::TooLong {
            maximum: MAX_FIELD_VALUE_BYTES,
            actual: MAX_FIELD_VALUE_BYTES + 1,
        })
    );
    Ok(())
}

#[test]
fn unknown_downgraded_and_reused_slots_fail_closed() -> TestResult {
    let vault = direct_policy_vault()?;
    vault.validate()?;

    let mut downgraded = vault.clone();
    let PolicyOperationV1::ItemCreate { direct_slots, .. } =
        &mut downgraded.policy.revisions[0].operations[0]
    else {
        return Err(failure("expected item creation").into());
    };
    direct_slots[0].slot_algorithm = 0;
    assert_eq!(
        downgraded.validate(),
        Err(FormatError::Invalid("direct slot context differs"))
    );

    let mut reused = vault.clone();
    let PolicyOperationV1::ItemCreate { direct_slots, .. } =
        &mut reused.policy.revisions[0].operations[0]
    else {
        return Err(failure("expected item creation").into());
    };
    direct_slots[1].encapsulation = direct_slots[0].encapsulation.clone();
    assert_eq!(
        reused.validate(),
        Err(FormatError::Invalid("direct encapsulation is reused"))
    );

    let mut unknown_role: Value = serde_json::from_slice(&vault.to_json_bytes()?)?;
    unknown_role["policy"]["revisions"][0]["operations"][0]["direct_slots"][0]["content_role"] =
        Value::String("future-role".to_owned());
    let mut bytes = serde_json::to_vec_pretty(&unknown_role)?;
    bytes.push(b'\n');
    assert_eq!(VaultFileV1::parse(&bytes), Err(FormatError::InvalidJson));

    let mut extra_operation_field: Value = serde_json::from_slice(&vault.to_json_bytes()?)?;
    extra_operation_field["policy"]["revisions"][0]["operations"][0]["local_state"] =
        Value::Bool(true);
    let mut bytes = serde_json::to_vec_pretty(&extra_operation_field)?;
    bytes.push(b'\n');
    assert_eq!(VaultFileV1::parse(&bytes), Err(FormatError::InvalidJson));
    Ok(())
}
