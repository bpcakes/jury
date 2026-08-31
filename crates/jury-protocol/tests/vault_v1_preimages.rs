use std::error::Error;
use std::io;

use jury_protocol::vault_v1::{
    AccessRole, ContentRole, DescriptorMetadataV1, Digest32, DirectSlotV1, FixedBytes, ItemKind,
    MigrationId, Nonce12, PolicyGenesisV1, PolicyOperationV1, PrincipalDescriptorV1, PrincipalId,
    PrincipalKind, RecipientPublicKey1216, RemovalReason, RevisionSealId, RolloverId, Signature64,
    SignedItemRevisionV1, SignedPolicyRevisionV1, SignedRolloverV1, SignedSuiteMigrationV1,
    SourceAttestationV1, VaultId, VerificationPublicKey32,
};
use serde_json::Value;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

fn failure(message: &'static str) -> io::Error {
    io::Error::other(message)
}

fn corpus() -> TestResult<Value> {
    Ok(serde_json::from_str(include_str!(
        "../../../docs/security/vectors/jury-v1-suite.json"
    ))?)
}

fn vector_bytes(value: &Value) -> TestResult<Vec<u8>> {
    Ok(hex::decode(
        value["hex"]
            .as_str()
            .ok_or_else(|| failure("missing vector hex"))?,
    )?)
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

    fn slice(&mut self, length: usize) -> TestResult<&'a [u8]> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or_else(|| failure("cursor overflow"))?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(|| failure("truncated vector"))?;
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

    fn bytes_field(&mut self) -> TestResult<&'a [u8]> {
        let length = usize::try_from(self.u32()?)?;
        self.slice(length)
    }

    fn done(&self) -> TestResult {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(failure("trailing vector bytes").into())
        }
    }
}

fn jce_fields<'a>(preimage: &'a [u8], domain: &str) -> TestResult<&'a [u8]> {
    let prefix_length = domain.len() + 3;
    let mut expected = domain.as_bytes().to_vec();
    expected.extend_from_slice(b"\0\0\x01");
    if preimage.get(..prefix_length) != Some(expected.as_slice()) {
        return Err(failure("wrong JCE1 prefix").into());
    }
    Ok(&preimage[prefix_length..])
}

fn principal_kind(tag: u8) -> TestResult<PrincipalKind> {
    match tag {
        1 => Ok(PrincipalKind::Human),
        2 => Ok(PrincipalKind::Machine),
        3 => Ok(PrincipalKind::Approver),
        4 => Ok(PrincipalKind::Witness),
        _ => Err(failure("unknown principal kind").into()),
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

fn parse_principal(bytes: &[u8]) -> TestResult<PrincipalDescriptorV1> {
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

fn parse_descriptor(cursor: &mut Cursor<'_>) -> TestResult<DescriptorMetadataV1> {
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

fn content_role(tag: u8) -> TestResult<ContentRole> {
    match tag {
        1 => Ok(ContentRole::Descriptor),
        2 => Ok(ContentRole::Body),
        _ => Err(failure("unknown content role").into()),
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
        item_id: jury_protocol::vault_v1::ItemId::from_bytes(cursor.take()?)?,
        key_epoch: cursor.u64()?,
        content_role: content_role(cursor.u8()?)?,
        revision: cursor.u64()?,
        revision_seal_id: RevisionSealId::from_bytes(cursor.take()?)?,
        recipient_principal_id: PrincipalId::from_bytes(cursor.take()?)?,
        policy_sequence: cursor.u64()?,
        recipient_public_key_fingerprint: FixedBytes::new(cursor.take()?),
        access_role: access_role(cursor.u8()?)?,
        item_access_mode: match cursor.u8()? {
            1 => jury_protocol::vault_v1::ItemAccessMode::DirectOnly,
            2 => jury_protocol::vault_v1::ItemAccessMode::WitnessedOnly,
            3 => jury_protocol::vault_v1::ItemAccessMode::Mixed,
            _ => return Err(failure("unknown access mode").into()),
        },
        encapsulation: FixedBytes::new(cursor.take()?),
        ciphertext: FixedBytes::new(cursor.take()?),
    };
    cursor.done()?;
    Ok(slot)
}

fn parse_optional_digest(cursor: &mut Cursor<'_>) -> TestResult<Option<Digest32>> {
    match cursor.u8()? {
        0 => Ok(None),
        1 => Ok(Some(FixedBytes::new(cursor.take()?))),
        _ => Err(failure("unknown optional tag").into()),
    }
}

fn parse_id_list(cursor: &mut Cursor<'_>) -> TestResult<Vec<PrincipalId>> {
    let count = usize::try_from(cursor.u32()?)?;
    (0..count)
        .map(|_| Ok(PrincipalId::from_bytes(cursor.take()?)?))
        .collect()
}

fn parse_direct_list(cursor: &mut Cursor<'_>) -> TestResult<Vec<DirectSlotV1>> {
    let count = usize::try_from(cursor.u32()?)?;
    (0..count)
        .map(|_| parse_direct_slot(cursor.slice(1_365)?))
        .collect()
}

fn parse_operation(bytes: &[u8]) -> TestResult<PolicyOperationV1> {
    let mut cursor = Cursor::new(bytes);
    let operation = match cursor.u8()? {
        1 => PolicyOperationV1::PrincipalAdd {
            descriptor: parse_principal(cursor.bytes_field()?)?,
            display_label: std::str::from_utf8(cursor.bytes_field()?)?.to_owned(),
            registration_proof_digest: FixedBytes::new(cursor.take()?),
        },
        2 => PolicyOperationV1::PrincipalLabelChange {
            principal_id: PrincipalId::from_bytes(cursor.take()?)?,
            prior_label: std::str::from_utf8(cursor.bytes_field()?)?.to_owned(),
            next_label: std::str::from_utf8(cursor.bytes_field()?)?.to_owned(),
        },
        3 => PolicyOperationV1::PrincipalRemove {
            principal_id: PrincipalId::from_bytes(cursor.take()?)?,
            removal_reason: match cursor.u8()? {
                1 => RemovalReason::OperatorRemoval,
                2 => RemovalReason::Replacement,
                3 => RemovalReason::SuspectedCompromise,
                4 => RemovalReason::Retirement,
                _ => return Err(failure("unknown removal reason").into()),
            },
        },
        4 => PolicyOperationV1::OwnerGrant {
            principal_id: PrincipalId::from_bytes(cursor.take()?)?,
        },
        5 => PolicyOperationV1::OwnerRevoke {
            principal_id: PrincipalId::from_bytes(cursor.take()?)?,
        },
        6 => PolicyOperationV1::ItemCreate {
            item_id: jury_protocol::vault_v1::ItemId::from_bytes(cursor.take()?)?,
            item_kind: match cursor.u8()? {
                1 => ItemKind::Canonical,
                2 => ItemKind::Legacy,
                _ => return Err(failure("unknown item kind").into()),
            },
            key_epoch: cursor.u64()?,
            descriptor: parse_descriptor(&mut cursor)?,
            current_item_revision_hash: FixedBytes::new(cursor.take()?),
            direct_slots: parse_direct_list(&mut cursor)?,
            witnessed_state: parse_optional_digest(&mut cursor)?.map(|digest| {
                jury_protocol::vault_v1::WitnessedStateV1 {
                    slots: Vec::new(),
                    digest,
                }
            }),
        },
        7 => PolicyOperationV1::ItemRename {
            item_id: jury_protocol::vault_v1::ItemId::from_bytes(cursor.take()?)?,
            prior_descriptor_revision: cursor.u64()?,
            next_descriptor: parse_descriptor(&mut cursor)?,
        },
        8 => PolicyOperationV1::ItemDelete {
            item_id: jury_protocol::vault_v1::ItemId::from_bytes(cursor.take()?)?,
            final_descriptor_digest: FixedBytes::new(cursor.take()?),
            final_item_revision_hash: FixedBytes::new(cursor.take()?),
            deletion_policy_sequence: cursor.u64()?,
        },
        9 => PolicyOperationV1::ItemRoleChange {
            item_id: jury_protocol::vault_v1::ItemId::from_bytes(cursor.take()?)?,
            principal_id: PrincipalId::from_bytes(cursor.take()?)?,
            prior_role: match cursor.u8()? {
                0 => None,
                1 => Some(access_role(cursor.u8()?)?),
                _ => return Err(failure("unknown optional role").into()),
            },
            next_role: match cursor.u8()? {
                0 => None,
                1 => Some(access_role(cursor.u8()?)?),
                _ => return Err(failure("unknown optional role").into()),
            },
        },
        10 => PolicyOperationV1::ItemReaderSetChange {
            item_id: jury_protocol::vault_v1::ItemId::from_bytes(cursor.take()?)?,
            prior_epoch: cursor.u64()?,
            next_epoch: cursor.u64()?,
            prior_reader_ids: parse_id_list(&mut cursor)?,
            next_reader_ids: parse_id_list(&mut cursor)?,
            replacement_descriptor: parse_descriptor(&mut cursor)?,
            replacement_current_item_revision_hash: FixedBytes::new(cursor.take()?),
        },
        11 => PolicyOperationV1::ItemSlotsReplace {
            item_id: jury_protocol::vault_v1::ItemId::from_bytes(cursor.take()?)?,
            next_epoch: cursor.u64()?,
            direct_slots: parse_direct_list(&mut cursor)?,
            witnessed_state: parse_optional_digest(&mut cursor)?.map(|digest| {
                jury_protocol::vault_v1::WitnessedStateV1 {
                    slots: Vec::new(),
                    digest,
                }
            }),
        },
        12 => PolicyOperationV1::PrincipalReplace {
            prior_principal_id: PrincipalId::from_bytes(cursor.take()?)?,
            next_descriptor: parse_principal(cursor.bytes_field()?)?,
            registration_proof_digest: FixedBytes::new(cursor.take()?),
        },
        _ => return Err(failure("unknown operation").into()),
    };
    cursor.done()?;
    Ok(operation)
}

fn parse_rollover(preimage: &[u8], signature: Signature64) -> TestResult<SignedRolloverV1> {
    let mut cursor = Cursor::new(jce_fields(preimage, "jury-v1/rollover/signature")?);
    let statement = SignedRolloverV1 {
        rollover_format: cursor.u16()?,
        rollover_id: RolloverId::from_bytes(cursor.take()?)?,
        source_vault_id: VaultId::from_bytes(cursor.take()?)?,
        source_genesis_fingerprint: FixedBytes::new(cursor.take()?),
        terminal_source_revision_hash: FixedBytes::new(cursor.take()?),
        destination_vault_id: VaultId::from_bytes(cursor.take()?)?,
        destination_suite: cursor.u16()?,
        bootstrap_manifest_digest: FixedBytes::new(cursor.take()?),
        acting_owner_principal_id: PrincipalId::from_bytes(cursor.take()?)?,
        signature,
    };
    cursor.done()?;
    Ok(statement)
}

fn parse_source(bytes: &[u8]) -> TestResult<SourceAttestationV1> {
    let mut cursor = Cursor::new(bytes);
    let source = match cursor.u8()? {
        1 => SourceAttestationV1::LegacyMigration {
            source_format: cursor.u16()?,
            migration_id: MigrationId::from_bytes(cursor.take()?)?,
            final_legacy_audit_digest: FixedBytes::new(cursor.take()?),
            terminal_legacy_audit_mac: FixedBytes::new(cursor.take()?),
        },
        2 => {
            let preimage = cursor.bytes_field()?;
            let signature = Signature64::new(cursor.take()?);
            SourceAttestationV1::Rollover {
                statement: parse_rollover(preimage, signature)?,
            }
        }
        _ => return Err(failure("unknown source attestation").into()),
    };
    cursor.done()?;
    Ok(source)
}

fn parse_genesis(preimage: &[u8]) -> TestResult<PolicyGenesisV1> {
    let mut cursor = Cursor::new(jce_fields(preimage, "jury-v1/policy-genesis/signature")?);
    let vault_id = VaultId::from_bytes(cursor.take()?)?;
    let policy_sequence = cursor.u64()?;
    let previous_policy_hash = FixedBytes::new(cursor.take()?);
    let created_at_ms = cursor.u64()?;
    let owner = parse_principal(cursor.bytes_field()?)?;
    let source_attestation = match cursor.u8()? {
        0 => None,
        1 => Some(parse_source(cursor.bytes_field()?)?),
        _ => return Err(failure("unknown optional source").into()),
    };
    if cursor.u32()? != 0 || cursor.u32()? != 0 {
        return Err(failure("genesis lists are not empty").into());
    }
    cursor.done()?;
    Ok(PolicyGenesisV1 {
        vault_id,
        policy_sequence,
        previous_policy_hash,
        created_at_ms,
        suite: 1,
        owner,
        source_attestation,
        item_inventory: Vec::new(),
        direct_grants: Vec::new(),
        owner_signature: Signature64::new([0; 64]),
    })
}

#[test]
fn every_policy_operation_matches_the_bound_bytes() -> TestResult {
    let corpus = corpus()?;
    let variants = corpus["encodings"]["policy_operations"]["variants"]
        .as_object()
        .ok_or_else(|| failure("operation vectors are not an object"))?;
    assert_eq!(variants.len(), 12);
    for (name, vector) in variants {
        let expected = vector_bytes(vector)?;
        assert_eq!(
            parse_operation(&expected)?.canonical_bytes()?,
            expected,
            "operation {name}"
        );
    }
    Ok(())
}

#[test]
fn genesis_and_reserved_source_preimages_match_the_bound_bytes() -> TestResult {
    let corpus = corpus()?;
    for name in [
        "policy_genesis_signature",
        "policy_genesis_legacy_migration_signature",
        "policy_genesis_rollover_signature",
    ] {
        let expected = vector_bytes(&corpus["preimages"][name])?;
        assert_eq!(parse_genesis(&expected)?.signature_preimage()?, expected);
    }
    for name in ["legacy_migration", "rollover"] {
        let expected = vector_bytes(&corpus["encodings"]["source_attestations"][name])?;
        assert_eq!(parse_source(&expected)?.canonical_bytes()?, expected);
    }

    let signature = vector_bytes(&corpus["preimages"]["policy_genesis_signature"])?;
    let fingerprint = vector_bytes(&corpus["preimages"]["policy_genesis_fingerprint"])?;
    let mut cursor = Cursor::new(jce_fields(
        &fingerprint,
        "jury-v1/policy-genesis/fingerprint",
    )?);
    assert_eq!(cursor.bytes_field()?, signature);
    let owner_signature = Signature64::new(cursor.take()?);
    cursor.done()?;
    let mut genesis = parse_genesis(&signature)?;
    genesis.owner_signature = owner_signature;
    assert_eq!(genesis.fingerprint_preimage()?, fingerprint);
    Ok(())
}

#[test]
fn signed_policy_and_item_history_match_the_bound_bytes() -> TestResult {
    let corpus = corpus()?;
    let signature = vector_bytes(&corpus["preimages"]["policy_revision_signature"])?;
    let mut cursor = Cursor::new(jce_fields(&signature, "jury-v1/policy-revision/signature")?);
    let vault_id = VaultId::from_bytes(cursor.take()?)?;
    let sequence = cursor.u64()?;
    let previous_revision_hash = FixedBytes::new(cursor.take()?);
    let timestamp_ms = cursor.u64()?;
    let author_principal_id = PrincipalId::from_bytes(cursor.take()?)?;
    let operation_count = usize::try_from(cursor.u32()?)?;
    let operations = (0..operation_count)
        .map(|_| parse_operation(cursor.bytes_field()?))
        .collect::<TestResult<Vec<_>>>()?;
    let resulting_policy_state_hash = FixedBytes::new(cursor.take()?);
    cursor.done()?;
    let hash = vector_bytes(&corpus["preimages"]["policy_revision_hash"])?;
    let mut hash_cursor = Cursor::new(jce_fields(&hash, "jury-v1/policy-revision/hash")?);
    assert_eq!(hash_cursor.bytes_field()?, signature);
    let revision_signature = Signature64::new(hash_cursor.take()?);
    hash_cursor.done()?;
    let revision = SignedPolicyRevisionV1 {
        vault_id,
        sequence,
        previous_revision_hash,
        timestamp_ms,
        author_principal_id,
        operations,
        resulting_policy_state_hash,
        signature: revision_signature,
    };
    assert_eq!(revision.signature_preimage()?, signature);
    assert_eq!(revision.hash_preimage()?, hash);

    let item_signature = vector_bytes(&corpus["preimages"]["item_revision_signature"])?;
    let mut item = Cursor::new(jce_fields(
        &item_signature,
        "jury-v1/item-revision/signature",
    )?);
    let mut item_revision = SignedItemRevisionV1 {
        vault_id: VaultId::from_bytes(item.take()?)?,
        item_id: jury_protocol::vault_v1::ItemId::from_bytes(item.take()?)?,
        item_revision: item.u64()?,
        previous_item_revision_hash: FixedBytes::new(item.take()?),
        key_epoch: item.u64()?,
        policy_sequence: item.u64()?,
        author_principal_id: PrincipalId::from_bytes(item.take()?)?,
        timestamp_ms: item.u64()?,
        revision_seal_id: RevisionSealId::from_bytes(item.take()?)?,
        nonce: Nonce12::new(item.take()?),
        ciphertext_length: item.u32()?,
        ciphertext_digest: FixedBytes::new(item.take()?),
        plaintext_schema: item.u8()?,
        bucket_id: item.u8()?,
        signature: Signature64::new([0; 64]),
    };
    item.done()?;
    let item_hash = vector_bytes(&corpus["preimages"]["item_revision_hash"])?;
    let mut item_hash_cursor = Cursor::new(jce_fields(&item_hash, "jury-v1/item-revision/hash")?);
    assert_eq!(item_hash_cursor.bytes_field()?, item_signature);
    item_revision.signature = Signature64::new(item_hash_cursor.take()?);
    item_hash_cursor.done()?;
    assert_eq!(item_revision.signature_preimage(), item_signature);
    assert_eq!(item_revision.hash_preimage()?, item_hash);
    Ok(())
}

#[test]
fn rollover_and_suite_migration_match_the_bound_bytes() -> TestResult {
    let corpus = corpus()?;
    let rollover = vector_bytes(&corpus["preimages"]["rollover_signature"])?;
    assert_eq!(
        parse_rollover(&rollover, Signature64::new([0; 64]))?.signature_preimage(),
        rollover
    );

    let migration = vector_bytes(&corpus["preimages"]["suite_migration_signature"])?;
    let mut cursor = Cursor::new(jce_fields(&migration, "jury-v1/suite-migration/signature")?);
    let statement = SignedSuiteMigrationV1 {
        migration_format: cursor.u16()?,
        migration_id: MigrationId::from_bytes(cursor.take()?)?,
        old_vault_id: VaultId::from_bytes(cursor.take()?)?,
        old_genesis_fingerprint: FixedBytes::new(cursor.take()?),
        old_terminal_revision_hash: FixedBytes::new(cursor.take()?),
        old_suite: cursor.u16()?,
        new_vault_id: VaultId::from_bytes(cursor.take()?)?,
        new_genesis_fingerprint: FixedBytes::new(cursor.take()?),
        new_suite: cursor.u16()?,
        migrated_item_manifest_digest: FixedBytes::new(cursor.take()?),
        signature: Signature64::new([0; 64]),
    };
    cursor.done()?;
    assert_eq!(statement.signature_preimage(), migration);
    Ok(())
}
