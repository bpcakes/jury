use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::Deserialize;
use sha2::{Digest as _, Sha256};

use super::bytes::{Digest32, FixedBytes, ItemId, Nonce12, RevisionSealId, SlotId};
use super::preimage::CanonicalError;
use super::types::{
    ContentRole, DirectSlotV1, ItemAccessMode, ItemEnvelopeV1, PolicyOperationV1,
    SignedItemRevisionV1, SourceAttestationV1, VaultFileV1, WitnessShareCapsuleV1, WitnessedSlotV1,
    WitnessedStateV1,
};

pub const MAX_VAULT_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_ITEMS: usize = 1_024;
pub const MAX_POLICY_REVISIONS: usize = 4_096;
pub const MAX_ITEM_REVISION_PROOFS: usize = 65_536;
pub const MAX_CURRENT_SLOTS: usize = 16_384;
pub const MAX_PUBLIC_LABEL_BYTES: usize = 256;

const SUITE: u16 = 1;
const DESCRIPTOR_CIPHERTEXT_BYTES: u32 = 272;
const ZERO_DIGEST: [u8; 32] = [0; 32];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FormatError {
    ArtifactTooLarge,
    ConflictMarker,
    InvalidJson,
    NonCanonicalJson,
    CapacityExhausted(&'static str),
    Invalid(&'static str),
    CanonicalEncoding,
}

impl fmt::Display for FormatError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ArtifactTooLarge => formatter.write_str("vault artifact exceeds 16 MiB"),
            Self::ConflictMarker => {
                formatter.write_str("vault artifact contains a conflict marker")
            }
            Self::InvalidJson => formatter.write_str("invalid vault JSON"),
            Self::NonCanonicalJson => formatter.write_str("vault JSON is not canonical"),
            Self::CapacityExhausted(dimension) => {
                write!(formatter, "vault capacity exhausted: {dimension}")
            }
            Self::Invalid(reason) => write!(formatter, "invalid vault format: {reason}"),
            Self::CanonicalEncoding => formatter.write_str("invalid canonical binary encoding"),
        }
    }
}

impl std::error::Error for FormatError {}

impl From<CanonicalError> for FormatError {
    fn from(_: CanonicalError) -> Self {
        Self::CanonicalEncoding
    }
}

#[derive(Deserialize)]
struct HeaderProbe {
    header: HeaderProbeFields,
}

#[derive(Deserialize)]
struct HeaderProbeFields {
    magic: String,
    version: u16,
    suite: u16,
    policy_schema: u16,
    item_schema: u16,
    identity_schema: u16,
}

impl VaultFileV1 {
    pub fn parse(bytes: &[u8]) -> Result<Self, FormatError> {
        if bytes.len() > MAX_VAULT_BYTES {
            return Err(FormatError::ArtifactTooLarge);
        }
        if contains_conflict_marker(bytes) {
            return Err(FormatError::ConflictMarker);
        }
        let probe: HeaderProbe =
            serde_json::from_slice(bytes).map_err(|_| FormatError::InvalidJson)?;
        validate_header_discriminants(&probe.header)?;
        let vault: Self = serde_json::from_slice(bytes).map_err(|_| FormatError::InvalidJson)?;
        vault.validate()?;
        let canonical = vault.to_json_bytes()?;
        if canonical != bytes {
            return Err(FormatError::NonCanonicalJson);
        }
        Ok(vault)
    }

    pub fn to_json_bytes(&self) -> Result<Vec<u8>, FormatError> {
        self.validate()?;
        let mut bytes = serde_json::to_vec_pretty(self).map_err(|_| FormatError::InvalidJson)?;
        bytes.push(b'\n');
        if bytes.len() > MAX_VAULT_BYTES {
            return Err(FormatError::ArtifactTooLarge);
        }
        Ok(bytes)
    }

    pub fn validate(&self) -> Result<(), FormatError> {
        validate_header(self)?;
        validate_policy(self)?;
        validate_items(self)?;
        validate_migration(self)?;
        validate_slot_inventory(self)?;
        Ok(())
    }
}

fn contains_conflict_marker(bytes: &[u8]) -> bool {
    bytes.split(|byte| *byte == b'\n').any(|line| {
        line.starts_with(b"<<<<<<<") || line.starts_with(b"=======") || line.starts_with(b">>>>>>>")
    })
}

fn validate_header_discriminants(header: &HeaderProbeFields) -> Result<(), FormatError> {
    if header.magic != "jury-vault" {
        return Err(FormatError::Invalid("unknown magic"));
    }
    if header.version != 1
        || header.suite != SUITE
        || header.policy_schema != 1
        || header.item_schema != 1
        || header.identity_schema != 1
    {
        return Err(FormatError::Invalid("unknown version or suite"));
    }
    Ok(())
}

fn validate_header(vault: &VaultFileV1) -> Result<(), FormatError> {
    validate_header_discriminants(&HeaderProbeFields {
        magic: vault.header.magic.clone(),
        version: vault.header.version,
        suite: vault.header.suite,
        policy_schema: vault.header.policy_schema,
        item_schema: vault.header.item_schema,
        identity_schema: vault.header.identity_schema,
    })?;
    if vault.header.vault_id != vault.policy.genesis.vault_id {
        return Err(FormatError::Invalid("header and genesis vault differ"));
    }
    if vault.header.created_at_ms != vault.policy.genesis.created_at_ms {
        return Err(FormatError::Invalid("header and genesis time differ"));
    }
    if vault.policy.genesis.suite != SUITE {
        return Err(FormatError::Invalid("genesis suite differs"));
    }
    if vault.policy.genesis.recomputed_fingerprint()? != vault.header.genesis_fingerprint {
        return Err(FormatError::Invalid("genesis fingerprint differs"));
    }
    Ok(())
}

fn validate_policy(vault: &VaultFileV1) -> Result<(), FormatError> {
    let genesis = &vault.policy.genesis;
    if genesis.policy_sequence != 0 || genesis.previous_policy_hash.as_bytes() != &ZERO_DIGEST {
        return Err(FormatError::Invalid("genesis sequence is not zero"));
    }
    if genesis.owner.descriptor_version != 1
        || genesis.owner.principal_kind != super::types::PrincipalKind::Human
    {
        return Err(FormatError::Invalid("genesis owner is not one v1 human"));
    }
    if !genesis.item_inventory.is_empty() || !genesis.direct_grants.is_empty() {
        return Err(FormatError::Invalid("genesis state is not empty"));
    }
    validate_source_attestation(vault)?;
    if vault.policy.revisions.len() > MAX_POLICY_REVISIONS {
        return Err(FormatError::CapacityExhausted("policy revisions"));
    }

    let mut previous_hash = vault.header.genesis_fingerprint.clone();
    for (index, revision) in vault.policy.revisions.iter().enumerate() {
        let expected_sequence = u64::try_from(index)
            .map_err(|_| FormatError::CapacityExhausted("policy revisions"))?
            + 1;
        if revision.vault_id != vault.header.vault_id
            || revision.sequence != expected_sequence
            || revision.previous_revision_hash != previous_hash
        {
            return Err(FormatError::Invalid("policy ancestry differs"));
        }
        if revision.operations.is_empty() {
            return Err(FormatError::Invalid("policy revision has no operation"));
        }
        for operation in &revision.operations {
            validate_operation(
                operation,
                revision.sequence,
                &vault.header.vault_id,
                &vault.header.genesis_fingerprint,
            )?;
        }
        previous_hash = revision.recomputed_hash()?;
    }
    Ok(())
}

fn validate_source_attestation(vault: &VaultFileV1) -> Result<(), FormatError> {
    let Some(attestation) = &vault.policy.genesis.source_attestation else {
        return Ok(());
    };
    match attestation {
        SourceAttestationV1::LegacyMigration { source_format, .. } => {
            if !matches!(source_format, 1 | 2) {
                return Err(FormatError::Invalid("legacy source version differs"));
            }
        }
        SourceAttestationV1::Rollover { statement } => {
            if statement.rollover_format != 1
                || statement.destination_vault_id != vault.header.vault_id
                || statement.destination_suite != vault.header.suite
                || statement.source_vault_id == statement.destination_vault_id
                || statement.source_genesis_fingerprint == vault.header.genesis_fingerprint
            {
                return Err(FormatError::Invalid(
                    "rollover does not create one new lineage",
                ));
            }
        }
    }
    Ok(())
}

fn validate_operation(
    operation: &PolicyOperationV1,
    sequence: u64,
    vault_id: &super::bytes::VaultId,
    genesis_fingerprint: &Digest32,
) -> Result<(), FormatError> {
    match operation {
        PolicyOperationV1::PrincipalAdd {
            descriptor,
            display_label,
            ..
        } => {
            validate_descriptor(descriptor)?;
            validate_label(display_label)?;
        }
        PolicyOperationV1::PrincipalLabelChange {
            prior_label,
            next_label,
            ..
        } => {
            validate_label(prior_label)?;
            validate_label(next_label)?;
        }
        PolicyOperationV1::ItemCreate {
            item_id,
            key_epoch,
            descriptor,
            direct_slots,
            witnessed_state,
            ..
        } => {
            if *key_epoch != 1 {
                return Err(FormatError::Invalid("item creation epoch is not one"));
            }
            validate_descriptor_metadata(descriptor)?;
            validate_access_paths(
                direct_slots,
                witnessed_state.as_ref(),
                vault_id,
                genesis_fingerprint,
                item_id,
                *key_epoch,
                sequence,
            )?;
        }
        PolicyOperationV1::ItemRename {
            prior_descriptor_revision,
            next_descriptor,
            ..
        } => {
            if *prior_descriptor_revision == 0
                || next_descriptor.revision != prior_descriptor_revision.saturating_add(1)
            {
                return Err(FormatError::Invalid("descriptor revision does not advance"));
            }
            validate_descriptor_metadata(next_descriptor)?;
        }
        PolicyOperationV1::ItemDelete {
            deletion_policy_sequence,
            ..
        } => {
            if *deletion_policy_sequence != sequence {
                return Err(FormatError::Invalid("deletion sequence differs"));
            }
        }
        PolicyOperationV1::ItemRoleChange {
            prior_role,
            next_role,
            ..
        } => {
            if prior_role == next_role {
                return Err(FormatError::Invalid("item role does not change"));
            }
        }
        PolicyOperationV1::ItemReaderSetChange {
            prior_epoch,
            next_epoch,
            prior_reader_ids,
            next_reader_ids,
            replacement_descriptor,
            ..
        } => {
            if *prior_epoch == 0 || next_epoch != &prior_epoch.saturating_add(1) {
                return Err(FormatError::Invalid("reader-set epoch does not advance"));
            }
            validate_sorted_unique(prior_reader_ids, "prior readers are not canonical")?;
            validate_sorted_unique(next_reader_ids, "next readers are not canonical")?;
            if prior_reader_ids == next_reader_ids
                || replacement_descriptor.key_epoch != *next_epoch
            {
                return Err(FormatError::Invalid("reader set does not rotate"));
            }
            validate_descriptor_metadata(replacement_descriptor)?;
        }
        PolicyOperationV1::ItemSlotsReplace {
            item_id,
            next_epoch,
            direct_slots,
            witnessed_state,
        } => {
            if *next_epoch == 0 {
                return Err(FormatError::Invalid("slot epoch is zero"));
            }
            validate_access_paths(
                direct_slots,
                witnessed_state.as_ref(),
                vault_id,
                genesis_fingerprint,
                item_id,
                *next_epoch,
                sequence,
            )?;
        }
        PolicyOperationV1::PrincipalReplace {
            prior_principal_id,
            next_descriptor,
            ..
        } => {
            validate_descriptor(next_descriptor)?;
            if *prior_principal_id == next_descriptor.principal_id {
                return Err(FormatError::Invalid("replacement reuses principal ID"));
            }
        }
        PolicyOperationV1::PrincipalRemove { .. }
        | PolicyOperationV1::OwnerGrant { .. }
        | PolicyOperationV1::OwnerRevoke { .. } => {}
    }
    Ok(())
}

fn validate_descriptor(
    descriptor: &super::types::PrincipalDescriptorV1,
) -> Result<(), FormatError> {
    if descriptor.descriptor_version != 1 || descriptor.canonical_bytes().len() != 1_347 {
        return Err(FormatError::Invalid("principal descriptor version differs"));
    }
    Ok(())
}

fn validate_label(label: &str) -> Result<(), FormatError> {
    if label.is_empty() || label.len() > MAX_PUBLIC_LABEL_BYTES {
        return Err(FormatError::Invalid("public label length is invalid"));
    }
    Ok(())
}

fn validate_descriptor_metadata(
    descriptor: &super::types::DescriptorMetadataV1,
) -> Result<(), FormatError> {
    if descriptor.revision == 0
        || descriptor.key_epoch == 0
        || descriptor.plaintext_schema != 1
        || descriptor.ciphertext_length != DESCRIPTOR_CIPHERTEXT_BYTES
        || descriptor.canonical_bytes().len() != 97
    {
        return Err(FormatError::Invalid("descriptor metadata differs"));
    }
    Ok(())
}

fn validate_access_paths(
    direct_slots: &[DirectSlotV1],
    witnessed_state: Option<&WitnessedStateV1>,
    vault_id: &super::bytes::VaultId,
    genesis_fingerprint: &Digest32,
    item_id: &ItemId,
    key_epoch: u64,
    policy_sequence: u64,
) -> Result<(), FormatError> {
    if direct_slots.is_empty() && witnessed_state.is_none() {
        return Err(FormatError::Invalid("item has no access path"));
    }
    let expected_mode = match (direct_slots.is_empty(), witnessed_state.is_none()) {
        (false, false) => ItemAccessMode::Mixed,
        (false, true) => ItemAccessMode::DirectOnly,
        (true, false) => ItemAccessMode::WitnessedOnly,
        (true, true) => return Err(FormatError::Invalid("item has no access path")),
    };
    validate_direct_slots(
        direct_slots,
        vault_id,
        item_id,
        key_epoch,
        policy_sequence,
        expected_mode,
    )?;
    if let Some(state) = witnessed_state {
        validate_witnessed_state(
            state,
            vault_id,
            genesis_fingerprint,
            item_id,
            key_epoch,
            policy_sequence,
            expected_mode,
        )?;
    }
    Ok(())
}

fn validate_direct_slots(
    slots: &[DirectSlotV1],
    vault_id: &super::bytes::VaultId,
    item_id: &ItemId,
    key_epoch: u64,
    policy_sequence: u64,
    access_mode: ItemAccessMode,
) -> Result<(), FormatError> {
    let mut last_key = None;
    let mut recipient_roles = BTreeMap::new();
    let mut recipient_content = BTreeSet::new();
    let mut content_scopes = BTreeMap::new();
    let mut encapsulations = BTreeSet::new();
    for slot in slots {
        if slot.slot_schema != 1
            || slot.slot_algorithm != 1
            || slot.suite != SUITE
            || slot.kem != 0x647a
            || slot.kdf != 1
            || slot.aead != 3
            || slot.vault_id != *vault_id
            || slot.item_id != *item_id
            || slot.key_epoch != key_epoch
            || slot.policy_sequence != policy_sequence
            || slot.item_access_mode != access_mode
            || slot.revision == 0
            || slot.canonical_bytes().len() != 1_365
        {
            return Err(FormatError::Invalid("direct slot context differs"));
        }
        if !encapsulations.insert(slot.encapsulation.clone()) {
            return Err(FormatError::Invalid("direct encapsulation is reused"));
        }
        let key = (
            slot.content_role,
            slot.recipient_principal_id,
            slot.canonical_bytes(),
        );
        if last_key.as_ref().is_some_and(|last| last >= &key) {
            return Err(FormatError::Invalid("direct slots are not canonical"));
        }
        last_key = Some(key);
        if !recipient_content.insert((slot.recipient_principal_id, slot.content_role)) {
            return Err(FormatError::Invalid("direct recipient slot is duplicated"));
        }
        if let Some(role) = recipient_roles.insert(slot.recipient_principal_id, slot.access_role)
            && role != slot.access_role
        {
            return Err(FormatError::Invalid("direct recipient role differs"));
        }
        let scope = (slot.revision, slot.revision_seal_id);
        if let Some(existing) = content_scopes.insert(slot.content_role, scope)
            && existing != scope
        {
            return Err(FormatError::Invalid("direct content seal differs"));
        }
    }
    for recipient in recipient_roles.keys() {
        if !recipient_content.contains(&(*recipient, ContentRole::Descriptor))
            || !recipient_content.contains(&(*recipient, ContentRole::Body))
        {
            return Err(FormatError::Invalid(
                "direct recipient lacks one content role",
            ));
        }
    }
    Ok(())
}

fn validate_witnessed_state(
    state: &WitnessedStateV1,
    vault_id: &super::bytes::VaultId,
    genesis_fingerprint: &Digest32,
    item_id: &ItemId,
    key_epoch: u64,
    policy_sequence: u64,
    access_mode: ItemAccessMode,
) -> Result<(), FormatError> {
    if state.slots.len() != 2 {
        return Err(FormatError::Invalid("witnessed slot count is invalid"));
    }
    let mut last_key = None;
    let mut roles = BTreeSet::new();
    let mut encapsulations = BTreeSet::new();
    for slot in &state.slots {
        validate_witnessed_slot(
            slot,
            vault_id,
            genesis_fingerprint,
            item_id,
            key_epoch,
            policy_sequence,
            access_mode,
        )?;
        for capsule in &slot.capsules {
            if !encapsulations.insert(capsule.encapsulation.clone()) {
                return Err(FormatError::Invalid("witness encapsulation is reused"));
            }
        }
        if !roles.insert(slot.content_role) {
            return Err(FormatError::Invalid("witnessed content role is duplicated"));
        }
        let key = (
            slot.content_role,
            slot.revision,
            *slot.revision_seal_id.as_bytes(),
            *slot.slot_id.as_bytes(),
        );
        if last_key.as_ref().is_some_and(|last| last >= &key) {
            return Err(FormatError::Invalid("witnessed slots are not canonical"));
        }
        last_key = Some(key);
    }
    if state.recomputed_digest()? != state.digest {
        return Err(FormatError::Invalid("witnessed state digest differs"));
    }
    Ok(())
}

fn validate_witnessed_slot(
    slot: &WitnessedSlotV1,
    vault_id: &super::bytes::VaultId,
    genesis_fingerprint: &Digest32,
    item_id: &ItemId,
    key_epoch: u64,
    policy_sequence: u64,
    access_mode: ItemAccessMode,
) -> Result<(), FormatError> {
    if slot.slot_schema != 1
        || slot.slot_algorithm != 2
        || slot.suite != SUITE
        || slot.protocol != 1
        || slot.construction != 1
        || slot.vault_id != *vault_id
        || slot.genesis_fingerprint != *genesis_fingerprint
        || slot.item_id != *item_id
        || slot.key_epoch != key_epoch
        || slot.vault_policy_sequence != policy_sequence
        || slot.item_access_mode != access_mode
        || slot.revision == 0
        || !(2..=32).contains(&slot.member_count)
        || !(2..=slot.member_count).contains(&slot.threshold)
        || usize::from(slot.member_count) != slot.capsules.len()
    {
        return Err(FormatError::Invalid("witnessed slot context differs"));
    }
    let mut last_index = 0;
    let mut witnesses = BTreeSet::new();
    let mut contribution_keys = BTreeSet::new();
    for capsule in &slot.capsules {
        validate_capsule(capsule, slot)?;
        if capsule.share_index <= last_index
            || !witnesses.insert(capsule.witness_id)
            || !contribution_keys.insert(capsule.contribution_key_fingerprint.clone())
        {
            return Err(FormatError::Invalid("witness capsules are not canonical"));
        }
        last_index = capsule.share_index;
    }
    if slot.recomputed_capsule_set_digest()? != slot.capsule_set_digest {
        return Err(FormatError::Invalid("capsule-set digest differs"));
    }
    Ok(())
}

fn validate_capsule(
    capsule: &WitnessShareCapsuleV1,
    slot: &WitnessedSlotV1,
) -> Result<(), FormatError> {
    if capsule.capsule_schema != 1
        || capsule.protocol != slot.protocol
        || capsule.construction != slot.construction
        || capsule.vault_id != slot.vault_id
        || capsule.genesis_fingerprint != slot.genesis_fingerprint
        || capsule.item_id != slot.item_id
        || capsule.key_epoch != slot.key_epoch
        || capsule.item_access_mode != slot.item_access_mode
        || capsule.slot_id != slot.slot_id
        || capsule.content_role != slot.content_role
        || capsule.revision != slot.revision
        || capsule.revision_seal_id != slot.revision_seal_id
        || capsule.vault_policy_sequence != slot.vault_policy_sequence
        || capsule.witness_policy_id != slot.witness_policy_id
        || capsule.witness_policy_revision != slot.witness_policy_revision
        || capsule.witness_policy_digest != slot.witness_policy_digest
        || capsule.threshold != slot.threshold
        || capsule.member_count != slot.member_count
        || capsule.share_index == 0
        || capsule.share_index > slot.member_count
        || capsule.recomputed_context_digest() != capsule.context_digest
    {
        return Err(FormatError::Invalid("witness capsule context differs"));
    }
    Ok(())
}

fn validate_items(vault: &VaultFileV1) -> Result<(), FormatError> {
    if vault.items.len() > MAX_ITEMS {
        return Err(FormatError::CapacityExhausted("items"));
    }
    let mut prior_item = None;
    let mut proof_count = 0_usize;
    let mut seal_scopes: BTreeMap<RevisionSealId, (ItemId, ContentRole, u64)> = BTreeMap::new();
    let mut nonces: BTreeSet<Nonce12> = BTreeSet::new();
    for item in &vault.items {
        if prior_item
            .as_ref()
            .is_some_and(|prior| prior >= &item.item_id)
        {
            return Err(FormatError::Invalid("items are not canonical"));
        }
        prior_item = Some(item.item_id);
        validate_item(vault, item, &mut seal_scopes, &mut nonces)?;
        proof_count = proof_count
            .checked_add(item.prior_revisions.len())
            .ok_or(FormatError::CapacityExhausted("item revision proofs"))?;
    }
    if proof_count > MAX_ITEM_REVISION_PROOFS {
        return Err(FormatError::CapacityExhausted("item revision proofs"));
    }
    Ok(())
}

fn validate_item(
    vault: &VaultFileV1,
    item: &ItemEnvelopeV1,
    seal_scopes: &mut BTreeMap<RevisionSealId, (ItemId, ContentRole, u64)>,
    nonces: &mut BTreeSet<Nonce12>,
) -> Result<(), FormatError> {
    validate_descriptor_metadata(&item.descriptor)?;
    if item.descriptor.key_epoch != item.current_revision.key_epoch {
        return Err(FormatError::Invalid(
            "descriptor and body key epochs differ",
        ));
    }
    if sha256(item.descriptor_ciphertext.as_bytes()) != item.descriptor.ciphertext_digest {
        return Err(FormatError::Invalid("descriptor ciphertext digest differs"));
    }
    insert_seal(
        seal_scopes,
        item.descriptor.revision_seal_id,
        item.item_id,
        ContentRole::Descriptor,
        item.descriptor.revision,
    )?;
    if !nonces.insert(item.descriptor.nonce.clone()) {
        return Err(FormatError::Invalid("nonce is reused"));
    }

    let final_policy_sequence = u64::try_from(vault.policy.revisions.len())
        .map_err(|_| FormatError::CapacityExhausted("policy revisions"))?;
    let mut previous_hash = FixedBytes::new(ZERO_DIGEST);
    for (index, revision) in item
        .prior_revisions
        .iter()
        .chain(std::iter::once(&item.current_revision))
        .enumerate()
    {
        let expected_revision = u64::try_from(index)
            .map_err(|_| FormatError::CapacityExhausted("item revision proofs"))?
            + 1;
        validate_item_revision(
            revision,
            &vault.header.vault_id,
            &item.item_id,
            expected_revision,
            &previous_hash,
            final_policy_sequence,
        )?;
        insert_seal(
            seal_scopes,
            revision.revision_seal_id,
            item.item_id,
            ContentRole::Body,
            revision.item_revision,
        )?;
        if !nonces.insert(revision.nonce.clone()) {
            return Err(FormatError::Invalid("nonce is reused"));
        }
        previous_hash = revision.recomputed_hash()?;
    }
    let current = &item.current_revision;
    if current.ciphertext_length as usize != item.body_ciphertext.len()
        || sha256(item.body_ciphertext.as_bytes()) != current.ciphertext_digest
        || current.ciphertext_length != bucket_ciphertext_length(current.bucket_id)?
    {
        return Err(FormatError::Invalid("body ciphertext metadata differs"));
    }
    Ok(())
}

fn validate_item_revision(
    revision: &SignedItemRevisionV1,
    vault_id: &super::bytes::VaultId,
    item_id: &ItemId,
    expected_revision: u64,
    previous_hash: &Digest32,
    final_policy_sequence: u64,
) -> Result<(), FormatError> {
    if revision.vault_id != *vault_id
        || revision.item_id != *item_id
        || revision.item_revision != expected_revision
        || revision.previous_item_revision_hash != *previous_hash
        || revision.key_epoch == 0
        || revision.policy_sequence > final_policy_sequence
        || revision.plaintext_schema != 1
    {
        return Err(FormatError::Invalid("item revision ancestry differs"));
    }
    bucket_ciphertext_length(revision.bucket_id)?;
    Ok(())
}

fn bucket_ciphertext_length(bucket_id: u8) -> Result<u32, FormatError> {
    let shift = match bucket_id {
        1..=12 => u32::from(bucket_id - 1),
        _ => return Err(FormatError::Invalid("unknown item bucket")),
    };
    4_096_u32
        .checked_shl(shift)
        .and_then(|length| length.checked_add(16))
        .ok_or(FormatError::Invalid("item bucket overflows"))
}

fn insert_seal(
    seals: &mut BTreeMap<RevisionSealId, (ItemId, ContentRole, u64)>,
    seal: RevisionSealId,
    item: ItemId,
    role: ContentRole,
    revision: u64,
) -> Result<(), FormatError> {
    if seals.insert(seal, (item, role, revision)).is_some() {
        return Err(FormatError::Invalid("revision seal is reused"));
    }
    Ok(())
}

fn validate_slot_inventory(vault: &VaultFileV1) -> Result<(), FormatError> {
    let mut witnessed_slot_ids: BTreeMap<SlotId, (ItemId, ContentRole, u64, RevisionSealId)> =
        BTreeMap::new();
    let mut seal_scopes: BTreeMap<RevisionSealId, (ItemId, ContentRole, u64)> = BTreeMap::new();
    for revision in &vault.policy.revisions {
        for operation in &revision.operations {
            let (direct, witnessed) = match operation {
                PolicyOperationV1::ItemCreate {
                    direct_slots,
                    witnessed_state,
                    ..
                }
                | PolicyOperationV1::ItemSlotsReplace {
                    direct_slots,
                    witnessed_state,
                    ..
                } => (direct_slots.as_slice(), witnessed_state.as_ref()),
                _ => continue,
            };
            let operation_slot_count = direct
                .len()
                .checked_add(witnessed.map_or(0, |state| state.slots.len()))
                .ok_or(FormatError::CapacityExhausted("current key slots"))?;
            if operation_slot_count > MAX_CURRENT_SLOTS {
                return Err(FormatError::CapacityExhausted("current key slots"));
            }
            for slot in direct {
                register_scope(
                    &mut seal_scopes,
                    slot.revision_seal_id,
                    slot.item_id,
                    slot.content_role,
                    slot.revision,
                )?;
            }
            if let Some(state) = witnessed {
                for slot in &state.slots {
                    register_scope(
                        &mut seal_scopes,
                        slot.revision_seal_id,
                        slot.item_id,
                        slot.content_role,
                        slot.revision,
                    )?;
                    let scope = (
                        slot.item_id,
                        slot.content_role,
                        slot.revision,
                        slot.revision_seal_id,
                    );
                    if witnessed_slot_ids.insert(slot.slot_id, scope).is_some() {
                        return Err(FormatError::Invalid("witnessed slot ID is reused"));
                    }
                }
            }
        }
    }
    Ok(())
}

fn register_scope(
    scopes: &mut BTreeMap<RevisionSealId, (ItemId, ContentRole, u64)>,
    seal: RevisionSealId,
    item: ItemId,
    role: ContentRole,
    revision: u64,
) -> Result<(), FormatError> {
    let scope = (item, role, revision);
    if let Some(existing) = scopes.get(&seal) {
        if existing != &scope {
            return Err(FormatError::Invalid("slot seal scope differs"));
        }
    } else {
        scopes.insert(seal, scope);
    }
    Ok(())
}

fn validate_migration(vault: &VaultFileV1) -> Result<(), FormatError> {
    let Some(migration) = &vault.suite_migration else {
        return Ok(());
    };
    if migration.migration_format != 1
        || migration.new_vault_id != vault.header.vault_id
        || migration.new_genesis_fingerprint != vault.header.genesis_fingerprint
        || migration.new_suite != vault.header.suite
        || migration.old_vault_id == migration.new_vault_id
        || migration.old_genesis_fingerprint == migration.new_genesis_fingerprint
        || migration.old_suite == migration.new_suite
    {
        return Err(FormatError::Invalid(
            "suite migration does not create one new lineage",
        ));
    }
    Ok(())
}

fn validate_sorted_unique<T: Ord>(values: &[T], reason: &'static str) -> Result<(), FormatError> {
    if values.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(FormatError::Invalid(reason));
    }
    Ok(())
}

fn sha256(bytes: &[u8]) -> Digest32 {
    FixedBytes::new(Sha256::digest(bytes).into())
}
