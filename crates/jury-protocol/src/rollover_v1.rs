//! Public pre-genesis rollover commitments. Encoding is specified in
//! `docs/security/rollover-v1.md`; shape validation is not source authorization
//! or proof of a complete, registered destination.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::vault_v1::{
    AccessRole, DescriptorMetadataV1, Digest32, FormatError, ItemId, ItemKind, MAX_ITEMS,
    MAX_PUBLIC_LABEL_BYTES, MAX_VAULT_BYTES, PrincipalId, SlotId, VaultId, WitnessPolicyId,
};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BootstrapPrincipalV1 {
    pub principal_id: PrincipalId,
    pub unsigned_descriptor_digest: Digest32,
    pub display_label: String,
    pub owner: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BootstrapGrantV1 {
    pub principal_id: PrincipalId,
    pub role: AccessRole,
    pub direct: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BootstrapWitnessedItemV1 {
    pub policy_id: WitnessPolicyId,
    pub descriptor_slot_id: SlotId,
    pub body_slot_id: SlotId,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BootstrapItemV1 {
    pub source_item_id: ItemId,
    pub destination_item_id: ItemId,
    pub item_kind: ItemKind,
    pub descriptor: DescriptorMetadataV1,
    pub initial_item_revision_hash: Digest32,
    pub direct_slot_set_digest: Digest32,
    pub grants: Vec<BootstrapGrantV1>,
    pub witnessed: Option<BootstrapWitnessedItemV1>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BootstrapWitnessPolicyV1 {
    pub source_policy_id: WitnessPolicyId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_policy_revision: Option<u64>,
    pub destination_policy_id: WitnessPolicyId,
    pub intent_digest: Digest32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BootstrapManifestV1 {
    pub version: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_suite: Option<u16>,
    pub destination_suite: u16,
    pub destination_vault_id: VaultId,
    pub created_at_ms: u64,
    pub acting_owner_principal_id: PrincipalId,
    pub principals: Vec<BootstrapPrincipalV1>,
    pub items: Vec<BootstrapItemV1>,
    pub witness_policies: Vec<BootstrapWitnessPolicyV1>,
}

fn invalid() -> FormatError {
    FormatError::Invalid("rollover bootstrap manifest differs")
}

fn sorted_unique<T, K: Ord>(values: &[T], key: impl Fn(&T) -> K) -> bool {
    values.windows(2).all(|pair| key(&pair[0]) < key(&pair[1]))
}

fn count(output: &mut Vec<u8>, length: usize) -> Result<(), FormatError> {
    let length = u32::try_from(length).map_err(|_| invalid())?;
    output.extend_from_slice(&length.to_be_bytes());
    Ok(())
}

fn record(output: &mut Vec<u8>, bytes: &[u8]) -> Result<(), FormatError> {
    if output.len().saturating_add(4).saturating_add(bytes.len()) > MAX_VAULT_BYTES {
        return Err(FormatError::ArtifactTooLarge);
    }
    count(output, bytes.len())?;
    output.extend_from_slice(bytes);
    Ok(())
}

impl BootstrapManifestV1 {
    pub fn validate_shape(&self) -> Result<(), FormatError> {
        if !matches!(
            (self.version, self.source_suite, self.destination_suite),
            (1, None, 1) | (2, Some(1), 1 | 2) | (2, Some(2), 2)
        ) || self.principals.is_empty()
            || self.principals.len() > MAX_VAULT_BYTES / 66
            || self.items.len() > MAX_ITEMS
            || self.witness_policies.len() > self.items.len()
            || !sorted_unique(&self.principals, |entry| entry.principal_id)
            || !sorted_unique(&self.items, |entry| entry.source_item_id)
            || !sorted_unique(&self.witness_policies, |entry| {
                (entry.source_policy_id, entry.source_policy_revision)
            })
            || self
                .witness_policies
                .iter()
                .any(|entry| match self.version {
                    1 => entry.source_policy_revision.is_some(),
                    2 => !entry
                        .source_policy_revision
                        .is_some_and(|revision| revision > 0),
                    _ => true,
                })
        {
            return Err(invalid());
        }
        let principals = self
            .principals
            .iter()
            .map(|entry| (entry.principal_id, entry))
            .collect::<BTreeMap<_, _>>();
        if !principals
            .get(&self.acting_owner_principal_id)
            .is_some_and(|entry| entry.owner)
            || self.principals.iter().any(|entry| {
                entry.display_label.is_empty() || entry.display_label.len() > MAX_PUBLIC_LABEL_BYTES
            })
        {
            return Err(invalid());
        }
        let old_items = self
            .items
            .iter()
            .map(|entry| entry.source_item_id)
            .collect::<BTreeSet<_>>();
        let old_policies = self
            .witness_policies
            .iter()
            .map(|entry| entry.source_policy_id)
            .collect::<BTreeSet<_>>();
        let new_policies = self
            .witness_policies
            .iter()
            .map(|entry| entry.destination_policy_id)
            .collect::<BTreeSet<_>>();
        if new_policies.len() != self.witness_policies.len()
            || !new_policies.is_disjoint(&old_policies)
        {
            return Err(invalid());
        }
        let mut new_items = BTreeSet::new();
        let mut slots = BTreeSet::new();
        let mut used_policies = BTreeSet::new();
        let owner_count = self.principals.iter().filter(|entry| entry.owner).count();
        for item in &self.items {
            if old_items.contains(&item.destination_item_id)
                || !new_items.insert(item.destination_item_id)
                || item.descriptor.revision != 1
                || item.descriptor.key_epoch != 1
                || item.descriptor.plaintext_schema != 1
                || item.descriptor.ciphertext_length != 272
                || item.grants.len() > principals.len()
                || !sorted_unique(&item.grants, |entry| entry.principal_id)
            {
                return Err(invalid());
            }
            let mut owners = BTreeSet::new();
            for grant in &item.grants {
                let principal = principals.get(&grant.principal_id).ok_or_else(invalid)?;
                if principal.owner != (grant.role == AccessRole::Owner)
                    || (!grant.direct && item.witnessed.is_none())
                    || (item.item_kind == ItemKind::Legacy && !principal.owner)
                {
                    return Err(invalid());
                }
                if principal.owner {
                    owners.insert(principal.principal_id);
                }
            }
            if owners.len() != owner_count {
                return Err(invalid());
            }
            if let Some(witnessed) = &item.witnessed {
                if !new_policies.contains(&witnessed.policy_id)
                    || !slots.insert(witnessed.descriptor_slot_id)
                    || !slots.insert(witnessed.body_slot_id)
                {
                    return Err(invalid());
                }
                used_policies.insert(witnessed.policy_id);
            }
        }
        if used_policies != new_policies {
            return Err(invalid());
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, FormatError> {
        self.validate_shape()?;
        let mut output = b"jury-v1/rollover/bootstrap\0\0\x01".to_vec();
        output.extend_from_slice(&self.version.to_be_bytes());
        if let Some(source_suite) = self.source_suite {
            output.extend_from_slice(&source_suite.to_be_bytes());
        }
        output.extend_from_slice(&self.destination_suite.to_be_bytes());
        output.extend_from_slice(self.destination_vault_id.as_bytes());
        output.extend_from_slice(&self.created_at_ms.to_be_bytes());
        output.extend_from_slice(self.acting_owner_principal_id.as_bytes());
        count(&mut output, self.principals.len())?;
        for principal in &self.principals {
            let mut entry = principal.principal_id.as_bytes().to_vec();
            entry.extend_from_slice(principal.unsigned_descriptor_digest.as_bytes());
            record(&mut entry, principal.display_label.as_bytes())?;
            entry.push(u8::from(principal.owner));
            record(&mut output, &entry)?;
        }
        count(&mut output, self.items.len())?;
        for item in &self.items {
            let mut entry = item.source_item_id.as_bytes().to_vec();
            entry.extend_from_slice(item.destination_item_id.as_bytes());
            entry.push(item.item_kind.tag());
            record(&mut entry, &item.descriptor.canonical_bytes())?;
            entry.extend_from_slice(item.initial_item_revision_hash.as_bytes());
            entry.extend_from_slice(item.direct_slot_set_digest.as_bytes());
            count(&mut entry, item.grants.len())?;
            for grant in &item.grants {
                let mut encoded = grant.principal_id.as_bytes().to_vec();
                encoded.push(grant.role.tag());
                encoded.push(u8::from(grant.direct));
                record(&mut entry, &encoded)?;
            }
            if let Some(witnessed) = &item.witnessed {
                entry.push(1);
                entry.extend_from_slice(witnessed.policy_id.as_bytes());
                entry.extend_from_slice(witnessed.descriptor_slot_id.as_bytes());
                entry.extend_from_slice(witnessed.body_slot_id.as_bytes());
            } else {
                entry.push(0);
            }
            record(&mut output, &entry)?;
        }
        count(&mut output, self.witness_policies.len())?;
        for policy in &self.witness_policies {
            let mut entry = policy.source_policy_id.as_bytes().to_vec();
            if let Some(revision) = policy.source_policy_revision {
                entry.extend_from_slice(&revision.to_be_bytes());
            }
            entry.extend_from_slice(policy.destination_policy_id.as_bytes());
            entry.extend_from_slice(policy.intent_digest.as_bytes());
            record(&mut output, &entry)?;
        }
        if output.len() > MAX_VAULT_BYTES {
            return Err(FormatError::ArtifactTooLarge);
        }
        Ok(output)
    }

    pub fn digest(&self) -> Result<Digest32, FormatError> {
        Ok(Digest32::new(
            Sha256::digest(self.canonical_bytes()?).into(),
        ))
    }
}
