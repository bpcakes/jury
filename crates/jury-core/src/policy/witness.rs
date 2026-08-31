use std::collections::{BTreeMap, BTreeSet};

use jury_protocol::vault_v1::{
    Digest32, FieldId, FixedBytes, ItemId, PrincipalId, RecipientPublicKey1216, Signature64,
    VaultId, VerificationPublicKey32, WitnessPolicyId, recipient_public_key_fingerprint,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::crypto;

use super::{PolicyError, PolicyErrorKind, PolicyState, replay::replay_policy_with_catalog};

const SUITE: u16 = 1;
const MAX_POLICY_MEMBERS: usize = 32;
const MAX_OPERATIONS: usize = 9;
const MAX_AUTOMATIC_TARGETS: usize = 64;
const MAX_REQUEST_LIFETIME_MS: u64 = 900_000;
const ZERO_DIGEST: [u8; 32] = [0; 32];

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum DescriptorStatus {
    Active,
    Revoked,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ApprovalMode {
    Human,
    Automatic,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum WitnessOperation {
    ReadStdout,
    WritePrivateFile,
    TemplateInjection,
    ChildEnvironment,
    ChildStdin,
    ItemMutation,
    Backup,
    Recovery,
    AdministrativeRekey,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum PlatformAssurance {
    NormalizedPathOnly,
    StableExecutableIdentity,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct AutomaticReadTarget {
    pub item_id: ItemId,
    pub field_id: Option<FieldId>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApproverPolicyDescriptor {
    pub schema: u16,
    pub approver_id: PrincipalId,
    pub signing_public_key: VerificationPublicKey32,
    pub signing_key_fingerprint: Digest32,
    pub signing_key_epoch: u64,
    pub status: DescriptorStatus,
    pub approval_mode: ApprovalMode,
    pub allowed_operations: Vec<WitnessOperation>,
    pub created_at_ms: u64,
    pub self_signature: Signature64,
}

impl ApproverPolicyDescriptor {
    pub fn canonical_body(&self) -> Result<Vec<u8>, PolicyError> {
        let mut output = Vec::new();
        output.extend_from_slice(&self.schema.to_be_bytes());
        output.extend_from_slice(self.approver_id.as_bytes());
        output.extend_from_slice(self.signing_public_key.as_bytes());
        output.extend_from_slice(self.signing_key_fingerprint.as_bytes());
        output.extend_from_slice(&self.signing_key_epoch.to_be_bytes());
        output.push(status_tag(self.status));
        output.push(approval_mode_tag(self.approval_mode));
        list_fixed(
            &mut output,
            self.allowed_operations
                .iter()
                .map(|operation| [operation_tag(*operation)]),
        )?;
        output.extend_from_slice(&self.created_at_ms.to_be_bytes());
        Ok(output)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, PolicyError> {
        let mut output = self.canonical_body()?;
        output.extend_from_slice(self.self_signature.as_bytes());
        Ok(output)
    }

    pub fn fingerprint(&self) -> Result<Digest32, PolicyError> {
        hash_body(
            "jury-witness-v1/approver-descriptor/fingerprint",
            &self.canonical_body()?,
        )
    }

    pub fn self_signature_preimage(&self) -> Result<Vec<u8>, PolicyError> {
        preimage_with_body(
            "jury-witness-v1/approver-descriptor/self-signature",
            &self.canonical_body()?,
        )
    }

    pub fn validate(&self) -> Result<(), PolicyError> {
        if self.schema != 1
            || self.signing_key_epoch == 0
            || self.allowed_operations.is_empty()
            || self.allowed_operations.len() > MAX_OPERATIONS
            || !strictly_sorted_unique(&self.allowed_operations)
            || self.signing_key_fingerprint
                != signing_key_fingerprint(
                    2,
                    &self.approver_id,
                    self.signing_key_epoch,
                    &self.signing_public_key,
                )
        {
            return Err(PolicyError::new(PolicyErrorKind::InvalidFormat));
        }
        crypto::verify_bytes(
            &self.signing_public_key,
            &self.self_signature_preimage()?,
            &self.self_signature,
        )
        .map_err(|_| PolicyError::new(PolicyErrorKind::InvalidSignature))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WitnessPolicyDescriptor {
    pub schema: u16,
    pub witness_id: PrincipalId,
    pub share_index: u8,
    pub signing_public_key: VerificationPublicKey32,
    pub signing_key_fingerprint: Digest32,
    pub signing_key_epoch: u64,
    pub contribution_public_key: RecipientPublicKey1216,
    pub contribution_key_fingerprint: Digest32,
    pub contribution_key_epoch: u64,
    pub status: DescriptorStatus,
    pub created_at_ms: u64,
    pub self_signature: Signature64,
}

impl WitnessPolicyDescriptor {
    pub fn canonical_body(&self) -> Vec<u8> {
        let mut output = Vec::with_capacity(1_379);
        output.extend_from_slice(&self.schema.to_be_bytes());
        output.extend_from_slice(self.witness_id.as_bytes());
        output.push(self.share_index);
        output.extend_from_slice(self.signing_public_key.as_bytes());
        output.extend_from_slice(self.signing_key_fingerprint.as_bytes());
        output.extend_from_slice(&self.signing_key_epoch.to_be_bytes());
        output.extend_from_slice(self.contribution_public_key.as_bytes());
        output.extend_from_slice(self.contribution_key_fingerprint.as_bytes());
        output.extend_from_slice(&self.contribution_key_epoch.to_be_bytes());
        output.push(status_tag(self.status));
        output.extend_from_slice(&self.created_at_ms.to_be_bytes());
        output
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut output = self.canonical_body();
        output.extend_from_slice(self.self_signature.as_bytes());
        output
    }

    pub fn fingerprint(&self) -> Result<Digest32, PolicyError> {
        hash_body(
            "jury-witness-v1/witness-descriptor/fingerprint",
            &self.canonical_body(),
        )
    }

    pub fn self_signature_preimage(&self) -> Result<Vec<u8>, PolicyError> {
        preimage_with_body(
            "jury-witness-v1/witness-descriptor/self-signature",
            &self.canonical_body(),
        )
    }

    pub fn validate(&self) -> Result<(), PolicyError> {
        if self.schema != 1
            || !(1..=32).contains(&self.share_index)
            || self.signing_key_epoch == 0
            || self.contribution_key_epoch == 0
            || self.signing_key_fingerprint
                != signing_key_fingerprint(
                    3,
                    &self.witness_id,
                    self.signing_key_epoch,
                    &self.signing_public_key,
                )
            || self.contribution_key_fingerprint
                != recipient_public_key_fingerprint(&self.contribution_public_key)
        {
            return Err(PolicyError::new(PolicyErrorKind::InvalidFormat));
        }
        crypto::verify_bytes(
            &self.signing_public_key,
            &self.self_signature_preimage()?,
            &self.self_signature,
        )
        .map_err(|_| PolicyError::new(PolicyErrorKind::InvalidSignature))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationRule {
    pub operation: WitnessOperation,
    pub eligible_approver_ids: Vec<PrincipalId>,
    pub approval_threshold: u8,
    pub allowed_request_lifetime_ms: u64,
    pub max_timeout_ms: u64,
    pub max_output_bytes: u32,
    pub max_target_count: u8,
    pub required_platform_assurance: PlatformAssurance,
    pub automatic_read_targets: Vec<AutomaticReadTarget>,
}

impl OperationRule {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, PolicyError> {
        let mut output = vec![operation_tag(self.operation)];
        list_fixed(
            &mut output,
            self.eligible_approver_ids.iter().map(|id| *id.as_bytes()),
        )?;
        output.push(self.approval_threshold);
        output.extend_from_slice(&self.allowed_request_lifetime_ms.to_be_bytes());
        output.extend_from_slice(&self.max_timeout_ms.to_be_bytes());
        output.extend_from_slice(&self.max_output_bytes.to_be_bytes());
        output.push(self.max_target_count);
        output.push(platform_assurance_tag(self.required_platform_assurance));
        let targets = self
            .automatic_read_targets
            .iter()
            .map(|target| {
                let mut bytes = target.item_id.as_bytes().to_vec();
                match target.field_id {
                    Some(field_id) => {
                        bytes.push(1);
                        bytes.extend_from_slice(field_id.as_bytes());
                    }
                    None => bytes.push(0),
                }
                bytes
            })
            .collect::<Vec<_>>();
        list_bytes(&mut output, &targets)?;
        Ok(output)
    }

    pub fn validate(&self) -> Result<(), PolicyError> {
        let threshold = usize::from(self.approval_threshold);
        let is_automatic = self.approval_threshold == 0;
        if self.eligible_approver_ids.len() > MAX_POLICY_MEMBERS
            || !strictly_sorted_unique(&self.eligible_approver_ids)
            || threshold > self.eligible_approver_ids.len()
            || !(1..=MAX_REQUEST_LIFETIME_MS).contains(&self.allowed_request_lifetime_ms)
            || self.max_timeout_ms == 0
            || self.max_output_bytes == 0
            || self.max_target_count == 0
            || usize::from(self.max_target_count) > MAX_AUTOMATIC_TARGETS
            || self.automatic_read_targets.len() > MAX_AUTOMATIC_TARGETS
            || !strictly_sorted_unique(&self.automatic_read_targets)
            || (is_automatic
                && (self.operation != WitnessOperation::ReadStdout
                    || self.automatic_read_targets.is_empty()))
            || (!is_automatic && !self.automatic_read_targets.is_empty())
        {
            return Err(PolicyError::new(PolicyErrorKind::InvalidTransition));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WitnessPolicy {
    pub schema: u16,
    pub witness_policy_id: WitnessPolicyId,
    pub revision: u64,
    pub predecessor_policy_digest: Digest32,
    pub vault_id: VaultId,
    pub genesis_fingerprint: Digest32,
    pub vault_policy_sequence: u64,
    pub vault_policy_hash: Digest32,
    pub construction: u16,
    pub suite: u16,
    pub approver_descriptors: Vec<ApproverPolicyDescriptor>,
    pub witness_descriptors: Vec<WitnessPolicyDescriptor>,
    pub witness_threshold: u8,
    pub operation_rules: Vec<OperationRule>,
    pub review_label_set_digest: Digest32,
    pub direct_fallback: bool,
}

impl WitnessPolicy {
    pub fn canonical_body(&self) -> Result<Vec<u8>, PolicyError> {
        let approvers = self
            .approver_descriptors
            .iter()
            .map(ApproverPolicyDescriptor::canonical_bytes)
            .collect::<Result<Vec<_>, _>>()?;
        let witnesses = self
            .witness_descriptors
            .iter()
            .map(WitnessPolicyDescriptor::canonical_bytes)
            .collect::<Vec<_>>();
        let rules = self
            .operation_rules
            .iter()
            .map(OperationRule::canonical_bytes)
            .collect::<Result<Vec<_>, _>>()?;
        let mut output = Vec::new();
        output.extend_from_slice(&self.schema.to_be_bytes());
        output.extend_from_slice(self.witness_policy_id.as_bytes());
        output.extend_from_slice(&self.revision.to_be_bytes());
        output.extend_from_slice(self.predecessor_policy_digest.as_bytes());
        output.extend_from_slice(self.vault_id.as_bytes());
        output.extend_from_slice(self.genesis_fingerprint.as_bytes());
        output.extend_from_slice(&self.vault_policy_sequence.to_be_bytes());
        output.extend_from_slice(self.vault_policy_hash.as_bytes());
        output.extend_from_slice(&self.construction.to_be_bytes());
        output.extend_from_slice(&self.suite.to_be_bytes());
        list_bytes(&mut output, &approvers)?;
        list_bytes(&mut output, &witnesses)?;
        output.push(self.witness_threshold);
        list_bytes(&mut output, &rules)?;
        output.extend_from_slice(self.review_label_set_digest.as_bytes());
        output.push(u8::from(self.direct_fallback));
        Ok(output)
    }

    pub fn digest(&self) -> Result<Digest32, PolicyError> {
        hash_body("jury-witness-v1/policy/hash", &self.canonical_body()?)
    }

    pub fn validate(&self) -> Result<(), PolicyError> {
        if self.schema != 1
            || self.revision == 0
            || self.construction != 1
            || self.suite != SUITE
            || self.direct_fallback
            || self.approver_descriptors.len() > MAX_POLICY_MEMBERS
            || self.witness_descriptors.len() > MAX_POLICY_MEMBERS
            || self.operation_rules.is_empty()
            || self.operation_rules.len() > MAX_OPERATIONS
            || !sorted_by_key(&self.approver_descriptors, |entry| entry.approver_id)
            || !sorted_by_key(&self.witness_descriptors, |entry| entry.witness_id)
            || !sorted_by_key(&self.operation_rules, |entry| entry.operation)
            || (self.revision == 1 && self.predecessor_policy_digest.as_bytes() != &ZERO_DIGEST)
            || (self.revision > 1 && self.predecessor_policy_digest.as_bytes() == &ZERO_DIGEST)
        {
            return Err(PolicyError::new(PolicyErrorKind::InvalidFormat));
        }
        for descriptor in &self.approver_descriptors {
            descriptor.validate()?;
        }
        for descriptor in &self.witness_descriptors {
            descriptor.validate()?;
        }
        for rule in &self.operation_rules {
            rule.validate()?;
        }

        let active_approvers = self
            .approver_descriptors
            .iter()
            .filter(|descriptor| descriptor.status == DescriptorStatus::Active)
            .map(|descriptor| (descriptor.approver_id, descriptor))
            .collect::<BTreeMap<_, _>>();
        let active_witnesses = self
            .witness_descriptors
            .iter()
            .filter(|descriptor| descriptor.status == DescriptorStatus::Active)
            .collect::<Vec<_>>();
        let role_ids = self
            .approver_descriptors
            .iter()
            .map(|descriptor| descriptor.approver_id)
            .chain(
                self.witness_descriptors
                    .iter()
                    .map(|descriptor| descriptor.witness_id),
            )
            .collect::<BTreeSet<_>>();
        if role_ids.len() != self.approver_descriptors.len() + self.witness_descriptors.len() {
            return Err(PolicyError::new(PolicyErrorKind::InvalidRole));
        }
        if !(2..=32).contains(&active_witnesses.len())
            || !(2..=active_witnesses.len()).contains(&usize::from(self.witness_threshold))
        {
            return Err(PolicyError::new(PolicyErrorKind::InvalidTransition));
        }
        let share_indexes = active_witnesses
            .iter()
            .map(|descriptor| descriptor.share_index)
            .collect::<BTreeSet<_>>();
        if share_indexes.len() != active_witnesses.len() {
            return Err(PolicyError::new(PolicyErrorKind::InvalidTransition));
        }
        for rule in &self.operation_rules {
            for approver_id in &rule.eligible_approver_ids {
                let approver = active_approvers
                    .get(approver_id)
                    .ok_or_else(|| PolicyError::new(PolicyErrorKind::InvalidRole))?;
                if !approver.allowed_operations.contains(&rule.operation) {
                    return Err(PolicyError::new(PolicyErrorKind::InvalidRole));
                }
            }
        }
        let signing_keys = self
            .approver_descriptors
            .iter()
            .map(|descriptor| descriptor.signing_public_key.clone())
            .chain(
                self.witness_descriptors
                    .iter()
                    .map(|descriptor| descriptor.signing_public_key.clone()),
            )
            .collect::<BTreeSet<_>>();
        if signing_keys.len() != self.approver_descriptors.len() + self.witness_descriptors.len() {
            return Err(PolicyError::new(PolicyErrorKind::InvalidRole));
        }
        let contribution_keys = self
            .witness_descriptors
            .iter()
            .map(|descriptor| descriptor.contribution_public_key.clone())
            .collect::<BTreeSet<_>>();
        if contribution_keys.len() != self.witness_descriptors.len() {
            return Err(PolicyError::new(PolicyErrorKind::InvalidRole));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WitnessAccessRule {
    pub policy_id: WitnessPolicyId,
    pub policy_revision: u64,
    pub policy_digest: Digest32,
    pub operation: WitnessOperation,
    pub eligible_approver_ids: Vec<PrincipalId>,
    pub approval_threshold: u8,
    pub witness_ids: Vec<PrincipalId>,
    pub witness_threshold: u8,
    pub allowed_request_lifetime_ms: u64,
    pub max_timeout_ms: u64,
    pub max_output_bytes: u32,
    pub max_target_count: u8,
    pub required_platform_assurance: PlatformAssurance,
    pub automatic_read_targets: Vec<AutomaticReadTarget>,
    pub carries_quorum_claim: bool,
}

impl PolicyState {
    /// Digests the exact active witness descriptor set bound to an item's
    /// current witnessed policy.
    pub fn intended_witness_set_digest(&self, item_id: &ItemId) -> Result<Digest32, PolicyError> {
        let authority = self
            .witness_authority(item_id)?
            .ok_or_else(|| PolicyError::new(PolicyErrorKind::InvalidRole))?;
        let policy = self
            .witness_policies
            .get(&authority.policy_digest)
            .ok_or_else(|| PolicyError::new(PolicyErrorKind::MissingWitnessPolicy))?;
        let entries = policy
            .witness_descriptors
            .iter()
            .filter(|descriptor| descriptor.status == DescriptorStatus::Active)
            .map(|descriptor| {
                let mut entry = [0_u8; 97];
                entry[..32].copy_from_slice(descriptor.witness_id.as_bytes());
                entry[32] = descriptor.share_index;
                entry[33..65].copy_from_slice(descriptor.signing_key_fingerprint.as_bytes());
                entry[65..].copy_from_slice(descriptor.contribution_key_fingerprint.as_bytes());
                entry
            });
        let mut preimage = jce("jury-witness-v1/intended-witness-set/hash");
        list_fixed(&mut preimage, entries)?;
        Ok(FixedBytes::new(Sha256::digest(preimage).into()))
    }

    pub fn witness_access_rule(
        &self,
        item_id: &ItemId,
        operation: WitnessOperation,
    ) -> Result<WitnessAccessRule, PolicyError> {
        let authority = self
            .witness_authority(item_id)?
            .ok_or_else(|| PolicyError::new(PolicyErrorKind::InvalidRole))?;
        let policy = self
            .witness_policies
            .get(&authority.policy_digest)
            .ok_or_else(|| PolicyError::new(PolicyErrorKind::MissingWitnessPolicy))?;
        let rule = policy
            .operation_rules
            .iter()
            .find(|rule| rule.operation == operation)
            .ok_or_else(|| PolicyError::new(PolicyErrorKind::Unauthorized))?;
        let witness_ids = policy
            .witness_descriptors
            .iter()
            .filter(|descriptor| descriptor.status == DescriptorStatus::Active)
            .map(|descriptor| descriptor.witness_id)
            .collect();
        Ok(WitnessAccessRule {
            policy_id: policy.witness_policy_id,
            policy_revision: policy.revision,
            policy_digest: authority.policy_digest,
            operation,
            eligible_approver_ids: rule.eligible_approver_ids.clone(),
            approval_threshold: rule.approval_threshold,
            witness_ids,
            witness_threshold: policy.witness_threshold,
            allowed_request_lifetime_ms: rule.allowed_request_lifetime_ms,
            max_timeout_ms: rule.max_timeout_ms,
            max_output_bytes: rule.max_output_bytes,
            max_target_count: rule.max_target_count,
            required_platform_assurance: rule.required_platform_assurance,
            automatic_read_targets: rule.automatic_read_targets.clone(),
            carries_quorum_claim: authority.carries_quorum_claim,
        })
    }
}

pub fn replay_policy_with_witness_policies(
    journal: &jury_protocol::vault_v1::PolicyJournalV1,
    policies: &[WitnessPolicy],
) -> Result<PolicyState, PolicyError> {
    let mut catalog = BTreeMap::new();
    for policy in policies {
        policy.validate()?;
        let digest = policy.digest()?;
        if catalog.insert(digest, policy.clone()).is_some() {
            return Err(PolicyError::new(PolicyErrorKind::InvalidTransition));
        }
    }
    for policy in policies.iter().filter(|policy| policy.revision > 1) {
        let predecessor = catalog
            .get(&policy.predecessor_policy_digest)
            .ok_or_else(|| PolicyError::new(PolicyErrorKind::InvalidAncestry))?;
        if predecessor.witness_policy_id != policy.witness_policy_id
            || predecessor.revision.checked_add(1) != Some(policy.revision)
        {
            return Err(PolicyError::new(PolicyErrorKind::InvalidAncestry));
        }
    }
    replay_policy_with_catalog(journal, catalog)
}

pub(super) fn validate_item_policy_binding(
    state: &PolicyState,
    item_id: &ItemId,
    witnessed: &jury_protocol::vault_v1::WitnessedStateV1,
) -> Result<(), PolicyError> {
    let first = witnessed
        .slots
        .first()
        .ok_or_else(|| PolicyError::new(PolicyErrorKind::InvalidFormat))?;
    let policy = state
        .witness_policies
        .get(&first.witness_policy_digest)
        .ok_or_else(|| PolicyError::new(PolicyErrorKind::MissingWitnessPolicy))?;
    if policy.witness_policy_id != first.witness_policy_id
        || policy.revision != first.witness_policy_revision
        || policy.vault_id != state.vault_id
        || policy.genesis_fingerprint != state.genesis_fingerprint
        || policy.vault_policy_sequence != first.vault_policy_sequence
        || policy.vault_policy_sequence > state.sequence
        || policy.witness_threshold != first.threshold
    {
        return Err(PolicyError::new(PolicyErrorKind::InvalidTransition));
    }

    let active_witnesses = policy
        .witness_descriptors
        .iter()
        .filter(|descriptor| descriptor.status == DescriptorStatus::Active)
        .collect::<Vec<_>>();
    let policy_members = active_witnesses
        .iter()
        .map(|descriptor| descriptor.witness_id)
        .collect::<Vec<_>>();
    let slot_members = first
        .capsules
        .iter()
        .map(|capsule| capsule.witness_id)
        .collect::<Vec<_>>();
    if policy_members != slot_members || first.item_id != *item_id {
        return Err(PolicyError::new(PolicyErrorKind::InvalidTransition));
    }
    for (descriptor, capsule) in active_witnesses.iter().zip(&first.capsules) {
        let principal = state
            .principals
            .get(&descriptor.witness_id)
            .ok_or_else(|| PolicyError::new(PolicyErrorKind::UnknownPrincipal))?;
        if principal.descriptor.principal_kind != jury_protocol::vault_v1::PrincipalKind::Witness
            || principal.descriptor.verification_public_key != descriptor.signing_public_key
            || principal.descriptor.recipient_public_key != descriptor.contribution_public_key
            || descriptor.share_index != capsule.share_index
            || descriptor.contribution_key_fingerprint != capsule.contribution_key_fingerprint
        {
            return Err(PolicyError::new(PolicyErrorKind::InvalidRole));
        }
    }
    for descriptor in policy
        .approver_descriptors
        .iter()
        .filter(|descriptor| descriptor.status == DescriptorStatus::Active)
    {
        let principal = state
            .principals
            .get(&descriptor.approver_id)
            .ok_or_else(|| PolicyError::new(PolicyErrorKind::UnknownPrincipal))?;
        if principal.descriptor.principal_kind != jury_protocol::vault_v1::PrincipalKind::Approver
            || principal.descriptor.verification_public_key != descriptor.signing_public_key
        {
            return Err(PolicyError::new(PolicyErrorKind::InvalidRole));
        }
    }
    Ok(())
}

fn signing_key_fingerprint(
    role: u8,
    subject_id: &PrincipalId,
    epoch: u64,
    public_key: &VerificationPublicKey32,
) -> Digest32 {
    let mut preimage = jce("jury-witness-v1/signing-key/fingerprint");
    preimage.push(role);
    preimage.extend_from_slice(subject_id.as_bytes());
    preimage.extend_from_slice(&epoch.to_be_bytes());
    preimage.extend_from_slice(public_key.as_bytes());
    FixedBytes::new(Sha256::digest(preimage).into())
}

fn preimage_with_body(domain: &str, body: &[u8]) -> Result<Vec<u8>, PolicyError> {
    let mut output = jce(domain);
    bytes_field(&mut output, body)?;
    Ok(output)
}

fn hash_body(domain: &str, body: &[u8]) -> Result<Digest32, PolicyError> {
    Ok(FixedBytes::new(
        Sha256::digest(preimage_with_body(domain, body)?).into(),
    ))
}

fn jce(domain: &str) -> Vec<u8> {
    let mut output = domain.as_bytes().to_vec();
    output.push(0);
    output.extend_from_slice(&SUITE.to_be_bytes());
    output
}

fn bytes_field(output: &mut Vec<u8>, value: &[u8]) -> Result<(), PolicyError> {
    let length = u32::try_from(value.len())
        .map_err(|_| PolicyError::new(PolicyErrorKind::CapacityExhausted))?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}

fn list_fixed<const N: usize>(
    output: &mut Vec<u8>,
    values: impl IntoIterator<Item = [u8; N]>,
) -> Result<(), PolicyError> {
    let values = values.into_iter().collect::<Vec<_>>();
    let count = u32::try_from(values.len())
        .map_err(|_| PolicyError::new(PolicyErrorKind::CapacityExhausted))?;
    output.extend_from_slice(&count.to_be_bytes());
    for value in values {
        output.extend_from_slice(&value);
    }
    Ok(())
}

fn list_bytes(output: &mut Vec<u8>, values: &[Vec<u8>]) -> Result<(), PolicyError> {
    let count = u32::try_from(values.len())
        .map_err(|_| PolicyError::new(PolicyErrorKind::CapacityExhausted))?;
    output.extend_from_slice(&count.to_be_bytes());
    for value in values {
        bytes_field(output, value)?;
    }
    Ok(())
}

fn strictly_sorted_unique<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn sorted_by_key<T, K: Ord>(values: &[T], key: impl Fn(&T) -> K) -> bool {
    values.windows(2).all(|pair| key(&pair[0]) < key(&pair[1]))
}

const fn status_tag(status: DescriptorStatus) -> u8 {
    match status {
        DescriptorStatus::Active => 1,
        DescriptorStatus::Revoked => 2,
    }
}

const fn approval_mode_tag(mode: ApprovalMode) -> u8 {
    match mode {
        ApprovalMode::Human => 1,
        ApprovalMode::Automatic => 2,
    }
}

const fn platform_assurance_tag(assurance: PlatformAssurance) -> u8 {
    match assurance {
        PlatformAssurance::NormalizedPathOnly => 1,
        PlatformAssurance::StableExecutableIdentity => 2,
    }
}

const fn operation_tag(operation: WitnessOperation) -> u8 {
    match operation {
        WitnessOperation::ReadStdout => 1,
        WitnessOperation::WritePrivateFile => 2,
        WitnessOperation::TemplateInjection => 3,
        WitnessOperation::ChildEnvironment => 4,
        WitnessOperation::ChildStdin => 5,
        WitnessOperation::ItemMutation => 6,
        WitnessOperation::Backup => 7,
        WitnessOperation::Recovery => 8,
        WitnessOperation::AdministrativeRekey => 9,
    }
}
