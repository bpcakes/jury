use super::*;
use crate::{
    access_provider::{
        DirectItemAccessProvider, ItemAccessError, ItemAccessOutcome, NeverCancelled,
        RevisionAccessRequest, ScopedRevisionAccess,
    },
    identity::{IdentityCreator, UnlockedIdentity, unlock},
    policy::AutomaticReadTarget,
    registration::{answer_challenge, answer_rollover_challenge},
    witness_approval::{OwnerReviewLabelCreator, OwnerReviewLabelInput, ReviewLabelSubject},
};
use jury_protected::{ProtectedMemory, RandomSource};
use jury_protocol::{
    identity_v1::KdfProfile,
    vault_v1::{
        ItemDescriptorV1, ItemFieldKind, ItemFieldV1, ItemFieldValue, ItemKind, ItemStateV1,
    },
};

mod historical;
mod migration;
mod topology;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const PROTECTION: ProtectionPolicy = ProtectionPolicy::EmergencyAllowDegraded;

struct IncrementingRandom(u8);
impl RandomSource for IncrementingRandom {
    fn fill(&mut self, bytes: &mut [u8]) -> Result<(), jury_protected::EntropyError> {
        bytes.fill(self.0);
        self.0 = self.0.wrapping_add(1);
        Ok(())
    }
}
struct FillByte(u8);
impl RandomSource for FillByte {
    fn fill(&mut self, bytes: &mut [u8]) -> Result<(), jury_protected::EntropyError> {
        bytes.fill(self.0);
        Ok(())
    }
}

struct AdministrativeProvider<'a> {
    direct: DirectItemAccessProvider<'a>,
    roles: Vec<ContentRole>,
}
impl ItemAccessProvider for AdministrativeProvider<'_> {
    fn access_revision<T, E>(
        &mut self,
        request: RevisionAccessRequest<'_>,
        consumer: impl FnOnce(&mut ScopedRevisionAccess<'_>) -> Result<T, E>,
    ) -> Result<ItemAccessOutcome<T>, ItemAccessError<E>> {
        assert_eq!(request.capability, crate::domain::Capability::Administer);
        self.roles.push(request.target.content_role);
        self.direct.access_revision(request, consumer)
    }
}

struct Fixture {
    vault: VaultFileV1,
    catalog: TransferPublicCatalogV1,
    identities: Vec<UnlockedIdentity>,
    recipient_keys: Vec<ProtectedMemory>,
    state: ItemStateV1,
}

fn fixture(owner: &VaultPrincipalIdentity) -> TestResult<Fixture> {
    let mut vault = crate::rollover::tests::source(owner)?;
    let initial = replay_policy(&vault.policy)?;
    let passphrase = ProtectedMemory::initialize(15, PROTECTION, |bytes| {
        bytes.copy_from_slice(b"ExamplePass1234");
        Ok::<_, ()>(bytes.len())
    })?;
    let mut identities = Vec::new();
    let mut proofs = Vec::new();
    let mut recipient_keys = Vec::new();
    let mut additions = Vec::new();
    for (index, marker) in [0x40, 0x60].into_iter().enumerate() {
        let created = IdentityCreator::from_source(IncrementingRandom(marker)).create(
            PrincipalKind::Witness,
            KdfProfile::PortableV1,
            1,
            &passphrase,
            |_| false,
        )?;
        let identity = unlock(&created.file, &passphrase)?;
        let challenge = RegistrationCreator::new(PROTECTION).create_challenge(
            &initial,
            owner,
            created.descriptor.clone(),
            3,
            60_000,
            Some(u8::try_from(index + 1)?),
        )?;
        let proof = answer_challenge(&initial, &identity, &challenge, 4)?;
        let digest = verify_proof(&initial, owner, &challenge, &proof, 5)?;
        additions.push(PolicyOperationV1::PrincipalAdd {
            descriptor: created.descriptor.clone(),
            display_label: format!("ExampleWitness{}", index + 1),
            registration_proof_digest: digest,
        });
        let (private, public) =
            crate::crypto::generate_recipient_keypair(PROTECTION, &mut FillByte(marker + 1))?;
        assert_eq!(public, created.descriptor.recipient_public_key);
        recipient_keys.push(private);
        identities.push(identity);
        proofs.push(proof);
    }
    let registered = initial.prepare_revision(owner, 5, additions)?;
    vault.policy.revisions.push(registered.revision);
    let field_id = FieldId::from_bytes([0x33; 32])?;
    let item_id = ItemId::from_bytes([0x90; 32])?;
    let (mut witness, _, _) = crate::policy::witness_tests::frozen_policy()?;
    witness.approver_descriptors.clear();
    witness.witness_descriptors = proofs
        .iter()
        .map(|proof| match &proof.role_descriptor {
            RegistrationRoleDescriptorV1::Witness { descriptor } => Ok(*descriptor.clone()),
            _ => Err("wrong fixture role"),
        })
        .collect::<Result<Vec<_>, _>>()?;
    witness.vault_id = registered.state.vault_id();
    witness.genesis_fingerprint = registered.state.genesis_fingerprint().clone();
    witness.vault_policy_sequence = 3;
    witness.vault_policy_hash = registered.state.terminal_revision_hash().clone();
    witness.operation_rules[0].approval_threshold = 0;
    witness.operation_rules[0].eligible_approver_ids.clear();
    witness.operation_rules[0].automatic_read_targets = vec![AutomaticReadTarget {
        item_id,
        content_role: ContentRole::Body,
        field_id: Some(field_id),
    }];
    let label = OwnerReviewLabelCreator::new().create(
        OwnerReviewLabelInput {
            policy: &registered.state,
            owner,
            label_revision: 1,
            subject: ReviewLabelSubject::Field { item_id, field_id },
            public_label: jury_protocol::witness_v1::ReviewLabelBytes::new(
                b"ExampleField".to_vec(),
            )?,
            target_policy_sequence: 3,
            issued_at_ms: 6,
            expires_at_ms: Some(100_020),
        },
        |_| false,
    )?;
    let labels = ReviewLabelSetV1::new(vec![label])?;
    witness.review_label_set_digest = labels.digest.clone();
    let policy =
        replay_policy_with_witness_policies(&vault.policy, std::slice::from_ref(&witness))?;
    let state = ItemStateV1 {
        plaintext_schema: 1,
        fields: vec![ItemFieldV1 {
            name: "ExampleField".into(),
            field_id,
            value: ItemFieldValue::new(b"ExampleValue".to_vec())?,
            decoded_length: 12,
            kind: ItemFieldKind::Concealed,
            created_at_ms: 1,
            updated_at_ms: 1,
        }],
    };
    let created = ItemCreator::from_source(IncrementingRandom(0x90), PROTECTION).prepare_create(
        &policy,
        owner,
        7,
        NewItem {
            kind: ItemKind::Canonical,
            descriptor: ItemDescriptorV1::new("ExampleWitnessedItem".into())?,
            state: state.clone(),
            bucket_id: 1,
            access: ItemAccessPlan {
                grants: Vec::new(),
                direct_recipient_ids: vec![owner.principal_id()],
                witness_policy_digest: Some(witness.digest()?),
            },
        },
        &ItemArtifactInventory::default(),
    )?;
    assert_eq!(created.envelope.item_id, item_id);
    vault.policy.revisions.push(created.policy.revision);
    vault.items.push(created.envelope);
    let catalog =
        TransferPublicCatalogV1::with_review_label_sets(proofs, vec![witness], vec![labels])?;
    Ok(Fixture {
        vault,
        catalog,
        identities,
        recipient_keys,
        state,
    })
}

#[test]
fn governed_bootstrap_binds_fresh_proofs_capsules_and_public_scopes() -> TestResult {
    let owner = crate::rollover::tests::owner()?;
    let fixture = fixture(&owner)?;
    let source_bytes = fixture.vault.to_json_bytes()?;
    let source = RolloverSource::validate(&fixture.vault, &fixture.catalog.witness_policies)?;
    let mut provider = AdministrativeProvider {
        direct: DirectItemAccessProvider::new(&owner),
        roles: Vec::new(),
    };
    assert_short_labels_refused_before_access(&source, &fixture.catalog, &owner)?;
    let mut draft = source.prepare_governed(
        &fixture.catalog,
        &owner,
        &mut provider,
        GovernedRolloverOptions {
            created_at_ms: 10,
            registration_lifetime_ms: 60_000,
            protection: PROTECTION,
        },
        &NeverCancelled,
    )?;
    assert_eq!(provider.roles, [ContentRole::Descriptor, ContentRole::Body]);
    let initial = source.verify_registration_draft(draft.registration_journal())?;
    assert_registration_draft_rejections(&source, &fixture.catalog, &owner, &draft)?;
    for (challenge, role) in draft.challenges().iter().zip(draft.prior_roles()) {
        assert_eq!(
            source.source_registration_role(
                &fixture.catalog,
                challenge.candidate_descriptor.principal_id
            )?,
            role
        );
    }
    let proofs = draft
        .challenges()
        .iter()
        .zip(draft.prior_roles())
        .zip(&fixture.identities)
        .map(|((challenge, role), identity)| {
            answer_rollover_challenge(&initial, identity, challenge, role, 11)
        })
        .collect::<Result<Vec<_>, _>>()?;
    for (prior, fresh) in fixture.catalog.registration_proofs.iter().zip(&proofs) {
        assert_ne!(
            prior.challenge.genesis_fingerprint,
            fresh.challenge.genesis_fingerprint
        );
        assert!(verify_proof_signatures(&initial, &fresh.challenge, prior, 12).is_err());
    }
    let fixed_genesis = replay_policy(draft.registration_journal())?
        .genesis_fingerprint()
        .clone();
    assert!(
        draft
            .verify_registration_proofs(&owner, &proofs[..1], 12)
            .is_err()
    );
    let mut invalid_proofs = proofs.clone();
    invalid_proofs[0].candidate_signature = Signature64::new([0; 64]);
    assert!(
        draft
            .verify_registration_proofs(&owner, &invalid_proofs, 12)
            .is_err()
    );
    draft.verify_registration_proofs(&owner, &proofs, 12)?;
    assert_eq!(
        *replay_policy(draft.registration_journal())?.genesis_fingerprint(),
        fixed_genesis
    );
    let proofs = renew_after_expiry(&mut draft, &owner, &fixture.identities, &proofs)?;
    let prepared = draft.complete(
        &source,
        &fixture.catalog,
        &owner,
        proofs,
        100_002,
        &NeverCancelled,
    )?;
    assert_eq!(fixture.vault.to_json_bytes()?, source_bytes);
    let destination =
        RolloverSource::validate(prepared.vault(), &prepared.catalog().witness_policies)?;
    let envelope = &prepared.vault().items[0];
    let item = destination
        .policy
        .item(&envelope.item_id)
        .ok_or("missing copied item")?;
    let witnessed = item
        .witnessed_state
        .as_ref()
        .ok_or("missing copied witness slots")?;
    let secret = crate::item::reconstruct_slot_secret(
        &witnessed.slots[1],
        &fixture.recipient_keys,
        PROTECTION,
    )?;
    let mut opened = crate::item::open_body(envelope, &secret)?;
    assert_eq!(opened.fields.len(), fixture.state.fields.len());
    assert_ne!(opened.fields[0].field_id, fixture.state.fields[0].field_id);
    assert!(opened.fields[0].value == fixture.state.fields[0].value);
    assert_eq!(opened.fields[0].name, fixture.state.fields[0].name);
    let copied_policy = &prepared.catalog().witness_policies[0];
    let target = &copied_policy.operation_rules[0].automatic_read_targets[0];
    assert_eq!(target.item_id, envelope.item_id);
    assert_eq!(target.field_id, Some(opened.fields[0].field_id));
    assert_eq!(
        prepared.catalog().review_label_sets[0].labels[0].field_id,
        target.field_id
    );
    opened.clear_sensitive();
    let mut wrong_genesis = witnessed.slots[1].clone();
    wrong_genesis.genesis_fingerprint = source.policy.genesis_fingerprint().clone();
    for capsule in &mut wrong_genesis.capsules {
        capsule.genesis_fingerprint = source.policy.genesis_fingerprint().clone();
        // HPKE binds the canonical context digest, so exercise a complete
        // attempted rebinding rather than leave a stale cached digest intact.
        capsule.context_digest = capsule.recomputed_context_digest();
    }
    assert!(
        crate::item::reconstruct_slot_secret(&wrong_genesis, &fixture.recipient_keys, PROTECTION)
            .is_err()
    );
    assert_missing_catalog_material_rejected(&source, &fixture.catalog, &prepared)?;
    assert_resigned_missing_item_rejected(&source, &fixture.catalog, &owner, &prepared)?;
    assert_expired_labels_rejected(&source, &fixture.catalog, &owner, &prepared)?;
    historical::verify_after_removal(&source, &fixture, &owner, &prepared)?;
    Ok(())
}

fn assert_registration_draft_rejections(
    source: &RolloverSource<'_>,
    catalog: &TransferPublicCatalogV1,
    owner: &VaultPrincipalIdentity,
    draft: &GovernedRolloverDraft,
) -> TestResult {
    let mut substituted = draft.registration_journal().clone();
    let Some(SourceAttestationV1::Rollover { statement }) =
        &mut substituted.genesis.source_attestation
    else {
        return Err("missing rollover statement".into());
    };
    let manifest = statement
        .bootstrap_manifest
        .as_mut()
        .ok_or("missing manifest")?;
    manifest.principals[0].display_label = "ExampleSubstitutedLabel".into();
    statement.bootstrap_manifest_digest = manifest.digest()?;
    statement.signature = owner.sign_validated_statement(&statement.signature_preimage())?;
    substituted.genesis.owner_signature =
        owner.sign_validated_statement(&substituted.genesis.signature_preimage()?)?;
    source.verify_source_authorization(&substituted.genesis)?;
    assert!(source.verify_registration_draft(&substituted).is_err());

    let unrelated = crate::rollover::tests::source(owner)?;
    let unrelated = RolloverSource::validate(&unrelated, &[])?;
    assert!(
        unrelated
            .verify_registration_draft(draft.registration_journal())
            .is_err()
    );
    let mut stale = catalog.clone();
    stale.registration_proofs[0].candidate_signature = Signature64::new([0; 64]);
    assert!(
        source
            .source_registration_role(
                &stale,
                catalog.registration_proofs[0].candidate_principal_id
            )
            .is_err()
    );
    assert!(
        source
            .source_registration_role(catalog, owner.principal_id())
            .is_err()
    );
    Ok(())
}

fn assert_missing_catalog_material_rejected(
    source: &RolloverSource<'_>,
    source_catalog: &TransferPublicCatalogV1,
    prepared: &PreparedGovernedRollover,
) -> TestResult {
    let mut missing = prepared.catalog().clone();
    missing.registration_proofs.pop();
    assert!(
        source
            .verify_fresh_governed_destination(source_catalog, prepared.vault(), &missing)
            .is_err()
    );
    let mut stale = prepared.catalog().clone();
    stale.registration_proofs = source_catalog.registration_proofs.clone();
    assert!(
        source
            .verify_fresh_governed_destination(source_catalog, prepared.vault(), &stale)
            .is_err()
    );
    let mut missing_labels = prepared.catalog().clone();
    missing_labels.review_label_sets.clear();
    assert!(
        source
            .verify_fresh_governed_destination(source_catalog, prepared.vault(), &missing_labels)
            .is_err()
    );
    Ok(())
}

fn assert_resigned_missing_item_rejected(
    source: &RolloverSource<'_>,
    source_catalog: &TransferPublicCatalogV1,
    owner: &VaultPrincipalIdentity,
    prepared: &PreparedGovernedRollover,
) -> TestResult {
    let mut incomplete = prepared.vault().clone();
    let mut operations = incomplete.policy.revisions[0].operations.clone();
    operations.retain(|operation| !matches!(operation, PolicyOperationV1::ItemCreate { .. }));
    incomplete.policy.revisions.clear();
    incomplete.items.clear();
    let initial = replay_policy_with_witness_policies(
        &incomplete.policy,
        &prepared.catalog().witness_policies,
    )?;
    incomplete.policy.revisions.push(
        initial
            .prepare_revision(
                owner,
                prepared.vault().policy.revisions[0].timestamp_ms,
                operations,
            )?
            .revision,
    );
    RolloverSource::validate(&incomplete, &prepared.catalog().witness_policies)?;
    source.verify_source_authorization(&incomplete.policy.genesis)?;
    assert!(
        source
            .verify_fresh_governed_destination(source_catalog, &incomplete, prepared.catalog())
            .is_err()
    );
    Ok(())
}

fn assert_short_labels_refused_before_access(
    source: &RolloverSource<'_>,
    catalog: &TransferPublicCatalogV1,
    owner: &VaultPrincipalIdentity,
) -> TestResult {
    let source_bytes = source.vault.to_json_bytes()?;
    let mut provider = AdministrativeProvider {
        direct: DirectItemAccessProvider::new(owner),
        roles: Vec::new(),
    };
    let refused = source.prepare_governed(
        catalog,
        owner,
        &mut provider,
        GovernedRolloverOptions {
            created_at_ms: 10,
            registration_lifetime_ms: 100_011,
            protection: PROTECTION,
        },
        &NeverCancelled,
    );
    assert_eq!(
        refused.err().map(|error| error.kind()),
        Some(RolloverErrorKind::ReviewLabelLifetime)
    );
    assert!(provider.roles.is_empty());
    assert_eq!(source.vault.to_json_bytes()?, source_bytes);
    Ok(())
}

fn renew_after_expiry(
    draft: &mut GovernedRolloverDraft,
    owner: &VaultPrincipalIdentity,
    identities: &[UnlockedIdentity],
    prior_proofs: &[RegistrationProofV1],
) -> TestResult<Vec<RegistrationProofV1>> {
    let genesis = draft.registration_journal().clone();
    let prior_challenges = draft.challenges().to_vec();
    assert!(
        draft
            .verify_registration_proofs(owner, prior_proofs, 100_000)
            .is_err()
    );
    assert!(
        draft
            .renew_registration_challenges(owner, 9, 60_000)
            .is_err()
    );
    assert!(
        draft
            .renew_registration_challenges(owner, 100_000, 0)
            .is_err()
    );
    assert_eq!(draft.challenges(), prior_challenges);
    assert_eq!(
        draft
            .renew_registration_challenges(owner, 100_000, 60_000)
            .err()
            .map(|error| error.kind()),
        Some(RolloverErrorKind::ReviewLabelLifetime),
    );
    assert_eq!(draft.challenges(), prior_challenges);
    // Labels expire exclusively; a challenge valid at that instant is too late.
    assert_eq!(
        draft
            .renew_registration_challenges(owner, 100_000, 20)
            .err()
            .map(|error| error.kind()),
        Some(RolloverErrorKind::ReviewLabelLifetime),
    );
    assert_eq!(draft.challenges(), prior_challenges);
    draft.renew_registration_challenges(owner, 100_000, 19)?;
    assert_eq!(*draft.registration_journal(), genesis);
    assert!(
        draft
            .verify_registration_proofs(owner, prior_proofs, 100_002)
            .is_err()
    );
    let initial = replay_policy(&genesis)?;
    let proofs = draft
        .challenges()
        .iter()
        .zip(draft.prior_roles())
        .zip(identities)
        .map(|((challenge, role), identity)| {
            answer_rollover_challenge(&initial, identity, challenge, role, 100_001)
        })
        .collect::<Result<Vec<_>, _>>()?;
    draft.verify_registration_proofs(owner, &proofs, 100_002)?;
    Ok(proofs)
}

fn assert_expired_labels_rejected(
    source: &RolloverSource<'_>,
    source_catalog: &TransferPublicCatalogV1,
    owner: &VaultPrincipalIdentity,
    prepared: &PreparedGovernedRollover,
) -> TestResult {
    let mut expired = prepared.vault().clone();
    let operations = expired.policy.revisions[0].operations.clone();
    expired.policy.revisions.clear();
    let initial =
        replay_policy_with_witness_policies(&expired.policy, &prepared.catalog().witness_policies)?;
    expired.policy.revisions.push(
        initial
            .prepare_revision(owner, 100_020, operations)?
            .revision,
    );
    RolloverSource::validate(&expired, &prepared.catalog().witness_policies)?;
    source.verify_source_authorization(&expired.policy.genesis)?;
    assert!(
        source
            .verify_fresh_governed_destination(source_catalog, &expired, prepared.catalog())
            .is_err()
    );
    Ok(())
}
