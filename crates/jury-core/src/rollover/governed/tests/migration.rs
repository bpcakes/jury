use super::*;
use jury_protocol::hpke_context::VaultSuite;

#[test]
fn migration_rebinds_governed_capsules_and_fresh_registration_to_suite_two() -> TestResult {
    let owner = crate::rollover::tests::owner()?;
    let fixture = fixture(&owner)?;
    let before = fixture.vault.to_json_bytes()?;
    let source = RolloverSource::validate(&fixture.vault, &fixture.catalog.witness_policies)?;
    let mut provider = AdministrativeProvider {
        direct: DirectItemAccessProvider::new(&owner),
        roles: Vec::new(),
    };
    let draft = source.prepare_governed_migration(
        VaultSuite::Suite2,
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
    assert_eq!(initial.suite(), 2);
    let proofs = draft
        .challenges()
        .iter()
        .zip(draft.prior_roles())
        .map(|(challenge, role)| {
            let identity = fixture
                .identities
                .iter()
                .find(|identity| {
                    identity
                        .public_descriptor()
                        .is_ok_and(|descriptor| descriptor == challenge.candidate_descriptor)
                })
                .ok_or("missing witness")?;
            Ok(answer_rollover_challenge(
                &initial, identity, challenge, role, 11,
            )?)
        })
        .collect::<TestResult<Vec<_>>>()?;
    let prepared = draft.complete(
        &source,
        &fixture.catalog,
        &owner,
        proofs,
        12,
        &NeverCancelled,
    )?;
    assert_eq!(prepared.vault().header.suite, 2);
    assert!(prepared.vault().suite_migration.is_some());
    assert!(
        prepared
            .catalog()
            .witness_policies
            .iter()
            .all(|policy| policy.suite == 2)
    );
    source.verify_fresh_governed_destination(
        &fixture.catalog,
        prepared.vault(),
        prepared.catalog(),
    )?;
    crate::transfer::TransferCreator::new().create(
        prepared.vault(),
        prepared.catalog().clone(),
        &owner,
        13,
    )?;
    let destination =
        RolloverSource::validate(prepared.vault(), &prepared.catalog().witness_policies)?;
    for envelope in &prepared.vault().items {
        let item = destination
            .policy
            .item(&envelope.item_id)
            .ok_or("missing item")?;
        let witnessed = item
            .witnessed_state
            .as_ref()
            .ok_or("missing witnessed state")?;
        for slot in &witnessed.slots {
            assert_eq!(slot.suite, 2);
            for capsule in &slot.capsules {
                let identity = fixture
                    .identities
                    .iter()
                    .find_map(|identity| match identity {
                        UnlockedIdentity::Witness(identity)
                            if identity.principal_id() == capsule.witness_id =>
                        {
                            Some(identity)
                        }
                        _ => None,
                    })
                    .ok_or("missing witness")?;
                identity.open_contribution_share(VaultSuite::Suite2, capsule)?;
                assert!(
                    identity
                        .open_contribution_share(VaultSuite::Suite1, capsule)
                        .is_err()
                );
            }
        }
        let secret = crate::item::reconstruct_slot_secret(
            &witnessed.slots[1],
            &fixture.recipient_keys,
            PROTECTION,
        )?;
        let mut body = crate::item::open_body(envelope, &secret)?;
        assert!(body.fields[0].value == fixture.state.fields[0].value);
        assert_ne!(body.fields[0].field_id, fixture.state.fields[0].field_id);
        body.clear_sensitive();
    }
    let mut stripped = prepared.vault().clone();
    stripped.suite_migration = None;
    assert!(
        crate::transfer::TransferCreator::new()
            .create(&stripped, prepared.catalog().clone(), &owner, 13)
            .is_err()
    );
    historical::verify_after_removal(&source, &fixture, &owner, &prepared)?;
    assert_eq!(fixture.vault.to_json_bytes()?, before);
    Ok(())
}
