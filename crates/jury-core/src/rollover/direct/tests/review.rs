use super::*;

#[test]
fn signed_v1_bootstrap_cannot_downgrade_a_suite_two_source() -> TestResult {
    let owner = crate::rollover::tests::owner()?;
    let original = crate::rollover::tests::source(&owner)?;
    let original_source = RolloverSource::validate(&original, &[])?;
    let migrated = original_source.prepare_direct_migration(
        jury_protocol::hpke_context::VaultSuite::Suite2,
        &owner,
        10,
        PROTECTION,
        &NeverCancelled,
    )?;
    let suite_two = RolloverSource::validate(migrated.vault(), &[])?;
    let prepared = original_source.prepare_direct(&owner, 20, PROTECTION, &NeverCancelled)?;
    let mut downgraded = prepared.vault().clone();
    let Some(SourceAttestationV1::Rollover { statement }) =
        &mut downgraded.policy.genesis.source_attestation
    else {
        return Err("missing bridge".into());
    };
    statement.source_vault_id = suite_two.policy.vault_id();
    statement.source_genesis_fingerprint = suite_two.policy.genesis_fingerprint().clone();
    statement.terminal_source_revision_hash = suite_two.policy.terminal_revision_hash().clone();
    let manifest = statement
        .bootstrap_manifest
        .as_mut()
        .ok_or("missing manifest")?;
    manifest.version = 1;
    manifest.source_suite = None;
    resign_bootstrap(&mut downgraded, &owner)?;
    // The whole artifact and both owner signatures are valid. Only binding
    // the implicit v1 source suite to the supplied source detects the downgrade.
    VaultFileV1::parse(&downgraded.to_json_bytes()?)?;
    replay_policy(&downgraded.policy)?;
    let mut stripped = downgraded.policy.genesis.clone();
    let Some(SourceAttestationV1::Rollover { statement }) = &mut stripped.source_attestation else {
        return Err("missing bridge".into());
    };
    statement.bootstrap_manifest = None;
    assert_eq!(
        suite_two
            .verify_source_authorization(&stripped)
            .err()
            .map(RolloverError::kind),
        Some(RolloverErrorKind::SourceMismatch)
    );
    assert_eq!(
        suite_two
            .verify_source_authorization(&downgraded.policy.genesis)
            .err()
            .map(RolloverError::kind),
        Some(RolloverErrorKind::SourceMismatch),
    );
    assert!(
        suite_two
            .verify_fresh_direct_destination(&downgraded)
            .is_err()
    );
    assert!(
        suite_two
            .verify_historical_direct_destination(
                &downgraded,
                &crate::transfer::TransferPublicCatalogV1::empty(),
            )
            .is_err()
    );
    Ok(())
}

#[test]
fn bridge_authorization_authenticates_manifest_bytes_before_reading_fields() -> TestResult {
    let owner = crate::rollover::tests::owner()?;
    let original = crate::rollover::tests::source(&owner)?;
    let source = RolloverSource::validate(&original, &[])?;
    let prepared = source.prepare_direct(&owner, 10, PROTECTION, &NeverCancelled)?;
    let mut changed = prepared.vault().policy.genesis.clone();
    let Some(SourceAttestationV1::Rollover { statement }) = &mut changed.source_attestation else {
        return Err("missing bridge".into());
    };
    let manifest = statement
        .bootstrap_manifest
        .as_mut()
        .ok_or("missing manifest")?;
    manifest.created_at_ms += 1;
    assert_ne!(manifest.digest()?, statement.bootstrap_manifest_digest);
    assert_eq!(
        source
            .verify_source_authorization(&changed)
            .err()
            .map(RolloverError::kind),
        Some(RolloverErrorKind::InvalidDestination)
    );
    Ok(())
}
