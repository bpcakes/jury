use super::*;

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
