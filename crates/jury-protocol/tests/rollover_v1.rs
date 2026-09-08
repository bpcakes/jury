use jury_protocol::{
    rollover_v1::BootstrapManifestV1,
    vault_v1::{AccessRole, PrincipalId, WitnessPolicyId},
};
use serde_json::Value;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn corpus() -> TestResult<Value> {
    Ok(serde_json::from_str(include_str!(
        "../../../conformance/rollover-v1/vectors.json"
    ))?)
}

fn parse(value: &Value) -> TestResult<BootstrapManifestV1> {
    Ok(serde_json::from_slice(&serde_json::to_vec(value)?)?)
}

#[test]
fn bootstrap_encoding_matches_independent_frozen_direct_and_witnessed_vectors() -> TestResult {
    let corpus = corpus()?;
    let vectors = corpus["vectors"].as_array().ok_or("missing vectors")?;
    assert_eq!(vectors.len(), 2);
    for vector in vectors {
        let manifest: BootstrapManifestV1 = parse(&vector["manifest"])?;
        assert_eq!(
            manifest.canonical_bytes()?,
            hex::decode(vector["preimage_hex"].as_str().ok_or("missing preimage")?)?
        );
        assert_eq!(
            manifest.digest()?.as_bytes().as_slice(),
            hex::decode(vector["digest_hex"].as_str().ok_or("missing digest")?)?
        );
    }
    Ok(())
}

#[test]
fn bootstrap_rejects_missing_owner_roles_aliased_ids_and_incomplete_policy_sets() -> TestResult {
    let corpus = corpus()?;
    let direct: BootstrapManifestV1 = parse(&corpus["vectors"][0]["manifest"])?;
    let witnessed: BootstrapManifestV1 = parse(&corpus["vectors"][1]["manifest"])?;
    let mut invalid = Vec::new();
    let mut changed = direct.clone();
    changed.principals[0].owner = false;
    invalid.push(changed);
    let mut changed = direct.clone();
    changed.items[0].grants.clear();
    invalid.push(changed);
    let mut changed = direct.clone();
    changed.items[0].grants[0].role = AccessRole::Writer;
    invalid.push(changed);
    let mut changed = direct.clone();
    changed.items[0].grants[0].principal_id = PrincipalId::from_bytes([0x44; 32])?;
    invalid.push(changed);
    let mut changed = direct.clone();
    changed.items[0].destination_item_id = changed.items[0].source_item_id;
    invalid.push(changed);
    let mut changed = direct.clone();
    changed.items.push(changed.items[0].clone());
    invalid.push(changed);
    let mut changed = direct.clone();
    changed.principals.push(changed.principals[0].clone());
    invalid.push(changed);
    let mut changed = direct.clone();
    changed.items[0].grants[0].direct = false;
    invalid.push(changed);
    let mut changed = direct.clone();
    changed.items[0].descriptor.revision = 2;
    invalid.push(changed);
    let mut changed = witnessed.clone();
    changed.witness_policies.clear();
    invalid.push(changed);
    let mut changed = witnessed.clone();
    changed.items[0].witnessed = None;
    invalid.push(changed);
    let mut changed = witnessed.clone();
    changed.witness_policies[0].destination_policy_id = WitnessPolicyId::from_bytes([0x44; 32])?;
    invalid.push(changed);
    let mut changed = witnessed;
    let slots = changed.items[0]
        .witnessed
        .as_mut()
        .ok_or("missing witnessed fixture")?;
    slots.body_slot_id = slots.descriptor_slot_id;
    invalid.push(changed);
    for manifest in invalid {
        assert!(manifest.canonical_bytes().is_err());
    }
    Ok(())
}

#[test]
fn bootstrap_rejects_unknown_fields_and_noncanonical_principal_order() -> TestResult {
    let corpus = corpus()?;
    let mut document = corpus["vectors"][0]["manifest"].clone();
    document["ignored_authority"] = Value::Bool(true);
    assert!(parse(&document).is_err());
    let mut manifest: BootstrapManifestV1 = parse(&corpus["vectors"][0]["manifest"])?;
    let mut principal = manifest.principals[0].clone();
    principal.principal_id = PrincipalId::from_bytes([1; 32])?;
    principal.owner = false;
    manifest.principals.push(principal);
    assert!(manifest.canonical_bytes().is_err());
    manifest.principals.swap(0, 1);
    manifest.validate_shape()?;
    Ok(())
}
