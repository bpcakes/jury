use jury_protocol::rollover_v1::BootstrapManifestV1;
use serde_json::Value;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn vectors() -> TestResult<Vec<Value>> {
    let corpus: Value = serde_json::from_str(include_str!(
        "../../../conformance/rollover-v2/vectors.json"
    ))?;
    Ok(corpus["vectors"]
        .as_array()
        .ok_or("missing vectors")?
        .clone())
}

fn manifest(vector: &Value) -> TestResult<BootstrapManifestV1> {
    Ok(serde_json::from_slice(&serde_json::to_vec(
        &vector["manifest"],
    )?)?)
}

#[test]
fn version_two_encodes_each_source_policy_revision_without_changing_v1() -> TestResult {
    let vectors = vectors()?;
    assert_eq!(vectors.len(), 3);
    for vector in &vectors {
        let manifest = manifest(vector)?;
        assert_eq!(manifest.version, 2);
        assert_eq!(manifest.source_suite, Some(1));
        assert_eq!(
            manifest.canonical_bytes()?,
            hex::decode(vector["preimage_hex"].as_str().ok_or("missing bytes")?)?
        );
        assert_eq!(
            manifest.digest()?.as_bytes().as_slice(),
            hex::decode(vector["digest_hex"].as_str().ok_or("missing digest")?)?
        );
    }
    let multiple = manifest(&vectors[2])?;
    assert_eq!(multiple.witness_policies.len(), 2);
    assert_eq!(
        multiple.witness_policies[0].source_policy_id,
        multiple.witness_policies[1].source_policy_id
    );
    assert_eq!(multiple.witness_policies[0].source_policy_revision, Some(1));
    assert_eq!(multiple.witness_policies[1].source_policy_revision, Some(2));
    Ok(())
}

#[test]
fn version_two_rejects_ambiguous_revision_and_suite_interpretations() -> TestResult {
    let vectors = vectors()?;
    let valid = manifest(&vectors[2])?;
    for mutation in 0..10 {
        let mut invalid = valid.clone();
        match mutation {
            0 => invalid.version = 1,
            1 => invalid.source_suite = None,
            2 => invalid.source_suite = Some(2),
            3 => invalid.destination_suite = 3,
            4 => invalid.witness_policies[0].source_policy_revision = None,
            5 => invalid.witness_policies[0].source_policy_revision = Some(0),
            6 => invalid.witness_policies[1].source_policy_revision = Some(1),
            7 => invalid.witness_policies.swap(0, 1),
            8 => {
                invalid.witness_policies[1].destination_policy_id =
                    invalid.witness_policies[0].destination_policy_id
            }
            _ => invalid.version = 3,
        }
        assert!(invalid.canonical_bytes().is_err(), "mutation {mutation}");
    }
    let mut changed = valid.clone();
    changed.witness_policies[1].source_policy_revision = Some(3);
    assert_ne!(changed.digest()?, valid.digest()?);
    // A v1 document never consumes a v2-only field, including a revision that
    // happens to be one. Existing frozen v1 tests separately pin exact bytes.
    let mut v1 = manifest(&vectors[1])?;
    v1.version = 1;
    v1.source_suite = None;
    assert!(v1.validate_shape().is_err());
    v1.witness_policies[0].source_policy_revision = None;
    v1.validate_shape()?;
    let mut unknown = vectors[2]["manifest"].clone();
    unknown["witness_policies"][0]["ignored_source_digest"] = Value::Bool(true);
    assert!(serde_json::from_slice::<BootstrapManifestV1>(&serde_json::to_vec(&unknown)?).is_err());
    Ok(())
}

#[test]
fn manifest_commits_one_way_migration_and_same_suite_two_rollover() -> TestResult {
    let vectors = vectors()?;
    let mut migration = manifest(&vectors[0])?;
    let old = migration.digest()?;
    migration.destination_suite = 2;
    migration.validate_shape()?;
    assert_ne!(migration.digest()?, old);
    let migration_digest = migration.digest()?;
    migration.source_suite = Some(2);
    migration.validate_shape()?;
    assert_ne!(migration.digest()?, migration_digest);
    migration.destination_suite = 1;
    assert!(migration.canonical_bytes().is_err());
    migration.destination_suite = 2;
    migration.source_suite = Some(3);
    assert!(migration.canonical_bytes().is_err());
    Ok(())
}
