use super::*;
use jury_protocol::hpke_context::{ContributionHpkeContext, VaultSuite};
use jury_protocol::vault_v1::ResponseId;

fn new_corpus() -> TestResult<Value> {
    Ok(serde_json::from_slice(include_bytes!(
        "../../../../conformance/suite-2/context-vectors.json"
    ))?)
}

fn bytes(value: &Value, key: &str) -> TestResult<Vec<u8>> {
    Ok(hex::decode(hex_value(value, key)?)?)
}

#[test]
fn direct_and_capsule_suite2_contexts_match_cross_provider_inputs() -> TestResult {
    let source = direct_corpus()?;
    let corpus = new_corpus()?;
    let vectors = corpus["vectors"].as_array().ok_or("missing vectors")?;
    let mut checked = 0;
    for vector in vectors {
        let name = hex_value(vector, "name")?;
        if let Some(role) = name.strip_prefix("direct-") {
            let mut slot =
                parse_direct_slot(&bytes(&source["encodings"]["direct_slots"][role], "hex")?)?;
            let old_info = slot.info_preimage();
            slot.suite = 2;
            slot.aead = 2;
            assert_eq!(slot.info_preimage(), bytes(vector, "info")?);
            assert_eq!(slot.aad_preimage(), bytes(vector, "aad")?);
            assert_ne!(slot.info_preimage(), old_info);
            checked += 1;
        } else if name.starts_with("capsule-") {
            let capsule = parse_capsule(&bytes(vector, "canonical_capsule")?)?;
            assert_eq!(
                capsule.context_preimage_for_suite(VaultSuite::Suite2),
                bytes(vector, "context_preimage")?
            );
            assert_eq!(
                capsule.recomputed_context_digest_for_suite(VaultSuite::Suite2),
                capsule.context_digest
            );
            assert_ne!(capsule.recomputed_context_digest(), capsule.context_digest);
            assert_eq!(
                capsule.info_preimage_for_suite(VaultSuite::Suite2),
                bytes(vector, "info")?
            );
            assert_eq!(
                capsule.aad_preimage_for_suite(VaultSuite::Suite2),
                bytes(vector, "aad")?
            );
            assert_eq!(
                capsule.canonical_bytes(),
                bytes(vector, "canonical_capsule")?
            );
            checked += 1;
        }
    }
    assert_eq!(checked, 5);
    assert_eq!(VaultSuite::from_id(1), Some(VaultSuite::Suite1));
    assert_eq!(VaultSuite::from_id(2), Some(VaultSuite::Suite2));
    assert_eq!(VaultSuite::from_id(0), None);
    assert_eq!(VaultSuite::from_id(3), None);
    assert_eq!(VaultSuite::Suite1.hpke_aead(), 3);
    assert_eq!(VaultSuite::Suite2.hpke_aead(), 2);
    Ok(())
}

fn fields<'a>(preimage: &'a [u8], domain: &str, suite: VaultSuite) -> TestResult<&'a [u8]> {
    let mut prefix = domain.as_bytes().to_vec();
    prefix.push(0);
    prefix.extend_from_slice(&suite.id().to_be_bytes());
    preimage
        .strip_prefix(prefix.as_slice())
        .ok_or_else(|| failure("wrong profile prefix").into())
}

fn contribution(info: &[u8], aad: &[u8], suite: VaultSuite) -> TestResult<ContributionHpkeContext> {
    let mut info = Cursor::new(fields(info, "jury-witness-v1/contribution/info", suite)?);
    let mut aad = Cursor::new(fields(aad, "jury-witness-v1/contribution/aad", suite)?);
    let context = ContributionHpkeContext {
        suite,
        request_digest: Digest32::new(info.take()?),
        action_manifest_digest: Digest32::new(info.take()?),
        response_id: ResponseId::from_bytes(info.take()?)?,
        witness_id: PrincipalId::from_bytes(info.take()?)?,
        witness_policy_digest: Digest32::new(info.take()?),
        checkpoint_digest: Digest32::new(info.take()?),
        share_commitment: Digest32::new(info.take()?),
        share_index: info.u8()?,
        capsule_set_digest: Digest32::new(aad.take()?),
        capsule_context_digest: Digest32::new(aad.take()?),
        session_fingerprint: Digest32::new(aad.take()?),
        expires_at_ms: aad.u64()?,
    };
    info.done()?;
    aad.done()?;
    Ok(context)
}

#[test]
fn contribution_contexts_preserve_frozen_v1_and_bind_v2() -> TestResult {
    let old = witness_corpus()?;
    for vector in old["construction_vector"]["contributions"]
        .as_array()
        .ok_or("missing contributions")?
    {
        let info = bytes(vector, "info_hex")?;
        let aad = bytes(vector, "aad_hex")?;
        let context = contribution(&info, &aad, VaultSuite::Suite1)?;
        assert_eq!(context.info_preimage(), info);
        assert_eq!(context.aad_preimage(), aad);
    }
    let corpus = new_corpus()?;
    let mut checked = 0;
    for vector in corpus["vectors"].as_array().ok_or("missing vectors")? {
        if !hex_value(vector, "name")?.starts_with("contribution-") {
            continue;
        }
        let info = bytes(vector, "info")?;
        let aad = bytes(vector, "aad")?;
        let mut context = contribution(&info, &aad, VaultSuite::Suite2)?;
        assert_eq!(context.info_preimage(), info);
        assert_eq!(context.aad_preimage(), aad);
        context.suite = VaultSuite::Suite1;
        assert_ne!(context.info_preimage(), info);
        assert_ne!(context.aad_preimage(), aad);
        checked += 1;
    }
    assert_eq!(checked, 2);
    Ok(())
}
