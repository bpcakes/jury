use super::*;

pub(super) fn string_field<'a>(value: &'a Value, field: &str) -> AnyResult<&'a str> {
    value[field]
        .as_str()
        .ok_or_else(|| format!("missing string field {field}"))
}

pub(super) fn decode_field(value: &Value, field: &str) -> AnyResult<Vec<u8>> {
    hex::decode(string_field(value, field)?)
        .map_err(|error| format!("decode field {field}: {error}"))
}

pub(super) fn consume_automatic_target(vector: &Value) -> AnyResult<()> {
    let bytes = decode_field(vector, "body_hex")?;
    let item = decode_field(vector, "item_id_hex")?;
    if item.len() != 32
        || item.iter().all(|byte| *byte == 0)
        || bytes.get(..32) != Some(item.as_slice())
    {
        return Err("automatic target item mismatch".to_owned());
    }
    match vector["content_role"].as_u64() {
        Some(1)
            if vector.get("field_id_hex").is_some_and(Value::is_null)
                && bytes.get(32..) == Some(&[1, 0]) =>
        {
            Ok(())
        }
        Some(2) => {
            let field = decode_field(vector, "field_id_hex")?;
            if field.len() == 32
                && field.iter().any(|byte| *byte != 0)
                && bytes.len() == 66
                && bytes[32..34] == [2, 1]
                && bytes[34..] == field
            {
                Ok(())
            } else {
                Err("automatic body target must contain one exact field".to_owned())
            }
        }
        _ => Err("invalid automatic target role or field encoding".to_owned()),
    }
}

pub fn consume_corpus(corpus: &Value) -> AnyResult<()> {
    if corpus["schema"] != "jury-witness-v1-conformance-corpus" || corpus["schema_version"] != 1 {
        return Err("unknown corpus schema".to_owned());
    }
    let vectors = corpus["vectors"]
        .as_object()
        .ok_or_else(|| "vectors must be an object".to_owned())?;
    for (name, vector) in vectors {
        if vector["kind"] == "automatic-target" {
            consume_automatic_target(vector)?;
        }
        if vector["kind"] == "owner-change-context" {
            let change = vector["change"]
                .as_u64()
                .and_then(|v| u8::try_from(v).ok())
                .ok_or("invalid change")?;
            let target = decode_field(vector, "target_principal_id_hex")?;
            let sequence = vector["next_sequence"].as_u64().ok_or("invalid sequence")?;
            let expected = owner_change_context_vector(name, change, &target, sequence)?;
            for field in ["domain", "body_hex", "preimage_hex", "digest_hex"] {
                if vector[field] != expected[field] {
                    return Err(format!("{name}: owner-change {field} mismatch"));
                }
            }
        }
        if vector["kind"] == "active-policy-set" {
            let digests =
                digest_list(&vector["policy_digests_hex"]).ok_or("invalid policy-set digests")?;
            let expected = active_policy_set_vector(name, &digests)?;
            for field in ["body_hex", "preimage_hex", "digest_hex"] {
                if vector[field] != expected[field] {
                    return Err(format!("{name}: policy-set {field} mismatch"));
                }
            }
        }

        if let Some(signature_hex) = vector["signature_hex"].as_str() {
            let signature_bytes =
                hex::decode(signature_hex).map_err(|error| format!("{name}: {error}"))?;
            let signature = Signature::from_slice(&signature_bytes)
                .map_err(|error| format!("{name}: signature: {error}"))?;
            let public_bytes = decode_field(vector, "signing_public_key_hex")?;
            let public_array: [u8; 32] = public_bytes
                .try_into()
                .map_err(|_| format!("{name}: public key length"))?;
            let public = VerifyingKey::from_bytes(&public_array)
                .map_err(|error| format!("{name}: public key: {error}"))?;
            let preimage = decode_field(vector, "preimage_hex")?;
            public
                .verify(&preimage, &signature)
                .map_err(|error| format!("{name}: signature verification: {error}"))?;
            if let Some(hash_domain) = vector["hash_domain"].as_str() {
                let expected =
                    hash_preimage(hash_domain, &[bytes_field(&preimage)?, signature_bytes]);
                if decode_field(vector, "digest_hex")? != expected {
                    return Err(format!("{name}: signed digest mismatch"));
                }
            }
        }
        if let (Some(_domain), Some(preimage_hex), Some(digest_hex)) = (
            vector["domain"].as_str(),
            vector["preimage_hex"].as_str(),
            vector["digest_hex"].as_str(),
        ) {
            let preimage = hex::decode(preimage_hex).map_err(|error| format!("{name}: {error}"))?;
            if hex_bytes(&sha256(&preimage)) != digest_hex {
                return Err(format!("{name}: digest mismatch"));
            }
        }
        if vector["fingerprint_domain"].is_string() {
            let fingerprint_preimage = decode_field(vector, "fingerprint_preimage_hex")?;
            if sha256(&fingerprint_preimage).as_slice() != decode_field(vector, "fingerprint_hex")?
            {
                return Err(format!("{name}: descriptor fingerprint mismatch"));
            }
        }
    }

    let mutations = corpus["byte_mutations"]
        .as_array()
        .ok_or_else(|| "byte_mutations must be an array".to_owned())?;
    for mutation in mutations {
        let Some(source) = mutation["source"].as_str() else {
            continue;
        };
        let Some(vector) = vectors.get(source) else {
            continue;
        };
        if let Some(mutated_hex) = mutation["mutated_signature_hex"].as_str() {
            let signature_bytes =
                hex::decode(mutated_hex).map_err(|error| format!("mutated signature: {error}"))?;
            let signature = Signature::from_slice(&signature_bytes)
                .map_err(|error| format!("mutated signature: {error}"))?;
            let public_bytes = decode_field(vector, "signing_public_key_hex")?;
            let public_array: [u8; 32] = public_bytes
                .try_into()
                .map_err(|_| "mutated public key length".to_owned())?;
            let public = VerifyingKey::from_bytes(&public_array)
                .map_err(|error| format!("mutated public key: {error}"))?;
            if public
                .verify(&decode_field(vector, "preimage_hex")?, &signature)
                .is_ok()
            {
                return Err(format!("{source}: mutated signature accepted"));
            }
        } else if mutation["mutation"] == "prepend wrong-domain byte to signed preimage" {
            let signature_bytes = decode_field(vector, "signature_hex")?;
            let signature = Signature::from_slice(&signature_bytes)
                .map_err(|error| format!("wrong-domain signature: {error}"))?;
            let public_bytes = decode_field(vector, "signing_public_key_hex")?;
            let public_array: [u8; 32] = public_bytes
                .try_into()
                .map_err(|_| "wrong-domain public key length".to_owned())?;
            let public = VerifyingKey::from_bytes(&public_array)
                .map_err(|error| format!("wrong-domain public key: {error}"))?;
            let mut wrong_preimage = vec![0xff];
            wrong_preimage.extend(decode_field(vector, "preimage_hex")?);
            if public.verify(&wrong_preimage, &signature).is_ok() {
                return Err(format!("{source}: wrong domain accepted"));
            }
        }
    }

    consume_construction(&corpus["construction_vector"])?;
    consume_registration(vectors)?;
    consume_cases(corpus)?;
    Ok(())
}

pub(super) fn decode_string_array(value: &Value) -> AnyResult<Vec<Vec<u8>>> {
    value
        .as_array()
        .ok_or_else(|| "expected string array".to_owned())?
        .iter()
        .map(|entry| {
            let encoded = entry
                .as_str()
                .ok_or_else(|| "array entry must be a string".to_owned())?;
            hex::decode(encoded).map_err(|error| format!("array hex: {error}"))
        })
        .collect()
}

pub(super) fn consume_construction(construction: &Value) -> AnyResult<()> {
    if construction["epoch_root"] != Value::Null || construction["reusable_contribution"] != false {
        return Err("construction exposes reusable material".to_owned());
    }
    let secret = decode_field(construction, "revision_secret_hex")?;
    let shares = decode_string_array(&construction["shares"])?;
    let reconstructed = Gf256::combine_bytes(&shares[0..WITNESS_THRESHOLD])
        .map_err(|error| format!("consumer combine: {error:?}"))?;
    if reconstructed != secret {
        return Err("consumer reconstruction mismatch".to_owned());
    }
    if let Ok(one_share) = Gf256::combine_bytes(std::slice::from_ref(&shares[0]))
        && one_share == secret
    {
        return Err("one share reconstructed threshold secret".to_owned());
    }

    let later = &construction["later_revision"];
    let later_secret = decode_field(later, "revision_secret_hex")?;
    let later_shares = decode_string_array(&later["shares"])?;
    let later_reconstructed = Gf256::combine_bytes(&later_shares[0..WITNESS_THRESHOLD])
        .map_err(|error| format!("consumer later combine: {error:?}"))?;
    if later_reconstructed != later_secret
        || decode_field(later, "cross_revision_share_result_hex")? == later_secret
    {
        return Err("later revision separation failed".to_owned());
    }

    let capsules = construction["capsules"]
        .as_array()
        .ok_or_else(|| "capsules must be an array".to_owned())?;
    for (index, capsule) in capsules.iter().enumerate() {
        let plaintext = hpke_open(
            &decode_field(capsule, "recipient_private_seed_hex")?,
            &decode_field(capsule, "enc_hex")?,
            &decode_field(capsule, "ciphertext_hex")?,
            &decode_field(capsule, "info_hex")?,
            &decode_field(capsule, "aad_hex")?,
        )?;
        if plaintext != shares[index] {
            return Err(format!("capsule {index}: wrong share"));
        }
        let expected_commitment = hash_preimage(
            "jury-witness-v1/share/commitment",
            &[
                decode_field(capsule, "context_digest_hex")?,
                plaintext.clone(),
            ],
        );
        if expected_commitment.as_slice() != decode_field(capsule, "share_commitment_hex")? {
            return Err(format!("capsule {index}: commitment mismatch"));
        }
        let mut ciphertext = decode_field(capsule, "ciphertext_hex")?;
        let first = ciphertext
            .first_mut()
            .ok_or_else(|| format!("capsule {index}: empty ciphertext"))?;
        *first ^= 1;
        if hpke_open(
            &decode_field(capsule, "recipient_private_seed_hex")?,
            &decode_field(capsule, "enc_hex")?,
            &ciphertext,
            &decode_field(capsule, "info_hex")?,
            &decode_field(capsule, "aad_hex")?,
        )
        .is_ok()
        {
            return Err(format!("capsule {index}: mutation opened"));
        }
    }
    let capsule_bytes = capsules
        .iter()
        .map(|capsule| decode_field(capsule, "capsule_hex"))
        .collect::<AnyResult<Vec<_>>>()?;
    let expected_capsule_set = hash_preimage(
        "jury-witness-v1/capsule-set/hash",
        &[list_bytes(&capsule_bytes)?],
    );
    if expected_capsule_set.as_slice() != decode_field(construction, "capsule_set_digest_hex")? {
        return Err("capsule-set digest mismatch".to_owned());
    }
    let witnessed_slot = decode_field(construction, "witnessed_slot_hex")?;
    let expected_slot_digest = hash_preimage(
        "jury-witness-v1/slot/hash",
        &[bytes_field(&witnessed_slot)?],
    );
    if expected_slot_digest.as_slice() != decode_field(construction, "witnessed_slot_digest_hex")? {
        return Err("witnessed-slot digest mismatch".to_owned());
    }
    let expected_state_digest = hash_preimage(
        "jury-witness-v1/slot-set/hash",
        &[list_bytes(std::slice::from_ref(&witnessed_slot))?],
    );
    if expected_state_digest.as_slice() != decode_field(construction, "witnessed_state_digest_hex")?
    {
        return Err("witnessed-state digest mismatch".to_owned());
    }

    let contributions = construction["contributions"]
        .as_array()
        .ok_or_else(|| "contributions must be an array".to_owned())?;
    let mut opened = Vec::new();
    for (index, contribution) in contributions.iter().enumerate() {
        let plaintext = hpke_open(
            &decode_field(contribution, "request_session_private_seed_hex")?,
            &decode_field(contribution, "enc_hex")?,
            &decode_field(contribution, "ciphertext_hex")?,
            &decode_field(contribution, "info_hex")?,
            &decode_field(contribution, "aad_hex")?,
        )?;
        if plaintext != decode_field(contribution, "plaintext_share_hex")? {
            return Err(format!("contribution {index}: wrong share"));
        }
        let envelope = decode_field(contribution, "envelope_hex")?;
        let digest = hash_preimage(
            "jury-witness-v1/contribution/hash",
            &[bytes_field(&envelope)?],
        );
        if digest.as_slice() != decode_field(contribution, "digest_hex")? {
            return Err(format!("contribution {index}: digest mismatch"));
        }
        opened.push(plaintext);
        let mut ciphertext = decode_field(contribution, "ciphertext_hex")?;
        let first = ciphertext
            .first_mut()
            .ok_or_else(|| format!("contribution {index}: empty ciphertext"))?;
        *first ^= 1;
        if hpke_open(
            &decode_field(contribution, "request_session_private_seed_hex")?,
            &decode_field(contribution, "enc_hex")?,
            &ciphertext,
            &decode_field(contribution, "info_hex")?,
            &decode_field(contribution, "aad_hex")?,
        )
        .is_ok()
        {
            return Err(format!("contribution {index}: mutation opened"));
        }
    }
    let assembled = Gf256::combine_bytes(opened)
        .map_err(|error| format!("consumer contribution assembly: {error:?}"))?;
    if assembled != secret {
        return Err("consumer contribution assembly mismatch".to_owned());
    }
    Ok(())
}

pub(super) fn consume_registration(vectors: &Map<String, Value>) -> AnyResult<()> {
    let vector = vectors
        .get("registration_key_proof")
        .ok_or_else(|| "missing registration key proof".to_owned())?;
    let plaintext = hpke_open(
        &decode_field(vector, "recipient_private_seed_hex")?,
        &decode_field(vector, "enc_hex")?,
        &decode_field(vector, "ciphertext_hex")?,
        &decode_field(vector, "info_hex")?,
        &decode_field(vector, "aad_hex")?,
    )?;
    if plaintext != decode_field(vector, "plaintext_hex")? {
        return Err("registration challenge plaintext mismatch".to_owned());
    }
    let mut mac = Hmac::<Sha256>::new_from_slice(&plaintext)
        .map_err(|error| format!("registration HMAC key: {error}"))?;
    mac.update(&decode_field(vector, "hmac_data_hex")?);
    let expected = mac.finalize().into_bytes();
    if expected.as_slice() != decode_field(vector, "hmac_hex")? {
        return Err("registration HMAC mismatch".to_owned());
    }
    Ok(())
}

pub(super) fn consume_cases(corpus: &Value) -> AnyResult<()> {
    let scope_cases = corpus["scope_cases"]
        .as_array()
        .ok_or_else(|| "scope cases must be an array".to_owned())?;
    for case in scope_cases {
        let request: BTreeMap<String, String> = serde_json::from_value(case["request"].clone())
            .map_err(|error| format!("scope request: {error}"))?;
        let manifest: BTreeMap<String, String> =
            serde_json::from_value(case["manifest"].clone())
                .map_err(|error| format!("scope manifest: {error}"))?;
        if scope_result(&request, &manifest) != string_field(case, "expected")? {
            return Err(format!(
                "scope case {} disagreed",
                string_field(case, "name")?
            ));
        }
    }
    for case in corpus["presentation_cases"]
        .as_array()
        .ok_or_else(|| "presentation cases must be an array".to_owned())?
    {
        if presentation_result(case) != string_field(case, "expected")? {
            return Err(format!(
                "presentation case {} disagreed",
                string_field(case, "name")?
            ));
        }
    }
    for case in corpus["protocol_cases"]
        .as_array()
        .ok_or_else(|| "protocol cases must be an array".to_owned())?
    {
        if protocol_case_result(case) != string_field(case, "expected")? {
            return Err(format!(
                "protocol case {} disagreed",
                string_field(case, "name")?
            ));
        }
    }
    for case in corpus["split_write_cases"]
        .as_array()
        .ok_or_else(|| "split-write cases must be an array".to_owned())?
    {
        if split_write_result(case) != string_field(case, "expected")? {
            return Err(format!(
                "split-write case {} disagreed",
                string_field(case, "name")?
            ));
        }
    }
    let counts = run_model_counts();
    let result = &corpus["retention_model"]["result"];
    for (name, actual) in [
        ("states", counts.states),
        ("applicable_states", counts.applicable_states),
        ("earlier_reopens", counts.earlier_reopens),
        (
            "old_approval_replay_attempts",
            counts.old_approval_replay_attempts,
        ),
        (
            "old_response_replay_attempts",
            counts.old_response_replay_attempts,
        ),
        (
            "prior_state_authorizations",
            counts.prior_state_authorizations,
        ),
        (
            "later_opens_with_fresh_quorum",
            counts.later_opens_with_fresh_quorum,
        ),
        ("excluded_direct_or_mixed", counts.excluded_direct_or_mixed),
        (
            "excluded_witness_threshold",
            counts.excluded_witness_threshold,
        ),
        ("authorization_compromise", counts.authorization_compromise),
        ("counterexamples", counts.counterexamples),
    ] {
        if result[name].as_u64() != Some(actual) {
            return Err(format!("model count {name} disagreed"));
        }
    }
    if counts.counterexamples != 0 || counts.prior_state_authorizations != 0 {
        return Err(format!(
            "retention model found {} decryption and {} authorization counterexamples",
            counts.counterexamples, counts.prior_state_authorizations
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn automatic_target_encoding_rejects_legacy_and_cross_role_shapes() -> Result<(), String> {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("vectors.json");
        let corpus: Value =
            serde_json::from_slice(&fs::read(path).map_err(|error| error.to_string())?)
                .map_err(|error| error.to_string())?;
        let descriptor = &corpus["vectors"]["automatic_descriptor_target"];
        consume_automatic_target(descriptor)?;
        let mut legacy = descriptor.clone();
        let mut bytes = decode_field(&legacy, "body_hex")?;
        bytes.remove(32);
        legacy["body_hex"] = hex_bytes(&bytes).into();
        assert!(consume_automatic_target(&legacy).is_err());
        let mut whole_body = descriptor.clone();
        whole_body["content_role"] = 2.into();
        let mut bytes = decode_field(&whole_body, "body_hex")?;
        bytes[32] = 2;
        whole_body["body_hex"] = hex_bytes(&bytes).into();
        assert!(consume_automatic_target(&whole_body).is_err());
        let mut field = corpus["vectors"]["automatic_field_target"].clone();
        consume_automatic_target(&field)?;
        field["content_role"] = 1.into();
        let mut bytes = decode_field(&field, "body_hex")?;
        bytes[32] = 1;
        field["body_hex"] = hex_bytes(&bytes).into();
        assert!(consume_automatic_target(&field).is_err());
        Ok(())
    }

    #[test]
    fn active_policy_set_rejects_noncanonical_sets_and_framing() -> Result<(), String> {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("vectors.json");
        let corpus: Value =
            serde_json::from_slice(&fs::read(path).map_err(|error| error.to_string())?)
                .map_err(|error| error.to_string())?;
        for digests in [
            vec![id(0xe2), id(0xe1)],
            vec![id(0xe1), id(0xe1)],
            vec![id(0)],
        ] {
            let mut changed = corpus.clone();
            let vector = &mut changed["vectors"]["active_policy_set_multiple"];
            vector["policy_digests_hex"] =
                json!(digests.iter().map(|d| hex_bytes(d)).collect::<Vec<_>>());
            let mut body = u32be(u32::try_from(digests.len()).map_err(|_| "count")?);
            body.extend(digests.concat());
            let preimage = jce(
                "jury-witness-v1/active-policy-set/hash",
                std::slice::from_ref(&body),
            );
            vector["body_hex"] = hex_bytes(&body).into();
            vector["preimage_hex"] = hex_bytes(&preimage).into();
            vector["digest_hex"] = hex_bytes(&sha256(&preimage)).into();
            assert!(consume_corpus(&changed).is_err());
        }
        let mut changed = corpus.clone();
        let vector = &mut changed["vectors"]["active_policy_set_multiple"];
        let body = decode_field(vector, "body_hex")?;
        let wrapped = jce(
            "jury-witness-v1/active-policy-set/hash",
            &[bytes_field(&body)?],
        );
        vector["preimage_hex"] = hex_bytes(&wrapped).into();
        vector["digest_hex"] = hex_bytes(&sha256(&wrapped)).into();
        assert!(consume_corpus(&changed).is_err());
        Ok(())
    }

    #[test]
    fn owner_change_context_rejects_unknown_tags_and_noncanonical_framing() -> Result<(), String> {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("vectors.json");
        let corpus: Value = serde_json::from_slice(&fs::read(path).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
        for (change, target, sequence) in [(3, id(0x71), 8), (1, id(0), 8), (1, id(0x71), 0)] {
            let mut changed = corpus.clone();
            let vector = &mut changed["vectors"]["owner_change_grant_context"];
            vector["change"] = json!(change);
            vector["target_principal_id_hex"] = json!(hex_bytes(&target));
            vector["next_sequence"] = json!(sequence);
            let body = [u16be(1), vec![change], target, u64be(sequence)].concat();
            let encoded = jce(
                "jury-witness-v1/operation-context/owner-change",
                std::slice::from_ref(&body),
            );
            vector["body_hex"] = json!(hex_bytes(&body));
            vector["preimage_hex"] = json!(hex_bytes(&encoded));
            vector["digest_hex"] = json!(hex_bytes(&sha256(&encoded)));
            assert!(consume_corpus(&changed).is_err());
        }
        let mut changed = corpus.clone();
        let vector = &mut changed["vectors"]["owner_change_grant_context"];
        let body = decode_field(vector, "body_hex")?;
        let encoded = jce(
            "jury-witness-v1/operation-context/owner-change",
            &[bytes_field(&body)?],
        );
        vector["preimage_hex"] = json!(hex_bytes(&encoded));
        vector["digest_hex"] = json!(hex_bytes(&sha256(&encoded)));
        assert!(consume_corpus(&changed).is_err());
        Ok(())
    }

    #[test]
    fn checked_in_corpus_matches_generation_and_consumes() -> Result<(), String> {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("vectors.json");
        check_corpus(&path)?;
        let bytes = fs::read(&path).map_err(|error| format!("read corpus: {error}"))?;
        let corpus: Value =
            serde_json::from_slice(&bytes).map_err(|error| format!("parse corpus: {error}"))?;
        consume_corpus(&corpus)
    }
}
