use super::*;

mod fixtures;
use fixtures::{RequestFixture, RevisionShares, build_request_vectors, build_revision_shares};

pub(super) fn build_protocol_vectors() -> AnyResult<(Map<String, Value>, Value)> {
    let RequestFixture {
        vault_id,
        genesis,
        item_id,
        slot_id,
        seal_id,
        request_id,
        requester_id,
        owner_id,
        witness_policy_id,
        issued_at,
        expires_at,
        requester_key,
        owner_key,
        witness_signing_keys,
        approver_ids,
        witness_ids,
        requester_fingerprint,
        owner_fingerprint,
        mut vectors,
        witness_descriptors,
        witness_descriptor_fingerprints,
        witness_signing_fingerprints,
        contribution_private_keys,
        contribution_public_keys,
        contribution_fingerprints,
        witness_policy_digest,
        policy_material,
        checkpoint_bytes,
        checkpoint_digest,
        presentation_digest,
        approval_target_digest,
        workload_digest,
        action_manifest_digest,
        session_fingerprint,
        request_message,
        request_digest,
        request_signature_preimage,
        client_signature,
        approval_messages,
        session_private,
        session_public,
    } = build_request_vectors()?;
    let RevisionShares {
        revision_secret,
        shares,
        later_revision_secret,
        later_shares,
        later_reconstructed,
        cross_revision_result,
    } = build_revision_shares()?;

    let mut capsule_contexts = Vec::new();
    let mut share_commitments = Vec::new();
    let mut capsules = Vec::new();
    let mut capsule_json = Vec::new();
    for index in 0..WITNESS_COUNT {
        let context_fields = vec![
            u16be(1),
            u16be(1),
            u16be(1),
            vault_id.clone(),
            genesis.clone(),
            item_id.clone(),
            u64be(3),
            vec![2],
            slot_id.clone(),
            vec![2],
            u64be(4),
            seal_id.clone(),
            u64be(7),
            witness_policy_id.clone(),
            u64be(1),
            witness_policy_digest.clone(),
            vec![2],
            vec![3],
            witness_ids[index].clone(),
            contribution_fingerprints[index].to_vec(),
            vec![u8::try_from(index + 1).map_err(|_| "share index")?],
        ];
        let context_preimage = jce("jury-witness-v1/capsule/context", &context_fields);
        let context_digest = sha256(&context_preimage);
        let commitment = hash_preimage(
            "jury-witness-v1/share/commitment",
            &[context_digest.to_vec(), shares[index].clone()],
        );
        let info = jce(
            "jury-witness-v1/capsule/info",
            &[
                context_digest.to_vec(),
                witness_ids[index].clone(),
                contribution_fingerprints[index].to_vec(),
                vec![u8::try_from(index + 1).map_err(|_| "share index")?],
            ],
        );
        let aad = jce(
            "jury-witness-v1/capsule/aad",
            &[
                context_digest.to_vec(),
                commitment.to_vec(),
                witness_policy_digest.clone(),
                u64be(7),
            ],
        );
        let (enc, ciphertext) = hpke_seal(
            &contribution_public_keys[index],
            &shares[index],
            &info,
            &aad,
            0xa0 + u8::try_from(index).map_err(|_| "capsule seed")?,
        )?;
        let capsule = [
            context_fields.concat(),
            context_digest.to_vec(),
            commitment.to_vec(),
            enc.clone(),
            ciphertext.clone(),
        ]
        .concat();
        capsule_contexts.push(context_digest);
        share_commitments.push(commitment);
        capsules.push(capsule.clone());
        capsule_json.push(json!({
            "witness_id_hex": hex_bytes(&witness_ids[index]),
            "share_index": index + 1,
            "context_preimage_hex": hex_bytes(&context_preimage),
            "context_digest_hex": hex_bytes(&context_digest),
            "share_hex": hex_bytes(&shares[index]),
            "share_commitment_hex": hex_bytes(&commitment),
            "info_hex": hex_bytes(&info),
            "aad_hex": hex_bytes(&aad),
            "recipient_private_seed_hex": hex_bytes(&contribution_private_keys[index]),
            "recipient_public_key_hex": hex_bytes(&contribution_public_keys[index]),
            "enc_hex": hex_bytes(&enc),
            "ciphertext_hex": hex_bytes(&ciphertext),
            "capsule_hex": hex_bytes(&capsule)
        }));
    }
    let capsule_set_digest = hash_preimage(
        "jury-witness-v1/capsule-set/hash",
        &[list_bytes(&capsules)?],
    );
    let witnessed_slot = [
        vec![1],
        vec![2],
        u16be(1),
        u16be(1),
        u16be(1),
        vault_id.clone(),
        genesis.clone(),
        item_id.clone(),
        u64be(3),
        vec![2],
        slot_id.clone(),
        vec![2],
        u64be(4),
        seal_id.clone(),
        u64be(7),
        witness_policy_id.clone(),
        u64be(1),
        witness_policy_digest.clone(),
        vec![2],
        vec![3],
        list_bytes(&capsules)?,
        capsule_set_digest.to_vec(),
    ]
    .concat();
    let witnessed_slot_digest = hash_preimage(
        "jury-witness-v1/slot/hash",
        &[bytes_field(&witnessed_slot)?],
    );
    let witnessed_state_digest = hash_preimage(
        "jury-witness-v1/slot-set/hash",
        &[list_bytes(std::slice::from_ref(&witnessed_slot))?],
    );

    let mut contribution_envelopes = Vec::new();
    let mut contribution_json = Vec::new();
    let mut witness_messages = Vec::new();
    let mut witness_responses = Vec::new();
    for index in 0..WITNESS_THRESHOLD {
        let response_id = id(0xb0 + u8::try_from(index).map_err(|_| "response id")?);
        let info = jce(
            "jury-witness-v1/contribution/info",
            &[
                request_digest.clone(),
                action_manifest_digest.clone(),
                response_id.clone(),
                witness_ids[index].clone(),
                witness_policy_digest.clone(),
                checkpoint_digest.clone(),
                share_commitments[index].to_vec(),
                vec![u8::try_from(index + 1).map_err(|_| "share index")?],
            ],
        );
        let aad = jce(
            "jury-witness-v1/contribution/aad",
            &[
                capsule_set_digest.to_vec(),
                capsule_contexts[index].to_vec(),
                session_fingerprint.to_vec(),
                u64be(expires_at),
            ],
        );
        let (enc, ciphertext) = hpke_seal(
            &session_public,
            &shares[index],
            &info,
            &aad,
            0xc0 + u8::try_from(index).map_err(|_| "contribution seed")?,
        )?;
        let envelope = [
            u16be(1),
            response_id.clone(),
            vec![u8::try_from(index + 1).map_err(|_| "share index")?],
            share_commitments[index].to_vec(),
            capsule_contexts[index].to_vec(),
            capsule_set_digest.to_vec(),
            session_fingerprint.to_vec(),
            enc.clone(),
            ciphertext.clone(),
        ]
        .concat();
        let contribution_digest = hash_preimage(
            "jury-witness-v1/contribution/hash",
            &[bytes_field(&envelope)?],
        );
        contribution_envelopes.push(envelope.clone());
        contribution_json.push(json!({
            "witness_id_hex": hex_bytes(&witness_ids[index]),
            "response_id_hex": hex_bytes(&response_id),
            "share_index": index + 1,
            "info_hex": hex_bytes(&info),
            "aad_hex": hex_bytes(&aad),
            "request_session_private_seed_hex": hex_bytes(&session_private),
            "request_session_public_key_hex": hex_bytes(&session_public),
            "enc_hex": hex_bytes(&enc),
            "ciphertext_hex": hex_bytes(&ciphertext),
            "envelope_hex": hex_bytes(&envelope),
            "digest_hex": hex_bytes(&contribution_digest),
            "plaintext_share_hex": hex_bytes(&shares[index])
        }));

        let decision_fields = vec![
            u16be(1),
            response_id,
            request_id.clone(),
            request_digest.clone(),
            action_manifest_digest.clone(),
            witness_ids[index].clone(),
            witness_signing_fingerprints[index].to_vec(),
            u64be(1),
            witness_policy_id.clone(),
            u64be(1),
            witness_policy_digest.clone(),
            checkpoint_digest.clone(),
            u64be(2 + u64::try_from(index).map_err(|_| "state generation")?),
            vec![1],
            vec![0],
            u64be(issued_at + 2_000),
            u64be(expires_at),
            optional(Some(&contribution_digest)),
            optional(Some(&[u8::try_from(index + 1).map_err(|_| "share index")?])),
            optional(Some(&share_commitments[index])),
        ];
        let vector = signed_vector(
            &format!("witness_decision_{}", index + 1),
            "jury-witness-v1/decision/signature",
            "jury-witness-v1/decision/hash",
            &decision_fields,
            &witness_signing_keys[index],
        )?;
        let decision_message = vector_bytes(&vector, "message_hex")?;
        let response = [decision_message.clone(), envelope].concat();
        witness_messages.push(decision_message);
        witness_responses.push(response.clone());
        contribution_json[index]["response_hex"] = json!(hex_bytes(&response));
        vectors.insert(format!("witness_decision_{}", index + 1), vector);
    }
    let contribution_shares: Vec<Vec<u8>> = contribution_json
        .iter()
        .map(|entry| {
            let value = entry["plaintext_share_hex"].as_str().unwrap_or("");
            hex::decode(value).unwrap_or_default()
        })
        .collect();
    let assembled = Gf256::combine_bytes(contribution_shares)
        .map_err(|error| format!("assemble contributions: {error:?}"))?;
    if assembled != revision_secret {
        return Err("contribution assembly mismatch".to_owned());
    }
    let construction = json!({
        "construction": "jury-witness-v1-shamir-xwing-hpke",
        "suite": 1,
        "threshold": WITNESS_THRESHOLD,
        "member_count": WITNESS_COUNT,
        "revision_secret_hex": hex_bytes(&revision_secret),
        "share_rng_seed_hex": hex_bytes(&[0x92; 32]),
        "shares": shares.iter().map(|share| hex_bytes(share)).collect::<Vec<_>>(),
        "later_revision": {
            "revision_seal_id_hex": hex_bytes(&id(0x95)),
            "revision_secret_hex": hex_bytes(&later_revision_secret),
            "share_rng_seed_hex": hex_bytes(&[0x94; 32]),
            "shares": later_shares.iter().map(|share| hex_bytes(share)).collect::<Vec<_>>(),
            "reconstructed_revision_secret_hex": hex_bytes(&later_reconstructed),
            "cross_revision_share_result_hex": hex_bytes(&cross_revision_result),
            "prior_state_opens_later_revision": false
        },
        "capsule_set_digest_hex": hex_bytes(&capsule_set_digest),
        "witnessed_slot_hex": hex_bytes(&witnessed_slot),
        "witnessed_slot_digest_hex": hex_bytes(&witnessed_slot_digest),
        "witnessed_state_digest_hex": hex_bytes(&witnessed_state_digest),
        "capsules": capsule_json,
        "contributions": contribution_json,
        "selected_share_indexes": [1, 2],
        "reconstructed_revision_secret_hex": hex_bytes(&assembled),
        "reusable_contribution": false,
        "epoch_root": null
    });

    let cancellation_fields = vec![
        u16be(1),
        id(0xd0),
        bytes_field(&request_signature_preimage)?,
        client_signature.clone(),
        request_id.clone(),
        request_digest.clone(),
        requester_id.clone(),
        requester_fingerprint.to_vec(),
        u64be(1),
        vec![1],
        u64be(issued_at + 3_000),
        vec![0x0b],
        id(0xd1),
    ];
    let cancellation = signed_vector(
        "request_cancellation",
        "jury-witness-v1/cancellation/signature",
        "jury-witness-v1/cancellation/hash",
        &cancellation_fields,
        &requester_key,
    )?;
    vectors.insert("request_cancellation".to_owned(), cancellation);

    let registration_id = id(0xd2);
    let registration_challenge_plaintext = fixed(0xd3, 32);
    let registration_info = jce(
        "jury-witness-v1/registration/info",
        &[
            registration_id.clone(),
            vault_id.clone(),
            genesis.clone(),
            witness_descriptor_fingerprints[0].clone(),
            contribution_fingerprints[0].to_vec(),
            checkpoint_digest.clone(),
        ],
    );
    let registration_aad = jce(
        "jury-witness-v1/registration/aad",
        &[
            u64be(issued_at),
            u64be(expires_at),
            owner_id.clone(),
            owner_fingerprint.to_vec(),
            u64be(1),
            witness_ids[0].clone(),
        ],
    );
    let (registration_enc, registration_ciphertext) = hpke_seal(
        &contribution_public_keys[0],
        &registration_challenge_plaintext,
        &registration_info,
        &registration_aad,
        0xd4,
    )?;
    let registration_challenge_fields = vec![
        u16be(1),
        registration_id.clone(),
        vault_id.clone(),
        genesis.clone(),
        bytes_field(&witness_descriptors[0])?,
        witness_descriptor_fingerprints[0].clone(),
        bytes_field(&checkpoint_bytes)?,
        checkpoint_digest.clone(),
        u64be(issued_at),
        u64be(expires_at),
        owner_id.clone(),
        owner_fingerprint.to_vec(),
        u64be(1),
        registration_enc.clone(),
        registration_ciphertext.clone(),
    ];
    let registration_challenge = signed_vector(
        "registration_challenge",
        "jury-witness-v1/registration/challenge-signature",
        "jury-witness-v1/registration/challenge-hash",
        &registration_challenge_fields,
        &owner_key,
    )?;
    let registration_challenge_digest = vector_bytes(&registration_challenge, "digest_hex")?;
    let registration_challenge_message = vector_bytes(&registration_challenge, "message_hex")?;
    vectors.insert("registration_challenge".to_owned(), registration_challenge);
    let key_proof_data = jce(
        "jury-witness-v1/registration/key-proof",
        &[
            registration_id.clone(),
            vault_id.clone(),
            genesis.clone(),
            witness_descriptor_fingerprints[0].clone(),
            checkpoint_digest.clone(),
            registration_enc.clone(),
            registration_ciphertext.clone(),
        ],
    );
    let mut mac = Hmac::<Sha256>::new_from_slice(&registration_challenge_plaintext)
        .map_err(|error| format!("HMAC key: {error}"))?;
    mac.update(&key_proof_data);
    let key_proof = mac.finalize().into_bytes().to_vec();
    let registration_response_fields = vec![
        u16be(1),
        registration_id.clone(),
        registration_challenge_digest.clone(),
        witness_ids[0].clone(),
        witness_signing_fingerprints[0].to_vec(),
        u64be(1),
        contribution_fingerprints[0].to_vec(),
        u64be(1),
        key_proof.clone(),
        u64be(issued_at + 1_000),
    ];
    let registration_response = signed_vector(
        "registration_response",
        "jury-witness-v1/registration/response-signature",
        "jury-witness-v1/registration/response-hash",
        &registration_response_fields,
        &witness_signing_keys[0],
    )?;
    let registration_response_digest = vector_bytes(&registration_response, "digest_hex")?;
    let registration_response_message = vector_bytes(&registration_response, "message_hex")?;
    vectors.insert("registration_response".to_owned(), registration_response);
    let registration_acceptance_fields = vec![
        u16be(1),
        registration_id.clone(),
        registration_challenge_digest.clone(),
        registration_response_digest.clone(),
        witness_descriptor_fingerprints[0].clone(),
        checkpoint_digest.clone(),
        u64be(issued_at + 2_000),
        owner_id.clone(),
        owner_fingerprint.to_vec(),
        u64be(1),
    ];
    let registration_acceptance = signed_vector(
        "registration_acceptance",
        "jury-witness-v1/registration/acceptance-signature",
        "jury-witness-v1/registration/acceptance-hash",
        &registration_acceptance_fields,
        &owner_key,
    )?;
    let registration_acceptance_message = vector_bytes(&registration_acceptance, "message_hex")?;
    vectors.insert(
        "registration_acceptance".to_owned(),
        registration_acceptance,
    );
    let registration_body = [
        bytes_field(&registration_challenge_message)?,
        bytes_field(&registration_response_message)?,
        bytes_field(&registration_acceptance_message)?,
    ]
    .concat();
    vectors.insert(
        "witness_registration".to_owned(),
        digest_vector(
            "witness_registration",
            "jury-witness-v1/registration/hash",
            &registration_body,
        )?,
    );
    vectors.insert(
        "registration_key_proof".to_owned(),
        json!({
            "name": "registration_key_proof",
            "info_hex": hex_bytes(&registration_info),
            "aad_hex": hex_bytes(&registration_aad),
            "recipient_private_seed_hex": hex_bytes(&contribution_private_keys[0]),
            "enc_hex": hex_bytes(&registration_enc),
            "ciphertext_hex": hex_bytes(&registration_ciphertext),
            "plaintext_hex": hex_bytes(&registration_challenge_plaintext),
            "hmac_data_hex": hex_bytes(&key_proof_data),
            "hmac_hex": hex_bytes(&key_proof)
        }),
    );

    let replay_record = [
        u16be(1),
        vault_id.clone(),
        request_id.clone(),
        request_digest.clone(),
        bytes_field(&request_message)?,
        action_manifest_digest.clone(),
        vec![2],
        u64be(expires_at),
        u64be(expires_at + 86_400_000),
        list_bytes(&approval_messages)?,
        optional(None),
        optional(Some(&bytes_field(&witness_responses[0])?)),
    ]
    .concat();
    vectors.insert(
        "witness_replay_record".to_owned(),
        json!({
            "name": "witness_replay_record",
            "body_hex": hex_bytes(&replay_record),
            "expected": "accepted"
        }),
    );
    let database_state_body = [
        u16be(1),
        witness_ids[0].clone(),
        u64be(4),
        list_bytes(&[[
            u16be(1),
            vault_id.clone(),
            genesis.clone(),
            bytes_field(&registration_body)?,
            bytes_field(&checkpoint_bytes)?,
            bytes_field(&policy_material)?,
        ]
        .concat()])?,
        list_bytes(&[replay_record])?,
        u64be(issued_at + 2_000),
    ]
    .concat();
    let database_state_digest = hash_preimage(
        "jury-witness-v1/database-state/hash",
        &[bytes_field(&database_state_body)?],
    );
    vectors.insert(
        "witness_database_state".to_owned(),
        digest_vector(
            "witness_database_state",
            "jury-witness-v1/database-state/hash",
            &database_state_body,
        )?,
    );
    let high_watermark = [
        vault_id.clone(),
        genesis.clone(),
        u64be(7),
        checkpoint_digest.clone(),
        u64be(expires_at),
    ]
    .concat();
    let anchor_fields = vec![
        u16be(1),
        witness_ids[0].clone(),
        witness_signing_fingerprints[0].to_vec(),
        u64be(1),
        u64be(4),
        database_state_digest.to_vec(),
        list_fixed(&[high_watermark])?,
        u64be(expires_at + 86_400_000),
        u64be(issued_at + 2_000),
        id(0xd5),
        u64be(issued_at + 2_100),
    ];
    let state_anchor = signed_vector(
        "witness_state_anchor",
        "jury-witness-v1/state-anchor/signature",
        "jury-witness-v1/state-anchor/hash",
        &anchor_fields,
        &witness_signing_keys[0],
    )?;
    vectors.insert("witness_state_anchor".to_owned(), state_anchor);
    let refusal = [
        u16be(1),
        vec![0x11],
        optional(Some(&request_id)),
        optional(Some(&vault_id)),
        optional(Some(&witness_ids[0])),
    ]
    .concat();
    vectors.insert(
        "protocol_refusal".to_owned(),
        json!({
            "name": "protocol_refusal",
            "body_hex": hex_bytes(&refusal),
            "reason": "unsupported-version",
            "state_change": false,
            "counts_as_decision": false,
            "expected": "accepted"
        }),
    );

    let affected_item = [
        item_id.clone(),
        u64be(3),
        u64be(4),
        u64be(5),
        id(0xd6),
        id(0xd7),
        u64be(5),
        id(0xd8),
        id(0xd9),
    ]
    .concat();
    let rotation_fields = vec![
        u16be(1),
        id(0xda),
        vault_id.clone(),
        genesis.clone(),
        u64be(7),
        id(0x72),
        u64be(8),
        id(0xdb),
        witness_policy_id.clone(),
        u64be(1),
        witness_policy_digest.clone(),
        id(0xdc),
        u64be(2),
        id(0xdd),
        vec![8],
        list_bytes(&[affected_item])?,
        u64be(issued_at + 4_000),
        owner_id.clone(),
        owner_fingerprint.to_vec(),
        u64be(1),
    ];
    let rotation = signed_vector(
        "witness_policy_rotation",
        "jury-witness-v1/rotation/signature",
        "jury-witness-v1/rotation/hash",
        &rotation_fields,
        &owner_key,
    )?;
    let rotation_digest = vector_bytes(&rotation, "digest_hex")?;
    vectors.insert("witness_policy_rotation".to_owned(), rotation);
    let recovery_fields = vec![
        u16be(1),
        id(0xde),
        vault_id.clone(),
        genesis.clone(),
        optional(Some(&witness_ids[0])),
        bytes_field(&witness_descriptors[2])?,
        hash_preimage(
            "jury-witness-v1/registration/hash",
            &[bytes_field(&registration_body)?],
        )
        .to_vec(),
        checkpoint_digest.clone(),
        id(0xdf),
        rotation_digest.clone(),
        vec![1],
        u64be(issued_at + 5_000),
        owner_id.clone(),
        owner_fingerprint.to_vec(),
        u64be(1),
    ];
    let recovery = signed_vector(
        "witness_recovery",
        "jury-witness-v1/recovery/signature",
        "jury-witness-v1/recovery/hash",
        &recovery_fields,
        &owner_key,
    )?;
    vectors.insert("witness_recovery".to_owned(), recovery);

    let public_scope = [
        u16be(1),
        request_id.clone(),
        vault_id.clone(),
        genesis.clone(),
        item_id.clone(),
        u64be(3),
        vec![2],
        slot_id.clone(),
        vec![2],
        u64be(4),
        seal_id.clone(),
        u64be(7),
        id(0x72),
        witness_policy_id.clone(),
        u64be(1),
        witness_policy_digest.clone(),
        requester_id.clone(),
        vec![1],
        vec![1],
        approval_target_digest.to_vec(),
        action_manifest_digest.clone(),
        workload_digest.to_vec(),
        u64be(issued_at),
        optional(None),
        u64be(expires_at),
    ]
    .concat();
    let receipt_id = id(0xe0);
    let receipt_core_fields = vec![
        u16be(1),
        receipt_id.clone(),
        bytes_field(&request_signature_preimage)?,
        client_signature,
        request_digest.clone(),
        action_manifest_digest.clone(),
        presentation_digest.to_vec(),
        bytes_field(&public_scope)?,
        list_bytes(&approval_messages)?,
        list_bytes(&witness_messages)?,
        bytes_field(&checkpoint_bytes)?,
        bytes_field(&policy_material)?,
        vec![2],
        vec![2],
        list_fixed(&approver_ids)?,
        list_fixed(&witness_ids[0..WITNESS_THRESHOLD])?,
        vec![1],
        vec![0],
        u64be(issued_at + 3_000),
        u64be(expires_at),
    ];
    let receipt_core = receipt_core_fields.concat();
    let receipt_core_digest = hash_preimage(
        "jury-witness-v1/receipt/core-hash",
        &[bytes_field(&receipt_core)?],
    );
    let acknowledgement_fields = vec![
        u16be(1),
        receipt_id.clone(),
        receipt_core_digest.to_vec(),
        request_digest.clone(),
        requester_id.clone(),
        requester_fingerprint.to_vec(),
        u64be(1),
        u64be(issued_at + 1_500),
    ];
    let acknowledgement = signed_vector(
        "receipt_acknowledgement",
        "jury-witness-v1/receipt/acknowledgement",
        "jury-witness-v1/receipt/acknowledgement/hash",
        &acknowledgement_fields,
        &requester_key,
    )?;
    let acknowledgement_digest = vector_bytes(&acknowledgement, "digest_hex")?;
    let acknowledgement_message = vector_bytes(&acknowledgement, "message_hex")?;
    vectors.insert("receipt_acknowledgement".to_owned(), acknowledgement);
    let completion_fields = vec![
        u16be(1),
        receipt_id.clone(),
        receipt_core_digest.to_vec(),
        optional(Some(&acknowledgement_digest)),
        requester_id.clone(),
        requester_fingerprint.to_vec(),
        u64be(1),
        vec![1],
        vec![0],
        u64be(issued_at + 3_000),
    ];
    let completion = signed_vector(
        "receipt_completion",
        "jury-witness-v1/receipt/completion",
        "jury-witness-v1/receipt/completion/hash",
        &completion_fields,
        &requester_key,
    )?;
    let completion_message = vector_bytes(&completion, "message_hex")?;
    vectors.insert("receipt_completion".to_owned(), completion);
    let full_receipt = [
        receipt_core.clone(),
        optional(Some(&bytes_field(&acknowledgement_message)?)),
        optional(Some(&bytes_field(&completion_message)?)),
    ]
    .concat();
    let receipt = digest_vector(
        "witness_receipt",
        "jury-witness-v1/receipt/hash",
        &full_receipt,
    )?;
    vectors.insert(
        "receipt_core".to_owned(),
        json!({
            "name": "receipt_core",
            "body_hex": hex_bytes(&receipt_core),
            "digest_hex": hex_bytes(&receipt_core_digest),
            "expected": "accepted"
        }),
    );
    vectors.insert("witness_receipt".to_owned(), receipt);

    Ok((vectors, construction))
}
