use super::*;

// Values shared by request generation and subsequent contribution/receipt vectors.
pub(super) struct RequestFixture {
    pub(super) vault_id: Vec<u8>,
    pub(super) genesis: Vec<u8>,
    pub(super) item_id: Vec<u8>,
    pub(super) slot_id: Vec<u8>,
    pub(super) seal_id: Vec<u8>,
    pub(super) request_id: Vec<u8>,
    pub(super) requester_id: Vec<u8>,
    pub(super) owner_id: Vec<u8>,
    pub(super) witness_policy_id: Vec<u8>,
    pub(super) issued_at: u64,
    pub(super) expires_at: u64,
    pub(super) requester_key: SigningKey,
    pub(super) owner_key: SigningKey,
    pub(super) witness_signing_keys: [SigningKey; WITNESS_COUNT],
    pub(super) approver_ids: [Vec<u8>; APPROVER_COUNT],
    pub(super) witness_ids: [Vec<u8>; WITNESS_COUNT],
    pub(super) requester_fingerprint: [u8; 32],
    pub(super) owner_fingerprint: [u8; 32],
    pub(super) vectors: Map<String, Value>,
    pub(super) witness_descriptors: Vec<Vec<u8>>,
    pub(super) witness_descriptor_fingerprints: Vec<Vec<u8>>,
    pub(super) witness_signing_fingerprints: Vec<[u8; 32]>,
    pub(super) contribution_private_keys: Vec<Vec<u8>>,
    pub(super) contribution_public_keys: Vec<Vec<u8>>,
    pub(super) contribution_fingerprints: Vec<[u8; 32]>,
    pub(super) witness_policy_digest: Vec<u8>,
    pub(super) policy_material: Vec<u8>,
    pub(super) checkpoint_bytes: Vec<u8>,
    pub(super) checkpoint_digest: Vec<u8>,
    pub(super) presentation_digest: [u8; 32],
    pub(super) approval_target_digest: [u8; 32],
    pub(super) workload_digest: [u8; 32],
    pub(super) action_manifest_digest: Vec<u8>,
    pub(super) session_fingerprint: [u8; 32],
    pub(super) request_message: Vec<u8>,
    pub(super) request_digest: Vec<u8>,
    pub(super) request_signature_preimage: Vec<u8>,
    pub(super) client_signature: Vec<u8>,
    pub(super) approval_messages: Vec<Vec<u8>>,
    pub(super) session_private: Vec<u8>,
    pub(super) session_public: Vec<u8>,
}

pub(super) fn build_request_vectors() -> AnyResult<RequestFixture> {
    let vault_id = id(0x01);
    let genesis = id(0x02);
    let item_id = id(0x03);
    let slot_id = id(0x05);
    let seal_id = id(0x06);
    let request_id = id(0x07);
    let requester_id = id(0x08);
    let owner_id = id(0x09);
    let witness_policy_id = id(0x0a);
    let issued_at = 1_700_000_000_000_u64;
    let expires_at = issued_at + 300_000;

    let requester_key = signing_key(0x11);
    let owner_key = signing_key(0x12);
    let approver_keys = [signing_key(0x21), signing_key(0x22)];
    let witness_signing_keys = [signing_key(0x31), signing_key(0x32), signing_key(0x33)];
    let approver_ids = [id(0x41), id(0x42)];
    let witness_ids = [id(0x51), id(0x52), id(0x53)];
    let requester_public = requester_key.verifying_key().to_bytes();
    let requester_fingerprint = signing_fingerprint(1, &requester_id, 1, &requester_public);
    let owner_public = owner_key.verifying_key().to_bytes();
    let owner_fingerprint = signing_fingerprint(1, &owner_id, 1, &owner_public);

    let mut vectors = Map::new();
    for (name, change) in [
        ("owner_change_grant_context", 1),
        ("owner_change_revoke_context", 2),
    ] {
        vectors.insert(
            name.to_owned(),
            owner_change_context_vector(name, change, &id(0x71), 8)?,
        );
    }

    let mut approver_descriptors = Vec::new();
    let mut approver_fingerprints = Vec::new();
    for index in 0..APPROVER_COUNT {
        let public = approver_keys[index].verifying_key().to_bytes();
        let fingerprint = signing_fingerprint(2, &approver_ids[index], 1, &public);
        approver_fingerprints.push(fingerprint);
        let fields = vec![
            u16be(1),
            approver_ids[index].clone(),
            public.to_vec(),
            fingerprint.to_vec(),
            u64be(1),
            vec![1],
            vec![1],
            list_fixed(&[vec![1]])?,
            u64be(issued_at - 10_000),
        ];
        let vector = descriptor_vector(
            &format!("approver_descriptor_{}", index + 1),
            "jury-witness-v1/approver-descriptor/fingerprint",
            "jury-witness-v1/approver-descriptor/self-signature",
            &fields,
            &approver_keys[index],
        )?;
        approver_descriptors.push(vector_bytes(&vector, "message_hex")?);
        vectors.insert(format!("approver_descriptor_{}", index + 1), vector);
    }

    let mut witness_descriptors = Vec::new();
    let mut witness_descriptor_fingerprints = Vec::new();
    let mut witness_signing_fingerprints = Vec::new();
    let mut contribution_private_keys = Vec::new();
    let mut contribution_public_keys = Vec::new();
    let mut contribution_fingerprints = Vec::new();
    for index in 0..WITNESS_COUNT {
        let (private, public) = xwing_keypair(0x61 + u8::try_from(index).map_err(|_| "index")?);
        let contribution_fingerprint = hash_preimage(
            "jury-v1/recipient-public-bundle/fingerprint",
            std::slice::from_ref(&public),
        );
        let signing_public = witness_signing_keys[index].verifying_key().to_bytes();
        let signing_fingerprint = signing_fingerprint(3, &witness_ids[index], 1, &signing_public);
        let fields = vec![
            u16be(1),
            witness_ids[index].clone(),
            vec![u8::try_from(index + 1).map_err(|_| "share index")?],
            signing_public.to_vec(),
            signing_fingerprint.to_vec(),
            u64be(1),
            public.clone(),
            contribution_fingerprint.to_vec(),
            u64be(1),
            vec![1],
            u64be(issued_at - 10_000),
        ];
        let vector = descriptor_vector(
            &format!("witness_descriptor_{}", index + 1),
            "jury-witness-v1/witness-descriptor/fingerprint",
            "jury-witness-v1/witness-descriptor/self-signature",
            &fields,
            &witness_signing_keys[index],
        )?;
        witness_descriptors.push(vector_bytes(&vector, "message_hex")?);
        witness_descriptor_fingerprints.push(vector_bytes(&vector, "fingerprint_hex")?);
        witness_signing_fingerprints.push(signing_fingerprint);
        contribution_private_keys.push(private);
        contribution_public_keys.push(public);
        contribution_fingerprints.push(contribution_fingerprint);
        vectors.insert(format!("witness_descriptor_{}", index + 1), vector);
    }

    let label_fields = vec![
        u16be(1),
        id(0x71),
        u64be(1),
        vec![1],
        vault_id.clone(),
        genesis.clone(),
        optional(Some(&item_id)),
        optional(None),
        optional(None),
        bytes_field(b"ExampleItem")?,
        u64be(7),
        u64be(issued_at - 1_000),
        optional(None),
        owner_id.clone(),
        owner_fingerprint.to_vec(),
        u64be(1),
    ];
    let review_label = signed_vector(
        "owner_review_label",
        "jury-witness-v1/review-label/signature",
        "jury-witness-v1/review-label/hash",
        &label_fields,
        &owner_key,
    )?;
    let review_label_bytes = vector_bytes(&review_label, "message_hex")?;
    let review_label_digest = vector_bytes(&review_label, "digest_hex")?;
    vectors.insert("owner_review_label".to_owned(), review_label);
    let review_label_set_digest = hash_preimage(
        "jury-witness-v1/review-label-set/hash",
        &[list_fixed(std::slice::from_ref(&review_label_digest))?],
    );

    let operation_rule = [
        vec![1],
        list_fixed(&approver_ids)?,
        vec![2],
        u64be(300_000),
        u64be(30_000),
        u32be(4_096),
        vec![1],
        vec![1],
        list_bytes(&[])?,
    ]
    .concat();
    // Canonical automatic-target bytes deliberately bind the content role.
    for (name, role, field) in [
        ("automatic_descriptor_target", 1_u8, None),
        ("automatic_field_target", 2_u8, Some(id(0x44))),
    ] {
        let mut body = id(0x03);
        body.push(role);
        match &field {
            Some(field) => {
                body.push(1);
                body.extend_from_slice(field);
            }
            None => body.push(0),
        }
        vectors.insert(
            name.to_owned(),
            json!({
                "kind": "automatic-target", "item_id_hex": hex_bytes(&id(0x03)),
                "content_role": role, "field_id_hex": field.as_ref().map(|id| hex_bytes(id)),
                "body_hex": hex_bytes(&body)
            }),
        );
    }
    let policy_body = [
        u16be(1),
        witness_policy_id.clone(),
        u64be(1),
        fixed(0, 32),
        vault_id.clone(),
        genesis.clone(),
        u64be(7),
        id(0x72),
        u16be(1),
        u16be(1),
        list_bytes(&approver_descriptors)?,
        list_bytes(&witness_descriptors)?,
        vec![2],
        list_bytes(&[operation_rule])?,
        review_label_set_digest.to_vec(),
        vec![0],
    ]
    .concat();
    let witness_policy = digest_vector(
        "witness_policy",
        "jury-witness-v1/policy/hash",
        &policy_body,
    )?;
    let witness_policy_digest = vector_bytes(&witness_policy, "digest_hex")?;
    vectors.insert("witness_policy".to_owned(), witness_policy);
    let policy_revision_fields = vec![
        vault_id.clone(),
        u64be(7),
        id(0x70),
        u64be(issued_at - 600),
        owner_id.clone(),
        list_bytes(&[[vec![0x0b], witness_policy_digest.clone()].concat()])?,
        id(0x72),
    ];
    let policy_revision = signed_vector(
        "owner_policy_revision",
        "jury-v1/policy-revision/signature",
        "jury-v1/policy-revision/hash",
        &policy_revision_fields,
        &owner_key,
    )?;
    let policy_material = [
        bytes_field(&vector_bytes(&policy_revision, "message_hex")?)?,
        bytes_field(&policy_body)?,
    ]
    .concat();
    vectors.insert("owner_policy_revision".to_owned(), policy_revision);

    let single_set = active_policy_set_vector(
        "active_policy_set_single",
        std::slice::from_ref(&witness_policy_digest),
    )?;
    let active_policy_set_digest = vector_bytes(&single_set, "digest_hex")?;
    vectors.insert("active_policy_set_single".to_owned(), single_set);
    vectors.insert(
        "active_policy_set_empty".to_owned(),
        active_policy_set_vector("active_policy_set_empty", &[])?,
    );
    vectors.insert(
        "active_policy_set_multiple".to_owned(),
        active_policy_set_vector("active_policy_set_multiple", &[id(0xe1), id(0xe2)])?,
    );
    let checkpoint_fields = vec![
        u16be(1),
        vault_id.clone(),
        genesis.clone(),
        u64be(7),
        id(0x72),
        active_policy_set_digest.clone(),
        fixed(0, 32),
        u64be(issued_at - 500),
        owner_id.clone(),
        owner_fingerprint.to_vec(),
        u64be(1),
    ];
    let checkpoint = signed_vector(
        "policy_checkpoint",
        "jury-witness-v1/checkpoint/signature",
        "jury-witness-v1/checkpoint/hash",
        &checkpoint_fields,
        &owner_key,
    )?;
    let checkpoint_bytes = vector_bytes(&checkpoint, "message_hex")?;
    let checkpoint_digest = vector_bytes(&checkpoint, "digest_hex")?;
    vectors.insert("policy_checkpoint".to_owned(), checkpoint);

    let presentation_entry = [
        vec![1],
        optional(Some(&item_id)),
        optional(None),
        optional(None),
        vec![2],
        bytes_field(b"ExampleItem")?,
        optional(Some(&u64be(4))),
        optional(Some(&seal_id)),
        optional(Some(&review_label_bytes)),
        id(0x73),
    ]
    .concat();
    let presentation_list = list_bytes(std::slice::from_ref(&presentation_entry))?;
    let presentation_digest = hash_preimage(
        "jury-witness-v1/approval-presentation/hash",
        std::slice::from_ref(&presentation_list),
    );
    let presentation_commitment = hash_preimage(
        "jury-witness-v1/approval-presentation/commitment",
        &[bytes_field(&presentation_entry)?],
    );
    vectors.insert(
        "approval_presentation".to_owned(),
        json!({
            "name": "approval_presentation",
            "entry_hex": hex_bytes(&presentation_entry),
            "entry_commitment_hex": hex_bytes(&presentation_commitment),
            "list_hex": hex_bytes(&presentation_list),
            "digest_hex": hex_bytes(&presentation_digest),
            "expected": "accepted"
        }),
    );

    let target_entry = [
        item_id.clone(),
        optional(None),
        presentation_commitment.to_vec(),
    ]
    .concat();
    let approval_target = [
        list_bytes(std::slice::from_ref(&target_entry))?,
        presentation_digest.to_vec(),
    ]
    .concat();
    let approval_target_digest = hash_preimage(
        "jury-witness-v1/approval-target/hash",
        &[bytes_field(&approval_target)?],
    );
    vectors.insert(
        "approval_target".to_owned(),
        json!({
            "name": "approval_target",
            "entry_hex": hex_bytes(&target_entry),
            "body_hex": hex_bytes(&approval_target),
            "digest_hex": hex_bytes(&approval_target_digest),
            "expected": "accepted"
        }),
    );

    let operation_context = jce("jury-witness-v1/operation-context/read-stdout", &[u16be(1)]);
    let workload_fields = vec![
        vec![1],
        bytes_field(&operation_context)?,
        optional(None),
        list_bytes(&[])?,
        optional(None),
        list_bytes(&[])?,
        optional(None),
        vec![1],
        vec![1],
        optional(None),
        vec![1],
        u64be(30_000),
        u32be(4_096),
    ];
    let workload_preimage = jce("jury-witness-v1/workload/hash", &workload_fields);
    let workload_digest = sha256(&workload_preimage);
    vectors.insert(
        "workload".to_owned(),
        json!({
            "name": "workload",
            "preimage_hex": hex_bytes(&workload_preimage),
            "digest_hex": hex_bytes(&workload_digest),
            "expected": "accepted"
        }),
    );

    let manifest_fields = vec![
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
        bytes_field(&operation_context)?,
        bytes_field(&approval_target)?,
        approval_target_digest.to_vec(),
        optional(None),
        list_bytes(&[])?,
        optional(None),
        list_bytes(&[])?,
        optional(None),
        vec![1],
        vec![1],
        optional(None),
        vec![1],
        u64be(30_000),
        u32be(4_096),
        u64be(issued_at),
        optional(None),
        u64be(expires_at),
        presentation_digest.to_vec(),
    ];
    let manifest_body = manifest_fields.concat();
    let action_manifest = digest_vector(
        "action_manifest",
        "jury-witness-v1/action-manifest/hash",
        &manifest_body,
    )?;
    let action_manifest_digest = vector_bytes(&action_manifest, "digest_hex")?;
    vectors.insert("action_manifest".to_owned(), action_manifest);

    let (session_private, session_public) = xwing_keypair(0x74);
    let session_fingerprint = hash_preimage(
        "jury-v1/recipient-public-bundle/fingerprint",
        std::slice::from_ref(&session_public),
    );
    let intended_witness_entries: Vec<Vec<u8>> = (0..WITNESS_COUNT)
        .map(|index| {
            [
                witness_ids[index].clone(),
                vec![u8::try_from(index + 1).unwrap_or(0)],
                witness_signing_fingerprints[index].to_vec(),
                contribution_fingerprints[index].to_vec(),
            ]
            .concat()
        })
        .collect();
    let intended_witness_set = list_fixed(&intended_witness_entries)?;
    let intended_witness_set_digest = hash_preimage(
        "jury-witness-v1/intended-witness-set/hash",
        std::slice::from_ref(&intended_witness_set),
    );
    let request_fields = vec![
        u16be(1),
        u16be(1),
        u16be(1),
        request_id.clone(),
        id(0x75),
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
        checkpoint_digest.clone(),
        witness_policy_id.clone(),
        u64be(1),
        witness_policy_digest.clone(),
        requester_id.clone(),
        requester_fingerprint.to_vec(),
        u64be(1),
        vec![1],
        vec![1],
        approval_target_digest.to_vec(),
        action_manifest_digest.clone(),
        workload_digest.to_vec(),
        u64be(issued_at),
        optional(None),
        u64be(expires_at),
        session_public.clone(),
        session_fingerprint.to_vec(),
        intended_witness_set.clone(),
    ];
    let request = signed_vector(
        "witness_request",
        "jury-witness-v1/request/signature",
        "jury-witness-v1/request/hash",
        &request_fields,
        &requester_key,
    )?;
    let request_message = vector_bytes(&request, "message_hex")?;
    let request_digest = vector_bytes(&request, "digest_hex")?;
    let request_signature_preimage = vector_bytes(&request, "preimage_hex")?;
    let client_signature = vector_bytes(&request, "signature_hex")?;
    vectors.insert("witness_request".to_owned(), request);

    let mut approval_messages = Vec::new();
    for index in 0..APPROVER_COUNT {
        let fields = vec![
            u16be(1),
            id(0x80 + u8::try_from(index).map_err(|_| "approval index")?),
            request_id.clone(),
            request_digest.clone(),
            action_manifest_digest.clone(),
            presentation_digest.to_vec(),
            witness_policy_id.clone(),
            u64be(1),
            witness_policy_digest.clone(),
            approver_ids[index].clone(),
            approver_fingerprints[index].to_vec(),
            u64be(1),
            vec![1],
            vec![1],
            vec![0],
            u64be(issued_at + 1_000),
            optional(None),
            u64be(expires_at),
            id(0x82 + u8::try_from(index).map_err(|_| "approval nonce")?),
            intended_witness_set_digest.to_vec(),
        ];
        let vector = signed_vector(
            &format!("approval_decision_{}", index + 1),
            "jury-witness-v1/approval-decision/signature",
            "jury-witness-v1/approval-decision/hash",
            &fields,
            &approver_keys[index],
        )?;
        approval_messages.push(vector_bytes(&vector, "message_hex")?);
        vectors.insert(format!("approval_decision_{}", index + 1), vector);
    }

    Ok(RequestFixture {
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
        vectors,
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
    })
}

pub(super) struct RevisionShares {
    pub(super) revision_secret: Vec<u8>,
    pub(super) shares: Vec<Vec<u8>>,
    pub(super) later_revision_secret: Vec<u8>,
    pub(super) later_shares: Vec<Vec<u8>>,
    pub(super) later_reconstructed: Vec<u8>,
    pub(super) cross_revision_result: Vec<u8>,
}

pub(super) fn build_revision_shares() -> AnyResult<RevisionShares> {
    let revision_secret = fixed(0x91, 32);
    let mut share_rng = ChaCha20Rng::from_seed([0x92; 32]);
    let shares = Gf256::split_bytes(
        WITNESS_THRESHOLD,
        WITNESS_COUNT,
        &revision_secret,
        &mut share_rng,
    )
    .map_err(|error| format!("split shares: {error:?}"))?;
    let reconstructed = Gf256::combine_bytes(&shares[0..WITNESS_THRESHOLD])
        .map_err(|error| format!("combine shares: {error:?}"))?;
    if reconstructed != revision_secret {
        return Err("share reconstruction mismatch".to_owned());
    }
    let later_revision_secret = fixed(0x93, 32);
    let mut later_share_rng = ChaCha20Rng::from_seed([0x94; 32]);
    let later_shares = Gf256::split_bytes(
        WITNESS_THRESHOLD,
        WITNESS_COUNT,
        &later_revision_secret,
        &mut later_share_rng,
    )
    .map_err(|error| format!("split later shares: {error:?}"))?;
    let later_reconstructed = Gf256::combine_bytes(&later_shares[0..WITNESS_THRESHOLD])
        .map_err(|error| format!("combine later shares: {error:?}"))?;
    let cross_revision_result =
        Gf256::combine_bytes(vec![shares[0].clone(), later_shares[1].clone()])
            .map_err(|error| format!("combine cross-revision shares: {error:?}"))?;
    if later_reconstructed != later_revision_secret
        || cross_revision_result == later_revision_secret
        || cross_revision_result == revision_secret
    {
        return Err("later revision separation mismatch".to_owned());
    }

    Ok(RevisionShares {
        revision_secret,
        shares,
        later_revision_secret,
        later_shares,
        later_reconstructed,
        cross_revision_result,
    })
}
