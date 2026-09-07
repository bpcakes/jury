#[test]
fn checkpoint_consumers_preserve_binding_checks_and_error_classification() -> TestResult {
    use crate::witness_operations::{
        CheckpointStatusErrorKind as Status, verify_checkpoint_propagation,
    };

    let fixture = fixture()?;
    let check = |checkpoint: &VaultPolicyCheckpointV1| {
        (
            validate_checkpoint_public(&fixture.policy, checkpoint)
                .map(|_| ())
                .map_err(WitnessEngineError::reason),
            verify_checkpoint_propagation(&fixture.policy, checkpoint, &[])
                .map(|_| ())
                .map_err(|error| error.kind()),
        )
    };
    assert_eq!(check(&fixture.checkpoint), (Ok(()), Ok(())));

    let mutations: &[fn(&mut VaultPolicyCheckpointV1) -> TestResult] = &[
        |c| {
            c.vault_id = VaultId::from_bytes([0x71; 32])?;
            Ok(())
        },
        |c| {
            c.genesis_fingerprint = Digest32::new([0x71; 32]);
            Ok(())
        },
        |c| {
            c.vault_policy_sequence += 1;
            Ok(())
        },
        |c| {
            c.vault_policy_hash = Digest32::new([0x71; 32]);
            Ok(())
        },
        |c| {
            c.active_witness_policy_set_digest = Digest32::new([0x71; 32]);
            Ok(())
        },
    ];
    for (index, mutate) in mutations.iter().enumerate() {
        let mut checkpoint = fixture.checkpoint.clone();
        mutate(&mut checkpoint)?;
        assert_ne!(
            checkpoint, fixture.checkpoint,
            "mutation {index} must change input"
        );
        assert_eq!(
            check(&checkpoint),
            (
                Err(WitnessReasonV1::CheckpointFork),
                Err(Status::InvalidCheckpoint)
            ),
            "binding mutation {index}"
        );
    }

    let mut checkpoint = fixture.checkpoint.clone();
    checkpoint.issuer_owner_id = PrincipalId::from_bytes([0x71; 32])?;
    assert_eq!(
        check(&checkpoint),
        (
            Err(WitnessReasonV1::InvalidSignature),
            Err(Status::InvalidCheckpoint)
        )
    );
    // A binding failure takes precedence over the missing owner on both paths.
    checkpoint.vault_policy_hash = Digest32::new([0x71; 32]);
    assert_eq!(
        check(&checkpoint),
        (
            Err(WitnessReasonV1::CheckpointFork),
            Err(Status::InvalidCheckpoint)
        )
    );
    checkpoint.schema = 2;
    assert_eq!(
        check(&checkpoint),
        (
            Err(WitnessReasonV1::Invalid),
            Err(Status::InvalidCheckpoint)
        )
    );

    for mutate in [
        (|c: &mut VaultPolicyCheckpointV1| c.issuer_key_epoch += 1)
            as fn(&mut VaultPolicyCheckpointV1),
        |c| c.issuer_key_fingerprint = Digest32::new([0x71; 32]),
        |c| c.signature = Signature64::new([0x71; 64]),
    ] {
        let mut checkpoint = fixture.checkpoint.clone();
        mutate(&mut checkpoint);
        assert_eq!(
            check(&checkpoint),
            (
                Err(WitnessReasonV1::InvalidSignature),
                Err(Status::InvalidSignature)
            )
        );
    }
    Ok(())
}

#[test]
fn global_checkpoint_covers_live_policies_without_pooling_request_authority() -> TestResult {
    let fixture = fixture()?;
    let mut policy = fixture.policy.clone();
    let original = policy.witness_policy(&fixture.request.witness_policy_digest)
        .ok_or("missing fixture policy")?.clone();
    let mut second = original.clone();
    second.witness_policy_id = WitnessPolicyId::from_bytes([0x79; 32])?;
    let second_digest = second.digest()?;
    policy.witness_policies.insert(second_digest.clone(), second);
    // Merely retaining an unreferenced policy must not alter the active set.
    assert_eq!(policy.active_witness_policy_set_digest()?, fixture.checkpoint.active_witness_policy_set_digest);
    let second_id = ItemId::from_bytes([0x78; 32])?;
    let mut item = policy.item(&fixture.request.item_id).ok_or("missing fixture item")?.clone();
    for slot in &mut item.witnessed_state.as_mut().ok_or("missing witnessed state")?.slots {
        slot.item_id = second_id;
        slot.witness_policy_id = WitnessPolicyId::from_bytes([0x79; 32])?;
        slot.witness_policy_digest = second_digest.clone();
    }
    policy.items.insert(second_id, item.clone());
    let checkpoint = VaultPolicyCheckpointCreator::create(
        &policy, Digest32::new([0; 32]), &fixture.actors.owner, NOW_MS - 1,
    )?;
    assert_ne!(checkpoint.active_witness_policy_set_digest, fixture.checkpoint.active_witness_policy_set_digest);
    let status = crate::witness_operations::verify_checkpoint_propagation(&policy, &checkpoint, &[])?;
    assert_eq!(status.expected_witness_count, original.witness_descriptors.len());
    // Reusing a policy in another item contributes no duplicate digest/member.
    let reused_id = ItemId::from_bytes([0x77; 32])?;
    for slot in &mut item.witnessed_state.as_mut().ok_or("missing witnessed state")?.slots {
        slot.item_id = reused_id;
    }
    policy.items.insert(reused_id, item);
    assert_eq!(policy.active_witness_policy_set_digest()?, checkpoint.active_witness_policy_set_digest);
    validate_checkpoint_public(&policy, &checkpoint)?;
    let mut omitted = checkpoint.clone();
    omitted.active_witness_policy_set_digest = fixture.checkpoint.active_witness_policy_set_digest.clone();
    omitted.signature = fixture.actors.owner.sign_validated_statement(&omitted.signature_preimage()?)?;
    assert!(matches!(validate_checkpoint_public(&policy, &omitted), Err(error) if error.reason() == WitnessReasonV1::CheckpointFork));

    let mut request = fixture.request.clone();
    request.policy_checkpoint_digest = checkpoint.digest()?;
    request.client_signature = fixture.actors.owner.sign_validated_statement(&request.signature_preimage()?)?;
    validate_public_request(&policy, &checkpoint, &request, &fixture.manifest)?;
    // Selecting another committed policy cannot authorize the original slot.
    let mut manifest = fixture.manifest.clone();
    manifest.witness_policy_id = WitnessPolicyId::from_bytes([0x79; 32])?;
    manifest.witness_policy_digest = second_digest.clone();
    request.witness_policy_id = manifest.witness_policy_id;
    request.witness_policy_digest = second_digest;
    request.action_manifest_digest = manifest.digest()?;
    request.client_signature = fixture.actors.owner.sign_validated_statement(&request.signature_preimage()?)?;
    let corpus: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../conformance/witness-v1/vectors.json"
    ))?;
    for (name, digest) in [
        ("global-checkpoint-wrong-slot-policy", request.witness_policy_digest.clone()),
        ("global-checkpoint-uncommitted-request-policy", Digest32::new([0xaa; 32])),
    ] {
        manifest.witness_policy_digest = digest.clone();
        request.witness_policy_digest = digest;
        request.action_manifest_digest = manifest.digest()?;
        request.client_signature = fixture.actors.owner.sign_validated_statement(&request.signature_preimage()?)?;
        let reason = match validate_public_request(&policy, &checkpoint, &request, &manifest) {
            Err(error) => error.reason(),
            Ok(_) => return Err("another policy authorized the selected slot".into()),
        };
        let case = corpus["protocol_cases"].as_array().ok_or("missing protocol cases")?
            .iter().find(|case| case["name"] == name).ok_or("missing frozen wrong-scope case")?;
        assert_eq!(serde_json::to_value(reason)?, case["expected"]);
    }
    policy.items.clear();
    assert_eq!(policy.active_witness_policy_set_digest()?, jury_protocol::witness_v1::active_witness_policy_set_digest(&[])?);
    Ok(())
}

#[test]
fn first_registration_can_join_a_chain_but_cannot_replace_established_state() -> TestResult {
    let fixture = fixture()?;
    let (policy, checkpoint) = descendant_policy_and_checkpoint(&fixture)?;
    assert_eq!(checkpoint.predecessor_checkpoint_digest, fixture.checkpoint.digest()?);
    let corpus: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../conformance/witness-v1/vectors.json"
    ))?;
    let case = corpus["protocol_cases"].as_array().ok_or("missing cases")?
        .iter().find(|case| case["name"] == "global-checkpoint-registration-any-active-policy")
        .ok_or("missing frozen registration case")?;
    assert_eq!(case["expected"], "accepted");
    assert_ne!(case["candidate"]["predecessor_digest"], "00".repeat(32));
    let mut store = empty_store(&fixture);
    let mut anchor = MemoryAnchor::default();
    let clock = FixedClock { wall_ms: NOW_MS, monotonic_ms: 1 };
    let mut random = TestRandom::new(0x1234_8765);
    let registration = RegistrationBytes::new(vec![1, 2, 3])?;
    let material = PolicyMaterialBytes::new(vec![4, 5, 6])?;
    {
        let mut engine = WitnessEngine::new(&fixture.actors.witnesses[0], &mut store, &mut anchor, &clock, &mut random);
        let ack = engine.register_vault(&policy, registration.clone(), checkpoint.clone(), material.clone())?;
        assert_eq!(ack, engine.register_vault(&policy, registration.clone(), checkpoint.clone(), material.clone())?);
        let mut sibling = checkpoint.clone();
        sibling.issued_at_ms += 1;
        sibling.signature = fixture.actors.owner.sign_validated_statement(&sibling.signature_preimage()?)?;
        assert_eq!(engine.register_vault(&policy, registration.clone(), sibling, material.clone()).map_err(WitnessEngineError::reason), Err(WitnessReasonV1::CheckpointFork));
        assert_eq!(engine.advance_checkpoint(&fixture.policy, fixture.checkpoint.clone(), material).map_err(WitnessEngineError::reason), Err(WitnessReasonV1::StalePolicy));
    }
    assert_eq!(store.state.logical.state_generation, 1);
    assert_eq!(anchor.publishes, 1);
    assert_eq!(store.state.logical.vaults.get(&checkpoint.vault_id).ok_or("missing registered vault")?.current_checkpoint, checkpoint);
    Ok(())
}
