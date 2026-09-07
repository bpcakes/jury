#[test]
fn owner_change_rules_consume_frozen_post_authentication_cases() -> TestResult {
    // These are the frozen post-authentication state/scope cases. The real
    // signed, interactive path is exercised by check-linux-owner-changes.
    let corpus: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../conformance/witness-v1/vectors.json"
    ))?;
    let fixture = fixture()?;
    let mut random = TestRandom(0x917);
    let descriptors = [
        (0x09, PrincipalKind::Human),
        (0x70, PrincipalKind::Human),
        (0x71, PrincipalKind::Human),
        (0x72, PrincipalKind::Machine),
    ]
    .into_iter()
    .map(|(id, kind)| {
        let public = descriptor(&make_identity(id, kind, &mut random)?)?;
        Ok((public.principal_id, public))
    })
    .collect::<TestResult<BTreeMap<_, _>>>()?;
    let mut checked = 0;
    for case in corpus["protocol_cases"]
        .as_array()
        .ok_or("protocol cases missing")?
        .iter()
        .filter(|case| case["kind"] == "owner-change")
    {
        let mut policy = fixture.policy.clone();
        policy.sequence = case["current_sequence"]
            .as_u64()
            .ok_or("current sequence missing")?;
        policy.owners = owner_case_value(case["owners"].clone())?;
        policy.principals = case["principals"]
            .as_array()
            .ok_or("principals missing")?
            .iter()
            .map(|principal| {
                let id: PrincipalId = owner_case_value(principal["id"].clone())?;
                let public = descriptors
                    .get(&id)
                    .ok_or("unrecognized fixture principal")?
                    .clone();
                assert_eq!(
                    serde_json::to_value(public.principal_kind)?,
                    principal["kind"]
                );
                Ok((
                    id,
                    PrincipalPolicyState {
                        descriptor: public,
                        display_label: "ExamplePrincipal".to_owned(),
                    },
                ))
            })
            .collect::<TestResult<BTreeMap<_, _>>>()?;
        let context = owner_case_value::<OperationContextV1>(serde_json::json!({
            "kind": "owner-change", "change": case["change"],
            "target_principal_id": case["target"], "next_vault_policy_sequence": case["next_sequence"],
        }));
        let result = match context {
            Err(_) => "invalid",
            Ok(context) => {
                let mut manifest = fixture.manifest.clone();
                manifest.operation_context = context;
                manifest.operation = owner_case_value(case["operation"].clone())?;
                manifest.content_role = owner_case_value(case["content_role"].clone())?;
                manifest.item_id = owner_case_value(case["item_id"].clone())?;
                manifest.approval_target.entries[0].item_id =
                    owner_case_value(case["target_item_id"].clone())?;
                manifest.approval_target.entries[0].field_id =
                    owner_case_value(case["field_id"].clone())?;
                manifest.approval_target_digest = manifest.approval_target.digest()?;
                manifest.output_sink = owner_case_value(case["output_sink"].clone())?;
                if manifest.validate_shape().is_err() {
                    "wrong-scope"
                } else {
                    match crate::witness_validation::validate_owner_change_context(
                        &policy,
                        &owner_case_value(case["requester"].clone())?,
                        &manifest.operation_context,
                    ) {
                        Ok(()) => "accepted",
                        Err(RequestPolicyError::PolicyDenied) => "policy-denied",
                        Err(RequestPolicyError::WrongScope) => "wrong-scope",
                        other => {
                            return Err(format!("unexpected owner-change result: {other:?}").into());
                        }
                    }
                }
            }
        };
        assert_eq!(
            result,
            case["expected"].as_str().ok_or("expected result missing")?,
            "{}",
            case["name"]
        );
        checked += 1;
    }
    assert_eq!(checked, 16);
    Ok(())
}

fn owner_case_value<T: serde::de::DeserializeOwned>(
    value: serde_json::Value,
) -> Result<T, serde_json::Error> {
    serde_json::from_slice(&serde_json::to_vec(&value)?)
}

#[test]
fn witness_reserve_checks_signed_owner_intent_before_publishing_state() -> TestResult {
    use jury_protocol::witness_v1::OwnerChangeKindV1;
    let fixture = owner_change_engine_fixture()?;
    let owner = fixture.actors.owner.principal_id();
    let target = PrincipalId::from_bytes([0x71; 32])?;
    let cases = [
        (OwnerChangeKindV1::Grant, target, 2, None),
        (
            OwnerChangeKindV1::Grant,
            owner,
            2,
            Some(WitnessReasonV1::PolicyDenied),
        ),
        (
            OwnerChangeKindV1::Grant,
            PrincipalId::from_bytes([0x72; 32])?,
            2,
            Some(WitnessReasonV1::PolicyDenied),
        ),
        (
            OwnerChangeKindV1::Grant,
            PrincipalId::from_bytes([0x73; 32])?,
            2,
            Some(WitnessReasonV1::PolicyDenied),
        ),
        (
            OwnerChangeKindV1::Revoke,
            target,
            2,
            Some(WitnessReasonV1::PolicyDenied),
        ),
        (
            OwnerChangeKindV1::Revoke,
            owner,
            2,
            Some(WitnessReasonV1::PolicyDenied),
        ),
        (
            OwnerChangeKindV1::Grant,
            target,
            3,
            Some(WitnessReasonV1::WrongScope),
        ),
    ];
    for (change, target_principal_id, next_vault_policy_sequence, expected) in cases {
        let mut manifest = fixture.manifest.clone();
        manifest.operation_context = OperationContextV1::OwnerChange {
            change,
            target_principal_id,
            next_vault_policy_sequence,
        };
        let mut request = fixture.request.clone();
        request.action_manifest_digest = manifest.digest()?;
        request.workload_digest = manifest.workload_digest()?;
        request.client_signature = fixture
            .actors
            .owner
            .sign_validated_statement(&request.signature_preimage()?)?;
        // Prove the signed request passes the old common policy checks. The
        // refused cases below must fail specifically on owner-change intent.
        validate_request_manifest(&request, &manifest)?;
        assert!(validate_request_policy(&fixture.policy, &request).is_ok());
        let public =
            validate_public_request(&fixture.policy, &fixture.checkpoint, &request, &manifest);
        assert_eq!(public.err().map(|error| error.reason()), expected);
        let mut store = empty_store(&fixture);
        let mut anchor = MemoryAnchor::default();
        let clock = FixedClock {
            wall_ms: NOW_MS,
            monotonic_ms: 43,
        };
        let mut random = TestRandom::new(0x841);
        register_fixture(&fixture, &mut store, &mut anchor, &clock, &mut random)?;
        let before = store.state.clone();
        let prior_anchor = anchor.value.clone();
        let progress = {
            let mut engine = WitnessEngine::new(
                &fixture.actors.witnesses[0],
                &mut store,
                &mut anchor,
                &clock,
                &mut random,
            );
            engine.reserve(&fixture.policy, request.clone(), &manifest)
        };
        match expected {
            Some(reason) => {
                assert_eq!(
                    progress
                        .err()
                        .ok_or("invalid owner intent was reserved")?
                        .reason(),
                    reason
                );
                assert_eq!(store.state, before);
                assert_eq!(anchor.value, prior_anchor);
            }
            None => {
                assert!(matches!(progress?, WitnessProgress::Reserved));
                let mut engine = WitnessEngine::new(
                    &fixture.actors.witnesses[0],
                    &mut store,
                    &mut anchor,
                    &clock,
                    &mut random,
                );
                let response =
                    engine.decide(&fixture.policy, &request, &manifest, &fixture.approvals)?;
                let WitnessProgress::Stable(response) = response else {
                    return Err("valid owner grant did not complete".into());
                };
                assert_eq!(response.decision.decision, WitnessDecisionKindV1::Approve);
                assert!(response.contribution.is_some());
            }
        }
    }
    Ok(())
}

fn owner_change_engine_fixture() -> TestResult<Fixture> {
    let mut principals = fixture_principals()?;
    let mut witness_policy = fixture_witness_policy(&principals)?;
    for (descriptor, identity) in principals
        .approver_policy_descriptors
        .iter_mut()
        .zip(&principals.actors.approvers)
    {
        descriptor.allowed_operations = vec![WitnessOperation::AdministrativeRekey];
        descriptor.self_signature =
            identity.sign_validated_approval(&descriptor.self_signature_preimage()?)?;
    }
    witness_policy.approver_descriptors = principals.approver_policy_descriptors.to_vec();
    witness_policy.operation_rules[0].operation = WitnessOperation::AdministrativeRekey;
    witness_policy.validate()?;
    let digest = witness_policy.digest()?;
    let mut policy = fixture_policy(&principals, &witness_policy, &digest)?;
    let mut random = TestRandom::new(0x991);
    for (id, kind) in [(0x71, PrincipalKind::Human), (0x72, PrincipalKind::Machine)] {
        let public = descriptor(&make_identity(id, kind, &mut random)?)?;
        policy.principals.insert(
            public.principal_id,
            PrincipalPolicyState {
                descriptor: public,
                display_label: "ExamplePrincipal".to_owned(),
            },
        );
    }
    let checkpoint = fixture_checkpoint(&principals, &digest)?;
    let (mut manifest, presentation_digest) =
        fixture_manifest(&principals.owner_descriptor, &digest)?;
    manifest.operation = WitnessOperationV1::AdministrativeRekey;
    manifest.operation_context = OperationContextV1::OwnerChange {
        change: jury_protocol::witness_v1::OwnerChangeKindV1::Grant,
        target_principal_id: PrincipalId::from_bytes([0x71; 32])?,
        next_vault_policy_sequence: 2,
    };
    manifest.output_sink = OutputSinkV1::None;
    let mut request = fixture_request(&principals, &checkpoint, &manifest, digest)?;
    request.operation = manifest.operation;
    request.client_signature = principals
        .actors
        .owner
        .sign_validated_statement(&request.signature_preimage()?)?;
    let approvals = fixture_approvals(&principals, &request, &manifest, &presentation_digest)?;
    Ok(Fixture {
        actors: principals.actors,
        policy,
        checkpoint,
        request,
        manifest,
        approvals,
    })
}

#[test]
fn owner_change_builder_refuses_sequence_overflow() -> TestResult {
    use crate::witness_client::{WitnessRequestContext, WitnessRequestCreator, WitnessRequestErrorKind};
    let mut fixture = owner_change_engine_fixture()?;
    fixture.policy.sequence = u64::MAX;
    let mut creator = WitnessRequestCreator::from_source(
        TestRandom::new(0x419), ProtectionPolicy::EmergencyAllowDegraded);
    let result = creator.create_owner_change(
        WitnessRequestContext {
            policy: &fixture.policy,
            checkpoint: &fixture.checkpoint,
            requester: &fixture.actors.owner,
            review_labels: Vec::new(),
            now_ms: NOW_MS,
        },
        fixture.request.item_id,
        ContentRole::Body,
        jury_protocol::witness_v1::OwnerChangeKindV1::Grant,
        PrincipalId::from_bytes([0x71; 32])?,
    );
    assert_eq!(result.err().ok_or("overflow created a request")?.kind(), WitnessRequestErrorKind::InvalidInput);
    Ok(())
}
