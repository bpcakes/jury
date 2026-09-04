
#[test]
fn role_bound_checkpoint_and_cancellation_creators_produce_shared_validated_evidence()
-> TestResult {
    let fixture = fixture()?;
    let checkpoint = VaultPolicyCheckpointCreator::create(
        &fixture.policy,
        &fixture.request.witness_policy_digest,
        Digest32::new([0; 32]),
        &fixture.actors.owner,
        NOW_MS - 1,
    )?;
    validate_checkpoint_public(&fixture.policy, &checkpoint)?;
    assert_eq!(checkpoint.vault_policy_hash, fixture.request.vault_policy_hash);

    let mut creator = RequestCancellationCreator::from_source(TestRandom::new(0x1234_5678));
    let cancellation = creator.create(
        &fixture.policy,
        &fixture.request,
        &fixture.actors.owner,
        NOW_MS,
    )?;
    validate_request_cancellation(
        &fixture.policy,
        &fixture.request,
        &cancellation,
        NOW_MS,
    )?;
    assert_ne!(cancellation.cancellation_id, cancellation.nonce);
    assert_eq!(
        cancellation.canceller_role,
        CancellerRoleV1::OriginalRequester
    );
    Ok(())
}
#[test]
fn automatic_read_builder_uses_only_the_exact_policy_target_and_empty_presentation() -> TestResult {
    let principals = fixture_principals()?;
    let item_id = ItemId::from_bytes([0x03; 32])?;
    let field_id = FieldId::from_bytes([0x44; 32])?;
    let mut witness_policy = fixture_witness_policy(&principals)?;
    witness_policy.approver_descriptors.clear();
    witness_policy.review_label_set_digest = owner_review_label_set_digest(&[])?;
    witness_policy.operation_rules[0].eligible_approver_ids.clear();
    witness_policy.operation_rules[0].approval_threshold = 0;
    witness_policy.operation_rules[0].automatic_read_targets = vec![AutomaticReadTarget {
        item_id,
        field_id: Some(field_id),
    }];
    witness_policy.validate()?;
    let witness_digest = witness_policy.digest()?;
    let policy = fixture_policy(&principals, &witness_policy, &witness_digest)?;
    let checkpoint = VaultPolicyCheckpointCreator::create(
        &policy,
        &witness_digest,
        Digest32::new([0; 32]),
        &principals.actors.owner,
        NOW_MS - 1,
    )?;
    let mut creator = WitnessRequestCreator::from_source(
        TestRandom::new(0xfeed_beef),
        ProtectionPolicy::EmergencyAllowDegraded,
    );
    let prepared = creator.create_read_stdout(
        WitnessRequestContext {
            policy: &policy,
            checkpoint: &checkpoint,
            requester: &principals.actors.owner,
            review_labels: Vec::new(),
            now_ms: NOW_MS,
        },
        item_id,
        field_id,
    )?;
    assert!(prepared.presentation.entries.is_empty());
    assert!(prepared.review_labels.is_empty());
    assert_eq!(
        prepared.manifest.approval_target.entries[0].presentation_commitment,
        Digest32::new([0; 32])
    );
    validate_public_request(
        &policy,
        &checkpoint,
        &prepared.request,
        &prepared.manifest,
    )?;

    assert!(
        creator
            .create_read_stdout(
                WitnessRequestContext {
                    policy: &policy,
                    checkpoint: &checkpoint,
                    requester: &principals.actors.owner,
                    review_labels: Vec::new(),
                    now_ms: NOW_MS,
                },
                item_id,
                FieldId::from_bytes([0x45; 32])?,
            )
            .is_err()
    );
    Ok(())
}

#[test]
fn human_action_builder_opens_every_scope_and_binds_command_changes() -> TestResult {
    let principals = fixture_principals()?;
    let mut witness_policy = fixture_witness_policy(&principals)?;
    for (descriptor, identity) in witness_policy
        .approver_descriptors
        .iter_mut()
        .zip(&principals.actors.approvers)
    {
        descriptor.allowed_operations = vec![WitnessOperation::TemplateInjection];
        descriptor.self_signature = Signature64::new([0; 64]);
        descriptor.self_signature =
            identity.sign_validated_approval(&descriptor.self_signature_preimage()?)?;
    }
    let item_id = ItemId::from_bytes([0x03; 32])?;
    let field_id = FieldId::from_bytes([0x44; 32])?;
    witness_policy.operation_rules[0].operation = WitnessOperation::TemplateInjection;
    witness_policy.operation_rules[0].max_target_count = 2;
    witness_policy
        .validate()
        .map_err(|error| format!("template policy before labels: {error:?}"))?;
    let provisional_digest = witness_policy.digest()?;
    let provisional_policy = fixture_policy(&principals, &witness_policy, &provisional_digest)?;
    let mut label_creator = OwnerReviewLabelCreator::from_source(TestRandom::new(0x1111_2222));
    let item_label = label_creator.create(
        OwnerReviewLabelInput {
            policy: &provisional_policy,
            owner: &principals.actors.owner,
            label_revision: 1,
            subject: ReviewLabelSubject::Item(item_id),
            public_label: ReviewLabelBytes::new(b"ExampleItem".to_vec())?,
            target_policy_sequence: 1,
            issued_at_ms: NOW_MS - 1_000,
            expires_at_ms: None,
        },
        |_| false,
    )?;
    let field_label = label_creator.create(
        OwnerReviewLabelInput {
            policy: &provisional_policy,
            owner: &principals.actors.owner,
            label_revision: 1,
            subject: ReviewLabelSubject::Field { item_id, field_id },
            public_label: ReviewLabelBytes::new(b"ExampleField".to_vec())?,
            target_policy_sequence: 1,
            issued_at_ms: NOW_MS - 1_000,
            expires_at_ms: None,
        },
        |candidate| candidate == &item_label.label_id,
    )?;
    let labels = vec![item_label, field_label];
    witness_policy.review_label_set_digest = owner_review_label_set_digest(&labels)?;
    witness_policy
        .validate()
        .map_err(|error| format!("template policy after labels: {error:?}"))?;
    let witness_digest = witness_policy.digest()?;
    let policy = fixture_policy(&principals, &witness_policy, &witness_digest)?;
    let checkpoint = VaultPolicyCheckpointCreator::create(
        &policy,
        &witness_digest,
        Digest32::new([0; 32]),
        &principals.actors.owner,
        NOW_MS - 1,
    )?;
    let action = |suffix: &[u8]| -> TestResult<WitnessActionRequest> {
        Ok(WitnessActionRequest {
            item_id,
            field_ids: vec![field_id],
            operation_context: OperationContextV1::TemplateInjection,
            executable_identity: Some(OperationBytes::new(b"jury-template-renderer-v1".to_vec())?),
            arguments: vec![
                ManifestArgumentV1::PublicLiteral {
                    bytes: OperationBytes::new([b"prefix=".as_slice(), suffix].concat())?,
                },
                ManifestArgumentV1::SecretPlaceholder {
                    target: WitnessTargetV1 {
                        item_id,
                        field_id: Some(field_id),
                    },
                },
            ],
            working_directory: Some(OperationBytes::new(b"/ExampleDirectory".to_vec())?),
            environment_injections: Vec::new(),
            stdin_target: None,
            stdin_mode: StdinModeV1::None,
            output_sink: OutputSinkV1::Stdout,
            output_destination: None,
            timeout_ms: 0,
            output_limit_bytes: 4_096,
        })
    };
    let mut creator = WitnessRequestCreator::from_source(
        TestRandom::new(0x3333_4444),
        ProtectionPolicy::EmergencyAllowDegraded,
    );
    let first = creator.create_action(
        WitnessRequestContext {
            policy: &policy,
            checkpoint: &checkpoint,
            requester: &principals.actors.owner,
            review_labels: labels.clone(),
            now_ms: NOW_MS,
        },
        action(b"one")?,
    )?;
    let second = creator.create_action(
        WitnessRequestContext {
            policy: &policy,
            checkpoint: &checkpoint,
            requester: &principals.actors.owner,
            review_labels: labels,
            now_ms: NOW_MS,
        },
        action(b"two")?,
    )?;
    assert!(first.presentation.entries.iter().any(|entry| {
        entry.subject_kind == PresentationSubjectV1::Item
            && entry.display_bytes.as_bytes() == b"ExampleItem"
    }));
    assert!(first.presentation.entries.iter().any(|entry| {
        entry.subject_kind == PresentationSubjectV1::Field
            && entry.display_bytes.as_bytes() == b"ExampleField"
    }));
    assert!(first.presentation.entries.iter().any(|entry| {
        entry.subject_kind == PresentationSubjectV1::WorkingDirectory
            && entry.display_bytes.as_bytes() == b"/ExampleDirectory"
    }));
    assert_ne!(first.manifest.workload_digest()?, second.manifest.workload_digest()?);
    assert_ne!(first.manifest.digest()?, second.manifest.digest()?);
    Ok(())
}

#[test]
fn policy_authenticated_presentation_opens_the_signed_request_and_rejects_tampering()
-> TestResult {
    let principals = fixture_principals()?;
    let item_id = ItemId::from_bytes([0x03; 32])?;
    let public_label = ReviewLabelBytes::new(b"ExampleItem".to_vec())?;
    let mut label = OwnerReviewLabelV1 {
        schema: 1,
        label_id: LabelId::from_bytes([0xb0; 32])?,
        label_revision: 1,
        subject_kind: PresentationSubjectV1::Item,
        vault_id: VaultId::from_bytes([0x01; 32])?,
        genesis_fingerprint: Digest32::new([0x02; 32]),
        item_id: Some(item_id),
        field_id: None,
        subject_commitment: None,
        public_label: public_label.clone(),
        vault_policy_sequence: 1,
        issued_at_ms: NOW_MS - 5_000,
        expires_at_ms: Some(NOW_MS + 5_000),
        issuer_owner_id: principals.owner_descriptor.principal_id,
        issuer_key_fingerprint: signing_key_fingerprint(
            1,
            &principals.owner_descriptor.principal_id,
            1,
            &principals.owner_descriptor.verification_public_key,
        ),
        issuer_key_epoch: 1,
        signature: Signature64::new([0; 64]),
    };
    label.signature = principals
        .actors
        .owner
        .sign_validated_statement(&label.signature_preimage()?)?;
    let labels = vec![label.clone()];

    let mut witness_policy = fixture_witness_policy(&principals)?;
    witness_policy.review_label_set_digest = owner_review_label_set_digest(&labels)?;
    witness_policy.validate()?;
    let witness_policy_digest = witness_policy.digest()?;
    let policy = fixture_policy(&principals, &witness_policy, &witness_policy_digest)?;
    let checkpoint = fixture_checkpoint(&principals, &witness_policy, &witness_policy_digest)?;

    let entry = ApprovalPresentationEntryV1 {
        subject_kind: PresentationSubjectV1::Item,
        item_id: Some(item_id),
        field_id: None,
        subject_commitment: None,
        presentation_kind: PresentationKindV1::OwnerReviewLabel,
        display_bytes: PresentationDisplayBytes::new(b"ExampleItem".to_vec())?,
        source_revision: Some(1),
        source_revision_seal_id: Some(RevisionSealId::from_bytes([0x06; 32])?),
        owner_review_label: Some(label),
        blinding_nonce: PresentationNonce::from_bytes([0xb1; 32])?,
    };
    let presentation = ApprovalPresentationV1 {
        entries: vec![entry.clone()],
    };
    let (mut manifest, _) = fixture_manifest(&principals.owner_descriptor, &witness_policy_digest)?;
    manifest.presentation_digest = presentation.digest()?;
    manifest.approval_target = ApprovalTargetV1 {
        entries: vec![ApprovalTargetEntryV1 {
            item_id,
            field_id: None,
            presentation_commitment: entry.commitment()?,
        }],
        presentation_digest: manifest.presentation_digest.clone(),
    };
    manifest.approval_target_digest = manifest.approval_target.digest()?;
    let mut creator = WitnessRequestCreator::from_source(
        TestRandom::new(0xcafe_babe_1122_3344),
        ProtectionPolicy::EmergencyAllowDegraded,
    );
    let prepared = creator.create(
        WitnessRequestContext {
            policy: &policy,
            checkpoint: &checkpoint,
            requester: &principals.actors.owner,
            review_labels: labels,
            now_ms: NOW_MS,
        },
        manifest,
        presentation,
    )?;
    let request = &prepared.request;
    let manifest = &prepared.manifest;
    let presentation = &prepared.presentation;
    let labels = &prepared.review_labels;
    assert_ne!(request.request_id, request.client_nonce);
    assert_eq!(
        request.request_session_key_fingerprint,
        *prepared.session.fingerprint()
    );

    let review_input = ApprovalReviewInput {
        policy: &policy,
        checkpoint: &checkpoint,
        request,
        manifest,
        presentation,
        review_labels: labels,
        now_ms: NOW_MS,
    };
    let validated = validate_policy_authenticated_presentation(review_input)?;
    assert!(validated.is_human());
    assert_eq!(validated.manifest(), manifest);
    let review = render_complete_approval_review(review_input)?;
    assert!(review.text().contains("ExampleItem"));
    assert!(!review.text().contains('…'));
    let mut approval_creator = ApprovalDecisionCreator::from_source(TestRandom::new(
        0xfeed_face_5566_7788,
    ));
    let approval = approval_creator.create(
        &policy,
        &checkpoint,
        &review,
        &principals.actors.approvers[0],
        ApprovalDecisionChoice {
            decision: ApprovalDecisionKindV1::Approve,
            reason: WitnessReasonV1::None,
            now_ms: NOW_MS,
        },
    )?;
    validate_approval_decision(&policy, &checkpoint, request, manifest, &approval, NOW_MS)?;
    let mut replayed_for_another_request = approval;
    replayed_for_another_request.request_digest = Digest32::new([0xbd; 32]);
    assert!(matches!(
        validate_approval_decision(
            &policy,
            &checkpoint,
            request,
            manifest,
            &replayed_for_another_request,
            NOW_MS,
        )
        .map_err(WitnessEngineError::reason),
        Err(WitnessReasonV1::Invalid)
    ));

    assert!(matches!(
        validate_policy_authenticated_presentation(ApprovalReviewInput {
            review_labels: &[],
            ..review_input
        })
        .map_err(|error| error.kind()),
        Err(ReviewLabelErrorKind::InvalidScope)
    ));
    let mut tampered = presentation.clone();
    tampered.entries[0].source_revision_seal_id =
        Some(RevisionSealId::from_bytes([0xb2; 32])?);
    assert!(matches!(
        validate_policy_authenticated_presentation(ApprovalReviewInput {
            presentation: &tampered,
            ..review_input
        })
        .map_err(|error| error.kind()),
        Err(ReviewLabelErrorKind::InvalidScope)
    ));
    Ok(())
}

#[test]
fn response_is_stable_and_escapes_only_after_anchor_publication() -> TestResult {
    let fixture = fixture()?;
    let witness_id = fixture.actors.witnesses[0].principal_id();
    let mut store = MemoryStore {
        state: PersistedWitnessState::empty(witness_id),
        fail_before_commit_once: false,
        fail_after_commit_once: false,
        fail_mark_once: false,
    };
    let mut anchor = MemoryAnchor::default();
    let clock = FixedClock {
        wall_ms: NOW_MS,
        monotonic_ms: 42,
    };
    let mut random = TestRandom::new(0xdead_beef_0123_4567);
    {
        let mut engine = WitnessEngine::new(
            &fixture.actors.witnesses[0],
            &mut store,
            &mut anchor,
            &clock,
            &mut random,
        );
        engine.register_vault(
            &fixture.policy,
            RegistrationBytes::new(vec![1, 2, 3])?,
            fixture.checkpoint.clone(),
            PolicyMaterialBytes::new(vec![4, 5, 6])?,
        )?;
        assert_eq!(
            engine.reserve(&fixture.policy, fixture.request.clone(), &fixture.manifest)?,
            WitnessProgress::Reserved
        );
        assert_eq!(
            engine.decide(
                &fixture.policy,
                &fixture.request,
                &fixture.manifest,
                &fixture.approvals[..1],
            )?,
            WitnessProgress::Pending
        );
        let stable = engine.decide(
            &fixture.policy,
            &fixture.request,
            &fixture.manifest,
            &fixture.approvals,
        )?;
        let WitnessProgress::Stable(response) = stable else {
            return Err("expected stable response".into());
        };
        assert_eq!(response.decision.decision, WitnessDecisionKindV1::Approve);
        assert!(response.contribution.is_some());
        validate_witness_response(
            &fixture.policy,
            &fixture.checkpoint,
            &fixture.request,
            &fixture.manifest,
            &response,
        )?;
        let mut corrupted = (*response).clone();
        let contribution = corrupted
            .contribution
            .as_mut()
            .ok_or("missing contribution")?;
        let mut ciphertext = *contribution.ciphertext.as_bytes();
        ciphertext[0] ^= 1;
        contribution.ciphertext = ShareCiphertext49::from_slice(&ciphertext)?;
        assert_eq!(
            validate_witness_response(
                &fixture.policy,
                &fixture.checkpoint,
                &fixture.request,
                &fixture.manifest,
                &corrupted,
            )
            .map_err(WitnessEngineError::reason),
            Err(WitnessReasonV1::InvalidContribution)
        );
        let stable_bytes = response.canonical_bytes()?;
        let retry = engine.decide(
            &fixture.policy,
            &fixture.request,
            &fixture.manifest,
            &fixture.approvals,
        )?;
        let WitnessProgress::Stable(retry) = retry else {
            return Err("expected stable retry".into());
        };
        assert_eq!(retry.canonical_bytes()?, stable_bytes);
    }
    assert_eq!(store.state.logical.state_generation, 4);
    assert_eq!(
        store
            .state
            .logical
            .replay
            .values()
            .next()
            .ok_or("missing replay entry")?
            .approvals
            .len(),
        2
    );
    assert!(store.state.pending_anchor.is_none());
    assert_eq!(anchor.publishes, 4);
    assert_eq!(
        anchor.value.as_ref().map(|value| value.state_generation),
        Some(4)
    );
    Ok(())
}

#[test]
fn receipt_material_is_bound_to_the_request_policy_and_counted_members() -> TestResult {
    let fixture = fixture()?;
    let mut counted_approver_ids = fixture
        .approvals
        .iter()
        .map(|approval| approval.approver_id)
        .collect::<Vec<_>>();
    counted_approver_ids.sort_unstable();
    let witness_policy = fixture
        .policy
        .witness_policy(&fixture.request.witness_policy_digest)
        .ok_or("missing witness policy")?;
    let mut counted_witness_ids = witness_policy
        .witness_descriptors
        .iter()
        .map(|descriptor| descriptor.witness_id)
        .collect::<Vec<_>>();
    counted_witness_ids.sort_unstable();
    let material = WitnessReceiptMaterialV1 {
        schema: 1,
        receipt_id: ReceiptId::from_bytes([0xd1; 32])?,
        request_digest: fixture.request.digest()?,
        action_manifest_digest: fixture.manifest.digest()?,
        presentation_digest: fixture.manifest.presentation_digest.clone(),
        policy_checkpoint_digest: fixture.checkpoint.digest()?,
        witness_policy_digest: fixture.request.witness_policy_digest.clone(),
        approval_threshold: 2,
        witness_threshold: 2,
        counted_approver_ids,
        counted_witness_ids,
        reason: WitnessReasonV1::None,
        issued_at_ms: NOW_MS,
        expires_at_ms: fixture.request.expires_at_ms,
    };
    validate_receipt_material(
        &fixture.policy,
        &fixture.checkpoint,
        &fixture.request,
        &fixture.manifest,
        &material,
    )?;

    let mut wrong_member = material.clone();
    *wrong_member
        .counted_witness_ids
        .last_mut()
        .ok_or("missing counted witness")? = PrincipalId::from_bytes([0x7f; 32])?;
    assert_eq!(
        validate_receipt_material(
            &fixture.policy,
            &fixture.checkpoint,
            &fixture.request,
            &fixture.manifest,
            &wrong_member,
        )
        .map_err(WitnessEngineError::reason),
        Err(WitnessReasonV1::WrongScope)
    );

    let mut wrong_scope = material;
    wrong_scope.presentation_digest = Digest32::new([0xff; 32]);
    assert_eq!(
        validate_receipt_material(
            &fixture.policy,
            &fixture.checkpoint,
            &fixture.request,
            &fixture.manifest,
            &wrong_scope,
        )
        .map_err(WitnessEngineError::reason),
        Err(WitnessReasonV1::WrongScope)
    );
    Ok(())
}
