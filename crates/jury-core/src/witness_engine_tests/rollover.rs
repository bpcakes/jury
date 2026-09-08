#[test]
fn recovery_builder_binds_whole_item_destination_and_preserved_mode() -> TestResult {
    let mut principals = fixture_principals()?;
    let mut witness_policy = fixture_witness_policy(&principals)?;
    for (descriptor, identity) in principals.approver_policy_descriptors.iter_mut().zip(&principals.actors.approvers) {
        descriptor.allowed_operations = vec![WitnessOperation::Recovery];
        descriptor.self_signature = identity.sign_validated_approval(&descriptor.self_signature_preimage()?)?;
    }
    witness_policy.approver_descriptors = principals.approver_policy_descriptors.to_vec();
    witness_policy.operation_rules[0].operation = WitnessOperation::Recovery;
    let initial = fixture_policy(&principals, &witness_policy, &witness_policy.digest()?)?;
    let item_id = ItemId::from_bytes([3; 32])?;
    let label = OwnerReviewLabelCreator::new().create(OwnerReviewLabelInput {
        policy: &initial, owner: &principals.actors.owner, label_revision: 1,
        subject: ReviewLabelSubject::Item(item_id), public_label: ReviewLabelBytes::new(b"ExampleItem".to_vec())?,
        target_policy_sequence: 1, issued_at_ms: NOW_MS, expires_at_ms: None,
    }, |_| false)?;
    witness_policy.review_label_set_digest = owner_review_label_set_digest(std::slice::from_ref(&label))?;
    let digest = witness_policy.digest()?;
    let policy = fixture_policy(&principals, &witness_policy, &digest)?;
    let checkpoint = fixture_checkpoint(&principals, &digest)?;
    let destination = OperationBytes::new(b"/tmp/ExampleVault/vault.json".to_vec())?;
    let mut creator = WitnessRequestCreator::new(ProtectionPolicy::Strict);
    let prepared = creator.create_recovery_reseal(WitnessRequestContext {
        policy: &policy, checkpoint: &checkpoint, requester: &principals.actors.owner,
        review_labels: vec![label.clone()], now_ms: NOW_MS,
    }, item_id, ContentRole::Body, &destination)?;
    assert_eq!(prepared.manifest.operation, WitnessOperationV1::Recovery);
    assert_eq!(prepared.manifest.vault_policy_sequence, policy.sequence());
    assert_eq!(prepared.manifest.approval_target.entries.len(), 1);
    assert_eq!(prepared.manifest.approval_target.entries[0].field_id, None);
    assert_eq!(prepared.manifest.output_sink, OutputSinkV1::PrivateFile);
    let OperationContextV1::Recovery { mode, destination_commitment, next_item_access_mode } = &prepared.manifest.operation_context else { return Err("recovery context absent".into()); };
    assert_eq!(*mode, 2);
    assert_eq!(*next_item_access_mode, ItemAccessMode::WitnessedOnly);
    assert_eq!(Some(destination_commitment), prepared.manifest.output_sink_commitment.as_ref());
    let review = render_complete_approval_review(ApprovalReviewInput {
        policy: &policy, checkpoint: &checkpoint, request: &prepared.request, manifest: &prepared.manifest,
        presentation: &prepared.presentation, review_labels: &prepared.review_labels, now_ms: NOW_MS,
    })?;
    assert!(review.text().contains("ExampleVault"));
    let approval = ApprovalDecisionCreator::new().create(&policy, &checkpoint, &review, &principals.actors.approvers[0], ApprovalDecisionChoice { decision: ApprovalDecisionKindV1::Approve, reason: WitnessReasonV1::None, now_ms: NOW_MS })?;
    validate_approval_decision(&policy, &checkpoint, &prepared.request, &prepared.manifest, &approval, NOW_MS)?;
    let another = creator.create_recovery_reseal(WitnessRequestContext {
        policy: &policy, checkpoint: &checkpoint, requester: &principals.actors.owner,
        review_labels: vec![label], now_ms: NOW_MS,
    }, item_id, ContentRole::Body, &OperationBytes::new(b"/tmp/ExampleOtherVault/vault.json".to_vec())?)?;
    assert_ne!(another.manifest.output_sink_commitment, prepared.manifest.output_sink_commitment);
    assert!(validate_approval_decision(&policy, &checkpoint, &another.request, &another.manifest, &approval, NOW_MS).is_err());
    assert!(creator.create_recovery_reseal(WitnessRequestContext {
        policy: &policy, checkpoint: &checkpoint, requester: &principals.actors.owner,
        review_labels: Vec::new(), now_ms: NOW_MS,
    }, item_id, ContentRole::Body, &destination).is_err());
    Ok(())
}
