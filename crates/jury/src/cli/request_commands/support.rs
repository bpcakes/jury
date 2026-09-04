fn draw_receipt_id() -> Result<ReceiptId, CliError> {
    let mut source = OsRandom;
    for _ in 0..8 {
        let mut bytes = [0_u8; 32];
        source.fill(&mut bytes).map_err(|_| {
            CliError::new(
                CliErrorKind::ProtectionUnavailable,
                "entropy-unavailable",
                "operating-system entropy is unavailable",
            )
        })?;
        if let Ok(receipt_id) = ReceiptId::from_bytes(bytes) {
            return Ok(receipt_id);
        }
    }
    Err(CliError::new(
        CliErrorKind::ProtectionUnavailable,
        "entropy-unavailable",
        "operating-system entropy is unavailable",
    ))
}

pub(super) fn request_cancel(
    cli: &Cli,
    arguments: &RequestCancelArgs,
    environment: &Environment,
    current: &Path,
    protection: ProtectionPolicy,
) -> Result<CommandOutput, CliError> {
    let endpoints = arguments
        .witnesses
        .iter()
        .map(|specification| {
            WitnessEndpointClient::parse(specification, arguments.allow_insecure_loopback)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let artifact = read_request_artifact(&arguments.request)?;
    validate_endpoint_set(&endpoints, &artifact.request)?;
    let context = load_vault_principal(cli, environment, current, protection)?;
    validated_review_at_issue(&context.policy, &artifact)?;
    let cancellation = RequestCancellationCreator::new()
        .create(
            &context.policy,
            &artifact.request,
            &context.identity,
            timestamp_ms()?,
        )
        .map_err(|_| invalid_request_cancellation())?;
    let bytes = serde_json::to_vec(&cancellation).map_err(|_| invalid_request_cancellation())?;
    let destination = preview_public_file(&arguments.out).map_err(map_filesystem_error)?;
    let publication = PreparedPublicFile::prepare_bounded_if_unchanged(
        destination,
        &bytes,
        MAX_REQUEST_ARTIFACT_BYTES,
        false,
    )
    .map_err(map_filesystem_error)?
    .publish()
    .map_err(map_filesystem_error)?;
    let witness_threshold = usize::from(
        context
            .policy
            .witness_access_rule(
                &artifact.request.item_id,
                request_policy_operation(artifact.request.operation),
            )
            .map_err(|_| invalid_request_artifact())?
            .witness_threshold,
    );
    let mut cancelled_count = 0_usize;
    let mut too_late_count = 0_usize;
    let mut failed_count = 0_usize;
    for endpoint in &endpoints {
        let Ok(progress) = endpoint.cancel(&artifact.request, &cancellation) else {
            failed_count = failed_count.saturating_add(1);
            continue;
        };
        let Some(response) = progress.response else {
            failed_count = failed_count.saturating_add(1);
            continue;
        };
        if jury_core::witness_engine::validate_witness_response(
            &context.policy,
            &artifact.checkpoint,
            &artifact.request,
            &artifact.action_manifest,
            &response,
        )
        .is_err()
        {
            failed_count = failed_count.saturating_add(1);
            continue;
        }
        match progress.kind {
            TransportProgressKind::Cancelled
                if response.decision.reason
                    == jury_protocol::witness_v1::WitnessReasonV1::Cancelled =>
            {
                cancelled_count = cancelled_count.saturating_add(1);
            }
            TransportProgressKind::TooLate => {
                too_late_count = too_late_count.saturating_add(1);
            }
            _ => failed_count = failed_count.saturating_add(1),
        }
    }
    let quorum_precluded = too_late_count == 0
        && cancelled_count > endpoints.len().saturating_sub(witness_threshold);
    let phase = if too_late_count > 0 {
        "too-late"
    } else if cancelled_count == endpoints.len() {
        "cancelled"
    } else if quorum_precluded {
        "quorum-precluded"
    } else {
        "partial"
    };
    Ok(CommandOutput::Safe {
        operation: "request-cancel",
        fields: serde_json::json!({
            "request_id": hex(artifact.request.request_id.as_bytes()),
            "cancellation_id": hex(cancellation.cancellation_id.as_bytes()),
            "phase": phase,
            "out": arguments.out,
            "durability": durability(publication),
            "witnesses_contacted": true,
            "witness_contact_count": endpoints.len(),
            "witness_response_count": cancelled_count.saturating_add(too_late_count),
            "cancelled_response_count": cancelled_count,
            "too_late_response_count": too_late_count,
            "failed_response_count": failed_count,
            "quorum_precluded": quorum_precluded,
            "already_approved_was_too_late": too_late_count > 0,
        }),
        lines: vec![
            "Cancellation intent signed and stored locally before witness contact".to_owned(),
            format!("Cancellation phase: {phase}"),
            format!("Witnesses contacted: {}", endpoints.len()),
            format!("Cancellation acknowledgements: {cancelled_count}"),
            format!("Unacknowledged or invalid responses: {failed_count}"),
        ],
    })
}

pub(super) fn approve_request(
    cli: &Cli,
    arguments: &ApproveArgs,
    environment: &Environment,
    current: &Path,
    protection: ProtectionPolicy,
) -> Result<CommandOutput, CliError> {
    let public = load_public_request_context(cli, environment, current)?;
    let artifact = read_request_artifact(&arguments.request)?;
    let review_time_ms = timestamp_ms()?;
    let review = render_complete_approval_review(ApprovalReviewInput {
        policy: &public.policy,
        checkpoint: &artifact.checkpoint,
        request: &artifact.request,
        manifest: &artifact.action_manifest,
        presentation: &artifact.presentation,
        review_labels: &artifact.review_labels,
        now_ms: review_time_ms,
    })
    .map_err(|_| invalid_request_artifact())?;
    let expected = if arguments.deny { "deny" } else { "approve" };
    if !std::io::stdin().is_terminal() {
        return Err(CliError::new(
            CliErrorKind::InvalidArguments,
            "interactive-approval-required",
            "human approval or denial requires a terminal after the complete review is rendered",
        ));
    }
    eprintln!("{}", review.text());
    eprint!("Type {expected} to sign this exact decision: ");
    std::io::stderr().flush().map_err(|_| filesystem_error())?;
    let mut confirmation = String::new();
    std::io::stdin()
        .read_line(&mut confirmation)
        .map_err(|_| filesystem_error())?;
    if confirmation.trim() != expected {
        return Err(CliError::new(
            CliErrorKind::Conflict,
            "approval-not-confirmed",
            "the exact approval decision was not confirmed",
        ));
    }
    let unlocked = unlock_selected_identity(cli, environment, current, protection)?;
    let UnlockedIdentity::Approver(approver) = unlocked.identity else {
        return Err(CliError::new(
            CliErrorKind::InvalidIdentity,
            "approver-identity-required",
            "the approve command requires a separately protected approver identity",
        ));
    };
    let decision_time_ms = timestamp_ms()?;
    let review = render_complete_approval_review(ApprovalReviewInput {
        policy: &public.policy,
        checkpoint: &artifact.checkpoint,
        request: &artifact.request,
        manifest: &artifact.action_manifest,
        presentation: &artifact.presentation,
        review_labels: &artifact.review_labels,
        now_ms: decision_time_ms,
    })
    .map_err(|_| invalid_request_artifact())?;
    let (decision_kind, reason) = approval_decision(arguments);
    let decision = ApprovalDecisionCreator::new()
        .create(
            &public.policy,
            &artifact.checkpoint,
            &review,
            &approver,
            ApprovalDecisionChoice {
                decision: decision_kind,
                reason,
                now_ms: decision_time_ms,
            },
        )
        .map_err(|_| invalid_approval_decision())?;
    let bytes = serde_json::to_vec(&decision).map_err(|_| invalid_approval_decision())?;
    let destination = preview_public_file(&arguments.out).map_err(map_filesystem_error)?;
    let publication = PreparedPublicFile::prepare_bounded_if_unchanged(
        destination,
        &bytes,
        MAX_REQUEST_ARTIFACT_BYTES,
        false,
    )
    .map_err(map_filesystem_error)?
    .publish()
    .map_err(map_filesystem_error)?;
    let complete_review: serde_json::Value =
        serde_json::from_str(review.text()).map_err(|_| invalid_request_artifact())?;
    Ok(CommandOutput::Safe {
        operation: "approve",
        fields: serde_json::json!({
            "request_id": hex(artifact.request.request_id.as_bytes()),
            "approval_id": hex(decision.approval_id.as_bytes()),
            "decision": decision.decision,
            "reason": decision.reason,
            "complete_review": complete_review,
            "complete_review_rendered": true,
            "lossy_review": false,
            "out": arguments.out,
            "durability": durability(publication),
            "witnesses_contacted": false,
        }),
        lines: vec![
            format!("Decision signed: {:?}", decision.decision),
            format!("Output: {}", arguments.out.display()),
            "Witnesses contacted: false".to_owned(),
        ],
    })
}

fn approval_decision(
    arguments: &ApproveArgs,
) -> (
    jury_protocol::witness_v1::ApprovalDecisionKindV1,
    jury_protocol::witness_v1::WitnessReasonV1,
) {
    use jury_protocol::witness_v1::{ApprovalDecisionKindV1, WitnessReasonV1};
    if !arguments.deny {
        return (ApprovalDecisionKindV1::Approve, WitnessReasonV1::None);
    }
    let reason = match arguments.reason.unwrap_or(ApprovalReasonArg::PolicyDenied) {
        ApprovalReasonArg::PolicyDenied => WitnessReasonV1::PolicyDenied,
        ApprovalReasonArg::WrongScope => WitnessReasonV1::WrongScope,
        ApprovalReasonArg::WrongOperation => WitnessReasonV1::WrongOperation,
        ApprovalReasonArg::WorkloadExceeded => WitnessReasonV1::WorkloadExceeded,
    };
    (ApprovalDecisionKindV1::Deny, reason)
}

fn load_public_request_context(
    cli: &Cli,
    environment: &Environment,
    current: &Path,
) -> Result<PublicRequestContext, CliError> {
    let home = selected_home(cli, environment, current)?;
    let vault_bytes = read_vault(&home)?;
    let vault = VaultFileV1::parse(&vault_bytes).map_err(|_| invalid_vault())?;
    let catalog = load_policy_catalog_for_vault(environment, &home, &vault)?;
    let policy = replay_policy_with_witness_policies(&vault.policy, &catalog.witness_policies)
        .map_err(|_| invalid_vault())?;
    Ok(PublicRequestContext { policy })
}

fn read_request_artifact(path: &Path) -> Result<WitnessRequestArtifactV1, CliError> {
    let bytes = read_public_file(path, MAX_REQUEST_ARTIFACT_BYTES).map_err(map_filesystem_error)?;
    let artifact: WitnessRequestArtifactV1 =
        serde_json::from_slice(&bytes).map_err(|_| invalid_request_artifact())?;
    if request_artifact_bytes(&artifact).ok().as_deref() != Some(bytes.as_slice()) {
        return Err(invalid_request_artifact());
    }
    Ok(artifact)
}

fn request_artifact_bytes(artifact: &WitnessRequestArtifactV1) -> Result<Vec<u8>, CliError> {
    if artifact.schema != 1 {
        return Err(invalid_request_artifact());
    }
    let bytes = serde_json::to_vec(artifact).map_err(|_| invalid_request_artifact())?;
    if bytes.len() > MAX_REQUEST_ARTIFACT_BYTES {
        return Err(invalid_request_artifact());
    }
    Ok(bytes)
}

fn publish_request_artifact(
    artifact: &WitnessRequestArtifactV1,
    path: &Path,
) -> Result<PublicationOutcome, CliError> {
    let bytes = request_artifact_bytes(artifact)?;
    let destination = preview_public_file(path).map_err(map_filesystem_error)?;
    PreparedPublicFile::prepare_bounded_if_unchanged(
        destination,
        &bytes,
        MAX_REQUEST_ARTIFACT_BYTES,
        false,
    )
    .map_err(map_filesystem_error)?
    .publish()
    .map_err(map_filesystem_error)
}

fn validate_endpoint_set(
    endpoints: &[WitnessEndpointClient],
    request: &jury_protocol::witness_v1::WitnessRequestV1,
) -> Result<(), CliError> {
    let mut configured = endpoints
        .iter()
        .map(|endpoint| endpoint.witness_id)
        .collect::<Vec<_>>();
    configured.sort_unstable();
    let mut intended = request
        .intended_witness_set
        .iter()
        .map(|witness| witness.witness_id)
        .collect::<Vec<_>>();
    intended.sort_unstable();
    if configured != intended || configured.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(CliError::new(
            CliErrorKind::InvalidArguments,
            "witness-endpoint-set-mismatch",
            "configured witness endpoints must exactly match the request's intended witness set",
        ));
    }
    Ok(())
}

fn wait_for_approvals(
    policy: &PolicyState,
    artifact: &WitnessRequestArtifactV1,
    paths: &[PathBuf],
    wait_seconds: u64,
) -> Result<Vec<jury_protocol::witness_v1::ApprovalDecisionV1>, CliError> {
    if paths.len() > jury_protocol::witness_v1::MAX_RECORDED_APPROVALS {
        return Err(invalid_approval_decision());
    }
    let rule = policy
        .witness_access_rule(
            &artifact.request.item_id,
            request_policy_operation(artifact.request.operation),
        )
        .map_err(|_| invalid_request_artifact())?;
    if rule.approval_threshold == 0 {
        return Ok(Vec::new());
    }
    let deadline = std::time::Instant::now()
        .checked_add(std::time::Duration::from_secs(wait_seconds))
        .ok_or_else(approval_pending)?;
    loop {
        let mut approvals: Vec<jury_protocol::witness_v1::ApprovalDecisionV1> = Vec::new();
        for path in paths {
            if !path.exists() {
                continue;
            }
            let bytes = read_public_file(path, 16 * 1024).map_err(map_filesystem_error)?;
            let approval: jury_protocol::witness_v1::ApprovalDecisionV1 =
                serde_json::from_slice(&bytes).map_err(|_| invalid_approval_decision())?;
            if serde_json::to_vec(&approval).ok().as_deref() != Some(bytes.as_slice()) {
                return Err(invalid_approval_decision());
            }
            jury_core::witness_engine::validate_approval_decision(
                policy,
                &artifact.checkpoint,
                &artifact.request,
                &artifact.action_manifest,
                &approval,
                timestamp_ms()?,
            )
            .map_err(|_| invalid_approval_decision())?;
            if let Some(prior) = approvals
                .iter()
                .find(|prior| prior.approver_id == approval.approver_id)
            {
                if prior != &approval {
                    return Err(invalid_approval_decision());
                }
            } else {
                approvals.push(approval);
            }
        }
        if approvals.len() >= usize::from(rule.approval_threshold) {
            approvals.sort_by_key(|approval| approval.approver_id);
            return Ok(approvals);
        }
        if timestamp_ms()? >= artifact.request.expires_at_ms
            || std::time::Instant::now() >= deadline
        {
            return Err(approval_pending());
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

const fn request_policy_operation(
    operation: jury_protocol::witness_v1::WitnessOperationV1,
) -> WitnessOperation {
    use jury_protocol::witness_v1::WitnessOperationV1;
    match operation {
        WitnessOperationV1::ReadStdout => WitnessOperation::ReadStdout,
        WitnessOperationV1::WritePrivateFile => WitnessOperation::WritePrivateFile,
        WitnessOperationV1::TemplateInjection => WitnessOperation::TemplateInjection,
        WitnessOperationV1::ChildEnvironment => WitnessOperation::ChildEnvironment,
        WitnessOperationV1::ChildStdin => WitnessOperation::ChildStdin,
        WitnessOperationV1::ItemMutation => WitnessOperation::ItemMutation,
        WitnessOperationV1::Backup => WitnessOperation::Backup,
        WitnessOperationV1::Recovery => WitnessOperation::Recovery,
        WitnessOperationV1::AdministrativeRekey => WitnessOperation::AdministrativeRekey,
    }
}

const fn map_witnessed_status(status: WitnessedAccessStatus) -> CliError {
    match status {
        WitnessedAccessStatus::Pending => approval_pending(),
        WitnessedAccessStatus::Denied => CliError::new(
            CliErrorKind::AccessDenied,
            "request-denied",
            "the witnessed request was denied",
        ),
        WitnessedAccessStatus::Expired => CliError::new(
            CliErrorKind::Conflict,
            "request-expired",
            "the witnessed request expired",
        ),
        WitnessedAccessStatus::Stale => CliError::new(
            CliErrorKind::Conflict,
            "request-stale",
            "the witnessed request is stale for current authenticated state",
        ),
        WitnessedAccessStatus::Replay => CliError::new(
            CliErrorKind::Conflict,
            "request-replay",
            "the witnessed response set contains replayed authority",
        ),
        WitnessedAccessStatus::Unavailable => witness_unavailable(),
        WitnessedAccessStatus::Cancelled => CliError::new(
            CliErrorKind::Conflict,
            "request-cancelled",
            "the witnessed request was cancelled",
        ),
        WitnessedAccessStatus::InsufficientQuorum => CliError::new(
            CliErrorKind::Conflict,
            "insufficient-witness-quorum",
            "too few distinct current witness responses approved this request",
        ),
    }
}

const fn map_witness_provider(kind: AccessProviderErrorKind) -> CliError {
    match kind {
        AccessProviderErrorKind::StalePolicy => map_witnessed_status(WitnessedAccessStatus::Stale),
        AccessProviderErrorKind::Cancelled => {
            map_witnessed_status(WitnessedAccessStatus::Cancelled)
        }
        AccessProviderErrorKind::Unauthorized => access_denied(),
        AccessProviderErrorKind::InvalidRequest
        | AccessProviderErrorKind::InvalidAncestry
        | AccessProviderErrorKind::WrongPrincipal
        | AccessProviderErrorKind::InvalidSlot
        | AccessProviderErrorKind::DirectSlotUnavailable
        | AccessProviderErrorKind::EntropyUnavailable
        | AccessProviderErrorKind::ProviderFailure
        | AccessProviderErrorKind::ConsumerPanicked => invalid_witness_response(),
    }
}

const fn approval_pending() -> CliError {
    CliError::new(
        CliErrorKind::Conflict,
        "approval-pending",
        "the request does not yet have its required independent approvals",
    )
}

fn validated_review_at_issue<'a>(
    policy: &'a PolicyState,
    artifact: &'a WitnessRequestArtifactV1,
) -> Result<jury_core::witness_approval::CompleteApprovalReview<'a>, CliError> {
    render_complete_approval_review(ApprovalReviewInput {
        policy,
        checkpoint: &artifact.checkpoint,
        request: &artifact.request,
        manifest: &artifact.action_manifest,
        presentation: &artifact.presentation,
        review_labels: &artifact.review_labels,
        now_ms: artifact.request.issued_at_ms,
    })
    .map_err(|_| invalid_request_artifact())
}

pub(super) fn review_labels_for_checkpoint(
    catalog: &PolicyCatalogV1,
    checkpoint: &VaultPolicyCheckpointV1,
) -> Result<Vec<jury_protocol::witness_v1::OwnerReviewLabelV1>, CliError> {
    catalog
        .review_label_sets
        .iter()
        .find(|set| set.digest == checkpoint.review_label_set_digest)
        .map(|set| set.labels.clone())
        .ok_or_else(invalid_request_artifact)
}

pub(super) fn resolve_request_target(
    labels: &[jury_protocol::witness_v1::OwnerReviewLabelV1],
    item_label: Option<&str>,
    item_id: Option<&str>,
    field_label: Option<&str>,
    field_id: Option<&str>,
) -> Result<(ItemId, FieldId), CliError> {
    match (item_id, field_id) {
        (Some(item_id), Some(field_id)) => {
            return Ok((parse_item_id(item_id)?, parse_field_id(field_id)?));
        }
        (None, None) => {}
        _ => return Err(invalid_request_artifact()),
    }
    let item_label = item_label.ok_or_else(invalid_request_artifact)?.as_bytes();
    let field_label = field_label.ok_or_else(invalid_request_artifact)?.as_bytes();
    use jury_protocol::witness_v1::PresentationSubjectV1;
    let matching_items = labels
        .iter()
        .filter(|label| {
            label.subject_kind == PresentationSubjectV1::Item
                && label.public_label.as_bytes() == item_label
        })
        .collect::<Vec<_>>();
    let item_id = match matching_items.as_slice() {
        [label] => label.item_id.ok_or_else(invalid_request_artifact)?,
        _ => return Err(invalid_request_artifact()),
    };
    let matching_fields = labels
        .iter()
        .filter(|label| {
            label.subject_kind == PresentationSubjectV1::Field
                && label.item_id == Some(item_id)
                && label.public_label.as_bytes() == field_label
        })
        .collect::<Vec<_>>();
    match matching_fields.as_slice() {
        [label] => Ok((
            item_id,
            label.field_id.ok_or_else(invalid_request_artifact)?,
        )),
        _ => Err(invalid_request_artifact()),
    }
}

fn parse_field_id(value: &str) -> Result<FieldId, CliError> {
    let bytes = decode_hex_32(value).ok_or_else(|| {
        CliError::new(
            CliErrorKind::InvalidArguments,
            "invalid-field-id",
            "field IDs must be canonical lowercase hexadecimal",
        )
    })?;
    FieldId::from_bytes(bytes).map_err(|_| {
        CliError::new(
            CliErrorKind::InvalidArguments,
            "invalid-field-id",
            "field IDs must be canonical lowercase hexadecimal",
        )
    })
}

const fn invalid_request_artifact() -> CliError {
    CliError::new(
        CliErrorKind::AuthenticationFailed,
        "invalid-witness-request",
        "the witnessed request artifact is missing, stale, malformed, or not fully authenticated",
    )
}

const fn invalid_request_cancellation() -> CliError {
    CliError::new(
        CliErrorKind::AuthenticationFailed,
        "invalid-request-cancellation",
        "the request cancellation could not be authenticated for this actor",
    )
}

const fn invalid_approval_decision() -> CliError {
    CliError::new(
        CliErrorKind::AuthenticationFailed,
        "invalid-approval-decision",
        "the approval decision could not be authenticated for this approver",
    )
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    #[test]
    fn witnessed_lifecycle_statuses_have_distinct_cli_codes() {
        let cases = [
            (WitnessedAccessStatus::Pending, "approval-pending"),
            (WitnessedAccessStatus::Denied, "request-denied"),
            (WitnessedAccessStatus::Expired, "request-expired"),
            (WitnessedAccessStatus::Stale, "request-stale"),
            (WitnessedAccessStatus::Replay, "request-replay"),
            (WitnessedAccessStatus::Unavailable, "witness-unavailable"),
            (WitnessedAccessStatus::Cancelled, "request-cancelled"),
            (
                WitnessedAccessStatus::InsufficientQuorum,
                "insufficient-witness-quorum",
            ),
        ];
        let codes = cases
            .into_iter()
            .map(|(status, expected)| {
                let error = map_witnessed_status(status);
                assert_eq!(error.code(), expected);
                expected
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(codes.len(), cases.len());
    }
}
