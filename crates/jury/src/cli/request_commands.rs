use super::*;

const MAX_REQUEST_ARTIFACT_BYTES: usize = 512 * 1024;

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct WitnessRequestArtifactV1 {
    schema: u16,
    checkpoint: VaultPolicyCheckpointV1,
    request: jury_protocol::witness_v1::WitnessRequestV1,
    action_manifest: jury_protocol::witness_v1::ActionManifestV1,
    presentation: jury_protocol::witness_v1::ApprovalPresentationV1,
    review_labels: Vec<jury_protocol::witness_v1::OwnerReviewLabelV1>,
}

struct PublicRequestContext {
    policy: PolicyState,
}

pub(super) struct PreparedWitnessReceiptDestination {
    destination: PublicFilePrecondition,
}

pub(super) struct CollectedWitnessAuthorization {
    pub(super) checkpoint: VaultPolicyCheckpointV1,
    pub(super) prepared: jury_core::witness_client::PreparedWitnessRequest,
    pub(super) approvals: Vec<jury_protocol::witness_v1::ApprovalDecisionV1>,
    pub(super) responses: Vec<jury_protocol::witness_v1::WitnessResponseV1>,
    pub(super) failure_status: Option<WitnessedAccessStatus>,
}

pub(super) fn request_create(
    cli: &Cli,
    arguments: &RequestCreateArgs,
    environment: &Environment,
    current: &Path,
    protection: ProtectionPolicy,
) -> Result<CommandOutput, CliError> {
    let context = load_vault_principal(cli, environment, current, protection)?;
    let checkpoint = read_checkpoint(&arguments.checkpoint)?;
    let review_labels = review_labels_for_checkpoint(&context.catalog, &checkpoint)?;
    let (item_id, field_id) = resolve_request_target(
        &review_labels,
        arguments.item.as_deref(),
        arguments.item_id.as_deref(),
        arguments.field.as_deref(),
        arguments.field_id.as_deref(),
    )?;
    let now_ms = timestamp_ms()?;
    let prepared = WitnessRequestCreator::new(protection)
        .create_action(
            WitnessRequestContext {
                policy: &context.policy,
                checkpoint: &checkpoint,
                requester: &context.identity,
                review_labels,
                now_ms,
            },
            read_action(item_id, field_id, None)?,
        )
        .map_err(|_| invalid_request_artifact())?;
    let request_digest = prepared
        .request
        .digest()
        .map_err(|_| invalid_request_artifact())?;
    let artifact = WitnessRequestArtifactV1 {
        schema: 1,
        checkpoint,
        request: prepared.request,
        action_manifest: prepared.manifest,
        presentation: prepared.presentation,
        review_labels: prepared.review_labels,
    };
    let bytes = request_artifact_bytes(&artifact)?;
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

    // The protected receiver deliberately dies with this command. The public
    // artifact remains reviewable/cancellable, but cannot be executed later.
    drop(prepared.session);
    Ok(CommandOutput::Safe {
        operation: "request-create",
        fields: serde_json::json!({
            "request_id": hex(artifact.request.request_id.as_bytes()),
            "request_digest": hex(request_digest.as_bytes()),
            "operation_kind": artifact.request.operation,
            "phase": "pending-review",
            "out": arguments.out,
            "durability": durability(publication),
            "session_private_key_persisted": false,
            "later_execution_available": false,
            "maturity": "pre-alpha",
        }),
        lines: vec![
            format!("Request: {}", grouped(&hex(artifact.request.request_id.as_bytes()))),
            format!("Request artifact: {}", arguments.out.display()),
            "Phase: pending review".to_owned(),
            "Session private key persisted: false".to_owned(),
            "Later execution of this detached artifact: unavailable; use a foreground governed operation".to_owned(),
        ],
    })
}

pub(super) fn request_inspect(
    cli: &Cli,
    arguments: &RequestArtifactArgs,
    environment: &Environment,
    current: &Path,
) -> Result<CommandOutput, CliError> {
    let context = load_public_request_context(cli, environment, current)?;
    let artifact = read_request_artifact(&arguments.request)?;
    let review = validated_review_at_issue(&context.policy, &artifact)?;
    let document: serde_json::Value =
        serde_json::from_str(review.text()).map_err(|_| invalid_request_artifact())?;
    Ok(CommandOutput::Safe {
        operation: "request-inspect",
        fields: serde_json::json!({
            "request_id": hex(artifact.request.request_id.as_bytes()),
            "request_digest": hex(artifact.request.digest().map_err(|_| invalid_request_artifact())?.as_bytes()),
            "complete_review": document,
            "complete": true,
            "lossy": false,
            "session_private_key_present": false,
            "maturity": "pre-alpha",
        }),
        lines: vec![review.text().to_owned()],
    })
}

pub(super) fn request_status(
    cli: &Cli,
    arguments: &RequestArtifactArgs,
    environment: &Environment,
    current: &Path,
) -> Result<CommandOutput, CliError> {
    let context = load_public_request_context(cli, environment, current)?;
    let artifact = read_request_artifact(&arguments.request)?;
    validated_review_at_issue(&context.policy, &artifact)?;
    let now_ms = timestamp_ms()?;
    let phase = if now_ms >= artifact.request.expires_at_ms {
        "expired"
    } else if artifact
        .request
        .not_before_ms
        .is_some_and(|time| time > now_ms)
    {
        "not-yet-valid"
    } else {
        "pending"
    };
    Ok(CommandOutput::Safe {
        operation: "request-status",
        fields: serde_json::json!({
            "request_id": hex(artifact.request.request_id.as_bytes()),
            "phase": phase,
            "expires_at_ms": artifact.request.expires_at_ms,
            "session_private_key_present": false,
            "witnesses_contacted": false,
            "maturity": "pre-alpha",
        }),
        lines: vec![
            format!(
                "Request: {}",
                grouped(&hex(artifact.request.request_id.as_bytes()))
            ),
            format!("Phase: {phase}"),
            "Witnesses contacted by this offline status check: false".to_owned(),
        ],
    })
}

pub(super) fn request_execute(
    cli: &Cli,
    arguments: &RequestExecuteArgs,
    environment: &Environment,
    current: &Path,
    protection: ProtectionPolicy,
) -> Result<CommandOutput, CliError> {
    validate_plaintext_sink(cli, arguments.out.as_deref(), arguments.reveal)?;
    let endpoints = arguments
        .witnesses
        .iter()
        .map(|specification| {
            WitnessEndpointClient::parse(specification, arguments.allow_insecure_loopback)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let action_output = arguments
        .out
        .as_deref()
        .map(normalized_read_output)
        .transpose()?;
    let receipt_destination = prepare_witness_receipt_destination(&arguments.receipt)?;
    let context = load_vault_principal(cli, environment, current, protection)?;
    let checkpoint = read_checkpoint(&arguments.checkpoint)?;
    let review_labels = review_labels_for_checkpoint(&context.catalog, &checkpoint)?;
    let (item_id, field_id) = resolve_request_target(
        &review_labels,
        arguments.item.as_deref(),
        arguments.item_id.as_deref(),
        arguments.field.as_deref(),
        arguments.field_id.as_deref(),
    )?;
    let files = WitnessActionFiles {
        checkpoint: &arguments.checkpoint,
        request_out: &arguments.request_out,
        approvals: &arguments.approvals,
        wait_seconds: arguments.wait_seconds,
    };
    let mut authorization = collect_witness_authorization_with_checkpoint(
        &context,
        read_action(item_id, field_id, action_output)?,
        &endpoints,
        &files,
        protection,
        checkpoint,
    )?;
    let mut state = open_witnessed_body(&context, item_id, &mut authorization)?;
    let value = state
        .fields
        .iter()
        .find(|field| field.field_id == field_id)
        .map(|field| Zeroizing::new(field.value.as_bytes().to_vec()))
        .ok_or_else(field_unavailable);
    state.clear_sensitive();
    let value = value?;
    let receipt_digest = publish_witness_receipt(&context, &authorization, receipt_destination)?;
    if let Some(path) = &arguments.out {
        let publication =
            write_private_file(&context.home, path, &value, arguments.overwrite, protection)?;
        Ok(CommandOutput::Safe {
            operation: "request-execute",
            fields: serde_json::json!({
                "request_id": hex(authorization.prepared.request.request_id.as_bytes()),
                "phase": "completed",
                "authority": "witnessed-approved",
                "sink": "private-file",
                "durability": durability(publication),
                "witness_response_count": authorization.responses.len(),
                "session_private_key_persisted": false,
                "receipt": arguments.receipt,
                "receipt_digest": hex(receipt_digest.as_bytes()),
                "receipt_nonclaim": VerifiedWitnessReceipt::NONCLAIM,
            }),
            lines: vec![
                "Witnessed request completed".to_owned(),
                "Authority: witnessed-approved".to_owned(),
                format!("Private output: {}", path.display()),
                format!("Receipt: {}", arguments.receipt.display()),
                VerifiedWitnessReceipt::NONCLAIM.to_owned(),
            ],
        })
    } else {
        eprintln!("Authority: witnessed-approved");
        eprintln!("Receipt: {}", arguments.receipt.display());
        eprintln!("{}", VerifiedWitnessReceipt::NONCLAIM);
        let mut stdout = std::io::stdout().lock();
        stdout
            .write_all(&value)
            .and_then(|()| stdout.flush())
            .map_err(|_| filesystem_error())?;
        Ok(CommandOutput::Silent)
    }
}

fn read_action(
    item_id: ItemId,
    field_id: FieldId,
    output_destination: Option<Vec<u8>>,
) -> Result<WitnessActionRequest, CliError> {
    use jury_protocol::witness_v1::{
        OperationBytes, OperationContextV1, OutputSinkV1, StdinModeV1,
    };
    let writes_private_file = output_destination.is_some();
    Ok(WitnessActionRequest {
        item_id,
        field_ids: vec![field_id],
        operation_context: if writes_private_file {
            OperationContextV1::WritePrivateFile
        } else {
            OperationContextV1::ReadStdout
        },
        executable_identity: None,
        arguments: Vec::new(),
        working_directory: None,
        environment_injections: Vec::new(),
        stdin_target: None,
        stdin_mode: StdinModeV1::None,
        output_sink: if writes_private_file {
            OutputSinkV1::PrivateFile
        } else {
            OutputSinkV1::Stdout
        },
        output_destination: output_destination
            .map(OperationBytes::new)
            .transpose()
            .map_err(|_| invalid_request_artifact())?,
        timeout_ms: 0,
        output_limit_bytes: 0,
    })
}

fn normalized_read_output(path: &Path) -> Result<Vec<u8>, CliError> {
    if !path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )
        })
    {
        return Err(invalid_request_artifact());
    }
    let parent = std::fs::canonicalize(path.parent().ok_or_else(invalid_request_artifact)?)
        .map_err(|_| invalid_request_artifact())?;
    let normalized = parent.join(path.file_name().ok_or_else(invalid_request_artifact)?);
    normalized
        .to_str()
        .map(str::as_bytes)
        .map(<[u8]>::to_vec)
        .ok_or_else(invalid_request_artifact)
}

pub(super) struct WitnessActionFiles<'a> {
    pub checkpoint: &'a Path,
    pub request_out: &'a Path,
    pub approvals: &'a [PathBuf],
    pub wait_seconds: u64,
}

pub(super) fn collect_witness_authorization(
    context: &VaultPrincipalContext,
    action: WitnessActionRequest,
    endpoints: &[WitnessEndpointClient],
    files: &WitnessActionFiles<'_>,
    protection: ProtectionPolicy,
) -> Result<CollectedWitnessAuthorization, CliError> {
    let checkpoint = read_checkpoint(files.checkpoint)?;
    collect_witness_authorization_with_checkpoint(
        context, action, endpoints, files, protection, checkpoint,
    )
}

fn collect_witness_authorization_with_checkpoint(
    context: &VaultPrincipalContext,
    action: WitnessActionRequest,
    endpoints: &[WitnessEndpointClient],
    files: &WitnessActionFiles<'_>,
    protection: ProtectionPolicy,
    checkpoint: VaultPolicyCheckpointV1,
) -> Result<CollectedWitnessAuthorization, CliError> {
    if files.wait_seconds > 900 {
        return Err(CliError::new(
            CliErrorKind::InvalidArguments,
            "invalid-approval-wait",
            "approval wait must not exceed 900 seconds",
        ));
    }
    let review_labels = review_labels_for_checkpoint(&context.catalog, &checkpoint)?;
    let prepared = WitnessRequestCreator::new(protection)
        .create_action(
            WitnessRequestContext {
                policy: &context.policy,
                checkpoint: &checkpoint,
                requester: &context.identity,
                review_labels,
                now_ms: timestamp_ms()?,
            },
            action,
        )
        .map_err(|_| invalid_request_artifact())?;
    validate_endpoint_set(endpoints, &prepared.request)?;
    let artifact = WitnessRequestArtifactV1 {
        schema: 1,
        checkpoint: checkpoint.clone(),
        request: prepared.request.clone(),
        action_manifest: prepared.manifest.clone(),
        presentation: prepared.presentation.clone(),
        review_labels: prepared.review_labels.clone(),
    };
    publish_request_artifact(&artifact, files.request_out)?;
    let mut responses = Vec::new();
    let mut failure_status = None;
    for endpoint in endpoints {
        match endpoint.reserve(&prepared.request, &prepared.manifest) {
            Ok(progress) => {
                if let Some(response) = progress.response {
                    responses.push(response);
                }
            }
            Err(error) => merge_failure_status(&mut failure_status, error.status()),
        }
    }
    let approvals = wait_for_approvals(
        &context.policy,
        &artifact,
        files.approvals,
        files.wait_seconds,
    )?;
    for endpoint in endpoints {
        match endpoint.decide(&prepared.request, &prepared.manifest, &approvals) {
            Ok(progress) => {
                if let Some(response) = progress.response {
                    responses
                        .retain(|prior| prior.decision.witness_id != response.decision.witness_id);
                    responses.push(response);
                }
            }
            Err(error) => merge_failure_status(&mut failure_status, error.status()),
        }
    }
    Ok(CollectedWitnessAuthorization {
        checkpoint,
        prepared,
        approvals,
        responses,
        failure_status,
    })
}

pub(super) fn open_witnessed_body(
    context: &VaultPrincipalContext,
    item_id: ItemId,
    authorization: &mut CollectedWitnessAuthorization,
) -> Result<jury_protocol::vault_v1::ItemStateV1, CliError> {
    let envelope = context
        .vault
        .items
        .iter()
        .find(|envelope| envelope.item_id == item_id)
        .ok_or_else(invalid_request_artifact)?;
    let capability = witness_operation_capability(authorization.prepared.request.operation);
    let target = RevisionAccessTarget::current(
        &context.policy,
        envelope,
        context.identity.principal_id(),
        ContentRole::Body,
        capability,
    )
    .map_err(|_| invalid_request_artifact())?;
    let access_request = RevisionAccessRequest {
        policy: &context.policy,
        envelope,
        target,
        capability,
        cancellation: &NeverCancelled,
    };
    let mut provider = WitnessedItemAccessProvider::new(
        &authorization.checkpoint,
        &authorization.prepared.request,
        &authorization.prepared.manifest,
        &authorization.responses,
        &authorization.prepared.session,
        timestamp_ms()?,
    );
    let outcome = provider.access_revision(access_request, |access| {
        access.open_body().map_err(|_| invalid_request_artifact())
    });
    let counted_responses = provider.counted_responses();
    match outcome {
        Ok(ItemAccessOutcome::Complete {
            authority: AccessCompletion::WitnessedApproved,
            value,
        }) => {
            authorization.responses = counted_responses;
            Ok(value)
        }
        Ok(ItemAccessOutcome::Complete {
            authority: AccessCompletion::Direct,
            ..
        }) => Err(invalid_witness_response()),
        Ok(ItemAccessOutcome::Witnessed(status)) => Err(map_witnessed_status(
            authorization
                .failure_status
                .map_or(status, |failure| status.merge(failure)),
        )),
        Err(ItemAccessError::Consumer(error)) => Err(error),
        Err(ItemAccessError::Provider(error)) => Err(map_witness_provider(error.kind())),
    }
}

fn merge_failure_status(current: &mut Option<WitnessedAccessStatus>, next: WitnessedAccessStatus) {
    *current = Some(current.map_or(next, |current| current.merge(next)));
}

pub(super) fn publish_witness_receipt(
    context: &VaultPrincipalContext,
    authorization: &CollectedWitnessAuthorization,
    destination: PreparedWitnessReceiptDestination,
) -> Result<Digest32, CliError> {
    let policy_material = ReceiptPolicyMaterialV1 {
        schema: 1,
        journal: context.vault.policy.clone(),
        witness_policies: context.catalog.witness_policies.clone(),
    }
    .encode()
    .map_err(|_| invalid_request_artifact())?;
    let receipt = assemble_witness_receipt(
        &context.policy,
        &authorization.prepared.request,
        authorization.checkpoint.clone(),
        WitnessReceiptEvidence {
            receipt_id: draw_receipt_id()?,
            presentation_digest: authorization.prepared.manifest.presentation_digest.clone(),
            policy_material,
            approval_decisions: authorization.approvals.clone(),
            witness_decisions: authorization
                .responses
                .iter()
                .map(|response| response.decision.clone())
                .collect(),
            reason: jury_protocol::witness_v1::WitnessReasonV1::None,
            issued_at_ms: timestamp_ms()?,
        },
    )
    .map_err(|_| invalid_witness_response())?;
    let digest = receipt.digest().map_err(|_| invalid_witness_response())?;
    let bytes = receipt
        .to_json_bytes()
        .map_err(|_| invalid_witness_response())?;
    PreparedPublicFile::prepare_bounded_if_unchanged(
        destination.destination,
        &bytes,
        MAX_RECEIPT_JSON_BYTES,
        false,
    )
    .map_err(map_filesystem_error)?
    .publish()
    .map_err(map_filesystem_error)?;
    Ok(digest)
}

pub(super) fn prepare_witness_receipt_destination(
    path: &Path,
) -> Result<PreparedWitnessReceiptDestination, CliError> {
    let destination = preview_public_file(path).map_err(map_filesystem_error)?;
    if destination.destination_exists() {
        return Err(CliError::new(
            CliErrorKind::Conflict,
            "already-exists",
            "the selected destination already exists",
        ));
    }
    Ok(PreparedWitnessReceiptDestination { destination })
}

include!("request_commands/support.rs");
