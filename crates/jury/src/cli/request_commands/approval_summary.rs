use super::*;

pub(super) fn approval_summary(
    review: &jury_core::witness_approval::CompleteApprovalReview<'_>,
    decision: &str,
    reason: jury_protocol::witness_v1::WitnessReasonV1,
    now_ms: u64,
) -> Result<String, CliError> {
    use jury_protocol::witness_v1::{
        ManifestArgumentV1, PresentationKindV1, PresentationSubjectV1,
    };

    let request = review.request();
    let manifest = review.validated().manifest();
    let scope = match manifest.content_role {
        ContentRole::Descriptor => "DESCRIPTOR — item name and metadata",
        ContentRole::Body => "BODY — item contents, potentially every field",
    };
    let mut lines = vec![
        format!("Content authorized: {scope}"),
        if decision == "deny" {
            format!("Decision to sign: deny (reason: {reason:?})")
        } else {
            format!("Decision to sign: {decision}")
        },
        format!("Item ID: {}", hex(request.item_id.as_bytes())),
    ];
    if let jury_protocol::witness_v1::OperationContextV1::OwnerChange {
        change,
        target_principal_id,
        next_vault_policy_sequence,
    } = &manifest.operation_context
    {
        let change = match change {
            jury_protocol::witness_v1::OwnerChangeKindV1::Grant => "grant",
            jury_protocol::witness_v1::OwnerChangeKindV1::Revoke => "revoke",
        };
        lines.push(format!("Owner change: {change} owner authority for principal {} at vault policy sequence {next_vault_policy_sequence}", hex(target_principal_id.as_bytes())));
        lines.push("The requesting client receives the decrypted content; no protocol output destination is specified.".to_owned());
        lines.push("Signing authorizes opening this content for the stated intent; it cannot enforce that the owner change is performed.".to_owned());
    }
    let presentation = review.validated().presentation();
    for label in review.authenticated_item_labels() {
        let text = std::str::from_utf8(label.public_label.as_bytes())
            .map_err(|_| invalid_request_artifact())?;
        lines.push(format!(
            "Authenticated item label: {text:?} (label {}; revision {})",
            hex(label.label_id.as_bytes()),
            label.label_revision
        ));
    }
    for entry in &presentation.entries {
        let label = match entry.subject_kind {
            PresentationSubjectV1::Item => "Item",
            PresentationSubjectV1::Field => "Field",
            PresentationSubjectV1::WorkingDirectory => "Working directory",
            PresentationSubjectV1::OutputSink => "Output destination",
        };
        let display = if entry.presentation_kind == PresentationKindV1::ExactNormalizedDisplay {
            exact_summary_bytes(entry.display_bytes.as_bytes())
        } else {
            // Keep owner-authenticated labels readable while escaping controls.
            let text = std::str::from_utf8(entry.display_bytes.as_bytes())
                .map_err(|_| invalid_request_artifact())?;
            format!("{text:?}")
        };
        lines.push(format!("{label}: {display}"));
    }
    lines.extend([
        format!(
            "Requester: {}",
            hex(request.requester_principal_id.as_bytes())
        ),
        format!(
            "Action / sink: {:?} / {:?}",
            manifest.operation, manifest.output_sink
        ),
        format!(
            "Revision: {}; key epoch: {}; seal: {}",
            request.revision,
            request.key_epoch,
            hex(request.revision_seal_id.as_bytes())
        ),
        format!(
            "Vault policy sequence: {}; witness policy revision: {}",
            request.vault_policy_sequence, request.witness_policy_revision
        ),
        format!(
            "Expires: {} Unix milliseconds ({} ms remaining at review)",
            request.expires_at_ms,
            request.expires_at_ms.saturating_sub(now_ms)
        ),
        format!(
            "Requested limits: {} ms; {} output bytes",
            manifest.timeout_ms, manifest.output_limit_bytes
        ),
        format!("Request: {}", hex(request.request_id.as_bytes())),
        format!("Platform assurance: {:?}", manifest.platform_assurance),
    ]);
    if let Some(not_before) = request.not_before_ms {
        lines.push(format!("Not before: {not_before} Unix milliseconds"));
    }
    for witness in &request.intended_witness_set {
        lines.push(format!("Witness: {}", hex(witness.witness_id.as_bytes())));
    }
    if let Some(executable) = &manifest.executable_identity {
        lines.push(format!(
            "Executable bytes: {}",
            exact_summary_bytes(executable.as_bytes())
        ));
    }
    for (position, argument) in manifest.arguments.iter().enumerate() {
        let value = match argument {
            ManifestArgumentV1::PublicLiteral { bytes } => exact_summary_bytes(bytes.as_bytes()),
            ManifestArgumentV1::SecretPlaceholder { target } => format!(
                "field placeholder: item {}, field {}",
                hex(target.item_id.as_bytes()),
                target
                    .field_id
                    .as_ref()
                    .map_or_else(|| "whole item".to_owned(), |id| hex(id.as_bytes()))
            ),
        };
        lines.push(format!("Argument {position}: {value}"));
    }
    for injection in &manifest.environment_injections {
        lines.push(format!(
            "Environment binding: {} -> {}",
            exact_summary_bytes(injection.name.as_bytes()),
            target_summary(&injection.target),
        ));
    }
    lines.push(format!("Stdin mode: {:?}", manifest.stdin_mode));
    if let Some(target) = &manifest.stdin_target {
        lines.push(format!("Stdin target: {}", target_summary(target)));
    }
    lines.push(
        "Full lossless review follows; signing binds the complete request and manifest.".to_owned(),
    );
    Ok(lines.join("\n"))
}

fn target_summary(target: &jury_protocol::witness_v1::WitnessTargetV1) -> String {
    format!(
        "item {}, field {}",
        hex(target.item_id.as_bytes()),
        target
            .field_id
            .as_ref()
            .map_or_else(|| "whole item".to_owned(), |id| hex(id.as_bytes()),),
    )
}

fn exact_summary_bytes(bytes: &[u8]) -> String {
    jury_core::witness_approval::exact_byte_display(bytes)
}
