use super::*;

pub(super) fn assert_request_artifact_workflow(
    repository: &Path,
    data: &Path,
    state: &Path,
    artifacts: &Path,
) -> TestResult {
    let checkpoint_path = artifacts.join("ExampleCheckpoint.json");
    let checkpoint_output = success_json(run(
        repository,
        data,
        state,
        &[
            "--json",
            "--passphrase-stdin",
            "--allow-degraded-protection",
            "witness",
            "checkpoint",
            "--out",
            checkpoint_path.to_str().ok_or("invalid checkpoint path")?,
        ],
        b"OwnerPassphrase1234\n",
    )?)?;
    assert_eq!(checkpoint_output["operation"], "witness-checkpoint");
    let active_policy_set = checkpoint_output["active_witness_policy_set_digest"]
        .as_str()
        .ok_or("missing active policy set digest")?;
    assert_eq!(active_policy_set.len(), 64);
    assert_eq!(checkpoint_output["contains_private_material"], false);
    let checkpoint_bytes = fs::read(&checkpoint_path)?;
    let checkpoint: jury_protocol::witness_v1::VaultPolicyCheckpointV1 =
        serde_json::from_slice(&checkpoint_bytes)?;
    assert_eq!(serde_json::to_vec(&checkpoint)?, checkpoint_bytes);
    assert_eq!(
        checkpoint_output["checkpoint_digest"],
        encode_hex(checkpoint.digest()?.as_bytes())
    );
    assert_request_preview_and_inspect(repository, data, state, artifacts, &checkpoint_path)
}

fn assert_request_preview_and_inspect(
    repository: &Path,
    data: &Path,
    state: &Path,
    artifacts: &Path,
    checkpoint_path: &Path,
) -> TestResult {
    let request_path = artifacts.join("ExampleRequest.json");
    let request_output = success_json(run(
        repository,
        data,
        state,
        &[
            "--json",
            "--passphrase-stdin",
            "--allow-degraded-protection",
            "request",
            "preview",
            "--item",
            "ExampleWitnessedItem",
            "--field",
            "ExampleWitnessedField",
            "--checkpoint",
            checkpoint_path.to_str().ok_or("invalid checkpoint path")?,
            "--out",
            request_path.to_str().ok_or("invalid request path")?,
        ],
        b"OwnerPassphrase1234\n",
    )?)?;
    assert_eq!(request_output["operation"], "request-create");
    assert_eq!(request_output["phase"], "pending-review");
    assert_eq!(request_output["session_private_key_persisted"], false);
    assert_eq!(request_output["later_execution_available"], false);
    let request_bytes = fs::read(&request_path)?;
    assert!(
        !request_bytes
            .windows(17)
            .any(|window| window == b"ExampleFieldValue")
    );
    let inspected = success_json(run(
        repository,
        data,
        state,
        &[
            "--json",
            "request",
            "inspect",
            request_path.to_str().ok_or("invalid request path")?,
        ],
        b"",
    )?)?;
    assert_eq!(inspected["operation"], "request-inspect");
    assert_eq!(inspected["complete"], true);
    assert_eq!(inspected["lossy"], false);
    let displays = inspected["complete_review"]["meaningful_displays"]
        .as_array()
        .ok_or("missing meaningful approval displays")?;
    assert!(
        displays
            .iter()
            .any(|display| display == "ExampleWitnessedItem")
    );
    assert!(
        displays
            .iter()
            .any(|display| display == "ExampleWitnessedField")
    );
    assert_review_is_not_terminal_width_dependent(repository, data, state, &request_path)?;
    let noninteractive_approval = artifacts.join("NoninteractiveApproval.json");
    let refused = run(
        repository,
        data,
        state,
        &[
            "--json",
            "--identity",
            "approver",
            "approve",
            request_path.to_str().ok_or("invalid request path")?,
            "--out",
            noninteractive_approval
                .to_str()
                .ok_or("invalid approval path")?,
        ],
        b"approve\n",
    )?;
    assert_eq!(refused.status.code(), Some(2));
    let refusal: serde_json::Value = serde_json::from_slice(&refused.stderr)?;
    assert_eq!(refusal["error"]["code"], "interactive-approval-required");
    assert!(!noninteractive_approval.exists());
    let status = success_json(run(
        repository,
        data,
        state,
        &[
            "--json",
            "request",
            "status",
            request_path.to_str().ok_or("invalid request path")?,
        ],
        b"",
    )?)?;
    assert_eq!(status["phase"], "pending");
    assert_eq!(status["session_private_key_present"], false);
    assert_eq!(status["witnesses_contacted"], false);
    Ok(())
}

fn assert_review_is_not_terminal_width_dependent(
    repository: &Path,
    data: &Path,
    state: &Path,
    request: &Path,
) -> TestResult {
    let request = request.to_str().ok_or("invalid request path")?;
    let mut reference = None;
    for columns in ["1", "20", "40", "80", "240"] {
        let output = run_with_environment(
            repository,
            data,
            state,
            &["request", "inspect", request],
            b"",
            &[("COLUMNS", columns)],
        )?;
        assert!(output.status.success());
        assert!(output.stderr.is_empty());
        assert!(
            !output
                .stdout
                .windows(3)
                .any(|window| window == "…".as_bytes())
        );
        if let Some(reference) = &reference {
            assert_eq!(&output.stdout, reference);
        } else {
            reference = Some(output.stdout);
        }
    }
    Ok(())
}
