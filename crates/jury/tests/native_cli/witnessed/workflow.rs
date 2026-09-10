fn assert_existing_receipt_prevents_authorization(context: &WorkflowContext<'_>) -> TestResult {
    let denied_marker = context.artifacts.join("existing-receipt-child-marker");
    let request = context.artifacts.join("existing-receipt.request.json");
    let approval = context.artifacts.join("existing-receipt.approval.json");
    let receipt = context.artifacts.join("existing.receipt.json");
    fs::write(&receipt, b"existing-public-receipt")?;
    fs::set_permissions(&receipt, fs::Permissions::from_mode(0o644))?;
    let mut arguments = vec![
        "--json".to_owned(),
        "--passphrase-stdin".to_owned(),
        "--allow-degraded-protection".to_owned(),
        "run".to_owned(),
        "--env".to_owned(),
        "TOKEN=ExampleWitnessedItem.ExampleWitnessedField".to_owned(),
        "--timeout".to_owned(),
        "5".to_owned(),
    ];
    append_witness_arguments(
        &mut arguments,
        context.checkpoint,
        &request,
        &approval,
        &receipt,
        context.endpoints,
    )?;
    arguments.extend([
        "--".to_owned(),
        "/usr/bin/touch".to_owned(),
        denied_marker
            .to_str()
            .ok_or("non-UTF-8 denied marker")?
            .to_owned(),
    ]);
    let references = arguments.iter().map(String::as_str).collect::<Vec<_>>();
    let rejected = run(
        context.approval.repository,
        context.approval.data,
        context.approval.state,
        &references,
        b"",
    )?;
    assert_eq!(rejected.status.code(), Some(4));
    let error: serde_json::Value = serde_json::from_slice(&rejected.stderr)?;
    assert_eq!(error["error"]["code"], "already-exists");
    assert!(!request.exists());
    assert!(!approval.exists());
    assert!(!denied_marker.exists());
    assert_eq!(fs::read(receipt)?, b"existing-public-receipt");
    Ok(())
}

fn assert_pending_approval_prevents_spawn(context: &WorkflowContext<'_>) -> TestResult {
    let denied_marker = context.artifacts.join("approval-pending-child-marker");
    let request = context.artifacts.join("pending.request.json");
    let approval = context.artifacts.join("missing.approval.json");
    let receipt = context.artifacts.join("pending.receipt.json");
    let mut arguments = vec![
        "--json".to_owned(),
        "--passphrase-stdin".to_owned(),
        "--allow-degraded-protection".to_owned(),
        "run".to_owned(),
        "--env".to_owned(),
        "TOKEN=ExampleWitnessedItem.ExampleWitnessedField".to_owned(),
        "--timeout".to_owned(),
        "5".to_owned(),
    ];
    append_witness_arguments(
        &mut arguments,
        context.checkpoint,
        &request,
        &approval,
        &receipt,
        context.endpoints,
    )?;
    let wait_index = arguments
        .iter()
        .position(|argument| argument == "30")
        .ok_or("missing wait argument")?;
    arguments[wait_index] = "1".to_owned();
    arguments.extend([
        "--".to_owned(),
        "/usr/bin/touch".to_owned(),
        denied_marker
            .to_str()
            .ok_or("non-UTF-8 denied marker")?
            .to_owned(),
    ]);
    let references = arguments.iter().map(String::as_str).collect::<Vec<_>>();
    let pending = run(
        context.approval.repository,
        context.approval.data,
        context.approval.state,
        &references,
        format!("{OWNER_PASSPHRASE}\n").as_bytes(),
    )?;
    assert_eq!(pending.status.code(), Some(4));
    let error: serde_json::Value = serde_json::from_slice(&pending.stderr)?;
    assert_eq!(error["error"]["code"], "approval-pending");
    assert!(!denied_marker.exists());
    assert!(!receipt.exists());
    Ok(())
}

fn exercise_witnessed_run(context: &WorkflowContext<'_>) -> TestResult<PathBuf> {
    let request = context.artifacts.join("run.request.json");
    let approval = context.artifacts.join("run.approval.json");
    let receipt = context.artifacts.join("run.receipt.json");
    let mut arguments = vec![
        "--json".to_owned(),
        "--passphrase-stdin".to_owned(),
        "--allow-degraded-protection".to_owned(),
        "run".to_owned(),
        "--env".to_owned(),
        "TOKEN=ExampleWitnessedItem.ExampleWitnessedField".to_owned(),
        "--timeout".to_owned(),
        "5".to_owned(),
    ];
    append_witness_arguments(
        &mut arguments,
        context.checkpoint,
        &request,
        &approval,
        &receipt,
        context.endpoints,
    )?;
    arguments.extend([
        "--".to_owned(),
        "/bin/sh".to_owned(),
        "-c".to_owned(),
        "printf '%s' \"$TOKEN\"".to_owned(),
    ]);
    let (result, review) =
        run_with_async_approval(&context.approval, &arguments, &request, &approval)?;
    let result = success_json(result)?;
    assert_eq!(result["authority"], "witnessed-approved");
    assert_eq!(result["stdout"], "ExampleFieldValue");
    assert!(review.contains("TOKEN"));
    assert!(review.contains("/bin/sh"));
    Ok(receipt)
}

fn exercise_witnessed_exec(context: &WorkflowContext<'_>) -> TestResult<PathBuf> {
    let environment_file = context.artifacts.join("exec.env");
    fs::write(
        &environment_file,
        b"TOKEN={{ExampleWitnessedItem.ExampleWitnessedField}}\n",
    )?;
    fs::set_permissions(&environment_file, fs::Permissions::from_mode(0o644))?;
    let request = context.artifacts.join("exec.request.json");
    let approval = context.artifacts.join("exec.approval.json");
    let receipt = context.artifacts.join("exec.receipt.json");
    let mut arguments = vec![
        "--passphrase-stdin".to_owned(),
        "--allow-degraded-protection".to_owned(),
        "exec".to_owned(),
        "--env-file".to_owned(),
        environment_file
            .to_str()
            .ok_or("non-UTF-8 environment file")?
            .to_owned(),
    ];
    append_witness_arguments(
        &mut arguments,
        context.checkpoint,
        &request,
        &approval,
        &receipt,
        context.endpoints,
    )?;
    arguments.extend([
        "--".to_owned(),
        "/bin/sh".to_owned(),
        "-c".to_owned(),
        "IFS= read -r inherited || true; printf '%s|%s|%s' \"$TOKEN\" \"${EXAMPLE_AMBIENT_INPUT-unset}\" \"$inherited\"".to_owned(),
    ]);
    let (result, review) =
        run_with_async_approval(&context.approval, &arguments, &request, &approval)?;
    assert!(result.status.success());
    assert_eq!(result.stdout, b"ExampleFieldValue|unset|");
    let stderr = String::from_utf8(result.stderr)?;
    assert!(stderr.contains("Authority: witnessed-approved"));
    assert!(stderr.contains("does not prove endpoint execution"));
    assert!(review.contains("TOKEN"));
    Ok(receipt)
}

fn exercise_too_late_cancellation(context: &WorkflowContext<'_>) -> TestResult {
    let request = context.artifacts.join("read.request.json");
    let cancellation = context.artifacts.join("read.cancellation.json");
    let mut arguments = vec![
        "--json".to_owned(),
        "--passphrase-stdin".to_owned(),
        "--allow-degraded-protection".to_owned(),
        "request".to_owned(),
        "cancel".to_owned(),
        request.to_str().ok_or("non-UTF-8 request")?.to_owned(),
        "--out".to_owned(),
        cancellation
            .to_str()
            .ok_or("non-UTF-8 cancellation")?
            .to_owned(),
        "--allow-insecure-loopback".to_owned(),
    ];
    let unavailable_listener = TcpListener::bind("127.0.0.1:0")?;
    let unavailable_address = unavailable_listener.local_addr()?;
    drop(unavailable_listener);
    let first_parts = context.endpoints[0].split(',').collect::<Vec<_>>();
    let unavailable_first = format!(
        "{},http://{},{}",
        first_parts[0], unavailable_address, first_parts[2]
    );
    for endpoint in std::iter::once(&unavailable_first).chain(context.endpoints.iter().skip(1)) {
        arguments.extend(["--witness".to_owned(), endpoint.clone()]);
    }
    let references = arguments.iter().map(String::as_str).collect::<Vec<_>>();
    let result = success_json(run(
        context.approval.repository,
        context.approval.data,
        context.approval.state,
        &references,
        format!("{OWNER_PASSPHRASE}\n").as_bytes(),
    )?)?;
    assert_eq!(result["phase"], "too-late");
    assert_eq!(result["already_approved_was_too_late"], true);
    assert_eq!(result["witness_contact_count"], 2);
    assert_eq!(result["witness_response_count"], 1);
    assert_eq!(result["too_late_response_count"], 1);
    assert_eq!(result["failed_response_count"], 1);
    assert_eq!(result["quorum_precluded"], false);
    assert!(cancellation.is_file());
    Ok(())
}

#[test]
fn witnessed_only_default_read_inject_and_execution_complete_after_async_approval() -> TestResult {
    exercise_witnessed_workflow(false, false)
}

#[test]
fn witnessed_suite_migration_uses_recovery_approvals_and_reads_destination() -> TestResult {
    exercise_witnessed_workflow(true, false)
}

#[test]
fn witnessed_rollover_refuses_checkpoint_advance_during_preparation() -> TestResult {
    exercise_witnessed_workflow(false, true)
}

fn exercise_witnessed_workflow(migration: bool, freshness_only: bool) -> TestResult {
    with_witnessed_workflow(|workflow, actors, endpoints| {
        if !migration && !freshness_only {
            assert_existing_receipt_prevents_authorization(workflow)?;
            assert_pending_approval_prevents_spawn(workflow)?;
            let read_receipt = exercise_witnessed_read(workflow)?;
            let inject_receipt = exercise_witnessed_injection(workflow)?;
            let run_receipt = exercise_witnessed_run(workflow)?;
            let exec_receipt = exercise_witnessed_exec(workflow)?;
            exercise_too_late_cancellation(workflow)?;
            verify_receipts(
                workflow.approval.repository,
                workflow.approval.data,
                workflow.approval.state,
                &[&read_receipt, &inject_receipt, &run_receipt, &exec_receipt],
            )?;
            assert_protected_value_not_persisted([
                workflow.approval.repository,
                workflow.approval.data,
                workflow.approval.state,
                workflow.artifacts,
            ])?;
        }
        if freshness_only {
            refuse_checkpoint_advanced_during_preparation(workflow, actors, endpoints, migration)?;
        } else {
            exercise_witnessed_rollover(workflow, actors, endpoints, migration)?;
        }
        Ok(())
    })
}
