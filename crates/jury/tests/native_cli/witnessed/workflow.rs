fn assert_protected_value_not_persisted(paths: [&Path; 4]) -> TestResult {
    for path in paths {
        assert_tree_omits(path, b"ExampleFieldValue")?;
    }
    Ok(())
}

fn append_witness_arguments(
    arguments: &mut Vec<String>,
    checkpoint: &Path,
    request: &Path,
    approval: &Path,
    receipt: &Path,
    endpoints: &[String],
) -> TestResult {
    arguments.extend([
        "--checkpoint".to_owned(),
        checkpoint
            .to_str()
            .ok_or("non-UTF-8 checkpoint")?
            .to_owned(),
        "--request-out".to_owned(),
        request.to_str().ok_or("non-UTF-8 request")?.to_owned(),
        "--approval".to_owned(),
        approval.to_str().ok_or("non-UTF-8 approval")?.to_owned(),
        "--receipt".to_owned(),
        receipt.to_str().ok_or("non-UTF-8 receipt")?.to_owned(),
        "--allow-insecure-loopback".to_owned(),
        "--wait-seconds".to_owned(),
        "30".to_owned(),
    ]);
    for endpoint in endpoints {
        arguments.extend(["--witness".to_owned(), endpoint.clone()]);
    }
    Ok(())
}

struct WorkflowContext<'a> {
    approval: ApprovalRunContext<'a>,
    artifacts: &'a Path,
    private_output: &'a Path,
    checkpoint: &'a Path,
    endpoints: &'a [String],
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

fn exercise_witnessed_read(context: &WorkflowContext<'_>) -> TestResult<PathBuf> {
    let request = context.artifacts.join("read.request.json");
    let approval = context.artifacts.join("read.approval.json");
    let receipt = context.artifacts.join("read.receipt.json");
    let output = context.private_output.join("read.output");
    let mut arguments = vec![
        "--json".to_owned(),
        "--passphrase-stdin".to_owned(),
        "--allow-degraded-protection".to_owned(),
        "read".to_owned(),
        "ExampleWitnessedItem".to_owned(),
        "ExampleWitnessedField".to_owned(),
        "--out".to_owned(),
        output.to_str().ok_or("non-UTF-8 read output")?.to_owned(),
    ];
    append_witness_arguments(
        &mut arguments,
        context.checkpoint,
        &request,
        &approval,
        &receipt,
        context.endpoints,
    )?;
    let (result, review) =
        run_with_async_approval(&context.approval, &arguments, &request, &approval)?;
    if !result.status.success() {
        return Err(format!(
            "witnessed read failed after request={}, approval={}, receipt={}, output={}: {}",
            request.exists(),
            approval.exists(),
            receipt.exists(),
            output.exists(),
            String::from_utf8_lossy(&result.stderr),
        )
        .into());
    }
    let result = success_json(result)?;
    assert_eq!(result["authority"], "witnessed-approved");
    assert_eq!(fs::read(&output)?, b"ExampleFieldValue");
    assert!(review.contains("ExampleWitnessedItem"));
    assert!(review.contains("ExampleWitnessedField"));
    assert!(review.contains(output.to_str().ok_or("non-UTF-8 output")?));
    Ok(receipt)
}

fn exercise_witnessed_injection(context: &WorkflowContext<'_>) -> TestResult<PathBuf> {
    let template = context.artifacts.join("ExampleTemplate.txt");
    fs::write(
        &template,
        b"prefix={{ExampleWitnessedItem.ExampleWitnessedField}}",
    )?;
    fs::set_permissions(&template, fs::Permissions::from_mode(0o644))?;
    let request = context.artifacts.join("inject.request.json");
    let approval = context.artifacts.join("inject.approval.json");
    let receipt = context.artifacts.join("inject.receipt.json");
    let output = context.private_output.join("inject.output");
    let mut arguments = vec![
        "--json".to_owned(),
        "--passphrase-stdin".to_owned(),
        "--allow-degraded-protection".to_owned(),
        "inject".to_owned(),
        "--template".to_owned(),
        template.to_str().ok_or("non-UTF-8 template")?.to_owned(),
        "--out".to_owned(),
        output.to_str().ok_or("non-UTF-8 inject output")?.to_owned(),
    ];
    append_witness_arguments(
        &mut arguments,
        context.checkpoint,
        &request,
        &approval,
        &receipt,
        context.endpoints,
    )?;
    let (result, review) =
        run_with_async_approval(&context.approval, &arguments, &request, &approval)?;
    assert_eq!(success_json(result)?["authority"], "witnessed-approved");
    assert_eq!(fs::read(&output)?, b"prefix=ExampleFieldValue");
    assert!(
        review.contains(
            context
                .approval
                .repository
                .to_str()
                .ok_or("non-UTF-8 repository")?
        )
    );
    assert!(review.contains(output.to_str().ok_or("non-UTF-8 output")?));
    Ok(receipt)
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
        "printf '%s' \"$TOKEN\"".to_owned(),
    ]);
    let (result, review) =
        run_with_async_approval(&context.approval, &arguments, &request, &approval)?;
    assert!(result.status.success());
    assert_eq!(result.stdout, b"ExampleFieldValue");
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
    let temporary = tempfile::tempdir()?;
    let repository = temporary.path().join("repository");
    let data = temporary.path().join("data");
    let state = temporary.path().join("state");
    let artifacts = temporary.path().join("artifacts");
    let private_output = temporary.path().join("private-output");
    fs::create_dir_all(repository.join(".git"))?;
    fs::write(repository.join(".git/HEAD"), b"ref: refs/heads/main\n")?;
    fs::create_dir(&artifacts)?;
    fs::set_permissions(&artifacts, fs::Permissions::from_mode(0o700))?;
    fs::create_dir(&private_output)?;
    fs::set_permissions(&private_output, fs::Permissions::from_mode(0o700))?;

    let actors = initialize_policy_actors(&repository, &data, &state, &artifacts)?;
    let policy_output = success_json(run(
        &repository,
        &data,
        &state,
        &[
            "--json",
            "--passphrase-stdin",
            "--allow-degraded-protection",
            "policy",
            "require",
            "witnessed",
            "--item",
            "ExampleWitnessedItem",
            "--approver",
            &actors.approver_id,
            "--witness",
            &actors.witness_one_id,
            "--witness",
            &actors.witness_two_id,
            "--approvals",
            "1",
            "--witness-quorum",
            "2",
            "--operation",
            "read-stdout",
            "--operation",
            "write-private-file",
            "--operation",
            "template-injection",
            "--operation",
            "child-environment",
            "--review-label",
            "ExampleWitnessedItem",
            "--field-review-label",
            "ExampleField=ExampleWitnessedField",
            "--request-lifetime",
            "300",
        ],
        format!("{OWNER_PASSPHRASE}\n").as_bytes(),
    )?)?;
    assert_eq!(policy_output["operation"], "policy-require-witnessed");
    assert_eq!(policy_output["vault_changed"], true);

    let material_path = artifacts.join("ExamplePolicyMaterial.json");
    success_json(run(
        &repository,
        &data,
        &state,
        &[
            "--json",
            "witness",
            "policy-material",
            "--output",
            material_path.to_str().ok_or("non-UTF-8 material path")?,
        ],
        b"",
    )?)?;
    let material_bytes = fs::read(&material_path)?;
    let policy_material = PolicyMaterialBytes::new(material_bytes)?;
    let policy = ReceiptPolicyMaterialV1::decode(&policy_material)?.replay()?;
    let vault = VaultFileV1::parse(&fs::read(repository.join(".jury/vault.json"))?)?;
    let item_id = vault.items.first().ok_or("missing item")?.item_id;
    let checkpoint_path = artifacts.join("ExampleCheckpoint.json");
    success_json(run(
        &repository,
        &data,
        &state,
        &[
            "--json",
            "--passphrase-stdin",
            "--allow-degraded-protection",
            "witness",
            "checkpoint",
            "--item-id",
            &encode_hex(item_id.as_bytes()),
            "--output",
            checkpoint_path.to_str().ok_or("non-UTF-8 checkpoint")?,
        ],
        format!("{OWNER_PASSPHRASE}\n").as_bytes(),
    )?)?;
    let checkpoint: VaultPolicyCheckpointV1 = serde_json::from_slice(&fs::read(&checkpoint_path)?)?;

    let witness_one = unlock_witness(&data, "witness-one", WITNESS_ONE_PASSPHRASE)?;
    let witness_two = unlock_witness(&data, "witness-two", WITNESS_TWO_PASSPHRASE)?;
    let approver = unlock_approver(&data, "approver", APPROVER_PASSPHRASE)?;
    let endpoint_one = spawn_engine_endpoint(
        witness_one,
        policy.clone(),
        checkpoint.clone(),
        policy_material.clone(),
    )?;
    let endpoint_two = spawn_engine_endpoint(
        witness_two,
        policy.clone(),
        checkpoint.clone(),
        policy_material,
    )?;
    let credential = artifacts.join("client.token");
    fs::write(&credential, CLIENT_TOKEN)?;
    fs::set_permissions(&credential, fs::Permissions::from_mode(0o600))?;
    assert_eq!(
        jury_filesystem::read_private_file(&credential, 258)?,
        CLIENT_TOKEN.as_bytes()
    );
    let endpoints = [
        endpoint_one.specification(&credential)?,
        endpoint_two.specification(&credential)?,
    ];
    let approval_context = ApprovalRunContext {
        repository: &repository,
        data: &data,
        state: &state,
        policy: &policy,
        approver: &approver,
    };
    let workflow = WorkflowContext {
        approval: approval_context,
        artifacts: &artifacts,
        private_output: &private_output,
        checkpoint: &checkpoint_path,
        endpoints: &endpoints,
    };
    assert_pending_approval_prevents_spawn(&workflow)?;
    let read_receipt = exercise_witnessed_read(&workflow)?;
    let inject_receipt = exercise_witnessed_injection(&workflow)?;
    let run_receipt = exercise_witnessed_run(&workflow)?;
    let exec_receipt = exercise_witnessed_exec(&workflow)?;
    exercise_too_late_cancellation(&workflow)?;
    verify_receipts(
        &repository,
        &data,
        &state,
        &[&read_receipt, &inject_receipt, &run_receipt, &exec_receipt],
    )?;
    assert_protected_value_not_persisted([&repository, &data, &state, &artifacts])?;

    endpoint_one.finish()?;
    endpoint_two.finish()?;
    Ok(())
}
