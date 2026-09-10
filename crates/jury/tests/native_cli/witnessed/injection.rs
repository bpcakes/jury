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
    assert_renderer_identity(&request, Path::new(env!("CARGO_BIN_EXE_jury")))?;
    Ok(receipt)
}

fn assert_renderer_identity(request: &Path, executable: &Path) -> TestResult {
    // Check the actual CLI request, not the test harness executable.
    use std::os::unix::fs::MetadataExt as _;
    let image = fs::canonicalize(executable)?;
    let metadata = fs::metadata(&image)?;
    let expected = format!(
        "jury-template-renderer-v1|{}|{}|{}|{}|{}",
        image.to_str().ok_or("non-UTF-8 executable")?,
        metadata.dev(),
        metadata.ino(),
        metadata.mode(),
        metadata.len(),
    );
    let artifact: RequestArtifact = serde_json::from_slice(&fs::read(request)?)?;
    assert_eq!(
        artifact.action_manifest.executable_identity,
        Some(jury_protocol::witness_v1::OperationBytes::new(
            expected.into_bytes()
        )?),
    );
    Ok(())
}
