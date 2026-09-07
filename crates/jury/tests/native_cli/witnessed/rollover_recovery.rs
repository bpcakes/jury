fn assert_rollover_registration_failure(output: Output, registration: &Path) -> TestResult {
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    let journal: jury_protocol::vault_v1::PolicyJournalV1 = serde_json::from_slice(&fs::read(registration.join("journal.json"))?)?;
    let fingerprint = encode_hex(journal.genesis.recomputed_fingerprint()?.as_bytes());
    let expected = format!("Rollover draft genesis: {fingerprint}. Each candidate must authenticate journal.json against the source and this expected genesis, then write <principal-id>.proof.json into --registration-dir.\n");
    assert!(output.stderr.starts_with(expected.as_bytes()));
    let error: serde_json::Value = serde_json::from_slice(&output.stderr[expected.len()..])?;
    assert_eq!(error["error"]["code"], "rollover-publication-incomplete");
    Ok(())
}

fn resume_rollover_candidate(
    context: &ApprovalRunContext<'_>,
    arguments: &[String],
    endpoints: [&EngineEndpoint; 2],
    offline: &Path,
    out: &Path,
    snapshot: &serde_json::Value,
) -> TestResult<serde_json::Value> {
    let counts = endpoints.map(EngineEndpoint::request_counts);
    let mut moved = arguments.to_vec();
    let index = moved.iter().position(|argument| argument == "--backup-out").ok_or("missing backup option")? + 1;
    moved[index] = offline.join("ExampleDifferent.backup").to_str().ok_or("invalid path")?.into();
    let error = run_rollover_resume(context, &moved)?;
    assert!(!error.status.success());
    assert!(error.stdout.is_empty());
    let error: serde_json::Value = serde_json::from_slice(&error.stderr)?;
    assert_eq!(error["error"]["code"], "invalid-rollover-target");
    assert_eq!(endpoints.map(EngineEndpoint::request_counts), counts);

    let prefix = snapshot["prefix"].as_str().ok_or("missing staging prefix")?;
    let saved_backup = offline.join(format!("{prefix}.backup.pending"));
    let original = fs::read(&saved_backup)?;
    let mut corrupt = original.clone();
    let last = corrupt.last_mut().ok_or("empty backup")?;
    *last ^= 1;
    fs::write(&saved_backup, &corrupt)?;
    let error = run_rollover_resume(context, arguments)?;
    assert_eq!(error.status.code(), Some(1));
    assert!(error.stdout.is_empty());
    let error: serde_json::Value = serde_json::from_slice(&error.stderr)?;
    assert_eq!(error["error"]["code"], "rollover-publication-incomplete");
    assert_eq!(endpoints.map(EngineEndpoint::request_counts), counts);
    fs::write(&saved_backup, &original)?;
    assert_corrupt_rollover_ack(context, arguments, endpoints, out)?;
    assert_bound_rollover_snapshot(context, arguments, endpoints, out)?;

    let result = resume_with_concurrent_source_mutation(context, arguments, endpoints[0], out)?;
    for (endpoint, (registration, reserve)) in endpoints.into_iter().zip(counts) {
        assert_eq!(endpoint.request_counts(), (registration + 1, reserve));
    }
    Ok(result)
}

fn run_rollover_resume(context: &ApprovalRunContext<'_>, arguments: &[String]) -> TestResult<Output> {
    let arguments = arguments.iter().map(String::as_str).collect::<Vec<_>>();
    run(context.repository, context.data, context.state, &arguments, format!("{OWNER_PASSPHRASE}\nExampleBackupPassphrase\n").as_bytes())
}

fn assert_rollover_staging_removed(out: &Path, offline: &Path) -> TestResult {
    for name in ["rollover.pending.json", "rollover.pending.cleanup.json", "rollover.outputs.pending.json", "rollover.outputs.cleanup.json"] {
        assert!(!out.join(name).exists(), "retained recovery marker: {name}");
    }
    for entry in fs::read_dir(offline)? {
        assert!(!entry?.file_name().to_string_lossy().starts_with(".jury-rollover-"));
    }
    Ok(())
}

fn exercise_rollover_cleanup_retry(
    context: &ApprovalRunContext<'_>,
    arguments: &[String],
    endpoints: [&EngineEndpoint; 2],
    out: &Path,
    offline: &Path,
    snapshot_bytes: &[u8],
) -> TestResult {
    let counts = endpoints.map(EngineEndpoint::request_counts);
    let vault_bytes = fs::read(out.join("vault.json"))?;
    // Recreate the exact last cleanup boundary: outputs exist, payload staging
    // and the candidate guard are gone, and only quarantined metadata remains.
    // Preserve struct field order because the runtime requires canonical bytes.
    let marker = out.join("rollover.outputs.cleanup.json");
    fs::write(&marker, snapshot_bytes)?;
    fs::set_permissions(&marker, fs::Permissions::from_mode(0o600))?;
    let recovered = success_json(run_rollover_resume(context, arguments)?)?;
    assert_eq!(recovered["published"], true);
    assert_eq!(recovered["global_freshness_claimed"], false);
    assert_eq!(endpoints.map(EngineEndpoint::request_counts), counts);
    assert_eq!(fs::read(out.join("vault.json"))?, vault_bytes);
    assert_rollover_staging_removed(out, offline)?;
    let repeated = success_json(run_rollover_resume(context, arguments)?)?;
    assert_eq!(repeated["published"], true);
    assert_eq!(endpoints.map(EngineEndpoint::request_counts), counts);
    assert_eq!(fs::read(out.join("vault.json"))?, vault_bytes);
    exercise_unpublished_rollover_retry(context, arguments, endpoints, out, offline, snapshot_bytes)?;
    Ok(())
}

fn assert_corrupt_rollover_ack(context: &ApprovalRunContext<'_>, arguments: &[String], endpoints: [&EngineEndpoint; 2], out: &Path) -> TestResult {
    let counts = endpoints.map(EngineEndpoint::request_counts);
    let path = out.join(format!("witness-{}-registration.json", encode_hex(endpoints[0].witness_id.as_bytes())));
    let original = fs::read(&path)?;
    let mut corrupt: serde_json::Value = serde_json::from_slice(&original)?;
    corrupt["exact_anchor"]["signature"] = serde_json::to_value(jury_protocol::vault_v1::Signature64::new([0; 64]))?;
    fs::write(&path, serde_json::to_vec(&corrupt)?)?;
    let error = run_rollover_resume(context, arguments)?;
    assert_eq!(error.status.code(), Some(2));
    assert!(error.stdout.is_empty());
    let error: serde_json::Value = serde_json::from_slice(&error.stderr)?;
    assert_eq!(error["error"]["code"], "invalid-rollover-witness-registration");
    assert_eq!(endpoints.map(EngineEndpoint::request_counts), counts);
    fs::write(&path, &original)?;
    Ok(())
}

fn exercise_unpublished_rollover_retry(
    context: &ApprovalRunContext<'_>, arguments: &[String], endpoints: [&EngineEndpoint; 2], out: &Path, offline: &Path, snapshot_bytes: &[u8],
) -> TestResult {
    let vault_path = out.join("vault.json");
    let candidate = fs::read(&vault_path)?;
    // Model the boundary after all registration acknowledgements and other
    // outputs exist, but before the last vault publication. Saved receipts
    // cannot replace contacting the endpoints in this incomplete installation.
    let pending = out.join("rollover.pending.json");
    let marker = out.join("rollover.outputs.pending.json");
    for (path, bytes) in [(&pending, candidate.as_slice()), (&marker, snapshot_bytes)] {
        fs::write(path, bytes)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    fs::remove_file(&vault_path)?;
    let rejected_token = out.parent().ok_or("missing output parent")?.join("ExampleRejectedResumeOperator.token");
    fs::write(&rejected_token, "ExampleRejectedResumeOperator_0123456789abcdef")?;
    fs::set_permissions(&rejected_token, fs::Permissions::from_mode(0o600))?;
    let mut rejected = arguments.to_vec();
    let index = rejected.iter().rposition(|argument| argument == "--destination-witness").ok_or("missing destination endpoint")? + 1;
    rejected[index] = endpoints[1].specification(&rejected_token)?;
    let counts = endpoints.map(EngineEndpoint::request_counts);
    let output = run_rollover_resume(context, &rejected)?;
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    let error: serde_json::Value = serde_json::from_slice(&output.stderr)?;
    assert_eq!(error["error"]["code"], "rollover-publication-incomplete");
    assert!(!vault_path.exists());
    for (endpoint, (registration, reserve)) in endpoints.into_iter().zip(counts) {
        assert_eq!(endpoint.request_counts(), (registration + 1, reserve));
    }
    let result = success_json(run_rollover_resume(context, arguments)?)?;
    assert_eq!(result["published"], true);
    assert_eq!(fs::read(&vault_path)?, candidate);
    for (endpoint, (registration, reserve)) in endpoints.into_iter().zip(counts) {
        assert_eq!(endpoint.request_counts(), (registration + 2, reserve));
    }
    assert_rollover_staging_removed(out, offline)?;
    Ok(())
}
