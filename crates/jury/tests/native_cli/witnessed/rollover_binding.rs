fn assert_bound_rollover_snapshot(
    context: &ApprovalRunContext<'_>, arguments: &[String], endpoints: [&EngineEndpoint; 2], out: &Path,
) -> TestResult {
    let marker = out.join("rollover.outputs.pending.json");
    let original = fs::read(&marker)?;
    let counts = endpoints.map(EngineEndpoint::request_counts);
    let index = arguments.iter().position(|argument| argument == "--backup-out").ok_or("missing backup option")? + 1;
    let mut moved = arguments.to_vec();
    let parent = Path::new(&arguments[index]).parent().ok_or("missing backup parent")?;
    moved[index] = parent.join("ExampleSubstituted.backup").to_str().ok_or("invalid path")?.into();
    // Both the invocation and canonical marker name the replacement path.
    // The existing owner-MAC state must still reject this self-consistent edit.
    let changed = replace_snapshot_field(&original, "backup_out", &arguments[index], &moved[index])?;
    fs::write(&marker, &changed)?;
    assert_bound_snapshot_refused(context, &moved, endpoints, counts)?;
    assert_eq!(fs::read(&marker)?, changed);
    fs::write(&marker, &original)?;
    assert_substituted_checkpoint_refused(context, arguments, endpoints, &marker, &original)?;
    Ok(())
}

fn assert_substituted_checkpoint_refused(
    context: &ApprovalRunContext<'_>, arguments: &[String], endpoints: [&EngineEndpoint; 2], marker: &Path, original: &[u8],
) -> TestResult {
    let snapshot: serde_json::Value = serde_json::from_slice(original)?;
    let checkpoint: VaultPolicyCheckpointV1 = serde_json::from_slice(&serde_json::to_vec(&snapshot["registration_checkpoint"])?)?;
    let backup_out: PathBuf = serde_json::from_value(snapshot["backup_out"].clone())?;
    let transfer_path = backup_out.parent().ok_or("missing backup parent")?.join(format!("{}.transfer.pending", snapshot["prefix"].as_str().ok_or("missing prefix")?));
    let transfer = jury_core::transfer::ValidatedTransfer::parse(&fs::read(transfer_path)?)?;
    let UnlockedIdentity::VaultPrincipal(owner) = unlock_named_identity(context.data, "default", OWNER_PASSPHRASE)? else { return Err("unexpected owner kind".into()); };
    let replacement = jury_core::witness_client::VaultPolicyCheckpointCreator::create(
        transfer.policy(), Digest32::new([0; 32]), &owner, checkpoint.issued_at_ms + 1,
    )?;
    assert_ne!(replacement, checkpoint);
    // This is a valid owner-signed checkpoint for the same vault and sequence,
    // not malformed syntax or a forged signature. It is not the saved intent.
    jury_core::witness_operations::verify_checkpoint_propagation(transfer.policy(), &replacement, &[])?;
    let changed = replace_snapshot_field(original, "registration_checkpoint", &checkpoint, &replacement)?;
    fs::write(marker, &changed)?;
    let counts = endpoints.map(EngineEndpoint::request_counts);
    assert_bound_snapshot_refused(context, arguments, endpoints, counts)?;
    assert_eq!(fs::read(marker)?, changed);
    fs::write(marker, original)?;
    Ok(())
}

fn replace_snapshot_field<T: serde::Serialize>(original: &[u8], name: &str, prior: &T, next: &T) -> TestResult<Vec<u8>> {
    let original = std::str::from_utf8(original)?;
    let prior = format!("\"{name}\":{}", serde_json::to_string(prior)?);
    let next = format!("\"{name}\":{}", serde_json::to_string(next)?);
    assert_eq!(original.matches(&prior).count(), 1);
    Ok(original.replacen(&prior, &next, 1).into_bytes())
}

fn assert_bound_snapshot_refused(
    context: &ApprovalRunContext<'_>, arguments: &[String], endpoints: [&EngineEndpoint; 2], counts: [(usize, usize); 2],
) -> TestResult {
    let error = run_rollover_resume(context, arguments)?;
    assert_eq!(error.status.code(), Some(1));
    assert!(error.stdout.is_empty());
    let error: serde_json::Value = serde_json::from_slice(&error.stderr)?;
    assert_eq!(error["error"]["code"], "rollover-publication-incomplete");
    assert_eq!(endpoints.map(EngineEndpoint::request_counts), counts);
    Ok(())
}
