struct RolloverChild(Option<std::process::Child>);

impl Drop for RolloverChild {
    fn drop(&mut self) {
        if let Some(child) = &mut self.0 {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn exercise_witnessed_rollover(
    workflow: &WorkflowContext<'_>,
    actors: &super::native_cli_additional::PolicyActors,
    endpoints: [&EngineEndpoint; 2],
    migration: bool,
) -> TestResult {
    let (_, operation, suite) = super::native_cli_rollover::lineage_contract(migration);
    let context = &workflow.approval;
    let source_path = context.repository.join(".jury/vault.json");
    let source_bytes = fs::read(&source_path)?;
    let source = VaultFileV1::parse(&source_bytes)?;
    let out = workflow.private_output.join("ExampleRollover");
    let registration = workflow.private_output.join("ExampleRegistration");
    let offline = workflow.private_output.join("ExampleOffline");
    fs::create_dir(&offline)?;
    fs::set_permissions(&offline, fs::Permissions::from_mode(0o700))?;
    let backup = offline.join("ExampleRecovery.backup");
    let transfer = workflow.artifacts.join("ExampleRollover.transfer");
    let plan_path = workflow.artifacts.join("ExampleRecoveryAccess.json");
    let item_id = source.items[0].item_id;
    let approval_paths = rollover_source_plan(workflow, item_id, &plan_path)?;
    let operator = workflow.artifacts.join("ExampleOperator.token");
    fs::write(&operator, OPERATOR_TOKEN)?;
    fs::set_permissions(&operator, fs::Permissions::from_mode(0o600))?;
    let mut arguments = rollover_arguments([&out, &backup, &transfer, &registration, &plan_path], endpoints, &operator)?;
    select_rollover_command(&mut arguments, migration)?;
    assert_rollover_preview(context, &arguments, &[&out, &registration, &backup, &transfer], &approval_paths)?;

    let rejected_operator = workflow.artifacts.join("ExampleRejectedOperator.token");
    fs::write(&rejected_operator, "ExampleRejectedOperator_0123456789abcdef")?;
    fs::set_permissions(&rejected_operator, fs::Permissions::from_mode(0o600))?;
    let last_endpoint = arguments.iter().rposition(|argument| argument == "--destination-witness").ok_or("missing endpoint")? + 1;
    arguments[last_endpoint] = endpoints[1].specification(&rejected_operator)?;
    arguments.push("--adopt-new-lineage".into());
    let mut child = RolloverChild(Some(jury_command(context.repository, context.data, context.state).args(&arguments).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn()?));
    child.0.as_mut().ok_or("missing child")?.stdin.take().ok_or("missing stdin")?.write_all(format!("{OWNER_PASSPHRASE}\nExampleBackupPassphrase\nExampleBackupPassphrase\n").as_bytes())?;
    approve_rollover_source(context, &approval_paths, &mut child)?;
    prove_rollover_roles(context, actors, &registration)?;
    let failed = child.0.take().ok_or("missing child")?.wait_with_output()?;
    assert_rollover_registration_failure(failed, &registration)?;
    let candidate_bytes = fs::read(out.join("rollover.pending.json"))?;
    let snapshot_bytes = fs::read(out.join("rollover.outputs.pending.json"))?;
    let snapshot: serde_json::Value = serde_json::from_slice(&snapshot_bytes)?;
    assert!(!out.join("vault.json").exists());
    assert!(!backup.exists() && !transfer.exists());
    assert!(out.join(format!("witness-{}-registration.json", encode_hex(endpoints[0].witness_id.as_bytes()))).exists());
    assert!(!out.join(format!("witness-{}-registration.json", encode_hex(endpoints[1].witness_id.as_bytes()))).exists());
    assert_eq!(fs::read(&source_path)?, source_bytes);
    arguments[last_endpoint] = endpoints[1].specification(&operator)?;
    arguments.push("--resume".into());
    let published = resume_rollover_candidate(context, &arguments, endpoints, &offline, &out, &snapshot)?;
    assert_eq!(fs::read(out.join("vault.json"))?, candidate_bytes);
    let checkpoint: serde_json::Value = serde_json::from_slice(&fs::read(out.join("witness.checkpoint.json"))?)?;
    assert_eq!(checkpoint, snapshot["registration_checkpoint"]);
    assert_rollover_staging_removed(&out, &offline)?;
    exercise_rollover_cleanup_retry(context, &arguments, endpoints, &out, &offline, &snapshot_bytes)?;
    assert_eq!(published["published"], true);
    assert_eq!(published["suite"], suite);
    assert_eq!(published["operation"], operation);
    assert_eq!(published["witness_registration_complete"], true);
    assert_eq!(published["global_freshness_claimed"], false);
    assert_eq!(fs::read(&source_path)?, source_bytes);
    let destination = VaultFileV1::parse(&fs::read(out.join("vault.json"))?)?;
    assert_eq!(destination.header.suite, suite);
    assert_eq!(destination.suite_migration.is_some(), migration);
    assert_ne!(destination.header.vault_id, source.header.vault_id);
    assert_ne!(destination.items[0].item_id, item_id);
    let exported = jury_core::transfer::ValidatedTransfer::parse(&fs::read(&transfer)?)?;
    let destination_policy = jury_core::policy::replay_policy_with_witness_policies(&destination.policy, &exported.catalog().witness_policies)?;
    assert_eq!(destination_policy.item(&destination.items[0].item_id).ok_or("missing destination item")?.access_mode(), Some(jury_protocol::vault_v1::ItemAccessMode::WitnessedOnly));
    assert!(destination_policy.item(&destination.items[0].item_id).ok_or("missing destination item")?.direct_slots.is_empty());
    read_rollover_value(workflow, &out, &destination_policy)?;
    verify_rollover_backup(&backup, &destination, exported.catalog())?;
    assert_rollover_witness_outputs(&out, endpoints);
    verify_receipts(context.repository, context.data, context.state, &approval_paths.iter().map(|(_,_,receipt)| receipt.as_path()).collect::<Vec<_>>())?;
    assert_protected_value_not_persisted([context.repository, context.data, context.state, workflow.artifacts])?;
    Ok(())
}

fn wait_for_rollover_journal(path: &Path) -> TestResult<jury_protocol::vault_v1::PolicyJournalV1> {
    for _ in 0..600 {
        if let Ok(bytes) = fs::read(path) && let Ok(journal) = serde_json::from_slice(&bytes) { return Ok(journal); }
        thread::sleep(Duration::from_millis(50));
    }
    Err("rollover journal did not appear".into())
}


fn prove_rollover_roles(context: &ApprovalRunContext<'_>, actors: &super::native_cli_additional::PolicyActors, registration: &Path) -> TestResult {
    let journal_path = registration.join("journal.json");
    let journal = wait_for_rollover_journal(&journal_path)?;
    let fingerprint = encode_hex(journal.genesis.recomputed_fingerprint()?.as_bytes());
    for id in [&actors.approver_id, &actors.witness_one_id, &actors.witness_two_id] {
        let challenge = jury_core::registration::RegistrationChallengeV1::parse(&fs::read(registration.join(format!("{id}.challenge.json")))?)?;
        assert_eq!(encode_hex(challenge.candidate_descriptor.principal_id.as_bytes()), *id);
        assert_eq!(challenge.genesis_fingerprint, journal.genesis.recomputed_fingerprint()?);
    }
    for (id, name, passphrase) in [(&actors.approver_id,"approver",APPROVER_PASSPHRASE), (&actors.witness_one_id,"witness-one",WITNESS_ONE_PASSPHRASE), (&actors.witness_two_id,"witness-two",WITNESS_TWO_PASSPHRASE)] {
        let challenge = registration.join(format!("{id}.challenge.json"));
        let proof = registration.join(format!("{id}.proof.json"));
        success_json(run(context.repository, context.data, context.state, &["--json","--passphrase-stdin","--allow-degraded-protection","--identity",name,"identity","prove","--challenge",challenge.to_str().ok_or("invalid challenge path")?,"--rollover-draft",journal_path.to_str().ok_or("invalid journal path")?,"--expected-rollover-genesis",&fingerprint,"--out",proof.to_str().ok_or("invalid proof path")?],format!("{passphrase}\n").as_bytes())?)?;
    }
    Ok(())
}

fn approve_rollover_source(context: &ApprovalRunContext<'_>, approvals: &[(PathBuf, PathBuf, PathBuf)], child: &mut RolloverChild) -> TestResult {
    for (request, approval, _) in approvals {
        let artifact = wait_for_rollover_request(request, child)?;
        assert_eq!(artifact.request.operation, jury_protocol::witness_v1::WitnessOperationV1::Recovery);
        assert_eq!(artifact.request.vault_policy_sequence, context.policy.sequence());
        assert!(artifact.action_manifest.approval_target.entries.iter().all(|entry| entry.field_id.is_none()));
        let review = publish_approval(approval, &artifact, context.policy, context.approver)?;
        assert!(review.contains("ExampleRollover"));
    }
    Ok(())
}

fn wait_for_rollover_request(path: &Path, child: &mut RolloverChild) -> TestResult<RequestArtifact> {
    for _ in 0..600 {
        if let Ok(bytes) = fs::read(path) && let Ok(request) = serde_json::from_slice(&bytes) { return Ok(request); }
        if child.0.as_mut().ok_or("missing rollover child")?.try_wait()?.is_some() {
            let output = child.0.take().ok_or("missing rollover child")?.wait_with_output()?;
            return Err(format!("rollover exited before source authorization: {}", String::from_utf8_lossy(&output.stderr)).into());
        }
        thread::sleep(Duration::from_millis(50));
    }
    Err("rollover source request did not appear".into())
}

fn assert_rollover_preview(context: &ApprovalRunContext<'_>, arguments: &[String], outputs: &[&Path], approvals: &[(PathBuf, PathBuf, PathBuf)]) -> TestResult {
    let mut preview = arguments.to_vec();
    preview.push("--dry-run".into());
    let mut incomplete = preview.clone();
    let index = incomplete.iter().rposition(|argument| argument == "--destination-witness").ok_or("missing endpoint option")?;
    incomplete.drain(index..index + 2);
    let incomplete_refs = incomplete.iter().map(String::as_str).collect::<Vec<_>>();
    let rejected = run(context.repository, context.data, context.state, &incomplete_refs, format!("{OWNER_PASSPHRASE}\n").as_bytes())?;
    assert_eq!(rejected.status.code(), Some(2));
    assert!(rejected.stdout.is_empty());
    let error: serde_json::Value = serde_json::from_slice(&rejected.stderr)?;
    assert_eq!(error["error"]["code"], "invalid-rollover-witness-registration");
    let preview_refs = preview.iter().map(String::as_str).collect::<Vec<_>>();
    let preview = success_json(run(context.repository, context.data, context.state, &preview_refs, format!("{OWNER_PASSPHRASE}\n").as_bytes())?)?;
    assert_eq!(preview["published"], false);
    assert_eq!(preview["source_access_validated"], false);
    for output in outputs { assert!(!output.exists()); }
    for (request, approval, receipt) in approvals { assert!(!request.exists() && !approval.exists() && !receipt.exists()); }
    Ok(())
}

fn read_rollover_value(workflow: &WorkflowContext<'_>, home: &Path, policy: &PolicyState) -> TestResult {
    let request = workflow.artifacts.join("ExampleNewRead.request.json");
    let approval = workflow.artifacts.join("ExampleNewRead.approval.json");
    let receipt = workflow.artifacts.join("ExampleNewRead.receipt.json");
    let output_root = workflow.private_output.join("ExampleRolloverValues");
    fs::create_dir(&output_root)?;
    fs::set_permissions(&output_root, fs::Permissions::from_mode(0o700))?;
    let output = output_root.join("ExampleField");
    let mut arguments = vec!["--json".into(), "--passphrase-stdin".into(), "--allow-degraded-protection".into(), "--home".into(), home.to_str().ok_or("invalid destination path")?.into(), "read".into(), "ExampleWitnessedItem".into(), "ExampleWitnessedField".into(), "--out".into(), output.to_str().ok_or("invalid output path")?.into()];
    append_witness_arguments(&mut arguments, &home.join("witness.checkpoint.json"), &request, &approval, &receipt, workflow.endpoints)?;
    let approval_context = ApprovalRunContext { repository: workflow.approval.repository, data: workflow.approval.data, state: workflow.approval.state, policy, approver: workflow.approval.approver };
    let (result, _) = run_with_async_approval(&approval_context, &arguments, &request, &approval)?;
    let result = success_json(result).map_err(|error| format!("destination witnessed read failed: {error}"))?;
    assert_eq!(result["authority"], "witnessed-approved");
    assert_eq!(fs::read(&output)?, b"ExampleFieldValue");
    fs::remove_file(&output)?;
    Ok(())
}

fn verify_rollover_backup(path: &Path, vault: &VaultFileV1, catalog: &jury_core::transfer::TransferPublicCatalogV1) -> TestResult {
    let envelope = jury_protocol::backup_v1::BackupEnvelopeV1::parse(&fs::read(path)?)?;
    let recovered = jury_core::backup::open(&envelope, &protected(b"ExampleBackupPassphrase")?)?;
    assert_eq!(recovered.vault(), vault);
    assert_eq!(recovered.catalog(), catalog);
    assert_eq!(recovered.header().genesis_fingerprint, vault.header.genesis_fingerprint);
    Ok(())
}

fn rollover_source_plan(workflow: &WorkflowContext<'_>, item_id: jury_protocol::vault_v1::ItemId, plan_path: &Path) -> TestResult<Vec<(PathBuf, PathBuf, PathBuf)>> {
    let mut entries = Vec::new();
    let mut approval_paths = Vec::new();
    for role in [jury_protocol::vault_v1::ContentRole::Descriptor, jury_protocol::vault_v1::ContentRole::Body] {
        let request = workflow.artifacts.join(format!("ExampleRecovery{}.request.json", role.tag()));
        let approval = workflow.artifacts.join(format!("ExampleRecovery{}.approval.json", role.tag()));
        let receipt = workflow.artifacts.join(format!("ExampleRecovery{}.receipt.json", role.tag()));
        entries.push(json!({"item_id":encode_hex(item_id.as_bytes()), "content_role":role,
            "checkpoint":workflow.checkpoint, "request_out":request, "receipt":receipt,
            "approvals":[approval], "witnesses":workflow.endpoints, "allow_insecure_loopback":true, "wait_seconds":30}));
        approval_paths.push((request, approval, receipt));
    }
    fs::write(plan_path, serde_json::to_vec(&json!({"version":1,"total_wait_seconds":120,"entries":entries}))?)?;
    fs::set_permissions(plan_path, fs::Permissions::from_mode(0o600))?;
    Ok(approval_paths)
}

fn rollover_arguments(paths: [&Path; 5], endpoints: [&EngineEndpoint; 2], operator: &Path) -> TestResult<Vec<String>> {
    let mut arguments = vec!["--json".into(), "--passphrase-stdin".into(), "--allow-degraded-protection".into(), "vault".into(), "rollover".into(), "--allow-insecure-loopback".into(), "--registration-wait-seconds".into(), "180".into()];
    for (flag, path) in ["--out", "--backup-out", "--transfer-out", "--registration-dir", "--administrative-access"].into_iter().zip(paths) {
        arguments.extend([flag.into(), path.to_str().ok_or("non-UTF-8 test path")?.into()]);
    }
    for endpoint in endpoints { arguments.extend(["--destination-witness".into(), endpoint.specification(operator)?]); }
    Ok(arguments)
}

fn assert_rollover_witness_outputs(out: &Path, endpoints: [&EngineEndpoint; 2]) {
    assert!(out.join("witness.checkpoint.json").exists());
    assert!(!out.join("rollover.pending.json").exists());
    assert!(!out.join("rollover.registration.pending.json").exists());
    for endpoint in endpoints { assert!(out.join(format!("witness-{}-registration.json", encode_hex(endpoint.witness_id.as_bytes()))).exists()); }
}

fn select_rollover_command(arguments: &mut Vec<String>, migration: bool) -> TestResult {
    if migration {
        let command = arguments.iter_mut().find(|arg| arg.as_str() == "rollover").ok_or("missing command")?;
        *command = "migrate-suite".into();
        arguments.extend(["--to".into(), "2".into()]);
    }
    Ok(())
}
