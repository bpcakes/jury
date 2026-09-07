struct RegistrationPauseServer {
    entered: std::sync::mpsc::SyncSender<()>,
    release: std::sync::mpsc::Receiver<()>,
}

impl RegistrationPauseServer {
    fn wait(self) -> Result<(), String> {
        self.entered.send(()).map_err(|_| "registration observer lost")?;
        self.release.recv_timeout(Duration::from_secs(60)).map_err(|_| "registration release timed out".to_owned())
    }
}

struct RegistrationPause {
    entered: std::sync::mpsc::Receiver<()>,
    release: std::sync::mpsc::SyncSender<()>,
}

impl Drop for RegistrationPause {
    fn drop(&mut self) {
        let _ = self.release.try_send(());
    }
}

impl EngineEndpoint {
    fn pause_registration(&self) -> TestResult<RegistrationPause> {
        let (entered_tx, entered) = std::sync::mpsc::sync_channel(1);
        let (release, release_rx) = std::sync::mpsc::sync_channel(1);
        let mut slot = self.calls.registration_pause.lock().map_err(|_| "registration pause poisoned")?;
        assert!(slot.is_none());
        *slot = Some(RegistrationPauseServer { entered: entered_tx, release: release_rx });
        Ok(RegistrationPause { entered, release })
    }
}

fn resume_with_concurrent_source_mutation(
    context: &ApprovalRunContext<'_>,
    arguments: &[String],
    endpoint: &EngineEndpoint,
    out: &Path,
) -> TestResult<serde_json::Value> {
    let source_path = context.repository.join(".jury/vault.json");
    let source_bytes = fs::read(&source_path)?;
    let mut child = RolloverChild(Some(jury_command(context.repository, context.data, context.state)
        .args(arguments).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn()?));
    let pause = endpoint.pause_registration()?;
    child.0.as_mut().ok_or("missing resume child")?.stdin.take().ok_or("missing stdin")?
        .write_all(format!("{OWNER_PASSPHRASE}\nExampleBackupPassphrase\n").as_bytes())?;
    pause.entered.recv_timeout(Duration::from_secs(120))?;
    assert!(!out.join("vault.json").exists());
    let owner = encode_hex(context.policy.owner_ids().next().ok_or("missing owner")?.as_bytes());
    let changed = run(context.repository, context.data, context.state,
        &["--json", "--passphrase-stdin", "--allow-degraded-protection", "principal", "label", &owner, "--label", "ExampleConcurrentOwner"],
        format!("{OWNER_PASSPHRASE}\n").as_bytes())?;
    assert_eq!(changed.status.code(), Some(4));
    assert!(changed.stdout.is_empty());
    let error: serde_json::Value = serde_json::from_slice(&changed.stderr)?;
    assert_eq!(error["error"]["code"], "mutation-conflict");
    assert_eq!(fs::read(&source_path)?, source_bytes);
    drop(pause);
    let result = success_json(child.0.take().ok_or("missing resume child")?.wait_with_output()?)?;
    assert_eq!(fs::read(source_path)?, source_bytes);
    Ok(result)
}

fn refuse_checkpoint_advanced_during_preparation(
    workflow: &WorkflowContext<'_>,
    actors: &super::native_cli_additional::PolicyActors,
    endpoints: [&EngineEndpoint; 2],
    migration: bool,
) -> TestResult {
    let context = &workflow.approval;
    let artifacts = workflow.artifacts.join("ExampleFreshness");
    let outputs = workflow.private_output.join("ExampleFreshness");
    for path in [&artifacts, &outputs] {
        fs::create_dir(path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    let workflow = WorkflowContext {
        approval: ApprovalRunContext { repository: context.repository, data: context.data,
            state: context.state, policy: context.policy, approver: context.approver },
        artifacts: &artifacts, private_output: &outputs, checkpoint: workflow.checkpoint,
        endpoints: workflow.endpoints,
    };
    let source_path = context.repository.join(".jury/vault.json");
    let source_bytes = fs::read(&source_path)?;
    let source = VaultFileV1::parse(&source_bytes)?;
    let plan = artifacts.join("ExampleAccess.json");
    let approvals = rollover_source_plan(&workflow, source.items[0].item_id, &plan)?;
    let out = outputs.join("ExampleVault");
    let offline = outputs.join("ExampleOffline");
    fs::create_dir(&offline)?;
    fs::set_permissions(&offline, fs::Permissions::from_mode(0o700))?;
    let backup = offline.join("ExampleBackup");
    let transfer = artifacts.join("ExampleTransfer");
    let registration = outputs.join("ExampleRegistration");
    let operator = artifacts.join("ExampleOperator.token");
    fs::write(&operator, OPERATOR_TOKEN)?;
    fs::set_permissions(&operator, fs::Permissions::from_mode(0o600))?;
    let mut arguments = rollover_arguments([&out, &backup, &transfer, &registration, &plan], endpoints, &operator)?;
    select_rollover_command(&mut arguments, migration)?;
    arguments.push("--adopt-new-lineage".into());
    let mut child = RolloverChild(Some(jury_command(context.repository, context.data, context.state)
        .args(&arguments).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn()?));
    child.0.as_mut().ok_or("missing child")?.stdin.take().ok_or("missing stdin")?
        .write_all(format!("{OWNER_PASSPHRASE}\nExampleBackupPassphrase\nExampleBackupPassphrase\n").as_bytes())?;
    approve_rollover_source(context, &approvals, &mut child)?;
    wait_for_rollover_journal(&registration.join("journal.json"))?;
    // Candidate proofs have not been supplied: preparation is deterministically
    // paused before publication. Mutate a different copy with shared owner state.
    let clone = outputs.join("ExampleClone");
    fs::create_dir(&clone)?;
    fs::set_permissions(&clone, fs::Permissions::from_mode(0o700))?;
    fs::write(clone.join("vault.json"), &source_bytes)?;
    fs::set_permissions(clone.join("vault.json"), fs::Permissions::from_mode(0o600))?;
    let owner = encode_hex(context.policy.owner_ids().next().ok_or("missing owner")?.as_bytes());
    success_json(run(context.repository, context.data, context.state,
        &["--json", "--home", clone.to_str().ok_or("invalid home")?, "--passphrase-stdin",
          "--allow-degraded-protection", "principal", "label", &owner, "--label", "ExampleConcurrentOwner"],
        format!("{OWNER_PASSPHRASE}\n").as_bytes())?)?;
    assert_ne!(fs::read(clone.join("vault.json"))?, source_bytes);
    assert_eq!(fs::read(&source_path)?, source_bytes);
    let counts = endpoints.map(EngineEndpoint::request_counts);
    prove_rollover_roles(context, actors, &registration)?;
    let refused = child.0.take().ok_or("missing child")?.wait_with_output()?;
    assert_eq!(refused.status.code(), Some(4));
    assert!(refused.stdout.is_empty());
    // stderr also includes the public draft-genesis progress line.
    let error = String::from_utf8(refused.stderr)?;
    assert!(error.contains("checkpoint-conflict"), "{error}");
    assert!(!out.exists() && !backup.exists() && !transfer.exists());
    assert_eq!(endpoints.map(EngineEndpoint::request_counts), counts);
    assert_eq!(fs::read(source_path)?, source_bytes);
    Ok(())
}
