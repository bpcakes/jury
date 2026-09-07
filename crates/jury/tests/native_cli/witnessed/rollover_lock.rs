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
