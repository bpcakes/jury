// A loader-only barrier stops the actual Jury binary before main. It requires
// the developer toolchain and an unhardened test binary; production has no hook.

#[test]
fn replaced_renderer_binds_the_original_running_image() -> TestResult {
    with_witnessed_workflow(|workflow, _, _| {
        let paths = RendererPaths::new(workflow)?;
        let arguments = paths.arguments(workflow, workflow.endpoints)?;
        let mut probe = RendererProbe::spawn(workflow, &arguments, "ExampleReplacement")?;
        probe.release(format!("x{OWNER_PASSPHRASE}\n").as_bytes())?;
        let artifact = wait_for_request(&paths.request)?;
        assert_renderer_identity(&paths.request, &probe.original)?;
        publish_approval(
            &paths.approval,
            &artifact,
            workflow.approval.policy,
            workflow.approval.approver,
        )?;
        assert_eq!(
            success_json(probe.finish()?)?["authority"],
            "witnessed-approved"
        );
        assert_eq!(fs::read(&paths.output)?, b"ExampleFieldValue");
        verify_receipts(
            workflow.approval.repository,
            workflow.approval.data,
            workflow.approval.state,
            &[&paths.receipt],
        )?;
        Ok(())
    })
}

#[test]
fn deleted_renderer_is_refused_before_private_input_or_request() -> TestResult {
    with_witnessed_workflow(|workflow, _, endpoints| {
        let paths = RendererPaths::new(workflow)?;
        let missing_credential = workflow.artifacts.join("ExampleAbsentCredential");
        let invalid_endpoints = endpoints
            .iter()
            .map(|endpoint| endpoint.specification(&missing_credential))
            .collect::<TestResult<Vec<_>>>()?;
        let counts = endpoints.map(EngineEndpoint::request_counts);
        for (index, specifications) in [workflow.endpoints, invalid_endpoints.as_slice()]
            .into_iter()
            .enumerate()
        {
            let arguments = paths.arguments(workflow, specifications)?;
            let mut probe =
                RendererProbe::spawn(workflow, &arguments, format!("ExampleDeletion{index}"))?;
            fs::remove_file(&probe.original)?;
            // Retain open, empty stdin after releasing the loader. Even a
            // missing credential must not be read before identity validation.
            probe.release(b"x")?;
            let result = probe.finish()?;
            assert!(!result.status.success());
            assert!(result.stdout.is_empty());
            let error: serde_json::Value = serde_json::from_slice(&result.stderr)?;
            assert_eq!(error["error"]["code"], "renderer-identity-unavailable");
            assert!(!paths.request.exists());
            assert!(!paths.receipt.exists());
            assert!(!paths.output.exists());
            assert_eq!(endpoints.map(EngineEndpoint::request_counts), counts);
        }
        Ok(())
    })
}

// APFS rejects non-UTF-8 names with EILSEQ; Linux can execute such paths.
#[cfg(target_os = "linux")]
#[test]
fn non_utf8_renderer_path_is_explained_before_private_input() -> TestResult {
    use std::os::unix::ffi::OsStringExt as _;
    with_witnessed_workflow(|workflow, _, endpoints| {
        let paths = RendererPaths::new(workflow)?;
        let arguments = paths.arguments(workflow, workflow.endpoints)?;
        let name = PathBuf::from(std::ffi::OsString::from_vec(b"ExampleRenderer-\xff".to_vec()));
        let counts = endpoints.map(EngineEndpoint::request_counts);
        let mut probe = RendererProbe::spawn(workflow, &arguments, &name)?;
        probe.release(b"x")?;
        let output = probe.finish()?;
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        let error: serde_json::Value = serde_json::from_slice(&output.stderr)?;
        assert_eq!(error["error"]["code"], "renderer-identity-unavailable");
        let message = error["error"]["message"].as_str().ok_or("missing renderer diagnostic")?;
        assert!(message.contains("UTF-8") && message.contains("move Jury"));
        assert!(!message.contains("ExampleRenderer"));
        assert!(!paths.request.exists() && !paths.receipt.exists() && !paths.output.exists());
        assert_eq!(endpoints.map(EngineEndpoint::request_counts), counts);
        Ok(())
    })
}

struct RendererPaths {
    template: PathBuf,
    request: PathBuf,
    approval: PathBuf,
    receipt: PathBuf,
    output: PathBuf,
}

impl RendererPaths {
    fn new(workflow: &WorkflowContext<'_>) -> TestResult<Self> {
        let template = workflow.artifacts.join("ExampleReplacementTemplate.txt");
        fs::write(&template, b"{{ExampleWitnessedItem.ExampleWitnessedField}}")?;
        fs::set_permissions(&template, fs::Permissions::from_mode(0o644))?;
        Ok(Self {
            template,
            request: workflow.artifacts.join("replacement.request.json"),
            approval: workflow.artifacts.join("replacement.approval.json"),
            receipt: workflow.artifacts.join("replacement.receipt.json"),
            output: workflow.private_output.join("replacement.output"),
        })
    }

    fn arguments(
        &self,
        workflow: &WorkflowContext<'_>,
        endpoints: &[String],
    ) -> TestResult<Vec<String>> {
        let mut arguments = vec![
            "--json".to_owned(),
            "--passphrase-stdin".to_owned(),
            "--allow-degraded-protection".to_owned(),
            "inject".to_owned(),
            "--template".to_owned(),
            self.template
                .to_str()
                .ok_or("non-UTF-8 template")?
                .to_owned(),
            "--out".to_owned(),
            self.output.to_str().ok_or("non-UTF-8 output")?.to_owned(),
        ];
        append_witness_arguments(
            &mut arguments,
            workflow.checkpoint,
            &self.request,
            &self.approval,
            &self.receipt,
            endpoints,
        )?;
        Ok(arguments)
    }
}

struct RendererProbe {
    child: Option<std::process::Child>,
    original: PathBuf,
}

impl RendererProbe {
    fn spawn(workflow: &WorkflowContext<'_>, arguments: &[String], name: impl AsRef<Path>) -> TestResult<Self> {
        let root = workflow.artifacts.join(name);
        fs::create_dir(&root)?;
        let executable = root.join("ExampleRenderer");
        let original = root.join("ExampleOriginalRenderer");
        let barrier = root.join("ExampleBarrier.library");
        let ready = root.join("ExampleRendererReady");
        compile_renderer_barrier(&barrier)?;
        let base = jury_command(
            workflow.approval.repository,
            workflow.approval.data,
            workflow.approval.state,
        );
        // Keep writable executable descriptors out of this multithreaded
        // runner. Unrelated test forks could otherwise retain one until exec
        // and make this launch fail with Linux ETXTBSY. A child copier owns
        // and closes every writable descriptor before we launch the image.
        let copied = Command::new("/bin/cp")
            .arg(base.get_program())
            .arg(&executable)
            .stdin(Stdio::null())
            .status()?;
        if !copied.success() {
            return Err("could not copy the renderer test executable; see cp diagnostics".into());
        }
        let child = Command::new(&executable)
            .current_dir(base.get_current_dir().ok_or("missing fixture directory")?)
            .env_clear()
            .envs(
                base.get_envs()
                    .filter_map(|(key, value)| value.map(|value| (key, value))),
            )
            .env(if cfg!(target_os = "macos") { "DYLD_INSERT_LIBRARIES" } else { "LD_PRELOAD" }, &barrier)
            .env("EXAMPLE_IMAGE_READY", &ready)
            .args(arguments)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let mut probe = Self {
            child: Some(child),
            original,
        };
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while !ready.exists() {
            if std::time::Instant::now() >= deadline || probe.child()?.try_wait()?.is_some() {
                return Err("renderer did not reach loader barrier: requires a dynamically linked, unhardened CLI test binary".into());
            }
            thread::sleep(Duration::from_millis(10));
        }
        fs::rename(&executable, &probe.original)?;
        fs::copy(&probe.original, &executable)?;
        Ok(probe)
    }

    fn child(&mut self) -> TestResult<&mut std::process::Child> {
        self.child
            .as_mut()
            .ok_or_else(|| "renderer was already reaped".into())
    }

    fn release(&mut self, input: &[u8]) -> TestResult {
        self.child()?
            .stdin
            .as_mut()
            .ok_or("renderer stdin unavailable")?
            .write_all(input)?;
        Ok(())
    }

    fn finish(mut self) -> TestResult<Output> {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while self.child()?.try_wait()?.is_none() {
            if std::time::Instant::now() >= deadline {
                return Err("renderer did not finish before its deadline".into());
            }
            thread::sleep(Duration::from_millis(10));
        }
        Ok(self
            .child
            .take()
            .ok_or("renderer was already reaped")?
            .wait_with_output()?)
    }
}

impl Drop for RendererProbe {
    fn drop(&mut self) {
        if let Some(child) = &mut self.child {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn compile_renderer_barrier(path: &Path) -> TestResult {
    let compiler_path = Path::new(if cfg!(target_os = "macos") { "/usr/bin/clang" } else { "/usr/bin/cc" });
    if !compiler_path.is_file() {
        return Err("test prerequisite missing: install the native C compiler (Xcode Command Line Tools on macOS)".into());
    }
    let mut compiler = Command::new(compiler_path)
        .args(if cfg!(target_os = "macos") { vec!["-dynamiclib"] } else { vec!["-shared", "-fPIC"] })
        .args(["-x", "c", "-", "-o"])
        .arg(path)
        .stdin(Stdio::piped())
        .spawn()?;
    let write = compiler
        .stdin
        .take()
        .ok_or("compiler stdin unavailable")?
        .write_all(include_bytes!("renderer_barrier.c"));
    let status = compiler.wait()?;
    write?;
    if !status.success() {
        return Err("test prerequisite failed: compiler could not build the loader barrier; see its diagnostics".into());
    }
    Ok(())
}
