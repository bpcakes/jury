fn with_witnessed_workflow(
    exercise: impl FnOnce(
        &WorkflowContext<'_>,
        &super::native_cli_additional::PolicyActors,
        [&EngineEndpoint; 2],
    ) -> TestResult,
) -> TestResult {
    let temporary = tempfile::tempdir()?;
    let root = fs::canonicalize(temporary.path())?;
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
    let repository = root.join("repository");
    let data = root.join("data");
    let state = root.join("state");
    let artifacts = root.join("artifacts");
    let private_output = root.join("private-output");
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
            "--operation",
            "recovery",
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
    let result = exercise(&workflow, &actors, [&endpoint_one, &endpoint_two]);
    let first = endpoint_one.finish();
    let second = endpoint_two.finish();
    result.map_err(|error| format!(
        "{error}; endpoint completion: {first:?}, {second:?}"
    ))?;
    first?;
    second?;
    Ok(())
}
