use super::*;

fn exercise_execution_and_plaintext(temporary: &Path, paths: NativePaths<'_>) -> TestResult {
    let NativePaths {
        repository,
        data,
        state,
    } = paths;
    native_cli_execution::exercise_successful_execution(temporary, repository, data, state)?;
    native_cli_execution::exercise_adversarial_execution(temporary, repository, data, state)?;
    native_cli_plaintext::exercise_plaintext_sinks(temporary, repository, data, state)
}

fn change_identity_passphrase(paths: NativePaths<'_>, identity: &serde_json::Value) -> TestResult {
    let NativePaths {
        repository,
        data,
        state,
    } = paths;
    let changed = success_json(run(
        repository,
        data,
        state,
        &[
            "--json",
            "--passphrase-stdin",
            "--allow-degraded-protection",
            "identity",
            "passphrase",
            "change",
        ],
        b"ExamplePass1234\nExamplePass5678\nExamplePass5678\n",
    )?)?;
    assert_eq!(changed["operation"], "identity-passphrase-change");
    assert_eq!(changed["principal_keys_changed"], false);
    assert_eq!(changed["principal_id"], identity["principal_id"]);
    assert_eq!(changed["fingerprint"], identity["fingerprint"]);

    let after_change = success_json(run(
        repository,
        data,
        state,
        &["--json", "identity", "status"],
        b"",
    )?)?;
    assert_eq!(after_change["principal_id"], identity["principal_id"]);
    assert_eq!(after_change["fingerprint"], identity["fingerprint"]);
    assert_eq!(after_change["kdf_profile"], "portable-v1");
    Ok(())
}

#[test]
fn fresh_repository_identity_vault_and_public_status_flow() -> TestResult {
    let temporary = tempfile::tempdir()?;
    let repository = temporary.path().join("repository");
    let data = temporary.path().join("data");
    let state = temporary.path().join("state");
    fs::create_dir(&repository)?;
    fs::create_dir(repository.join(".git"))?;
    fs::write(
        repository.join(".git").join("HEAD"),
        [b"ref: refs".as_slice(), b"/heads/main\n"].concat(),
    )?;
    let paths = NativePaths {
        repository: &repository,
        data: &data,
        state: &state,
    };

    let identity = initialize_identity(paths)?;
    assert_identity_inventory(paths, &identity)?;
    let vault = initialize_vault(paths)?;
    assert_public_vault_status(paths, &vault)?;
    assert_local_audit(paths)?;
    create_direct_item(paths)?;
    assert_owner_access(paths)?;
    let candidate = register_candidate(temporary.path(), paths)?;
    grant_candidate_access(paths, &vault, &candidate)?;
    change_and_revoke_candidate_access(paths, &candidate)?;
    set_example_field(paths)?;
    exercise_execution_and_plaintext(temporary.path(), paths)?;
    cover_and_remove_fields(paths)?;
    change_identity_passphrase(paths, &identity)
}
