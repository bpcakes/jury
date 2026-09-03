use super::*;

struct PolicyActors {
    approver_id: String,
    witness_one_id: String,
    witness_two_id: String,
}

fn initialize_policy_actors(
    repository: &Path,
    data: &Path,
    state: &Path,
    artifacts: &Path,
) -> TestResult<PolicyActors> {
    success_json(run(
        repository,
        data,
        state,
        &[
            "--json",
            "--passphrase-stdin",
            "--allow-degraded-protection",
            "identity",
            "init",
        ],
        b"OwnerPassphrase1234\nOwnerPassphrase1234\n",
    )?)?;
    success_json(run(
        repository,
        data,
        state,
        &[
            "--json",
            "--passphrase-stdin",
            "--allow-degraded-protection",
            "vault",
            "init",
        ],
        b"OwnerPassphrase1234\n",
    )?)?;
    success_json(run(
        repository,
        data,
        state,
        &[
            "--json",
            "--passphrase-stdin",
            "--allow-degraded-protection",
            "item",
            "create",
            "ExampleWitnessedItem",
            "--allow-direct",
        ],
        b"OwnerPassphrase1234\n",
    )?)?;

    let approver = register_role_principal(
        repository,
        data,
        state,
        artifacts,
        "approver",
        "approver",
        None,
        "ApproverPass1234",
        "OwnerPassphrase1234",
    )?;
    let witness_one = register_role_principal(
        repository,
        data,
        state,
        artifacts,
        "witness-one",
        "witness",
        Some(2),
        "WitnessOnePass1234",
        "OwnerPassphrase1234",
    )?;
    let witness_two = register_role_principal(
        repository,
        data,
        state,
        artifacts,
        "witness-two",
        "witness",
        Some(31),
        "WitnessTwoPass1234",
        "OwnerPassphrase1234",
    )?;
    Ok(PolicyActors {
        approver_id: approver["principal_id"]
            .as_str()
            .ok_or("missing approver principal ID")?
            .to_owned(),
        witness_one_id: witness_one["principal_id"]
            .as_str()
            .ok_or("missing first witness principal ID")?
            .to_owned(),
        witness_two_id: witness_two["principal_id"]
            .as_str()
            .ok_or("missing second witness principal ID")?
            .to_owned(),
    })
}

fn assert_unsafe_policy_preflight(
    repository: &Path,
    data: &Path,
    state: &Path,
    vault_path: &Path,
    actors: &PolicyActors,
) -> TestResult {
    let before_rejections = fs::read(vault_path)?;
    let impossible = run(
        repository,
        data,
        state,
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
            "2",
            "--witness-quorum",
            "2",
            "--operation",
            "read-stdout",
            "--request-lifetime",
            "300",
        ],
        b"",
    )?;
    assert_eq!(impossible.status.code(), Some(2));
    assert!(impossible.stdout.is_empty());
    let impossible_error: serde_json::Value = serde_json::from_slice(&impossible.stderr)?;
    assert_eq!(impossible_error["error"]["code"], "impossible-quorum");
    assert_eq!(fs::read(vault_path)?, before_rejections);

    let implicit_direct = run(
        repository,
        data,
        state,
        &[
            "--json",
            "--passphrase-stdin",
            "--allow-degraded-protection",
            "policy",
            "allow",
            "direct",
            "--item",
            "ExampleWitnessedItem",
            "--principal",
            &actors.approver_id,
        ],
        b"",
    )?;
    assert_eq!(implicit_direct.status.code(), Some(2));
    assert!(implicit_direct.stdout.is_empty());
    let direct_error: serde_json::Value = serde_json::from_slice(&implicit_direct.stderr)?;
    assert_eq!(
        direct_error["error"]["code"],
        "direct-access-acknowledgement-required"
    );
    assert_eq!(fs::read(vault_path)?, before_rejections);
    Ok(())
}

fn commit_witnessed_policy(
    repository: &Path,
    data: &Path,
    state: &Path,
    artifacts: &Path,
    vault_path: &Path,
    actors: &PolicyActors,
) -> TestResult {
    let before_preview = fs::read(vault_path)?;
    let preview = success_json(run(
        repository,
        data,
        state,
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
            "--request-lifetime",
            "300",
            "--dry-run",
        ],
        b"OwnerPassphrase1234\n",
    )?)?;
    assert_eq!(preview["operation"], "policy-require-witnessed");
    assert_eq!(preview["dry_run"], true);
    assert_eq!(preview["vault_changed"], false);
    assert_eq!(fs::read(vault_path)?, before_preview);

    let committed = success_json(run(
        repository,
        data,
        state,
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
            "--request-lifetime",
            "300",
        ],
        b"OwnerPassphrase1234\n",
    )?)?;
    assert_eq!(committed["operation"], "policy-require-witnessed");
    assert_eq!(committed["vault_changed"], true);
    assert_eq!(committed["pending_requests_invalidated"], true);
    assert_eq!(committed["item_quorum_claim_suppressed"], false);
    assert_eq!(committed["warnings"].as_array().map(Vec::len), Some(1));
    assert!(
        committed["warnings"][0]
            .as_str()
            .is_some_and(|warning| warning.contains("per verified witness acknowledgement"))
    );

    let material_path = artifacts.join("ExamplePolicyMaterial.json");
    let exported = success_json(run(
        repository,
        data,
        state,
        &[
            "--json",
            "witness",
            "policy-material",
            "--output",
            material_path.to_str().ok_or("invalid material path")?,
        ],
        b"",
    )?)?;
    assert_eq!(exported["operation"], "witness-policy-material");
    assert_eq!(exported["contains_private_material"], false);
    let material_bytes = fs::read(&material_path)?;
    let encoded_material = PolicyMaterialBytes::new(material_bytes.clone())?;
    let material = ReceiptPolicyMaterialV1::decode(&encoded_material)?;
    let replayed = material.replay()?;
    assert_eq!(
        Some(replayed.sequence()),
        exported["policy_sequence"].as_u64()
    );
    assert_eq!(material.witness_policies.len(), 1);
    let mut padded_material = vec![b'\n'];
    padded_material.extend_from_slice(&material_bytes);
    assert!(ReceiptPolicyMaterialV1::decode(&PolicyMaterialBytes::new(padded_material)?).is_err());

    let vault = VaultFileV1::parse(&fs::read(vault_path)?)?;
    let (direct_slots, witnessed_state) = vault
        .policy
        .revisions
        .iter()
        .rev()
        .flat_map(|revision| revision.operations.iter().rev())
        .find_map(|operation| match operation {
            PolicyOperationV1::ItemSlotsReplace {
                direct_slots,
                witnessed_state,
                ..
            } => Some((direct_slots, witnessed_state.as_ref())),
            _ => None,
        })
        .ok_or("witnessed item slot replacement was not committed")?;
    assert!(direct_slots.is_empty());
    let witnessed_state = witnessed_state.ok_or("witnessed state is absent")?;
    assert_eq!(witnessed_state.slots.len(), 2);
    assert!(
        witnessed_state
            .slots
            .iter()
            .all(|slot| slot.threshold == 2 && slot.member_count == 2)
    );
    Ok(())
}

fn assert_witness_removal_requires_rotation(
    repository: &Path,
    data: &Path,
    state: &Path,
    vault_path: &Path,
    witness_id: &str,
) -> TestResult {
    let before_role_removal = fs::read(vault_path)?;
    let removal = run(
        repository,
        data,
        state,
        &[
            "--json",
            "--passphrase-stdin",
            "--allow-degraded-protection",
            "principal",
            "remove",
            witness_id,
            "--revoke-all",
        ],
        b"OwnerPassphrase1234\n",
    )?;
    assert_eq!(removal.status.code(), Some(4));
    assert!(removal.stdout.is_empty());
    let removal_error: serde_json::Value = serde_json::from_slice(&removal.stderr)?;
    assert_eq!(
        removal_error["error"]["code"],
        "witnessed-role-rotation-required"
    );
    assert_eq!(fs::read(vault_path)?, before_role_removal);

    let public_status = success_json(run(
        repository,
        data,
        state,
        &["--json", "vault", "status"],
        b"",
    )?)?;
    assert_eq!(public_status["public_validation"], "valid");
    assert_eq!(public_status["item_count"], 1);
    Ok(())
}

#[test]
fn native_cli_configures_witnessed_only_policy_and_rejects_unsafe_preflight() -> TestResult {
    let temporary = tempfile::tempdir()?;
    let repository = temporary.path().join("repository");
    let data = temporary.path().join("data");
    let state = temporary.path().join("state");
    let artifacts = temporary.path().join("registration");
    fs::create_dir(&repository)?;
    fs::create_dir(repository.join(".git"))?;
    fs::write(
        repository.join(".git").join("HEAD"),
        [b"ref: refs".as_slice(), b"/heads/main\n"].concat(),
    )?;
    fs::create_dir(&artifacts)?;
    fs::set_permissions(&artifacts, fs::Permissions::from_mode(0o700))?;

    let actors = initialize_policy_actors(&repository, &data, &state, &artifacts)?;
    let vault_path = repository.join(".jury/vault.json");
    assert_unsafe_policy_preflight(&repository, &data, &state, &vault_path, &actors)?;
    commit_witnessed_policy(&repository, &data, &state, &artifacts, &vault_path, &actors)?;
    assert_witness_removal_requires_rotation(
        &repository,
        &data,
        &state,
        &vault_path,
        &actors.witness_one_id,
    )
}

#[test]
fn explicit_detached_home_supports_native_mutation_publication() -> TestResult {
    let temporary = tempfile::tempdir()?;
    let working = temporary.path().join("working");
    let data = temporary.path().join("data");
    let state = temporary.path().join("state");
    let home = temporary.path().join("detached-vault");
    fs::create_dir(&working)?;
    let home_value = home.to_str().ok_or("non-UTF-8 detached home")?;

    success_json(run(
        &working,
        &data,
        &state,
        &[
            "--json",
            "--home",
            home_value,
            "--passphrase-stdin",
            "--allow-degraded-protection",
            "identity",
            "init",
        ],
        b"DetachedPass1234\nDetachedPass1234\n",
    )?)?;
    let created = success_json(run(
        &working,
        &data,
        &state,
        &[
            "--json",
            "--home",
            home_value,
            "--passphrase-stdin",
            "--allow-degraded-protection",
            "vault",
            "init",
        ],
        b"DetachedPass1234\n",
    )?)?;
    assert_eq!(created["home_source"], "explicit");
    assert!(home.join("vault.json").is_file());
    assert!(!home.join(".gitattributes").exists());
    assert_eq!(fs::metadata(&home)?.permissions().mode() & 0o777, 0o700);
    assert_eq!(
        fs::metadata(home.join("vault.json"))?.permissions().mode() & 0o777,
        0o600
    );

    let item = success_json(run(
        &working,
        &data,
        &state,
        &[
            "--json",
            "--home",
            home_value,
            "--passphrase-stdin",
            "--allow-degraded-protection",
            "item",
            "create",
            "DetachedItem",
            "--allow-direct",
        ],
        b"DetachedPass1234\n",
    )?)?;
    assert_eq!(item["operation"], "item-create");
    assert_eq!(item["vault_changed"], true);
    let status = success_json(run(
        &working,
        &data,
        &state,
        &["--json", "--home", home_value, "vault", "status"],
        b"",
    )?)?;
    assert_eq!(status["home_source"], "explicit");
    assert_eq!(status["public_validation"], "valid");
    assert_eq!(status["item_count"], 1);
    Ok(())
}

#[test]
fn non_terminal_passphrase_requires_explicit_opt_in() -> TestResult {
    let temporary = tempfile::tempdir()?;
    let repository = temporary.path().join("repository");
    fs::create_dir(&repository)?;
    fs::create_dir(repository.join(".git"))?;
    fs::write(
        repository.join(".git").join("HEAD"),
        [b"ref: refs".as_slice(), b"/heads/main\n"].concat(),
    )?;
    let output = run(
        &repository,
        &temporary.path().join("data"),
        &temporary.path().join("state"),
        &["--json", "--allow-degraded-protection", "identity", "init"],
        b"ExamplePass1234\nExamplePass1234\n",
    )?;
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let error: serde_json::Value = serde_json::from_slice(&output.stderr)?;
    assert_eq!(error["error"]["code"], "passphrase-input-opt-in-required");
    Ok(())
}
