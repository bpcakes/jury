#[derive(Clone, Copy)]
struct NativePaths<'a> {
    repository: &'a Path,
    data: &'a Path,
    state: &'a Path,
}

struct CandidateFixture {
    identity: serde_json::Value,
    descriptor_path: std::path::PathBuf,
    proof_path: std::path::PathBuf,
}

fn initialize_identity(paths: NativePaths<'_>) -> TestResult<serde_json::Value> {
    let NativePaths {
        repository,
        data,
        state,
    } = paths;
    let identity = success_json(run(
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
        b"ExamplePass1234\nExamplePass1234\n",
    )?)?;
    assert_eq!(identity["operation"], "identity-init");
    assert_eq!(identity["kind"], "human");
    assert_eq!(identity["kdf_profile"], "portable-v1");
    assert!(!repository.join(".jury").exists());
    assert!(data.join("jury/identities/default.identity.json").is_file());
    Ok(identity)
}

fn assert_identity_inventory(paths: NativePaths<'_>, identity: &serde_json::Value) -> TestResult {
    let NativePaths {
        repository,
        data,
        state,
    } = paths;
    let identity_status = success_json(run(
        repository,
        data,
        state,
        &["--json", "identity", "status"],
        b"",
    )?)?;
    assert_eq!(identity_status["operation"], "identity-status");
    assert_eq!(identity_status["public_fields_authenticated"], false);
    assert_eq!(identity_status["private_payload_verified"], false);
    let identities = success_json(run(
        repository,
        data,
        state,
        &["--json", "identity", "list"],
        b"",
    )?)?;
    assert_eq!(identities["operation"], "identity-list");
    assert_eq!(identities["count"], 1);
    assert_eq!(identities["identities"][0]["name"], "default");
    assert_eq!(
        identities["identities"][0]["principal_id"],
        identity["principal_id"]
    );
    Ok(())
}

fn initialize_vault(paths: NativePaths<'_>) -> TestResult<serde_json::Value> {
    let NativePaths {
        repository,
        data,
        state,
    } = paths;
    let vault = success_json(run(
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
        b"ExamplePass1234\n",
    )?)?;
    assert_eq!(vault["operation"], "vault-init");
    assert_eq!(vault["home_source"], "repository");
    assert_eq!(vault["local_state"], "initialized");

    let mut shared_entries = fs::read_dir(repository.join(".jury"))?
        .map(|entry| entry.map(|entry| entry.file_name()))
        .collect::<Result<Vec<_>, _>>()?;
    shared_entries.sort();
    assert_eq!(shared_entries, [".gitattributes", "vault.json"]);
    assert_eq!(
        fs::read(repository.join(".jury/.gitattributes"))?,
        b"vault.json -diff -merge\n"
    );
    let shared = fs::read(repository.join(".jury/vault.json"))?;
    assert!(
        !shared
            .windows("ExamplePass1234".len())
            .any(|window| window == b"ExamplePass1234")
    );

    // Git preserves only the executable bit. A fresh checkout ordinarily
    // recreates these public encrypted files and their directory as 0644/0755.
    fs::set_permissions(repository.join(".jury"), fs::Permissions::from_mode(0o755))?;
    fs::set_permissions(
        repository.join(".jury/.gitattributes"),
        fs::Permissions::from_mode(0o644),
    )?;
    fs::set_permissions(
        repository.join(".jury/vault.json"),
        fs::Permissions::from_mode(0o644),
    )?;
    Ok(vault)
}

fn assert_public_vault_status(paths: NativePaths<'_>, vault: &serde_json::Value) -> TestResult {
    let NativePaths {
        repository,
        data,
        state,
    } = paths;
    let status = success_json(run(
        repository,
        data,
        state,
        &["--json", "vault", "status"],
        b"",
    )?)?;
    assert_eq!(status["operation"], "vault-status");
    assert_eq!(status["public_validation"], "valid");
    assert_eq!(status["identity_unlocked"], false);
    assert_eq!(status["principal_count"], 1);
    assert_eq!(status["owner_count"], 1);
    assert_eq!(status["item_count"], 0);
    assert_eq!(status["tombstone_count"], 0);
    assert_eq!(status["format_version"], 1);
    assert_eq!(status["suite_id"], 1);
    assert_eq!(status["cryptographic_scopes"], true);
    assert_eq!(status["capacity"]["item_revision_proofs"]["used"], 0);
    assert_eq!(status["vault_id"], vault["vault_id"]);
    assert_eq!(status["genesis_fingerprint"], vault["genesis_fingerprint"]);

    let history = success_json(run(
        repository,
        data,
        state,
        &["--json", "history", "status"],
        b"",
    )?)?;
    assert_eq!(history["operation"], "history-status");
    assert_eq!(history["identity_unlocked"], false);
    assert_eq!(history["capacity"], status["capacity"]);
    Ok(())
}

fn assert_local_audit(paths: NativePaths<'_>) -> TestResult {
    let NativePaths {
        repository,
        data,
        state,
    } = paths;
    let audit = success_json(run(
        repository,
        data,
        state,
        &[
            "--json",
            "--passphrase-stdin",
            "--allow-degraded-protection",
            "vault",
            "audit",
            "verify",
        ],
        b"ExamplePass1234\n",
    )?)?;
    assert_eq!(audit["operation"], "vault-audit-verify");
    assert_eq!(audit["evidence"], "current-jury-v1-local");
    assert_eq!(audit["event_count"], 1);
    assert_eq!(audit["local_activity_only"], true);
    assert_eq!(audit["other_principals_verified"], false);
    assert_eq!(audit["remote_freshness_verified"], false);
    Ok(())
}

fn create_direct_item(paths: NativePaths<'_>) -> TestResult {
    let NativePaths {
        repository,
        data,
        state,
    } = paths;
    let preview = success_json(run(
        repository,
        data,
        state,
        &[
            "--json",
            "--passphrase-stdin",
            "--allow-degraded-protection",
            "item",
            "create",
            "ExampleItem",
            "--allow-direct",
            "--dry-run",
        ],
        b"ExamplePass1234\n",
    )?)?;
    assert_eq!(preview["operation"], "item-create");
    assert_eq!(preview["dry_run"], true);
    assert_eq!(preview["vault_changed"], false);
    assert_eq!(preview["delivery_claimed"], false);
    let unchanged = success_json(run(
        repository,
        data,
        state,
        &["--json", "vault", "status"],
        b"",
    )?)?;
    assert_eq!(unchanged["item_count"], 0);

    let created_item = success_json(run(
        repository,
        data,
        state,
        &[
            "--json",
            "--passphrase-stdin",
            "--allow-degraded-protection",
            "item",
            "create",
            "ExampleItem",
            "--allow-direct",
        ],
        b"ExamplePass1234\n",
    )?)?;
    assert_eq!(created_item["operation"], "item-create");
    assert_eq!(created_item["item"], "ExampleItem");
    assert_eq!(created_item["dry_run"], false);
    assert_eq!(created_item["vault_changed"], true);
    assert_eq!(created_item["redistribution_recommended"], true);
    assert_eq!(created_item["delivery_claimed"], false);
    let with_item = success_json(run(
        repository,
        data,
        state,
        &["--json", "vault", "status"],
        b"",
    )?)?;
    assert_eq!(with_item["item_count"], 1);
    assert_eq!(with_item["capacity"]["item_revision_proofs"]["used"], 1);

    let before_duplicate = fs::read(repository.join(".jury/vault.json"))?;
    let duplicate = run(
        repository,
        data,
        state,
        &[
            "--json",
            "--passphrase-stdin",
            "--allow-degraded-protection",
            "item",
            "create",
            "ExampleItem",
            "--allow-direct",
        ],
        b"ExamplePass1234\n",
    )?;
    assert_eq!(duplicate.status.code(), Some(4));
    assert!(duplicate.stdout.is_empty());
    let duplicate_error: serde_json::Value = serde_json::from_slice(&duplicate.stderr)?;
    assert_eq!(duplicate_error["error"]["code"], "duplicate-item-name");
    assert_eq!(
        fs::read(repository.join(".jury/vault.json"))?,
        before_duplicate
    );
    Ok(())
}

fn assert_owner_access(paths: NativePaths<'_>) -> TestResult {
    let NativePaths {
        repository,
        data,
        state,
    } = paths;
    let principals = success_json(run(
        repository,
        data,
        state,
        &["--json", "principal", "list"],
        b"",
    )?)?;
    assert_eq!(principals["operation"], "principal-list");
    assert_eq!(principals["count"], 1);
    assert_eq!(principals["item_names_disclosed"], false);
    assert!(!principals.to_string().contains("ExampleItem"));

    let my_access = success_json(run(
        repository,
        data,
        state,
        &[
            "--json",
            "--passphrase-stdin",
            "--allow-degraded-protection",
            "access",
            "list",
            "--me",
        ],
        b"ExamplePass1234\n",
    )?)?;
    assert_eq!(my_access["operation"], "access-list-me");
    assert_eq!(my_access["count"], 1);
    assert_eq!(my_access["items"][0]["item"], "ExampleItem");
    assert_eq!(my_access["items"][0]["role"], "owner");
    assert_eq!(my_access["items"][0]["path"], "direct");
    assert_eq!(my_access["items"][0]["carries_item_quorum_claim"], false);

    let policy = success_json(run(
        repository,
        data,
        state,
        &[
            "--json",
            "--passphrase-stdin",
            "--allow-degraded-protection",
            "policy",
            "status",
            "--item",
            "ExampleItem",
        ],
        b"ExamplePass1234\n",
    )?)?;
    assert_eq!(policy["operation"], "policy-status");
    assert_eq!(policy["mode"], "direct-only");
    assert_eq!(policy["carries_item_quorum_claim"], false);
    assert_eq!(policy["item_quorum_claim_suppressed"], true);
    Ok(())
}
