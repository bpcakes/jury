fn register_candidate(temporary: &Path, paths: NativePaths<'_>) -> TestResult<CandidateFixture> {
    let NativePaths {
        repository,
        data,
        state,
    } = paths;
    let candidate = success_json(run(
        repository,
        data,
        state,
        &[
            "--json",
            "--passphrase-stdin",
            "--allow-degraded-protection",
            "identity",
            "init",
            "--name",
            "candidate",
            "--kind",
            "machine",
        ],
        b"CandidatePass1234\nCandidatePass1234\n",
    )?)?;
    assert_eq!(candidate["kind"], "machine");
    let registration = temporary.join("registration");
    fs::create_dir(&registration)?;
    fs::set_permissions(&registration, fs::Permissions::from_mode(0o700))?;
    let descriptor_path = registration.join("candidate.json");
    let challenge_path = registration.join("challenge.json");
    let proof_path = registration.join("proof.json");
    let public = success_json(run(
        repository,
        data,
        state,
        &[
            "--json",
            "--identity",
            "candidate",
            "--passphrase-stdin",
            "--allow-degraded-protection",
            "identity",
            "public",
            "--out",
            descriptor_path
                .to_str()
                .ok_or("non-UTF-8 descriptor path")?,
        ],
        b"CandidatePass1234\n",
    )?)?;
    assert_eq!(public["operation"], "identity-public");
    assert_eq!(public["principal_id"], candidate["principal_id"]);
    let challenge = success_json(run(
        repository,
        data,
        state,
        &[
            "--json",
            "--passphrase-stdin",
            "--allow-degraded-protection",
            "principal",
            "challenge",
            "--from",
            descriptor_path
                .to_str()
                .ok_or("non-UTF-8 descriptor path")?,
            "--out",
            challenge_path.to_str().ok_or("non-UTF-8 challenge path")?,
        ],
        b"ExamplePass1234\n",
    )?)?;
    assert_eq!(challenge["operation"], "principal-challenge");
    assert_eq!(
        challenge["candidate_principal_id"],
        candidate["principal_id"]
    );
    let proof = success_json(run(
        repository,
        data,
        state,
        &[
            "--json",
            "--identity",
            "candidate",
            "--passphrase-stdin",
            "--allow-degraded-protection",
            "identity",
            "prove",
            "--challenge",
            challenge_path.to_str().ok_or("non-UTF-8 challenge path")?,
            "--out",
            proof_path.to_str().ok_or("non-UTF-8 proof path")?,
        ],
        b"CandidatePass1234\n",
    )?)?;
    assert_eq!(proof["operation"], "identity-prove");
    assert_eq!(proof["principal_id"], candidate["principal_id"]);
    assert_eq!(proof["recovered_response_disclosed"], false);
    Ok(CandidateFixture {
        identity: candidate,
        descriptor_path,
        proof_path,
    })
}

fn grant_candidate_access(
    paths: NativePaths<'_>,
    vault: &serde_json::Value,
    candidate: &CandidateFixture,
) -> TestResult {
    let NativePaths {
        repository,
        data,
        state,
    } = paths;
    let before_unacknowledged_grant = fs::read(repository.join(".jury/vault.json"))?;
    let unacknowledged_grant = run(
        repository,
        data,
        state,
        &[
            "--json",
            "--passphrase-stdin",
            "--allow-degraded-protection",
            "principal",
            "add",
            "--from",
            candidate
                .descriptor_path
                .to_str()
                .ok_or("non-UTF-8 descriptor path")?,
            "--proof",
            candidate
                .proof_path
                .to_str()
                .ok_or("non-UTF-8 proof path")?,
            "--reader",
            "ExampleItem",
        ],
        b"",
    )?;
    assert_eq!(unacknowledged_grant.status.code(), Some(2));
    assert!(unacknowledged_grant.stdout.is_empty());
    let grant_error: serde_json::Value = serde_json::from_slice(&unacknowledged_grant.stderr)?;
    assert_eq!(
        grant_error["error"]["code"],
        "direct-access-acknowledgement-required"
    );
    assert_eq!(
        fs::read(repository.join(".jury/vault.json"))?,
        before_unacknowledged_grant
    );
    let added = success_json(run(
        repository,
        data,
        state,
        &[
            "--json",
            "--passphrase-stdin",
            "--allow-degraded-protection",
            "principal",
            "add",
            "--from",
            candidate
                .descriptor_path
                .to_str()
                .ok_or("non-UTF-8 descriptor path")?,
            "--proof",
            candidate
                .proof_path
                .to_str()
                .ok_or("non-UTF-8 proof path")?,
            "--reader",
            "ExampleItem",
            "--acknowledge-direct-access",
        ],
        b"ExamplePass1234\n",
    )?)?;
    assert_eq!(added["operation"], "principal-add");
    assert_eq!(added["vault_changed"], true);

    let candidate_access = success_json(run(
        repository,
        data,
        state,
        &[
            "--json",
            "--identity",
            "candidate",
            "--expected-genesis",
            vault["genesis_fingerprint"]
                .as_str()
                .ok_or("missing genesis fingerprint")?,
            "--passphrase-stdin",
            "--allow-degraded-protection",
            "access",
            "list",
            "--me",
        ],
        b"CandidatePass1234\n",
    )?)?;
    assert_eq!(candidate_access["count"], 1);
    assert_eq!(candidate_access["items"][0]["item"], "ExampleItem");
    assert_eq!(candidate_access["items"][0]["role"], "reader");
    assert_eq!(candidate_access["items"][0]["path"], "direct");
    Ok(())
}

fn assert_human_access_inspection(
    paths: NativePaths<'_>,
    owner: &serde_json::Value,
    candidate: &CandidateFixture,
) -> TestResult {
    let NativePaths {
        repository,
        data,
        state,
    } = paths;
    let owner_id = owner["principal_id"]
        .as_str()
        .ok_or("missing owner principal")?;
    let candidate_id = candidate.identity["principal_id"]
        .as_str()
        .ok_or("missing candidate principal")?;

    assert_human_principal_labels_are_escaped(repository, data, state, candidate_id)?;
    let owner_display = human_principal_display(repository, data, state, owner_id)?;
    let candidate_display = human_principal_display(repository, data, state, candidate_id)?;
    assert_human_principal_list(repository, data, state, owner_id, candidate_id)?;
    assert_human_my_access_list(repository, data, state)?;
    assert_human_item_access_list(repository, data, state, &owner_display, &candidate_display)?;
    assert_human_access_matrix(repository, data, state, &owner_display, &candidate_display)
}

fn assert_human_principal_labels_are_escaped(
    repository: &Path,
    data: &Path,
    state: &Path,
    candidate_id: &str,
) -> TestResult {
    const UNSAFE_LABEL: &str = "Zoë\n\u{202e}candidate\x1b[2K";
    let (prior_label, _) = principal_metadata(repository, data, state, candidate_id)?;
    relabel_principal(repository, data, state, candidate_id, UNSAFE_LABEL)?;

    let principals = run(repository, data, state, &["principal", "list"], b"")?;
    assert!(principals.status.success());
    let principals = String::from_utf8(principals.stdout)?;
    assert!(principals.contains(r"label: Zoë\n\u{202e}candidate\u{1b}[2K"));
    assert!(!principals.contains(UNSAFE_LABEL));

    relabel_principal(repository, data, state, candidate_id, &prior_label)
}

fn relabel_principal(
    repository: &Path,
    data: &Path,
    state: &Path,
    principal_id: &str,
    label: &str,
) -> TestResult {
    let relabeled = success_json(run(
        repository,
        data,
        state,
        &[
            "--json",
            "--passphrase-stdin",
            "--allow-degraded-protection",
            "principal",
            "label",
            principal_id,
            "--label",
            label,
        ],
        b"ExamplePass1234\n",
    )?)?;
    assert_eq!(relabeled["operation"], "principal-label");
    Ok(())
}

fn human_principal_display(
    repository: &Path,
    data: &Path,
    state: &Path,
    principal_id: &str,
) -> TestResult<String> {
    let (label, fingerprint) = principal_metadata(repository, data, state, principal_id)?;
    Ok(format!("{label} ({})", grouped(&fingerprint)))
}

fn principal_metadata(
    repository: &Path,
    data: &Path,
    state: &Path,
    principal_id: &str,
) -> TestResult<(String, String)> {
    let principals = success_json(run(
        repository,
        data,
        state,
        &["--json", "principal", "list"],
        b"",
    )?)?;
    let principal = principals["principals"]
        .as_array()
        .and_then(|principals| {
            principals.iter().find(|principal| {
                principal["principal_id"].as_str() == Some(principal_id)
            })
        })
        .ok_or("missing listed principal")?;
    Ok((
        principal["label"]
            .as_str()
            .ok_or("missing listed principal label")?
            .to_owned(),
        principal["fingerprint"]
            .as_str()
            .ok_or("missing listed principal fingerprint")?
            .to_owned(),
    ))
}

fn grouped(fingerprint: &str) -> String {
    fingerprint
        .chars()
        .enumerate()
        .fold(String::new(), |mut grouped, (index, character)| {
            if index != 0 && index % 8 == 0 {
                grouped.push('-');
            }
            grouped.push(character);
            grouped
        })
}

fn assert_human_principal_list(
    repository: &Path,
    data: &Path,
    state: &Path,
    owner_id: &str,
    candidate_id: &str,
) -> TestResult {
    let principals = run(repository, data, state, &["principal", "list"], b"")?;
    assert!(principals.status.success());
    let principals = String::from_utf8(principals.stdout)?;
    assert!(principals.contains(&format!("Principal: {owner_id}")));
    assert!(principals.contains(&format!("Principal: {candidate_id}")));
    assert!(principals.contains("Owner: yes"));
    assert!(principals.contains("Owner: no"));
    assert!(principals.contains("Effective readable items: 1"));
    assert!(!principals.contains("ExampleItem"));
    Ok(())
}

fn assert_human_my_access_list(repository: &Path, data: &Path, state: &Path) -> TestResult {
    let mine = run(
        repository,
        data,
        state,
        &[
            "--passphrase-stdin",
            "--allow-degraded-protection",
            "access",
            "list",
            "--me",
        ],
        b"ExamplePass1234\n",
    )?;
    assert!(mine.status.success());
    let mine = String::from_utf8(mine.stdout)?;
    assert!(mine.contains("Item: ExampleItem"));
    assert!(mine.contains("Role: owner; path: direct"));
    assert!(mine.contains("Permissions: read: yes; write: yes; administer: yes"));
    assert!(mine.contains("Carries item quorum claim: no"));

    let candidate = run(
        repository,
        data,
        state,
        &[
            "--identity",
            "candidate",
            "--passphrase-stdin",
            "--allow-degraded-protection",
            "access",
            "list",
            "--me",
        ],
        b"CandidatePass1234\n",
    )?;
    assert!(candidate.status.success());
    let candidate = String::from_utf8(candidate.stdout)?;
    assert!(candidate.contains("Item: ExampleItem"));
    assert!(candidate.contains("Role: reader; path: direct"));
    assert!(candidate.contains("Permissions: read: yes; write: no; administer: no"));
    Ok(())
}

fn assert_human_item_access_list(
    repository: &Path,
    data: &Path,
    state: &Path,
    owner_display: &str,
    candidate_display: &str,
) -> TestResult {
    let item = run(
        repository,
        data,
        state,
        &[
            "--passphrase-stdin",
            "--allow-degraded-protection",
            "access",
            "list",
            "ExampleItem",
        ],
        b"ExamplePass1234\n",
    )?;
    assert!(item.status.success());
    let item = String::from_utf8(item.stdout)?;
    assert!(item.contains(&format!("Owners: 1\n  {owner_display}")));
    assert!(item.contains("Access mode: direct-only"));
    assert!(item.contains(&format!(
        "Explicit grants: 1\n  {candidate_display}: reader"
    )));
    Ok(())
}

fn assert_human_access_matrix(
    repository: &Path,
    data: &Path,
    state: &Path,
    owner_display: &str,
    candidate_display: &str,
) -> TestResult {
    let matrix = run(
        repository,
        data,
        state,
        &[
            "--passphrase-stdin",
            "--allow-degraded-protection",
            "access",
            "matrix",
        ],
        b"ExamplePass1234\n",
    )?;
    assert!(matrix.status.success());
    let matrix = String::from_utf8(matrix.stdout)?;
    assert!(matrix.contains(&format!("Vault owners: 1\n  {owner_display}")));
    assert!(matrix.contains("Item: ExampleItem"));
    assert!(matrix.contains("Access mode: direct-only"));
    assert!(matrix.contains(&format!(
        "Explicit grants: 1\n    {candidate_display}: reader"
    )));
    Ok(())
}

fn change_and_revoke_candidate_access(
    paths: NativePaths<'_>,
    candidate: &CandidateFixture,
) -> TestResult {
    let NativePaths {
        repository,
        data,
        state,
    } = paths;
    let changed_access = success_json(run(
        repository,
        data,
        state,
        &[
            "--json",
            "--passphrase-stdin",
            "--allow-degraded-protection",
            "access",
            "change",
            "ExampleItem",
            "--principal",
            candidate.identity["principal_id"]
                .as_str()
                .ok_or("missing candidate principal")?,
            "--role",
            "writer",
        ],
        b"ExamplePass1234\n",
    )?)?;
    assert_eq!(changed_access["operation"], "access-change");
    assert_eq!(changed_access["vault_changed"], true);
    let candidate_writer = success_json(run(
        repository,
        data,
        state,
        &[
            "--json",
            "--identity",
            "candidate",
            "--passphrase-stdin",
            "--allow-degraded-protection",
            "access",
            "list",
            "--me",
        ],
        b"CandidatePass1234\n",
    )?)?;
    assert_eq!(candidate_writer["items"][0]["role"], "writer");

    let revoked_access = success_json(run(
        repository,
        data,
        state,
        &[
            "--json",
            "--passphrase-stdin",
            "--allow-degraded-protection",
            "access",
            "revoke",
            "ExampleItem",
            "--principal",
            candidate.identity["principal_id"]
                .as_str()
                .ok_or("missing candidate principal")?,
        ],
        b"ExamplePass1234\n",
    )?)?;
    assert_eq!(revoked_access["operation"], "access-revoke");
    assert_eq!(revoked_access["vault_changed"], true);
    let candidate_revoked = success_json(run(
        repository,
        data,
        state,
        &[
            "--json",
            "--identity",
            "candidate",
            "--passphrase-stdin",
            "--allow-degraded-protection",
            "access",
            "list",
            "--me",
        ],
        b"CandidatePass1234\n",
    )?)?;
    assert_eq!(candidate_revoked["count"], 0);
    Ok(())
}

fn set_example_field(paths: NativePaths<'_>) -> TestResult {
    let NativePaths {
        repository,
        data,
        state,
    } = paths;
    let field_set = success_json(run(
        repository,
        data,
        state,
        &[
            "--json",
            "--passphrase-stdin",
            "--allow-degraded-protection",
            "vault",
            "field",
            "set",
            "ExampleItem",
            "ExampleField",
            "--value-stdin",
        ],
        b"ExamplePass1234\nExampleValue",
    )?)?;
    assert_eq!(field_set["operation"], "field-set");
    assert_eq!(field_set["vault_changed"], true);
    assert!(!field_set.to_string().contains("ExampleValue"));
    Ok(())
}

fn cover_and_remove_fields(paths: NativePaths<'_>) -> TestResult {
    let NativePaths {
        repository,
        data,
        state,
    } = paths;
    let cover = success_json(run(
        repository,
        data,
        state,
        &[
            "--json",
            "--passphrase-stdin",
            "--allow-degraded-protection",
            "privacy",
            "cover",
            "--item",
            "ExampleItem",
        ],
        b"ExamplePass1234\n",
    )?)?;
    assert_eq!(cover["operation"], "privacy-cover");
    assert_eq!(cover["vault_changed"], true);

    let removed = success_json(run(
        repository,
        data,
        state,
        &[
            "--json",
            "--passphrase-stdin",
            "--allow-degraded-protection",
            "vault",
            "field",
            "remove",
            "ExampleItem",
            "ExampleField",
        ],
        b"ExamplePass1234\n",
    )?)?;
    assert_eq!(removed["operation"], "field-remove");
    assert_eq!(removed["vault_changed"], true);
    let removed_secret = success_json(run(
        repository,
        data,
        state,
        &[
            "--json",
            "--passphrase-stdin",
            "--allow-degraded-protection",
            "vault",
            "field",
            "remove",
            "ExampleItem",
            "ExampleSecret",
        ],
        b"ExamplePass1234\n",
    )?)?;
    assert_eq!(removed_secret["operation"], "field-remove");
    assert_eq!(removed_secret["vault_changed"], true);
    let removed_binary = success_json(run(
        repository,
        data,
        state,
        &[
            "--json",
            "--passphrase-stdin",
            "--allow-degraded-protection",
            "vault",
            "field",
            "remove",
            "ExampleItem",
            "ExampleBinary",
        ],
        b"ExamplePass1234\n",
    )?)?;
    assert_eq!(removed_binary["operation"], "field-remove");
    assert_eq!(removed_binary["vault_changed"], true);
    let no_fields = success_json(run(
        repository,
        data,
        state,
        &[
            "--json",
            "--passphrase-stdin",
            "--allow-degraded-protection",
            "vault",
            "field",
            "list",
            "ExampleItem",
        ],
        b"ExamplePass1234\n",
    )?)?;
    assert_eq!(no_fields["count"], 0);
    Ok(())
}
