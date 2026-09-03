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
