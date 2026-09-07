use super::*;

#[test]
fn new_fields_redact_and_updates_preserve_explicit_classification() -> TestResult {
    let temporary = tempfile::tempdir()?;
    let repository = temporary.path().join("repository");
    let data = temporary.path().join("data");
    let state = temporary.path().join("state");
    fs::create_dir(&repository)?;
    assert!(
        Command::new("git")
            .args(["init", "--quiet"])
            .arg(&repository)
            .status()?
            .success()
    );
    let paths = NativePaths {
        repository: &repository,
        data: &data,
        state: &state,
    };
    initialize_identity(paths)?;
    initialize_vault(paths)?;
    create_direct_item(paths)?;

    // Cover creation, replacement without flags, and explicit transitions in
    // both directions. The exact child output is the oracle, not just metadata.
    for (field, flag, concealed) in [
        ("ExampleDefault", None, true),
        ("ExampleDefault", None, true),
        ("ExamplePublic", Some("--unconcealed"), false),
        ("ExamplePublic", None, false),
        ("ExamplePublic", Some("--concealed"), true),
        ("ExamplePublic", None, true),
        ("ExampleDefault", Some("--unconcealed"), false),
    ] {
        let mut arguments = vec![
            "--json",
            "--passphrase-stdin",
            "--allow-degraded-protection",
            "vault",
            "field",
            "set",
            "ExampleItem",
            field,
            "--value-stdin",
        ];
        arguments.extend(flag);
        let output = run(
            &repository,
            &data,
            &state,
            &arguments,
            b"ExamplePass1234\nExampleRedactionValue",
        )?;
        assert!(output.status.success(), "field mutation failed");
        assert!(
            !output
                .stdout
                .windows(b"ExampleRedactionValue".len())
                .any(|value| value == b"ExampleRedactionValue")
        );

        let listed = success_json(run(
            &repository,
            &data,
            &state,
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
        let fields = listed["fields"]
            .as_array()
            .ok_or("missing field inventory")?;
        let selected = fields
            .iter()
            .find(|entry| entry["field"] == field)
            .ok_or("field missing from inventory")?;
        assert_eq!(
            selected["kind"],
            if concealed { "concealed" } else { "text" }
        );

        let reference = format!("ExampleItem.{field}");
        let child = run(
            &repository,
            &data,
            &state,
            &[
                "--passphrase-stdin",
                "--allow-degraded-protection",
                "exec",
                "--direct",
                "--stdin",
                &reference,
                "--",
                "/bin/sh",
                "-c",
                "VALUE=$(cat); printf '%s' \"$VALUE\"; printf '%s' \"$VALUE\" >&2",
            ],
            b"ExamplePass1234\n",
        )?;
        assert!(child.status.success(), "child execution failed");
        let expected = if concealed {
            b"[REDACTED]".as_slice()
        } else {
            b"ExampleRedactionValue".as_slice()
        };
        assert!(
            child.stdout == expected,
            "child stdout violated field classification"
        );
        assert!(
            child.stderr == [b"PRE-ALPHA: externally unreviewed; do not use with real secrets\nAuthority: direct-unilateral\n".as_slice(), expected].concat(),
            "child stderr violated field classification"
        );
    }
    for (field, value) in [
        ("ExampleEmpty", b"".as_slice()),
        ("ExampleShort", b"abc".as_slice()),
    ] {
        let mut arguments = vec![
            "--json",
            "--passphrase-stdin",
            "--allow-degraded-protection",
            "vault",
            "field",
            "set",
            "ExampleItem",
            field,
            "--value-stdin",
        ];
        let input = [b"ExamplePass1234\n".as_slice(), value].concat();
        let refused = run(&repository, &data, &state, &arguments, &input)?;
        assert_eq!(refused.status.code(), Some(2));
        assert!(refused.stdout.is_empty());
        let error: serde_json::Value = serde_json::from_slice(&refused.stderr)?;
        assert_eq!(error["error"]["code"], "concealed-field-too-short");
        assert!(
            error["error"]["message"]
                .as_str()
                .ok_or("missing diagnostic")?
                .contains("--unconcealed")
        );
        arguments.push("--unconcealed");
        assert!(
            run(&repository, &data, &state, &arguments, &input)?
                .status
                .success(),
            "explicit short text creation failed"
        );
        arguments.pop();
        assert!(
            run(&repository, &data, &state, &arguments, &input)?
                .status
                .success(),
            "short text replacement did not preserve its kind"
        );
    }
    assert!(
        run(
            &repository,
            &data,
            &state,
            &[
                "--json",
                "--passphrase-stdin",
                "--allow-degraded-protection",
                "vault",
                "field",
                "set",
                "ExampleItem",
                "ExampleBoundary",
                "--value-stdin"
            ],
            b"ExamplePass1234\nabcd"
        )?
        .status
        .success(),
        "four-byte concealed boundary was refused"
    );
    Ok(())
}
