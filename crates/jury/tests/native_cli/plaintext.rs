use super::*;

pub(super) fn exercise_plaintext_sinks(
    temporary: &Path,
    repository: &Path,
    data: &Path,
    state: &Path,
) -> TestResult {
    let private = temporary.join("private-output");
    fs::create_dir(&private)?;
    fs::set_permissions(&private, fs::Permissions::from_mode(0o700))?;
    let output_path = private.join("value.txt");
    let read = success_json(run(
        repository,
        data,
        state,
        &[
            "--json",
            "--passphrase-stdin",
            "--allow-degraded-protection",
            "read",
            "ExampleItem",
            "ExampleField",
            "--out",
            output_path.to_str().ok_or("non-UTF-8 output path")?,
        ],
        b"ExamplePass1234\n",
    )?)?;
    assert_eq!(read["operation"], "field-read");
    assert_eq!(read["plaintext_in_structured_output"], false);
    assert!(!read.to_string().contains("ExampleValue"));
    assert_eq!(fs::read(&output_path)?, b"ExampleValue");
    assert_eq!(
        fs::metadata(&output_path)?.permissions().mode() & 0o777,
        0o600
    );

    let revealed = run(
        repository,
        data,
        state,
        &[
            "--passphrase-stdin",
            "--allow-degraded-protection",
            "read",
            "ExampleItem",
            "ExampleField",
            "--reveal",
        ],
        b"ExamplePass1234\n",
    )?;
    assert!(revealed.status.success());
    assert_eq!(revealed.stdout, b"ExampleValue");
    assert!(revealed.stderr.is_empty());

    let template_path = temporary.join("template.txt");
    fs::write(
        &template_path,
        b"prefix={{ExampleItem.ExampleField}};suffix",
    )?;
    fs::set_permissions(&template_path, fs::Permissions::from_mode(0o644))?;
    let injected_path = private.join("injected.txt");
    let injected = success_json(run(
        repository,
        data,
        state,
        &[
            "--json",
            "--passphrase-stdin",
            "--allow-degraded-protection",
            "inject",
            "--template",
            template_path.to_str().ok_or("non-UTF-8 template path")?,
            "--out",
            injected_path.to_str().ok_or("non-UTF-8 output path")?,
        ],
        b"ExamplePass1234\n",
    )?)?;
    assert_eq!(injected["operation"], "template-inject");
    assert_eq!(injected["plaintext_in_structured_output"], false);
    assert!(!injected.to_string().contains("ExampleValue"));
    assert_eq!(fs::read(&injected_path)?, b"prefix=ExampleValue;suffix");

    let revealed_injection = run(
        repository,
        data,
        state,
        &[
            "--passphrase-stdin",
            "--allow-degraded-protection",
            "inject",
            "--template",
            template_path.to_str().ok_or("non-UTF-8 template path")?,
            "--reveal",
        ],
        b"ExamplePass1234\n",
    )?;
    assert!(revealed_injection.status.success());
    assert_eq!(revealed_injection.stdout, b"prefix=ExampleValue;suffix");
    assert!(revealed_injection.stderr.is_empty());

    let denied_template = temporary.join("denied-template.txt");
    fs::write(
        &denied_template,
        b"{{ExampleItem.ExampleField}} {{MissingItem.ExampleField}}",
    )?;
    fs::set_permissions(&denied_template, fs::Permissions::from_mode(0o644))?;
    let denied_output = private.join("denied.txt");
    let denied = run(
        repository,
        data,
        state,
        &[
            "--json",
            "--passphrase-stdin",
            "--allow-degraded-protection",
            "inject",
            "--template",
            denied_template
                .to_str()
                .ok_or("non-UTF-8 denied template path")?,
            "--out",
            denied_output
                .to_str()
                .ok_or("non-UTF-8 denied output path")?,
        ],
        b"ExamplePass1234\n",
    )?;
    assert_eq!(denied.status.code(), Some(6));
    assert!(denied.stdout.is_empty());
    assert!(!denied_output.exists());
    let denied_error: serde_json::Value = serde_json::from_slice(&denied.stderr)?;
    assert_eq!(denied_error["error"]["code"], "item-unavailable");
    assert!(!denied_error.to_string().contains("ExampleValue"));
    Ok(())
}
