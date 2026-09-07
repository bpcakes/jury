//! Offline CLI regression using public artifacts produced by real Linux jury
//! and juryd processes with generated Example identities during the QA audit.
//! No private identity, credential, passphrase, or plaintext payload is present;
//! fixtures contain public protocol values and encrypted slot material.

#![cfg(target_os = "linux")]

use std::{fs, os::unix::fs::PermissionsExt as _, path::Path, process::Command};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn status(directory: &Path) -> std::io::Result<std::process::Output> {
    Command::new(env!("CARGO_BIN_EXE_jury"))
        .env_clear()
        .current_dir(directory)
        .args(["--json", "witness", "policy-status", "--policy-material"])
        .arg(directory.join("policy.json"))
        .arg("--checkpoint")
        .arg(directory.join("checkpoint.json"))
        .arg("--acknowledgement")
        .arg(directory.join("ExampleWitnessOne.ack.json"))
        .arg("--acknowledgement")
        .arg(directory.join("ExampleWitnessTwo.ack.json"))
        .output()
}

#[test]
fn real_signed_bare_and_wrapped_acknowledgements_verify_but_tampering_fails() -> TestResult {
    let temporary = tempfile::tempdir()?;
    let directory = temporary.path();
    let fixtures =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/witness-policy-status");
    for entry in fs::read_dir(fixtures)? {
        let entry = entry?;
        let destination = directory.join(entry.file_name());
        fs::copy(entry.path(), &destination)?;
        fs::set_permissions(destination, fs::Permissions::from_mode(0o600))?;
    }
    let one_path = directory.join("ExampleWitnessOne.ack.json");
    let two_path = directory.join("ExampleWitnessTwo.ack.json");
    let one: serde_json::Value = serde_json::from_slice(&fs::read(&one_path)?)?;
    let two: serde_json::Value = serde_json::from_slice(&fs::read(&two_path)?)?;
    for (wrap_one, wrap_two) in [(false, false), (true, false), (false, true), (true, true)] {
        for (path, acknowledgement, wrapped) in
            [(&one_path, &one, wrap_one), (&two_path, &two, wrap_two)]
        {
            let value = if wrapped {
                serde_json::json!({"acknowledgement": acknowledgement, "durability": "witness-database-and-external-anchor-readback"})
            } else {
                acknowledgement.clone()
            };
            fs::write(path, serde_json::to_vec(&value)?)?;
        }
        let output = status(directory)?;
        assert!(
            output.status.success(),
            "public status error: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.stderr.is_empty());
        let result: serde_json::Value = serde_json::from_slice(&output.stdout)?;
        assert_eq!(result["acknowledged_witness_count"], 2);
        assert_eq!(result["expected_witness_count"], 2);
        assert_eq!(result["global_freshness_claimed"], false);
        assert_eq!(result["offline"], true);
        assert_eq!(result["phase"], "durably-accepted");
        assert_eq!(
            result["checkpoint_digest"],
            "06ac6bf5a49076b2dc1bde63ab954ac3e6f40338ac92c5e155ec8dd1c2b228a2"
        );
    }
    let mut tampered = one.clone();
    // Change the signed anchor, then recompute its public digest so refusal
    // requires signature verification rather than only a digest mismatch.
    tampered["exact_anchor"]["signature"] =
        serde_json::to_value(jury_protocol::vault_v1::Signature64::new([0; 64]))?;
    let anchor: jury_protocol::witness_v1::WitnessStateAnchorV1 =
        serde_json::from_slice(&serde_json::to_vec(&tampered["exact_anchor"])?)?;
    tampered["anchor_digest"] = serde_json::to_value(anchor.digest()?)?;
    for value in [
        tampered.clone(),
        serde_json::json!({"acknowledgement": tampered}),
        serde_json::json!({"acknowledgement": null}),
        serde_json::json!({"acknowledgement": {}}),
    ] {
        fs::write(&one_path, serde_json::to_vec(&value)?)?;
        let output = status(directory)?;
        assert_eq!(output.status.code(), Some(5));
        assert!(output.stdout.is_empty());
        let error: serde_json::Value = serde_json::from_slice(&output.stderr)?;
        assert_eq!(error["error"]["code"], "invalid-witness-acknowledgement");
    }
    Ok(())
}
