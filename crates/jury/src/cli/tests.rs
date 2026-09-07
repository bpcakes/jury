use super::*;

#[test]
fn field_redaction_options_are_explicit_and_mutually_exclusive()
-> Result<(), Box<dyn std::error::Error>> {
    let field_help = help(&["jury", "vault", "field", "set", "--help"])?;
    assert!(field_help.contains("default for new fields"));
    assert!(field_help.contains("updates preserve the kind"));
    assert!(field_help.contains("stored field remains encrypted"));
    assert!(
        Cli::try_parse_from([
            "jury",
            "vault",
            "field",
            "set",
            "ExampleItem",
            "ExampleField",
            "--concealed",
            "--unconcealed",
            "--value-stdin"
        ])
        .is_err()
    );
    Ok(())
}

#[test]
fn parser_rejects_ambiguous_home_and_identity_flags() {
    assert!(
        Cli::try_parse_from(["jury", "--home", "/tmp/v", "--global", "vault", "status"]).is_err()
    );
    assert!(
        Cli::try_parse_from([
            "jury",
            "--identity",
            "one",
            "--identity-file",
            "/tmp/identity.json",
            "identity",
            "status"
        ])
        .is_err()
    );
    assert!(
        Cli::try_parse_from([
            "jury",
            "identity",
            "passphrase",
            "change",
            "--allow-kdf-downgrade"
        ])
        .is_err()
    );
    assert!(
        Cli::try_parse_from([
            "jury",
            "identity",
            "passphrase",
            "change",
            "--kdf-profile",
            "portable",
            "--allow-kdf-downgrade"
        ])
        .is_ok()
    );
}

#[test]
fn help_preserves_active_scope_and_warning() -> Result<(), Box<dyn std::error::Error>> {
    let error = match Cli::try_parse_from(["jury", "--help"]) {
        Ok(_) => return Err("help unexpectedly parsed as a command".into()),
        Err(error) => error,
    };
    let help = error.to_string();
    assert!(help.contains("Native Linux support only"));
    assert!(help.contains("PRE-ALPHA"));
    assert!(!help.contains("managed service"));
    assert!(!help.contains("semantic merge"));
    assert!(!help.contains("rollover"));
    Ok(())
}

#[test]
fn execution_help_states_plaintext_and_platform_limits() -> Result<(), Box<dyn std::error::Error>> {
    for command in ["exec", "run"] {
        let error = match Cli::try_parse_from(["jury", command, "--help"]) {
            Ok(_) => return Err("execution help unexpectedly parsed as a command".into()),
            Err(error) => error,
        };
        let help = error.to_string();
        assert!(help.contains("PRE-ALPHA"));
        assert!(help.contains("Native Linux only"));
        assert!(help.contains("authorized child can copy or retain"));
    }
    Ok(())
}

#[test]
fn access_help_explains_inputs() -> Result<(), Box<dyn std::error::Error>> {
    let access_list_help = help(&["jury", "access", "list", "--help"])?;
    assert!(access_list_help.contains("Resolved item name to inspect"));
    assert!(access_list_help.contains("List directly accessible items"));
    assert!(access_list_help.contains("witnessed-only"));

    let access_help = help(&["jury", "access", "--help"])?;
    assert!(access_help.contains("Change one explicit grant's role"));
    assert!(access_help.contains("Revoke one principal's explicit grant"));

    let matrix_help = help(&["jury", "access", "matrix", "--help"])?;
    assert!(matrix_help.contains("direct access to every item"));

    let access_grant_help = help(&["jury", "access", "grant", "--help"])?;
    assert!(access_grant_help.contains("explicit grant"));
    assert!(access_grant_help.contains("Explicit role for ITEM"));
    assert!(access_grant_help.contains("Required acknowledgement"));
    assert!(access_grant_help.contains("Validate the access grant"));

    let access_explain_help = help(&["jury", "access", "explain", "--help"])?;
    assert!(access_explain_help.contains("defaults to read for access explain"));
    Ok(())
}

#[test]
fn witnessed_automatic_help_names_exact_authority() -> Result<(), Box<dyn std::error::Error>> {
    let witnessed_help = help(&["jury", "policy", "require", "witnessed", "--help"])?;
    assert!(witnessed_help.contains("--automatic-read <FIELD>"));
    assert!(witnessed_help.contains("exact field plus the item descriptor"));
    assert!(witnessed_help.contains("Other body fields remain unauthorized"));
    assert!(witnessed_help.contains("--automatic-descriptor"));
    assert!(witnessed_help.contains("without body contents"));
    assert!(!witnessed_help.contains("--automatic-read-item"));
    Ok(())
}

#[test]
fn witnessed_policy_help_explains_inputs() -> Result<(), Box<dyn std::error::Error>> {
    let witnessed_help = help(&["jury", "policy", "require", "witnessed", "--help"])?;
    assert!(witnessed_help.contains("Resolved item name that will require witnessed authority"));
    assert!(witnessed_help.contains("at least two unique values"));
    assert!(witnessed_help.contains("descriptor permits every declared operation"));
    assert!(witnessed_help.contains("--review-label"));
    assert!(witnessed_help.contains("field-touching operations"));
    assert!(witnessed_help.contains("2..=the number of --witness values"));
    assert!(witnessed_help.contains("administrative-rekey"));
    assert!(witnessed_help.contains("1..=900"));
    assert!(witnessed_help.contains("never exceeds 30 seconds"));
    for operation in [
        "read-stdout",
        "write-private-file",
        "template-injection",
        "child-environment",
        "child-stdin",
        "item-mutation",
        "backup",
        "recovery",
        "administrative-rekey",
    ] {
        assert!(witnessed_help.contains(operation));
    }

    let status_help = help(&["jury", "policy", "status", "--help"])?;
    assert!(status_help.contains("Resolved item name whose authority policy to show or explain"));

    let allow_direct_help = help(&["jury", "policy", "allow", "direct", "--help"])?;
    assert!(allow_direct_help.contains("Resolved item name that will allow direct access"));
    assert!(allow_direct_help.contains("human or machine principal that already has read access"));

    let witness_status_help = help(&["jury", "witness", "policy-status", "--help"])?;
    assert!(witness_status_help.contains("Exact public checkpoint to classify"));
    Ok(())
}

fn help(arguments: &[&str]) -> Result<String, Box<dyn std::error::Error>> {
    let error = Cli::try_parse_from(arguments.iter().copied())
        .err()
        .ok_or("help unexpectedly parsed")?;
    Ok(error
        .to_string()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" "))
}

#[test]
fn governed_read_accepts_opaque_target_ids() {
    let id = "11".repeat(32);
    assert!(matches!(
        Cli::try_parse_from([
            "jury",
            "read",
            "--item-id",
            &id,
            "--field-id",
            &id,
            "--checkpoint",
            "/tmp/ExampleCheckpoint.json",
            "--request-out",
            "/tmp/ExampleRequest.json",
            "--receipt",
            "/tmp/ExampleReceipt.json",
            "--witness",
            "ExampleWitness,https://127.0.0.1:7443,/tmp/ExampleToken",
        ]),
        Ok(Cli {
            command: Command::Read(ReadArgs {
                item: None,
                field: None,
                item_id: Some(_),
                field_id: Some(_),
                direct: false,
                ..
            }),
            ..
        })
    ));
}

#[test]
fn transfer_commands_require_artifact_path_options() {
    let parsed = Cli::try_parse_from([
        "jury",
        "transfer",
        "import",
        "--in",
        "/tmp/ExampleTransfer.json",
        "--dry-run",
        "--allow-no-access",
    ]);
    assert!(matches!(
        parsed,
        Ok(Cli {
            command: Command::Transfer {
                command: TransferCommand::Import(TransferImportArgs {
                    dry_run: true,
                    allow_no_access: true,
                    ..
                })
            },
            ..
        })
    ));
    assert!(Cli::try_parse_from(["jury", "transfer", "inspect", "--against-current"]).is_err());
    assert!(Cli::try_parse_from(["jury", "transfer", "export"]).is_err());
}

#[test]
fn backup_surface_requires_explicit_sensitive_artifacts_and_drill_state() {
    assert!(matches!(
        Cli::try_parse_from([
            "jury",
            "backup",
            "create",
            "--out",
            "/tmp/ExampleRecovery.jury",
            "--kdf-profile",
            "hardened",
        ]),
        Ok(Cli {
            command: Command::Backup {
                command: BackupCommand::Create(BackupCreateArgs {
                    kdf_profile: KdfProfileArg::Hardened,
                    ..
                })
            },
            ..
        })
    ));
    assert!(Cli::try_parse_from(["jury", "backup", "verify"]).is_err());
    assert!(
        Cli::try_parse_from([
            "jury",
            "backup",
            "restore",
            "--in",
            "/tmp/ExampleRecovery.jury"
        ])
        .is_err()
    );
    assert!(
        Cli::try_parse_from([
            "jury",
            "backup",
            "drill",
            "--in",
            "/tmp/ExampleRecovery.jury",
            "--vault-out",
            "/tmp/ExampleVaultCopy",
            "--identity-out",
            "/tmp/ExampleIdentityCopy.json",
        ])
        .is_err()
    );
}

#[test]
fn backup_help_states_the_private_recovery_power() -> Result<(), Box<dyn std::error::Error>> {
    let error = Cli::try_parse_from(["jury", "backup", "create", "--help"])
        .err()
        .ok_or("backup help unexpectedly parsed")?;
    let help = error.to_string();
    assert!(help.contains("more sensitive than a transfer"));
    assert!(help.contains("recover the included owner identity"));
    assert!(help.contains("current direct-access item"));
    Ok(())
}

#[test]
fn receipt_and_witness_operations_require_explicit_public_artifacts() {
    assert!(matches!(
        Cli::try_parse_from([
            "jury",
            "receipt",
            "verify",
            "/tmp/ExampleReceipt.json",
            "--checkpoint",
            "/tmp/ExampleCheckpoint.json",
        ]),
        Ok(Cli {
            command: Command::Receipt {
                command: ReceiptCommand::Verify(ReceiptVerifyArgs {
                    checkpoint: Some(_),
                    ..
                })
            },
            ..
        })
    ));
    assert!(matches!(
        Cli::try_parse_from([
            "jury",
            "witness",
            "policy-material",
            "--output",
            "/tmp/ExamplePolicy.json",
        ]),
        Ok(Cli {
            command: Command::Witness {
                command: WitnessCommand::PolicyMaterial(_)
            },
            ..
        })
    ));
    assert!(matches!(
        Cli::try_parse_from([
            "jury",
            "witness",
            "policy-status",
            "--policy-material",
            "/tmp/ExamplePolicy.json",
            "--checkpoint",
            "/tmp/ExampleCheckpoint.json",
            "--acknowledgement",
            "/tmp/ExampleWitnessOneAck.json",
        ]),
        Ok(Cli {
            command: Command::Witness {
                command: WitnessCommand::PolicyStatus(WitnessPolicyStatusArgs {
                    acknowledgements,
                    ..
                })
            },
            ..
        }) if acknowledgements.len() == 1
    ));
    assert!(Cli::try_parse_from(["jury", "receipt", "inspect"]).is_err());
    assert!(Cli::try_parse_from(["jury", "witness", "policy-material"]).is_err());
}

#[test]
fn grouped_fingerprint_is_stable() {
    assert_eq!(grouped("0011223344556677"), "00112233-44556677");
}

#[test]
fn witnessed_wait_bounds_are_checked_before_execution() -> Result<(), Box<dyn std::error::Error>> {
    let commands: &[&[&str]] = &[
        &["read", "ExampleItem", "ExampleField", "--reveal"],
        &["inject", "--template", "/tmp/ExampleTemplate", "--reveal"],
        &["run"],
        &["exec"],
        &[
            "request",
            "execute",
            "--item",
            "ExampleItem",
            "--field",
            "ExampleField",
            "--checkpoint",
            "/tmp/ExampleCheckpoint",
            "--request-out",
            "/tmp/ExampleRequest",
            "--receipt",
            "/tmp/ExampleReceipt",
            "--witness",
            "ExampleEndpoint",
            "--reveal",
        ],
    ];
    for command in commands {
        for wait in ["0", "900", "901"] {
            let mut arguments = vec!["jury"];
            arguments.extend_from_slice(command);
            arguments.extend(["--wait-seconds", wait]);
            if matches!(command[0], "run" | "exec") {
                arguments.extend(["--", "/bin/true"]);
            }
            match Cli::try_parse_from(arguments) {
                Ok(_) => assert_ne!(wait, "901", "out-of-range wait parsed"),
                Err(error) => {
                    assert_eq!(wait, "901", "valid wait failed: {error}");
                    assert_eq!(error.kind(), clap::error::ErrorKind::ValueValidation);
                }
            }
        }
    }
    Ok(())
}
