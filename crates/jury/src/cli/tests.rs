use super::*;

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
