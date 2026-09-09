use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn raw_help(arguments: &[&str]) -> Result<String, Box<dyn std::error::Error>> {
    let error = Cli::try_parse_from(arguments)
        .err()
        .ok_or("help parsed as a command")?;
    assert_eq!(error.kind(), clap::error::ErrorKind::DisplayHelp);
    Ok(error.to_string())
}

#[test]
fn item_and_field_commands_are_discoverable_and_keep_legacy_routes() -> TestResult {
    assert!(matches!(
        Cli::try_parse_from(["jury", "item", "list"])?.command,
        Command::Item {
            command: ItemCommand::List
        }
    ));
    for prefix in [vec!["jury", "field"], vec!["jury", "vault", "field"]] {
        for operation in ["set", "remove"] {
            let cli = Cli::try_parse_from(prefix.iter().copied().chain([
                operation,
                "ExampleItem",
                "ExampleField",
            ]))?;
            let command = match cli.command {
                Command::Field { command }
                | Command::Vault {
                    command: VaultCommand::Field { command },
                } => command,
                _ => return Err("unexpected field command route".into()),
            };
            let (item, field) = match command {
                FieldCommand::Set(args) => (args.item, args.field),
                FieldCommand::Remove(args) => (args.item, args.field),
                FieldCommand::List(_) => return Err("mutation parsed as field list".into()),
            };
            assert_eq!(item, "ExampleItem");
            assert_eq!(field, "ExampleField");
        }
        let cli = Cli::try_parse_from(prefix.iter().copied().chain(["list"]))?;
        assert!(matches!(
            cli.command,
            Command::Field {
                command: FieldCommand::List(FieldListArgs { item: None })
            } | Command::Vault {
                command: VaultCommand::Field {
                    command: FieldCommand::List(FieldListArgs { item: None })
                }
            }
        ));
    }
    let item_help = help(&["jury", "item", "list", "--help"])?;
    assert!(item_help.contains("directly accessible"));
    assert!(item_help.contains("witnessed-only items are not disclosed"));
    let field_help = raw_help(&["jury", "field", "--help"])?;
    for command in ["list", "set", "remove"] {
        assert!(
            field_help
                .lines()
                .any(|line| line.trim_start().starts_with(command))
        );
    }
    Ok(())
}

#[test]
fn policy_and_privacy_require_exactly_one_item_spelling() -> TestResult {
    let commands = [
        vec!["jury", "policy", "status"],
        vec!["jury", "policy", "explain"],
        vec!["jury", "privacy", "cover"],
        vec![
            "jury",
            "policy",
            "allow",
            "direct",
            "--principal",
            "ExamplePrincipal",
        ],
        vec![
            "jury",
            "policy",
            "require",
            "witnessed",
            "--witness",
            "ExampleWitness",
            "--approvals",
            "0",
            "--witness-quorum",
            "2",
            "--operation",
            "read-stdout",
            "--request-lifetime",
            "300",
        ],
    ];
    for command in commands {
        for selector in [
            vec!["ExampleItem"],
            vec!["--item", "ExampleItem"],
            vec!["--item=ExampleItem"],
        ] {
            let cli = Cli::try_parse_from(command.iter().copied().chain(selector))?;
            let target = match cli.command {
                Command::Policy {
                    command: PolicyCommand::Status(target) | PolicyCommand::Explain(target),
                }
                | Command::Policy {
                    command:
                        PolicyCommand::Allow {
                            command:
                                PolicyAllowCommand::Direct(PolicyAllowDirectArgs { target, .. }),
                        },
                }
                | Command::Policy {
                    command:
                        PolicyCommand::Require {
                            command:
                                PolicyRequireCommand::Witnessed(PolicyRequireWitnessedArgs {
                                    target,
                                    ..
                                }),
                        },
                }
                | Command::Privacy {
                    command: PrivacyCommand::Cover(PrivacyCoverArgs { target, .. }),
                } => target,
                _ => return Err("unexpected item selector route".into()),
            };
            assert_eq!(target.item()?, "ExampleItem");
        }
        let absent = Cli::try_parse_from(&command)
            .err()
            .ok_or("missing item accepted")?;
        assert_eq!(
            absent.kind(),
            clap::error::ErrorKind::MissingRequiredArgument
        );
        for extra in [
            vec!["ExampleItem", "--item", "ExampleOtherItem"],
            vec!["--item", "ExampleItem", "ExampleItem"],
        ] {
            let ambiguous = Cli::try_parse_from(command.iter().copied().chain(extra))
                .err()
                .ok_or("ambiguous item accepted")?;
            assert_eq!(ambiguous.kind(), clap::error::ErrorKind::ArgumentConflict);
        }
        let usage = help(
            &command
                .iter()
                .copied()
                .chain(["--help"])
                .collect::<Vec<_>>(),
        )?;
        assert!(usage.contains("<ITEM>"));
        assert!(!usage.contains("[ITEM]"));
        assert!(!usage.contains("--item"));
    }
    Ok(())
}

#[test]
fn request_help_teaches_foreground_access_and_keeps_compatibility() -> TestResult {
    let request_help = raw_help(&["jury", "request", "--help"])?;
    assert!(request_help.contains("\n  preview "));
    assert!(!request_help.contains("\n  create "));
    assert!(!request_help.contains("\n  execute "));
    for command in [
        "jury read",
        "jury inject",
        "jury exec",
        "jury run",
        "jury approve",
    ] {
        assert!(request_help.contains(command));
    }
    assert!(request_help.contains("must keep running"));
    assert!(request_help.contains("cannot be executed later"));
    for command in ["preview", "create"] {
        let cli = Cli::try_parse_from([
            "jury",
            "request",
            command,
            "--item",
            "ExampleItem",
            "--field",
            "ExampleField",
            "--checkpoint",
            "/tmp/ExampleCheckpoint.json",
            "--out",
            "/tmp/ExampleRequest.json",
        ])?;
        assert!(matches!(
            cli.command,
            Command::Request {
                command: RequestCommand::Create(_)
            }
        ));
        let preview_help = help(&["jury", "request", command, "--help"])?;
        assert!(preview_help.contains("inspection only; it cannot execute"));
    }
    let cli = Cli::try_parse_from([
        "jury",
        "request",
        "execute",
        "--item",
        "ExampleItem",
        "--field",
        "ExampleField",
        "--checkpoint",
        "/tmp/ExampleCheckpoint.json",
        "--request-out",
        "/tmp/ExampleRequest.json",
        "--receipt",
        "/tmp/ExampleReceipt.json",
        "--witness",
        "ExampleWitness",
        "--out",
        "/tmp/ExampleValue",
    ])?;
    assert!(matches!(
        cli.command,
        Command::Request {
            command: RequestCommand::Execute(_)
        }
    ));
    Ok(())
}

#[test]
fn witness_output_uses_out_and_accepts_output_without_ambiguity() -> TestResult {
    for command in ["checkpoint", "policy-material"] {
        for flag in ["--out", "--output"] {
            let cli =
                Cli::try_parse_from(["jury", "witness", command, flag, "/tmp/ExamplePublic.json"])?;
            let output = match cli.command {
                Command::Witness {
                    command:
                        WitnessCommand::Checkpoint(WitnessCheckpointArgs { output, .. })
                        | WitnessCommand::PolicyMaterial(WitnessPolicyMaterialArgs { output }),
                } => output,
                _ => return Err("unexpected public output route".into()),
            };
            assert_eq!(output, PathBuf::from("/tmp/ExamplePublic.json"));
        }
        assert!(
            Cli::try_parse_from([
                "jury",
                "witness",
                command,
                "--out",
                "/tmp/ExampleOne",
                "--output",
                "/tmp/ExampleTwo"
            ])
            .is_err()
        );
        let output_help = help(&["jury", "witness", command, "--help"])?;
        assert!(output_help.contains("--out <FILE>"));
        assert!(!output_help.contains("--output"));
    }
    Ok(())
}

#[test]
fn both_initialization_help_paths_explain_the_identity_prerequisite() -> TestResult {
    for command in [
        vec!["jury", "init", "--help"],
        vec!["jury", "vault", "init", "--help"],
    ] {
        let init_help = help(&command)?;
        assert!(init_help.contains("jury identity init"));
        assert!(init_help.contains("same identity and home selection"));
        assert!(init_help.contains("shortcut `jury init`"));
    }
    Ok(())
}
