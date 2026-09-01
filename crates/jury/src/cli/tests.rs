use clap::Parser as _;

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
fn grouped_fingerprint_is_stable() {
    assert_eq!(grouped("0011223344556677"), "00112233-44556677");
}
