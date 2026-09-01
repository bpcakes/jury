use super::*;

pub fn execute(cli: Cli) -> Result<CommandOutput, CliError> {
    if !cfg!(target_os = "linux") {
        return Err(CliError::new(
            CliErrorKind::UnsupportedPlatform,
            "unsupported-platform",
            "native vault commands currently support Linux only",
        ));
    }
    let environment = Environment::capture();
    let current = env::current_dir().map_err(|_| filesystem_error())?;
    let protection = if cli.allow_degraded_protection {
        ProtectionPolicy::EmergencyAllowDegraded
    } else {
        ProtectionPolicy::Strict
    };
    match &cli.command {
        Command::Identity {
            command: IdentityCommand::Init(arguments),
        } => identity_init(&cli, arguments, &environment, &current, protection),
        Command::Identity {
            command: IdentityCommand::List,
        } => identity_list(&cli, &environment, &current),
        Command::Identity {
            command: IdentityCommand::Status(arguments),
        } => identity_status(&cli, arguments, &environment, &current),
        Command::Identity {
            command: IdentityCommand::Public(arguments),
        } => identity_public(&cli, arguments, &environment, &current, protection),
        Command::Identity {
            command: IdentityCommand::Prove(arguments),
        } => identity_prove(&cli, arguments, &environment, &current, protection),
        Command::Identity {
            command:
                IdentityCommand::Passphrase {
                    command: IdentityPassphraseCommand::Change(arguments),
                },
        } => identity_passphrase_change(&cli, arguments, &environment, &current, protection),
        Command::Init(arguments) => vault_init(&cli, arguments, &environment, &current, protection),
        Command::Vault {
            command: VaultCommand::Init(arguments),
        } => vault_init(&cli, arguments, &environment, &current, protection),
        Command::Vault {
            command: VaultCommand::Status,
        } => vault_status(&cli, &environment, &current, "vault-status"),
        Command::History {
            command: HistoryCommand::Status,
        } => vault_status(&cli, &environment, &current, "history-status"),
        Command::Item {
            command: ItemCommand::Create(arguments),
        } => item_create(&cli, arguments, &environment, &current, protection),
        Command::Vault {
            command:
                VaultCommand::Field {
                    command: FieldCommand::List(arguments),
                },
        } => field_list(&cli, arguments, &environment, &current, protection),
        Command::Vault {
            command:
                VaultCommand::Field {
                    command: FieldCommand::Set(arguments),
                },
        } => field_set(&cli, arguments, &environment, &current, protection),
        Command::Vault {
            command:
                VaultCommand::Field {
                    command: FieldCommand::Remove(arguments),
                },
        } => field_remove(&cli, arguments, &environment, &current, protection),
        Command::Read(arguments)
        | Command::Vault {
            command: VaultCommand::Read(arguments),
        } => field_read(&cli, arguments, &environment, &current, protection),
        Command::Privacy {
            command: PrivacyCommand::Cover(arguments),
        } => privacy_cover(&cli, arguments, &environment, &current, protection),
        Command::Principal {
            command: PrincipalCommand::List,
        } => principal_list(&cli, &environment, &current),
        Command::Principal {
            command: PrincipalCommand::Challenge(arguments),
        } => principal_challenge(&cli, arguments, &environment, &current, protection),
        Command::Principal {
            command: PrincipalCommand::Add(arguments),
        } => principal_add(&cli, arguments, &environment, &current, protection),
        Command::Principal {
            command: PrincipalCommand::Label(arguments),
        } => principal_label(&cli, arguments, &environment, &current, protection),
        Command::Principal {
            command: PrincipalCommand::Replace(arguments),
        } => principal_replace(&cli, arguments, &environment, &current, protection),
        Command::Principal {
            command: PrincipalCommand::Remove(arguments),
        } => principal_remove(&cli, arguments, &environment, &current, protection),
        Command::Principal {
            command: PrincipalCommand::GrantOwner(arguments),
        } => principal_owner_change(&cli, arguments, true, &environment, &current, protection),
        Command::Principal {
            command: PrincipalCommand::RevokeOwner(arguments),
        } => principal_owner_change(&cli, arguments, false, &environment, &current, protection),
        Command::Access {
            command: AccessCommand::List(arguments),
        } => access_list(&cli, arguments, &environment, &current, protection),
        Command::Access {
            command: AccessCommand::Explain(arguments),
        } => access_explain(&cli, arguments, false, &environment, &current, protection),
        Command::Access {
            command: AccessCommand::Check(arguments),
        } => access_explain(&cli, arguments, true, &environment, &current, protection),
        Command::Access {
            command: AccessCommand::Matrix,
        } => access_matrix(&cli, &environment, &current, protection),
        Command::Access {
            command: AccessCommand::Grant(arguments),
        } => access_grant(&cli, arguments, &environment, &current, protection),
        Command::Access {
            command: AccessCommand::Change(arguments),
        } => access_change(&cli, arguments, &environment, &current, protection),
        Command::Access {
            command: AccessCommand::Revoke(arguments),
        } => access_revoke(&cli, arguments, &environment, &current, protection),
        Command::Policy {
            command: PolicyCommand::Status(arguments),
        } => policy_status(&cli, arguments, false, &environment, &current, protection),
        Command::Policy {
            command: PolicyCommand::Explain(arguments),
        } => policy_status(&cli, arguments, true, &environment, &current, protection),
        Command::Policy {
            command:
                PolicyCommand::Require {
                    command: PolicyRequireCommand::Witnessed(arguments),
                },
        } => policy_require_witnessed(&cli, arguments, &environment, &current, protection),
        Command::Policy {
            command:
                PolicyCommand::Allow {
                    command: PolicyAllowCommand::Direct(arguments),
                },
        } => policy_allow_direct(&cli, arguments, &environment, &current, protection),
        Command::Vault {
            command:
                VaultCommand::Audit {
                    command: AuditCommand::Verify,
                },
        } => vault_audit_verify(&cli, &environment, &current, protection),
        Command::Inject(arguments) => {
            template_inject(&cli, arguments, &environment, &current, protection)
        }
        Command::Exec(arguments) => {
            transparent_exec(&cli, arguments, &environment, &current, protection)
        }
        Command::Run(arguments) => {
            brokered_run(&cli, arguments, &environment, &current, protection)
        }
        Command::InternalExec(arguments) => internal_exec(arguments),
    }
}
