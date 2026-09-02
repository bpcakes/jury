use std::{path::PathBuf, process::ExitCode};

use clap::{Parser, Subcommand};
use jury_witness::{
    AdapterError,
    anchor::{SqliteAnchorRepository, backup_anchor_database, restore_anchor_database},
    config::{AnchorServiceConfig, WitnessServiceConfig},
    persistence::{SqliteWitnessStore, backup_witness_database, restore_witness_database},
    server::{run_anchor_service, run_witness_service},
};

#[derive(Debug, Parser)]
#[command(
    name = "juryd",
    version,
    about = "Self-hostable Jury witness and external-anchor services",
    after_help = "WARNING: pre-alpha; do not use with real secrets."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run the authenticated witness protocol service.
    Serve {
        /// Absolute path to the witness-service JSON configuration.
        #[arg(long)]
        config: PathBuf,
    },
    /// Manage the witness replay/checkpoint database offline.
    Database {
        #[command(subcommand)]
        command: DatabaseCommand,
    },
    /// Run or manage the independent external rollback-anchor service.
    Anchor {
        #[command(subcommand)]
        command: AnchorCommand,
    },
}

#[derive(Debug, Subcommand)]
enum DatabaseCommand {
    /// Atomically migrate and initialize the configured database.
    Init {
        #[arg(long)]
        config: PathBuf,
    },
    /// Create a consistent standalone backup without overwriting a target.
    Backup {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Restore a validated backup only to the configured absent target.
    Restore {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        backup: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum AnchorCommand {
    /// Run the public read/authenticated-CAS external-anchor service.
    Serve {
        #[arg(long)]
        config: PathBuf,
    },
    /// Atomically migrate and initialize the anchor database.
    Init {
        #[arg(long)]
        config: PathBuf,
    },
    /// Create a consistent standalone anchor backup without overwriting a target.
    Backup {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Restore an anchor backup only to the configured absent target.
    Restore {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        backup: PathBuf,
    },
}

#[tokio::main]
async fn main() -> ExitCode {
    match run(Cli::parse()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("juryd: {error}");
            ExitCode::from(1)
        }
    }
}

async fn run(cli: Cli) -> Result<(), AdapterError> {
    match cli.command {
        Command::Serve { config } => {
            run_witness_service(WitnessServiceConfig::load(&config)?).await
        }
        Command::Database { command } => run_database(command),
        Command::Anchor { command } => run_anchor(command).await,
    }
}

fn run_database(command: DatabaseCommand) -> Result<(), AdapterError> {
    match command {
        DatabaseCommand::Init { config } => {
            let config = WitnessServiceConfig::load_database_command(&config)?;
            SqliteWitnessStore::open(&config.database.path, config.witness_id)?;
            println!(
                "juryd database initialized; contribution readiness still requires the exact external anchor"
            );
            Ok(())
        }
        DatabaseCommand::Backup { config, output } => {
            let config = WitnessServiceConfig::load_database_command(&config)?;
            backup_witness_database(&config.database.path, &output)?;
            println!("juryd database backup completed");
            Ok(())
        }
        DatabaseCommand::Restore { config, backup } => {
            let config = WitnessServiceConfig::load_database_command(&config)?;
            restore_witness_database(&backup, &config.database.path)?;
            println!(
                "juryd database restored; contribution readiness remains disabled until exact external-anchor reconciliation"
            );
            Ok(())
        }
    }
}

async fn run_anchor(command: AnchorCommand) -> Result<(), AdapterError> {
    match command {
        AnchorCommand::Serve { config } => {
            run_anchor_service(AnchorServiceConfig::load(&config)?).await
        }
        AnchorCommand::Init { config } => {
            let config = AnchorServiceConfig::load_database_command(&config)?;
            SqliteAnchorRepository::open(&config.database.path)?;
            println!("juryd external-anchor database initialized");
            Ok(())
        }
        AnchorCommand::Backup { config, output } => {
            let config = AnchorServiceConfig::load_database_command(&config)?;
            backup_anchor_database(&config.database.path, &output)?;
            println!("juryd external-anchor backup completed");
            Ok(())
        }
        AnchorCommand::Restore { config, backup } => {
            let config = AnchorServiceConfig::load_database_command(&config)?;
            restore_anchor_database(&backup, &config.database.path)?;
            println!(
                "juryd external-anchor database restored; witnesses independently verify exact state before contributing"
            );
            Ok(())
        }
    }
}
