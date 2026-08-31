use std::process::ExitCode;

use clap::Parser as _;

fn main() -> ExitCode {
    let cli = jury::cli::Cli::parse();
    let json = cli.json;
    match jury::cli::execute(cli) {
        Ok(output) => {
            output.write(json);
            ExitCode::SUCCESS
        }
        Err(error) => {
            error.write(json);
            ExitCode::from(error.exit_code())
        }
    }
}
