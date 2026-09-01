use std::process::ExitCode;

use clap::Parser as _;

fn main() -> ExitCode {
    let cli = jury::cli::Cli::parse();
    let json = cli.json;
    match jury::cli::execute(cli) {
        Ok(output) => {
            let exit_code = output.exit_code();
            output.write(json);
            ExitCode::from(exit_code)
        }
        Err(error) => {
            error.write(json);
            ExitCode::from(error.exit_code())
        }
    }
}
