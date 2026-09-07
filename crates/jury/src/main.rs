use std::process::ExitCode;

use clap::Parser as _;

fn main() -> ExitCode {
    let arguments = std::env::args_os().collect::<Vec<_>>();
    // Child arguments after `--` do not select Jury's output format.
    let json_requested = arguments
        .iter()
        .skip(1)
        .take_while(|argument| *argument != "--")
        .any(|argument| {
            argument == "--json" || argument.as_encoded_bytes().starts_with(b"--json=")
        });
    let cli = match jury::cli::Cli::try_parse_from(arguments) {
        Ok(cli) => cli,
        Err(error) if json_requested && error.use_stderr() => {
            // Clap diagnostics may quote arbitrary argument values. Keep machine
            // failures static, including malformed values and non-UTF-8 input.
            let error = jury::cli::CliError::invalid_command_arguments();
            error.write(true);
            return ExitCode::from(error.exit_code());
        }
        Err(error) => error.exit(),
    };
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
