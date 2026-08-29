use std::env;
use std::process::ExitCode;

fn main() -> ExitCode {
    let version = env!("CARGO_PKG_VERSION");

    match env::args().nth(1).as_deref() {
        None | Some("-h" | "--help") => {
            print!("{}", jury::help_text(version));
            ExitCode::SUCCESS
        }
        Some("-V" | "--version") => {
            println!("jury {version}");
            ExitCode::SUCCESS
        }
        Some(argument) => {
            eprintln!("jury: command `{argument}` is not implemented");
            eprintln!("run `jury --help` for scaffold status");
            ExitCode::from(2)
        }
    }
}
