use std::env;
use std::process::ExitCode;

fn main() -> ExitCode {
    let version = env!("CARGO_PKG_VERSION");

    match env::args().nth(1).as_deref() {
        Some("-h" | "--help") => {
            println!("juryd {version}");
            println!("Self-hostable Jury witness service");
            println!();
            println!("WARNING: {}.", jury_core::MATURITY);
            println!("No server or witness protocol is implemented.");
            ExitCode::SUCCESS
        }
        Some("-V" | "--version") => {
            println!("juryd {version}");
            ExitCode::SUCCESS
        }
        _ => {
            eprintln!("juryd: refusing to start; no witness protocol is implemented");
            eprintln!("run `juryd --help` for scaffold status");
            ExitCode::from(2)
        }
    }
}
