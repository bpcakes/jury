use jury_witness_v1_conformance::{check_corpus, write_corpus};
use std::{env, path::PathBuf};

fn main() -> Result<(), String> {
    let mut args = env::args().skip(1);
    let mode = args
        .next()
        .ok_or_else(|| "usage: generate --check|--write".to_owned())?;
    if args.next().is_some() {
        return Err("usage: generate --check|--write".to_owned());
    }
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("vectors.json");
    match mode.as_str() {
        "--check" => check_corpus(&path),
        "--write" => write_corpus(&path),
        _ => Err("usage: generate --check|--write".to_owned()),
    }
}
