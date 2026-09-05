use std::{fs, path::PathBuf};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let root = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .ok_or("provide an explicit corpus output directory")?;
    for seed in jury_fuzz::seeds::seeds()? {
        let directory = root.join(seed.target);
        fs::create_dir_all(&directory)?;
        let path = directory.join(seed.name);
        // Preserve fuzzer discoveries and refuse to replace a different seed.
        match fs::read(&path) {
            Ok(existing) if existing != seed.bytes => {
                return Err("existing corpus seed differs".into());
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                use std::io::Write;
                let mut file = fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(path)?;
                file.write_all(&seed.bytes)?;
            }
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}
