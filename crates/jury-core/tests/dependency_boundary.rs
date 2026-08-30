use std::fs;
use std::path::Path;

#[test]
fn core_manifest_and_lock_have_no_jig_crate() -> Result<(), Box<dyn std::error::Error>> {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let manifest = fs::read_to_string(manifest_dir.join("Cargo.toml"))?;
    let lock = fs::read_to_string(manifest_dir.join("../../Cargo.lock"))?;

    for forbidden in ["jig-core", "jig-vault", "../jig", "name = \"jig"] {
        assert!(
            !manifest.contains(forbidden),
            "manifest contains {forbidden:?}"
        );
        assert!(!lock.contains(forbidden), "lockfile contains {forbidden:?}");
    }
    Ok(())
}

#[test]
fn production_sources_embed_no_external_routing_literals() -> Result<(), Box<dyn std::error::Error>>
{
    let source_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut pending = vec![source_root];

    while let Some(path) = pending.pop() {
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            let file_type = entry.file_type()?;
            if file_type.is_dir() {
                pending.push(entry.path());
            } else if entry.path().extension().and_then(|value| value.to_str()) == Some("rs") {
                let source = fs::read_to_string(entry.path())?;
                for forbidden in ["jig://", "JIG_", "refs/heads/", ".git/"] {
                    assert!(
                        !source.contains(forbidden),
                        "production source contains external routing literal {forbidden:?}"
                    );
                }
            }
        }
    }
    Ok(())
}
