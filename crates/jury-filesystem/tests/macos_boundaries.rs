#![cfg(target_os = "macos")]

use jury_filesystem::{
    ExclusiveStateLock, FilesystemErrorKind, HardenedStateRoot, PreparedPrivateFile,
    RepositoryLocation, read_private_file,
};
use std::error::Error;
use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;

fn acl(path: &Path, entry: &str) -> Result<(), Box<dyn Error>> {
    let status = std::process::Command::new("/bin/chmod")
        .args(["+a", entry])
        .arg(path)
        .status()?;
    assert!(status.success(), "synthetic native ACL fixture failed");
    Ok(())
}

#[test]
fn root_acl_and_acl_changes_on_retained_roots_are_refused() -> Result<(), Box<dyn Error>> {
    for entry in ["everyone allow read", "everyone deny delete"] {
        let temporary = tempfile::tempdir()?;
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700))?;
        let root = HardenedStateRoot::open_existing(temporary.path(), &[])?;
        let preview = root.preview_private_file(Path::new("ExampleSecret"))?;
        acl(temporary.path(), entry)?;
        assert_eq!(
            HardenedStateRoot::open_existing(temporary.path(), &[])
                .err()
                .ok_or("expected refusal")?
                .kind(),
            FilesystemErrorKind::Permission
        );
        assert_eq!(
            PreparedPrivateFile::prepare_bounded_private_bytes_if_unchanged(
                preview,
                b"ExampleSecret",
                128,
                false,
            )
            .err()
            .ok_or("expected refusal")?
            .kind(),
            FilesystemErrorKind::Permission
        );
        assert!(ExclusiveStateLock::try_acquire(&root, Path::new("lock")).is_err());
        assert_eq!(fs::read_dir(temporary.path())?.count(), 0);
    }
    Ok(())
}

#[test]
fn file_acl_blocks_private_read_preview_and_post_prepare_publication() -> Result<(), Box<dyn Error>>
{
    let temporary = tempfile::tempdir()?;
    fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700))?;
    let root = HardenedStateRoot::open_existing(temporary.path(), &[])?;
    let path = temporary.path().join("ExampleSecret");
    fs::write(&path, b"ExampleSecret")?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    acl(&path, "everyone allow read")?;
    assert_eq!(
        read_private_file(&path, 128)
            .err()
            .ok_or("expected refusal")?
            .kind(),
        FilesystemErrorKind::Permission
    );
    assert_eq!(
        root.preview_private_file(Path::new("ExampleSecret"))
            .err()
            .ok_or("expected refusal")?
            .kind(),
        FilesystemErrorKind::Permission
    );
    let prepared = PreparedPrivateFile::prepare_bounded_private_bytes_if_unchanged(
        root.preview_private_file(Path::new("new"))?,
        b"ExampleSecret",
        128,
        false,
    )?;
    let temp_path = fs::read_dir(temporary.path())?
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .find(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .starts_with(".jury-private-")
        })
        .ok_or("missing prepared file")?
        .path();
    acl(&temp_path, "everyone allow read")?;
    assert_eq!(
        prepared.publish().err().ok_or("expected refusal")?.kind(),
        FilesystemErrorKind::Permission
    );
    assert!(!temporary.path().join("new").exists());
    assert!(
        !temp_path.exists(),
        "refusal must remove the owned temporary inode"
    );
    Ok(())
}

#[test]
fn real_volume_case_and_unicode_aliases_do_not_bypass_separation() -> Result<(), Box<dyn Error>> {
    use std::os::unix::fs::MetadataExt as _;
    let temporary = tempfile::tempdir()?;
    let path = temporary.path().join("ExampleVault");
    fs::create_dir_all(path.join(".git"))?;
    fs::write(path.join(".git/HEAD"), b"ref: refs/heads/main\n")?;
    let repository = RepositoryLocation::discover(&path)?;
    let case_alias = temporary.path().join("examplevault");
    let insensitive = case_alias.exists();
    if let Some(expected) = std::env::var_os("JURY_M02_CASE_MODE") {
        assert_eq!(
            insensitive,
            expected == "insensitive",
            "test volume has wrong case mode"
        );
    }
    if insensitive {
        assert_eq!(fs::metadata(&path)?.ino(), fs::metadata(&case_alias)?.ino());
        assert_eq!(
            HardenedStateRoot::open_or_create(&case_alias.join("state"), &[&repository])
                .err()
                .ok_or("expected refusal")?
                .kind(),
            FilesystemErrorKind::Containment
        );
    } else {
        // On sensitive APFS these really are distinct objects, not aliases.
        HardenedStateRoot::open_or_create(&case_alias, &[&repository])?;
        assert_ne!(fs::metadata(&path)?.ino(), fs::metadata(&case_alias)?.ino());
    }
    let composed = temporary.path().join("ExampleCaf\u{e9}");
    let decomposed = temporary.path().join("ExampleCafe\u{301}");
    fs::create_dir(&composed)?;
    fs::set_permissions(&composed, fs::Permissions::from_mode(0o700))?;
    // Both APFS case modes are normalization insensitive.
    assert_eq!(
        fs::metadata(&composed)?.ino(),
        fs::metadata(&decomposed)?.ino()
    );
    assert_eq!(
        HardenedStateRoot::open_existing_excluding(&composed, &[], &[&decomposed])
            .err()
            .ok_or("expected refusal")?
            .kind(),
        FilesystemErrorKind::Containment
    );
    Ok(())
}

#[test]
#[ignore = "requires an owned non-APFS image; invoked by scripts/test-macos-filesystem"]
fn unsupported_volume_refuses_private_root_and_publication() -> Result<(), Box<dyn Error>> {
    use jury_filesystem::{PreparedPublicFile, preview_public_file};
    let path = std::env::var_os("JURY_M02_UNSUPPORTED_ROOT").ok_or("missing owned test volume")?;
    let temporary = tempfile::tempdir_in(path)?;
    fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700))?;
    assert_eq!(
        HardenedStateRoot::open_existing(temporary.path(), &[])
            .err()
            .ok_or("expected unsupported volume")?
            .kind(),
        FilesystemErrorKind::Unsupported
    );
    let preview = preview_public_file(&temporary.path().join("ExampleCiphertext"))?;
    assert_eq!(
        PreparedPublicFile::prepare_bounded_if_unchanged(preview, b"ExampleCiphertext", 128, false)
            .err()
            .ok_or("expected unsupported publication")?
            .kind(),
        FilesystemErrorKind::Unsupported
    );
    assert_eq!(fs::read_dir(temporary.path())?.count(), 0);
    Ok(())
}

#[test]
fn changed_parent_acl_refuses_publication_and_cleans_the_prepared_file()
-> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let path = temporary.path().join("state");
    let root = HardenedStateRoot::open_or_create(&path, &[])?;
    let prepared = PreparedPrivateFile::prepare_bounded_private_bytes_if_unchanged(
        root.preview_private_file(Path::new("ExampleSecret"))?,
        b"ExampleSecret",
        128,
        false,
    )?;
    acl(&path, "everyone allow read")?;
    assert_eq!(
        prepared
            .publish()
            .err()
            .ok_or("expected ACL refusal")?
            .kind(),
        FilesystemErrorKind::Permission
    );
    assert_eq!(fs::read_dir(&path)?.count(), 0);
    assert_eq!(
        HardenedStateRoot::open_existing(&path, &[])
            .err()
            .ok_or("ACL must be preserved")?
            .kind(),
        FilesystemErrorKind::Permission
    );
    Ok(())
}
