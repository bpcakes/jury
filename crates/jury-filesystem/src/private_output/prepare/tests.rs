use super::*;
use std::cell::Cell;
use std::error::Error;
use std::os::unix::fs::PermissionsExt as _;

#[test]
fn invalid_mode_is_rejected_before_the_writer() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let path = temporary.path().join("ExampleSecret");
    let mut file = File::from_std(std::fs::File::create(&path)?);
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))?;
    let called = Cell::new(false);
    let result = validate_and_write(&mut file, FileVisibility::OwnerOnly, |_| {
        called.set(true);
        Ok(())
    });
    assert_eq!(
        result.err().ok_or("expected refusal")?.kind(),
        FilesystemErrorKind::Permission
    );
    assert!(!called.get());
    assert_eq!(file.metadata()?.len(), 0);
    Ok(())
}

#[test]
fn file_sync_failure_prevents_a_prepared_publication() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempfile()?;
    temporary.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    let mut file = File::from_std(temporary);
    let result = validate_and_write_with_sync(
        &mut file,
        FileVisibility::OwnerOnly,
        |file| file.write_all(b"ExampleSecret"),
        |_| Err(std::io::Error::other("injected file sync failure")),
    );
    assert_eq!(
        result.err().ok_or("expected refusal")?.operation(),
        FilesystemOperation::Prepare
    );
    Ok(())
}

#[cfg(target_os = "macos")]
#[test]
fn inherited_acl_is_checked_on_the_fresh_descriptor_before_the_writer() -> Result<(), Box<dyn Error>>
{
    use std::os::fd::AsFd;
    for entry in [
        "everyone allow read,file_inherit,directory_inherit,only_inherit",
        "everyone deny delete,file_inherit,directory_inherit,only_inherit",
    ] {
        let temporary = tempfile::tempdir()?;
        let status = std::process::Command::new("/bin/chmod")
            .args(["+a", entry])
            .arg(temporary.path())
            .status()?;
        assert!(status.success(), "native synthetic ACL creation failed");
        let parent = Dir::open_ambient_dir(temporary.path(), cap_std::ambient_authority())?;
        let mut options = OpenOptions::new();
        options
            .write(true)
            .create_new(true)
            .mode(0o600)
            .follow(FollowSymlinks::No);
        let mut file = parent.open_with("ExampleSecret", &options)?;
        let acl = calcifer_macos_acl::read_acl(file.as_fd())?;
        assert!(!acl.entries.is_empty());
        assert!(
            acl.entries
                .iter()
                .all(|entry| entry.flags & calcifer_macos_acl::FLAG_INHERITED != 0)
        );
        assert_eq!(file.metadata()?.permissions().mode() & 0o777, 0o600);
        let called = Cell::new(false);
        let result = validate_and_write(&mut file, FileVisibility::OwnerOnly, |_| {
            called.set(true);
            Ok(())
        });
        assert_eq!(
            result.err().ok_or("expected refusal")?.kind(),
            FilesystemErrorKind::Permission
        );
        assert!(!called.get());
        assert_eq!(file.metadata()?.len(), 0);
    }
    Ok(())
}
