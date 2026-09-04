use super::*;
use jury_protected::ProtectionPolicy;
use std::os::unix::fs::PermissionsExt as _;

#[test]
fn reports_publication_when_parent_sync_fails() -> Result<(), Box<dyn std::error::Error>> {
    let temporary = tempfile::tempdir()?;
    let state = HardenedStateRoot::open_or_create(&temporary.path().join("state"), &[])?;
    let contents = ProtectedMemory::initialize(16, ProtectionPolicy::Strict, |destination| {
        destination.copy_from_slice(b"ExampleSecret123");
        Ok::<usize, ()>(destination.len())
    })?;
    let prepared = PreparedPrivateFile::prepare_state(
        &state,
        Path::new("value.bin"),
        &contents,
        PublicationPolicy::CreateNew,
    )?;
    let outcome = prepared.publish_with_sync(|_| Err(std::io::Error::other("injected")))?;
    assert_eq!(outcome, PublicationOutcome::PublishedButParentUnsynced);
    assert_eq!(
        std::fs::read(temporary.path().join("state/value.bin"))?,
        b"ExampleSecret123"
    );
    assert_eq!(
        std::os::unix::fs::MetadataExt::nlink(&std::fs::metadata(
            temporary.path().join("state/value.bin")
        )?),
        1
    );
    assert_eq!(
        std::fs::read_dir(temporary.path().join("state"))?.count(),
        1
    );
    Ok(())
}

#[test]
fn bounded_encrypted_archive_is_owner_only_and_never_replaces_by_default()
-> Result<(), Box<dyn std::error::Error>> {
    let temporary = tempfile::tempdir()?;
    let state = HardenedStateRoot::open_or_create(&temporary.path().join("state"), &[])?;
    let bytes = vec![0x91; 2 * 1024 * 1024];
    let preview = state.preview_private_file(Path::new("backup.jury"))?;
    PreparedPrivateFile::prepare_bounded_private_bytes_if_unchanged(
        preview,
        &bytes,
        4 * 1024 * 1024,
        false,
    )?
    .publish()?;
    let path = temporary.path().join("state/backup.jury");
    let metadata = std::fs::metadata(&path)?;
    assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
    assert_eq!(std::os::unix::fs::MetadataExt::nlink(&metadata), 1);
    let preview = state.preview_private_file(Path::new("backup.jury"))?;
    assert!(matches!(
        PreparedPrivateFile::prepare_bounded_private_bytes_if_unchanged(
            preview,
            b"replacement",
            4 * 1024 * 1024,
            false,
        ),
        Err(error) if error.kind() == FilesystemErrorKind::AlreadyExists
    ));
    assert_eq!(std::fs::read(path)?, bytes);

    let loose = temporary.path().join("state/loose.jury");
    std::fs::write(&loose, b"existing")?;
    std::fs::set_permissions(&loose, std::fs::Permissions::from_mode(0o644))?;
    assert!(matches!(
        state.preview_private_file(Path::new("loose.jury")),
        Err(error) if error.kind() == FilesystemErrorKind::Permission
    ));
    Ok(())
}

#[test]
fn concurrent_create_new_publications_preserve_the_first_destination()
-> Result<(), Box<dyn std::error::Error>> {
    let temporary = tempfile::tempdir()?;
    let state = HardenedStateRoot::open_or_create(&temporary.path().join("state"), &[])?;
    let first = ProtectedMemory::initialize(5, ProtectionPolicy::Strict, |output| {
        output.copy_from_slice(b"first");
        Ok::<usize, ()>(output.len())
    })?;
    let second = ProtectedMemory::initialize(6, ProtectionPolicy::Strict, |output| {
        output.copy_from_slice(b"second");
        Ok::<usize, ()>(output.len())
    })?;
    let first_prepared = PreparedPrivateFile::prepare_state(
        &state,
        Path::new("value.bin"),
        &first,
        PublicationPolicy::CreateNew,
    )?;
    let second_prepared = PreparedPrivateFile::prepare_state(
        &state,
        Path::new("value.bin"),
        &second,
        PublicationPolicy::CreateNew,
    )?;

    assert_eq!(
        first_prepared.publish()?,
        PublicationOutcome::PublishedAndSynced
    );
    assert!(matches!(
        second_prepared.publish(),
        Err(error) if error.kind() == FilesystemErrorKind::IdentityChanged
    ));
    assert_eq!(
        std::fs::read(temporary.path().join("state/value.bin"))?,
        b"first"
    );
    Ok(())
}

#[test]
fn visibility_validation_uses_the_retained_destination_snapshot()
-> Result<(), Box<dyn std::error::Error>> {
    let temporary = tempfile::tempdir()?;
    let state = HardenedStateRoot::open_or_create(&temporary.path().join("state"), &[])?;
    let output = temporary.path().join("state/existing.bin");
    std::fs::write(&output, b"existing")?;
    std::fs::set_permissions(&output, std::fs::Permissions::from_mode(0o600))?;
    let name = OsString::from("existing.bin");
    let snapshot = destination_state(&state.root.dir, &name, FilesystemOperation::Preview)?;
    std::fs::remove_file(output)?;

    validate_existing_visibility(snapshot, FileVisibility::OwnerOnly)?;
    assert!(matches!(
        validate_expected(&state.root.dir, &name, snapshot),
        Err(error) if error.kind() == FilesystemErrorKind::IdentityChanged
    ));
    Ok(())
}
