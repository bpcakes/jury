use super::*;
use jury_protected::ProtectionPolicy;
use std::os::unix::fs::PermissionsExt as _;
#[cfg(target_os = "linux")]
use std::{
    os::unix::process::ExitStatusExt as _,
    path::PathBuf,
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

#[cfg(target_os = "linux")]
const J25_CRASH_ROOT: &str = "JURY_J25_CRASH_ROOT";
#[cfg(target_os = "linux")]
const J25_CRASH_MARKER: &str = "JURY_J25_CRASH_MARKER";
#[cfg(target_os = "linux")]
const J25_CRASH_STAGE: &str = "JURY_J25_CRASH_STAGE";

#[cfg(target_os = "linux")]
fn hold_for_sigkill() -> ! {
    loop {
        thread::park();
    }
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "subprocess fixture for abrupt_publication_is_always_complete_and_retryable"]
fn j25_sigkill_publication_probe() -> Result<(), Box<dyn std::error::Error>> {
    let root = PathBuf::from(std::env::var_os(J25_CRASH_ROOT).ok_or("crash root is absent")?);
    let marker = PathBuf::from(std::env::var_os(J25_CRASH_MARKER).ok_or("crash marker is absent")?);
    let stage = std::env::var(J25_CRASH_STAGE)?;
    let state = HardenedStateRoot::open_or_create(&root, &[])?;
    let contents =
        ProtectedMemory::initialize(128 * 1_024, ProtectionPolicy::Strict, |destination| {
            destination.fill(0x5a);
            Ok::<usize, ()>(destination.len())
        })?;
    let prepared = PreparedPrivateFile::prepare_state(
        &state,
        Path::new("value.bin"),
        &contents,
        PublicationPolicy::ReplaceExisting,
    )?;
    match stage.as_str() {
        "before-publication" => {
            std::fs::write(marker, b"prepared")?;
            hold_for_sigkill();
        }
        "after-rename-before-parent-sync" => {
            prepared.publish_with_sync(|_| {
                std::fs::write(marker, b"renamed")?;
                hold_for_sigkill();
            })?;
        }
        "after-publication" => {
            prepared.publish()?;
            std::fs::write(marker, b"published")?;
            hold_for_sigkill();
        }
        _ => return Err("unknown crash stage".into()),
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn wait_for_crash_marker(
    child: &mut Child,
    marker: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if marker.is_file() {
            return Ok(());
        }
        if let Some(status) = child.try_wait()? {
            return Err(format!("publication crash probe exited early with {status}").into());
        }
        thread::sleep(Duration::from_millis(5));
    }
    Err("publication crash probe did not reach its selected boundary".into())
}

#[cfg(target_os = "linux")]
#[test]
fn abrupt_publication_is_always_complete_and_retryable() -> Result<(), Box<dyn std::error::Error>> {
    const PROBE_TEST: &str = "private_output::tests::j25_sigkill_publication_probe";
    let old_contents = vec![0x49; 128 * 1_024];
    let new_contents = vec![0x5a; 128 * 1_024];
    for (stage, expected) in [
        ("before-publication", old_contents.as_slice()),
        ("after-rename-before-parent-sync", new_contents.as_slice()),
        ("after-publication", new_contents.as_slice()),
    ] {
        let temporary = tempfile::tempdir()?;
        let root = temporary.path().join("state");
        std::fs::create_dir(&root)?;
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))?;
        let destination = root.join("value.bin");
        std::fs::write(&destination, &old_contents)?;
        std::fs::set_permissions(&destination, std::fs::Permissions::from_mode(0o600))?;
        let marker = temporary.path().join("boundary-reached");
        let mut child = Command::new(std::env::current_exe()?)
            .args(["--ignored", "--exact", PROBE_TEST, "--test-threads=1"])
            .env(J25_CRASH_ROOT, &root)
            .env(J25_CRASH_MARKER, &marker)
            .env(J25_CRASH_STAGE, stage)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()?;
        wait_for_crash_marker(&mut child, &marker)?;
        child.kill()?;
        let status = child.wait()?;
        assert_eq!(status.signal(), Some(9));
        assert_eq!(std::fs::read(&destination)?, expected);
        let metadata = std::fs::metadata(&destination)?;
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        assert_eq!(std::os::unix::fs::MetadataExt::nlink(&metadata), 1);

        let state = HardenedStateRoot::open_or_create(&root, &[])?;
        let successor =
            ProtectedMemory::initialize(128 * 1_024, ProtectionPolicy::Strict, |output| {
                output.fill(0x6b);
                Ok::<usize, ()>(output.len())
            })?;
        assert_eq!(
            PreparedPrivateFile::prepare_state(
                &state,
                Path::new("value.bin"),
                &successor,
                PublicationPolicy::ReplaceExisting,
            )?
            .publish()?,
            PublicationOutcome::PublishedAndSynced
        );
        assert_eq!(std::fs::read(destination)?, vec![0x6b; 128 * 1_024]);
    }
    Ok(())
}

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
