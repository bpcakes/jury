#![cfg(unix)]

use std::error::Error;
use std::ffi::OsStr;
use std::fs;
use std::os::unix::fs::{PermissionsExt as _, symlink};
use std::path::Path;

use jury_filesystem::{
    FilesystemErrorKind, LockError, MAX_RECEIPTS_BYTES, PrincipalStateDirectory,
    PrincipalStateFile, RepositoryLocation, StatePathError, resolve_linux_state_root,
};
use jury_protected::{ProtectedMemory, ProtectionPolicy};

fn repository(path: &Path) -> Result<RepositoryLocation, Box<dyn Error>> {
    fs::create_dir_all(path.join(".git"))?;
    fs::write(path.join(".git/HEAD"), b"ref: refs/heads/main\n")?;
    Ok(RepositoryLocation::discover(path)?)
}

fn protected(bytes: &[u8]) -> Result<ProtectedMemory, Box<dyn Error>> {
    Ok(ProtectedMemory::initialize(
        bytes.len(),
        ProtectionPolicy::EmergencyAllowDegraded,
        |destination| {
            destination.copy_from_slice(bytes);
            Ok::<usize, ()>(destination.len())
        },
    )?)
}

#[test]
fn linux_state_root_precedence_is_exact_and_absolute() -> Result<(), Box<dyn Error>> {
    assert_eq!(
        resolve_linux_state_root(
            Some(OsStr::new("/ExampleOverride")),
            Some(OsStr::new("/ExampleXdg")),
            Some(OsStr::new("/ExampleHome")),
        )?,
        Path::new("/ExampleOverride")
    );
    assert_eq!(
        resolve_linux_state_root(
            None,
            Some(OsStr::new("/ExampleXdg")),
            Some(OsStr::new("/ExampleHome")),
        )?,
        Path::new("/ExampleXdg/jury/vaults")
    );
    assert_eq!(
        resolve_linux_state_root(None, None, Some(OsStr::new("/ExampleHome")))?,
        Path::new("/ExampleHome/.local/state/jury/vaults")
    );
    assert_eq!(
        resolve_linux_state_root(Some(OsStr::new("relative")), None, None),
        Err(StatePathError::NotAbsolute)
    );
    assert_eq!(
        resolve_linux_state_root(None, None, None),
        Err(StatePathError::MissingHome)
    );
    Ok(())
}

#[test]
fn scoped_state_is_private_locked_atomic_and_shared_across_clones() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let first_worktree = temporary.path().join("ExampleCloneA");
    let second_worktree = temporary.path().join("ExampleCloneB");
    let first_repository = repository(&first_worktree)?;
    let second_repository = repository(&second_worktree)?;
    let state_path = temporary.path().join("missing/parents/state");
    let vault_home = temporary.path().join("ExampleDetachedVault");
    fs::create_dir(&vault_home)?;

    let directory = PrincipalStateDirectory::open_or_create(
        &state_path,
        &[0x11; 32],
        &[0x12; 32],
        &[0x13; 32],
        &[&first_repository, &second_repository],
        &[&vault_home],
    )?;
    assert!(format!("{directory:?}").contains("[REDACTED]"));
    let locked = directory.try_lock()?;
    let duplicate = PrincipalStateDirectory::open_or_create(
        &state_path,
        &[0x11; 32],
        &[0x12; 32],
        &[0x13; 32],
        &[&first_repository, &second_repository],
        &[&vault_home],
    )?;
    assert!(matches!(duplicate.try_lock(), Err(LockError::Busy)));

    let audit = protected(b"{\"Example\":\"value-free\"}\n")?;
    locked.publish(PrincipalStateFile::Audit, &audit)?;
    assert_eq!(
        locked.read(PrincipalStateFile::Audit)?,
        b"{\"Example\":\"value-free\"}\n"
    );
    let oversized = protected(&vec![0; MAX_RECEIPTS_BYTES + 1])?;
    assert_eq!(
        locked
            .publish(PrincipalStateFile::Receipts, &oversized)
            .err()
            .map(|error| error.kind()),
        Some(FilesystemErrorKind::HardLinkOrSize)
    );

    let tuple_path = state_path
        .join("11".repeat(32))
        .join("12".repeat(32))
        .join("13".repeat(32));
    assert_eq!(
        fs::metadata(&state_path)?.permissions().mode() & 0o777,
        0o700
    );
    assert_eq!(
        fs::metadata(&tuple_path)?.permissions().mode() & 0o777,
        0o700
    );
    assert_eq!(
        fs::metadata(tuple_path.join("audit.jsonl"))?
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert!(!first_worktree.join(".jury/audit.jsonl").exists());
    assert!(!second_worktree.join(".jury/checkpoint.json").exists());

    drop(locked);
    assert!(duplicate.try_lock().is_ok());
    Ok(())
}

#[test]
fn containment_and_tuple_link_attacks_fail_closed() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let worktree = temporary.path().join("ExampleWorktree");
    let repository = repository(&worktree)?;
    let contained = PrincipalStateDirectory::open_or_create(
        &worktree.join("state"),
        &[0x21; 32],
        &[0x22; 32],
        &[0x23; 32],
        &[&repository],
        &[],
    )
    .err()
    .ok_or("contained state root was accepted")?;
    assert_eq!(contained.kind(), FilesystemErrorKind::Containment);
    assert!(!worktree.join("state").exists());

    let state = temporary.path().join("state");
    let containing_vault = temporary.path();
    let error = PrincipalStateDirectory::open_or_create(
        &state,
        &[0x21; 32],
        &[0x22; 32],
        &[0x23; 32],
        &[],
        &[containing_vault],
    )
    .err()
    .ok_or("state root containing relationship was accepted")?;
    assert_eq!(error.kind(), FilesystemErrorKind::Containment);

    let broad = temporary.path().join("broad");
    fs::create_dir(&broad)?;
    fs::set_permissions(&broad, fs::Permissions::from_mode(0o755))?;
    let error = PrincipalStateDirectory::open_or_create(
        &broad,
        &[0x21; 32],
        &[0x22; 32],
        &[0x23; 32],
        &[],
        &[],
    )
    .err()
    .ok_or("broad existing state root was accepted")?;
    assert_eq!(error.kind(), FilesystemErrorKind::Permission);
    assert_eq!(fs::metadata(&broad)?.permissions().mode() & 0o777, 0o755);

    fs::create_dir(&state)?;
    fs::set_permissions(&state, fs::Permissions::from_mode(0o700))?;
    let outside = temporary.path().join("outside");
    fs::create_dir(&outside)?;
    symlink(&outside, state.join("21".repeat(32)))?;
    let error = PrincipalStateDirectory::open_or_create(
        &state,
        &[0x21; 32],
        &[0x22; 32],
        &[0x23; 32],
        &[],
        &[],
    )
    .err()
    .ok_or("tuple symlink was accepted")?;
    assert_eq!(error.kind(), FilesystemErrorKind::LinkOrWrongType);
    Ok(())
}
