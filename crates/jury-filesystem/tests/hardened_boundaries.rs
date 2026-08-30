#![cfg(unix)]

use std::error::Error;
use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::Path;

use jury_filesystem::{
    ExclusiveStateLock, FilesystemErrorKind, HardenedStateRoot, PreparedPrivateFile,
    PublicationOutcome, PublicationPolicy, RepositoryLocation,
};
use jury_protected::{ProtectedMemory, ProtectionPolicy};

fn protected(bytes: &[u8]) -> Result<ProtectedMemory, Box<dyn Error>> {
    Ok(ProtectedMemory::initialize(
        bytes.len(),
        ProtectionPolicy::Strict,
        |destination| {
            destination.copy_from_slice(bytes);
            Ok::<usize, ()>(destination.len())
        },
    )?)
}

fn repository(path: &Path) -> Result<RepositoryLocation, Box<dyn Error>> {
    fs::create_dir_all(path.join(".git"))?;
    fs::write(path.join(".git/HEAD"), b"ref: refs/heads/main\n")?;
    Ok(RepositoryLocation::discover(path)?)
}

#[test]
fn nearest_nested_repository_is_retained_without_path_disclosure() -> Result<(), Box<dyn Error>> {
    let temp = tempfile::tempdir()?;
    fs::create_dir_all(temp.path().join("outer/.git"))?;
    fs::create_dir_all(temp.path().join("outer/inner/.git"))?;
    fs::write(
        temp.path().join("outer/.git/HEAD"),
        b"ref: refs/heads/main\n",
    )?;
    fs::write(
        temp.path().join("outer/inner/.git/HEAD"),
        b"ref: refs/heads/main\n",
    )?;
    fs::create_dir_all(temp.path().join("outer/inner/sub"))?;

    let found = RepositoryLocation::discover(&temp.path().join("outer/inner/sub"))?;
    let debug = format!("{found:?}");
    assert!(!found.has_jury_directory());
    assert!(debug.contains("[REDACTED]"));
    assert!(!debug.contains(temp.path().to_string_lossy().as_ref()));
    Ok(())
}

#[test]
fn linked_worktree_marker_is_bounded_single_link_and_hardened() -> Result<(), Box<dyn Error>> {
    let temp = tempfile::tempdir()?;
    let worktree = temp.path().join("worktree");
    let git_dir = temp.path().join("gitdirs/linked");
    fs::create_dir_all(&worktree)?;
    fs::create_dir_all(&git_dir)?;
    fs::write(git_dir.join("HEAD"), b"ref: refs/heads/main\n")?;
    fs::write(worktree.join(".git"), b"gitdir: ../gitdirs/linked\n")?;
    assert!(!RepositoryLocation::discover(&worktree)?.has_jury_directory());

    let hard_link = temp.path().join("marker-copy");
    fs::hard_link(worktree.join(".git"), hard_link)?;
    let error = RepositoryLocation::discover(&worktree)
        .err()
        .ok_or("marker should fail")?;
    assert_eq!(error.kind(), FilesystemErrorKind::HardLinkOrSize);
    Ok(())
}

#[test]
fn marker_and_jury_symlinks_fail_closed() -> Result<(), Box<dyn Error>> {
    let temp = tempfile::tempdir()?;
    let worktree = temp.path().join("worktree");
    let target = temp.path().join("target");
    fs::create_dir_all(&worktree)?;
    fs::create_dir_all(&target)?;
    symlink(&target, worktree.join(".git"))?;
    let marker_error = RepositoryLocation::discover(&worktree)
        .err()
        .ok_or("symlinked marker should fail")?;
    assert_eq!(marker_error.kind(), FilesystemErrorKind::LinkOrWrongType);

    fs::remove_file(worktree.join(".git"))?;
    fs::create_dir(worktree.join(".git"))?;
    fs::write(worktree.join(".git/HEAD"), b"ref: refs/heads/main\n")?;
    symlink(&target, worktree.join(".jury"))?;
    let jury_error = RepositoryLocation::discover(&worktree)
        .err()
        .ok_or("symlinked jury directory should fail")?;
    assert_eq!(jury_error.kind(), FilesystemErrorKind::LinkOrWrongType);
    Ok(())
}

#[test]
fn symlinked_start_components_and_malformed_git_heads_fail_closed() -> Result<(), Box<dyn Error>> {
    let temp = tempfile::tempdir()?;
    let worktree = temp.path().join("worktree");
    let repository = repository(&worktree)?;
    drop(repository);
    fs::create_dir_all(worktree.join("real/sub"))?;
    symlink(worktree.join("real"), worktree.join("alias"))?;
    let alias_error = RepositoryLocation::discover(&worktree.join("alias/sub"))
        .err()
        .ok_or("symlinked start should fail")?;
    assert_eq!(alias_error.kind(), FilesystemErrorKind::LinkOrWrongType);

    fs::write(worktree.join(".git/HEAD"), b"not-a-git-head\n")?;
    let head_error = RepositoryLocation::discover(&worktree)
        .err()
        .ok_or("malformed HEAD should fail")?;
    assert_eq!(head_error.kind(), FilesystemErrorKind::InvalidMarker);
    Ok(())
}

#[test]
fn state_root_is_owner_only_and_must_not_overlap_a_worktree() -> Result<(), Box<dyn Error>> {
    let temp = tempfile::tempdir()?;
    let repository = repository(&temp.path().join("worktree"))?;
    let state = HardenedStateRoot::open_or_create(&temp.path().join("state"), &[&repository])?;
    let mode = fs::metadata(temp.path().join("state"))?
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o700);
    assert!(format!("{state:?}").contains("[REDACTED]"));

    let overlap = HardenedStateRoot::open_or_create(
        &temp.path().join("worktree/private-state"),
        &[&repository],
    )
    .err()
    .ok_or("overlapping state root should fail")?;
    assert_eq!(overlap.kind(), FilesystemErrorKind::Containment);
    Ok(())
}

#[test]
fn private_publication_is_owner_only_atomic_and_policy_bound() -> Result<(), Box<dyn Error>> {
    let temp = tempfile::tempdir()?;
    let state = HardenedStateRoot::open_or_create(&temp.path().join("state"), &[])?;
    let first = protected(b"ExampleSecret-one")?;
    let prepared = PreparedPrivateFile::prepare_state(
        &state,
        Path::new("private.bin"),
        &first,
        PublicationPolicy::CreateNew,
    )?;
    let debug = format!("{prepared:?}");
    assert!(debug.contains("[REDACTED]"));
    assert!(!debug.contains("ExampleSecret-one"));
    assert_eq!(prepared.publish()?, PublicationOutcome::PublishedAndSynced);
    let output = temp.path().join("state/private.bin");
    assert_eq!(fs::read(&output)?, b"ExampleSecret-one");
    assert_eq!(fs::metadata(&output)?.permissions().mode() & 0o777, 0o600);

    let conflict = PreparedPrivateFile::prepare_state(
        &state,
        Path::new("private.bin"),
        &first,
        PublicationPolicy::CreateNew,
    )
    .err()
    .ok_or("create-new should not clobber")?;
    assert_eq!(conflict.kind(), FilesystemErrorKind::AlreadyExists);

    let second = protected(b"ExampleSecret-two")?;
    PreparedPrivateFile::prepare_state(
        &state,
        Path::new("private.bin"),
        &second,
        PublicationPolicy::ReplaceExisting,
    )?
    .publish()?;
    assert_eq!(fs::read(output)?, b"ExampleSecret-two");
    Ok(())
}

#[test]
fn preview_and_publish_reject_destination_replacement() -> Result<(), Box<dyn Error>> {
    let temp = tempfile::tempdir()?;
    let state = HardenedStateRoot::open_or_create(&temp.path().join("state"), &[])?;
    let output = temp.path().join("state/value.bin");
    fs::write(&output, b"old")?;
    fs::set_permissions(&output, fs::Permissions::from_mode(0o600))?;
    let precondition = state.preview_private_file(Path::new("value.bin"))?;
    let contents = protected(b"complete-new-value")?;
    let prepared = PreparedPrivateFile::prepare_if_unchanged(precondition, &contents, true)?;

    fs::remove_file(&output)?;
    fs::write(&output, b"attacker-replacement")?;
    fs::set_permissions(&output, fs::Permissions::from_mode(0o600))?;
    let error = prepared.publish().err().ok_or("replacement should fail")?;
    assert_eq!(error.kind(), FilesystemErrorKind::IdentityChanged);
    assert_eq!(fs::read(output)?, b"attacker-replacement");
    Ok(())
}

#[test]
fn exact_preview_detects_in_place_destination_changes() -> Result<(), Box<dyn Error>> {
    let temp = tempfile::tempdir()?;
    let state = HardenedStateRoot::open_or_create(&temp.path().join("state"), &[])?;
    let output = temp.path().join("state/value.bin");
    fs::write(&output, b"old")?;
    fs::set_permissions(&output, fs::Permissions::from_mode(0o600))?;
    let precondition = state.preview_private_file(Path::new("value.bin"))?;
    fs::write(&output, b"changed-in-place")?;
    let contents = protected(b"complete-new-value")?;
    let error = PreparedPrivateFile::prepare_if_unchanged(precondition, &contents, true)
        .err()
        .ok_or("in-place change should fail")?;
    assert_eq!(error.kind(), FilesystemErrorKind::IdentityChanged);
    assert_eq!(fs::read(output)?, b"changed-in-place");
    Ok(())
}

#[test]
fn symlink_and_hard_link_destinations_are_rejected() -> Result<(), Box<dyn Error>> {
    let temp = tempfile::tempdir()?;
    let state = HardenedStateRoot::open_or_create(&temp.path().join("state"), &[])?;
    let outside = temp.path().join("outside");
    fs::write(&outside, b"outside")?;
    symlink(&outside, temp.path().join("state/link"))?;
    let bytes = protected(b"ExampleSecret")?;
    let link_error = PreparedPrivateFile::prepare_state(
        &state,
        Path::new("link"),
        &bytes,
        PublicationPolicy::ReplaceExisting,
    )
    .err()
    .ok_or("symlink should fail")?;
    assert_eq!(link_error.kind(), FilesystemErrorKind::LinkOrWrongType);

    let linked = temp.path().join("state/linked");
    fs::hard_link(&outside, &linked)?;
    let hard_link_error = PreparedPrivateFile::prepare_state(
        &state,
        Path::new("linked"),
        &bytes,
        PublicationPolicy::ReplaceExisting,
    )
    .err()
    .ok_or("hard link should fail")?;
    assert_eq!(hard_link_error.kind(), FilesystemErrorKind::LinkOrWrongType);
    assert_eq!(fs::read(outside)?, b"outside");
    Ok(())
}

#[test]
fn dropping_prepared_output_cleans_only_its_own_temporary() -> Result<(), Box<dyn Error>> {
    let temp = tempfile::tempdir()?;
    let state_path = temp.path().join("state");
    let state = HardenedStateRoot::open_or_create(&state_path, &[])?;
    let contents = protected(b"ExampleSecret")?;
    let prepared = PreparedPrivateFile::prepare_state(
        &state,
        Path::new("value.bin"),
        &contents,
        PublicationPolicy::CreateNew,
    )?;
    assert_eq!(fs::read_dir(&state_path)?.count(), 1);
    drop(prepared);
    assert_eq!(fs::read_dir(&state_path)?.count(), 0);
    assert!(!state_path.join("value.bin").exists());
    Ok(())
}

#[test]
fn state_lock_is_exclusive_and_identity_safe_on_drop() -> Result<(), Box<dyn Error>> {
    let temp = tempfile::tempdir()?;
    let state_path = temp.path().join("state");
    let state = HardenedStateRoot::open_or_create(&state_path, &[])?;
    let lock = ExclusiveStateLock::try_acquire(&state, Path::new("public-id.lock"))?;
    assert!(matches!(
        ExclusiveStateLock::try_acquire(&state, Path::new("public-id.lock")),
        Err(jury_filesystem::LockError::Busy)
    ));

    fs::remove_file(state_path.join("public-id.lock"))?;
    fs::write(state_path.join("public-id.lock"), b"replacement")?;
    drop(lock);
    assert_eq!(fs::read(state_path.join("public-id.lock"))?, b"replacement");
    Ok(())
}

#[test]
fn worktree_api_can_publish_only_the_fixed_encrypted_artifact_leaf() -> Result<(), Box<dyn Error>> {
    let temp = tempfile::tempdir()?;
    let mut repository = repository(&temp.path().join("worktree"))?;
    repository.create_jury_directory()?;
    let bytes = protected(b"opaque-shared-artifact")?;
    PreparedPrivateFile::prepare_encrypted_shared_artifact(
        &repository,
        &bytes,
        PublicationPolicy::CreateNew,
    )?
    .publish()?;
    assert_eq!(
        fs::read(temp.path().join("worktree/.jury/vault.json"))?,
        b"opaque-shared-artifact"
    );
    Ok(())
}

#[test]
fn errors_are_value_and_path_free() -> Result<(), Box<dyn Error>> {
    let temp = tempfile::tempdir()?;
    let state = HardenedStateRoot::open_or_create(&temp.path().join("state"), &[])?;
    let bytes = protected(b"ExampleSecret-value")?;
    let error = PreparedPrivateFile::prepare_state(
        &state,
        Path::new("../private-name"),
        &bytes,
        PublicationPolicy::CreateNew,
    )
    .err()
    .ok_or("traversal should fail")?;
    let rendered = format!("{error:?} {error}");
    assert!(!rendered.contains("ExampleSecret-value"));
    assert!(!rendered.contains("private-name"));
    assert!(!rendered.contains(temp.path().to_string_lossy().as_ref()));
    Ok(())
}
