#![cfg(unix)]

use std::error::Error;
use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::Path;

use jury_filesystem::{
    ExclusiveStateLock, FilesystemErrorKind, HardenedStateRoot, IdentitySelectionError,
    IdentitySelector, PreparedPrivateFile, PreparedPublicFile, PublicationOutcome,
    PublicationPolicy, RepositoryLocation, list_named_identities, preview_public_file,
    read_private_file, read_public_file,
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
fn repository_ancestry_digest_tracks_head_ref_and_index_without_git() -> Result<(), Box<dyn Error>>
{
    let temp = tempfile::tempdir()?;
    let worktree = temp.path().join("worktree");
    let repository = repository(&worktree)?;
    let initial = repository.git_ancestry_digest()?;

    fs::create_dir_all(worktree.join(".git/refs/heads"))?;
    fs::write(
        worktree.join(".git/refs/heads/main"),
        b"1111111111111111111111111111111111111111\n",
    )?;
    let with_ref = repository.git_ancestry_digest()?;
    assert_ne!(with_ref, initial);

    fs::write(
        worktree.join(".git/refs/heads/main"),
        b"2222222222222222222222222222222222222222\n",
    )?;
    let moved_ref = repository.git_ancestry_digest()?;
    assert_ne!(moved_ref, with_ref);

    fs::write(worktree.join(".git/index"), b"ExampleIndex")?;
    assert_ne!(repository.git_ancestry_digest()?, moved_ref);
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
fn identity_selection_is_single_explicit_and_portable() -> Result<(), Box<dyn Error>> {
    let default = IdentitySelector::select(None, None)?;
    assert_eq!(
        format!("{default:?}"),
        "IdentitySelector::Named(<redacted>)"
    );
    assert!(IdentitySelector::select(Some("Example-Identity_1"), None).is_ok());

    for invalid in [
        "",
        ".hidden",
        "trailing-",
        "../escape",
        "nested/name",
        "not portable",
        "Příliš",
    ] {
        assert_eq!(
            IdentitySelector::select(Some(invalid), None),
            Err(IdentitySelectionError::InvalidName)
        );
    }
    assert_eq!(
        IdentitySelector::select(Some(&"a".repeat(65)), None),
        Err(IdentitySelectionError::InvalidName)
    );
    assert_eq!(
        IdentitySelector::select(
            Some("ExampleIdentity"),
            Some(Path::new("/tmp/Example.identity.json").to_path_buf()),
        ),
        Err(IdentitySelectionError::Ambiguous)
    );
    assert_eq!(
        IdentitySelector::select(
            None,
            Some(Path::new("relative/Example.identity.json").to_path_buf()),
        ),
        Err(IdentitySelectionError::InvalidExplicitPath)
    );
    assert_eq!(
        IdentitySelector::select(
            None,
            Some(Path::new("/tmp/../Example.identity.json").to_path_buf()),
        ),
        Err(IdentitySelectionError::InvalidExplicitPath)
    );
    Ok(())
}

#[test]
fn named_and_explicit_identity_files_use_hardened_bounded_io() -> Result<(), Box<dyn Error>> {
    let temp = tempfile::tempdir()?;
    let named_root = HardenedStateRoot::open_or_create(&temp.path().join("named"), &[])?;
    let named = IdentitySelector::select(Some("ExampleIdentity"), None)?;
    let contents = protected(b"ExampleEncryptedIdentity")?;
    assert_eq!(
        named
            .prepare(&named_root, &[], &contents, PublicationPolicy::CreateNew,)?
            .publish()?,
        PublicationOutcome::PublishedAndSynced
    );
    assert_eq!(
        named.read(&named_root, &[], 64)?,
        b"ExampleEncryptedIdentity"
    );
    fs::write(temp.path().join("named/ignored.txt"), b"ignored")?;
    fs::write(temp.path().join("named/.hidden.identity.json"), b"ignored")?;
    assert_eq!(
        list_named_identities(&named_root)?
            .iter()
            .map(|name| name.as_str())
            .collect::<Vec<_>>(),
        ["ExampleIdentity"]
    );
    let named_path = temp.path().join("named/ExampleIdentity.identity.json");
    assert_eq!(
        fs::metadata(named_path)?.permissions().mode() & 0o777,
        0o600
    );

    let explicit_parent = temp.path().join("explicit");
    fs::create_dir(&explicit_parent)?;
    fs::set_permissions(&explicit_parent, fs::Permissions::from_mode(0o700))?;
    let explicit_path = explicit_parent.join("Chosen.identity.json");
    let explicit = IdentitySelector::select(None, Some(explicit_path.clone()))?;
    explicit
        .prepare(&named_root, &[], &contents, PublicationPolicy::CreateNew)?
        .publish()?;
    assert_eq!(
        explicit.read(&named_root, &[], 64)?,
        contents.expose(|bytes| bytes.to_vec())?
    );
    assert_eq!(
        fs::metadata(explicit_path)?.permissions().mode() & 0o777,
        0o600
    );
    Ok(())
}

#[test]
fn identity_reads_reject_links_modes_sizes_and_worktree_paths() -> Result<(), Box<dyn Error>> {
    let temp = tempfile::tempdir()?;
    let named_path = temp.path().join("named");
    let named_root = HardenedStateRoot::open_or_create(&named_path, &[])?;

    let outside = temp.path().join("outside");
    fs::write(&outside, b"ExampleEncryptedIdentity")?;
    fs::set_permissions(&outside, fs::Permissions::from_mode(0o600))?;
    symlink(&outside, named_path.join("Link.identity.json"))?;
    let link = IdentitySelector::select(Some("Link"), None)?;
    assert_eq!(
        link.read(&named_root, &[], 64)
            .err()
            .ok_or("symlink should fail")?
            .kind(),
        FilesystemErrorKind::HardLinkOrSize
    );

    let linked = named_path.join("Linked.identity.json");
    fs::hard_link(&outside, &linked)?;
    let hard_link = IdentitySelector::select(Some("Linked"), None)?;
    assert_eq!(
        hard_link
            .read(&named_root, &[], 64)
            .err()
            .ok_or("hard link should fail")?
            .kind(),
        FilesystemErrorKind::HardLinkOrSize
    );

    let open = named_path.join("Open.identity.json");
    fs::write(&open, b"ExampleEncryptedIdentity")?;
    fs::set_permissions(&open, fs::Permissions::from_mode(0o644))?;
    let permissive = IdentitySelector::select(Some("Open"), None)?;
    assert_eq!(
        permissive
            .read(&named_root, &[], 64)
            .err()
            .ok_or("permissive mode should fail")?
            .kind(),
        FilesystemErrorKind::Permission
    );

    let large = named_path.join("Large.identity.json");
    fs::write(&large, [0xa5; 65])?;
    fs::set_permissions(&large, fs::Permissions::from_mode(0o600))?;
    let oversized = IdentitySelector::select(Some("Large"), None)?;
    assert_eq!(
        oversized
            .read(&named_root, &[], 64)
            .err()
            .ok_or("oversized file should fail")?
            .kind(),
        FilesystemErrorKind::HardLinkOrSize
    );

    let repository = repository(&temp.path().join("worktree"))?;
    let private = temp.path().join("worktree/private");
    fs::create_dir(&private)?;
    fs::set_permissions(&private, fs::Permissions::from_mode(0o700))?;
    let in_worktree =
        IdentitySelector::select(None, Some(private.join("ExampleIdentity.identity.json")))?;
    let contents = protected(b"ExampleEncryptedIdentity")?;
    assert_eq!(
        in_worktree
            .prepare(
                &named_root,
                &[&repository],
                &contents,
                PublicationPolicy::CreateNew,
            )
            .err()
            .ok_or("worktree identity should fail")?
            .kind(),
        FilesystemErrorKind::Containment
    );
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
fn public_file_preview_publishes_encrypted_bytes_without_following_paths()
-> Result<(), Box<dyn Error>> {
    let temp = tempfile::tempdir()?;
    let output = temp.path().join("ExampleTransfer.json");
    let precondition = preview_public_file(&output)?;
    assert!(!precondition.destination_exists());
    let contents = b"ExampleEncryptedTransfer";
    let publication = PreparedPublicFile::prepare_bounded_if_unchanged(
        precondition,
        contents,
        contents.len(),
        false,
    )?
    .publish()?;

    assert_eq!(publication, PublicationOutcome::PublishedAndSynced);
    assert_eq!(fs::read(&output)?, b"ExampleEncryptedTransfer");
    assert_eq!(fs::metadata(&output)?.permissions().mode() & 0o777, 0o644);
    assert_eq!(
        preview_public_file(Path::new("relative-transfer.json"))
            .err()
            .ok_or("relative public destination should fail")?
            .kind(),
        FilesystemErrorKind::Traversal
    );
    Ok(())
}

#[test]
fn public_file_writer_enforces_its_own_format_bound() -> Result<(), Box<dyn Error>> {
    let temp = tempfile::tempdir()?;
    let output = temp.path().join("ExampleTransfer.json");
    let precondition = preview_public_file(&output)?;
    let error = PreparedPublicFile::prepare_bounded_if_unchanged(precondition, b"five!", 4, false)
        .err()
        .ok_or("oversized public output should fail")?;

    assert_eq!(error.kind(), FilesystemErrorKind::HardLinkOrSize);
    assert!(!output.exists());
    Ok(())
}

#[test]
fn public_file_writer_is_not_limited_by_secret_memory_capacity() -> Result<(), Box<dyn Error>> {
    let temp = tempfile::tempdir()?;
    let output = temp.path().join("LargeExampleTransfer.json");
    let contents = vec![0x5a; 16 * 1024 * 1024 + 1];
    let precondition = preview_public_file(&output)?;

    PreparedPublicFile::prepare_bounded_if_unchanged(
        precondition,
        &contents,
        32 * 1024 * 1024,
        false,
    )?
    .publish()?;

    assert_eq!(fs::metadata(output)?.len(), contents.len() as u64);
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
    repository.ensure_vault_attributes()?;
    repository.ensure_vault_attributes()?;
    assert_eq!(
        fs::read(temp.path().join("worktree/.jury/.gitattributes"))?,
        b"vault.json -diff -merge\n"
    );

    fs::write(
        temp.path().join("worktree/.jury/.gitattributes"),
        b"vault.json merge=text\n",
    )?;
    let mismatch = repository
        .ensure_vault_attributes()
        .err()
        .ok_or("noncanonical attributes should fail")?;
    assert_eq!(mismatch.kind(), FilesystemErrorKind::IdentityChanged);
    Ok(())
}

#[test]
fn retained_repository_refuses_publication_after_git_marker_disappears()
-> Result<(), Box<dyn Error>> {
    let temp = tempfile::tempdir()?;
    let worktree = temp.path().join("worktree");
    let mut repository = repository(&worktree)?;
    fs::remove_dir_all(worktree.join(".git"))?;
    let error = repository
        .create_jury_directory()
        .err()
        .ok_or("missing Git marker should fail")?;
    assert_eq!(error.kind(), FilesystemErrorKind::InvalidMarker);
    assert!(!worktree.join(".jury").exists());
    Ok(())
}

#[test]
fn retained_repository_refuses_a_replaced_jury_directory() -> Result<(), Box<dyn Error>> {
    let temp = tempfile::tempdir()?;
    let worktree = temp.path().join("worktree");
    let mut repository = repository(&worktree)?;
    repository.create_jury_directory()?;
    let original = protected(b"original-encrypted-vault")?;
    PreparedPrivateFile::prepare_encrypted_shared_artifact(
        &repository,
        &original,
        PublicationPolicy::CreateNew,
    )?
    .publish()?;

    fs::rename(worktree.join(".jury"), worktree.join(".jury-retained"))?;
    fs::create_dir(worktree.join(".jury"))?;
    fs::set_permissions(worktree.join(".jury"), fs::Permissions::from_mode(0o700))?;
    fs::write(worktree.join(".jury/vault.json"), b"replacement")?;

    let error = repository
        .read_encrypted_shared_artifact(1024)
        .err()
        .ok_or("replaced Jury directory should fail")?;
    assert_eq!(error.kind(), FilesystemErrorKind::IdentityChanged);
    let create_error = repository
        .create_jury_directory()
        .err()
        .ok_or("existing retained Jury identity should be revalidated")?;
    assert_eq!(create_error.kind(), FilesystemErrorKind::IdentityChanged);
    assert_eq!(
        fs::read(worktree.join(".jury-retained/vault.json"))?,
        b"original-encrypted-vault"
    );
    assert_eq!(fs::read(worktree.join(".jury/vault.json"))?, b"replacement");
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

#[test]
fn bounded_public_file_read_accepts_read_only_leaf_and_rejects_links() -> Result<(), Box<dyn Error>>
{
    let temp = tempfile::tempdir()?;
    let template = temp.path().join("template.txt");
    fs::write(&template, b"{{ExampleItem.ExampleField}}")?;
    fs::set_permissions(&template, fs::Permissions::from_mode(0o644))?;
    assert_eq!(
        read_public_file(&template, 1024)?,
        b"{{ExampleItem.ExampleField}}"
    );

    let linked = temp.path().join("linked.txt");
    symlink(&template, &linked)?;
    let error = read_public_file(&linked, 1024)
        .err()
        .ok_or("linked public input should fail")?;
    assert_eq!(error.kind(), FilesystemErrorKind::HardLinkOrSize);
    Ok(())
}

#[test]
fn bounded_private_file_read_requires_owner_only_unaliased_leaf() -> Result<(), Box<dyn Error>> {
    let temp = tempfile::tempdir()?;
    let credential = temp.path().join("ExampleCredential");
    fs::write(&credential, b"ExampleCredentialValue")?;
    fs::set_permissions(&credential, fs::Permissions::from_mode(0o600))?;
    assert_eq!(
        read_private_file(&credential, 1024)?,
        b"ExampleCredentialValue"
    );

    fs::set_permissions(&credential, fs::Permissions::from_mode(0o640))?;
    assert_eq!(
        read_private_file(&credential, 1024)
            .err()
            .ok_or("group-readable private input should fail")?
            .kind(),
        FilesystemErrorKind::Permission
    );
    fs::set_permissions(&credential, fs::Permissions::from_mode(0o600))?;
    let linked = temp.path().join("linked-credential");
    symlink(&credential, &linked)?;
    assert_eq!(
        read_private_file(&linked, 1024)
            .err()
            .ok_or("linked private input should fail")?
            .kind(),
        FilesystemErrorKind::HardLinkOrSize
    );
    Ok(())
}
