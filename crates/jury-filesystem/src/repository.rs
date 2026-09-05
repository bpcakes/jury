use std::ffi::OsString;
use std::fmt;
use std::io::Read;
use std::path::{Path, PathBuf};

use cap_fs_ext::{DirExt as _, FollowSymlinks, MetadataExt, OpenOptionsFollowExt};
use cap_std::fs::{Dir, OpenOptions};
use sha2::{Digest as _, Sha256};

use crate::capability::{FileIdentity, HardenedDir, nofollow_directory_child, open_absolute_dir};
use crate::{FilesystemError, FilesystemErrorKind, FilesystemOperation};

const MAX_GITDIR_MARKER_BYTES: u64 = 4096;
const MAX_GIT_CONTROL_BYTES: u64 = 64 * 1024 * 1024;
const MAX_GIT_INDEX_BYTES: u64 = 256 * 1024 * 1024;
// Count excludes HEAD itself and matches Git's bounded file-ref resolution.
const MAX_GIT_SYMBOLIC_REFERENCE_DEPTH: usize = 4;
const VAULT_ATTRIBUTES: &[u8] = b"vault.json -diff -merge\n";

/// Retained capability to the nearest hardened Git worktree.
pub struct RepositoryLocation {
    pub(crate) worktree: HardenedDir,
    _git_dir: HardenedDir,
    git_common_dir: HardenedDir,
    jury_dir_identity: Option<FileIdentity>,
}

impl RepositoryLocation {
    #[must_use]
    pub fn worktree_path(&self) -> &Path {
        &self.worktree.absolute
    }

    /// Whether an already syntax-validated absolute path names this
    /// repository's shared Jury artifact. Used to reject transfer self-aliases
    /// before any credential capture.
    #[must_use]
    pub fn is_encrypted_shared_artifact_path(&self, path: &Path) -> bool {
        path == self.worktree.absolute.join(".jury/vault.json")
    }

    /// Discovers the nearest ordinary or linked Git worktree without following
    /// user-controlled path components or marker links.
    pub fn discover(start: &Path) -> Result<Self, FilesystemError> {
        let start =
            crate::capability::normalized_absolute(start, FilesystemOperation::DiscoverRepository)?;
        let mut current = Some(start.as_path());
        while let Some(candidate_path) = current {
            let worktree =
                open_absolute_dir(candidate_path, FilesystemOperation::DiscoverRepository)?;
            match open_git_marker(&worktree) {
                Ok(Some(git_dir)) => {
                    let git_common_dir = open_git_common_dir(&git_dir)?;
                    let jury_dir_identity = inspect_jury_directory(&worktree.dir)?;
                    return Ok(Self {
                        worktree,
                        _git_dir: git_dir,
                        git_common_dir,
                        jury_dir_identity,
                    });
                }
                Ok(None) => {}
                Err(error) => return Err(error),
            }
            current = candidate_path.parent();
        }
        Err(FilesystemError::new(
            FilesystemOperation::DiscoverRepository,
            FilesystemErrorKind::NotFound,
        ))
    }

    #[must_use]
    pub fn has_jury_directory(&self) -> bool {
        self.jury_dir_identity.is_some()
    }

    /// Explicitly creates the encrypted shared-artifact directory owner-only.
    pub fn create_jury_directory(&mut self) -> Result<(), FilesystemError> {
        self.revalidate_worktree()?;
        if self.jury_dir_identity.is_some() {
            self.jury_dir_clone()?;
            return sync_directory(&self.worktree.dir);
        }
        #[cfg(not(unix))]
        return Err(FilesystemError::new(
            FilesystemOperation::Open,
            FilesystemErrorKind::Unsupported,
        ));
        #[cfg(unix)]
        {
            use cap_std::fs::{DirBuilder, DirBuilderExt};
            let mut builder = DirBuilder::new();
            builder.mode(0o700);
            self.worktree
                .dir
                .create_dir_with(".jury", &builder)
                .map_err(|error| {
                    let kind = if error.kind() == std::io::ErrorKind::AlreadyExists {
                        FilesystemErrorKind::AlreadyExists
                    } else {
                        FilesystemErrorKind::Io
                    };
                    FilesystemError::new(FilesystemOperation::Open, kind)
                })?;
            let jury_dir = nofollow_directory_child(
                &self.worktree.dir,
                Path::new(".jury"),
                FilesystemOperation::Open,
            )?;
            self.jury_dir_identity = Some(FileIdentity::from_metadata(
                &jury_dir.dir_metadata().map_err(|_| {
                    FilesystemError::new(FilesystemOperation::Open, FilesystemErrorKind::Io)
                })?,
            ));
            sync_directory(&self.worktree.dir)
        }
    }

    pub fn preview_encrypted_shared_artifact(
        &self,
    ) -> Result<crate::PrivateFilePrecondition, FilesystemError> {
        crate::private_output::preview_encrypted_shared_artifact(
            &self.jury_dir_clone()?,
            Path::new("vault.json"),
        )
    }

    /// Reads the bounded encrypted shared artifact without exposing any other
    /// worktree leaf through this capability.
    pub fn read_encrypted_shared_artifact(
        &self,
        maximum_bytes: usize,
    ) -> Result<Vec<u8>, FilesystemError> {
        crate::private_input::read_public_from_dir(
            &self.jury_dir_clone()?,
            Path::new("vault.json"),
            maximum_bytes,
        )
    }

    /// Opaque digest of the worktree's current Git ancestry and index state.
    /// This reads control files directly and never invokes Git.
    pub fn git_ancestry_digest(&self) -> Result<[u8; 32], FilesystemError> {
        self.revalidate_worktree()?;
        ensure_files_reference_storage(&self._git_dir.dir)?;
        if self._git_dir.identity != self.git_common_dir.identity {
            ensure_files_reference_storage(&self.git_common_dir.dir)?;
        }
        let mut digest = Sha256::new();
        digest.update(b"jury-repository-ancestry-v1\0");
        let head = read_git_control(&self._git_dir.dir, Path::new("HEAD"), 1024, false)?
            .ok_or_else(|| {
                FilesystemError::new(
                    FilesystemOperation::Preview,
                    FilesystemErrorKind::InvalidMarker,
                )
            })?;
        hash_component(&mut digest, b"HEAD", Some(&head));

        let mut reference =
            parse_git_reference(&head, FilesystemOperation::Preview)?.map(Path::to_path_buf);
        let mut visited = Vec::new();
        loop {
            let Some(name) = reference.take() else {
                if visited.is_empty() {
                    hash_component(&mut digest, b"REF", None);
                }
                break;
            };
            if visited.len() == MAX_GIT_SYMBOLIC_REFERENCE_DEPTH || visited.contains(&name) {
                return Err(FilesystemError::new(
                    FilesystemOperation::Preview,
                    FilesystemErrorKind::InvalidMarker,
                ));
            }
            hash_component(
                &mut digest,
                b"REF_NAME",
                Some(
                    name.to_str()
                        .ok_or_else(|| {
                            FilesystemError::new(
                                FilesystemOperation::Preview,
                                FilesystemErrorKind::InvalidMarker,
                            )
                        })?
                        .as_bytes(),
                ),
            );
            let reference_directory = if self._git_dir.identity == self.git_common_dir.identity
                || is_per_worktree_reference(&name)
            {
                &self._git_dir.dir
            } else {
                &self.git_common_dir.dir
            };
            let reference_bytes = read_git_control(reference_directory, &name, 1024, true)?;
            hash_component(&mut digest, b"REF", reference_bytes.as_deref());
            visited.push(name);
            let Some(reference_bytes) = reference_bytes else {
                break;
            };
            reference = parse_git_reference(&reference_bytes, FilesystemOperation::Preview)?
                .map(Path::to_path_buf);
            if reference.is_none() {
                break;
            }
        }
        let packed = read_git_control(
            &self.git_common_dir.dir,
            Path::new("packed-refs"),
            MAX_GIT_CONTROL_BYTES,
            true,
        )?;
        hash_component(&mut digest, b"PACKED", packed.as_deref());
        let worktree_log = read_git_control(
            &self._git_dir.dir,
            Path::new("logs/HEAD"),
            MAX_GIT_CONTROL_BYTES,
            true,
        )?;
        hash_component(&mut digest, b"LOG", worktree_log.as_deref());
        let index = read_git_control(
            &self._git_dir.dir,
            Path::new("index"),
            MAX_GIT_INDEX_BYTES,
            true,
        )?;
        hash_component(&mut digest, b"INDEX", index.as_deref());
        Ok(digest.finalize().into())
    }

    /// Creates or validates the one fixed Git attributes file used by V1.
    /// Existing non-identical content is never overwritten.
    pub fn ensure_vault_attributes(&self) -> Result<(), FilesystemError> {
        let directory = self.jury_dir_clone()?;
        let destination =
            crate::private_output::preview_public_in_dir(&directory, Path::new(".gitattributes"))?;
        if destination.destination_exists() {
            return validate_vault_attributes(&directory);
        }
        match crate::PreparedPublicFile::prepare_bounded_if_unchanged(
            destination,
            VAULT_ATTRIBUTES,
            VAULT_ATTRIBUTES.len(),
            false,
        ) {
            Ok(prepared) => match prepared.publish()? {
                crate::PublicationOutcome::PublishedAndSynced => Ok(()),
                crate::PublicationOutcome::PublishedButParentUnsynced => Err(FilesystemError::new(
                    FilesystemOperation::SyncParent,
                    FilesystemErrorKind::Io,
                )),
            },
            Err(error) if error.kind() == FilesystemErrorKind::AlreadyExists => {
                validate_vault_attributes(&directory)
            }
            Err(error) => Err(error),
        }
    }

    pub(crate) fn jury_dir_clone(&self) -> Result<Dir, FilesystemError> {
        self.revalidate_worktree()?;
        let expected = self.jury_dir_identity.ok_or(FilesystemError::new(
            FilesystemOperation::Open,
            FilesystemErrorKind::NotFound,
        ))?;
        let directory = nofollow_directory_child(
            &self.worktree.dir,
            Path::new(".jury"),
            FilesystemOperation::Open,
        )?;
        let observed = FileIdentity::from_metadata(&directory.dir_metadata().map_err(|_| {
            FilesystemError::new(
                FilesystemOperation::Open,
                FilesystemErrorKind::IdentityChanged,
            )
        })?);
        if observed != expected {
            return Err(FilesystemError::new(
                FilesystemOperation::Open,
                FilesystemErrorKind::IdentityChanged,
            ));
        }
        Ok(directory)
    }

    fn revalidate_worktree(&self) -> Result<(), FilesystemError> {
        let reopened = open_absolute_dir(
            &self.worktree.absolute,
            FilesystemOperation::DiscoverRepository,
        )
        .map_err(|_| {
            FilesystemError::new(
                FilesystemOperation::DiscoverRepository,
                FilesystemErrorKind::IdentityChanged,
            )
        })?;
        if reopened.identity != self.worktree.identity {
            return Err(FilesystemError::new(
                FilesystemOperation::DiscoverRepository,
                FilesystemErrorKind::IdentityChanged,
            ));
        }
        let worktree_metadata = self.worktree.dir.dir_metadata().map_err(|_| {
            FilesystemError::new(
                FilesystemOperation::DiscoverRepository,
                FilesystemErrorKind::IdentityChanged,
            )
        })?;
        if crate::capability::FileIdentity::from_metadata(&worktree_metadata)
            != self.worktree.identity
        {
            return Err(FilesystemError::new(
                FilesystemOperation::DiscoverRepository,
                FilesystemErrorKind::IdentityChanged,
            ));
        }
        let git_dir = open_git_marker(&self.worktree)?.ok_or_else(|| {
            FilesystemError::new(
                FilesystemOperation::DiscoverRepository,
                FilesystemErrorKind::InvalidMarker,
            )
        })?;
        if git_dir.identity != self._git_dir.identity {
            return Err(FilesystemError::new(
                FilesystemOperation::DiscoverRepository,
                FilesystemErrorKind::IdentityChanged,
            ));
        }
        let git_common_dir = open_git_common_dir(&git_dir)?;
        if git_common_dir.identity != self.git_common_dir.identity {
            return Err(FilesystemError::new(
                FilesystemOperation::DiscoverRepository,
                FilesystemErrorKind::IdentityChanged,
            ));
        }
        Ok(())
    }
}

fn validate_vault_attributes(directory: &Dir) -> Result<(), FilesystemError> {
    let bytes = crate::private_input::read_public_from_dir(
        directory,
        Path::new(".gitattributes"),
        VAULT_ATTRIBUTES.len(),
    )?;
    if bytes != VAULT_ATTRIBUTES {
        return Err(FilesystemError::new(
            FilesystemOperation::Prepare,
            FilesystemErrorKind::IdentityChanged,
        ));
    }
    sync_directory(directory)
}

fn sync_directory(directory: &Dir) -> Result<(), FilesystemError> {
    directory
        .open(".")
        .and_then(|parent| parent.sync_all())
        .map_err(|_| FilesystemError::new(FilesystemOperation::SyncParent, FilesystemErrorKind::Io))
}

impl fmt::Debug for RepositoryLocation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RepositoryLocation")
            .field("has_jury_directory", &self.has_jury_directory())
            .field("path", &"[REDACTED]")
            .finish()
    }
}

fn open_git_marker(worktree: &HardenedDir) -> Result<Option<HardenedDir>, FilesystemError> {
    match worktree.dir.symlink_metadata(".git") {
        Ok(metadata) if metadata.is_dir() => {
            let dir = nofollow_directory_child(
                &worktree.dir,
                Path::new(".git"),
                FilesystemOperation::DiscoverRepository,
            )?;
            let identity = crate::capability::FileIdentity::from_metadata(
                &dir.dir_metadata().map_err(|_| {
                    FilesystemError::new(
                        FilesystemOperation::DiscoverRepository,
                        FilesystemErrorKind::Io,
                    )
                })?,
            );
            let git_dir = HardenedDir {
                dir,
                absolute: worktree.absolute.join(".git"),
                identity,
                lineage: {
                    let mut lineage = worktree.lineage.clone();
                    lineage.push(identity);
                    lineage
                },
            };
            validate_git_head(&git_dir)?;
            Ok(Some(git_dir))
        }
        Ok(metadata) if metadata.is_file() => {
            let git_dir = linked_git_dir(worktree, metadata)?;
            validate_git_head(&git_dir)?;
            Ok(Some(git_dir))
        }
        Ok(_) => Err(FilesystemError::new(
            FilesystemOperation::DiscoverRepository,
            FilesystemErrorKind::LinkOrWrongType,
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(FilesystemError::new(
            FilesystemOperation::DiscoverRepository,
            FilesystemErrorKind::Io,
        )),
    }
}

fn validate_git_head(git_dir: &HardenedDir) -> Result<(), FilesystemError> {
    let metadata = git_dir.dir.symlink_metadata("HEAD").map_err(|_| {
        FilesystemError::new(
            FilesystemOperation::DiscoverRepository,
            FilesystemErrorKind::InvalidMarker,
        )
    })?;
    if !metadata.is_file() || metadata.nlink() != 1 || metadata.len() == 0 || metadata.len() > 1024
    {
        return Err(FilesystemError::new(
            FilesystemOperation::DiscoverRepository,
            FilesystemErrorKind::InvalidMarker,
        ));
    }
    let mut options = OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    let head = git_dir.dir.open_with("HEAD", &options).map_err(|_| {
        FilesystemError::new(
            FilesystemOperation::DiscoverRepository,
            FilesystemErrorKind::InvalidMarker,
        )
    })?;
    let opened = head.metadata().map_err(|_| {
        FilesystemError::new(
            FilesystemOperation::DiscoverRepository,
            FilesystemErrorKind::InvalidMarker,
        )
    })?;
    if opened.dev() != metadata.dev() || opened.ino() != metadata.ino() || opened.nlink() != 1 {
        return Err(FilesystemError::new(
            FilesystemOperation::DiscoverRepository,
            FilesystemErrorKind::IdentityChanged,
        ));
    }
    let mut bytes = Vec::with_capacity(opened.len() as usize);
    head.take(1025).read_to_end(&mut bytes).map_err(|_| {
        FilesystemError::new(
            FilesystemOperation::DiscoverRepository,
            FilesystemErrorKind::InvalidMarker,
        )
    })?;
    parse_git_reference(&bytes, FilesystemOperation::DiscoverRepository).map(|_| ())
}

fn parse_git_reference(
    bytes: &[u8],
    operation: FilesystemOperation,
) -> Result<Option<&Path>, FilesystemError> {
    let value = git_control_line(bytes, operation)?;
    let detached =
        matches!(value.len(), 40 | 64) && value.bytes().all(|byte| byte.is_ascii_hexdigit());
    if detached {
        return Ok(None);
    }
    let reference = value
        .strip_prefix("ref: ")
        .map(Path::new)
        .ok_or_else(|| FilesystemError::new(operation, FilesystemErrorKind::InvalidMarker))?;
    let reference_text = reference
        .to_str()
        .ok_or_else(|| FilesystemError::new(operation, FilesystemErrorKind::InvalidMarker))?;
    if !is_valid_git_reference_name(reference_text) {
        return Err(FilesystemError::new(
            operation,
            FilesystemErrorKind::InvalidMarker,
        ));
    }
    let mut components = reference.components();
    if !matches!(components.next(), Some(std::path::Component::Normal(name)) if name == "refs") {
        return Err(FilesystemError::new(
            operation,
            FilesystemErrorKind::InvalidMarker,
        ));
    }
    let mut suffix_components = 0usize;
    for component in components {
        if !matches!(component, std::path::Component::Normal(_)) {
            return Err(FilesystemError::new(
                operation,
                FilesystemErrorKind::InvalidMarker,
            ));
        }
        suffix_components += 1;
    }
    if suffix_components == 0 {
        return Err(FilesystemError::new(
            operation,
            FilesystemErrorKind::InvalidMarker,
        ));
    }
    Ok(Some(reference))
}

fn git_control_line(bytes: &[u8], operation: FilesystemOperation) -> Result<&str, FilesystemError> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| FilesystemError::new(operation, FilesystemErrorKind::InvalidMarker))?;
    let value = text.strip_suffix('\n').unwrap_or(text);
    if value.is_empty() || value.contains(['\0', '\n', '\r']) {
        return Err(FilesystemError::new(
            operation,
            FilesystemErrorKind::InvalidMarker,
        ));
    }
    Ok(value)
}

fn is_valid_git_reference_name(reference: &str) -> bool {
    reference.starts_with("refs/")
        && !reference.ends_with(['/', '.'])
        && !["//", "..", "@{"]
            .into_iter()
            .any(|forbidden| reference.contains(forbidden))
        && !reference.bytes().any(|byte| {
            byte <= b' '
                || byte == 0x7f
                || matches!(byte, b'~' | b'^' | b':' | b'?' | b'*' | b'[' | b'\\')
        })
        && reference.split('/').all(|component| {
            !component.is_empty() && !component.starts_with('.') && !component.ends_with(".lock")
        })
}

fn is_per_worktree_reference(reference: &Path) -> bool {
    ["refs/bisect", "refs/rewritten", "refs/worktree"]
        .into_iter()
        .any(|prefix| reference.starts_with(Path::new(prefix)))
}

fn ensure_files_reference_storage(directory: &Dir) -> Result<(), FilesystemError> {
    match directory.symlink_metadata("reftable") {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Ok(_) => Err(FilesystemError::new(
            FilesystemOperation::Preview,
            FilesystemErrorKind::Unsupported,
        )),
        Err(_) => Err(FilesystemError::new(
            FilesystemOperation::Preview,
            FilesystemErrorKind::Io,
        )),
    }
}

fn open_git_common_dir(git_dir: &HardenedDir) -> Result<HardenedDir, FilesystemError> {
    let Some(bytes) = read_git_control(
        &git_dir.dir,
        Path::new("commondir"),
        MAX_GITDIR_MARKER_BYTES,
        true,
    )?
    else {
        return open_absolute_dir(&git_dir.absolute, FilesystemOperation::DiscoverRepository);
    };
    let value = git_control_line(&bytes, FilesystemOperation::DiscoverRepository)?;
    let path = Path::new(value);
    let resolved = if path.is_absolute() {
        path.to_path_buf()
    } else {
        git_dir.absolute.join(path)
    };
    open_absolute_dir(&resolved, FilesystemOperation::DiscoverRepository)
}

fn linked_git_dir(
    worktree: &HardenedDir,
    path_metadata: cap_std::fs::Metadata,
) -> Result<HardenedDir, FilesystemError> {
    if path_metadata.nlink() != 1 || path_metadata.len() > MAX_GITDIR_MARKER_BYTES {
        return Err(FilesystemError::new(
            FilesystemOperation::DiscoverRepository,
            FilesystemErrorKind::HardLinkOrSize,
        ));
    }
    let mut options = OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    let marker = worktree.dir.open_with(".git", &options).map_err(|_| {
        FilesystemError::new(
            FilesystemOperation::DiscoverRepository,
            FilesystemErrorKind::LinkOrWrongType,
        )
    })?;
    let opened = marker.metadata().map_err(|_| {
        FilesystemError::new(
            FilesystemOperation::DiscoverRepository,
            FilesystemErrorKind::Io,
        )
    })?;
    if opened.dev() != path_metadata.dev()
        || opened.ino() != path_metadata.ino()
        || opened.nlink() != 1
        || opened.len() > MAX_GITDIR_MARKER_BYTES
    {
        return Err(FilesystemError::new(
            FilesystemOperation::DiscoverRepository,
            FilesystemErrorKind::IdentityChanged,
        ));
    }
    let mut bytes = Vec::with_capacity(opened.len() as usize);
    marker
        .take(MAX_GITDIR_MARKER_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| {
            FilesystemError::new(
                FilesystemOperation::DiscoverRepository,
                FilesystemErrorKind::Io,
            )
        })?;
    if bytes.len() as u64 > MAX_GITDIR_MARKER_BYTES {
        return Err(FilesystemError::new(
            FilesystemOperation::DiscoverRepository,
            FilesystemErrorKind::HardLinkOrSize,
        ));
    }
    let value = git_control_line(&bytes, FilesystemOperation::DiscoverRepository)?
        .strip_prefix("gitdir: ")
        .filter(|value| !value.is_empty())
        .ok_or(FilesystemError::new(
            FilesystemOperation::DiscoverRepository,
            FilesystemErrorKind::InvalidMarker,
        ))?;
    let path = PathBuf::from(value);
    let resolved = if path.is_absolute() {
        path
    } else {
        worktree.absolute.join(path)
    };
    open_absolute_dir(&resolved, FilesystemOperation::DiscoverRepository)
}

fn inspect_jury_directory(worktree: &Dir) -> Result<Option<FileIdentity>, FilesystemError> {
    match worktree.symlink_metadata(".jury") {
        Ok(metadata) if metadata.is_dir() => {
            let directory = nofollow_directory_child(
                worktree,
                Path::new(".jury"),
                FilesystemOperation::DiscoverRepository,
            )?;
            let metadata = directory.dir_metadata().map_err(|_| {
                FilesystemError::new(
                    FilesystemOperation::DiscoverRepository,
                    FilesystemErrorKind::Io,
                )
            })?;
            Ok(Some(FileIdentity::from_metadata(&metadata)))
        }
        Ok(_) => Err(FilesystemError::new(
            FilesystemOperation::DiscoverRepository,
            FilesystemErrorKind::LinkOrWrongType,
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(FilesystemError::new(
            FilesystemOperation::DiscoverRepository,
            FilesystemErrorKind::Io,
        )),
    }
}

fn read_git_control(
    directory: &Dir,
    name: &Path,
    maximum_bytes: u64,
    optional: bool,
) -> Result<Option<Vec<u8>>, FilesystemError> {
    let Some((parent, leaf)) = control_parent(directory, name, optional)? else {
        return Ok(None);
    };
    let metadata = match parent.symlink_metadata(&leaf) {
        Ok(metadata) => metadata,
        Err(error) if optional && error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => {
            return Err(FilesystemError::new(
                FilesystemOperation::Preview,
                FilesystemErrorKind::Io,
            ));
        }
    };
    if !metadata.is_file() || metadata.nlink() != 1 || metadata.len() > maximum_bytes {
        return Err(FilesystemError::new(
            FilesystemOperation::Preview,
            FilesystemErrorKind::HardLinkOrSize,
        ));
    }
    let mut options = OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    let file = parent
        .open_with(&leaf, &options)
        .map_err(|_| FilesystemError::new(FilesystemOperation::Preview, FilesystemErrorKind::Io))?;
    let opened = file
        .metadata()
        .map_err(|_| FilesystemError::new(FilesystemOperation::Preview, FilesystemErrorKind::Io))?;
    if opened.dev() != metadata.dev()
        || opened.ino() != metadata.ino()
        || opened.nlink() != 1
        || opened.len() > maximum_bytes
    {
        return Err(FilesystemError::new(
            FilesystemOperation::Preview,
            FilesystemErrorKind::IdentityChanged,
        ));
    }
    let capacity = usize::try_from(opened.len()).map_err(|_| {
        FilesystemError::new(
            FilesystemOperation::Preview,
            FilesystemErrorKind::HardLinkOrSize,
        )
    })?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(capacity)
        .map_err(|_| FilesystemError::new(FilesystemOperation::Preview, FilesystemErrorKind::Io))?;
    file.take(maximum_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| FilesystemError::new(FilesystemOperation::Preview, FilesystemErrorKind::Io))?;
    if bytes.len() > usize::try_from(maximum_bytes).unwrap_or(usize::MAX) {
        return Err(FilesystemError::new(
            FilesystemOperation::Preview,
            FilesystemErrorKind::HardLinkOrSize,
        ));
    }
    Ok(Some(bytes))
}

fn control_parent(
    directory: &Dir,
    name: &Path,
    optional: bool,
) -> Result<Option<(Dir, OsString)>, FilesystemError> {
    let mut components = name.components().peekable();
    let mut parent = directory
        .try_clone()
        .map_err(|_| FilesystemError::new(FilesystemOperation::Preview, FilesystemErrorKind::Io))?;
    while let Some(component) = components.next() {
        let std::path::Component::Normal(value) = component else {
            return Err(FilesystemError::new(
                FilesystemOperation::Preview,
                FilesystemErrorKind::InvalidMarker,
            ));
        };
        if components.peek().is_none() {
            return Ok(Some((parent, value.to_os_string())));
        }
        parent = match parent.open_dir_nofollow(value) {
            Ok(child) => child,
            Err(error) if optional && error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(None);
            }
            Err(_) => {
                return Err(FilesystemError::new(
                    FilesystemOperation::Preview,
                    FilesystemErrorKind::InvalidMarker,
                ));
            }
        };
    }
    Err(FilesystemError::new(
        FilesystemOperation::Preview,
        FilesystemErrorKind::InvalidMarker,
    ))
}

fn hash_component(digest: &mut Sha256, label: &[u8], bytes: Option<&[u8]>) {
    digest.update((label.len() as u32).to_be_bytes());
    digest.update(label);
    match bytes {
        Some(bytes) => {
            digest.update([1]);
            digest.update((bytes.len() as u64).to_be_bytes());
            digest.update(bytes);
        }
        None => digest.update([0]),
    }
}
