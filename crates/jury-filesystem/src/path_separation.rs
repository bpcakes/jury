use std::path::{Path, PathBuf};

use crate::capability::{FileIdentity, HardenedDir, normalized_absolute, open_absolute_dir};
use crate::{FilesystemError, FilesystemErrorKind, FilesystemOperation};

struct ResolvedPath {
    absolute: PathBuf,
    ancestor: HardenedDir,
    suffix: PathBuf,
    existing_identity: Option<FileIdentity>,
}

/// Proves that path boundaries are disjoint using retained filesystem
/// identities as well as normalized spelling. Existing bind-mount and
/// hard-link aliases are rejected; absent descendants are compared relative
/// to their deepest existing ancestor.
pub fn validate_path_separation(paths: &[&Path]) -> Result<(), FilesystemError> {
    let resolved = paths
        .iter()
        .map(|path| resolve(path))
        .collect::<Result<Vec<_>, _>>()?;
    for (index, left) in resolved.iter().enumerate() {
        for right in &resolved[index + 1..] {
            if overlaps(&left.absolute, &right.absolute) {
                return Err(separation_error(FilesystemErrorKind::Containment));
            }
            if left.existing_identity.is_some() && left.existing_identity == right.existing_identity
            {
                return Err(separation_error(FilesystemErrorKind::Alias));
            }
            if left.ancestor.identity == right.ancestor.identity
                && overlaps(&left.suffix, &right.suffix)
            {
                return Err(separation_error(FilesystemErrorKind::Alias));
            }
            if (left.suffix.as_os_str().is_empty()
                && right.ancestor.lineage.contains(&left.ancestor.identity))
                || (right.suffix.as_os_str().is_empty()
                    && left.ancestor.lineage.contains(&right.ancestor.identity))
            {
                return Err(separation_error(FilesystemErrorKind::Containment));
            }
        }
    }
    Ok(())
}

fn resolve(path: &Path) -> Result<ResolvedPath, FilesystemError> {
    let absolute = normalized_absolute(path, FilesystemOperation::Preview)?;
    let mut candidate = absolute.as_path();
    loop {
        match open_absolute_dir(candidate, FilesystemOperation::Preview) {
            Ok(ancestor) => {
                let suffix = absolute
                    .strip_prefix(candidate)
                    .map_err(|_| separation_error(FilesystemErrorKind::Traversal))?
                    .to_path_buf();
                let existing_identity = if suffix.as_os_str().is_empty() {
                    Some(ancestor.identity)
                } else if suffix.components().count() == 1 {
                    match ancestor.dir.symlink_metadata(&suffix) {
                        Ok(metadata) => Some(FileIdentity::from_metadata(&metadata)),
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
                        Err(_) => return Err(separation_error(FilesystemErrorKind::Io)),
                    }
                } else {
                    None
                };
                return Ok(ResolvedPath {
                    absolute,
                    ancestor,
                    suffix,
                    existing_identity,
                });
            }
            Err(error)
                if matches!(
                    error.kind(),
                    FilesystemErrorKind::NotFound | FilesystemErrorKind::LinkOrWrongType
                ) =>
            {
                candidate = candidate
                    .parent()
                    .ok_or_else(|| separation_error(FilesystemErrorKind::NotFound))?;
            }
            Err(error) => return Err(error),
        }
    }
}

fn overlaps(left: &Path, right: &Path) -> bool {
    left == right || left.starts_with(right) || right.starts_with(left)
}

const fn separation_error(kind: FilesystemErrorKind) -> FilesystemError {
    FilesystemError::new(FilesystemOperation::Preview, kind)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn hard_link_file_aliases_are_rejected_by_identity() -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        let real = temporary.path().join("real.backup");
        let alias = temporary.path().join("alias");
        std::fs::write(&real, b"public-test-bytes")?;
        std::fs::hard_link(&real, &alias)?;

        assert!(matches!(
            validate_path_separation(&[&real, &alias]),
            Err(error) if error.kind() == FilesystemErrorKind::Alias
        ));
        Ok(())
    }
}
