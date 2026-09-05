use std::path::{Component, Path};

#[derive(Debug)]
pub(super) struct InvalidOutputPath;

/// Produces the path bytes bound into a witnessed action. This is a naming
/// operation; publication still requires its own filesystem capability checks.
pub(super) fn normalize(path: &Path) -> Result<Vec<u8>, InvalidOutputPath> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(InvalidOutputPath);
    }
    let parent = std::fs::canonicalize(path.parent().ok_or(InvalidOutputPath)?)
        .map_err(|_| InvalidOutputPath)?;
    let normalized = parent.join(path.file_name().ok_or(InvalidOutputPath)?);
    normalized
        .to_str()
        .map(str::as_bytes)
        .map(<[u8]>::to_vec)
        .ok_or(InvalidOutputPath)
}

#[cfg(all(test, unix))]
mod tests {
    use std::{
        ffi::OsString,
        os::unix::{ffi::OsStringExt, fs::symlink},
    };

    use super::*;

    #[test]
    fn manifest_path_resolves_parent_but_preserves_the_leaf()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let parent = directory.path().join("ExampleOutput");
        std::fs::create_dir(&parent)?;
        let alias = directory.path().join("ExampleAlias");
        symlink(&parent, &alias)?;
        let expected = std::fs::canonicalize(&parent)?.join("ExampleSecret");
        assert_eq!(
            normalize(&alias.join("ExampleSecret")).map_err(|_| "valid output rejected")?,
            expected.as_os_str().as_encoded_bytes()
        );
        // Resolving the destination itself would change what the approver sees.
        symlink("ExampleOther", parent.join("ExampleSecret"))?;
        assert_eq!(
            normalize(&alias.join("ExampleSecret")).map_err(|_| "valid output rejected")?,
            expected.as_os_str().as_encoded_bytes()
        );
        Ok(())
    }

    #[test]
    fn invalid_manifest_paths_are_rejected() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        for path in [
            std::path::PathBuf::from("ExampleSecret"),
            std::path::PathBuf::from("/"),
            directory.path().join("../ExampleSecret"),
            directory.path().join("missing/ExampleSecret"),
            directory.path().join(OsString::from_vec(vec![0xff])),
        ] {
            assert!(normalize(&path).is_err());
        }
        Ok(())
    }
}
