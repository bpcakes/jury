use std::fs;

use super::*;

#[test]
fn precedence_is_explicit_global_environment_repository_default()
-> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let repository = root.path().join("repository");
    fs::create_dir_all(repository.join(".git"))?;
    fs::write(
        repository.join(".git").join("HEAD"),
        [b"ref: refs".as_slice(), b"/heads/main\n"].concat(),
    )?;
    let nested = repository.join("nested");
    fs::create_dir(&nested)?;
    let explicit = root.path().join("explicit");
    let environment = root.path().join("environment");
    let xdg = root.path().join("xdg");

    let selected = resolve_vault_home(
        &nested,
        Some(explicit.clone()),
        false,
        Some(environment.as_os_str()),
        Some(xdg.as_os_str()),
        Some(root.path().as_os_str()),
    )?;
    assert_eq!(selected.source(), HomeSource::Explicit);
    assert_eq!(selected.detached_path(), Some(explicit.as_path()));
    assert!(matches!(
        resolve_vault_home(
            &nested,
            Some(explicit),
            true,
            None,
            Some(xdg.as_os_str()),
            Some(root.path().as_os_str()),
        ),
        Err(HomeSelectionError::Ambiguous)
    ));

    let selected = resolve_vault_home(
        &nested,
        None,
        true,
        Some(environment.as_os_str()),
        Some(xdg.as_os_str()),
        Some(root.path().as_os_str()),
    )?;
    assert_eq!(selected.source(), HomeSource::GlobalFlag);
    let expected_global = if cfg!(target_os = "macos") {
        root.path()
            .join("Library/Application Support/Jury/vaults/default")
    } else {
        xdg.join("jury/vaults/default")
    };
    assert_eq!(selected.detached_path(), Some(expected_global.as_path()));

    let selected = resolve_vault_home(
        &nested,
        None,
        false,
        Some(environment.as_os_str()),
        Some(xdg.as_os_str()),
        Some(root.path().as_os_str()),
    )?;
    assert_eq!(selected.source(), HomeSource::Environment);
    assert_eq!(selected.detached_path(), Some(environment.as_path()));
    let selected = resolve_vault_home(
        &nested,
        None,
        false,
        None,
        Some(xdg.as_os_str()),
        Some(root.path().as_os_str()),
    )?;
    assert_eq!(selected.source(), HomeSource::Repository);

    let selected = resolve_vault_home(
        Path::new("/"),
        None,
        false,
        None,
        Some(xdg.as_os_str()),
        Some(root.path().as_os_str()),
    )?;
    assert_eq!(selected.source(), HomeSource::PlatformDefault);
    assert_eq!(selected.detached_path(), Some(expected_global.as_path()));
    Ok(())
}

#[test]
fn relative_and_parent_paths_fail_without_disclosing_them() {
    for path in [PathBuf::from("relative"), PathBuf::from("/tmp/../escape")] {
        let error = resolve_vault_home(
            Path::new("/tmp"),
            Some(path),
            false,
            None,
            None,
            Some(OsStr::new("/tmp")),
        )
        .err();
        assert_eq!(error, Some(HomeSelectionError::InvalidPath));
    }
}

#[test]
fn native_roots_are_exact_and_do_not_touch_disk() -> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let home = root.path().join("Example Home");
    let xdg = root.path().join("Example XDG");
    let base = if cfg!(target_os = "macos") {
        home.join("Library/Application Support/Jury")
    } else {
        xdg.join("jury")
    };
    assert_eq!(
        resolve_identity_root(None, Some(xdg.as_os_str()), Some(home.as_os_str()))?,
        base.join("identities")
    );
    for global in [false, true] {
        let selected = resolve_vault_home(
            Path::new("/"),
            None,
            global,
            Some(OsStr::new("")),
            Some(xdg.as_os_str()),
            Some(home.as_os_str()),
        )?;
        assert_eq!(
            selected.detached_path(),
            Some(base.join("vaults/default").as_path())
        );
    }
    let fallback = if cfg!(target_os = "macos") {
        home.join("Library/Application Support/Jury")
    } else {
        home.join(".local/share/jury")
    };
    assert_eq!(
        resolve_identity_root(None, None, Some(home.as_os_str()))?,
        fallback.join("identities")
    );
    assert_eq!(
        resolve_identity_root(None, Some(OsStr::new("")), Some(home.as_os_str()))?,
        fallback.join("identities")
    );
    let legacy = root.path().join(".local/share/jury/identities");
    assert_eq!(
        resolve_identity_root(Some(legacy.as_os_str()), None, None)?,
        legacy
    );
    assert_eq!(fs::read_dir(root.path())?.count(), 0);
    Ok(())
}

#[test]
fn invalid_overrides_never_fall_back() {
    for invalid in ["relative", "/Example/../Other", "/Example\0Other"] {
        assert_eq!(
            resolve_identity_root(
                Some(OsStr::new(invalid)),
                None,
                Some(OsStr::new("/ExampleHome"))
            ),
            Err(HomeSelectionError::InvalidPath)
        );
        for explicit in [true, false] {
            assert!(matches!(
                resolve_vault_home(
                    Path::new("/"),
                    explicit.then(|| PathBuf::from(invalid)),
                    false,
                    (!explicit).then(|| OsStr::new(invalid)),
                    None,
                    Some(OsStr::new("/ExampleHome"))
                ),
                Err(HomeSelectionError::InvalidPath)
            ));
        }
    }
    assert!(matches!(
        resolve_vault_home(
            Path::new("/"),
            Some(PathBuf::new()),
            false,
            None,
            None,
            None
        ),
        Err(HomeSelectionError::InvalidPath)
    ));
    assert_eq!(
        resolve_identity_root(None, None, None),
        Err(HomeSelectionError::MissingUserHome)
    );
}

#[cfg(target_os = "macos")]
#[test]
fn macos_rejects_empty_identity_override_and_invalid_home() {
    assert_eq!(
        resolve_identity_root(Some(OsStr::new("")), None, Some(OsStr::new("/ExampleHome"))),
        Err(HomeSelectionError::InvalidPath)
    );
    for invalid in ["relative", "/Example/../Other", "/Example\0Other"] {
        assert_eq!(
            resolve_identity_root(
                None,
                Some(OsStr::new("/Ignored")),
                Some(OsStr::new(invalid))
            ),
            Err(HomeSelectionError::InvalidPath)
        );
    }
    assert_eq!(
        resolve_identity_root(None, None, Some(OsStr::new(""))),
        Err(HomeSelectionError::MissingUserHome)
    );
}

#[cfg(unix)]
#[test]
fn os_path_bytes_are_preserved() -> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::ffi::OsStringExt as _;
    let home = std::ffi::OsString::from_vec(b"/Example Home-\xff".to_vec());
    let identity = resolve_identity_root(None, None, Some(&home))?;
    assert!(identity.starts_with(Path::new(&home)));
    let selected = resolve_vault_home(
        Path::new("/"),
        Some(PathBuf::from(&home)),
        false,
        None,
        None,
        None,
    )?;
    assert_eq!(selected.detached_path(), Some(Path::new(&home)));
    Ok(())
}

#[test]
fn linked_worktree_precedes_default_without_creating_vault()
-> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let root = fs::canonicalize(root.path())?;
    let repository = root.join("repository");
    let linked = root.join("linked");
    assert!(
        git(&root)
            .args(["init", "--quiet"])
            .arg(&repository)
            .status()?
            .success()
    );
    assert!(
        git(&root)
            .arg("-C")
            .arg(&repository)
            .args([
                "-c",
                "user.name=ExamplePrincipal",
                "-c",
                "user.email=example@example.invalid",
                "commit",
                "--quiet",
                "--allow-empty",
                "-m",
                "Example initial commit"
            ])
            .status()?
            .success()
    );
    assert!(
        git(&root)
            .arg("-C")
            .arg(&repository)
            .args(["worktree", "add", "--quiet", "-b", "example-linked"])
            .arg(&linked)
            .status()?
            .success()
    );
    let selected = resolve_vault_home(&linked, None, false, None, None, Some(root.as_os_str()))?;
    assert_eq!(selected.source(), HomeSource::Repository);
    assert!(!linked.join(".jury").exists());
    assert!(!root.join("Library").exists());
    Ok(())
}

fn git(home: &Path) -> std::process::Command {
    let mut command = std::process::Command::new("git");
    command
        .env_clear()
        .env("HOME", home)
        .env("GIT_CONFIG_NOSYSTEM", "1");
    command
}
