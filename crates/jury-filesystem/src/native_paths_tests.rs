use super::*;

#[test]
fn platform_state_precedence_and_defaults() -> Result<(), Box<dyn std::error::Error>> {
    let home = OsStr::new("/Example Home");
    let xdg = OsStr::new("/Example Xdg");
    assert_eq!(
        resolve_platform_state_root(Some(OsStr::new("/Example Legacy")), Some(xdg), Some(home))?,
        PathBuf::from("/Example Legacy")
    );
    let expected = if cfg!(target_os = "macos") {
        "/Example Home/Library/Application Support/Jury/state/vaults"
    } else {
        "/Example Xdg/jury/vaults"
    };
    assert_eq!(
        resolve_platform_state_root(None, Some(xdg), Some(home))?,
        PathBuf::from(expected)
    );
    let fallback = if cfg!(target_os = "macos") {
        "/Example Home/Library/Application Support/Jury/state/vaults"
    } else {
        "/Example Home/.local/state/jury/vaults"
    };
    assert_eq!(
        resolve_platform_state_root(None, None, Some(home))?,
        PathBuf::from(fallback)
    );
    assert_eq!(
        resolve_platform_state_root(None, Some(OsStr::new("")), Some(home))?,
        PathBuf::from(fallback)
    );
    assert_eq!(
        resolve_platform_state_root(None, None, None),
        Err(StatePathError::MissingHome)
    );
    assert_eq!(
        resolve_platform_state_root(Some(OsStr::new("relative")), None, Some(home)),
        Err(StatePathError::NotAbsolute)
    );
    assert_eq!(
        resolve_platform_state_root(Some(OsStr::new("/Example\0Path")), None, Some(home)),
        Err(StatePathError::Nul)
    );
    assert_eq!(
        resolve_platform_state_root(Some(OsStr::new("/Example/../Other")), None, Some(home)),
        Err(StatePathError::Traversal)
    );
    assert_eq!(
        resolve_platform_state_root(None, None, Some(OsStr::new("/Example/../Other"))),
        Err(StatePathError::Traversal)
    );
    Ok(())
}

#[cfg(target_os = "macos")]
#[test]
fn invalid_macos_state_inputs_never_fall_back() {
    for invalid in ["", "relative", "/Example/../Other", "/Example\0Other"] {
        assert!(
            resolve_platform_state_root(
                Some(OsStr::new(invalid)),
                Some(OsStr::new("/Ignored")),
                Some(OsStr::new("/ExampleHome"))
            )
            .is_err()
        );
        assert!(
            resolve_platform_state_root(
                None,
                Some(OsStr::new("/Ignored")),
                Some(OsStr::new(invalid))
            )
            .is_err()
        );
    }
    assert_eq!(
        resolve_linux_state_root(Some(OsStr::new("/ExampleOverride")), None, None),
        Err(StatePathError::Unsupported)
    );
}

#[cfg(unix)]
#[test]
fn non_utf8_state_home_is_lossless() -> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::ffi::OsStringExt as _;
    let home = std::ffi::OsString::from_vec(b"/Example-\xff".to_vec());
    assert_eq!(
        resolve_platform_state_root(Some(&home), None, None)?,
        PathBuf::from(&home)
    );
    assert!(resolve_platform_state_root(None, None, Some(&home))?.starts_with(&home));
    Ok(())
}

#[test]
fn xdg_traversal_is_rejected_on_linux_and_ignored_on_macos() {
    let result = resolve_platform_state_root(
        None,
        Some(OsStr::new("/Example/../Other")),
        Some(OsStr::new("/ExampleHome")),
    );
    if cfg!(target_os = "macos") {
        assert_eq!(
            result,
            Ok(PathBuf::from(
                "/ExampleHome/Library/Application Support/Jury/state/vaults"
            ))
        );
    } else {
        assert_eq!(result, Err(StatePathError::Traversal));
    }
}

#[test]
fn interior_dot_is_preserved_by_selection() -> Result<(), Box<dyn std::error::Error>> {
    let path = OsStr::new("/Example/./State");
    // Selection is not filesystem authority. Opening the state root separately
    // enforces containment and alias checks on normalized path components.
    assert_eq!(
        resolve_platform_state_root(Some(path), None, None)?.as_os_str(),
        path
    );
    Ok(())
}
