use std::{
    ffi::OsStr,
    path::PathBuf,
    process::{Child, Command, ExitCode, Stdio, Termination},
    time::{Duration, Instant},
};

const CASE_ENV: &str = "JURY_PROTECTED_TEST_CASE";
const COMPLETION_ENV: &str = "JURY_PROTECTED_TEST_COMPLETION";

// Derive the libtest filter from the declared identifier. The body belongs to
// the child; callers cannot accidentally continue it in the parent.
macro_rules! isolated_test {
    ($(#[$attribute:meta])* fn $name:ident() $(-> $result:ty)? $body:block) => {
        $(#[$attribute])*
        #[test]
        fn $name() {
            $crate::test_support::run_isolated(
                concat!(module_path!(), "::", stringify!($name)),
                || $(-> $result)? { $body },
            );
        }
    };
}
pub(crate) use isolated_test;

struct ReapedChild(Child);
impl Drop for ReapedChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn test_name(case: &str) -> &str {
    case.split_once("::").map_or(case, |(_, name)| name)
}

fn is_child(name: &str) -> bool {
    child_completion(name).is_some()
}

fn child_completion(name: &str) -> Option<PathBuf> {
    matching_completion(
        name,
        std::env::var(CASE_ENV).ok().as_deref(),
        std::env::var_os(COMPLETION_ENV).as_deref(),
    )
}

fn pending_record(name: &str) -> String {
    format!("pending:{name}")
}

fn matching_completion(
    name: &str,
    case: Option<&str>,
    completion: Option<&OsStr>,
) -> Option<PathBuf> {
    if case != Some(name) {
        return None;
    }
    let path = PathBuf::from(completion?);
    // The private temporary path is unique per invocation. Validate its pending
    // record before any body runs; a lone or stale inherited marker is not a child.
    (std::fs::read(&path).ok()?.as_slice() == pending_record(name).as_bytes()).then_some(path)
}

/// Success requires both a successful child and completion of the named body.
/// The temporary acknowledgement contains only the public test name and is
/// removed after the child is reaped, including on errors and timeouts.
pub(crate) fn run_isolated<T: Termination>(case: &str, body: impl FnOnce() -> T) {
    let name = test_name(case);
    if let Some(completion) = child_completion(name) {
        assert_eq!(body().report(), ExitCode::SUCCESS, "isolated body failed");
        assert!(
            std::fs::write(completion, name).is_ok(),
            "test completion acknowledgement failed"
        );
    } else {
        assert_eq!(
            run_child(name, Duration::from_secs(45)),
            Ok(()),
            "isolated test failed: {name}"
        );
    }
}

#[derive(Debug, PartialEq)]
enum IsolationError {
    Io,
    ChildFailed,
    MissingCompletion,
    Timeout,
}

fn run_child(name: &str, timeout: Duration) -> Result<(), IsolationError> {
    #[cfg(unix)]
    let before = rlimit::getrlimit(rlimit::Resource::CORE).map_err(|_| IsolationError::Io)?;
    let directory = tempfile::tempdir().map_err(|_| IsolationError::Io)?;
    let completion = directory.path().join("completion");
    std::fs::write(&completion, pending_record(name)).map_err(|_| IsolationError::Io)?;
    let executable = std::env::current_exe().map_err(|_| IsolationError::Io)?;
    let child = Command::new(executable)
        .args(["--exact", name, "--nocapture"])
        .env(CASE_ENV, name)
        .env(COMPLETION_ENV, &completion)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|_| IsolationError::Io)?;
    let mut child = ReapedChild(child);
    let deadline = Instant::now() + timeout;
    loop {
        match child.0.try_wait().map_err(|_| IsolationError::Io)? {
            Some(status) if !status.success() => return Err(IsolationError::ChildFailed),
            Some(_) => break,
            None if Instant::now() >= deadline => {
                let _ = child.0.kill();
                child.0.wait().map_err(|_| IsolationError::Io)?;
                return Err(IsolationError::Timeout);
            }
            None => std::thread::sleep(Duration::from_millis(10)),
        }
    }
    if std::fs::read(&completion).ok().as_deref() != Some(name.as_bytes()) {
        return Err(IsolationError::MissingCompletion);
    }
    #[cfg(unix)]
    assert_eq!(
        before,
        rlimit::getrlimit(rlimit::Resource::CORE).map_err(|_| IsolationError::Io)?,
        "parent core limits unchanged"
    );
    Ok(())
}

#[test]
fn child_dispatch_requires_a_matching_pending_invocation() -> std::io::Result<()> {
    let name = "ExampleCase";
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("completion");
    assert_eq!(matching_completion(name, Some(name), None), None);
    assert_eq!(
        matching_completion(name, Some(name), Some(path.as_os_str())),
        None
    );
    std::fs::write(&path, pending_record(name))?;
    assert_eq!(
        matching_completion(name, None, Some(path.as_os_str())),
        None
    );
    assert_eq!(
        matching_completion(name, Some("ExampleOther"), Some(path.as_os_str())),
        None
    );
    assert_eq!(
        matching_completion(name, Some(name), Some(path.as_os_str())),
        Some(path.clone())
    );
    std::fs::write(&path, name)?;
    assert_eq!(
        matching_completion(name, Some(name), Some(path.as_os_str())),
        None
    );
    Ok(())
}

isolated_test! {
    fn named_body_runs_in_child() {
        assert!(is_child(test_name(concat!(module_path!(), "::named_body_runs_in_child"))));
    }
}

#[test]
fn unknown_test_filter_is_rejected() {
    assert_eq!(
        run_child("ExampleNonexistentTest", Duration::from_secs(5)),
        Err(IsolationError::MissingCompletion)
    );
}

#[test]
fn successful_child_without_completion_is_rejected() {
    let name = test_name(concat!(
        module_path!(),
        "::successful_child_without_completion_is_rejected"
    ));
    if !is_child(name) {
        assert_eq!(
            run_child(name, Duration::from_secs(5)),
            Err(IsolationError::MissingCompletion)
        );
    }
}

#[test]
fn failed_child_is_rejected() {
    let name = test_name(concat!(module_path!(), "::failed_child_is_rejected"));
    if is_child(name) {
        std::process::exit(17);
    }
    assert_eq!(
        run_child(name, Duration::from_secs(5)),
        Err(IsolationError::ChildFailed)
    );
}

#[test]
fn timed_out_child_is_reaped() {
    let name = test_name(concat!(module_path!(), "::timed_out_child_is_reaped"));
    if is_child(name) {
        std::thread::sleep(Duration::from_secs(10));
    } else {
        assert_eq!(
            run_child(name, Duration::from_millis(100)),
            Err(IsolationError::Timeout)
        );
    }
}
