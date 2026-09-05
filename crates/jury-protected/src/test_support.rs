use std::{
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

struct ReapedChild(Child);
impl Drop for ReapedChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Isolate irreversible resource-limit changes. Only the named test executes
/// in the child, and every exit/timeout path reaps it. No secret-bearing core
/// file is created or inspected.
pub(crate) fn in_subprocess(case: &str) -> bool {
    let name = case.strip_prefix("jury_protected::").unwrap_or(case);
    if std::env::var("JURY_PROTECTED_TEST_CASE").as_deref() == Ok(name) {
        return true;
    }
    #[cfg(unix)]
    let before = rlimit::getrlimit(rlimit::Resource::CORE);
    let executable =
        std::env::current_exe().unwrap_or_else(|_| panic!("test executable unavailable"));
    let child = Command::new(executable)
        .args(["--exact", name, "--nocapture"])
        .env("JURY_PROTECTED_TEST_CASE", name)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap_or_else(|_| panic!("test subprocess unavailable"));
    let mut child = ReapedChild(child);
    let deadline = Instant::now() + Duration::from_secs(45);
    loop {
        match child.0.try_wait() {
            Ok(Some(status)) => {
                assert!(status.success(), "isolated test failed: {name}");
                break;
            }
            Ok(None) => assert!(Instant::now() < deadline, "isolated test timed out: {name}"),
            Err(_) => panic!("isolated test wait failed"),
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    #[cfg(unix)]
    assert_eq!(
        before.ok(),
        rlimit::getrlimit(rlimit::Resource::CORE).ok(),
        "parent core limits unchanged"
    );
    false
}
