use super::*;
use crate::{ProtectedMemory, test_support::in_subprocess};
use std::cell::{Cell, RefCell};

#[derive(Clone, Copy)]
pub(crate) enum CoreFailure {
    Set,
    Read,
    SoftNonzero,
    HardNonzero,
}
thread_local! {
    static FAILURE: Cell<Option<CoreFailure>> = const { Cell::new(None) };
}
struct ResetFailure;
impl Drop for ResetFailure {
    fn drop(&mut self) {
        FAILURE.set(None);
    }
}
pub(crate) fn with_failure<T>(failure: CoreFailure, run: impl FnOnce() -> T) -> T {
    FAILURE.set(Some(failure));
    let _reset = ResetFailure;
    run()
}
pub(super) fn before_set() -> Result<(), CaptureError> {
    if matches!(FAILURE.get(), Some(CoreFailure::Set)) {
        Err(suppression_error())
    } else {
        Ok(())
    }
}
pub(super) fn read_override() -> Option<Result<(u64, u64), CaptureError>> {
    match FAILURE.get() {
        Some(CoreFailure::Read) => Some(Err(suppression_error())),
        Some(CoreFailure::SoftNonzero) => Some(Ok((1, 0))),
        Some(CoreFailure::HardNonzero) => Some(Ok((0, 1))),
        _ => None,
    }
}

struct FakeLimits<'a> {
    set: Result<(), CaptureError>,
    read: Result<(u64, u64), CaptureError>,
    calls: &'a RefCell<Vec<&'static str>>,
}
impl CoreLimits for FakeLimits<'_> {
    fn set_zero(&mut self) -> Result<(), CaptureError> {
        self.calls.borrow_mut().push("set");
        self.set
    }
    fn read(&mut self) -> Result<(u64, u64), CaptureError> {
        self.calls.borrow_mut().push("read");
        self.read
    }
}
fn status() -> ProtectionStatus {
    ProtectedMemory::initialize(31, ProtectionPolicy::EmergencyAllowDegraded, |bytes| {
        Ok::<usize, ()>(bytes.len())
    })
    .unwrap_or_else(|_| panic!("guarded test owner unavailable"))
    .status()
    .clone()
}

#[test]
fn suppression_requires_set_and_exact_readback_before_capture() {
    for (set, read, captured, calls_expected) in [
        (Ok(()), Ok((0, 0)), true, vec!["set", "read", "capture"]),
        (Err(suppression_error()), Ok((0, 0)), false, vec!["set"]),
        (Ok(()), Err(suppression_error()), false, vec!["set", "read"]),
        (Ok(()), Ok((1, 0)), false, vec!["set", "read"]),
        (Ok(()), Ok((0, 1)), false, vec!["set", "read"]),
    ] {
        let calls = RefCell::new(Vec::new());
        let result = capture_with(
            &mut FakeLimits {
                set,
                read,
                calls: &calls,
            },
            ProtectionPolicy::Strict,
            status(),
            || calls.borrow_mut().push("capture"),
        );
        assert_eq!(result.is_ok(), captured);
        assert_eq!(*calls.borrow(), calls_expected);
        if let Err(error) = result {
            assert_eq!(error.kind(), CaptureErrorKind::CoreSuppression);
            assert_eq!(error.to_string(), "process core-dump suppression failed");
        }
    }
}

#[test]
fn native_core_suppression_is_verified_before_capture() -> Result<(), Box<dyn std::error::Error>> {
    if !in_subprocess(concat!(
        module_path!(),
        "::native_core_suppression_is_verified_before_capture"
    )) {
        return Ok(());
    }
    let capture = capture_after_process_protection(ProtectionPolicy::Strict, status(), || {
        rlimit::getrlimit(rlimit::Resource::CORE)
    })?;
    assert_eq!(capture.value?, (0, 0));
    assert!(capture.status.core_dump_suppressed());
    assert!(!capture.status.is_degraded());
    Ok(())
}

#[test]
fn native_readback_observation_never_invents_suppression() {
    if !in_subprocess(concat!(
        module_path!(),
        "::native_readback_observation_never_invents_suppression"
    )) {
        return;
    }
    suppress_with(&mut PlatformCoreLimits).unwrap_or_else(|_| panic!("native suppression failed"));
    assert!(core_dump_suppressed());
    for failure in [
        CoreFailure::Read,
        CoreFailure::SoftNonzero,
        CoreFailure::HardNonzero,
    ] {
        with_failure(failure, || {
            assert!(!core_dump_suppressed());
            let memory = ProtectedMemory::initialize(
                31,
                ProtectionPolicy::EmergencyAllowDegraded,
                |bytes| Ok::<usize, ()>(bytes.len()),
            )
            .unwrap_or_else(|_| panic!("guarded owner"));
            assert!(!memory.status().core_dump_suppressed());
            assert!(memory.status().is_degraded());
        });
    }
}

#[test]
fn native_set_failure_prevents_capture() {
    if !in_subprocess(concat!(
        module_path!(),
        "::native_set_failure_prevents_capture"
    )) {
        return;
    }
    let mut called = false;
    with_failure(CoreFailure::Set, || {
        let result =
            capture_after_process_protection(ProtectionPolicy::Strict, status(), || called = true);
        assert!(matches!(result, Err(error) if error.kind() == CaptureErrorKind::CoreSuppression));
    });
    assert!(!called);
}
