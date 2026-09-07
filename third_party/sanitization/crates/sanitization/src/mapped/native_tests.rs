//! Native-only, private test seams. No caller data or addresses leave the tests.
use super::*;
use core::ffi::c_int;
#[cfg(target_os = "linux")]
use core::ffi::c_void;
use std::{
    cell::RefCell,
    time::{Duration, Instant},
};

#[derive(Default)]
struct Observation {
    active: bool,
    failure: Option<ProtectionControl>,
    hit: bool,
    mapping: Option<(usize, usize)>,
    writable: Option<(usize, usize)>,
    maps: usize,
    unmaps: usize,
    cleared: usize,
}
std::thread_local! {
    static OBSERVATION: RefCell<Observation> = RefCell::new(Observation::default());
}

struct Probe;
impl Probe {
    fn start(failure: Option<ProtectionControl>) -> Self {
        OBSERVATION.with(|state| {
            assert!(!state.borrow().active);
            *state.borrow_mut() = Observation {
                active: true,
                failure,
                ..Observation::default()
            };
        });
        Self
    }
    fn check(&self, expected_maps: usize, expected_cleared: usize) {
        OBSERVATION.with(|state| {
            let state = state.borrow();
            assert_eq!(state.hit, state.failure.is_some(), "injection reached");
            assert_eq!(state.maps, expected_maps, "mapping count");
            assert_eq!(state.unmaps, expected_maps, "successful cleanup count");
            assert_eq!(
                state.cleared, expected_cleared,
                "zero-before-unmap observations"
            );
            assert!(state.mapping.is_none(), "no live allocation remains");
        });
    }
}
impl Drop for Probe {
    fn drop(&mut self) {
        OBSERVATION.with(|state| *state.borrow_mut() = Observation::default());
    }
}
pub(super) fn fail(control: ProtectionControl) -> bool {
    OBSERVATION.with(|state| {
        let mut state = state.borrow_mut();
        let fail = state.active && state.failure == Some(control);
        state.hit |= fail;
        fail
    })
}
pub(super) fn mapped(ptr: *mut u8, len: usize) {
    OBSERVATION.with(|state| {
        let mut state = state.borrow_mut();
        if state.active {
            assert!(state.mapping.is_none());
            state.mapping = Some((ptr as usize, len));
            state.maps += 1;
        }
    });
}
pub(super) fn writable(ptr: *mut u8, len: usize) {
    OBSERVATION.with(|state| {
        let mut state = state.borrow_mut();
        if state.active {
            state.writable = Some((ptr as usize, len));
        }
    });
}
pub(super) fn before_unmap(ptr: *mut u8) {
    OBSERVATION.with(|state| {
        let mut state = state.borrow_mut();
        if !state.active {
            return;
        }
        assert!(state.mapping.is_some_and(|(base, _)| base == ptr as usize));
        if let Some((data, len)) = state.writable {
            // SAFETY: only owning backend hooks register the still-live writable
            // region, and this observation runs immediately before its unmap.
            let bytes = unsafe { core::slice::from_raw_parts(data as *const u8, len) };
            assert!(
                bytes.iter().all(|byte| *byte == 0),
                "complete writable region cleared"
            );
            state.cleared += 1;
        }
    });
}
pub(super) fn unmapped(ptr: *mut u8, success: bool) {
    OBSERVATION.with(|state| {
        let mut state = state.borrow_mut();
        if state.active {
            assert!(state.mapping.is_some_and(|(base, _)| base == ptr as usize));
            assert!(success, "native unmap completed");
            state.mapping = None;
            state.writable = None;
            state.unmaps += 1;
        }
    });
}

pub(super) fn request(guarded: bool) -> ProtectionRequest {
    ProtectionRequest {
        memory_lock: Requirement::Required,
        dump_exclusion: if cfg!(target_os = "macos") {
            Requirement::Preferred
        } else {
            Requirement::Required
        },
        fork: ForkProtectionRequest::exclude(Requirement::Required),
        guard_pages: if guarded {
            Requirement::Required
        } else {
            Requirement::NotRequested
        },
        canary: Requirement::Required,
        cache_policy: Requirement::NotRequested,
    }
}

#[test]
fn native_guarded_required_failures_precede_fill_and_cleanup() {
    for control in [
        ProtectionControl::Canary,
        ProtectionControl::Mapping,
        ProtectionControl::GuardPages,
        ProtectionControl::ForkPolicy,
        ProtectionControl::MemoryLock,
    ] {
        let probe = Probe::start(Some(control));
        let mut filled = false;
        let result = GuardedSecretVec::try_from_capacity_with_protection(31, request(true), |_| {
            filled = true;
            Ok::<usize, ()>(31)
        });
        let Err(ProtectedSecretFillError::Protection(error)) = result else {
            panic!("expected owning-layer failure");
        };
        assert_eq!(error.failure.control, control, "actual failure stage");
        assert!(!filled);
        let has_map = !matches!(
            control,
            ProtectionControl::Canary | ProtectionControl::Mapping
        );
        assert_eq!(
            error.rollback.unmap,
            if has_map {
                RollbackState::Completed
            } else {
                RollbackState::NotNeeded
            }
        );
        assert_eq!(error.rollback.unlock, RollbackState::NotNeeded);
        probe.check(
            usize::from(has_map),
            usize::from(has_map && control != ProtectionControl::GuardPages),
        );
    }
}

#[test]
fn native_locked_required_failures_precede_fill_and_cleanup() {
    for control in [
        ProtectionControl::Canary,
        ProtectionControl::Mapping,
        ProtectionControl::ForkPolicy,
        ProtectionControl::MemoryLock,
    ] {
        let probe = Probe::start(Some(control));
        let mut filled = false;
        let result = LockedSecretVec::try_from_capacity_with_protection(31, request(false), |_| {
            filled = true;
            Ok::<usize, ()>(31)
        });
        let Err(ProtectedSecretFillError::Protection(error)) = result else {
            panic!("expected owning-layer failure");
        };
        assert_eq!(error.failure.control, control);
        assert!(!filled);
        let has_map = !matches!(
            control,
            ProtectionControl::Canary | ProtectionControl::Mapping
        );
        assert_eq!(
            error.rollback.unmap,
            if has_map {
                RollbackState::Completed
            } else {
                RollbackState::NotNeeded
            }
        );
        probe.check(usize::from(has_map), usize::from(has_map));
    }
}

#[test]
fn native_partial_fill_and_invalid_length_clear_before_unmap() {
    for guarded in [true, false] {
        for invalid_length in [false, true] {
            let probe = Probe::start(None);
            let mut filled = false;
            let fill = |bytes: &mut [u8]| {
                filled = true;
                bytes[..3].fill(0xa5);
                if invalid_length {
                    Ok(bytes.len() + 1)
                } else {
                    Err(())
                }
            };
            let result = if guarded {
                GuardedSecretVec::try_from_capacity_with_protection(31, request(true), fill)
                    .map(drop)
            } else {
                LockedSecretVec::try_from_capacity_with_protection(31, request(false), fill)
                    .map(drop)
            };
            assert!(filled);
            if invalid_length {
                assert!(matches!(result, Err(ProtectedSecretFillError::Length(_))));
            } else {
                assert!(matches!(result, Err(ProtectedSecretFillError::Fill(()))));
            }
            probe.check(1, 1);
        }
    }
}

#[test]
fn native_success_status_and_drop_clear_complete_mapping() {
    for guarded in [true, false] {
        let probe = Probe::start(None);
        let fill = |bytes: &mut [u8]| {
            bytes.fill(0xa5);
            Ok::<usize, ()>(bytes.len())
        };
        let report = if guarded {
            let owner =
                GuardedSecretVec::try_from_capacity_with_protection(31, request(true), fill)
                    .expect("guarded owner");
            *owner.protection_report()
        } else {
            let owner =
                LockedSecretVec::try_from_capacity_with_protection(31, request(false), fill)
                    .expect("locked owner");
            *owner.protection_report()
        };
        // Provider satisfies() deliberately includes preferred controls;
        // Darwin must remain truthfully degraded at the mapping-only layer.
        assert_eq!(
            report.satisfies(request(guarded)),
            !cfg!(target_os = "macos")
        );
        assert_eq!(report.mapping, ProtectionState::Established);
        assert_eq!(report.memory_lock, ProtectionState::Established);
        assert_eq!(report.canary, ProtectionState::Established);
        if guarded {
            assert_eq!(report.guard_pages, ProtectionState::Established);
        }
        assert_eq!(report.fork.policy, ForkPolicy::Exclude);
        assert_eq!(report.fork.state, ProtectionState::Established);
        assert_eq!(
            report.dump_exclusion,
            if cfg!(target_os = "macos") {
                ProtectionState::Unsupported
            } else {
                ProtectionState::Established
            }
        );
        assert!(report.locked_bytes >= 31);
        assert_eq!(report.locked_bytes % report.page_granule, 0);
        probe.check(1, 1);
    }
}

unsafe extern "C" {
    fn fork() -> c_int;
    fn waitpid(pid: c_int, status: *mut c_int, options: c_int) -> c_int;
    fn kill(pid: c_int, signal: c_int) -> c_int;
    fn _exit(status: c_int) -> !;
    fn getpagesize() -> c_int;
    #[cfg(target_os = "linux")]
    fn mincore(addr: *mut c_void, len: usize, vec: *mut u8) -> c_int;
    #[cfg_attr(target_os = "macos", link_name = "__error")]
    #[cfg_attr(target_os = "linux", link_name = "__errno_location")]
    fn errno_location() -> *mut c_int;
}

#[cfg(target_os = "macos")]
unsafe extern "C" {
    static mach_task_self_: u32;
    fn mach_vm_region(
        task: u32,
        address: *mut u64,
        size: *mut u64,
        flavor: c_int,
        info: *mut c_int,
        count: *mut u32,
        object: *mut u32,
    ) -> c_int;
    fn mach_port_deallocate(task: u32, name: u32) -> c_int;
}

#[cfg(target_os = "macos")]
fn range_absent(ptr: *mut u8, len: usize, _page: usize) -> bool {
    let mut address = ptr as u64;
    let mut size = 0u64;
    // SDK vm_region.h: VM_REGION_BASIC_INFO_64 = 9. Supply more than
    // VM_REGION_BASIC_INFO_COUNT_64 integer slots; only address is inspected.
    let mut info = [0; 64];
    let mut count = info.len() as u32;
    let mut object = 0;
    // SAFETY: SDK-sized scalar arguments and writable stack output storage.
    // mach_vm_region returns the containing region or the next region.
    let result = unsafe {
        mach_vm_region(
            mach_task_self_,
            &mut address,
            &mut size,
            9,
            info.as_mut_ptr(),
            &mut count,
            &mut object,
        )
    };
    if object != 0 {
        unsafe {
            mach_port_deallocate(mach_task_self_, object);
        }
    }
    result == 1 || (result == 0 && address >= (ptr as u64) + len as u64)
}

#[cfg(target_os = "linux")]
fn range_absent(ptr: *mut u8, len: usize, page: usize) -> bool {
    let mut absent = true;
    for offset in (0..len).step_by(page) {
        let mut residency = 0u8;
        // SAFETY: mincore queries VM metadata without dereferencing addr;
        // one byte is sufficient for exactly one page on Linux.
        let result = unsafe { mincore(ptr.wrapping_add(offset).cast(), page, &mut residency) };
        absent &= result == -1 && unsafe { *errno_location() } == 12; // ENOMEM
    }
    absent
}

/// Query the exact original data range, without reading payload bytes. Darwin
/// uses Mach VM regions (mincore reports residency even for holes); Linux uses
/// per-page mincore ENOMEM. Child returns only a bounded exit status.
pub(super) fn range_absent_after_fork(ptr: *mut u8, len: usize) -> bool {
    // SAFETY: getpagesize has no pointer arguments or preconditions.
    let page = unsafe { getpagesize() };
    assert!(page > 0);
    let page = page as usize;
    assert_eq!(ptr as usize % page, 0);
    assert_eq!(len % page, 0);
    // SAFETY: the child calls only native operations and _exit. Parent retains
    // the mapping owner until the child is reaped, including timeout/error paths.
    let pid = unsafe { fork() };
    assert!(pid >= 0, "native fork failed");
    if pid == 0 {
        let absent = range_absent(ptr, len, page);
        unsafe { _exit(if absent { 0 } else { 1 }) }
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let mut status = 0;
        let result = unsafe { waitpid(pid, &mut status, 1) }; // WNOHANG
        if result == pid {
            return status == 0;
        }
        if result == -1 && unsafe { *errno_location() } != 4 {
            // EINTR
            // A surprising wait error is never accepted as exclusion proof.
            unsafe {
                kill(pid, 9);
            }
            while unsafe { waitpid(pid, &mut status, 0) } == -1 && unsafe { *errno_location() } == 4
            {
            }
            panic!("native child wait failed");
        }
        if Instant::now() >= deadline {
            unsafe {
                kill(pid, 9);
            }
            while unsafe { waitpid(pid, &mut status, 0) } == -1 && unsafe { *errno_location() } == 4
            {
            }
            panic!("native child timed out and was reaped");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn native_fork_oracle_rejects_a_present_zero_mapping() {
    let mut inherited = request(true);
    inherited.fork = ForkProtectionRequest {
        policy: ForkPolicy::Inherit,
        requirement: Requirement::Required,
    };
    let owner = GuardedSecretVec::try_from_capacity_with_protection(31, inherited, |bytes| {
        bytes.fill(0);
        Ok::<usize, ()>(bytes.len())
    })
    .expect("inherited owner");
    owner
        .try_with_secret(|bytes| {
            // Align only within this live mapping for the oracle's control page.
            let page = unsafe { getpagesize() } as usize;
            let start = (bytes.as_ptr() as usize / page * page) as *mut u8;
            assert!(!range_absent_after_fork(start, page));
        })
        .expect("integrity");
}

#[test]
fn native_preferred_control_failures_remain_visible_after_fill() {
    for control in [ProtectionControl::MemoryLock, ProtectionControl::ForkPolicy] {
        let probe = Probe::start(Some(control));
        let mut policy = request(true);
        policy.memory_lock = Requirement::Preferred;
        policy.fork.requirement = Requirement::Preferred;
        let mut calls = 0;
        let owner = GuardedSecretVec::try_from_capacity_with_protection(31, policy, |bytes| {
            calls += 1;
            bytes.fill(0xa5);
            Ok::<usize, ()>(bytes.len())
        })
        .expect("explicit preferred failure returns guarded owner");
        let report = owner.protection_report();
        let state = if control == ProtectionControl::MemoryLock {
            report.memory_lock
        } else {
            report.fork.state
        };
        assert!(matches!(state, ProtectionState::Failed { .. }));
        assert_eq!(report.guard_pages, ProtectionState::Established);
        assert_eq!(report.canary, ProtectionState::Established);
        assert_eq!(calls, 1);
        drop(owner);
        probe.check(1, 1);
    }
}

#[test]
fn native_compact_and_large_boundary_accounting() {
    // Denominator: four sequential guarded strict-policy allocations per native
    // lane, straddling Jury's 1 MiB compact and 16 MiB large public boundaries.
    // Countermetric: refusals; this is behavior/cleanup evidence, not an SLO.
    for requested in [
        1024 * 1024,
        1024 * 1024 + 1,
        16 * 1024 * 1024,
        16 * 1024 * 1024 + 1,
    ] {
        let probe = Probe::start(None);
        let mut called = false;
        let result = GuardedSecretVec::try_from_capacity_with_protection(
            requested,
            request(true),
            |bytes| {
                called = true;
                bytes.fill(0xa5);
                Ok::<usize, ()>(bytes.len())
            },
        );
        let (outcome, report) = match result {
            Ok(owner) => {
                assert!(called);
                let report = *owner.protection_report();
                assert_eq!(
                    report.locked_bytes,
                    report.mapped_bytes - 2 * report.page_granule
                );
                drop(owner);
                ("accepted", report)
            }
            Err(ProtectedSecretFillError::Protection(error)) => {
                assert!(!called);
                assert_eq!(
                    error.failure.control,
                    ProtectionControl::MemoryLock,
                    "only native lock budget may refuse this case"
                );
                assert_eq!(error.rollback.unmap, RollbackState::Completed);
                ("refused", error.partial_report)
            }
            Err(_) => panic!("unexpected boundary construction failure"),
        };
        probe.check(1, 1);
        std::println!("M01_PROVIDER_BOUNDARY requested={} mapped={} locked={} page_granule={} outcome={} cleanup=completed", requested, report.mapped_bytes, report.locked_bytes, report.page_granule, outcome);
    }
}

#[cfg(target_os = "linux")]
#[test]
fn native_zero_lock_budget_refuses_before_fill() {
    use std::process::{Command, Stdio};
    const CASE: &str = "mapped::native_tests::native_zero_lock_budget_refuses_before_fill";
    if std::env::var("SANITIZATION_LOCK_TEST_CHILD").as_deref() != Ok("1") {
        let mut child = Command::new(std::env::current_exe().expect("test executable"))
            .args(["--exact", CASE, "--nocapture"])
            .env("SANITIZATION_LOCK_TEST_CHILD", "1")
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("lock-budget subprocess");
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    assert!(status.success());
                    return;
                }
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(10))
                }
                _ => {
                    let _ = child.kill();
                    let _ = child.wait();
                    panic!("lock-budget subprocess failed or timed out");
                }
            }
        }
    }
    unsafe extern "C" {
        fn setrlimit(resource: c_int, limits: *const u64) -> c_int;
    }
    // Linux x86_64/aarch64 SDK ABI: two unsigned-long limits, RLIMIT_MEMLOCK=8.
    // SAFETY: limits points to both initialized fields; only this child is changed.
    assert_eq!(unsafe { setrlimit(8, [0u64, 0].as_ptr()) }, 0);
    for guarded in [true, false] {
        let probe = Probe::start(None);
        let mut called = false;
        let fill = |_: &mut [u8]| {
            called = true;
            Ok::<usize, ()>(1)
        };
        let result = if guarded {
            GuardedSecretVec::try_from_capacity_with_protection(31, request(true), fill).map(drop)
        } else {
            LockedSecretVec::try_from_capacity_with_protection(31, request(false), fill).map(drop)
        };
        let Err(ProtectedSecretFillError::Protection(error)) = result else {
            panic!("expected native lock refusal");
        };
        assert_eq!(error.failure.control, ProtectionControl::MemoryLock);
        assert_eq!(error.rollback.unmap, RollbackState::Completed);
        assert!(!called);
        probe.check(1, 1);
    }
}
