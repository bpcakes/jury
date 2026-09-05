use super::*;

#[test]
fn strict_memory_is_guarded_locked_dump_excluded_and_fork_excluded() -> Result<(), MemoryError> {
    if !crate::test_support::in_subprocess(concat!(
        module_path!(),
        "::strict_memory_is_guarded_locked_dump_excluded_and_fork_excluded"
    )) {
        return Ok(());
    }

    let memory = ProtectedMemory::initialize(31, ProtectionPolicy::Strict, |bytes| {
        bytes.fill(0xa5);
        Ok::<usize, ()>(bytes.len())
    })?;
    let status = memory.status();
    assert_eq!(memory.capacity(), 31);
    assert_eq!(memory.len(), 31);
    assert!(status.mapped_bytes() >= 31);
    assert!(status.page_granule() > 0);
    assert_eq!(status.memory_lock(), RuntimeControlStatus::Established);
    assert_eq!(
        status.dump_exclusion(),
        if cfg!(target_os = "macos") {
            RuntimeControlStatus::Unsupported
        } else {
            RuntimeControlStatus::Established
        }
    );
    assert_eq!(status.fork_exclusion(), RuntimeControlStatus::Established);
    assert_eq!(status.guard_pages(), RuntimeControlStatus::Established);
    assert_eq!(status.canary(), RuntimeControlStatus::Established);
    Ok(())
}

#[test]
fn initializer_writes_directly_and_invalid_lengths_return_no_owner() {
    if !crate::test_support::in_subprocess(concat!(
        module_path!(),
        "::initializer_writes_directly_and_invalid_lengths_return_no_owner"
    )) {
        return;
    }

    let error = ProtectedMemory::initialize(8, ProtectionPolicy::Strict, |bytes| {
        bytes.fill(0x5a);
        Ok::<usize, ()>(bytes.len() + 1)
    });
    assert_eq!(
        error.map(|_| ()),
        Err(MemoryError::new(MemoryErrorKind::InvalidLength))
    );
}

#[test]
fn supported_dispatch_preserves_compact_and_large_bounds() -> Result<(), MemoryError> {
    let length = MAX_PROTECTED_BYTES + 1;
    let compact =
        ProtectedMemory::initialize(length, ProtectionPolicy::EmergencyAllowDegraded, |bytes| {
            Ok::<usize, ()>(bytes.len())
        });
    assert!(matches!(compact, Err(error) if error.kind() == MemoryErrorKind::Capacity));

    let large = ProtectedMemory::initialize_supported(
        length,
        ProtectionPolicy::EmergencyAllowDegraded,
        |bytes| {
            bytes.fill(0xa5);
            Ok::<usize, ()>(bytes.len())
        },
    )?;
    assert_eq!(large.len(), length);
    assert_eq!(large.capacity(), length);
    assert!(matches!(
        ProtectedMemory::initialize_supported(
            0,
            ProtectionPolicy::EmergencyAllowDegraded,
            |_| Ok::<usize, ()>(0),
        ),
        Err(error) if error.kind() == MemoryErrorKind::Capacity
    ));
    assert!(matches!(
        ProtectedMemory::initialize_supported(
            MAX_LARGE_PROTECTED_BYTES + 1,
            ProtectionPolicy::EmergencyAllowDegraded,
            |bytes| Ok::<usize, ()>(bytes.len()),
        ),
        Err(error) if error.kind() == MemoryErrorKind::Capacity
    ));
    Ok(())
}

#[test]
fn debug_and_json_are_value_free() -> Result<(), Box<dyn std::error::Error>> {
    if !crate::test_support::in_subprocess(concat!(
        module_path!(),
        "::debug_and_json_are_value_free"
    )) {
        return Ok(());
    }

    let memory = ProtectedMemory::initialize(16, ProtectionPolicy::Strict, |bytes| {
        bytes.copy_from_slice(b"ExampleSecret123");
        Ok::<usize, ()>(bytes.len())
    })?;
    let debug = format!("{memory:?}");
    let json = serde_json::to_string(memory.status())?;
    assert!(!debug.contains("ExampleSecret123"));
    assert!(!json.contains("ExampleSecret123"));
    assert!(debug.contains("[REDACTED]"));
    Ok(())
}

thread_local! {
    static PROVIDER_ENTRIES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}
pub(super) fn record_provider_entry() {
    PROVIDER_ENTRIES.set(PROVIDER_ENTRIES.get() + 1);
}

fn established_status() -> ProtectionStatus {
    ProtectionStatus {
        policy: ProtectionPolicy::Strict,
        mapping: RuntimeControlStatus::Established,
        memory_lock: RuntimeControlStatus::Established,
        dump_exclusion: if cfg!(target_os = "macos") {
            RuntimeControlStatus::Unsupported
        } else {
            RuntimeControlStatus::Established
        },
        fork_exclusion: RuntimeControlStatus::Established,
        guard_pages: RuntimeControlStatus::Established,
        canary: RuntimeControlStatus::Established,
        requested_bytes: 31,
        mapped_bytes: 3 * 16384,
        locked_bytes: 16384,
        page_granule: 16384,
        core_dump_suppressed: true,
    }
}

#[test]
fn exact_platform_predicate_rejects_each_missing_control() {
    let good = established_status();
    assert!(!good.is_degraded());
    for unavailable in [
        RuntimeControlStatus::Failed,
        RuntimeControlStatus::Unsupported,
        RuntimeControlStatus::NotRequested,
        RuntimeControlStatus::NotApplicable,
        RuntimeControlStatus::CompatibilityOnly,
    ] {
        for field in 0..5 {
            let mut status = good.clone();
            *match field {
                0 => &mut status.mapping,
                1 => &mut status.memory_lock,
                2 => &mut status.fork_exclusion,
                3 => &mut status.guard_pages,
                _ => &mut status.canary,
            } = unavailable;
            assert!(status.is_degraded());
            assert!(!status.memory_controls_established());
        }
    }
    for dump in [
        RuntimeControlStatus::Established,
        RuntimeControlStatus::Unsupported,
        RuntimeControlStatus::Failed,
        RuntimeControlStatus::NotRequested,
        RuntimeControlStatus::NotApplicable,
        RuntimeControlStatus::CompatibilityOnly,
    ] {
        let mut status = good.clone();
        status.dump_exclusion = dump;
        assert_eq!(!status.is_degraded(), dump == good.dump_exclusion);
        status.policy = ProtectionPolicy::EmergencyAllowDegraded;
        assert_eq!(!status.is_degraded(), dump == good.dump_exclusion);
    }
    let mut status = good.clone();
    status.core_dump_suppressed = false;
    assert!(status.is_degraded());
    assert_eq!(
        status.memory_controls_established(),
        !cfg!(target_os = "macos")
    );
    for (locked, page, mapped) in [
        (0, 16384, 49152),
        (31, 16384, 49152),
        (16384, 0, 49152),
        (16384, 16384, 31),
    ] {
        let mut status = good.clone();
        status.locked_bytes = locked;
        status.page_granule = page;
        status.mapped_bytes = mapped;
        assert!(status.is_degraded());
    }
}

#[cfg(target_os = "macos")]
#[test]
fn darwin_core_failures_precede_provider_and_every_initializer() {
    use crate::process_protection::tests::{CoreFailure, with_failure};
    if !crate::test_support::in_subprocess(concat!(
        module_path!(),
        "::darwin_core_failures_precede_provider_and_every_initializer"
    )) {
        return;
    }
    for failure in [
        CoreFailure::Set,
        CoreFailure::Read,
        CoreFailure::SoftNonzero,
        CoreFailure::HardNonzero,
    ] {
        with_failure(failure, || {
            for entry in 0..5 {
                let mut called = false;
                let before = PROVIDER_ENTRIES.get();
                let fill = |_: &mut [u8]| {
                    called = true;
                    Ok::<usize, ()>(1)
                };
                let result = match entry {
                    0 => ProtectedMemory::initialize(31, ProtectionPolicy::Strict, fill),
                    1 => ProtectedMemory::initialize_large(31, ProtectionPolicy::Strict, fill),
                    2 => ProtectedMemory::initialize_supported(31, ProtectionPolicy::Strict, fill),
                    3 => ProtectedMemory::initialize_supported(
                        MAX_PROTECTED_BYTES + 1,
                        ProtectionPolicy::Strict,
                        fill,
                    ),
                    _ => {
                        struct Marker<'a>(&'a mut bool);
                        impl crate::RandomSource for Marker<'_> {
                            fn fill(&mut self, _: &mut [u8]) -> Result<(), crate::EntropyError> {
                                *self.0 = true;
                                Ok(())
                            }
                        }
                        let error = crate::protected_random(
                            31,
                            ProtectionPolicy::Strict,
                            &mut Marker(&mut called),
                        );
                        assert!(
                            matches!(error, Err(crate::ProtectedRandomError::Memory(error)) if error.kind() == MemoryErrorKind::Protection)
                        );
                        Err(MemoryError::new(MemoryErrorKind::Protection))
                    }
                };
                assert!(
                    matches!(result, Err(error) if error.kind() == MemoryErrorKind::Protection)
                );
                assert!(!called);
                assert_eq!(PROVIDER_ENTRIES.get(), before);
            }
        });
    }
}

#[test]
fn strict_public_entrypoints_initialize_once_after_platform_controls()
-> Result<(), Box<dyn std::error::Error>> {
    if !crate::test_support::in_subprocess(concat!(
        module_path!(),
        "::strict_public_entrypoints_initialize_once_after_platform_controls"
    )) {
        return Ok(());
    }
    for entry in 0..5 {
        let mut calls = 0;
        let fill = |bytes: &mut [u8]| {
            #[cfg(target_os = "macos")]
            assert_eq!(rlimit::getrlimit(rlimit::Resource::CORE).ok(), Some((0, 0)));
            calls += 1;
            bytes.fill(0xa5);
            Ok::<usize, ()>(bytes.len())
        };
        let memory = match entry {
            0 => ProtectedMemory::initialize(31, ProtectionPolicy::Strict, fill)?,
            1 => ProtectedMemory::initialize_large(31, ProtectionPolicy::Strict, fill)?,
            2 => ProtectedMemory::initialize_supported(31, ProtectionPolicy::Strict, fill)?,
            3 => ProtectedMemory::initialize_supported(
                MAX_PROTECTED_BYTES + 1,
                ProtectionPolicy::Strict,
                fill,
            )?,
            _ => {
                struct Observed<'a>(&'a mut usize);
                impl crate::RandomSource for Observed<'_> {
                    fn fill(&mut self, bytes: &mut [u8]) -> Result<(), crate::EntropyError> {
                        #[cfg(target_os = "macos")]
                        assert_eq!(rlimit::getrlimit(rlimit::Resource::CORE).ok(), Some((0, 0)));
                        *self.0 += 1;
                        bytes.fill(0xa5);
                        Ok(())
                    }
                }
                crate::protected_random(31, ProtectionPolicy::Strict, &mut Observed(&mut calls))?
            }
        };
        assert_eq!(calls, 1);
        assert!(memory.expose(|bytes| bytes.iter().all(|byte| *byte == 0xa5))?);
        assert!(memory.status.memory_controls_established());
        assert_eq!(
            memory.status.core_dump_suppressed(),
            rlimit::getrlimit(rlimit::Resource::CORE).ok() == Some((0, 0))
        );
        #[cfg(target_os = "macos")]
        assert!(!memory.status.is_degraded());
    }
    Ok(())
}

#[test]
fn partial_initializer_failure_is_value_free_and_returns_no_owner() {
    if !crate::test_support::in_subprocess(concat!(
        module_path!(),
        "::partial_initializer_failure_is_value_free_and_returns_no_owner"
    )) {
        return;
    }
    let mut called = false;
    let result = ProtectedMemory::initialize(31, ProtectionPolicy::Strict, |bytes| {
        called = true;
        bytes[..3].fill(0xa5);
        Err::<usize, _>("ExampleSecret")
    });
    assert!(called);
    assert_eq!(
        result.map(drop),
        Err(MemoryError::new(MemoryErrorKind::Initializer))
    );
    assert_eq!(
        format!("{:?}", MemoryError::new(MemoryErrorKind::Initializer)),
        "MemoryError { kind: Initializer }"
    );
}

#[test]
fn strict_boundary_capacities_and_page_accounting() -> Result<(), Box<dyn std::error::Error>> {
    if !crate::test_support::in_subprocess(concat!(
        module_path!(),
        "::strict_boundary_capacities_and_page_accounting"
    )) {
        return Ok(());
    }
    // Denominator: compact maximum, first large capacity, and large maximum.
    // Refusals at the large ceiling are a countermetric, not silently skipped.
    for capacity in [
        MAX_PROTECTED_BYTES,
        MAX_PROTECTED_BYTES + 1,
        MAX_LARGE_PROTECTED_BYTES,
    ] {
        let mut calls = 0;
        let result =
            ProtectedMemory::initialize_supported(capacity, ProtectionPolicy::Strict, |bytes| {
                #[cfg(target_os = "macos")]
                assert_eq!(rlimit::getrlimit(rlimit::Resource::CORE).ok(), Some((0, 0)));
                calls += 1;
                bytes.fill(0xa5);
                Ok::<usize, ()>(bytes.len())
            });
        match result {
            Ok(owner) => {
                assert_eq!(calls, 1);
                assert_eq!(owner.capacity(), capacity);
                assert_eq!(owner.len(), capacity);
                let status = owner.status().clone();
                assert!(status.memory_controls_established());
                assert!(status.locked_bytes() > capacity); // provider canary overhead
                assert_eq!(
                    status.mapped_bytes() - status.locked_bytes(),
                    2 * status.page_granule()
                );
                drop(owner);
                println!(
                    "M01_JURY_BOUNDARY requested={} mapped={} locked={} page_granule={} outcome=accepted cleanup=owner_dropped",
                    capacity,
                    status.mapped_bytes(),
                    status.locked_bytes(),
                    status.page_granule()
                );
            }
            Err(error) => {
                assert_eq!(
                    capacity, MAX_LARGE_PROTECTED_BYTES,
                    "compact/dispatch strict boundary must be usable"
                );
                assert_eq!(error.kind(), MemoryErrorKind::Protection);
                assert_eq!(calls, 0);
                // Jury intentionally does not expose the provider's partial error report.
                println!(
                    "M01_JURY_BOUNDARY requested={capacity} mapped=unavailable locked=unavailable outcome=refused cleanup=no_owner"
                );
            }
        }
    }
    Ok(())
}

#[test]
fn strict_invalid_capacities_refuse_before_provider_entry() {
    for capacity in [0, MAX_LARGE_PROTECTED_BYTES + 1] {
        let before = PROVIDER_ENTRIES.get();
        let result = ProtectedMemory::initialize_supported(
            capacity,
            ProtectionPolicy::Strict,
            |_| -> Result<usize, ()> {
                panic!("out-of-bounds initializer reached");
            },
        );
        assert!(matches!(result, Err(error) if error.kind() == MemoryErrorKind::Capacity));
        assert_eq!(PROVIDER_ENTRIES.get(), before);
    }
    let before = PROVIDER_ENTRIES.get();
    assert!(
        matches!(ProtectedMemory::initialize(MAX_PROTECTED_BYTES + 1, ProtectionPolicy::Strict, |_| Ok::<usize, ()>(0)), Err(error) if error.kind() == MemoryErrorKind::Capacity)
    );
    assert_eq!(PROVIDER_ENTRIES.get(), before);
}

#[test]
fn strict_capture_refuses_degraded_controls_while_emergency_reports_them() {
    if !crate::test_support::in_subprocess(concat!(
        module_path!(),
        "::strict_capture_refuses_degraded_controls_while_emergency_reports_them"
    )) {
        return;
    }
    let mut status = established_status();
    status.memory_lock = RuntimeControlStatus::Failed;
    let mut called = false;
    let strict =
        crate::capture_after_process_protection(ProtectionPolicy::Strict, status.clone(), || {
            called = true
        });
    assert!(
        matches!(strict, Err(error) if error.kind() == crate::CaptureErrorKind::DegradedMemory)
    );
    assert!(!called);
    let emergency = crate::capture_after_process_protection(
        ProtectionPolicy::EmergencyAllowDegraded,
        status,
        || called = true,
    )
    .unwrap_or_else(|_| panic!("explicit emergency capture"));
    assert!(called);
    assert!(emergency.status.is_degraded());
    assert_eq!(emergency.status.memory_lock(), RuntimeControlStatus::Failed);
    assert!(emergency.status.core_dump_suppressed());
}
