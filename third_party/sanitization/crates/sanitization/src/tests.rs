#[cfg(all(feature = "alloc", feature = "serde"))]
use alloc::vec::Vec;

use crate::*;

crate::define_secret_storage_policy! {
    TestStoragePolicy {
        SecretBytes<4> => "test policy accepts reviewed fixed secret bytes",
    }
}

struct TestClock<'a>(&'a core::cell::Cell<u64>);

impl MonotonicClock for TestClock<'_> {
    #[inline]
    fn now(&self) -> u64 {
        self.0.get()
    }
}

#[test]
fn secret_integrity_error_adapters_preserve_error_classification() {
    let canary = SecretIntegrityError::<u8>::Canary(CanaryCorruptedError);
    assert!(canary.is_canary());
    assert!(!canary.is_operation());
    assert_eq!(canary.operation(), None);
    assert_eq!(
        canary.map_operation(u16::from),
        SecretIntegrityError::Canary(CanaryCorruptedError)
    );

    let operation = SecretIntegrityError::Operation(7_u8);
    assert!(!operation.is_canary());
    assert!(operation.is_operation());
    assert_eq!(operation.operation(), Some(&7));
    assert_eq!(
        operation.map_operation(u16::from),
        SecretIntegrityError::Operation(7_u16)
    );

    fn canary_only() -> IntegrityResult<()> {
        Err(CanaryCorruptedError)
    }

    fn propagate_canary() -> MappedResult<(), LengthError> {
        canary_only()?;
        Ok(())
    }

    fn propagate_length() -> MappedResult<(), LengthError> {
        Err(LengthError {
            expected: 4,
            actual: 3,
        })?;
        Ok(())
    }

    assert_eq!(
        propagate_canary(),
        Err(SecretIntegrityError::Canary(CanaryCorruptedError))
    );
    assert_eq!(
        propagate_length(),
        Err(SecretIntegrityError::Operation(LengthError {
            expected: 4,
            actual: 3,
        }))
    );
}

#[test]
fn bounded_mapped_error_preserves_integrity_and_operation_classes() {
    assert_eq!(
        BoundedMappedSecretError::from(SecretIntegrityError::<u8>::Canary(CanaryCorruptedError)),
        BoundedMappedSecretError::Integrity(CanaryCorruptedError)
    );
    assert_eq!(
        BoundedMappedSecretError::from(SecretIntegrityError::Operation(7_u8)),
        BoundedMappedSecretError::Operation(7_u8)
    );
}

#[cfg(feature = "memory-lock")]
#[test]
fn memory_lock_errors_propagate_into_mapped_results() {
    fn operation() -> MappedResult<(), MemoryLockError> {
        Err(MemoryLockError {
            operation: MemoryLockOperation::Lock,
            errno: 1,
        })?;
        Ok(())
    }

    assert!(matches!(
        operation(),
        Err(SecretIntegrityError::Operation(MemoryLockError {
            operation: MemoryLockOperation::Lock,
            errno: 1,
        }))
    ));
}

#[cfg(all(
    miri,
    feature = "memory-lock",
    any(
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ),
        target_os = "macos",
        target_os = "ios",
        target_os = "android",
        target_os = "windows",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
    )
))]
#[test]
fn miri_models_locked_mapping_lifecycle_without_native_syscalls() {
    let mut fixed = LockedSecretBytes::<4>::from_array([1, 2, 3, 4]).unwrap();
    assert!(fixed.constant_time_eq_or_panic(&[1, 2, 3, 4]));
    fixed
        .try_replace_from_fallible_fill(|bytes| {
            bytes.copy_from_slice(&[5, 6, 7, 8]);
            Ok::<(), core::convert::Infallible>(())
        })
        .unwrap();
    assert!(fixed.constant_time_eq_or_panic(&[5, 6, 7, 8]));
    drop(fixed);

    let mut dynamic = LockedSecretVec::from_slice(b"key").unwrap();
    dynamic.try_extend_from_slice(b"-material").unwrap();
    assert!(dynamic.constant_time_eq_or_panic(b"key-material"));
    dynamic
        .try_replace_from_exact_len(4, |bytes| bytes.copy_from_slice(b"next"))
        .unwrap();
    assert!(dynamic.constant_time_eq_or_panic(b"next"));
    drop(dynamic);

    let mut bounded = BoundedLockedSecretVec::<8>::from_slice_with_protection(
        b"key!",
        ProtectionRequest::locked(),
    )
    .unwrap();
    bounded.try_extend_from_slice(b"1234").unwrap();
    assert_eq!(
        bounded.try_extend_from_slice(b"x"),
        Err(BoundedMappedSecretError::CapacityLimit {
            maximum: 8,
            actual: 9,
        })
    );
    assert!(bounded.try_constant_time_eq(b"key!1234").unwrap());
    drop(bounded);

    let policy_dynamic = LockedSecretVec::try_from_capacity_with_protection(
        8,
        ProtectionRequest::locked(),
        |output| {
            assert!(output.iter().all(|byte| *byte == 0));
            output[..5].copy_from_slice(b"token");
            Ok::<usize, core::convert::Infallible>(5)
        },
    )
    .unwrap();
    assert!(policy_dynamic.constant_time_eq_or_panic(b"token"));
    assert!(policy_dynamic
        .protection_report()
        .satisfies(ProtectionRequest::locked()));
    drop(policy_dynamic);

    let bounded_callback_ran = core::cell::Cell::new(false);
    assert_eq!(
        LockedSecretVec::try_from_capacity_bounded_with_protection(
            9,
            8,
            ProtectionRequest::locked(),
            |_| {
                bounded_callback_ran.set(true);
                Ok::<usize, core::convert::Infallible>(0)
            },
        )
        .err(),
        Some(ProtectedSecretFillError::CapacityLimit {
            maximum: 8,
            actual: 9,
        })
    );
    assert!(!bounded_callback_ran.get());

    assert_eq!(
        LockedSecretVec::try_from_capacity_with_protection(
            4,
            ProtectionRequest::locked(),
            |output| {
                output[..2].copy_from_slice(b"no");
                Err::<usize, _>("decode failed")
            },
        )
        .err(),
        Some(ProtectedSecretFillError::Fill("decode failed"))
    );

    assert_eq!(
        LockedSecretVec::try_from_capacity_with_protection(
            4,
            ProtectionRequest::locked(),
            |output| {
                output.copy_from_slice(b"data");
                Ok::<usize, core::convert::Infallible>(5)
            },
        )
        .err(),
        Some(ProtectedSecretFillError::Length(LengthError {
            expected: 4,
            actual: 5,
        }))
    );

    let panic_result = std::panic::catch_unwind(|| {
        let _ = LockedSecretVec::try_from_capacity_with_protection(
            4,
            ProtectionRequest::locked(),
            |output| -> Result<usize, core::convert::Infallible> {
                output.copy_from_slice(b"data");
                panic!("decoder panic");
            },
        );
    });
    assert!(panic_result.is_err());

    let mut text = LockedSecretString::from_secret_str("secret").unwrap();
    text.try_push_str("-text").unwrap();
    assert!(text.constant_time_eq_or_panic("secret-text"));
    text.try_replace_from_secret_str("next").unwrap();
    assert!(text.constant_time_eq_or_panic("next"));
    drop(text);

    let pool = SecretPool::<4, 2>::new().unwrap();
    let first = pool.try_allocate_from_array([9, 8, 7, 6]).unwrap().unwrap();
    let first_id = first.slot_id();
    let second = pool.try_allocate().unwrap().unwrap();
    assert!(pool.try_allocate().unwrap().is_none());
    drop(first);
    let reused = pool.try_allocate().unwrap().unwrap();
    assert_eq!(reused.slot_index(), first_id.index);
    assert_ne!(reused.slot_id(), first_id);
    drop(reused);
    drop(second);
    drop(pool);

    #[cfg(feature = "zeroize-interop")]
    {
        fn assert_zeroize_interop<T: zeroize::Zeroize + zeroize::ZeroizeOnDrop>() {}

        assert_zeroize_interop::<LockedSecretVec>();
        assert_zeroize_interop::<LockedSecretString>();

        let mut bytes = LockedSecretVec::from_slice(b"interop").unwrap();
        zeroize::Zeroize::zeroize(&mut bytes);
        assert_eq!(bytes.try_with_secret(<[u8]>::len), Ok(0));

        let mut string = LockedSecretString::from_secret_str("interop").unwrap();
        zeroize::Zeroize::zeroize(&mut string);
        assert_eq!(string.try_with_secret(str::len), Ok(0));
    }

    #[cfg(feature = "subtle-interop")]
    {
        fn assert_subtle_interop<T: subtle::ConstantTimeEq>() {}

        assert_subtle_interop::<LockedSecretVec>();
        assert_subtle_interop::<LockedSecretString>();

        let left = LockedSecretVec::from_slice(b"interop").unwrap();
        let right = LockedSecretVec::from_slice(b"interop").unwrap();
        assert!(bool::from(subtle::ConstantTimeEq::ct_eq(&left, &right)));

        let left = LockedSecretString::from_secret_str("interop").unwrap();
        let right = LockedSecretString::from_secret_str("interop").unwrap();
        assert!(bool::from(subtle::ConstantTimeEq::ct_eq(&left, &right)));
    }
}

#[cfg(all(
    miri,
    feature = "memory-lock",
    feature = "canary-check",
    any(
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ),
        target_os = "macos",
        target_os = "ios",
        target_os = "android",
        target_os = "windows",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
    )
))]
#[test]
fn miri_models_canary_failure_clear_and_quarantine() {
    let mut fixed = LockedSecretBytes::<4>::from_array([1, 2, 3, 4]).unwrap();
    fixed.corrupt_prefix_canary_for_test();
    assert_eq!(fixed.try_expose_secret(|_| ()), Err(CanaryCorruptedError));
    drop(fixed);

    let pool = SecretPool::<4, 1>::new().unwrap();
    let mut slot = pool.try_allocate().unwrap().unwrap();
    slot.try_copy_from_slice(&[5, 6, 7, 8]).unwrap();
    slot.corrupt_prefix_canary_for_test();
    assert_eq!(slot.try_expose_secret(|_| ()), Err(CanaryCorruptedError));
    drop(slot);
    assert_eq!(pool.quarantined_slots(), 1);
    drop(pool);
}

#[cfg(all(
    feature = "guard-pages",
    any(
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ),
        target_os = "macos",
        target_os = "ios",
        target_os = "android",
        target_os = "windows",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
    ),
    not(miri)
))]
#[test]
fn guard_page_errors_propagate_into_mapped_results() {
    fn operation() -> MappedResult<(), GuardPageError> {
        Err(GuardPageError {
            operation: GuardPageOperation::Lock,
            errno: 1,
        })?;
        Ok(())
    }

    assert!(matches!(
        operation(),
        Err(SecretIntegrityError::Operation(GuardPageError {
            operation: GuardPageOperation::Lock,
            errno: 1,
        }))
    ));
}

#[test]
fn allowlisted_secret_requires_policy_and_storage_contracts() {
    let mut secret =
        AllowlistedSecret::<SecretBytes<4>, TestStoragePolicy>::new(SecretBytes::from_array([
            1, 2, 3, 4,
        ]));
    assert_eq!(
        AllowlistedSecret::<SecretBytes<4>, TestStoragePolicy>::policy_rationale(),
        "test policy accepts reviewed fixed secret bytes"
    );
    assert_eq!(
        secret.with_secret(|bytes| bytes.expose_secret(|value| *value)),
        [1, 2, 3, 4]
    );
    secret.with_secret_mut(|bytes| bytes.replace_from_array([4, 3, 2, 1]));
    assert!(secret.with_secret(|bytes| bytes.constant_time_eq(&[4, 3, 2, 1])));
    assert_eq!(
        std::format!("{secret:?}"),
        "AllowlistedSecret { contents: \"<redacted>\" }"
    );
}

#[test]
fn secret_integrity_result_adapter_flattens_fallible_exposure() {
    let success: Result<Result<u8, &str>, CanaryCorruptedError> = Ok(Ok(7));
    assert_eq!(success.flatten_secret_integrity(), Ok(7));

    let operation: Result<Result<u8, &str>, CanaryCorruptedError> = Ok(Err("decode failed"));
    assert_eq!(
        operation.flatten_secret_integrity(),
        Err(SecretIntegrityError::Operation("decode failed"))
    );

    let canary: Result<Result<u8, &str>, CanaryCorruptedError> = Err(CanaryCorruptedError);
    assert_eq!(
        canary.flatten_secret_integrity(),
        Err(SecretIntegrityError::Canary(CanaryCorruptedError))
    );
}

#[test]
fn protection_report_can_validate_requested_controls_once() {
    let request = ProtectionRequest {
        memory_lock: Requirement::Required,
        dump_exclusion: Requirement::Preferred,
        fork: ForkProtectionRequest::exclude(Requirement::Preferred),
        guard_pages: Requirement::NotRequested,
        canary: Requirement::Required,
        cache_policy: Requirement::NotRequested,
    };
    let mut report = ProtectionReport {
        mapping: ProtectionState::Established,
        memory_lock: ProtectionState::Established,
        dump_exclusion: ProtectionState::Established,
        fork: ForkProtectionReport {
            policy: ForkPolicy::Exclude,
            state: ProtectionState::Established,
        },
        guard_pages: ProtectionState::NotRequested,
        canary: ProtectionState::Established,
        cache_policy: ProtectionState::NotRequested,
        requested_bytes: 32,
        mapped_bytes: 4096,
        locked_bytes: 4096,
        page_granule: 4096,
        lock_quota_likely: false,
    };

    assert!(report.satisfies(request));
    assert!(report.all_requested_controls_established(request));
    assert!(!report.is_degraded());
    assert!(report.memory_is_locked());
    assert!(!report.guard_pages_established());
    assert!(report.failed_or_unsupported_controls().next().is_none());

    report.dump_exclusion = ProtectionState::Unsupported;
    assert!(!report.satisfies(request));
    assert!(!report.all_requested_controls_established(request));
    assert!(report.is_degraded());
    assert_eq!(
        report.failed_or_unsupported_controls().next(),
        Some(ProtectionControl::DumpExclusion)
    );

    report.dump_exclusion = ProtectionState::Established;
    report.guard_pages = ProtectionState::CompatibilityOnly;
    let mut unavailable = report.failed_or_unsupported_controls();
    assert_eq!(unavailable.next(), Some(ProtectionControl::GuardPages));
    assert_eq!(unavailable.next(), None);

    report.guard_pages = ProtectionState::Established;
    assert!(report.guard_pages_established());
    report.mapping = ProtectionState::Failed { code: 12 };
    assert!(!report.satisfies(request));
    assert!(report.is_degraded());
    assert_eq!(
        report.failed_or_unsupported_controls().next(),
        Some(ProtectionControl::Mapping)
    );

    let empty_report = ProtectionReport {
        mapping: ProtectionState::NotApplicable,
        memory_lock: ProtectionState::NotApplicable,
        dump_exclusion: ProtectionState::NotApplicable,
        fork: ForkProtectionReport {
            policy: ForkPolicy::Exclude,
            state: ProtectionState::NotApplicable,
        },
        guard_pages: ProtectionState::NotRequested,
        canary: ProtectionState::NotApplicable,
        cache_policy: ProtectionState::NotRequested,
        requested_bytes: 0,
        mapped_bytes: 0,
        locked_bytes: 0,
        page_granule: 4096,
        lock_quota_likely: false,
    };
    assert!(empty_report.satisfies(request));
    assert!(!empty_report.is_degraded());

    let mut released_nonempty_report = empty_report;
    released_nonempty_report.requested_bytes = 32;
    assert!(!released_nonempty_report.satisfies(request));
    assert!(released_nonempty_report.is_degraded());
    assert_eq!(
        released_nonempty_report
            .failed_or_unsupported_controls()
            .next(),
        Some(ProtectionControl::Mapping)
    );

    assert!(!ProtectionState::NotApplicable.satisfies(Requirement::Required));
    assert!(ProtectionState::Unsupported.satisfies(Requirement::NotRequested));
}

#[test]
fn ct_choice_normalizes_and_declassifies_explicitly() {
    let false_choice = ct::Choice::from_u8(0);
    let true_choice = ct::Choice::from_u8(7);

    assert_eq!(
        false_choice.declassify_u8("test or verification observes normalized choice"),
        0
    );
    assert_eq!(
        true_choice.declassify_u8("test or verification observes normalized choice"),
        1
    );
    assert_eq!(
        (true_choice & false_choice)
            .declassify_u8("test or verification observes normalized choice"),
        0
    );
    assert_eq!(
        (true_choice | false_choice)
            .declassify_u8("test or verification observes normalized choice"),
        1
    );
    assert_eq!(
        (true_choice ^ ct::Choice::TRUE)
            .declassify_u8("test or verification observes normalized choice"),
        0
    );
    assert_eq!(
        (!false_choice).declassify_u8("test or verification observes normalized choice"),
        1
    );
    assert!(true_choice.declassify("test observes true choice assertion"));
    assert!(!false_choice.declassify("test observes false choice assertion"));
}

#[test]
fn ct_primitives_compare_and_select() {
    use ct::{ConditionallyAssignable, ConditionallySelectable, ConstantTimeEq, ConstantTimeOrd};

    assert_eq!(
        7u8.ct_eq(&7)
            .declassify_u8("test or verification observes normalized choice"),
        1
    );
    assert_eq!(
        7u8.ct_eq(&8)
            .declassify_u8("test or verification observes normalized choice"),
        0
    );
    assert_eq!(
        (-3i32)
            .ct_eq(&-3)
            .declassify_u8("test or verification observes normalized choice"),
        1
    );
    assert_eq!(
        (-3i32)
            .ct_ne(&4)
            .declassify_u8("test or verification observes normalized choice"),
        1
    );
    assert_eq!(
        3u8.ct_cmp(&9)
            .is_less()
            .declassify_u8("test or verification observes normalized choice"),
        1
    );
    assert_eq!(
        9u16.ct_cmp(&3)
            .is_greater()
            .declassify_u8("test or verification observes normalized choice"),
        1
    );
    assert_eq!(
        5usize
            .ct_cmp(&5)
            .is_equal()
            .declassify_u8("test or verification observes normalized choice"),
        1
    );
    assert_eq!(
        (-9i32)
            .ct_lt(&-3)
            .declassify_u8("test or verification observes normalized choice"),
        1
    );
    assert_eq!(
        3i32.ct_gt(&-9)
            .declassify_u8("test or verification observes normalized choice"),
        1
    );
    assert_eq!(
        3u8.ct_cmp(&9).declassify("test exposes primitive ordering"),
        core::cmp::Ordering::Less
    );

    let selected = u32::conditional_select(&11, &22, ct::Choice::TRUE);
    assert_eq!(selected, 22);

    let mut assigned = 11u32;
    assigned.conditional_assign(&22, ct::Choice::FALSE);
    assert_eq!(assigned, 11);
    assigned.conditional_assign(&22, ct::Choice::TRUE);
    assert_eq!(assigned, 22);
}

#[test]
fn ct_ordering_constructor_normalizes_invalid_states() {
    assert_eq!(
        ct::CtOrdering::new(ct::Choice::TRUE, ct::Choice::TRUE, ct::Choice::FALSE)
            .declassify("test observes normalized ordering"),
        core::cmp::Ordering::Less
    );
    assert_eq!(
        ct::CtOrdering::new(ct::Choice::FALSE, ct::Choice::TRUE, ct::Choice::TRUE)
            .declassify("test observes normalized ordering"),
        core::cmp::Ordering::Greater
    );
    assert_eq!(
        ct::CtOrdering::new(ct::Choice::FALSE, ct::Choice::FALSE, ct::Choice::FALSE)
            .declassify("test observes normalized ordering"),
        core::cmp::Ordering::Equal
    );
}

#[test]
fn ct_mask_requires_explicit_declassification() {
    assert_eq!(
        ct::Mask::<u32>::from_choice(ct::Choice::FALSE)
            .declassify("test observes public false mask"),
        0
    );
    assert_eq!(
        ct::Mask::<u32>::from_choice(ct::Choice::TRUE).declassify("test observes public true mask"),
        u32::MAX
    );
    assert_eq!(std::format!("{:?}", ct::Choice::TRUE), "Choice(..)");
    assert_eq!(std::format!("{:?}", ct::CtOrdering::LESS), "CtOrdering(..)");
    assert_eq!(
        std::format!("{:?}", ct::Mask::<u32>::from_choice(ct::Choice::TRUE)),
        "Mask(..)"
    );
}

#[test]
fn ct_arrays_and_public_len_slices_compare() {
    use ct::{ConditionallySelectable, ConstantTimeEq, ConstantTimeOrd};

    let left = [1u8, 2, 3, 4];
    let same = [1u8, 2, 3, 4];
    let different = [1u8, 2, 3, 9];

    assert_eq!(
        ct::eq_fixed(&left, &same).declassify_u8("test or verification observes normalized choice"),
        1
    );
    assert_eq!(
        left.ct_eq(&different)
            .declassify_u8("test or verification observes normalized choice"),
        0
    );
    assert_eq!(
        ct::cmp_fixed(&left, &different)
            .is_less()
            .declassify_u8("test or verification observes normalized choice"),
        1
    );
    assert_eq!(
        different
            .ct_cmp(&left)
            .is_greater()
            .declassify_u8("test or verification observes normalized choice"),
        1
    );
    assert_eq!(
        same.ct_cmp(&left)
            .is_equal()
            .declassify_u8("test or verification observes normalized choice"),
        1
    );
    assert_eq!(
        ct::eq_public_len(&left, &[1, 2, 3])
            .declassify_u8("test or verification observes normalized choice"),
        0
    );
    assert!(ct::declassified_eq_fixed(
        &left,
        &same,
        "test exposes fixed equality result"
    ));
    assert!(!ct::declassified_eq_public_len(
        &left,
        &[1, 2, 3],
        "test exposes public-length equality result"
    ));
    assert_eq!(
        ct::declassified_cmp_fixed(&left, &different, "test exposes fixed ordering result"),
        core::cmp::Ordering::Less
    );

    let selected = <[u8; 4]>::conditional_select(&left, &different, ct::Choice::TRUE);
    assert_eq!(selected, different);
}

#[test]
fn ct_oblivious_lookup_scans_public_table() {
    let table = [10u8, 20, 30, 40];

    let selected = ct::oblivious_lookup(&table, ct::SecretIndex::new(2usize), &99);
    assert_eq!(selected, 30);

    let fallback = ct::oblivious_lookup(&table, ct::SecretIndex::new(7usize), &99);
    assert_eq!(fallback, 99);

    let secret_selected = ct::oblivious_lookup_secret(&table, ct::SecretIndex::new(1usize), &99);
    assert_eq!(
        secret_selected.declassify("test reveals selected table value"),
        20
    );
}

#[test]
fn ct_conditional_copy_swap_and_select_slice() {
    let mut destination = [1u8, 2, 3, 4];
    let source = [9u8, 8, 7, 6];

    ct::conditional_copy(&mut destination, &source, ct::Choice::FALSE).unwrap();
    assert_eq!(destination, [1, 2, 3, 4]);

    ct::conditional_copy(&mut destination, &source, ct::Choice::TRUE).unwrap();
    assert_eq!(destination, source);

    let mut left = [1u8, 2, 3];
    let mut right = [7u8, 8, 9];
    ct::conditional_swap(&mut left, &mut right, ct::Choice::FALSE).unwrap();
    assert_eq!(left, [1, 2, 3]);
    assert_eq!(right, [7, 8, 9]);

    ct::conditional_swap(&mut left, &mut right, ct::Choice::TRUE).unwrap();
    assert_eq!(left, [7, 8, 9]);
    assert_eq!(right, [1, 2, 3]);

    let mut selected = [0u8; 3];
    ct::select_slice(&mut selected, &left, &right, ct::Choice::FALSE).unwrap();
    assert_eq!(selected, left);
    ct::select_slice(&mut selected, &left, &right, ct::Choice::TRUE).unwrap();
    assert_eq!(selected, right);
}

#[test]
fn ct_memory_helpers_report_public_length_errors() {
    let mut destination = [0u8; 4];
    assert_eq!(
        ct::conditional_copy(&mut destination, &[1, 2], ct::Choice::TRUE),
        Err(LengthError {
            expected: 4,
            actual: 2,
        })
    );

    let mut left = [1u8, 2, 3];
    let mut right = [4u8, 5];
    assert_eq!(
        ct::conditional_swap(&mut left, &mut right, ct::Choice::TRUE),
        Err(LengthError {
            expected: 3,
            actual: 2,
        })
    );

    assert_eq!(
        ct::select_slice(&mut destination, &[1, 2, 3], &[4, 5], ct::Choice::TRUE),
        Err(LengthError {
            expected: 3,
            actual: 2,
        })
    );
}

#[test]
fn ct_secret_containers_expose_native_traits() {
    use ct::{ConditionallySelectable, ConstantTimeEq};

    let left = SecretBytes::from_array([1u8, 2, 3, 4]);
    let same = SecretBytes::from_array([1u8, 2, 3, 4]);
    let different = SecretBytes::from_array([9u8, 8, 7, 6]);

    assert_eq!(
        left.ct_eq(&same)
            .declassify_u8("test observes native equality"),
        1
    );
    assert_eq!(
        left.ct_eq(&different)
            .declassify_u8("test observes native inequality"),
        0
    );
    assert_eq!(
        left.ct_eq([1u8, 2, 3, 4].as_slice())
            .declassify_u8("test or verification observes normalized choice"),
        1
    );

    let selected = SecretBytes::conditional_select(&left, &different, ct::Choice::TRUE);
    assert!(selected.constant_time_eq(&[9, 8, 7, 6]));

    #[cfg(feature = "alloc")]
    {
        let boxed_left = SecretBoxBytes::from_slice(b"token");
        let boxed_same = SecretBoxBytes::from_slice(b"token");
        let boxed_different = SecretBoxBytes::from_slice(b"other");
        assert_eq!(
            boxed_left
                .ct_eq(&boxed_same)
                .declassify_u8("test observes native boxed equality"),
            1
        );
        assert_eq!(
            boxed_left
                .ct_eq(&boxed_different)
                .declassify_u8("test observes native boxed inequality"),
            0
        );
        assert_eq!(
            boxed_left
                .ct_eq(b"token".as_slice())
                .declassify_u8("test or verification observes normalized choice"),
            1
        );

        let vec_left = SecretVec::from_slice(b"token");
        let vec_same = SecretVec::from_slice(b"token");
        let vec_different = SecretVec::from_slice(b"other");
        assert_eq!(
            vec_left
                .ct_eq(&vec_same)
                .declassify_u8("test or verification observes normalized choice"),
            1
        );
        assert_eq!(
            vec_left
                .ct_eq(&vec_different)
                .declassify_u8("test or verification observes normalized choice"),
            0
        );
        assert_eq!(
            vec_left
                .ct_eq(b"token".as_slice())
                .declassify_u8("test or verification observes normalized choice"),
            1
        );

        let string_left = SecretString::from_secret_str("token");
        let string_same = SecretString::from_secret_str("token");
        let string_different = SecretString::from_secret_str("other");
        assert_eq!(
            string_left
                .ct_eq(&string_same)
                .declassify_u8("test or verification observes normalized choice"),
            1
        );
        assert_eq!(
            string_left
                .ct_eq(&string_different)
                .declassify_u8("test or verification observes normalized choice"),
            0
        );
        assert_eq!(
            string_left
                .ct_eq("token")
                .declassify_u8("test or verification observes normalized choice"),
            1
        );

        let bounded_left = BoundedSecretString::<8>::from_secret_str("token").unwrap();
        let bounded_same = BoundedSecretString::<8>::from_secret_str("token").unwrap();
        let bounded_different = BoundedSecretString::<8>::from_secret_str("other").unwrap();
        assert_eq!(
            bounded_left
                .ct_eq(&bounded_same)
                .declassify_u8("test or verification observes normalized choice"),
            1
        );
        assert_eq!(
            bounded_left
                .ct_eq(&bounded_different)
                .declassify_u8("test or verification observes normalized choice"),
            0
        );
        assert_eq!(
            bounded_left
                .ct_eq("token")
                .declassify_u8("test or verification observes normalized choice"),
            1
        );
    }

    #[cfg(all(
        feature = "memory-lock",
        not(miri),
        any(
            all(
                target_os = "linux",
                any(target_arch = "x86_64", target_arch = "aarch64")
            ),
            target_os = "macos",
            target_os = "ios",
            target_os = "android",
            target_os = "windows",
            target_os = "freebsd",
            target_os = "openbsd",
            target_os = "netbsd",
            target_os = "dragonfly",
            all(target_arch = "wasm32", feature = "wasm-compat"),
        )
    ))]
    {
        let (locked_left, locked_same, locked_different) = match (
            LockedSecretBytes::from_array([1u8, 2, 3, 4]),
            LockedSecretBytes::from_array([1u8, 2, 3, 4]),
            LockedSecretBytes::from_array([9u8, 8, 7, 6]),
        ) {
            (Ok(left), Ok(same), Ok(different)) => (left, same, different),
            _ => return,
        };
        assert_eq!(
            locked_left
                .ct_eq(&locked_same)
                .declassify_u8("test or verification observes normalized choice"),
            1
        );
        assert_eq!(
            locked_left
                .ct_eq(&locked_different)
                .declassify_u8("test or verification observes normalized choice"),
            0
        );
        assert_eq!(
            locked_left
                .ct_eq([1u8, 2, 3, 4].as_slice())
                .declassify_u8("test or verification observes normalized choice"),
            1
        );

        let pool = match SecretPool::<4, 2>::new() {
            Ok(pool) => pool,
            Err(_) => return,
        };
        let pooled_left = pool
            .try_allocate_from_array([1u8, 2, 3, 4])
            .unwrap()
            .unwrap();
        let pooled_same = pool
            .try_allocate_from_array([1u8, 2, 3, 4])
            .unwrap()
            .unwrap();
        assert_eq!(
            pooled_left
                .ct_eq(&pooled_same)
                .declassify_u8("test or verification observes normalized choice"),
            1
        );
        assert_eq!(
            pooled_left
                .ct_eq([1u8, 2, 3, 4].as_slice())
                .declassify_u8("test or verification observes normalized choice"),
            1
        );
    }

    #[cfg(all(
        feature = "memory-lock",
        not(target_arch = "wasm32"),
        not(miri),
        any(
            all(
                target_os = "linux",
                any(target_arch = "x86_64", target_arch = "aarch64")
            ),
            target_os = "macos",
            target_os = "ios",
            target_os = "android",
            target_os = "windows",
            target_os = "freebsd",
            target_os = "openbsd",
            target_os = "netbsd",
            target_os = "dragonfly",
        )
    ))]
    {
        let (locked_vec_left, locked_vec_same, locked_vec_different) = match (
            LockedSecretVec::from_slice(b"token"),
            LockedSecretVec::from_slice(b"token"),
            LockedSecretVec::from_slice(b"other"),
        ) {
            (Ok(left), Ok(same), Ok(different)) => (left, same, different),
            _ => return,
        };
        assert_eq!(
            locked_vec_left
                .ct_eq(&locked_vec_same)
                .declassify_u8("test or verification observes normalized choice"),
            1
        );
        assert_eq!(
            locked_vec_left
                .ct_eq(&locked_vec_different)
                .declassify_u8("test or verification observes normalized choice"),
            0
        );
        assert_eq!(
            locked_vec_left
                .ct_eq(b"token".as_slice())
                .declassify_u8("test or verification observes normalized choice"),
            1
        );

        let (locked_text_left, locked_text_same, locked_text_different) = match (
            LockedSecretString::from_secret_str("token"),
            LockedSecretString::from_secret_str("token"),
            LockedSecretString::from_secret_str("other"),
        ) {
            (Ok(left), Ok(same), Ok(different)) => (left, same, different),
            _ => return,
        };
        assert_eq!(
            locked_text_left
                .ct_eq(&locked_text_same)
                .declassify_u8("test or verification observes normalized choice"),
            1
        );
        assert_eq!(
            locked_text_left
                .ct_eq(&locked_text_different)
                .declassify_u8("test or verification observes normalized choice"),
            0
        );
        assert_eq!(
            locked_text_left
                .ct_eq("token")
                .declassify_u8("test or verification observes normalized choice"),
            1
        );
    }

    #[cfg(all(
        feature = "guard-pages",
        not(miri),
        any(
            all(
                target_os = "linux",
                any(target_arch = "x86_64", target_arch = "aarch64")
            ),
            target_os = "macos",
            target_os = "ios",
            target_os = "android",
            target_os = "windows",
            target_os = "freebsd",
            target_os = "openbsd",
            target_os = "netbsd",
            target_os = "dragonfly",
        )
    ))]
    {
        let (guarded_left, guarded_same, guarded_different) = match (
            GuardedSecretVec::from_slice(b"token"),
            GuardedSecretVec::from_slice(b"token"),
            GuardedSecretVec::from_slice(b"other"),
        ) {
            (Ok(left), Ok(same), Ok(different)) => (left, same, different),
            _ => return,
        };
        assert_eq!(
            guarded_left
                .ct_eq(&guarded_same)
                .declassify_u8("test or verification observes normalized choice"),
            1
        );
        assert_eq!(
            guarded_left
                .ct_eq(&guarded_different)
                .declassify_u8("test or verification observes normalized choice"),
            0
        );
        assert_eq!(
            guarded_left
                .ct_eq(b"token".as_slice())
                .declassify_u8("test or verification observes normalized choice"),
            1
        );

        let (guarded_text_left, guarded_text_same, guarded_text_different) = match (
            GuardedSecretString::from_secret_str("token"),
            GuardedSecretString::from_secret_str("token"),
            GuardedSecretString::from_secret_str("other"),
        ) {
            (Ok(left), Ok(same), Ok(different)) => (left, same, different),
            _ => return,
        };
        assert_eq!(
            guarded_text_left
                .ct_eq(&guarded_text_same)
                .declassify_u8("test or verification observes normalized choice"),
            1
        );
        assert_eq!(
            guarded_text_left
                .ct_eq(&guarded_text_different)
                .declassify_u8("test or verification observes normalized choice"),
            0
        );
        assert_eq!(
            guarded_text_left
                .ct_eq("token")
                .declassify_u8("test or verification observes normalized choice"),
            1
        );
    }
}

#[test]
fn ct_option_keeps_presence_as_choice() {
    use ct::ConditionallySelectable;

    let present = ct::PublicCtOption::some(9u8);
    let absent = ct::PublicCtOption::none(3u8);

    assert_eq!(
        present
            .is_some()
            .declassify_u8("test or verification observes normalized choice"),
        1
    );
    assert_eq!(
        absent
            .is_none()
            .declassify_u8("test or verification observes normalized choice"),
        1
    );
    assert_eq!(present.unwrap_or(&1), 9);
    assert_eq!(absent.unwrap_or(&1), 1);
    assert_eq!(present.map(|value| value.wrapping_add(1)).unwrap_or(&0), 10);
    assert_eq!(
        absent
            .map(|value| value.wrapping_add(1))
            .declassify("test exposes mapped optional absence"),
        None
    );
    assert_eq!(present.and(ct::PublicCtOption::some(4u8)).unwrap_or(&0), 4);
    assert_eq!(present.and(ct::PublicCtOption::none(4u8)).unwrap_or(&0), 0);
    assert_eq!(present.or(ct::PublicCtOption::some(4u8)).unwrap_or(&0), 9);
    assert_eq!(absent.or(ct::PublicCtOption::some(4u8)).unwrap_or(&0), 4);
    let selected = ct::PublicCtOption::conditional_select(
        &present,
        &ct::PublicCtOption::some(11),
        ct::Choice::TRUE,
    );
    assert_eq!(selected.unwrap_or(&0), 11);
    assert_eq!(present.declassify("test exposes optional success"), Some(9));
    assert_eq!(absent.declassify("test exposes optional absence"), None);
}

#[test]
fn ct_result_keeps_success_as_choice() {
    use ct::ConditionallySelectable;

    let ok = ct::PublicCtResult::new(7u8, 99u8, ct::Choice::TRUE);
    let err = ct::PublicCtResult::new(7u8, 99u8, ct::Choice::FALSE);

    assert_eq!(
        ok.is_ok()
            .declassify_u8("test or verification observes normalized choice"),
        1
    );
    assert_eq!(
        ok.is_err()
            .declassify_u8("test or verification observes normalized choice"),
        0
    );
    assert_eq!(
        err.is_ok()
            .declassify_u8("test or verification observes normalized choice"),
        0
    );
    assert_eq!(
        err.is_err()
            .declassify_u8("test or verification observes normalized choice"),
        1
    );
    assert_eq!(ok.unwrap_or(&1), 7);
    assert_eq!(err.unwrap_or(&1), 1);
    assert_eq!(ok.map(|value| value.wrapping_add(1)).unwrap_or(&0), 8);
    assert_eq!(
        err.map(|value| value.wrapping_add(1))
            .declassify("test exposes mapped result error"),
        Err(99)
    );
    assert_eq!(
        ok.map_err(|error| error.wrapping_add(1))
            .declassify("test exposes mapped result success"),
        Ok(7)
    );
    assert_eq!(
        err.map_err(|error| error.wrapping_add(1))
            .declassify("test exposes mapped result error"),
        Err(100)
    );
    let selected = ct::PublicCtResult::conditional_select(
        &ok,
        &ct::PublicCtResult::new(42u8, 1u8, ct::Choice::TRUE),
        ct::Choice::TRUE,
    );
    assert_eq!(selected.unwrap_or(&0), 42);
    assert_eq!(ok.declassify("test exposes result success"), Ok(7));
    assert_eq!(err.declassify("test exposes result error"), Err(99));
}

#[test]
fn ct_secret_scalar_clears_on_drop_and_transfers_on_declassification() {
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    struct Probe {
        clears: Arc<AtomicUsize>,
        value: u8,
    }

    impl SecureSanitize for Probe {
        fn secure_sanitize(&mut self) {
            self.value.secure_sanitize();
            self.clears.fetch_add(1, Ordering::SeqCst);
        }
    }

    let dropped_clears = Arc::new(AtomicUsize::new(0));
    drop(ct::SecretScalar::new(Probe {
        clears: Arc::clone(&dropped_clears),
        value: 7,
    }));
    assert_eq!(dropped_clears.load(Ordering::SeqCst), 1);

    let transferred_clears = Arc::new(AtomicUsize::new(0));
    let mut transferred = ct::SecretScalar::new(Probe {
        clears: Arc::clone(&transferred_clears),
        value: 9,
    })
    .declassify("test assumes cleanup responsibility for scalar");
    assert_eq!(transferred_clears.load(Ordering::SeqCst), 0);
    transferred.secure_sanitize();
    assert_eq!(transferred_clears.load(Ordering::SeqCst), 1);
}

#[test]
fn secret_ct_option_clears_dummy_and_preserves_selected_ownership() {
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    struct Probe(Arc<AtomicUsize>);

    impl SecureSanitize for Probe {
        fn secure_sanitize(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    let dummy_clears = Arc::new(AtomicUsize::new(0));
    let absent = ct::SecretCtOption::secret(Probe(Arc::clone(&dummy_clears)), ct::Choice::FALSE);
    assert!(absent
        .declassify("test exposes secret optional absence")
        .is_none());
    assert_eq!(dummy_clears.load(Ordering::SeqCst), 1);

    let selected_clears = Arc::new(AtomicUsize::new(0));
    let present = ct::SecretCtOption::secret(Probe(Arc::clone(&selected_clears)), ct::Choice::TRUE);
    let mut selected = present
        .declassify("test assumes cleanup responsibility for selected option")
        .expect("present secret option");
    assert_eq!(selected_clears.load(Ordering::SeqCst), 0);
    selected.secure_sanitize();
    assert_eq!(selected_clears.load(Ordering::SeqCst), 1);
}

#[test]
fn secret_ct_result_clears_unselected_secret_backing() {
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    struct Probe(Arc<AtomicUsize>);

    impl SecureSanitize for Probe {
        fn secure_sanitize(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    let value_clears = Arc::new(AtomicUsize::new(0));
    let error_clears = Arc::new(AtomicUsize::new(0));
    let result = ct::SecretCtResult::secret(
        Probe(Arc::clone(&value_clears)),
        Probe(Arc::clone(&error_clears)),
        ct::Choice::TRUE,
    );
    let mut selected = match result.declassify("test exposes secret result success") {
        Ok(value) => value,
        Err(_) => panic!("expected successful secret result"),
    };

    assert_eq!(value_clears.load(Ordering::SeqCst), 0);
    assert_eq!(error_clears.load(Ordering::SeqCst), 1);
    selected.secure_sanitize();
    assert_eq!(value_clears.load(Ordering::SeqCst), 1);

    struct PublicError;

    let result = ct::SecretCtResult::secret_success([7u8; 4], PublicError, ct::Choice::FALSE);
    assert!(result
        .declassify("test exposes public error metadata")
        .is_err());
}

#[test]
fn secret_ct_mapping_panic_clears_still_owned_values() {
    use std::{
        panic::{catch_unwind, AssertUnwindSafe},
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        },
    };

    struct Probe(Arc<AtomicUsize>);

    impl SecureSanitize for Probe {
        fn secure_sanitize(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    let option_clears = Arc::new(AtomicUsize::new(0));
    let option = ct::SecretCtOption::secret(Probe(Arc::clone(&option_clears)), ct::Choice::TRUE);
    let option_result = catch_unwind(AssertUnwindSafe(|| {
        let _: ct::SecretCtOption<ct::SecretValue<Probe>> =
            option.map_secret(|_| panic!("secret option mapping panic"));
    }));
    assert!(option_result.is_err());
    assert_eq!(option_clears.load(Ordering::SeqCst), 1);

    let value_clears = Arc::new(AtomicUsize::new(0));
    let error_clears = Arc::new(AtomicUsize::new(0));
    let result = ct::SecretCtResult::secret(
        Probe(Arc::clone(&value_clears)),
        Probe(Arc::clone(&error_clears)),
        ct::Choice::FALSE,
    );
    let result_panic = catch_unwind(AssertUnwindSafe(|| {
        let _: ct::SecretCtResult<ct::SecretValue<Probe>, ct::SecretValue<Probe>> =
            result.map_secret_success(|_| panic!("secret result mapping panic"));
    }));
    assert!(result_panic.is_err());
    assert_eq!(value_clears.load(Ordering::SeqCst), 1);
    assert_eq!(error_clears.load(Ordering::SeqCst), 1);
}

#[test]
fn secret_ct_sanitize_panic_is_not_retried() {
    use std::{
        panic::{catch_unwind, AssertUnwindSafe},
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        },
    };

    struct PanicProbe(Arc<AtomicUsize>);

    impl SecureSanitize for PanicProbe {
        fn secure_sanitize(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
            panic!("intentional sanitize panic");
        }
    }

    let clears = Arc::new(AtomicUsize::new(0));
    let option = ct::SecretCtOption::secret(PanicProbe(Arc::clone(&clears)), ct::Choice::FALSE);
    let result = catch_unwind(AssertUnwindSafe(|| {
        let _ = option.declassify("test exposes absent state before panic");
    }));

    assert!(result.is_err());
    assert_eq!(clears.load(Ordering::SeqCst), 1);

    struct SelectedProbe(Arc<AtomicUsize>);

    impl SecureSanitize for SelectedProbe {
        fn secure_sanitize(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    let selected_clears = Arc::new(AtomicUsize::new(0));
    let unselected_clears = Arc::new(AtomicUsize::new(0));
    let result = ct::SecretCtResult::secret(
        SelectedProbe(Arc::clone(&selected_clears)),
        PanicProbe(Arc::clone(&unselected_clears)),
        ct::Choice::TRUE,
    );
    let panic_result = catch_unwind(AssertUnwindSafe(|| {
        let _ = result.declassify("test exposes success before cleanup panic");
    }));

    assert!(panic_result.is_err());
    assert_eq!(selected_clears.load(Ordering::SeqCst), 1);
    assert_eq!(unselected_clears.load(Ordering::SeqCst), 1);
}

#[test]
fn secret_ct_selection_creates_independent_owned_value() {
    use ct::ConditionallySelectable;

    let left = ct::SecretScalar::new([1u8, 2, 3, 4]);
    let right = ct::SecretScalar::new([9u8, 8, 7, 6]);
    let selected = ct::SecretScalar::conditional_select(&left, &right, ct::Choice::TRUE);

    assert_eq!(
        selected.declassify("test reveals selected scalar"),
        [9, 8, 7, 6]
    );
    assert_eq!(
        left.declassify("test reveals still-owned left scalar"),
        [1, 2, 3, 4]
    );
    assert_eq!(
        right.declassify("test reveals still-owned right scalar"),
        [9, 8, 7, 6]
    );

    let zst = ct::SecretCtOption::secret((), ct::Choice::FALSE);
    assert_eq!(zst.declassify("test exposes absent zero-sized value"), None);

    let left_option = ct::SecretCtOption::secret([1u8; 4], ct::Choice::TRUE);
    let right_option = ct::SecretCtOption::secret([2u8; 4], ct::Choice::TRUE);
    let selected_option =
        ct::SecretCtOption::conditional_select(&left_option, &right_option, ct::Choice::TRUE);
    assert_eq!(
        selected_option.declassify("test reveals selected secret option"),
        Some([2u8; 4])
    );
    assert_eq!(
        left_option.declassify("test reveals original left secret option"),
        Some([1u8; 4])
    );
    assert_eq!(
        right_option.declassify("test reveals original right secret option"),
        Some([2u8; 4])
    );

    let left_result = ct::SecretCtResult::secret([3u8; 4], [4u8; 4], ct::Choice::TRUE);
    let right_result = ct::SecretCtResult::secret([5u8; 4], [6u8; 4], ct::Choice::FALSE);
    let selected_result =
        ct::SecretCtResult::conditional_select(&left_result, &right_result, ct::Choice::TRUE);
    assert_eq!(
        selected_result.declassify("test reveals selected secret result"),
        Err([6u8; 4])
    );
    assert_eq!(
        left_result.declassify("test reveals original left secret result"),
        Ok([3u8; 4])
    );
    assert_eq!(
        right_result.declassify("test reveals original right secret result"),
        Err([6u8; 4])
    );
}

#[test]
fn length_error_formats_clearly() {
    let error = LengthError {
        expected: 4,
        actual: 2,
    };

    assert_eq!(
        std::format!("{error}"),
        "length mismatch: expected 4 bytes, got 2 bytes"
    );
}

#[test]
fn secret_pool_report_calculates_public_efficiency_metadata() {
    let report = SecretPoolReport {
        slot_size: 32,
        slot_stride: 48,
        capacity_slots: 64,
        live_slots: 8,
        quarantined_slots: 0,
        payload_capacity_bytes: 2048,
        reserved_bytes: 3072,
        mapped_bytes: 4096,
        locked_bytes: 4096,
        mapping_overhead_bytes: 1024,
        locked_overhead_bytes: 2048,
        page_granule: 4096,
        lock_quota_likely: false,
    };

    assert_eq!(report.storage_efficiency_basis_points(), Some(6666));
    assert_eq!(report.mapping_efficiency_basis_points(), Some(5000));
    assert_eq!(report.lock_efficiency_basis_points(), Some(5000));

    let compatibility = SecretPoolReport {
        mapped_bytes: 0,
        locked_bytes: 0,
        ..report
    };
    assert_eq!(compatibility.mapping_efficiency_basis_points(), None);
    assert_eq!(compatibility.lock_efficiency_basis_points(), None);
}

#[cfg(feature = "zeroize-interop")]
#[test]
fn zeroize_interop_clears_secret_bytes() {
    use zeroize::Zeroize;

    let mut secret = SecretBytes::<4>::from_array([1, 2, 3, 4]);
    secret.zeroize();

    assert_eq!(secret.expose_secret(|bytes| *bytes), [0; 4]);

    #[cfg(feature = "alloc")]
    {
        let mut boxed = SecretBoxBytes::from_slice(&[1, 2, 3, 4]);
        boxed.zeroize();
        assert!(boxed.constant_time_eq(&[0, 0, 0, 0]));
    }
}

#[cfg(feature = "subtle-interop")]
#[test]
fn subtle_interop_compares_secret_bytes() {
    use subtle::ConstantTimeEq;

    let left = SecretBytes::<4>::from_array([1, 2, 3, 4]);
    let same = SecretBytes::<4>::from_array([1, 2, 3, 4]);
    let different = SecretBytes::<4>::from_array([1, 2, 3, 0]);

    assert!(bool::from(left.ct_eq(&same)));
    assert!(!bool::from(left.ct_eq(&different)));

    #[cfg(feature = "alloc")]
    {
        let boxed_left = SecretBoxBytes::from_slice(&[1, 2, 3, 4]);
        let boxed_same = SecretBoxBytes::from_slice(&[1, 2, 3, 4]);
        let boxed_different = SecretBoxBytes::from_slice(&[1, 2, 3, 0]);
        assert!(bool::from(boxed_left.ct_eq(&boxed_same)));
        assert!(!bool::from(boxed_left.ct_eq(&boxed_different)));
    }
}

#[cfg(feature = "serde")]
#[test]
fn serde_interop_loads_fixed_secret_bytes_and_redacts_output() {
    let secret: SecretBytes<4> = serde_json::from_str("[1,2,3,4]").unwrap();

    assert_eq!(secret.expose_secret(|bytes| *bytes), [1, 2, 3, 4]);
    assert_eq!(serde_json::to_string(&secret).unwrap(), "\"<redacted>\"");
}

#[cfg(all(feature = "serde", feature = "alloc"))]
#[test]
fn serde_interop_loads_alloc_secrets_and_redacts_output() {
    let bytes: SecretVec = serde_json::from_str("[1,2,3,4]").unwrap();
    let boxed: SecretBoxBytes = serde_json::from_str("[1,2,3,4]").unwrap();
    let text: SecretString = serde_json::from_str("\"token\"").unwrap();
    let bounded_text: BoundedSecretString<5> = serde_json::from_str("\"token\"").unwrap();

    assert_eq!(bytes.with_secret(|secret| secret.len()), 4);
    assert!(boxed.constant_time_eq(&[1, 2, 3, 4]));
    assert_eq!(text.try_with_secret(str::len), Ok(5));
    assert_eq!(bounded_text.try_with_secret(str::len), Ok(5));
    assert_eq!(serde_json::to_string(&bytes).unwrap(), "\"<redacted>\"");
    assert_eq!(serde_json::to_string(&boxed).unwrap(), "\"<redacted>\"");
    assert_eq!(serde_json::to_string(&text).unwrap(), "\"<redacted>\"");
    assert_eq!(
        serde_json::to_string(&bounded_text).unwrap(),
        "\"<redacted>\""
    );
    assert!(serde_json::from_str::<BoundedSecretString<4>>("\"token\"").is_err());
}

#[cfg(all(feature = "serde", feature = "alloc"))]
#[test]
fn bounded_secret_vec_rejects_oversized_serde_sequences() {
    let accepted: BoundedSecretVec<4> = serde_json::from_str("[1,2,3,4]").unwrap();
    let rejected = serde_json::from_str::<BoundedSecretVec<4>>("[1,2,3,4,5]");

    assert_eq!(accepted.with_secret(|bytes| bytes.len()), 4);
    assert!(rejected.is_err());
    assert_eq!(serde_json::to_string(&accepted).unwrap(), "\"<redacted>\"");
}

#[cfg(all(feature = "serde", feature = "alloc"))]
#[test]
fn bounded_secret_vec_rejects_oversized_serde_byte_inputs() {
    use serde::{
        de::value::{BytesDeserializer, Error as ValueError},
        Deserialize,
    };

    struct OwnedBytesDeserializer(Vec<u8>);

    impl<'de> serde::Deserializer<'de> for OwnedBytesDeserializer {
        type Error = ValueError;

        fn deserialize_any<V>(self, visitor: V) -> Result<V::Value, Self::Error>
        where
            V: serde::de::Visitor<'de>,
        {
            visitor.visit_byte_buf(self.0)
        }

        fn deserialize_bytes<V>(self, visitor: V) -> Result<V::Value, Self::Error>
        where
            V: serde::de::Visitor<'de>,
        {
            visitor.visit_byte_buf(self.0)
        }

        serde::forward_to_deserialize_any! {
            bool i8 i16 i32 i64 u8 u16 u32 u64 f32 f64 char str string
            byte_buf option unit unit_struct newtype_struct seq tuple
            tuple_struct map struct enum identifier ignored_any
        }
    }

    let borrowed = BytesDeserializer::<ValueError>::new(&[1, 2, 3, 4, 5]);
    let owned = OwnedBytesDeserializer(std::vec![1, 2, 3, 4, 5]);

    assert!(BoundedSecretVec::<4>::deserialize(borrowed).is_err());
    assert!(BoundedSecretVec::<4>::deserialize(owned).is_err());
}

#[cfg(feature = "alloc")]
#[test]
fn bounded_secret_vec_enforces_limits_during_mutation() {
    let mut secret = BoundedSecretVec::<4>::from_slice(&[1, 2]).unwrap();

    assert_eq!(secret.extend_from_slice(&[3, 4]), Ok(()));
    assert_eq!(
        secret.extend_from_slice(&[5]),
        Err(SecretVecLimitError {
            maximum: 4,
            actual: 5,
        })
    );
    secret.with_secret(|bytes| assert_eq!(bytes, &[1, 2, 3, 4]));

    let unbounded: SecretVec = secret.into();
    unbounded.with_secret(|bytes| assert_eq!(bytes, &[1, 2, 3, 4]));
}

#[cfg(all(feature = "serde", feature = "alloc"))]
#[test]
fn serde_secret_vec_clamps_untrusted_sequence_size_hint() {
    use serde::de::{value::Error as ValueError, DeserializeSeed, IntoDeserializer, SeqAccess};
    use serde::Deserialize;

    struct HostileHintDeserializer;

    impl<'de> serde::Deserializer<'de> for HostileHintDeserializer {
        type Error = ValueError;

        fn deserialize_any<V>(self, visitor: V) -> Result<V::Value, Self::Error>
        where
            V: serde::de::Visitor<'de>,
        {
            self.deserialize_bytes(visitor)
        }

        fn deserialize_bytes<V>(self, visitor: V) -> Result<V::Value, Self::Error>
        where
            V: serde::de::Visitor<'de>,
        {
            visitor.visit_seq(HostileHintSeq { yielded: false })
        }

        serde::forward_to_deserialize_any! {
            bool i8 i16 i32 i64 u8 u16 u32 u64 f32 f64 char str string
            byte_buf option unit unit_struct newtype_struct seq tuple
            tuple_struct map struct enum identifier ignored_any
        }
    }

    struct HostileHintSeq {
        yielded: bool,
    }

    impl<'de> SeqAccess<'de> for HostileHintSeq {
        type Error = ValueError;

        fn next_element_seed<T>(&mut self, seed: T) -> Result<Option<T::Value>, Self::Error>
        where
            T: DeserializeSeed<'de>,
        {
            if self.yielded {
                return Ok(None);
            }

            self.yielded = true;
            seed.deserialize(7u8.into_deserializer()).map(Some)
        }

        fn size_hint(&self) -> Option<usize> {
            Some(usize::MAX)
        }
    }

    let secret = SecretVec::deserialize(HostileHintDeserializer).unwrap();

    assert_eq!(secret.with_secret(|bytes| bytes[0]), 7);
    assert!(secret.capacity() <= 4096);
}

#[cfg(feature = "std")]
#[test]
fn expiring_error_exposes_source() {
    let error = ExpiringSecretError::Length(LengthError {
        expected: 4,
        actual: 2,
    });

    assert!(std::error::Error::source(&error).is_some());
}

#[cfg(all(
    feature = "std",
    feature = "memory-lock",
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#[test]
fn locked_secret_errors_expose_sources() {
    let length = LockedSecretBytesError::Length(LengthError {
        expected: 4,
        actual: 2,
    });
    let memory = LockedSecretBytesError::Memory(MemoryLockError {
        operation: MemoryLockOperation::Lock,
        errno: 12,
    });
    let generated: LockedSecretBytesGenerateError<std::io::Error> =
        LockedSecretBytesGenerateError::Generate(std::io::Error::other("generation failed"));
    let filled: LockedSecretBytesFillError<std::io::Error> =
        LockedSecretBytesFillError::Generate(std::io::Error::other("fill failed"));
    let initialized: LockedSecretInitializeError<std::io::Error> =
        LockedSecretInitializeError::Generate(std::io::Error::other("initialization failed"));

    assert!(std::error::Error::source(&length).is_some());
    assert!(std::error::Error::source(&memory).is_some());
    assert!(std::error::Error::source(&generated).is_some());
    assert!(std::error::Error::source(&filled).is_some());
    assert!(std::error::Error::source(&initialized).is_some());
}

#[cfg(all(
    feature = "memory-lock",
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#[test]
fn locked_secret_bytes_is_send() {
    fn assert_send<T: Send>() {}
    fn assert_sync<T: Sync>() {}

    assert_send::<LockedSecretBytes<4>>();
    assert_send::<SecretPool<4, 2>>();
    assert_sync::<SecretPool<4, 2>>();
}

#[cfg(all(
    feature = "std",
    feature = "guard-pages",
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64"),
    not(miri)
))]
#[test]
fn guarded_secret_errors_expose_sources() {
    let guarded: GuardedSecretVecGenerateError<std::io::Error> =
        GuardedSecretVecGenerateError::Guard(GuardPageError {
            operation: GuardPageOperation::Protect,
            errno: 13,
        });
    let generated: GuardedSecretVecGenerateError<std::io::Error> =
        GuardedSecretVecGenerateError::Generate(std::io::Error::other("generation failed"));

    assert!(std::error::Error::source(&guarded).is_some());
    assert!(std::error::Error::source(&generated).is_some());
}

#[cfg(all(
    feature = "guard-pages",
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64"),
    not(miri)
))]
#[test]
fn guarded_secret_vec_is_send() {
    fn assert_send<T: Send>() {}

    assert_send::<GuardedSecretVec>();
}

#[test]
fn secret_bytes_round_trip_and_clear() {
    let mut secret = SecretBytes::<4>::from_array([1, 2, 3, 4]);
    let mut out = [0; 4];

    assert!(secret
        .export_to_slice("test exports bytes for round trip", &mut out)
        .is_ok());
    assert_eq!(out, [1, 2, 3, 4]);

    secret.secure_clear();
    assert!(secret
        .export_to_slice("test exports cleared bytes for verification", &mut out)
        .is_ok());
    assert_eq!(out, [0, 0, 0, 0]);

    secret.into_cleared();
}

#[cfg(feature = "multi-pass-clear")]
#[test]
fn secret_bytes_can_clear_multi_pass() {
    let mut secret = SecretBytes::<4>::from_array([1, 2, 3, 4]);

    secret.secure_clear_multi_pass();

    assert!(secret.constant_time_eq(&[0, 0, 0, 0]));
}

#[test]
fn secret_bytes_can_initialize_from_fallible_fn() {
    let mut secret =
        SecretBytes::<4>::try_from_fn(|index| Ok::<u8, &'static str>((index as u8) + 1)).unwrap();

    assert!(secret.constant_time_eq(&[1, 2, 3, 4]));
    assert_eq!(
        SecretBytes::<4>::try_from_fn(|index| {
            if index == 2 {
                Err("generation failed")
            } else {
                Ok(index as u8)
            }
        })
        .err(),
        Some("generation failed")
    );

    secret.secure_clear();
    assert!(secret.constant_time_eq(&[0, 0, 0, 0]));
}

#[test]
fn secret_bytes_can_replace_from_fn() {
    let mut secret = SecretBytes::<4>::from_array([1, 2, 3, 4]);

    secret.replace_from_array([4, 3, 2, 1]);
    assert!(secret.constant_time_eq(&[4, 3, 2, 1]));

    secret.replace_from_fn(|index| (index as u8) + 7);
    assert!(secret.constant_time_eq(&[7, 8, 9, 10]));

    assert_eq!(
        secret.try_replace_from_fn(|index| {
            if index == 2 {
                Err("generation failed")
            } else {
                Ok(index as u8)
            }
        }),
        Err("generation failed")
    );
    assert!(secret.constant_time_eq(&[7, 8, 9, 10]));

    secret
        .try_replace_from_fn(|index| Ok::<u8, &'static str>((index as u8) + 1))
        .unwrap();
    assert!(secret.constant_time_eq(&[1, 2, 3, 4]));

    secret.secure_clear();
}

#[test]
fn secret_bytes_can_transform_in_place() {
    let mut secret = SecretBytes::<4>::from_array([1, 2, 3, 4]);

    secret.transform(|bytes| {
        for byte in bytes.iter_mut() {
            *byte ^= 0xFF;
        }
    });

    assert!(secret.constant_time_eq(&[254, 253, 252, 251]));

    assert_eq!(
        secret.try_transform(|bytes| {
            bytes[0] = 7;
            Ok::<(), &'static str>(())
        }),
        Ok(())
    );
    assert!(secret.constant_time_eq(&[7, 253, 252, 251]));
}

#[test]
fn secret_bytes_can_derive_new_secret() {
    let secret = SecretBytes::<4>::from_array([1, 2, 3, 4]);

    let derived = secret.derive::<8>(|input, output| {
        output[..4].copy_from_slice(input);
        output[4..].copy_from_slice(input);
    });

    assert!(derived.constant_time_eq(&[1, 2, 3, 4, 1, 2, 3, 4]));

    let fallible = secret
        .try_derive::<2, _>(|input, output| {
            output.copy_from_slice(&input[..2]);
            Ok::<(), &'static str>(())
        })
        .unwrap();

    assert!(fallible.constant_time_eq(&[1, 2]));
    assert_eq!(
        secret
            .try_derive::<2, _>(|_input, output| {
                output[0] = 9;
                Err::<(), &'static str>("derive failed")
            })
            .err(),
        Some("derive failed")
    );
}

#[test]
fn length_errors_are_explicit() {
    let mut secret = SecretBytes::<4>::zeroed();

    assert_eq!(
        secret.copy_from_slice(&[1, 2]).err(),
        Some(LengthError {
            expected: 4,
            actual: 2
        })
    );
}

#[test]
fn equality_does_not_short_circuit_on_first_byte() {
    let left = SecretBytes::<4>::from_array([9, 8, 7, 6]);
    let same = SecretBytes::<4>::from_array([9, 8, 7, 6]);
    let different = SecretBytes::<4>::from_array([0, 8, 7, 6]);

    assert!(left.constant_time_eq(&[9, 8, 7, 6]));
    assert!(!left.constant_time_eq(&[9, 8, 7]));
    assert!(!left.constant_time_eq(&[0, 8, 7, 6]));
    assert!(left.constant_time_eq_secret(&same));
    assert!(!left.constant_time_eq_secret(&different));
}

#[cfg(all(
    feature = "asm-compare",
    any(target_arch = "x86_64", target_arch = "aarch64"),
    not(miri)
))]
#[test]
fn assembly_comparison_matches_portable_path() {
    let left = [1_u8, 2, 3, 4, 5, 6, 7, 8];
    let same = [1_u8, 2, 3, 4, 5, 6, 7, 8];
    let different = [1_u8, 2, 3, 4, 5, 6, 7, 0];
    let empty: [u8; 0] = [];

    assert_eq!(
        compare_asm::constant_time_eq_equal_len(&left, &same),
        portable_constant_time_eq_equal_len(&left, &same)
    );
    assert_eq!(
        compare_asm::constant_time_eq_equal_len(&left, &different),
        portable_constant_time_eq_equal_len(&left, &different)
    );
    assert_eq!(
        compare_asm::constant_time_eq_equal_len(&empty, &empty),
        portable_constant_time_eq_equal_len(&empty, &empty)
    );
    assert_eq!(compare_asm::equal_len_choice_bit(&left, &same), 1);
    assert_eq!(compare_asm::equal_len_choice_bit(&left, &different), 0);
    assert_eq!(compare_asm::equal_len_choice_bit(&empty, &empty), 1);
}

#[test]
fn fixed_secret_direct_exposure_borrows_owned_storage() {
    let mut secret = SecretBytes::<4>::from_array([1, 2, 3, 4]);
    let mut owned_address = 0usize;
    secret.transform(|bytes| owned_address = bytes.as_ptr() as usize);

    let sum = secret.expose_secret(|bytes| {
        assert_eq!(bytes.as_ptr() as usize, owned_address);
        bytes
            .iter()
            .copied()
            .fold(0_u8, |total, byte| total.wrapping_add(byte))
    });

    assert_eq!(sum, 10);
}

#[test]
fn fixed_secret_copy_exposure_uses_independent_storage() {
    let mut secret = SecretBytes::<4>::from_array([1, 2, 3, 4]);
    let mut owned_address = 0usize;
    secret.transform(|bytes| owned_address = bytes.as_ptr() as usize);

    let sum =
        secret.export_secret_copy("test observes independent copied secret storage", |bytes| {
            assert_ne!(bytes.as_ptr() as usize, owned_address);
            bytes
                .iter()
                .copied()
                .fold(0_u8, |total, byte| total.wrapping_add(byte))
        });

    assert_eq!(sum, 10);
}

#[cfg(feature = "std")]
#[test]
fn expiring_secret_allows_access_before_expiration() {
    let mut secret =
        ExpiringSecretBytes::<4>::from_array([1, 2, 3, 4], std::time::Duration::from_secs(60));
    let mut out = [0; 4];

    assert!(secret
        .try_export_to_slice("test exports live expiring secret bytes", &mut out)
        .is_ok());
    assert_eq!(out, [1, 2, 3, 4]);
    assert_eq!(
        secret.try_expose_secret(|bytes| bytes[0].wrapping_add(bytes[3])),
        Ok(5)
    );
    assert_eq!(
        secret.try_export_secret_copy("test observes copied expiring secret bytes", |bytes| bytes
            [1]
        .wrapping_add(bytes[2]),),
        Ok(5)
    );
    assert_eq!(secret.try_constant_time_eq(&[1, 2, 3, 4]), Ok(true));

    secret.into_cleared();
}

#[cfg(feature = "std")]
#[test]
fn expiring_secret_clears_and_rejects_after_expiration() {
    let mut secret = ExpiringSecretBytes::<4>::from_array([1, 2, 3, 4], std::time::Duration::ZERO);
    let mut out = [9; 4];

    assert_eq!(
        secret.try_expose_secret(|bytes| bytes[0]),
        Err(SecretExpiredError)
    );
    assert_eq!(
        secret.try_export_to_slice("test exports expiring secret bytes", &mut out),
        Err(ExpiringSecretError::Expired(SecretExpiredError))
    );
}

#[cfg(feature = "std")]
#[test]
fn expiring_secret_replacement_restarts_lifetime() {
    let mut secret =
        ExpiringSecretBytes::<4>::from_array([1, 2, 3, 4], std::time::Duration::from_secs(60));
    let mut out = [0; 4];

    secret.replace_from_slice(&[5, 6, 7, 8]).unwrap();
    assert_eq!(
        secret.try_export_to_slice("test exports expiring secret bytes", &mut out),
        Ok(())
    );
    assert_eq!(out, [5, 6, 7, 8]);

    secret.replace_from_array([8, 7, 6, 5]);
    assert_eq!(
        secret.try_export_to_slice("test exports expiring secret bytes", &mut out),
        Ok(())
    );
    assert_eq!(out, [8, 7, 6, 5]);
}

#[cfg(feature = "std")]
#[test]
fn expiring_secret_can_initialize_from_fallible_fn() {
    let mut secret =
        ExpiringSecretBytes::<4>::try_from_fn(std::time::Duration::from_secs(60), |index| {
            Ok::<u8, &'static str>((index as u8) + 1)
        })
        .unwrap();
    let mut out = [0; 4];

    assert_eq!(
        secret.try_export_to_slice("test exports expiring secret bytes", &mut out),
        Ok(())
    );
    assert_eq!(out, [1, 2, 3, 4]);

    assert_eq!(
        ExpiringSecretBytes::<4>::try_from_fn(std::time::Duration::from_secs(60), |index| {
            if index == 2 {
                Err("generation failed")
            } else {
                Ok(index as u8)
            }
        })
        .err(),
        Some("generation failed")
    );
}

#[cfg(feature = "std")]
#[test]
fn expiring_secret_can_replace_from_fn() {
    let mut secret =
        ExpiringSecretBytes::<4>::from_array([1, 2, 3, 4], std::time::Duration::from_secs(60));
    let mut out = [0; 4];

    secret.replace_from_fn(|index| (index as u8) + 7);
    assert_eq!(
        secret.try_export_to_slice("test exports expiring secret bytes", &mut out),
        Ok(())
    );
    assert_eq!(out, [7, 8, 9, 10]);

    assert_eq!(
        secret.try_replace_from_fn(|index| {
            if index == 2 {
                Err("generation failed")
            } else {
                Ok(index as u8)
            }
        }),
        Err("generation failed")
    );
    assert_eq!(
        secret.try_export_to_slice("test exports expiring secret bytes", &mut out),
        Ok(())
    );
    assert_eq!(out, [7, 8, 9, 10]);

    secret
        .try_replace_from_fn(|index| Ok::<u8, &'static str>((index as u8) + 1))
        .unwrap();
    assert_eq!(
        secret.try_export_to_slice("test exports expiring secret bytes", &mut out),
        Ok(())
    );
    assert_eq!(out, [1, 2, 3, 4]);
}

#[test]
fn monotonic_expiring_secret_allows_access_before_expiration() {
    let ticks = core::cell::Cell::new(10);
    let mut secret =
        MonotonicExpiringSecretBytes::<4, _>::from_array([1, 2, 3, 4], TestClock(&ticks), 5);
    let mut out = [0; 4];

    ticks.set(14);

    assert_eq!(secret.age_ticks(), 4);
    assert!(!secret.is_expired());
    assert_eq!(
        secret.try_export_to_slice("test exports expiring secret bytes", &mut out),
        Ok(())
    );
    assert_eq!(out, [1, 2, 3, 4]);
    assert_eq!(secret.try_constant_time_eq(&[1, 2, 3, 4]), Ok(true));
}

#[test]
fn monotonic_expiring_secret_clears_and_rejects_after_expiration() {
    let ticks = core::cell::Cell::new(10);
    let mut secret =
        MonotonicExpiringSecretBytes::<4, _>::from_array([1, 2, 3, 4], TestClock(&ticks), 5);
    let mut out = [9; 4];

    ticks.set(15);

    assert!(secret.is_expired());
    assert_eq!(
        secret.try_export_to_slice("test exports expiring secret bytes", &mut out),
        Err(ExpiringSecretError::Expired(SecretExpiredError))
    );
    assert_eq!(
        secret.try_expose_secret(|bytes| bytes[0]),
        Err(SecretExpiredError)
    );
}

#[test]
fn monotonic_expiring_secret_zero_max_age_expires_immediately() {
    let ticks = core::cell::Cell::new(10);
    let mut secret =
        MonotonicExpiringSecretBytes::<4, _>::from_array([1, 2, 3, 4], TestClock(&ticks), 0);

    assert_eq!(secret.age_ticks(), 0);
    assert!(secret.is_expired());
    assert_eq!(
        secret.try_expose_secret(|bytes| bytes[0]),
        Err(SecretExpiredError)
    );
}

#[test]
fn monotonic_expiring_secret_replacement_restarts_lifetime() {
    let ticks = core::cell::Cell::new(10);
    let mut secret =
        MonotonicExpiringSecretBytes::<4, _>::from_array([1, 2, 3, 4], TestClock(&ticks), 5);
    let mut out = [0; 4];

    ticks.set(15);
    secret.replace_from_array([5, 6, 7, 8]);

    assert_eq!(secret.age_ticks(), 0);
    assert_eq!(
        secret.try_export_to_slice("test exports expiring secret bytes", &mut out),
        Ok(())
    );
    assert_eq!(out, [5, 6, 7, 8]);

    ticks.set(17);
    secret.replace_from_slice(&[8, 7, 6, 5]).unwrap();
    assert_eq!(secret.age_ticks(), 0);
    assert_eq!(
        secret.try_export_to_slice("test exports expiring secret bytes", &mut out),
        Ok(())
    );
    assert_eq!(out, [8, 7, 6, 5]);
}

#[test]
fn debug_output_is_redacted() {
    let secret = SecretBytes::<3>::from_array(*b"abc");
    let rendered = std::format!("{secret:?}");

    assert!(rendered.contains("redacted"));
    assert!(!rendered.contains("abc"));

    #[cfg(feature = "alloc")]
    {
        let boxed = SecretBoxBytes::from_slice(b"boxed-secret");
        let rendered = std::format!("{boxed:?}");
        assert!(rendered.contains("redacted"));
        assert!(!rendered.contains("boxed-secret"));
    }
}

#[test]
fn generic_secret_uses_closure_access() {
    let mut secret = Secret::new([1, 2, 3, 4]);

    assert_eq!(secret.with_secret(|bytes| bytes[0]), 1);
    secret.with_secret_mut(|bytes| bytes[0] = 9);
    assert_eq!(secret.with_secret(|bytes| bytes[0]), 9);

    secret.into_cleared();
}

#[test]
fn generic_secret_allows_reviewed_user_storage() {
    struct FixedRecord {
        left: [u8; 4],
        right: [u8; 4],
    }

    impl SecureSanitize for FixedRecord {
        fn secure_sanitize(&mut self) {
            self.left.secure_sanitize();
            self.right.secure_sanitize();
        }
    }

    // STORAGE CONTRACT: all bytes are inline and every safe method used by
    // this test inspects or overwrites them in place.
    impl StableSharedSecretStorage for FixedRecord {}
    impl StableMutableSecretStorage for FixedRecord {}

    let mut secret = Secret::new(FixedRecord {
        left: [1; 4],
        right: [2; 4],
    });

    assert_eq!(secret.with_secret(|value| value.left[0]), 1);
    secret.with_secret_mut(|value| value.right[0] = 9);
    assert_eq!(secret.with_secret(|value| value.right[0]), 9);
}

#[test]
fn generic_secret_preserves_clear_only_ownership_for_unstable_types() {
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };

    struct UnstableOwner {
        cleared: Arc<AtomicBool>,
        bytes: std::vec::Vec<u8>,
    }

    impl SecureSanitize for UnstableOwner {
        fn secure_sanitize(&mut self) {
            self.bytes.secure_sanitize();
            self.cleared.store(true, Ordering::SeqCst);
        }
    }

    let cleared = Arc::new(AtomicBool::new(false));
    let secret = Secret::new(UnstableOwner {
        cleared: Arc::clone(&cleared),
        bytes: std::vec![1, 2, 3, 4],
    });

    drop(secret);
    assert!(cleared.load(Ordering::SeqCst));
}

#[test]
fn generic_secret_default_wraps_default_value() {
    let mut secret = Secret::<[u8; 4]>::default();

    assert_eq!(secret.with_secret(|bytes| *bytes), [0; 4]);
    secret.with_secret_mut(|bytes| bytes[0] = 7);
    assert_eq!(secret.with_secret(|bytes| bytes[0]), 7);
}

#[test]
fn consume_once_secret_consumes_once_by_shared_reference() {
    let secret = ConsumeOnceSecret::new(SecretBytes::<4>::from_array([1, 2, 3, 4]));

    let sum = secret.consume(|bytes| {
        let mut out = [0; 4];
        bytes
            .export_to_slice("test exports consumed token bytes", &mut out)
            .unwrap();
        out.iter().copied().fold(0_u8, u8::wrapping_add)
    });

    assert_eq!(sum, Ok(10));
    assert_eq!(
        secret.consume(|_| unreachable!()),
        Err(AlreadyConsumedError)
    );
    assert!(secret.is_claimed());
}

#[test]
fn consume_once_secret_allows_only_one_shared_consumer() {
    let secret = std::sync::Arc::new(ConsumeOnceSecret::new([1_u8, 2, 3, 4]));
    let worker_secret = std::sync::Arc::clone(&secret);
    let start = std::sync::Arc::new(std::sync::Barrier::new(2));
    let worker_start = std::sync::Arc::clone(&start);

    let worker = std::thread::spawn(move || {
        worker_start.wait();
        worker_secret.consume(|bytes| bytes[0])
    });

    start.wait();
    let main_result = secret.consume(|bytes| bytes[0]);
    let worker_result = worker.join().unwrap();

    let successes = usize::from(main_result.is_ok()) + usize::from(worker_result.is_ok());
    let failures = usize::from(main_result == Err(AlreadyConsumedError))
        + usize::from(worker_result == Err(AlreadyConsumedError));

    assert_eq!(successes, 1);
    assert_eq!(failures, 1);
}

#[test]
fn consume_once_secret_clears_when_consume_unwinds_while_shared() {
    use core::sync::atomic::{AtomicBool, Ordering};
    use std::{
        panic::{catch_unwind, AssertUnwindSafe},
        sync::Arc,
    };

    struct Probe(Arc<AtomicBool>);

    impl SecureSanitize for Probe {
        fn secure_sanitize(&mut self) {
            self.0.store(true, Ordering::Release);
        }
    }

    let cleared = Arc::new(AtomicBool::new(false));
    // STORAGE CONTRACT: `Probe` has no shared methods that release storage.
    impl StableSharedSecretStorage for Probe {}

    let secret = Arc::new(ConsumeOnceSecret::new(Probe(Arc::clone(&cleared))));
    let retained_owner = Arc::clone(&secret);

    let result = catch_unwind(AssertUnwindSafe(|| {
        let _ = secret.consume(|_| panic!("consumer panic"));
    }));

    assert!(result.is_err());
    assert!(cleared.load(Ordering::Acquire));
    assert!(retained_owner.is_claimed());
    assert!(Arc::strong_count(&retained_owner) > 1);
}

#[test]
fn consume_once_secret_clears_after_a_closure_returns_an_error() {
    use core::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    struct Probe(Arc<AtomicBool>);

    impl SecureSanitize for Probe {
        fn secure_sanitize(&mut self) {
            self.0.store(true, Ordering::Release);
        }
    }

    // STORAGE CONTRACT: `Probe` has no shared methods that release storage.
    impl StableSharedSecretStorage for Probe {}

    let cleared = Arc::new(AtomicBool::new(false));
    let secret = ConsumeOnceSecret::new(Probe(Arc::clone(&cleared)));
    let result: Result<Result<(), &'static str>, AlreadyConsumedError> =
        secret.consume(|_| Err("operation failed"));

    assert_eq!(result, Ok(Err("operation failed")));
    assert!(cleared.load(Ordering::Acquire));
    assert!(secret.is_claimed());
}

#[test]
fn consume_once_secret_clears_when_never_consumed() {
    use core::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    struct Probe(Arc<AtomicBool>);

    impl SecureSanitize for Probe {
        fn secure_sanitize(&mut self) {
            self.0.store(true, Ordering::Release);
        }
    }

    let cleared = Arc::new(AtomicBool::new(false));
    drop(ConsumeOnceSecret::new(Probe(Arc::clone(&cleared))));

    assert!(cleared.load(Ordering::Acquire));
}

#[test]
fn consume_once_secret_default_debug_and_auto_traits_are_safe() {
    fn assert_send_sync<T: Send + Sync>() {}

    assert_send_sync::<ConsumeOnceSecret<[u8; 4]>>();

    let secret = ConsumeOnceSecret::<[u8; 4]>::default();
    let rendered = std::format!("{secret:?}");

    assert!(rendered.contains("redacted"));
    assert!(!rendered.contains("consumed"));
    assert!(!rendered.contains("[0, 0, 0, 0]"));
}

#[cfg(feature = "split-secret")]
#[test]
fn split_secret_reconstructs_with_all_shares() {
    let split = SplitSecretBytes::<4, 3>::from_array_with_generator(
        [9, 8, 7, 6],
        |share, index| match share {
            0 => index as u8,
            _ => 0x51_u8.wrapping_add((index as u8).wrapping_mul(2)),
        },
    )
    .unwrap();

    assert_eq!(split.shares().len(), 3);
    assert!(split
        .reconstruct()
        .constant_time_eq_secret(&SecretBytes::from_array([9, 8, 7, 6])));
    assert_eq!(
        split.expose_secret_copy(|bytes| bytes.iter().copied().sum::<u8>()),
        30
    );
    assert!(std::format!("{split:?}").contains("redacted"));
}

#[cfg(feature = "split-secret")]
#[test]
fn split_secret_rejects_trivially_constant_masks() {
    assert!(matches!(
        SplitSecretBytes::<4, 3>::from_array_with_generator([9, 8, 7, 6], |_, _| 0),
        Err(SplitSecretError::TrivialMask)
    ));
}

#[cfg(feature = "split-secret")]
#[test]
fn split_secret_rejects_canceling_mask_accumulator() {
    assert!(matches!(
        SplitSecretBytes::<4, 3>::from_array_with_generator([9, 8, 7, 6], |_, index| {
            [1, 2, 3, 4][index]
        }),
        Err(SplitSecretError::TrivialMask)
    ));
}

#[cfg(feature = "split-secret")]
#[test]
fn split_secret_rejects_constant_nonzero_mask_accumulator() {
    assert!(matches!(
        SplitSecretBytes::<4, 3>::from_array_with_generator(
            [9, 8, 7, 6],
            |share, index| match share {
                0 => index as u8,
                _ => (index as u8) ^ 0xA5,
            },
        ),
        Err(SplitSecretError::TrivialMask)
    ));
}

#[cfg(feature = "split-secret")]
#[test]
fn split_secret_accepts_varying_mask_accumulator_with_zero_first_byte() {
    let accumulator = [0x00, 0x44, 0xBB, 0xFF];
    let first_mask = [0x11, 0x22, 0x33, 0x44];
    let split = SplitSecretBytes::<4, 3>::from_array_with_generator(
        [9, 8, 7, 6],
        |share, index| match share {
            0 => first_mask[index],
            _ => first_mask[index] ^ accumulator[index],
        },
    )
    .expect("a varying accumulator must not be rejected because its first byte is zero");

    assert!(split
        .reconstruct()
        .constant_time_eq_secret(&SecretBytes::from_array([9, 8, 7, 6])));
}

#[cfg(feature = "split-secret")]
#[test]
fn split_secret_one_byte_accumulator_rejects_only_zero() {
    assert!(matches!(
        SplitSecretBytes::<1, 2>::from_array_with_generator([9], |_, _| 0),
        Err(SplitSecretError::TrivialMask)
    ));
    assert!(SplitSecretBytes::<1, 2>::from_array_with_generator([9], |_, _| 0xA5).is_ok());
}

#[cfg(feature = "split-secret")]
#[test]
fn split_secret_can_consume_source_secret() {
    let secret = SecretBytes::from_array([9, 8, 7, 6]);
    let split =
        SplitSecretBytes::<4, 3>::from_secret_consuming_with_generator(secret, |share, index| {
            match share {
                0 => index as u8,
                _ => 0x51_u8.wrapping_add((index as u8).wrapping_mul(2)),
            }
        })
        .unwrap();

    assert!(split
        .reconstruct()
        .constant_time_eq_secret(&SecretBytes::from_array([9, 8, 7, 6])));
}

#[cfg(feature = "split-secret")]
#[test]
fn split_secret_requires_multiple_shares() {
    assert!(matches!(
        SplitSecretBytes::<4, 1>::from_array_with_generator([1, 2, 3, 4], |_, _| 0),
        Err(SplitSecretError::TooFewShares)
    ));
}

#[cfg(feature = "hardware-secrets")]
#[test]
fn hardware_secret_error_is_displayable() {
    let error = hardware::HardwareSecretError {
        kind: hardware::HardwareSecretErrorKind::Unavailable,
        code: 0,
    };

    assert!(std::format!("{error}").contains("Unavailable"));
}

#[cfg(feature = "register-scrub")]
#[test]
fn register_scrub_reports_the_executed_scope() {
    let report = register_scrub::scrub_simd_registers();

    #[cfg(all(target_arch = "x86_64", not(miri)))]
    assert!(matches!(
        report,
        register_scrub::RegisterScrubReport::X86CallerSavedXmm
            | register_scrub::RegisterScrubReport::X86AvxYmm0To15
            | register_scrub::RegisterScrubReport::X86WindowsCallerSavedXmmAndYmmUpper
    ));
    #[cfg(all(target_arch = "aarch64", not(miri)))]
    assert_eq!(
        report,
        register_scrub::RegisterScrubReport::Aarch64CallerSavedVector
    );
    #[cfg(miri)]
    assert_eq!(
        report,
        register_scrub::RegisterScrubReport::UnavailableUnderMiri
    );
    #[cfg(all(not(miri), not(any(target_arch = "x86_64", target_arch = "aarch64"))))]
    assert_eq!(
        report,
        register_scrub::RegisterScrubReport::UnsupportedArchitecture
    );
}

#[test]
fn scalar_values_implement_secure_sanitize() {
    fn assert_clears<T>(mut value: T)
    where
        T: crate::wipe_backend::ZeroValidPlainData
            + SecureSanitize
            + Default
            + PartialEq
            + core::fmt::Debug,
    {
        value.secure_sanitize();
        assert_eq!(value, T::default());
    }

    assert_clears(0xA5_u8);
    assert_clears(0xA5A5_u16);
    assert_clears(0xA5A5_A5A5_u32);
    assert_clears(0xDEAD_BEEF_CAFE_BABE_u64);
    assert_clears(u128::MAX);
    assert_clears(usize::MAX);
    assert_clears(-1_i8);
    assert_clears(-2_i16);
    assert_clears(-3_i32);
    assert_clears(-4_i64);
    assert_clears(-5_i128);
    assert_clears(-6_isize);
    assert_clears(true);
    assert_clears('S');
    assert_clears(12.5_f32);
    assert_clears(-42.25_f64);
}

#[test]
fn storage_contracts_cover_fixed_builtins_and_tuples() {
    use crate::{StableMutableSecretStorage, StableSharedSecretStorage};

    fn assert_shared<T: StableSharedSecretStorage + ?Sized>() {}
    fn assert_mutable<T: StableMutableSecretStorage + ?Sized>() {}

    assert_shared::<u64>();
    assert_mutable::<u64>();
    assert_shared::<[u8]>();
    assert_mutable::<[u8]>();
    assert_shared::<[u8; 32]>();
    assert_mutable::<[u8; 32]>();
    assert_shared::<(u8, [u8; 4], SecretBytes<8>)>();
    assert_mutable::<(u8, [u8; 4], SecretBytes<8>)>();
    assert_shared::<(u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, SecretBytes<8>)>();
    assert_mutable::<(u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, SecretBytes<8>)>();
    assert_shared::<SecretBytes<32>>();
    assert_mutable::<SecretBytes<32>>();
    assert_shared::<Secret<[u8; 32]>>();
    assert_mutable::<Secret<[u8; 32]>>();

    #[cfg(feature = "alloc")]
    {
        assert_shared::<SecretBoxBytes>();
        assert_mutable::<SecretBoxBytes>();
    }

    #[cfg(feature = "split-secret")]
    {
        assert_shared::<SplitSecretBytes<4, 2>>();
        assert_mutable::<SplitSecretBytes<4, 2>>();
    }

    #[cfg(feature = "std")]
    {
        assert_shared::<ExpiringSecretBytes<32>>();
        assert_mutable::<ExpiringSecretBytes<32>>();
    }

    #[cfg(feature = "memory-lock")]
    {
        assert_shared::<LockedSecretBytes<32>>();
        assert_mutable::<LockedSecretBytes<32>>();
        assert_shared::<SecretPool<32, 4>>();
        assert_mutable::<SecretPool<32, 4>>();

        fn assert_slot<'pool>()
        where
            SecretPoolSlot<'pool, 32, 4>: StableMutableSecretStorage,
        {
        }

        assert_slot();
    }
}

#[test]
fn tuple_sanitization_runs_left_to_right() {
    use std::{cell::RefCell, rc::Rc, vec::Vec};

    struct OrderedProbe {
        position: u8,
        observed: Rc<RefCell<Vec<u8>>>,
    }

    impl SecureSanitize for OrderedProbe {
        fn secure_sanitize(&mut self) {
            self.observed.borrow_mut().push(self.position);
            self.position = 0;
        }
    }

    let observed = Rc::new(RefCell::new(Vec::new()));
    let mut tuple = (
        OrderedProbe {
            position: 1,
            observed: Rc::clone(&observed),
        },
        OrderedProbe {
            position: 2,
            observed: Rc::clone(&observed),
        },
        OrderedProbe {
            position: 3,
            observed: Rc::clone(&observed),
        },
    );

    tuple.secure_sanitize();

    assert_eq!(*observed.borrow(), [1, 2, 3]);
    assert_eq!(
        (tuple.0.position, tuple.1.position, tuple.2.position),
        (0, 0, 0)
    );
}

#[test]
fn compound_standard_types_implement_secure_sanitize() {
    let mut array = [1_u64, 2, 3, 4];
    let mut optional = Some([9_u8, 8, 7, 6]);
    let mut result = Ok::<[u8; 2], [u8; 2]>([5, 4]);

    array.secure_sanitize();
    optional.secure_sanitize();
    result.secure_sanitize();

    assert_eq!(array, [0; 4]);
    assert_eq!(optional, None);
    assert_eq!(result, Ok([0, 0]));
}

#[test]
fn secure_sanitize_struct_macro_covers_all_fields() {
    crate::secure_sanitize_struct! {
        struct MacroCredentials {
            private_key: SecretBytes<4>,
            nonce: SecretBytes<2>,
        }
    }

    let mut credentials = MacroCredentials {
        private_key: SecretBytes::from_array([1, 2, 3, 4]),
        nonce: SecretBytes::from_array([5, 6]),
    };

    credentials.secure_sanitize();

    assert!(credentials.private_key.constant_time_eq(&[0, 0, 0, 0]));
    assert!(credentials.nonce.constant_time_eq(&[0, 0]));
}

#[test]
fn secure_drop_struct_macro_generates_sanitize_and_drop() {
    crate::secure_drop_struct! {
        struct DropCredentials {
            private_key: SecretBytes<4>,
            nonce: SecretBytes<2>,
        }
    }

    let mut credentials = DropCredentials {
        private_key: SecretBytes::from_array([1, 2, 3, 4]),
        nonce: SecretBytes::from_array([5, 6]),
    };

    credentials.secure_sanitize();

    assert!(credentials.private_key.constant_time_eq(&[0, 0, 0, 0]));
    assert!(credentials.nonce.constant_time_eq(&[0, 0]));

    {
        let credentials = DropCredentials {
            private_key: SecretBytes::from_array([1, 2, 3, 4]),
            nonce: SecretBytes::from_array([5, 6]),
        };

        let _ = &credentials;
    }
}

#[cfg(feature = "alloc")]
#[test]
fn secret_vec_round_trip_and_clear() {
    let mut secret = SecretVec::from_vec(std::vec![1, 2, 3]);

    assert_eq!(secret.with_secret(|bytes| bytes.len()), 3);
    assert!(secret.constant_time_eq(&[1, 2, 3]));
    assert!(!secret.constant_time_eq(&[1, 2]));
    secret.extend_from_slice(&[4]);
    assert_eq!(secret.with_secret(|bytes| bytes[3]), 4);

    secret.clear_secret();
    assert!(secret.is_empty());

    secret.into_cleared();
}

#[cfg(feature = "alloc")]
#[test]
fn secret_box_bytes_owns_fixed_allocation_and_clears_in_place() {
    let boxed = std::vec![1_u8, 2, 3, 4].into_boxed_slice();
    let boxed_address = boxed.as_ptr() as usize;
    let mut secret = SecretBoxBytes::from_boxed_slice(boxed);

    assert_eq!(secret.len(), 4);
    assert!(!secret.is_empty());
    assert_eq!(
        secret.with_secret(|bytes| bytes.as_ptr() as usize),
        boxed_address
    );
    assert!(secret.constant_time_eq(&[1, 2, 3, 4]));

    secret.with_secret_mut(|bytes| bytes[0] = 9);
    assert!(secret.constant_time_eq(&[9, 2, 3, 4]));

    let mut copied = [0_u8; 4];
    secret.copy_to_slice(&mut copied).unwrap();
    assert_eq!(copied, [9, 2, 3, 4]);
    assert_eq!(
        secret.copy_to_slice(&mut [0_u8; 3]),
        Err(LengthError {
            expected: 4,
            actual: 3,
        })
    );

    secret.clear_secret();
    assert_eq!(secret.len(), 4);
    assert!(secret.constant_time_eq(&[0, 0, 0, 0]));
    secret.into_cleared();
}

#[cfg(feature = "alloc")]
#[test]
fn secret_box_bytes_bounded_construction_is_fallible() {
    let secret = SecretBoxBytes::try_zeroed(4, 4).unwrap();
    assert_eq!(secret.len(), 4);
    assert!(secret.constant_time_eq(&[0, 0, 0, 0]));

    assert!(matches!(
        SecretBoxBytes::try_zeroed(5, 4),
        Err(SecretBoxBytesBuildError::TooLong {
            maximum: 4,
            actual: 5
        })
    ));
    assert!(matches!(
        SecretBoxBytes::try_zeroed(usize::MAX, usize::MAX),
        Err(SecretBoxBytesBuildError::Allocation(_))
    ));

    let copied = SecretBoxBytes::try_from_slice(&[1, 2, 3, 4], 4).unwrap();
    assert!(copied.constant_time_eq(&[1, 2, 3, 4]));
    assert!(matches!(
        SecretBoxBytes::try_from_slice(&[1, 2, 3, 4, 5], 4),
        Err(SecretBoxBytesBuildError::TooLong {
            maximum: 4,
            actual: 5
        })
    ));
}

#[cfg(feature = "alloc")]
#[test]
fn secret_box_bytes_bounded_generation_reports_build_and_generator_errors() {
    let generated =
        SecretBoxBytes::try_from_fn_bounded(4, 4, |index| Ok::<u8, &'static str>(index as u8))
            .unwrap();
    assert!(generated.constant_time_eq(&[0, 1, 2, 3]));

    assert!(matches!(
        SecretBoxBytes::try_from_fn_bounded(5, 4, |_| Ok::<u8, &'static str>(0)),
        Err(SecretBoxBytesGenerateError::Build(
            SecretBoxBytesBuildError::TooLong {
                maximum: 4,
                actual: 5
            }
        ))
    ));
    assert!(matches!(
        SecretBoxBytes::try_from_fn_bounded(4, 4, |index| {
            if index == 2 {
                Err("generation failed")
            } else {
                Ok(index as u8)
            }
        }),
        Err(SecretBoxBytesGenerateError::Generate("generation failed"))
    ));
}

#[cfg(feature = "alloc")]
#[test]
fn secret_box_bytes_stages_same_length_replacements() {
    let mut secret = SecretBoxBytes::from_slice(&[1, 2, 3, 4]);
    let old_address = secret.with_secret(|bytes| bytes.as_ptr() as usize);

    secret.replace_from_slice(&[9, 8, 7, 6]).unwrap();
    let replacement_address = secret.with_secret(|bytes| bytes.as_ptr() as usize);
    assert_ne!(old_address, replacement_address);
    assert!(secret.constant_time_eq(&[9, 8, 7, 6]));

    assert_eq!(
        secret.replace_from_slice(&[1, 2, 3]),
        Err(LengthError {
            expected: 4,
            actual: 3,
        })
    );
    assert!(secret.constant_time_eq(&[9, 8, 7, 6]));

    secret
        .replace_from_boxed_slice(std::vec![4_u8, 5, 6, 7].into_boxed_slice())
        .unwrap();
    assert!(secret.constant_time_eq(&[4, 5, 6, 7]));

    assert_eq!(
        secret.replace_from_boxed_slice(std::vec![1_u8, 2].into_boxed_slice()),
        Err(LengthError {
            expected: 4,
            actual: 2,
        })
    );
    assert!(secret.constant_time_eq(&[4, 5, 6, 7]));
}

#[cfg(feature = "alloc")]
#[test]
fn secret_box_bytes_generator_replacement_preserves_old_value_on_failure() {
    let generated = SecretBoxBytes::from_fn(4, |index| (index as u8) + 1);
    assert!(generated.constant_time_eq(&[1, 2, 3, 4]));

    assert_eq!(
        SecretBoxBytes::try_from_fn(4, |index| {
            if index == 2 {
                Err("generation failed")
            } else {
                Ok(index as u8)
            }
        })
        .err(),
        Some("generation failed")
    );

    let mut secret = SecretBoxBytes::from_slice(&[1, 2, 3, 4]);
    secret.replace_from_fn(|index| (index as u8) + 7);
    assert!(secret.constant_time_eq(&[7, 8, 9, 10]));

    assert_eq!(
        secret
            .try_replace_from_fn(|index| {
                if index == 2 {
                    Err("replacement failed")
                } else {
                    Ok(index as u8)
                }
            })
            .err(),
        Some("replacement failed")
    );
    assert!(secret.constant_time_eq(&[7, 8, 9, 10]));

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        secret.replace_from_fn(|index| {
            if index == 2 {
                panic!("replacement panic");
            }
            index as u8
        });
    }));
    assert!(result.is_err());
    assert!(secret.constant_time_eq(&[7, 8, 9, 10]));
}

#[cfg(feature = "alloc")]
#[test]
fn secret_vec_default_is_empty() {
    let mut secret = SecretVec::default();

    assert!(secret.is_empty());
    secret.extend_from_slice(&[1, 2, 3]);
    assert!(secret.constant_time_eq(&[1, 2, 3]));
}

#[cfg(feature = "alloc")]
#[test]
fn secret_vec_can_initialize_from_fn() {
    let mut secret = SecretVec::from_fn(4, |index| (index as u8) + 1);

    assert_eq!(secret.len(), 4);
    assert!(secret.constant_time_eq(&[1, 2, 3, 4]));

    secret.clear_secret();
    assert!(secret.is_empty());

    secret.into_cleared();
}

#[cfg(feature = "alloc")]
#[test]
fn secret_vec_can_initialize_from_fallible_fn() {
    let mut secret =
        SecretVec::try_from_fn(4, |index| Ok::<u8, &'static str>((index as u8) + 1)).unwrap();

    assert_eq!(secret.len(), 4);
    assert!(secret.constant_time_eq(&[1, 2, 3, 4]));
    assert!(matches!(
        SecretVec::try_from_fn(4, |index| {
            if index == 2 {
                Err("generation failed")
            } else {
                Ok(index as u8)
            }
        })
        .err(),
        Some(SecretGenerateError::Generate("generation failed"))
    ));

    secret.clear_secret();
    assert!(secret.is_empty());
}

#[cfg(feature = "alloc")]
#[test]
fn dynamic_secret_fallible_construction_reports_limits_and_capacity_failures() {
    let calls = core::cell::Cell::new(0);
    assert!(matches!(
        SecretVec::try_from_fn_bounded(5, 4, |index| {
            calls.set(calls.get() + 1);
            Ok::<u8, &'static str>(index as u8)
        }),
        Err(SecretGenerateError::Build(SecretAllocationError::TooLong {
            maximum: 4,
            actual: 5
        }))
    ));
    assert_eq!(calls.get(), 0);

    assert!(SecretVec::try_with_capacity(usize::MAX).is_err());
    assert!(matches!(
        SecretVec::try_from_fn(usize::MAX, |_| Ok::<u8, &'static str>(0)),
        Err(SecretGenerateError::Build(
            SecretAllocationError::Allocation(_)
        ))
    ));

    assert!(matches!(
        SecretVec::try_from_slice_bounded(&[1, 2, 3, 4], 3),
        Err(SecretAllocationError::TooLong {
            maximum: 3,
            actual: 4
        })
    ));
    let bounded_bytes = SecretVec::try_from_slice_bounded(&[1, 2, 3, 4], 4).unwrap();
    assert!(bounded_bytes.constant_time_eq(&[1, 2, 3, 4]));

    let char_calls = core::cell::Cell::new(0);
    assert!(matches!(
        SecretString::try_from_chars_bounded(3, 2, |index| {
            char_calls.set(char_calls.get() + 1);
            Ok::<char, &'static str>(if index == 0 { 'a' } else { 'b' })
        }),
        Err(SecretGenerateError::Build(SecretAllocationError::TooLong {
            maximum: 2,
            actual: 12
        }))
    ));
    assert_eq!(char_calls.get(), 0);

    let overflowing_count = usize::MAX / 4 + 1;
    let overflow_calls = core::cell::Cell::new(0);
    assert!(matches!(
        SecretString::try_from_chars(overflowing_count, |_| {
            overflow_calls.set(overflow_calls.get() + 1);
            Ok::<char, &'static str>('x')
        }),
        Err(SecretGenerateError::Build(
            SecretAllocationError::CapacityOverflow
        ))
    ));
    assert_eq!(overflow_calls.get(), 0);
    assert!(SecretString::try_with_capacity(usize::MAX).is_err());

    assert!(matches!(
        SecretString::try_from_secret_str_bounded("secret", 5),
        Err(SecretAllocationError::TooLong {
            maximum: 5,
            actual: 6
        })
    ));
    let bounded_text = SecretString::try_from_secret_str_bounded("secret", 6).unwrap();
    assert!(bounded_text.constant_time_eq("secret"));
}

#[cfg(feature = "alloc")]
#[test]
fn secret_vec_can_replace_secret() {
    let mut secret = SecretVec::with_capacity(8);
    secret.extend_from_slice(&[1, 2, 3, 4]);

    assert!(secret.capacity() >= 8);

    secret.replace_from_slice(&[9, 8]);

    assert_eq!(secret.len(), 2);
    assert!(secret.constant_time_eq(&[9, 8]));

    let larger = [7_u8; 64];
    secret.replace_from_slice(&larger);

    assert_eq!(secret.len(), larger.len());
    assert_eq!(secret.with_secret(|bytes| (bytes[0], bytes[63])), (7, 7));

    secret.replace_from_vec(std::vec![4, 5, 6]);
    assert_eq!(secret.len(), 3);
    assert!(secret.constant_time_eq(&[4, 5, 6]));

    secret.clear_secret();
    assert!(secret.is_empty());
}

#[cfg(feature = "alloc")]
#[test]
fn secret_vec_can_replace_from_fn() {
    let mut secret = SecretVec::from_slice(&[1, 2, 3, 4]);

    secret.replace_from_fn(3, |index| (index as u8) + 7);

    assert_eq!(secret.len(), 3);
    assert!(secret.constant_time_eq(&[7, 8, 9]));

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        secret.replace_from_fn(4, |index| {
            if index == 2 {
                panic!("intentional generator panic");
            }
            index as u8
        });
    }));

    assert!(result.is_err());
    assert!(secret.constant_time_eq(&[7, 8, 9]));

    secret.clear_secret();
    assert!(secret.is_empty());
}

#[cfg(feature = "alloc")]
#[test]
fn secret_vec_try_replace_from_fn_preserves_old_secret_on_error() {
    let mut secret = SecretVec::from_slice(&[1, 2, 3, 4]);

    secret
        .try_replace_from_fn(3, |index| Ok::<u8, &'static str>((index as u8) + 7))
        .unwrap();

    assert!(secret.constant_time_eq(&[7, 8, 9]));
    assert!(matches!(
        secret
            .try_replace_from_fn(4, |index| {
                if index == 2 {
                    Err("generation failed")
                } else {
                    Ok(index as u8)
                }
            })
            .err(),
        Some(SecretGenerateError::Generate("generation failed"))
    ));
    assert!(secret.constant_time_eq(&[7, 8, 9]));

    secret.clear_secret();
    assert!(secret.is_empty());
}

#[cfg(feature = "alloc")]
#[test]
fn secret_vec_grows_exponentially() {
    let mut secret = SecretVec::from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
    let initial_capacity = secret.inner.capacity();

    secret.extend_from_slice(&[9]);

    assert!(secret.inner.capacity() >= initial_capacity.saturating_mul(2));
}

#[cfg(feature = "alloc")]
#[test]
fn secret_string_round_trip_and_clear() {
    let mut secret = SecretString::from_string(std::string::String::from("secret"));

    assert_eq!(secret.try_with_secret(|text| text.len()), Ok(6));
    secret.push_str("-token");
    assert_eq!(
        secret.try_with_secret(|text| text.ends_with("token")),
        Ok(true)
    );
    assert_eq!(
        secret.try_with_secret_mut(|text| text.make_ascii_uppercase()),
        Ok(())
    );
    assert!(secret.constant_time_eq("SECRET-TOKEN"));
    assert!(!secret.constant_time_eq("secret-token"));
    assert_eq!(
        secret.try_with_secret_mut(|text| text.make_ascii_lowercase()),
        Ok(())
    );
    assert!(secret.constant_time_eq("secret-token"));
    assert!(!secret.constant_time_eq("secret"));

    let rendered = std::format!("{secret:?}");
    assert!(rendered.contains("redacted"));
    assert!(!rendered.contains("secret-token"));

    secret.clear_secret();
    assert!(secret.is_empty());
}

#[cfg(feature = "alloc")]
#[test]
fn secret_string_default_is_empty() {
    let mut secret = SecretString::default();

    assert!(secret.is_empty());
    secret.push_str("secret");
    assert!(secret.constant_time_eq("secret"));
}

#[cfg(feature = "alloc")]
#[test]
fn secret_string_can_replace_secret() {
    let mut secret = SecretString::with_capacity(8);
    secret.push_str("secret");

    assert!(secret.capacity() >= 8);

    secret.replace_from_secret_str("rotated");

    assert_eq!(secret.len(), 7);
    assert!(secret.constant_time_eq("rotated"));

    let larger = "larger-rotated-secret";
    secret.replace_from_secret_str(larger);

    assert_eq!(secret.len(), larger.len());
    assert_eq!(secret.try_with_secret(|text| text == larger), Ok(true));

    secret.replace_from_string(std::string::String::from("owned-token"));
    assert_eq!(
        secret.try_with_secret(|text| text == "owned-token"),
        Ok(true)
    );

    secret.clear_secret();
    assert!(secret.is_empty());
}

#[cfg(feature = "alloc")]
#[test]
fn secret_string_can_initialize_from_chars() {
    let mut secret = SecretString::from_chars(4, |index| match index {
        0 => 's',
        1 => 'e',
        2 => 'c',
        _ => '\u{1F512}',
    });

    assert_eq!(
        secret.try_with_secret(|text| text == "sec\u{1F512}"),
        Ok(true)
    );
    assert_eq!(secret.len(), "sec\u{1F512}".len());

    assert!(matches!(
        SecretString::try_from_chars(4, |index| {
            if index == 2 {
                Err("generation failed")
            } else {
                Ok('x')
            }
        })
        .err(),
        Some(SecretGenerateError::Generate("generation failed"))
    ));

    secret.clear_secret();
    assert!(secret.is_empty());
}

#[cfg(feature = "alloc")]
#[test]
fn secret_string_can_replace_from_chars() {
    let mut secret = SecretString::from_secret_str("secret");

    secret.replace_from_chars(3, |index| match index {
        0 => 'k',
        1 => 'e',
        _ => 'y',
    });
    assert!(secret.constant_time_eq("key"));

    assert!(matches!(
        secret
            .try_replace_from_chars(4, |index| {
                if index == 2 {
                    Err("generation failed")
                } else {
                    Ok('z')
                }
            })
            .err(),
        Some(SecretGenerateError::Generate("generation failed"))
    ));
    assert!(secret.constant_time_eq("key"));

    secret
        .try_replace_from_chars(2, |index| {
            Ok::<char, &'static str>(if index == 0 { '\u{00F8}' } else { 'k' })
        })
        .unwrap();
    assert_eq!(secret.try_with_secret(|text| text == "\u{00F8}k"), Ok(true));

    secret.clear_secret();
    assert!(secret.is_empty());
}

#[cfg(feature = "alloc")]
#[test]
fn secret_string_grows_exponentially() {
    let mut secret = SecretString::from_secret_str("abcdefgh");
    let initial_capacity = secret.inner.capacity();

    secret.push_str("i");

    assert!(secret.inner.capacity() >= initial_capacity.saturating_mul(2));
}

#[cfg(feature = "alloc")]
#[test]
fn secret_string_and_secret_vec_transfer_allocations() {
    let bytes = SecretVec::from_vec(std::vec![115, 101, 99, 114, 101, 116]);
    let original_ptr = bytes.inner.as_ptr();
    let text = SecretString::from_secret_vec(bytes).unwrap();

    assert_eq!(text.inner.as_ptr(), original_ptr);
    assert!(text.constant_time_eq("secret"));

    let text_ptr = text.inner.as_ptr();
    let bytes = text.into_secret_vec();

    assert_eq!(bytes.inner.as_ptr(), text_ptr);
    assert!(bytes.constant_time_eq(b"secret"));
}

#[cfg(feature = "alloc")]
#[test]
fn secret_string_rejects_invalid_secret_bytes() {
    let invalid = SecretVec::from_vec(std::vec![0xFF, 0xFE]);

    assert!(SecretString::from_secret_vec(invalid).is_err());
}

#[cfg(feature = "alloc")]
#[test]
fn bounded_secret_string_enforces_utf8_byte_limit() {
    let mut secret = BoundedSecretString::<8>::from_secret_str("secret").unwrap();

    assert_eq!(secret.push_str("!!"), Ok(()));
    assert_eq!(
        secret.push_str("x"),
        Err(SecretStringLimitError {
            maximum: 8,
            actual: 9,
        })
    );
    assert_eq!(secret.try_with_secret(|text| text == "secret!!"), Ok(true));
    assert_eq!(
        BoundedSecretString::<1>::from_secret_str("\u{00F8}").err(),
        Some(SecretStringLimitError {
            maximum: 1,
            actual: 2,
        })
    );

    let unbounded = secret.into_secret_string();
    assert!(unbounded.constant_time_eq("secret!!"));
}

#[cfg(all(
    feature = "memory-lock",
    not(miri),
    any(
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ),
        target_os = "macos",
        target_os = "ios",
        target_os = "android",
        target_os = "windows",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
    )
))]
#[test]
fn locked_secret_string_preserves_utf8_and_lock_lifecycle() {
    let bounded_callback_ran = core::cell::Cell::new(false);
    assert_eq!(
        LockedSecretString::try_from_capacity_bounded_with_protection(
            9,
            8,
            ProtectionRequest::locked(),
            |_| {
                bounded_callback_ran.set(true);
                Ok::<usize, core::convert::Infallible>(0)
            },
        )
        .err(),
        Some(ProtectedSecretTextFillError::CapacityLimit {
            maximum: 8,
            actual: 9,
        })
    );
    assert!(!bounded_callback_ran.get());

    let mut secret = match LockedSecretString::from_secret_str("token") {
        Ok(secret) => secret,
        Err(_) => return,
    };

    assert_eq!(secret.try_with_secret(|text| text == "token"), Ok(true));
    secret.try_push_str("-v2").unwrap();
    secret
        .try_with_secret_mut(|text| text.make_ascii_uppercase())
        .unwrap();
    assert!(secret.constant_time_eq_or_panic("TOKEN-V2"));

    let bytes = secret.into_locked_secret_vec();
    let mut text = LockedSecretString::from_locked_secret_vec(bytes).unwrap();
    assert!(text.constant_time_eq_or_panic("TOKEN-V2"));
    text.clear_secret();
    assert!(text.is_empty());

    let request = ProtectionRequest::locked();
    let generated =
        match LockedSecretString::try_from_capacity_with_protection(8, request, |output| {
            output[..5].copy_from_slice(b"token");
            Ok::<usize, core::convert::Infallible>(5)
        }) {
            Ok(secret) => secret,
            Err(ProtectedSecretTextFillError::Protection(_)) => return,
            Err(error) => panic!("unexpected protected text fill error: {error}"),
        };
    assert!(generated.constant_time_eq_or_panic("token"));

    assert!(matches!(
        LockedSecretString::try_from_capacity_with_protection(1, request, |output| {
            output[0] = 0xff;
            Ok::<usize, core::convert::Infallible>(1)
        }),
        Err(ProtectedSecretTextFillError::Utf8(_))
    ));
}

#[cfg(all(
    feature = "guard-pages",
    not(miri),
    any(
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ),
        target_os = "macos",
        target_os = "ios",
        target_os = "android",
        target_os = "windows",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
    )
))]
#[test]
fn guarded_secret_string_preserves_utf8_and_guard_lifecycle() {
    let bounded_callback_ran = core::cell::Cell::new(false);
    assert_eq!(
        GuardedSecretString::try_from_capacity_bounded_with_protection(
            9,
            8,
            ProtectionRequest::guarded(),
            |_| {
                bounded_callback_ran.set(true);
                Ok::<usize, core::convert::Infallible>(0)
            },
        )
        .err(),
        Some(ProtectedSecretTextFillError::CapacityLimit {
            maximum: 8,
            actual: 9,
        })
    );
    assert!(!bounded_callback_ran.get());

    let mut secret = match GuardedSecretString::from_secret_str("token") {
        Ok(secret) => secret,
        Err(_) => return,
    };

    assert_eq!(secret.try_with_secret(|text| text == "token"), Ok(true));
    secret.try_push_str("-v2").unwrap();
    secret
        .try_with_secret_mut(|text| text.make_ascii_uppercase())
        .unwrap();
    assert!(secret.constant_time_eq_or_panic("TOKEN-V2"));

    let bytes = secret.into_guarded_secret_vec();
    let mut text = GuardedSecretString::from_guarded_secret_vec(bytes).unwrap();
    assert!(text.constant_time_eq_or_panic("TOKEN-V2"));
    text.clear_secret();
    assert!(text.is_empty());

    let request = ProtectionRequest::guarded();
    let generated = GuardedSecretString::try_from_capacity_with_protection(8, request, |output| {
        output[..5].copy_from_slice(b"token");
        Ok::<usize, core::convert::Infallible>(5)
    })
    .unwrap();
    assert!(generated.constant_time_eq_or_panic("token"));

    assert!(matches!(
        GuardedSecretString::try_from_capacity_with_protection(1, request, |output| {
            output[0] = 0xff;
            Ok::<usize, core::convert::Infallible>(1)
        }),
        Err(ProtectedSecretTextFillError::Utf8(_))
    ));
}

#[test]
fn canonical_wipe_clears_slice() {
    let mut bytes = [0xA5; 16];

    crate::wipe::bytes(&mut bytes);

    assert_eq!(bytes, [0; 16]);
}

#[test]
fn canonical_wipe_array_and_trait_reach_same_backend() {
    use crate::wipe::Wipe as _;

    let mut by_function = [0xA5; 16];
    let mut by_trait = [0x5A; 16];

    crate::wipe::array(&mut by_function);
    by_trait.wipe();

    assert_eq!(by_function, [0; 16]);
    assert_eq!(by_trait, [0; 16]);
}

#[cfg(feature = "multi-pass-clear")]
#[test]
fn multi_pass_wipe_clears_slice() {
    let mut bytes = [0xA5; 16];

    wipe::bytes_multi_pass(&mut bytes);

    assert_eq!(bytes, [0; 16]);
}

#[cfg(feature = "alloc")]
#[test]
fn canonical_wipe_clears_alloc_types_when_enabled() {
    let mut bytes = std::vec![0xBB; 8];
    let mut text = std::string::String::from("secret");

    crate::wipe::vec(&mut bytes);
    crate::wipe::string(&mut text);

    assert!(bytes.is_empty());
    assert!(text.is_empty());
}

#[cfg(all(feature = "alloc", feature = "multi-pass-clear"))]
#[test]
fn multi_pass_wipe_clears_alloc_types_when_enabled() {
    let mut bytes = SecretVec::from_slice(&[1, 2, 3]);
    let mut text = SecretString::from_secret_str("secret");
    let mut ordinary = std::vec![0xBB; 8];
    let mut ordinary_text = std::string::String::from("secret");

    bytes.clear_secret_multi_pass();
    text.clear_secret_multi_pass();
    crate::wipe::vec_multi_pass(&mut ordinary);
    crate::wipe::string_multi_pass(&mut ordinary_text);

    assert!(bytes.is_empty());
    assert!(text.is_empty());
    assert!(ordinary.is_empty());
    assert!(ordinary_text.is_empty());
}

#[cfg(feature = "alloc")]
#[test]
fn alloc_standard_types_implement_secure_sanitize() {
    let mut boxed = std::boxed::Box::new([1_u64, 2, 3]);
    let mut values = std::vec![7_u32, 8, 9];
    let mut text = std::string::String::from("secret");

    boxed.secure_sanitize();
    values.secure_sanitize();
    text.secure_sanitize();

    assert_eq!(*boxed, [0; 3]);
    assert!(values.is_empty());
    assert!(text.is_empty());
}

#[test]
fn wipe_on_drop_wrapper_is_explicit() {
    let mut secret = crate::wipe::WipeOnDrop::new([1, 2, 3, 4]);

    assert_eq!(secret.with_secret(|bytes| bytes[2]), 3);
    secret.with_secret_mut(|bytes| bytes[2] = 9);
    assert_eq!(secret.with_secret(|bytes| bytes[2]), 9);

    secret.into_cleared();
}

#[cfg(feature = "cache-flush")]
#[test]
fn cache_flush_sanitize_clears_slice_and_secret_bytes() {
    let mut bytes = [0xA5; 16];
    let capability = crate::cache_flush::cache_flush_capability();
    let result = crate::cache_flush::cache_flush_sanitize_array(&mut bytes);
    assert_eq!(bytes, [0; 16]);
    assert_eq!(result.is_ok(), capability.is_ok());
    if let (Ok(report), Ok(capability)) = (result, capability) {
        assert_eq!(report.cache_line_size(), capability.cache_line_size());
        assert_eq!(report.bytes_covered(), bytes.len());
        assert!(report.cache_lines_flushed() >= 1);
    }
    #[cfg(miri)]
    assert_eq!(
        result,
        Err(crate::cache_flush::CacheFlushError::UnavailableUnderMiri)
    );
    #[cfg(all(not(miri), not(target_arch = "x86_64")))]
    assert_eq!(
        result,
        Err(crate::cache_flush::CacheFlushError::UnsupportedArchitecture)
    );

    let mut secret = SecretBytes::<4>::from_array([1, 2, 3, 4]);
    let secret_result = secret.secure_clear_and_flush();
    assert!(secret.constant_time_eq(&[0, 0, 0, 0]));
    assert_eq!(secret_result.is_ok(), capability.is_ok());

    let mut wrapped = crate::cache_flush::CacheFlushOnDrop::new([1, 2, 3, 4]);
    wrapped.with_secret_mut(|value| value[0] = 9);
    assert_eq!(wrapped.with_secret(|value| value[0]), 9);
    assert_eq!(wrapped.into_cleared().is_ok(), capability.is_ok());
}

#[cfg(all(feature = "cache-flush", feature = "alloc"))]
#[test]
fn cache_flush_sanitize_clears_alloc_types() {
    let mut bytes = SecretVec::from_slice(&[1, 2, 3]);
    let mut text = SecretString::from_secret_str("secret");

    let bytes_result = bytes.clear_secret_and_flush();
    let text_result = text.clear_secret_and_flush();

    assert!(bytes.is_empty());
    assert!(text.is_empty());
    assert_eq!(bytes_result.is_ok(), text_result.is_ok());
}

#[cfg(all(
    feature = "memory-lock",
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64"),
    not(miri)
))]
#[test]
fn protection_request_profiles_are_explicit() {
    let locked = ProtectionRequest::locked();
    assert_eq!(locked.memory_lock, Requirement::Required);
    assert_eq!(locked.dump_exclusion, Requirement::Preferred);
    assert_eq!(
        locked.fork.requirement,
        if cfg!(feature = "require-fork-exclusion") {
            Requirement::Required
        } else {
            Requirement::Preferred
        }
    );
    assert_eq!(locked.fork.policy, ForkPolicy::Exclude);
    assert_eq!(locked.guard_pages, Requirement::NotRequested);

    let guarded = ProtectionRequest::guarded();
    assert_eq!(guarded.memory_lock, Requirement::NotRequested);
    assert_eq!(guarded.guard_pages, Requirement::Required);

    let locked_guarded = ProtectionRequest::locked_guarded();
    assert_eq!(locked_guarded.memory_lock, Requirement::Required);
    assert_eq!(locked_guarded.guard_pages, Requirement::Required);
}

#[cfg(feature = "profile-hardened-native")]
#[test]
fn hardened_native_profile_maps_to_explicit_policy() {
    let request = ProtectionRequest::profile_hardened_native();
    assert_eq!(request.memory_lock, Requirement::Required);
    assert_eq!(request.dump_exclusion, Requirement::Preferred);
    assert_eq!(request.fork.policy, ForkPolicy::Exclude);
    assert_eq!(request.fork.requirement, Requirement::Preferred);
    assert_eq!(request.guard_pages, Requirement::NotRequested);
    assert_eq!(request.canary, Requirement::Required);
    assert_eq!(request.cache_policy, Requirement::NotRequested);
}

#[cfg(all(feature = "profile-hardened-native", not(miri)))]
#[test]
fn hardened_native_type_constructors_select_the_profile_request() {
    let expected = ProtectionRequest::profile_hardened_native();

    let bytes = LockedSecretBytes::<0>::zeroed_hardened_native().unwrap();
    assert_eq!(bytes.protection_request(), expected);

    let vector = LockedSecretVec::with_capacity_hardened_native(0).unwrap();
    assert_eq!(vector.protection_request(), expected);

    let text = LockedSecretString::with_capacity_hardened_native(0).unwrap();
    assert_eq!(text.protection_request(), expected);

    let pool = SecretPool::<1, 0>::new_hardened_native().unwrap();
    assert_eq!(pool.protection_request(), expected);
}

#[cfg(feature = "profile-guarded-native")]
#[test]
fn guarded_native_profile_requires_guard_pages() {
    let request = ProtectionRequest::profile_guarded_native();
    assert_eq!(request.memory_lock, Requirement::Required);
    assert_eq!(request.guard_pages, Requirement::Required);
    assert_eq!(request.canary, Requirement::Required);
}

#[cfg(all(feature = "profile-guarded-native", not(miri)))]
#[test]
fn guarded_native_type_constructors_select_the_profile_request() {
    let expected = ProtectionRequest::profile_guarded_native();
    let vector = match GuardedSecretVec::with_capacity_guarded_native(0) {
        Ok(vector) => vector,
        Err(error) => {
            assert_eq!(error.partial_report.fork.policy, expected.fork.policy);
            assert_ne!(
                error.partial_report.memory_lock,
                ProtectionState::NotRequested
            );
            assert_ne!(
                error.partial_report.guard_pages,
                ProtectionState::NotRequested
            );
            assert_ne!(error.partial_report.canary, ProtectionState::NotRequested);
            return;
        }
    };
    assert_eq!(vector.protection_request(), expected);
    drop(vector);

    let text = match GuardedSecretString::with_capacity_guarded_native(0) {
        Ok(text) => text,
        Err(error) => {
            assert_eq!(error.partial_report.fork.policy, expected.fork.policy);
            assert_ne!(
                error.partial_report.memory_lock,
                ProtectionState::NotRequested
            );
            assert_ne!(
                error.partial_report.guard_pages,
                ProtectionState::NotRequested
            );
            assert_ne!(error.partial_report.canary, ProtectionState::NotRequested);
            return;
        }
    };
    assert_eq!(text.protection_request(), expected);
}

#[cfg(feature = "profile-hardened-linux")]
#[test]
fn hardened_linux_profile_requires_fork_exclusion() {
    let request = ProtectionRequest::profile_hardened_linux();
    assert_eq!(request.memory_lock, Requirement::Required);
    assert_eq!(request.fork.policy, ForkPolicy::Exclude);
    assert_eq!(request.fork.requirement, Requirement::Required);
    assert_eq!(request.canary, Requirement::Required);
}

#[cfg(all(feature = "profile-hardened-linux", not(miri)))]
#[test]
fn hardened_linux_type_constructors_select_the_profile_request() {
    let expected = ProtectionRequest::profile_hardened_linux();

    let bytes = LockedSecretBytes::<0>::zeroed_hardened_linux().unwrap();
    assert_eq!(bytes.protection_request(), expected);

    let vector = LockedSecretVec::with_capacity_hardened_linux(0).unwrap();
    assert_eq!(vector.protection_request(), expected);

    let text = LockedSecretString::with_capacity_hardened_linux(0).unwrap();
    assert_eq!(text.protection_request(), expected);

    let pool = SecretPool::<1, 0>::new_hardened_linux().unwrap();
    assert_eq!(pool.protection_request(), expected);
}

#[cfg(all(
    feature = "memory-lock",
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64"),
    not(miri)
))]
#[test]
fn explicit_protection_reports_achieved_native_state() {
    let request = ProtectionRequest {
        memory_lock: Requirement::Preferred,
        dump_exclusion: Requirement::NotRequested,
        fork: ForkProtectionRequest::inherit(),
        guard_pages: Requirement::NotRequested,
        canary: if cfg!(feature = "canary-check") {
            Requirement::Required
        } else {
            Requirement::NotRequested
        },
        cache_policy: Requirement::NotRequested,
    };
    let secret = LockedSecretBytes::<32>::zeroed_with_protection(request).unwrap();
    let report = secret.protection_report();

    assert_eq!(report.mapping, ProtectionState::Established);
    assert_eq!(report.requested_bytes, 32);
    assert!(report.mapped_bytes >= 32);
    assert_eq!(report.dump_exclusion, ProtectionState::NotRequested);
    assert_eq!(report.fork.policy, ForkPolicy::Inherit);
    assert_eq!(report.fork.state, ProtectionState::Established);
    assert!(matches!(
        report.memory_lock,
        ProtectionState::Established | ProtectionState::Failed { .. }
    ));
    assert_eq!(
        report.locked_bytes == report.mapped_bytes,
        report.memory_lock == ProtectionState::Established
    );
}

#[cfg(all(
    feature = "std",
    feature = "memory-lock",
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64"),
    not(miri)
))]
#[test]
fn wipe_child_policy_zeroes_payload_in_forked_child() {
    let request = ProtectionRequest {
        memory_lock: Requirement::NotRequested,
        dump_exclusion: Requirement::NotRequested,
        fork: ForkProtectionRequest::wipe_child(Requirement::Preferred),
        guard_pages: Requirement::NotRequested,
        canary: if cfg!(feature = "canary-check") {
            Requirement::Required
        } else {
            Requirement::NotRequested
        },
        cache_policy: Requirement::NotRequested,
    };
    let mut secret = match LockedSecretBytes::<4>::zeroed_with_protection(request) {
        Ok(secret) => secret,
        Err(_) => return,
    };
    secret.try_copy_from_slice(&[1, 2, 3, 4]).unwrap();

    assert_eq!(
        secret.protection_report().fork.policy,
        ForkPolicy::WipeChild
    );
    if secret.protection_report().fork.state != ProtectionState::Established {
        return;
    }

    assert!(secret.child_observes_zero_payload_after_fork_for_test());
    assert_eq!(secret.try_constant_time_eq(&[1, 2, 3, 4]), Ok(true));
}

#[cfg(all(
    feature = "memory-lock",
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64"),
    not(miri)
))]
#[test]
fn required_unavailable_protection_fails_before_mapping() {
    let request = ProtectionRequest {
        memory_lock: Requirement::NotRequested,
        dump_exclusion: Requirement::NotRequested,
        fork: ForkProtectionRequest::inherit(),
        guard_pages: Requirement::Required,
        canary: Requirement::NotRequested,
        cache_policy: Requirement::NotRequested,
    };
    let error = LockedSecretBytes::<32>::zeroed_with_protection(request).unwrap_err();

    assert_eq!(error.failure.control, ProtectionControl::GuardPages);
    assert_eq!(error.partial_report.mapped_bytes, 0);
    assert_eq!(error.rollback, RollbackReport::not_needed());
}

#[cfg(all(
    feature = "memory-lock",
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64"),
    not(miri)
))]
#[test]
fn locked_growth_preserves_controls_accepted_for_empty_storage() {
    let request = ProtectionRequest {
        memory_lock: Requirement::NotRequested,
        dump_exclusion: Requirement::NotRequested,
        fork: ForkProtectionRequest::inherit(),
        guard_pages: Requirement::Preferred,
        canary: Requirement::NotRequested,
        cache_policy: Requirement::NotRequested,
    };
    let mut secret = LockedSecretVec::with_capacity_with_protection(1, request).unwrap();
    secret.try_extend_from_slice(&[0xA5]).unwrap();
    secret.mark_guard_pages_established_for_replacement_test();
    let original_report = *secret.protection_report();

    let error = secret.try_extend_from_slice(&[0x5A]).unwrap_err();

    assert!(matches!(
        error,
        SecretIntegrityError::Operation(MemoryLockError {
            operation: MemoryLockOperation::Map,
            ..
        })
    ));
    assert_eq!(secret.try_constant_time_eq(&[0xA5]), Ok(true));
    assert_eq!(secret.protection_request(), request);
    assert_eq!(*secret.protection_report(), original_report);
}

#[cfg(all(
    feature = "guard-pages",
    not(feature = "memory-lock"),
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64"),
    not(miri)
))]
#[test]
fn required_lock_failure_rolls_back_guarded_mapping() {
    let request = ProtectionRequest {
        memory_lock: Requirement::Required,
        dump_exclusion: Requirement::NotRequested,
        fork: ForkProtectionRequest::inherit(),
        guard_pages: Requirement::Required,
        canary: Requirement::NotRequested,
        cache_policy: Requirement::NotRequested,
    };
    let error = GuardedSecretVec::with_capacity_with_protection(32, request).unwrap_err();

    assert_eq!(error.failure.control, ProtectionControl::MemoryLock);
    assert_eq!(
        error.partial_report.guard_pages,
        ProtectionState::Established
    );
    assert!(error.partial_report.mapped_bytes >= 32);
    assert_eq!(error.rollback.unlock, RollbackState::NotNeeded);
    assert_eq!(error.rollback.unmap, RollbackState::Completed);
}

#[cfg(all(
    feature = "guard-pages",
    not(feature = "memory-lock"),
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64"),
    not(miri)
))]
#[test]
fn guarded_growth_preserves_controls_accepted_for_empty_storage() {
    let request = ProtectionRequest {
        memory_lock: Requirement::Preferred,
        dump_exclusion: Requirement::NotRequested,
        fork: ForkProtectionRequest::inherit(),
        guard_pages: Requirement::Required,
        canary: Requirement::NotRequested,
        cache_policy: Requirement::NotRequested,
    };
    let mut secret = GuardedSecretVec::with_capacity_with_protection(1, request).unwrap();
    secret.try_extend_from_slice(&[0xA5]).unwrap();
    secret.mark_memory_lock_established_for_replacement_test();
    let original_report = *secret.protection_report();
    let growth_bytes = std::vec![0x5A; secret.capacity() + 1];

    let error = secret.try_extend_from_slice(&growth_bytes).unwrap_err();

    assert!(matches!(
        error,
        SecretIntegrityError::Operation(GuardPageError {
            operation: GuardPageOperation::Lock,
            ..
        })
    ));
    assert_eq!(secret.try_constant_time_eq(&[0xA5]), Ok(true));
    assert_eq!(secret.protection_request(), request);
    assert_eq!(*secret.protection_report(), original_report);
}

#[cfg(all(
    feature = "guard-pages",
    not(feature = "memory-lock"),
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64"),
    not(miri)
))]
#[test]
fn preferred_guarded_controls_report_independent_fork_support() {
    let request = ProtectionRequest {
        memory_lock: Requirement::Preferred,
        dump_exclusion: Requirement::Preferred,
        fork: ForkProtectionRequest::exclude(Requirement::Preferred),
        guard_pages: Requirement::Required,
        canary: Requirement::NotRequested,
        cache_policy: Requirement::NotRequested,
    };
    let secret = GuardedSecretVec::with_capacity_with_protection(32, request).unwrap();
    let report = secret.protection_report();

    assert_eq!(report.guard_pages, ProtectionState::Established);
    assert_eq!(report.memory_lock, ProtectionState::Unsupported);
    assert_eq!(report.dump_exclusion, ProtectionState::Unsupported);
    assert_eq!(report.fork.policy, ForkPolicy::Exclude);
    assert_eq!(report.fork.state, ProtectionState::Established);
    assert_eq!(report.locked_bytes, 0);
}

#[cfg(all(
    feature = "page-seal",
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64"),
    not(miri)
))]
#[test]
fn sealed_secret_bytes_reseal_after_scoped_access() {
    let mut secret = SealedSecretBytes::<4>::from_array([1, 2, 3, 4]).unwrap();

    assert!(secret.is_sealed());
    assert_eq!(
        secret.protection_request(),
        ProtectionRequest::page_sealed()
    );
    assert_eq!(
        secret.protection_report().fork.policy,
        ForkPolicy::WipeChild
    );
    assert_eq!(
        secret.protection_report().fork.state,
        ProtectionState::Established
    );
    assert_eq!(secret.len(), 4);
    assert_eq!(
        secret.try_with_secret(|bytes| *bytes).unwrap(),
        [1, 2, 3, 4]
    );
    assert!(secret.is_sealed());

    secret.try_with_secret_mut(|bytes| bytes[0] = 9).unwrap();
    assert!(secret.is_sealed());
    assert_eq!(secret.try_constant_time_eq(&[9, 2, 3, 4]), Ok(true));

    secret.try_clear_secret().unwrap();
    assert!(secret.is_sealed());
    assert_eq!(
        secret.try_with_secret(|bytes| *bytes).unwrap(),
        [0, 0, 0, 0]
    );

    secret
        .try_with_secret_mut(|bytes| bytes.copy_from_slice(&[5, 6, 7, 8]))
        .unwrap();
    secret.try_secure_sanitize().unwrap();
    assert_eq!(
        secret.try_with_secret(|bytes| *bytes).unwrap(),
        [0, 0, 0, 0]
    );
    assert!(std::format!("{secret:?}").contains("redacted"));
}

#[cfg(all(
    feature = "page-seal",
    feature = "std",
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64"),
    not(miri)
))]
#[test]
fn sealed_secret_bytes_reseal_after_unwind() {
    let mut secret = SealedSecretBytes::<4>::from_array([1, 2, 3, 4]).unwrap();
    let panic_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = secret.try_with_secret(|_| panic!("sealed access panic"));
    }));

    assert!(panic_result.is_err());
    assert!(secret.is_sealed());
    assert_eq!(secret.try_constant_time_eq(&[1, 2, 3, 4]), Ok(true));
}

#[cfg(all(
    feature = "page-seal",
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64"),
    not(miri)
))]
#[test]
fn sealed_secret_bytes_wipe_exposed_payload_in_forked_child() {
    let mut secret = SealedSecretBytes::<4>::from_array([1, 2, 3, 4]).unwrap();

    assert!(secret
        .child_observes_zero_during_exposed_fork_for_test()
        .unwrap());
    assert!(secret.is_sealed());
    assert_eq!(
        secret.try_with_secret(|bytes| *bytes).unwrap(),
        [1, 2, 3, 4]
    );
}

#[cfg(all(
    feature = "page-seal",
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64"),
    not(miri)
))]
#[test]
fn sealed_secret_bytes_reject_nested_state_and_retire_on_partial_reseal_failure() {
    let mut nested = SealedSecretBytes::<4>::zeroed().unwrap();
    nested.mark_access_in_progress_for_test().unwrap();
    assert_eq!(
        nested.try_with_secret(|_| ()),
        Err(SealedSecretAccessError::AccessInProgress)
    );

    let mut retired = SealedSecretBytes::<4>::from_array([1, 2, 3, 4]).unwrap();
    retired.fail_next_seal_for_test();
    assert!(matches!(
        retired.try_with_secret(|bytes| bytes[0]),
        Err(SealedSecretAccessError::Guard(_))
    ));
    assert!(retired.is_retired());
    assert_eq!(
        retired.try_with_secret(|_| ()),
        Err(SealedSecretAccessError::Retired)
    );
}

#[cfg(all(
    feature = "page-seal",
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64"),
    not(miri)
))]
#[test]
fn sealed_secret_bytes_retires_after_partial_unseal_failure() {
    let mut secret = SealedSecretBytes::<4>::from_array([1, 2, 3, 4]).unwrap();
    secret.fail_next_unseal_for_test();

    assert!(matches!(
        secret.try_secure_sanitize(),
        Err(SealedSecretAccessError::Guard(_))
    ));
    assert!(!secret.is_sealed());
    assert!(secret.is_retired());
    assert_eq!(
        secret.try_with_secret(|_| ()),
        Err(SealedSecretAccessError::Retired)
    );
}

#[cfg(all(
    feature = "page-seal",
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64"),
    not(miri)
))]
#[test]
fn sealed_secret_bytes_recovers_and_retires_multi_page_mapping() {
    const N: usize = 128 * 1024;
    let mut secret = SealedSecretBytes::<N>::zeroed().unwrap();
    secret
        .try_with_secret_mut(|bytes| {
            bytes[0] = 0xAA;
            bytes[N - 1] = 0x55;
        })
        .unwrap();

    secret.fail_next_seal_for_test();
    assert!(matches!(
        secret.try_with_secret(|_| ()),
        Err(SealedSecretAccessError::Guard(_))
    ));
    assert!(secret.is_retired());
    assert_eq!(
        secret.try_with_secret(|_| ()),
        Err(SealedSecretAccessError::Retired)
    );
}

#[cfg(all(
    feature = "page-seal",
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64"),
    not(miri)
))]
#[test]
fn sealed_secret_bytes_remains_poisoned_after_normalization_and_unmap_failures() {
    const N: usize = 128 * 1024;
    let mut secret = SealedSecretBytes::<N>::zeroed().unwrap();
    secret
        .try_with_secret_mut(|bytes| {
            bytes[0] = 0xAA;
            bytes[N - 1] = 0x55;
        })
        .unwrap();

    secret.fail_normalization_page_for_test(1);
    secret.fail_next_unmap_for_test();
    secret.fail_next_seal_for_test();
    assert!(matches!(
        secret.try_with_secret(|_| ()),
        Err(SealedSecretAccessError::Guard(_))
    ));
    assert!(secret.is_poisoned());
    assert_eq!(
        secret.try_with_secret(|_| ()),
        Err(SealedSecretAccessError::Poisoned)
    );
    assert_eq!(
        secret.try_with_secret_mut(|_| ()),
        Err(SealedSecretAccessError::Poisoned)
    );
    assert_eq!(
        secret.try_clear_secret(),
        Err(SealedSecretAccessError::Poisoned)
    );
    assert_eq!(
        secret.try_secure_sanitize(),
        Err(SealedSecretAccessError::Poisoned)
    );
}

#[cfg(all(
    feature = "page-seal",
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64"),
    not(miri)
))]
#[test]
fn sealed_secret_explicit_close_reports_failures_and_supports_retry() {
    const N: usize = 128 * 1024;
    let mut secret = SealedSecretBytes::<N>::zeroed().unwrap();
    secret
        .try_with_secret_mut(|bytes| {
            bytes[0] = 0xAA;
            bytes[N - 1] = 0x55;
        })
        .unwrap();

    secret.fail_normalization_page_for_test(1);
    secret.fail_next_unmap_for_test();
    let error = secret.try_close().unwrap_err();
    let report = error.report();
    assert_eq!(error.operation(), GuardPageOperation::Protect);
    assert_eq!(error.errno(), 0);
    assert!(report.normalization_failed());
    assert_eq!(report.unlock, CleanupState::NotNeeded);
    assert_eq!(report.unmap, CleanupState::NotNeeded);
    assert!(secret.is_poisoned());
    assert_eq!(secret.erased_page_is_zero_for_test(0), Ok(true));
    assert_eq!(
        secret.try_with_secret(|_| ()),
        Err(SealedSecretAccessError::Poisoned)
    );

    let error = secret.try_close().unwrap_err();
    let report = error.report();
    assert_eq!(report.normalization, CleanupState::Completed);
    assert!(report.unmap_failed());
    assert!(secret.is_poisoned());

    secret.try_close().unwrap();
    assert!(secret.is_retired());
    assert_eq!(
        secret.try_with_secret(|_| ()),
        Err(SealedSecretAccessError::Retired)
    );
    assert_eq!(secret.try_close(), Ok(()));
}

#[cfg(all(
    feature = "page-seal",
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64"),
    not(miri)
))]
#[test]
fn sealed_secret_cleanup_continues_after_first_page_failure() {
    const N: usize = 128 * 1024;
    let mut secret = SealedSecretBytes::<N>::zeroed().unwrap();
    secret
        .try_with_secret_mut(|bytes| {
            bytes[0] = 0xAA;
            bytes[N - 1] = 0x55;
        })
        .unwrap();

    secret.fail_normalization_page_for_test(0);
    let error = secret.try_close().unwrap_err();
    assert!(error.report().normalization_failed());
    assert!(secret.is_poisoned());
    assert_eq!(secret.erased_page_is_zero_for_test(1), Ok(true));
    assert_eq!(
        secret.protection_report().mapping,
        ProtectionState::Established
    );

    secret.try_close().unwrap();
    assert!(secret.is_retired());
}

#[cfg(all(
    feature = "page-seal",
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64"),
    not(miri)
))]
#[allow(unsafe_code)]
#[test]
fn sealed_secret_cleanup_reseal_failure_retains_zeroed_mapping_for_retry() {
    const N: usize = 128 * 1024;
    let mut secret = SealedSecretBytes::<N>::zeroed().unwrap();
    secret
        .try_with_secret_mut(|bytes| {
            bytes[0] = 0xAA;
            bytes[N - 1] = 0x55;
        })
        .unwrap();

    secret.fail_cleanup_reseal_page_for_test(0);
    let error = secret.try_close().unwrap_err();
    assert!(error.report().normalization_failed());
    assert_eq!(error.report().unlock, CleanupState::NotNeeded);
    assert_eq!(error.report().unmap, CleanupState::NotNeeded);
    assert!(secret.is_poisoned());
    // SAFETY: this is the first operation after the injected cleanup-reseal
    // failure; no helper has changed the recorded page's readable state.
    assert_eq!(
        unsafe { secret.writable_failed_reseal_page_is_zero_for_test(0) },
        Ok(true)
    );
    assert_eq!(
        secret.protection_report().mapping,
        ProtectionState::Established
    );

    secret.try_close().unwrap();
    assert!(secret.is_retired());
}

#[cfg(all(
    feature = "page-seal",
    feature = "memory-lock",
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64"),
    not(miri)
))]
#[test]
fn sealed_secret_retains_lock_and_mapping_when_normalization_fails() {
    const N: usize = 8 * 1024;
    let request = ProtectionRequest::locked_guarded();
    let mut secret = SealedSecretBytes::<N>::zeroed_with_protection(request).unwrap();
    secret
        .try_with_secret_mut(|bytes| {
            bytes[0] = 0xAA;
            bytes[N - 1] = 0x55;
        })
        .unwrap();

    let locked_bytes = secret.protection_report().locked_bytes;
    assert!(secret.protection_report().memory_is_locked());
    assert!(locked_bytes >= N);

    secret.fail_normalization_page_for_test(1);
    secret.fail_next_unmap_for_test();
    let error = secret.try_close().unwrap_err();
    let cleanup = error.report();

    assert!(cleanup.normalization_failed());
    assert_eq!(cleanup.unlock, CleanupState::NotNeeded);
    assert_eq!(cleanup.unmap, CleanupState::NotNeeded);
    assert!(secret.is_poisoned());
    assert_eq!(secret.erased_page_is_zero_for_test(0), Ok(true));
    assert!(secret.protection_report().memory_is_locked());
    assert_eq!(secret.protection_report().locked_bytes, locked_bytes);
    assert_eq!(
        secret.protection_report().mapping,
        ProtectionState::Established
    );

    let error = secret.try_close().unwrap_err();
    let cleanup = error.report();
    assert_eq!(cleanup.normalization, CleanupState::Completed);
    assert_eq!(cleanup.unlock, CleanupState::Completed);
    assert!(cleanup.unmap_failed());
    assert!(secret.is_poisoned());
    assert!(!secret.protection_report().memory_is_locked());
    assert_eq!(secret.protection_report().locked_bytes, 0);
    assert_eq!(
        secret.protection_report().mapping,
        ProtectionState::Established
    );

    secret.try_close().unwrap();
    assert!(secret.is_retired());
    assert!(!secret.protection_report().memory_is_locked());
    assert_eq!(secret.protection_report().locked_bytes, 0);
    assert_eq!(secret.protection_report().mapped_bytes, 0);
    assert_eq!(
        secret.protection_report().mapping,
        ProtectionState::NotApplicable
    );
    assert!(!secret.protection_report().satisfies(request));
    assert!(secret.protection_report().is_degraded());
}

#[cfg(all(
    feature = "page-seal",
    feature = "memory-lock",
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64"),
    not(miri)
))]
#[test]
fn sealed_secret_unlocks_wiped_mapping_after_release_failure() {
    let request = ProtectionRequest::locked_guarded();
    let mut secret = SealedSecretBytes::<4096>::zeroed_with_protection(request).unwrap();
    secret
        .try_with_secret_mut(|bytes| bytes.fill(0xA5))
        .unwrap();
    assert!(secret.protection_report().memory_is_locked());

    secret.fail_next_unmap_for_test();
    let error = secret.try_close().unwrap_err();
    let cleanup = error.report();

    assert_eq!(cleanup.normalization, CleanupState::Completed);
    assert_eq!(cleanup.unlock, CleanupState::Completed);
    assert!(cleanup.unmap_failed());
    assert!(secret.is_poisoned());
    assert!(!secret.protection_report().memory_is_locked());
    assert_eq!(secret.protection_report().locked_bytes, 0);
    assert_eq!(
        secret.protection_report().memory_lock,
        ProtectionState::NotApplicable
    );
    assert!(!secret.protection_report().satisfies(request));
    assert!(secret.protection_report().is_degraded());

    secret.try_close().unwrap();
    assert!(secret.is_retired());
    assert_eq!(secret.protection_report().mapped_bytes, 0);
}

#[cfg(all(
    feature = "page-seal",
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64"),
    not(miri)
))]
#[test]
fn sealed_secret_explicit_close_retires_mapping() {
    let mut secret = SealedSecretBytes::<4>::from_array([1, 2, 3, 4]).unwrap();
    secret.try_close().unwrap();

    assert!(secret.is_retired());
    assert_eq!(
        secret.try_with_secret(|_| ()),
        Err(SealedSecretAccessError::Retired)
    );
}

#[cfg(all(
    feature = "page-seal",
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64"),
    not(miri)
))]
#[test]
fn sealed_secret_explicit_close_reports_unmap_failure() {
    let mut secret = SealedSecretBytes::<4>::from_array([1, 2, 3, 4]).unwrap();
    secret.fail_next_unmap_for_test();

    let error = secret.try_close().unwrap_err();
    assert_eq!(error.operation(), GuardPageOperation::Unmap);
    assert!(matches!(
        error.report().normalization,
        CleanupState::Completed
    ));
    assert!(error.report().unmap_failed());
    assert!(secret.is_poisoned());

    secret.try_close().unwrap();
    assert!(secret.is_retired());
}

#[cfg(all(
    feature = "page-seal",
    feature = "canary-check",
    feature = "std",
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64"),
    not(miri)
))]
#[test]
fn sealed_secret_bytes_fail_closed_on_canary_corruption() {
    let mut secret = SealedSecretBytes::<4>::from_array([1, 2, 3, 4]).unwrap();
    assert_eq!(
        secret.corrupt_canary_for_test(),
        Err(SealedSecretAccessError::Canary(CanaryCorruptedError))
    );
    assert!(secret.is_sealed());
    assert_eq!(
        secret.try_with_secret(|_| ()),
        Err(SealedSecretAccessError::Canary(CanaryCorruptedError))
    );
}

#[cfg(all(
    feature = "memory-lock",
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64"),
    not(miri)
))]
#[test]
fn locked_secret_bytes_round_trip_and_clear() {
    let mut secret = LockedSecretBytes::<4>::from_array([1, 2, 3, 4]).unwrap();
    let mut out = [0; 4];

    assert!(secret.try_copy_to_slice(&mut out).is_ok());
    assert_eq!(out, [1, 2, 3, 4]);
    assert!(secret.constant_time_eq_or_panic(&[1, 2, 3, 4]));
    assert!(!secret.constant_time_eq_or_panic(&[1, 2, 3]));
    let direct_address = secret.expose_secret_or_panic(|bytes| bytes.as_ptr() as usize);
    let copy_address = secret.expose_secret_copy_or_panic(|bytes| bytes.as_ptr() as usize);
    assert_ne!(direct_address, copy_address);

    secret.secure_clear();
    #[cfg(feature = "canary-check")]
    {
        assert_eq!(secret.verify_integrity(), Ok(()));
        assert!(secret.try_copy_to_slice(&mut out).is_ok());
        assert_eq!(out, [0, 0, 0, 0]);
        assert!(secret.try_copy_from_slice(&[9, 8, 7, 6]).is_ok());
        assert!(secret.constant_time_eq_or_panic(&[9, 8, 7, 6]));
    }
    #[cfg(not(feature = "canary-check"))]
    {
        assert!(secret.try_copy_to_slice(&mut out).is_ok());
        assert_eq!(out, [0, 0, 0, 0]);
    }

    secret.into_cleared();
}

#[cfg(all(
    feature = "memory-lock",
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64"),
    not(miri)
))]
#[test]
fn locked_secret_bytes_can_load_from_slice() {
    let mut secret = LockedSecretBytes::<4>::from_slice(&[1, 2, 3, 4]).unwrap();
    let mut out = [0; 4];

    assert!(secret.try_copy_to_slice(&mut out).is_ok());
    assert_eq!(out, [1, 2, 3, 4]);
    assert!(secret.constant_time_eq_or_panic(&[1, 2, 3, 4]));

    assert_eq!(
        LockedSecretBytes::<4>::from_slice(&[1, 2]).err(),
        Some(LockedSecretBytesError::Length(LengthError {
            expected: 4,
            actual: 2,
        }))
    );

    secret.secure_clear();
}

#[cfg(all(
    feature = "memory-lock",
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64"),
    not(miri)
))]
#[test]
fn locked_secret_bytes_can_initialize_from_fn() {
    let mut secret = LockedSecretBytes::<4>::from_fn(|index| (index as u8) + 1).unwrap();
    let mut out = [0; 4];

    assert!(secret.try_copy_to_slice(&mut out).is_ok());
    assert_eq!(out, [1, 2, 3, 4]);
    assert!(secret.constant_time_eq_or_panic(&[1, 2, 3, 4]));

    secret.secure_clear();
}

#[cfg(all(
    feature = "memory-lock",
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64"),
    not(miri)
))]
#[test]
fn locked_secret_bytes_can_initialize_from_fallible_fn() {
    let mut secret = match LockedSecretBytes::<4>::try_from_fn(|index| {
        Ok::<u8, &'static str>((index as u8) + 1)
    }) {
        Ok(secret) => secret,
        Err(LockedSecretBytesGenerateError::Memory(_)) => return,
        Err(LockedSecretBytesGenerateError::Generate(error)) => {
            panic!("unexpected generator error: {error}")
        }
    };
    let mut out = [0; 4];

    assert!(secret.try_copy_to_slice(&mut out).is_ok());
    assert_eq!(out, [1, 2, 3, 4]);
    assert!(secret.constant_time_eq_or_panic(&[1, 2, 3, 4]));

    match LockedSecretBytes::<4>::try_from_fn(|index| {
        if index == 2 {
            Err("generation failed")
        } else {
            Ok(index as u8)
        }
    }) {
        Ok(_) => panic!("generation should have failed"),
        Err(LockedSecretBytesGenerateError::Memory(_)) => return,
        Err(LockedSecretBytesGenerateError::Generate(error)) => {
            assert_eq!(error, "generation failed");
        }
    }

    secret.secure_clear();
}

#[cfg(all(
    feature = "memory-lock",
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64"),
    not(miri)
))]
#[test]
fn locked_secret_bytes_can_replace_secret() {
    let mut secret = match LockedSecretBytes::<4>::from_array([1, 2, 3, 4]) {
        Ok(secret) => secret,
        Err(_) => return,
    };
    let mut out = [0; 4];

    if let Err(SecretIntegrityError::Operation(LockedSecretBytesError::Memory(_))) =
        secret.try_replace_from_slice(&[9, 8, 7, 6])
    {
        return;
    }
    assert!(secret.try_copy_to_slice(&mut out).is_ok());
    assert_eq!(out, [9, 8, 7, 6]);

    if secret.try_replace_from_array([6, 7, 8, 9]).is_err() {
        return;
    }
    assert!(secret.try_copy_to_slice(&mut out).is_ok());
    assert_eq!(out, [6, 7, 8, 9]);

    assert_eq!(
        secret.try_replace_from_slice(&[1, 2]).err(),
        Some(SecretIntegrityError::Operation(
            LockedSecretBytesError::Length(LengthError {
                expected: 4,
                actual: 2,
            })
        ))
    );
    assert!(secret.constant_time_eq_or_panic(&[6, 7, 8, 9]));

    if secret
        .try_replace_from_fn(|index| (index as u8) + 1)
        .is_err()
    {
        return;
    }
    assert!(secret.constant_time_eq_or_panic(&[1, 2, 3, 4]));

    match secret.try_replace_from_fallible_fn(|index| {
        if index == 2 {
            Err("generation failed")
        } else {
            Ok(index as u8)
        }
    }) {
        Ok(_) => panic!("generation should have failed"),
        Err(SecretIntegrityError::Operation(LockedSecretBytesGenerateError::Memory(_))) => return,
        Err(SecretIntegrityError::Operation(LockedSecretBytesGenerateError::Generate(error))) => {
            assert_eq!(error, "generation failed");
        }
        Err(SecretIntegrityError::Canary(error)) => {
            panic!("unexpected integrity error: {error}")
        }
    }
    assert!(secret.constant_time_eq_or_panic(&[1, 2, 3, 4]));

    match secret.try_replace_from_fallible_fn(|index| Ok::<u8, &'static str>((index as u8) + 7)) {
        Ok(()) => {}
        Err(SecretIntegrityError::Operation(LockedSecretBytesGenerateError::Memory(_))) => return,
        Err(SecretIntegrityError::Operation(LockedSecretBytesGenerateError::Generate(error))) => {
            panic!("unexpected generator error: {error}")
        }
        Err(SecretIntegrityError::Canary(error)) => {
            panic!("unexpected integrity error: {error}")
        }
    }
    assert!(secret.constant_time_eq_or_panic(&[7, 8, 9, 10]));

    secret.secure_clear();
}

#[cfg(all(
    feature = "memory-lock",
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64"),
    not(miri)
))]
#[test]
fn locked_secret_bytes_can_fill_in_place() {
    let mut secret = match LockedSecretBytes::<4>::from_fill(|output| {
        output.copy_from_slice(&[1, 2, 3, 4]);
    }) {
        Ok(secret) => secret,
        Err(_) => return,
    };

    assert!(secret.constant_time_eq_or_panic(&[1, 2, 3, 4]));

    match LockedSecretBytes::<4>::try_from_fill(|output| {
        output[..2].copy_from_slice(&[9, 8]);
        Err("decode failed")
    }) {
        Ok(_) => panic!("fill should have failed"),
        Err(LockedSecretBytesFillError::Memory(_)) => return,
        Err(LockedSecretBytesFillError::Integrity(error)) => {
            panic!("unexpected integrity error: {error}")
        }
        Err(LockedSecretBytesFillError::Generate(error)) => {
            assert_eq!(error, "decode failed");
        }
    }

    secret
        .try_replace_from_fill(|output| output.copy_from_slice(&[5, 6, 7, 8]))
        .unwrap();
    assert!(secret.constant_time_eq_or_panic(&[5, 6, 7, 8]));

    assert_eq!(
        secret.try_replace_from_fallible_fill(|output| {
            output[0] = 0;
            Err("decode failed")
        }),
        Err(SecretIntegrityError::Operation(
            LockedSecretBytesGenerateError::Generate("decode failed")
        ))
    );
    assert!(secret.constant_time_eq_or_panic(&[5, 6, 7, 8]));
}

#[cfg(all(
    feature = "memory-lock",
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64"),
    not(miri)
))]
#[test]
fn locked_secret_bytes_can_initialize_an_existing_mapping_in_place() {
    let secret = match LockedSecretBytes::<4>::zeroed() {
        Ok(secret) => secret,
        Err(_) => return,
    };
    let mut secret = secret
        .try_init_with(|output| {
            output.copy_from_slice(&[1, 2, 3, 4]);
            Ok::<(), &'static str>(())
        })
        .unwrap();

    assert!(secret.constant_time_eq_or_panic(&[1, 2, 3, 4]));
    secret.secure_clear();
}

#[cfg(all(
    feature = "memory-lock",
    feature = "canary-check",
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64"),
    not(miri)
))]
#[test]
fn locked_secret_bytes_try_init_rejects_corruption_before_callback() {
    let mut secret = match LockedSecretBytes::<4>::zeroed() {
        Ok(secret) => secret,
        Err(_) => return,
    };
    secret.corrupt_prefix_canary_for_test();

    let callback_ran = core::cell::Cell::new(false);
    let result = secret.try_init_with(|_| {
        callback_ran.set(true);
        Ok::<(), &'static str>(())
    });

    assert!(matches!(
        result,
        Err(LockedSecretInitializeError::Integrity(CanaryCorruptedError))
    ));
    assert!(!callback_ran.get());
}

#[cfg(all(
    feature = "memory-lock",
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64"),
    not(miri)
))]
#[test]
fn locked_secret_bytes_try_init_preserves_generator_errors() {
    let secret = match LockedSecretBytes::<4>::zeroed() {
        Ok(secret) => secret,
        Err(_) => return,
    };

    assert!(matches!(
        secret.try_init_with(|output| {
            output[0] = 9;
            Err("decode failed")
        }),
        Err(LockedSecretInitializeError::Generate("decode failed"))
    ));
}

#[cfg(all(
    feature = "memory-lock",
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64"),
    not(miri)
))]
#[test]
fn locked_secret_vec_round_trip_grow_replace_and_clear() {
    let mut secret = match LockedSecretVec::from_slice(b"key") {
        Ok(secret) => secret,
        Err(_) => return,
    };

    assert_eq!(secret.len(), 3);
    assert!(secret.capacity() >= 3);
    assert!(secret.locked_len() >= 3);
    assert_eq!(secret.with_secret_or_panic(|bytes| bytes[0]), b'k');
    assert!(secret.constant_time_eq_or_panic(b"key"));
    assert!(!secret.constant_time_eq_or_panic(b"ke"));

    secret.try_extend_from_slice(b"-material").unwrap();
    assert!(secret.constant_time_eq_or_panic(b"key-material"));

    secret
        .try_replace_from_fn(4, |index| (index as u8) + 1)
        .unwrap();
    assert!(secret.constant_time_eq_or_panic(&[1, 2, 3, 4]));

    assert_eq!(
        secret.try_replace_from_fallible_fn(4, |index| {
            if index == 2 {
                Err("generation failed")
            } else {
                Ok(index as u8)
            }
        }),
        Err(SecretIntegrityError::Operation(
            LockedSecretVecGenerateError::Generate("generation failed")
        ))
    );
    assert!(secret.constant_time_eq_or_panic(&[1, 2, 3, 4]));

    secret.with_secret_mut_or_panic(|bytes| bytes[0] = 9);
    assert!(secret.constant_time_eq_or_panic(&[9, 2, 3, 4]));

    secret.clear_secret();
    assert!(secret.is_empty());
    #[cfg(feature = "canary-check")]
    assert_eq!(secret.verify_integrity(), Ok(()));

    secret.try_extend_from_slice(b"next").unwrap();
    assert!(secret.constant_time_eq_or_panic(b"next"));
}

#[cfg(all(
    feature = "memory-lock",
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64"),
    not(miri)
))]
#[test]
fn locked_secret_vec_can_fill_in_place() {
    let mut exact = match LockedSecretVec::from_exact_len(4, |output| {
        output.copy_from_slice(&[1, 2, 3, 4]);
    }) {
        Ok(secret) => secret,
        Err(_) => return,
    };
    assert!(exact.constant_time_eq_or_panic(&[1, 2, 3, 4]));

    match LockedSecretVec::try_from_exact_len(4, |output| {
        output[..2].copy_from_slice(&[9, 8]);
        Err("decode failed")
    }) {
        Ok(_) => panic!("fill should have failed"),
        Err(LockedSecretVecGenerateError::Memory(_)) => return,
        Err(LockedSecretVecGenerateError::Generate(error)) => {
            assert_eq!(error, "decode failed");
        }
    }

    let mut bounded = match LockedSecretVec::from_capacity(8, |output| {
        output[..5].copy_from_slice(b"token");
        output[5..8].copy_from_slice(b"old");
        5
    }) {
        Ok(secret) => secret,
        Err(LockedSecretVecFillError::Memory(_)) => return,
        Err(error) => panic!("unexpected capacity fill error: {error}"),
    };
    assert_eq!(bounded.len(), 5);
    assert!(bounded.capacity() >= 8);
    assert!(bounded.constant_time_eq_or_panic(b"token"));

    match LockedSecretVec::try_from_capacity(4, |output| {
        output.copy_from_slice(b"abcd");
        Ok::<usize, &'static str>(5)
    }) {
        Ok(_) => panic!("reported length should have failed"),
        Err(LockedSecretVecFillError::Memory(_)) => return,
        Err(error) => assert_eq!(
            error,
            LockedSecretVecFillError::Length(LengthError {
                expected: 4,
                actual: 5,
            })
        ),
    }

    exact
        .try_replace_from_exact_len(3, |output| output.copy_from_slice(b"key"))
        .unwrap();
    assert!(exact.constant_time_eq_or_panic(b"key"));

    assert_eq!(
        exact.try_replace_from_fallible_exact_len(4, |output| {
            output[..2].copy_from_slice(&[9, 8]);
            Err("decode failed")
        }),
        Err(SecretIntegrityError::Operation(
            LockedSecretVecGenerateError::Generate("decode failed")
        ))
    );
    assert!(exact.constant_time_eq_or_panic(b"key"));

    assert_eq!(
        exact.try_replace_from_fallible_exact_len(4, |output| {
            output.copy_from_slice(b"fail");
            Err("decode failed")
        }),
        Err(SecretIntegrityError::Operation(
            LockedSecretVecGenerateError::Generate("decode failed")
        ))
    );
    assert!(exact.constant_time_eq_or_panic(b"key"));

    bounded
        .try_replace_from_capacity(8, |output| {
            output[..6].copy_from_slice(b"secret");
            6
        })
        .unwrap();
    assert!(bounded.constant_time_eq_or_panic(b"secret"));

    assert_eq!(
        bounded.try_replace_from_fallible_capacity(4, |output| {
            output.copy_from_slice(b"abcd");
            Ok::<usize, &'static str>(5)
        }),
        Err(SecretIntegrityError::Operation(
            LockedSecretVecFillError::Length(LengthError {
                expected: 4,
                actual: 5,
            })
        ))
    );
    assert!(bounded.constant_time_eq_or_panic(b"secret"));
}

#[cfg(all(
    feature = "memory-lock",
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64"),
    not(miri)
))]
#[test]
fn locked_secret_vec_policy_aware_fill_establishes_protection_first() {
    let request = ProtectionRequest {
        memory_lock: Requirement::NotRequested,
        dump_exclusion: Requirement::NotRequested,
        fork: ForkProtectionRequest::inherit(),
        guard_pages: Requirement::NotRequested,
        canary: Requirement::NotRequested,
        cache_policy: Requirement::NotRequested,
    };
    let secret = LockedSecretVec::try_from_capacity_with_protection(32, request, |output| {
        assert_eq!(output.len(), 32);
        assert!(output.iter().all(|byte| *byte == 0));
        output[..5].copy_from_slice(b"token");
        output[5..].fill(0xa5);
        Ok::<usize, &'static str>(5)
    })
    .unwrap();

    assert!(secret.protection_report().satisfies(request));
    assert_eq!(secret.len(), 5);
    assert!(secret.constant_time_eq_or_panic(b"token"));
    assert!(secret.unreported_tail_is_clear_for_test());

    assert_eq!(
        LockedSecretVec::try_from_capacity_with_protection(4, request, |output| {
            output.copy_from_slice(b"data");
            Err::<usize, _>("decode failed")
        })
        .err(),
        Some(ProtectedSecretFillError::Fill("decode failed"))
    );

    assert_eq!(
        LockedSecretVec::try_from_capacity_with_protection(4, request, |_| {
            Ok::<usize, &'static str>(5)
        })
        .err(),
        Some(ProtectedSecretFillError::Length(LengthError {
            expected: 4,
            actual: 5,
        }))
    );

    let callback_ran = core::cell::Cell::new(false);
    assert_eq!(
        LockedSecretVec::try_from_capacity_bounded_with_protection(9, 8, request, |_| {
            callback_ran.set(true);
            Ok::<usize, &'static str>(0)
        },)
        .err(),
        Some(ProtectedSecretFillError::CapacityLimit {
            maximum: 8,
            actual: 9,
        })
    );
    assert!(!callback_ran.get());
}

#[cfg(all(
    feature = "memory-lock",
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64"),
    not(miri)
))]
#[test]
fn bounded_locked_secret_vec_enforces_lifetime_maximum() {
    let request = ProtectionRequest {
        memory_lock: Requirement::NotRequested,
        dump_exclusion: Requirement::NotRequested,
        fork: ForkProtectionRequest::inherit(),
        guard_pages: Requirement::NotRequested,
        canary: Requirement::NotRequested,
        cache_policy: Requirement::NotRequested,
    };
    let mut secret =
        BoundedLockedSecretVec::<8>::try_from_capacity_with_protection(4, request, |output| {
            output.copy_from_slice(b"key!");
            Ok::<usize, core::convert::Infallible>(4)
        })
        .unwrap();

    secret.try_extend_from_slice(b"1234").unwrap();
    assert!(secret.try_constant_time_eq(b"key!1234").unwrap());
    assert_eq!(
        secret.try_extend_from_slice(b"x"),
        Err(BoundedMappedSecretError::CapacityLimit {
            maximum: 8,
            actual: 9,
        })
    );
    assert!(secret.try_constant_time_eq(b"key!1234").unwrap());

    let generator_ran = core::cell::Cell::new(false);
    assert!(matches!(
        secret.try_replace_from_fn(9, |_| {
            generator_ran.set(true);
            0
        }),
        Err(BoundedMappedSecretError::CapacityLimit {
            maximum: 8,
            actual: 9,
        })
    ));
    assert!(!generator_ran.get());
    assert!(secret.try_constant_time_eq(b"key!1234").unwrap());

    let mut text =
        BoundedLockedSecretString::<8>::from_secret_str_with_protection("key", request).unwrap();
    text.try_push_str("-1234").unwrap();
    assert_eq!(
        text.try_push_str("x"),
        Err(BoundedMappedSecretError::CapacityLimit {
            maximum: 8,
            actual: 9,
        })
    );
    assert!(text.try_constant_time_eq("key-1234").unwrap());

    let callback_ran = core::cell::Cell::new(false);
    assert_eq!(
        BoundedLockedSecretVec::<8>::try_from_capacity_with_protection(9, request, |_| {
            callback_ran.set(true);
            Ok::<usize, core::convert::Infallible>(0)
        },)
        .err(),
        Some(ProtectedSecretFillError::CapacityLimit {
            maximum: 8,
            actual: 9,
        })
    );
    assert!(!callback_ran.get());
}

#[cfg(all(
    feature = "memory-lock",
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64"),
    not(miri)
))]
#[test]
fn locked_secret_vec_required_policy_failure_prevents_fill() {
    let request = ProtectionRequest {
        guard_pages: Requirement::Required,
        ..ProtectionRequest::locked()
    };
    let callback_ran = core::cell::Cell::new(false);

    let result = LockedSecretVec::try_from_capacity_with_protection(4, request, |_| {
        callback_ran.set(true);
        Ok::<usize, core::convert::Infallible>(4)
    });

    assert!(matches!(
        result,
        Err(ProtectedSecretFillError::Protection(ProtectionError {
            failure: ProtectionFailure {
                control: ProtectionControl::GuardPages,
                ..
            },
            ..
        }))
    ));
    assert!(!callback_ran.get());
}

#[cfg(all(
    feature = "memory-lock",
    feature = "canary-check",
    feature = "std",
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64"),
    not(miri)
))]
#[test]
fn locked_secret_vec_policy_aware_fill_detects_capacity_boundary_corruption() {
    let request = ProtectionRequest {
        memory_lock: Requirement::NotRequested,
        dump_exclusion: Requirement::NotRequested,
        fork: ForkProtectionRequest::inherit(),
        guard_pages: Requirement::NotRequested,
        canary: Requirement::Required,
        cache_policy: Requirement::NotRequested,
    };
    let result = LockedSecretVec::try_from_capacity_with_protection_and_corrupt_boundary_for_test(
        4,
        request,
        |output| {
            output.copy_from_slice(b"data");
            Ok::<usize, core::convert::Infallible>(4)
        },
    );

    assert_eq!(
        result.err(),
        Some(ProtectedSecretFillError::Integrity(CanaryCorruptedError))
    );
}

#[cfg(all(
    feature = "memory-lock",
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64"),
    not(miri)
))]
#[test]
fn locked_secret_vec_zero_capacity_is_reusable() {
    let mut secret = LockedSecretVec::with_capacity(0).unwrap();

    assert!(secret.is_empty());
    assert_eq!(secret.capacity(), 0);
    assert_eq!(secret.locked_len(), 0);
    secret.clear_secret();
    #[cfg(feature = "canary-check")]
    assert_eq!(secret.verify_integrity(), Ok(()));

    if secret.try_extend_from_slice(b"x").is_err() {
        return;
    }
    assert!(secret.constant_time_eq_or_panic(b"x"));
}

#[cfg(all(
    feature = "std",
    feature = "canary-check",
    feature = "memory-lock",
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64"),
    not(miri)
))]
#[test]
fn locked_secret_vec_canaries_detect_corruption() {
    let mut secret = match LockedSecretVec::from_slice(b"secret") {
        Ok(secret) => secret,
        Err(_) => return,
    };

    assert_eq!(secret.verify_integrity(), Ok(()));
    assert_eq!(secret.try_with_secret(|bytes| bytes[0]), Ok(b's'));
    assert_eq!(secret.try_constant_time_eq(b"secret"), Ok(true));

    secret.corrupt_prefix_canary_for_test();

    assert_eq!(
        ct::ConstantTimeEq::ct_eq(&secret, b"secret".as_slice())
            .declassify_u8("test verifies corrupted mapped vector comparison fails closed"),
        0
    );

    #[cfg(feature = "subtle-interop")]
    {
        let same = LockedSecretVec::from_slice(b"secret").unwrap();
        assert!(!bool::from(subtle::ConstantTimeEq::ct_eq(&secret, &same)));
    }

    assert_eq!(
        secret.try_with_secret(|bytes| bytes[0]),
        Err(CanaryCorruptedError)
    );
    assert_eq!(
        secret.try_with_secret_mut(|bytes| bytes[0] = b'x'),
        Err(CanaryCorruptedError)
    );
    assert_eq!(
        secret.try_replace_from_slice(b"replacement"),
        Err(SecretIntegrityError::Canary(CanaryCorruptedError))
    );
    assert_eq!(
        secret.try_constant_time_eq(b"secret"),
        Err(CanaryCorruptedError)
    );
    secret.clear_secret();
    assert_eq!(secret.verify_integrity(), Err(CanaryCorruptedError));
}

#[cfg(all(
    feature = "memory-lock",
    feature = "cache-flush",
    target_os = "linux",
    target_arch = "x86_64",
    not(miri)
))]
#[test]
fn locked_secret_bytes_can_clear_and_flush() {
    let mut secret = LockedSecretBytes::<4>::from_array([1, 2, 3, 4]).unwrap();
    #[cfg(not(feature = "canary-check"))]
    let mut out = [0; 4];

    secret.try_secure_clear_and_flush().unwrap();

    #[cfg(feature = "canary-check")]
    assert_eq!(secret.verify_integrity(), Ok(()));
    #[cfg(not(feature = "canary-check"))]
    {
        assert!(secret.try_copy_to_slice(&mut out).is_ok());
        assert_eq!(out, [0, 0, 0, 0]);
    }
}

#[cfg(all(
    feature = "std",
    feature = "canary-check",
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64"),
    not(miri)
))]
#[test]
fn locked_secret_canary_checked_apis_detect_corruption() {
    let mut secret = match LockedSecretBytes::<4>::from_array([1, 2, 3, 4]) {
        Ok(secret) => secret,
        Err(_) => return,
    };
    let mut out = [0; 4];

    assert_eq!(secret.verify_integrity(), Ok(()));
    assert_eq!(secret.try_expose_secret(|bytes| bytes[0]), Ok(1));
    assert_eq!(secret.try_expose_secret_copy(|bytes| bytes[3]), Ok(4));
    assert_eq!(secret.try_copy_to_slice(&mut out), Ok(()));
    assert_eq!(out, [1, 2, 3, 4]);
    assert_eq!(secret.try_constant_time_eq(&[1, 2, 3, 4]), Ok(true));
    assert_eq!(
        secret.try_copy_to_slice(&mut [0; 2]),
        Err(SecretIntegrityError::Operation(LengthError {
            expected: 4,
            actual: 2,
        }))
    );

    secret.corrupt_prefix_canary_for_test();

    assert_eq!(
        ct::ConstantTimeEq::ct_eq(&secret, [1, 2, 3, 4].as_slice())
            .declassify_u8("test verifies corrupted mapped secret comparison fails closed"),
        0
    );

    #[cfg(feature = "subtle-interop")]
    {
        let same = LockedSecretBytes::<4>::from_array([1, 2, 3, 4]).unwrap();
        assert!(!bool::from(subtle::ConstantTimeEq::ct_eq(&secret, &same)));
    }

    assert_eq!(
        secret.try_expose_secret(|bytes| bytes[0]),
        Err(CanaryCorruptedError)
    );
    assert_eq!(
        secret.try_copy_from_slice(&[9, 8, 7, 6]),
        Err(SecretIntegrityError::Canary(CanaryCorruptedError))
    );
    out.fill(0xA5);
    assert_eq!(
        secret.try_copy_to_slice(&mut out),
        Err(SecretIntegrityError::Canary(CanaryCorruptedError))
    );
    assert_eq!(out, [0xA5; 4]);
    assert_eq!(
        secret.try_replace_from_slice(&[9, 8, 7, 6]),
        Err(SecretIntegrityError::Canary(CanaryCorruptedError))
    );
    assert_eq!(
        secret.try_constant_time_eq(&[1, 2, 3, 4]),
        Err(CanaryCorruptedError)
    );
    secret.secure_clear();
    assert_eq!(secret.verify_integrity(), Err(CanaryCorruptedError));
}

#[cfg(all(
    feature = "std",
    feature = "canary-check",
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64"),
    not(miri)
))]
#[test]
fn locked_secret_canary_legacy_exposure_fails_closed() {
    let mut secret = match LockedSecretBytes::<4>::from_array([1, 2, 3, 4]) {
        Ok(secret) => secret,
        Err(_) => return,
    };

    secret.corrupt_prefix_canary_for_test();

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = secret.expose_secret_or_panic(|bytes| bytes[0]);
    }));

    assert!(result.is_err());
}

#[cfg(all(
    feature = "memory-lock",
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64"),
    not(miri)
))]
#[test]
fn secret_pool_allocates_reuses_and_clears_slots() {
    let pool = match SecretPool::<4, 2>::new() {
        Ok(pool) => pool,
        Err(_) => return,
    };

    assert_eq!(pool.slot_size(), 4);
    assert_eq!(pool.capacity_slots(), 2);
    assert!(pool.locked_len() >= 8);
    assert_eq!(pool.available_slots(), 2);
    let empty_report = pool.arena_report();
    assert_eq!(empty_report.slot_size, 4);
    assert_eq!(empty_report.capacity_slots, 2);
    assert_eq!(empty_report.live_slots, 0);
    assert_eq!(empty_report.payload_capacity_bytes, 8);
    assert_eq!(empty_report.reserved_bytes, empty_report.slot_stride * 2);
    assert_eq!(
        empty_report.mapped_bytes,
        pool.protection_report().mapped_bytes
    );
    assert_eq!(pool.protection_report().requested_bytes, 8);
    assert!(empty_report.storage_efficiency_basis_points().is_some());
    assert!(empty_report.mapping_efficiency_basis_points().is_some());

    let mut first = pool.try_allocate_from_array([1, 2, 3, 4]).unwrap().unwrap();
    let mut second = pool
        .try_allocate_from_fn(|index| Ok::<u8, core::convert::Infallible>((index as u8) + 5))
        .unwrap()
        .unwrap();
    let first_id = first.slot_id();
    let second_id = second.slot_id();
    let mut out = [0; 4];

    assert_ne!(first_id, second_id);
    assert_ne!(first.generation(), 0);
    assert_eq!(pool.available_slots(), 0);
    assert_eq!(pool.arena_report().live_slots, 2);
    assert!(pool.try_allocate().unwrap().is_none());
    assert!(first.constant_time_eq_or_panic(&[1, 2, 3, 4]));
    assert!(second.try_copy_to_slice(&mut out).is_ok());
    assert_eq!(out, [5, 6, 7, 8]);
    let direct_address = second.expose_secret_or_panic(|bytes| bytes.as_ptr() as usize);
    let copy_address = second.expose_secret_copy_or_panic(|bytes| bytes.as_ptr() as usize);
    assert_ne!(direct_address, copy_address);

    first.with_secret_mut_or_panic(|bytes| bytes[0] = 9);
    assert!(first.constant_time_eq_or_panic(&[9, 2, 3, 4]));
    first.secure_clear();
    #[cfg(feature = "canary-check")]
    assert_eq!(first.verify_integrity(), Ok(()));
    assert!(first.constant_time_eq_or_panic(&[0, 0, 0, 0]));
    first.try_copy_from_slice(&[4, 3, 2, 1]).unwrap();
    assert!(first.constant_time_eq_or_panic(&[4, 3, 2, 1]));
    first.secure_clear();
    assert!(first.constant_time_eq_or_panic(&[0, 0, 0, 0]));

    let freed_index = first.slot_index();
    drop(first);
    assert_eq!(pool.available_slots(), 1);

    let reused = pool
        .try_allocate_from_slice(&[7, 7, 7, 7])
        .unwrap()
        .unwrap();
    assert_eq!(reused.slot_index(), freed_index);
    assert_ne!(reused.slot_id(), first_id);
    assert!(reused.constant_time_eq_or_panic(&[7, 7, 7, 7]));

    second.try_replace_from_array([8, 8, 8, 8]).unwrap();
    assert!(second.constant_time_eq_or_panic(&[8, 8, 8, 8]));
}

#[cfg(all(
    feature = "memory-lock",
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64"),
    not(miri)
))]
#[test]
fn secret_pool_handles_generation_and_zero_slot_cases() {
    let pool = match SecretPool::<4, 1>::new() {
        Ok(pool) => pool,
        Err(_) => return,
    };

    let mut slot = match pool
        .try_allocate_from_fn(|index| Ok::<u8, &'static str>((index as u8).wrapping_add(1)))
    {
        Ok(Some(slot)) => slot,
        Ok(None) => panic!("pool should have one available slot"),
        Err(error) => panic!("unexpected generator error: {error}"),
    };

    assert!(slot.constant_time_eq_or_panic(&[1, 2, 3, 4]));
    assert_eq!(
        slot.try_replace_from_fallible_fn(|index| {
            if index == 2 {
                Err("generation failed")
            } else {
                Ok(index as u8)
            }
        }),
        Err(SecretIntegrityError::Operation("generation failed"))
    );
    #[cfg(feature = "canary-check")]
    assert_eq!(slot.verify_integrity(), Ok(()));
    assert!(slot.constant_time_eq_or_panic(&[0, 0, 0, 0]));
    slot.try_copy_from_slice(&[9, 9, 9, 9]).unwrap();
    assert!(slot.constant_time_eq_or_panic(&[9, 9, 9, 9]));
    drop(slot);

    match pool.try_allocate_from_fn(|index| {
        if index == 1 {
            Err("generation failed")
        } else {
            Ok(index as u8)
        }
    }) {
        Ok(_) => panic!("generation should have failed"),
        Err(error) => assert_eq!(
            error,
            SecretPoolGenerateError::Generate("generation failed")
        ),
    }
    assert_eq!(pool.available_slots(), 1);
    let reused_after_error = pool
        .try_allocate()
        .unwrap()
        .expect("failed generation must release slot");
    assert!(reused_after_error.constant_time_eq_or_panic(&[0, 0, 0, 0]));
    drop(reused_after_error);

    let panic_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = pool.try_allocate_from_fn(|index| {
            if index == 2 {
                panic!("generation panic");
            }
            Ok::<u8, core::convert::Infallible>((index as u8).wrapping_add(1))
        });
    }));
    assert!(panic_result.is_err());
    assert_eq!(pool.available_slots(), 1);
    let reused_after_panic = pool
        .try_allocate()
        .unwrap()
        .expect("panic must release slot");
    assert!(reused_after_panic.constant_time_eq_or_panic(&[0, 0, 0, 0]));
    drop(reused_after_panic);

    let empty = SecretPool::<0, 2>::new().unwrap();
    assert!(empty.is_empty());
    assert_eq!(empty.locked_len(), 0);
    assert_eq!(empty.arena_report().storage_efficiency_basis_points(), None);
    let slot = empty.try_allocate().unwrap().unwrap();
    assert!(slot.is_empty());
}

#[cfg(all(
    feature = "memory-lock",
    feature = "random-canary",
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64"),
    not(miri)
))]
#[test]
fn mapped_initializers_preserve_injected_csprng_failures() {
    let mut locked_input = [1, 2, 3, 4];
    crate::canary::fail_next_fill_for_test();
    assert!(matches!(
        LockedSecretBytes::<4>::from_array_buffer_for_test(&mut locked_input),
        Err(LockedSecretInitError::Allocation(MemoryLockError {
            operation: MemoryLockOperation::Random,
            errno: -3,
        }))
    ));
    assert_eq!(locked_input, [0; 4]);

    let infallible_fill_ran = core::cell::Cell::new(false);
    crate::canary::fail_next_fill_for_test();
    assert!(matches!(
        LockedSecretBytes::<4>::from_fill(|_| infallible_fill_ran.set(true)),
        Err(LockedSecretInitError::Allocation(MemoryLockError {
            operation: MemoryLockOperation::Random,
            errno: -3,
        }))
    ));
    assert!(!infallible_fill_ran.get());

    let fallible_fill_ran = core::cell::Cell::new(false);
    crate::canary::fail_next_fill_for_test();
    assert!(matches!(
        LockedSecretBytes::<4>::try_from_fill(|_| {
            fallible_fill_ran.set(true);
            Ok::<(), &'static str>(())
        }),
        Err(LockedSecretBytesFillError::Memory(MemoryLockError {
            operation: MemoryLockOperation::Random,
            errno: -3,
        }))
    ));
    assert!(!fallible_fill_ran.get());

    let pool = match SecretPool::<4, 1>::new() {
        Ok(pool) => pool,
        Err(_) => return,
    };

    let initialized = pool.try_allocate().unwrap().unwrap();
    drop(initialized);

    crate::canary::fail_next_fill_for_test();
    assert!(matches!(
        pool.try_allocate(),
        Err(MemoryLockError {
            operation: MemoryLockOperation::Random,
            errno: -3,
        })
    ));
    assert_eq!(pool.available_slots(), 1);
    assert_eq!(pool.quarantined_slots(), 0);

    crate::canary::fail_next_fill_for_test();
    assert!(matches!(
        pool.try_allocate_from_slice(&[1, 2, 3, 4]),
        Err(PoolInitError::Allocation(MemoryLockError {
            operation: MemoryLockOperation::Random,
            errno: -3,
        }))
    ));
    assert_eq!(pool.available_slots(), 1);

    let mut pool_input = [1, 2, 3, 4];
    crate::canary::fail_next_fill_for_test();
    assert!(matches!(
        pool.try_allocate_from_array_buffer_for_test(&mut pool_input),
        Err(PoolInitError::Allocation(MemoryLockError {
            operation: MemoryLockOperation::Random,
            errno: -3,
        }))
    ));
    assert_eq!(pool_input, [0; 4]);
    assert_eq!(pool.available_slots(), 1);

    crate::canary::fail_next_fill_for_test();
    assert!(matches!(
        pool.try_allocate_from_fn(|index| Ok::<u8, &'static str>(index as u8)),
        Err(SecretPoolGenerateError::Allocation(MemoryLockError {
            operation: MemoryLockOperation::Random,
            errno: -3,
        }))
    ));
    assert_eq!(pool.available_slots(), 1);
}

#[cfg(all(
    feature = "std",
    feature = "canary-check",
    feature = "memory-lock",
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64"),
    not(miri)
))]
#[test]
fn pool_initialization_integrity_failure_wipes_and_quarantines() {
    let pool = match SecretPool::<4, 2>::new() {
        Ok(pool) => pool,
        Err(_) => return,
    };

    let mut input = [1, 2, 3, 4];
    pool.fail_next_initialization_integrity_for_test();
    assert!(matches!(
        pool.try_allocate_from_array_buffer_for_test(&mut input),
        Err(PoolInitError::Integrity(CanaryCorruptedError))
    ));
    assert_eq!(input, [0; 4]);
    assert_eq!(pool.quarantined_slots(), 1);
    assert_eq!(pool.available_slots(), 1);

    let live = pool.try_allocate().unwrap().unwrap();
    assert_eq!(pool.available_slots(), 0);
    assert!(matches!(pool.try_allocate(), Ok(None)));
    drop(live);
    assert_eq!(pool.available_slots(), 1);
    assert_eq!(pool.arena_report().quarantined_slots, 1);
}

#[cfg(all(
    feature = "memory-lock",
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64"),
    not(miri)
))]
#[test]
fn owned_array_initialization_wipes_success_inputs() {
    let mut locked_input = [1, 2, 3, 4];
    let locked = match LockedSecretBytes::<4>::from_array_buffer_for_test(&mut locked_input) {
        Ok(locked) => locked,
        Err(_) => return,
    };
    assert_eq!(locked_input, [0; 4]);
    drop(locked);

    let pool = match SecretPool::<4, 1>::new() {
        Ok(pool) => pool,
        Err(_) => return,
    };
    let mut pool_input = [5, 6, 7, 8];
    let slot = pool
        .try_allocate_from_array_buffer_for_test(&mut pool_input)
        .unwrap()
        .unwrap();
    assert_eq!(pool_input, [0; 4]);
    drop(slot);
}

#[cfg(all(
    feature = "memory-lock",
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64"),
    not(miri)
))]
#[test]
fn secret_pool_test_quarantine_and_generation_wrap_fail_closed() {
    let pool = match SecretPool::<4, 2>::new() {
        Ok(pool) => pool,
        Err(_) => return,
    };

    assert!(pool.quarantine_slot_for_test(0, true));
    let slot = pool
        .try_allocate()
        .unwrap()
        .expect("unquarantined slot must allocate");
    assert_eq!(slot.slot_index(), 1);
    assert!(!pool.quarantine_slot_for_test(1, true));
    drop(slot);

    assert!(pool.quarantine_slot_for_test(0, false));
    assert!(pool.quarantine_slot_for_test(1, true));
    assert!(pool.quarantine_slot_for_test(0, true));
    assert!(pool.set_slot_generation_for_test(0, usize::MAX));
    assert!(pool.quarantine_slot_for_test(0, false));
    let wrapped = pool
        .try_allocate()
        .unwrap()
        .expect("generation wrap must remain usable");
    assert_eq!(wrapped.slot_index(), 0);
    assert_eq!(wrapped.generation(), 1);
}

#[cfg(all(
    feature = "std",
    feature = "canary-check",
    feature = "memory-lock",
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64"),
    not(miri)
))]
#[test]
fn secret_pool_slot_canaries_detect_corruption() {
    let pool = match SecretPool::<4, 1>::new() {
        Ok(pool) => pool,
        Err(_) => return,
    };
    let mut slot = pool.try_allocate_from_array([1, 2, 3, 4]).unwrap().unwrap();

    assert_eq!(slot.verify_integrity(), Ok(()));
    assert_eq!(slot.try_expose_secret(|bytes| bytes[0]), Ok(1));
    assert_eq!(slot.try_expose_secret_copy(|bytes| bytes[3]), Ok(4));
    assert_eq!(slot.try_constant_time_eq(&[1, 2, 3, 4]), Ok(true));

    slot.corrupt_prefix_canary_for_test();

    assert_eq!(
        ct::ConstantTimeEq::ct_eq(&slot, [1, 2, 3, 4].as_slice())
            .declassify_u8("test verifies corrupted pool slot comparison fails closed"),
        0
    );

    assert_eq!(
        slot.try_expose_secret(|bytes| bytes[0]),
        Err(CanaryCorruptedError)
    );
    assert_eq!(
        slot.try_copy_from_slice(&[9, 8, 7, 6]),
        Err(SecretIntegrityError::Canary(CanaryCorruptedError))
    );
    assert_eq!(
        slot.try_constant_time_eq(&[1, 2, 3, 4]),
        Err(CanaryCorruptedError)
    );
    slot.secure_clear();
    assert_eq!(slot.verify_integrity(), Err(CanaryCorruptedError));
    drop(slot);
    assert_eq!(pool.quarantined_slots(), 1);
    assert_eq!(pool.available_slots(), 0);
}

#[cfg(all(
    feature = "std",
    feature = "canary-check",
    feature = "memory-lock",
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64"),
    not(miri)
))]
#[test]
fn pool_slot_drop_detects_and_quarantines_corruption() {
    let pool = match SecretPool::<4, 1>::new() {
        Ok(pool) => pool,
        Err(_) => return,
    };
    let mut slot = pool.try_allocate().unwrap().unwrap();

    slot.corrupt_prefix_canary_for_test();
    drop(slot);

    assert_eq!(pool.quarantined_slots(), 1);
    assert_eq!(pool.available_slots(), 0);
    assert!(pool.try_allocate().unwrap().is_none());
}

#[cfg(all(
    feature = "std",
    feature = "canary-check",
    not(feature = "random-canary"),
    feature = "memory-lock",
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64"),
    not(miri)
))]
#[test]
fn secret_pool_deterministic_canary_rotates_when_slot_is_reused() {
    let pool = match SecretPool::<4, 1>::new() {
        Ok(pool) => pool,
        Err(_) => return,
    };

    let first = pool.try_allocate().unwrap().unwrap();
    let first_canary = first.deterministic_canary_for_test();
    let slot_index = first.slot_index();
    drop(first);

    let second = pool.try_allocate().unwrap().unwrap();
    assert_eq!(second.slot_index(), slot_index);
    assert_ne!(second.deterministic_canary_for_test(), first_canary);
    assert_eq!(second.verify_integrity(), Ok(()));
}

#[cfg(all(
    feature = "std",
    feature = "memory-lock",
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64"),
    not(miri)
))]
#[test]
fn secret_pool_concurrent_allocation_gets_distinct_slots() {
    let pool = match SecretPool::<4, 2>::new() {
        Ok(pool) => std::sync::Arc::new(pool),
        Err(_) => return,
    };
    let worker_pool = std::sync::Arc::clone(&pool);
    let start = std::sync::Arc::new(std::sync::Barrier::new(2));
    let finish = std::sync::Arc::new(std::sync::Barrier::new(2));
    let worker_start = std::sync::Arc::clone(&start);
    let worker_finish = std::sync::Arc::clone(&finish);

    let worker = std::thread::spawn(move || {
        worker_start.wait();
        let slot = worker_pool.try_allocate().unwrap();
        let index = slot.as_ref().map(|slot| slot.slot_index());
        worker_finish.wait();
        index
    });

    start.wait();
    let slot = pool.try_allocate().unwrap();
    let main_index = slot.as_ref().map(|slot| slot.slot_index());
    finish.wait();
    let worker_index = worker.join().unwrap();

    if let (Some(left), Some(right)) = (main_index, worker_index) {
        assert_ne!(left, right);
    }
}

#[cfg(all(
    feature = "guard-pages",
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64"),
    not(miri)
))]
#[test]
fn guarded_secret_vec_round_trip_grow_and_clear() {
    let mut secret = GuardedSecretVec::from_slice(&[1, 2, 3]).unwrap();

    assert_eq!(secret.len(), 3);
    assert!(secret.capacity() >= 3);
    assert!(!secret.is_memory_locked());
    assert_eq!(secret.with_secret_or_panic(|bytes| bytes[0]), 1);
    assert!(secret.constant_time_eq_or_panic(&[1, 2, 3]));
    assert!(!secret.constant_time_eq_or_panic(&[1, 2]));

    secret.with_secret_mut_or_panic(|bytes| bytes[0] = 9);
    let original_capacity = secret.capacity();
    let extra = [4_u8; 5000];
    secret.try_extend_from_slice(&extra).unwrap();

    assert!(secret.capacity() > original_capacity);
    assert_eq!(secret.len(), 5003);
    assert_eq!(
        secret.with_secret_or_panic(|bytes| (bytes[0], bytes[2], bytes[5002])),
        (9, 3, 4)
    );

    secret.clear_secret();
    assert!(secret.is_empty());
    #[cfg(feature = "canary-check")]
    assert_eq!(secret.verify_integrity(), Ok(()));
    secret.try_extend_from_slice(b"world").unwrap();
    assert!(secret.constant_time_eq_or_panic(b"world"));

    secret.into_cleared();
}

#[cfg(all(
    feature = "guard-pages",
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64"),
    not(miri)
))]
#[test]
fn guarded_secret_vec_can_replace_secret() {
    let mut secret = GuardedSecretVec::from_slice(&[1, 2, 3, 4]).unwrap();
    let original_capacity = secret.capacity();

    secret.try_replace_from_slice(&[9, 8]).unwrap();

    assert_eq!(secret.len(), 2);
    assert_eq!(secret.capacity(), original_capacity);
    assert!(secret.constant_time_eq_or_panic(&[9, 8]));

    let larger = [7_u8; 70_000];
    secret.try_replace_from_slice(&larger).unwrap();

    assert_eq!(secret.len(), larger.len());
    assert!(secret.capacity() >= larger.len());
    assert_eq!(
        secret.with_secret_or_panic(|bytes| (bytes[0], bytes[69_999])),
        (7, 7)
    );

    secret.clear_secret();
}

#[cfg(all(
    feature = "guard-pages",
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64"),
    not(miri)
))]
#[test]
fn guarded_secret_vec_can_replace_from_fn() {
    let mut secret = GuardedSecretVec::from_slice(&[1, 2, 3, 4]).unwrap();

    secret
        .try_replace_from_fn(3, |index| (index as u8) + 7)
        .unwrap();

    assert_eq!(secret.len(), 3);
    assert!(secret.constant_time_eq_or_panic(&[7, 8, 9]));

    assert_eq!(
        secret
            .try_replace_from_fallible_fn(4, |index| {
                if index == 2 {
                    Err("generation failed")
                } else {
                    Ok(index as u8)
                }
            })
            .err(),
        Some(SecretIntegrityError::Operation(
            GuardedSecretVecGenerateError::Generate("generation failed")
        ))
    );
    assert!(secret.constant_time_eq_or_panic(&[7, 8, 9]));

    secret
        .try_replace_from_fallible_fn(4, |index| Ok::<u8, &'static str>((index as u8) + 1))
        .unwrap();

    assert!(secret.constant_time_eq_or_panic(&[1, 2, 3, 4]));

    secret.clear_secret();
    assert!(secret.is_empty());
}

#[cfg(all(
    feature = "guard-pages",
    feature = "cache-flush",
    target_os = "linux",
    target_arch = "x86_64",
    not(miri)
))]
#[test]
fn guarded_secret_vec_can_clear_and_flush() {
    let mut secret = GuardedSecretVec::from_slice(&[1, 2, 3, 4]).unwrap();

    secret.try_clear_secret_and_flush().unwrap();

    assert!(secret.is_empty());
    #[cfg(feature = "canary-check")]
    assert_eq!(secret.verify_integrity(), Ok(()));
    #[cfg(not(feature = "canary-check"))]
    assert_eq!(secret.with_secret_or_panic(|bytes| bytes.len()), 0);

    let wrapped = crate::cache_flush::CacheFlushOnDrop::new(
        GuardedSecretVec::from_slice(&[5, 6, 7, 8]).unwrap(),
    );
    assert_eq!(wrapped.with_secret(|secret| secret.len()), 4);
    wrapped.into_cleared().unwrap();
}

#[cfg(all(
    feature = "std",
    feature = "guard-pages",
    feature = "canary-check",
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64"),
    not(miri)
))]
#[test]
fn guarded_secret_vec_canaries_detect_corruption() {
    let mut secret = GuardedSecretVec::from_slice(&[1, 2, 3, 4]).unwrap();

    assert_eq!(secret.verify_integrity(), Ok(()));
    assert_eq!(secret.try_with_secret(|bytes| bytes[0]), Ok(1));
    assert_eq!(secret.try_constant_time_eq(&[1, 2, 3, 4]), Ok(true));

    secret.try_extend_from_slice(&[5, 6]).unwrap();
    assert_eq!(secret.try_with_secret(|bytes| bytes[5]), Ok(6));

    secret.corrupt_suffix_canary_for_test();

    assert_eq!(
        ct::ConstantTimeEq::ct_eq(&secret, [1, 2, 3, 4, 5, 6].as_slice())
            .declassify_u8("test verifies corrupted guarded vector comparison fails closed"),
        0
    );

    #[cfg(feature = "subtle-interop")]
    {
        let same = GuardedSecretVec::from_slice(&[1, 2, 3, 4, 5, 6]).unwrap();
        assert!(!bool::from(subtle::ConstantTimeEq::ct_eq(&secret, &same)));
    }

    assert_eq!(
        secret.try_with_secret(|bytes| bytes[0]),
        Err(CanaryCorruptedError)
    );
    assert_eq!(
        secret.try_with_secret_mut(|bytes| bytes[0] = 9),
        Err(CanaryCorruptedError)
    );
    assert_eq!(
        secret.try_replace_from_slice(&[9, 8, 7, 6]),
        Err(SecretIntegrityError::Canary(CanaryCorruptedError))
    );
    assert_eq!(
        secret.try_constant_time_eq(&[1, 2, 3, 4]),
        Err(CanaryCorruptedError)
    );
    secret.clear_secret();
    assert_eq!(secret.verify_integrity(), Err(CanaryCorruptedError));
}

#[cfg(all(
    feature = "guard-pages",
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64"),
    not(miri)
))]
#[test]
fn guarded_secret_vec_can_initialize_from_fn() {
    let mut secret = GuardedSecretVec::from_fn(4, |index| (index as u8) + 1).unwrap();

    assert_eq!(secret.len(), 4);
    assert!(!secret.is_memory_locked());
    assert!(secret.constant_time_eq_or_panic(&[1, 2, 3, 4]));
    assert_eq!(
        secret.with_secret_or_panic(|bytes| (bytes[0], bytes[3])),
        (1, 4)
    );

    secret.clear_secret();
    assert!(secret.is_empty());
}

#[cfg(all(
    feature = "guard-pages",
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64"),
    not(miri)
))]
#[test]
fn guarded_secret_vec_can_initialize_from_fallible_fn() {
    let mut secret =
        GuardedSecretVec::try_from_fn(4, |index| Ok::<u8, &'static str>((index as u8) + 1))
            .unwrap();

    assert_eq!(secret.len(), 4);
    assert!(secret.constant_time_eq_or_panic(&[1, 2, 3, 4]));
    assert_eq!(
        GuardedSecretVec::try_from_fn(4, |index| {
            if index == 2 {
                Err("generation failed")
            } else {
                Ok(index as u8)
            }
        })
        .err(),
        Some(GuardedSecretVecGenerateError::Generate("generation failed"))
    );

    secret.clear_secret();
    assert!(secret.is_empty());
}

#[cfg(all(
    feature = "guard-pages",
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64"),
    not(miri)
))]
#[test]
fn guarded_secret_vec_policy_aware_fill_establishes_protection_first() {
    let request = ProtectionRequest::guarded();
    let secret = GuardedSecretVec::try_from_capacity_with_protection(32, request, |output| {
        assert_eq!(output.len(), 32);
        assert!(output.iter().all(|byte| *byte == 0));
        output[..5].copy_from_slice(b"token");
        output[5..].fill(0xa5);
        Ok::<usize, &'static str>(5)
    })
    .unwrap();

    assert!(secret.protection_report().satisfies(request));
    assert_eq!(secret.len(), 5);
    assert!(secret.constant_time_eq_or_panic(b"token"));
    assert!(secret.unreported_tail_is_clear_for_test());

    assert_eq!(
        GuardedSecretVec::try_from_capacity_with_protection(4, request, |output| {
            output.copy_from_slice(b"data");
            Err::<usize, _>("decode failed")
        })
        .err(),
        Some(ProtectedSecretFillError::Fill("decode failed"))
    );

    assert_eq!(
        GuardedSecretVec::try_from_capacity_with_protection(4, request, |_| {
            Ok::<usize, &'static str>(5)
        })
        .err(),
        Some(ProtectedSecretFillError::Length(LengthError {
            expected: 4,
            actual: 5,
        }))
    );

    let callback_ran = core::cell::Cell::new(false);
    assert_eq!(
        GuardedSecretVec::try_from_capacity_bounded_with_protection(9, 8, request, |_| {
            callback_ran.set(true);
            Ok::<usize, &'static str>(0)
        },)
        .err(),
        Some(ProtectedSecretFillError::CapacityLimit {
            maximum: 8,
            actual: 9,
        })
    );
    assert!(!callback_ran.get());
}

#[cfg(all(
    feature = "guard-pages",
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64"),
    not(miri)
))]
#[test]
fn bounded_guarded_secret_vec_enforces_logical_maximum_over_page_capacity() {
    let request = ProtectionRequest::guarded();
    let mut secret =
        BoundedGuardedSecretVec::<8>::try_from_capacity_with_protection(4, request, |output| {
            output.copy_from_slice(b"key!");
            Ok::<usize, core::convert::Infallible>(4)
        })
        .unwrap();

    assert!(secret.backing_capacity() > BoundedGuardedSecretVec::<8>::max_len());
    secret.try_extend_from_slice(b"1234").unwrap();
    assert_eq!(
        secret.try_extend_from_slice(b"x"),
        Err(BoundedMappedSecretError::CapacityLimit {
            maximum: 8,
            actual: 9,
        })
    );
    assert!(secret.try_constant_time_eq(b"key!1234").unwrap());

    let mut text =
        BoundedGuardedSecretString::<8>::from_secret_str_with_protection("key", request).unwrap();
    text.try_push_str("-1234").unwrap();
    assert_eq!(
        text.try_replace_from_secret_str("too-long!"),
        Err(BoundedMappedSecretError::CapacityLimit {
            maximum: 8,
            actual: 9,
        })
    );
    assert!(text.try_constant_time_eq("key-1234").unwrap());
}

#[cfg(all(
    feature = "guard-pages",
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64"),
    not(miri)
))]
#[test]
fn guarded_secret_vec_required_policy_failure_prevents_fill() {
    let request = ProtectionRequest {
        cache_policy: Requirement::Required,
        ..ProtectionRequest::guarded()
    };
    let callback_ran = core::cell::Cell::new(false);

    let result = GuardedSecretVec::try_from_capacity_with_protection(4, request, |_| {
        callback_ran.set(true);
        Ok::<usize, core::convert::Infallible>(4)
    });

    assert!(matches!(
        result,
        Err(ProtectedSecretFillError::Protection(ProtectionError {
            failure: ProtectionFailure {
                control: ProtectionControl::CachePolicy,
                ..
            },
            ..
        }))
    ));
    assert!(!callback_ran.get());
}

#[cfg(all(
    feature = "guard-pages",
    feature = "canary-check",
    feature = "std",
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64"),
    not(miri)
))]
#[test]
fn guarded_secret_vec_policy_aware_fill_detects_capacity_boundary_corruption() {
    let result = GuardedSecretVec::try_from_capacity_with_protection_and_corrupt_boundary_for_test(
        4,
        ProtectionRequest::guarded(),
        |output| {
            output.copy_from_slice(b"data");
            Ok::<usize, core::convert::Infallible>(4)
        },
    );

    assert!(matches!(
        result,
        Err(ProtectedSecretFillError::Integrity(CanaryCorruptedError))
    ));
}

#[cfg(all(
    feature = "guard-pages",
    feature = "memory-lock",
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64"),
    not(miri)
))]
#[test]
fn guarded_secret_vec_can_be_memory_locked() {
    let mut secret = match GuardedSecretVec::locked_from_slice(&[1, 2, 3]) {
        Ok(secret) => secret,
        Err(GuardPageError {
            operation:
                GuardPageOperation::DontDump | GuardPageOperation::DontFork | GuardPageOperation::Lock,
            ..
        }) => return,
        Err(error) => panic!("unexpected guarded lock error: {error:?}"),
    };

    assert!(secret.is_memory_locked());
    assert!(secret.constant_time_eq_or_panic(&[1, 2, 3]));

    secret.try_extend_from_slice(&[4]).unwrap();

    assert!(secret.is_memory_locked());
    assert_eq!(
        secret.with_secret_or_panic(|bytes| (bytes[0], bytes[3])),
        (1, 4)
    );

    let larger = [9_u8; 5000];
    secret.try_replace_from_slice(&larger).unwrap();

    assert!(secret.is_memory_locked());
    assert_eq!(secret.len(), larger.len());
    assert_eq!(
        secret.with_secret_or_panic(|bytes| (bytes[0], bytes[4999])),
        (9, 9)
    );

    secret
        .try_replace_from_fn(4, |index| (index as u8) + 1)
        .unwrap();

    assert!(secret.is_memory_locked());
    assert!(secret.constant_time_eq_or_panic(&[1, 2, 3, 4]));

    match secret.try_replace_from_fallible_fn(4, |index| {
        if index == 2 {
            Err("generation failed")
        } else {
            Ok(index as u8)
        }
    }) {
        Ok(_) => panic!("generation should have failed"),
        Err(SecretIntegrityError::Operation(GuardedSecretVecGenerateError::Generate(error))) => {
            assert_eq!(error, "generation failed");
        }
        Err(SecretIntegrityError::Operation(GuardedSecretVecGenerateError::Guard(error))) => {
            panic!("unexpected guarded setup error: {error:?}")
        }
        Err(SecretIntegrityError::Canary(error)) => {
            panic!("unexpected integrity error: {error}")
        }
    }

    assert!(secret.is_memory_locked());
    assert!(secret.constant_time_eq_or_panic(&[1, 2, 3, 4]));

    secret.clear_secret();
    assert!(secret.is_empty());
}

#[cfg(all(
    feature = "guard-pages",
    feature = "memory-lock",
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64"),
    not(miri)
))]
#[test]
fn guarded_secret_vec_can_initialize_locked_from_fn() {
    let mut secret = match GuardedSecretVec::locked_from_fn(4, |index| (index as u8) + 1) {
        Ok(secret) => secret,
        Err(GuardPageError {
            operation:
                GuardPageOperation::DontDump | GuardPageOperation::DontFork | GuardPageOperation::Lock,
            ..
        }) => return,
        Err(error) => panic!("unexpected guarded lock error: {error:?}"),
    };

    assert!(secret.is_memory_locked());
    assert!(secret.constant_time_eq_or_panic(&[1, 2, 3, 4]));
    assert_eq!(
        secret.with_secret_or_panic(|bytes| (bytes[0], bytes[3])),
        (1, 4)
    );

    secret.clear_secret();
    assert!(secret.is_empty());
}

#[cfg(all(
    feature = "guard-pages",
    feature = "memory-lock",
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64"),
    not(miri)
))]
#[test]
fn guarded_secret_vec_can_initialize_locked_from_fallible_fn() {
    let mut secret = match GuardedSecretVec::locked_try_from_fn(4, |index| {
        Ok::<u8, &'static str>((index as u8) + 1)
    }) {
        Ok(secret) => secret,
        Err(GuardedSecretVecGenerateError::Guard(GuardPageError {
            operation:
                GuardPageOperation::DontDump | GuardPageOperation::DontFork | GuardPageOperation::Lock,
            ..
        })) => return,
        Err(error) => panic!("unexpected guarded generation error: {error:?}"),
    };

    assert!(secret.is_memory_locked());
    assert_eq!(secret.len(), 4);
    assert!(secret.constant_time_eq_or_panic(&[1, 2, 3, 4]));

    match GuardedSecretVec::locked_try_from_fn(4, |index| {
        if index == 2 {
            Err("generation failed")
        } else {
            Ok(index as u8)
        }
    }) {
        Ok(_) => panic!("generation should have failed"),
        Err(GuardedSecretVecGenerateError::Guard(GuardPageError {
            operation:
                GuardPageOperation::DontDump | GuardPageOperation::DontFork | GuardPageOperation::Lock,
            ..
        })) => return,
        Err(GuardedSecretVecGenerateError::Guard(error)) => {
            panic!("unexpected guarded setup error: {error:?}")
        }
        Err(GuardedSecretVecGenerateError::Generate(error)) => {
            assert_eq!(error, "generation failed");
        }
    }

    secret.clear_secret();
    assert!(secret.is_empty());
}

#[cfg(all(
    feature = "guard-pages",
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64"),
    not(miri)
))]
#[test]
fn guarded_secret_vec_debug_is_redacted_and_sanitizable() {
    let mut secret = GuardedSecretVec::from_slice(b"secret").unwrap();
    let rendered = std::format!("{secret:?}");

    assert!(rendered.contains("redacted"));
    assert!(!rendered.contains("secret"));

    secret.secure_sanitize();
    assert!(secret.is_empty());
}
