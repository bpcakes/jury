#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(test)]
mod tests {
    use sanitization::SecretVec;
    use std::{
        alloc::{GlobalAlloc, Layout, System},
        ptr,
        sync::atomic::{AtomicUsize, Ordering},
    };

    const MAX_QUARANTINED: usize = 16_384;
    static QUARANTINE_COUNT: AtomicUsize = AtomicUsize::new(0);
    static QUARANTINE_PTRS: [AtomicUsize; MAX_QUARANTINED] =
        [const { AtomicUsize::new(0) }; MAX_QUARANTINED];
    static QUARANTINE_LENS: [AtomicUsize; MAX_QUARANTINED] =
        [const { AtomicUsize::new(0) }; MAX_QUARANTINED];

    struct QuarantiningAllocator;

    unsafe impl GlobalAlloc for QuarantiningAllocator {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            // SAFETY: Delegates the allocation request unchanged to System.
            unsafe { System.alloc(layout) }
        }

        unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
            // SAFETY: Delegates the allocation request unchanged to System.
            unsafe { System.alloc_zeroed(layout) }
        }

        unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
            let index = QUARANTINE_COUNT.fetch_add(1, Ordering::AcqRel);
            if index < MAX_QUARANTINED {
                QUARANTINE_LENS[index].store(layout.size(), Ordering::Relaxed);
                QUARANTINE_PTRS[index].store(pointer as usize, Ordering::Release);
                return;
            }

            // SAFETY: The quarantine is full, so ownership returns to System
            // with the original pointer and layout.
            unsafe { System.dealloc(pointer, layout) }
        }

        unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
            let new_layout =
                Layout::from_size_align(new_size, layout.align()).expect("valid realloc layout");
            // SAFETY: Allocates a replacement block using the same allocator.
            let replacement = unsafe { System.alloc(new_layout) };
            if replacement.is_null() {
                return ptr::null_mut();
            }

            // SAFETY: Both allocations are valid for the copied minimum size
            // and do not overlap.
            unsafe {
                ptr::copy_nonoverlapping(pointer, replacement, layout.size().min(new_size));
                self.dealloc(pointer, layout);
            }
            replacement
        }
    }

    #[global_allocator]
    static ALLOCATOR: QuarantiningAllocator = QuarantiningAllocator;

    fn quarantined_since(start: usize) -> impl Iterator<Item = (*const u8, usize)> {
        let end = QUARANTINE_COUNT
            .load(Ordering::Acquire)
            .min(MAX_QUARANTINED);
        (start..end).filter_map(|index| {
            let pointer = QUARANTINE_PTRS[index].load(Ordering::Acquire);
            let len = QUARANTINE_LENS[index].load(Ordering::Relaxed);
            (pointer != 0).then_some((pointer as *const u8, len))
        })
    }

    fn contains_marker(pointer: *const u8, len: usize, marker: &[u8]) -> bool {
        if marker.is_empty() || marker.len() > len {
            return false;
        }

        // SAFETY: Quarantined allocations are deliberately not returned to
        // System, so the recorded allocation remains readable for its layout.
        let bytes = unsafe { std::slice::from_raw_parts(pointer, len) };
        bytes.windows(marker.len()).any(|window| window == marker)
    }

    #[test]
    fn dropped_secret_vec_leaves_no_marker_in_quarantined_allocation() {
        let marker = [0xA5_u8; 32];
        let start = QUARANTINE_COUNT.load(Ordering::Acquire);
        {
            let secret = SecretVec::from_slice(&marker);
            std::hint::black_box(secret);
        }

        let released: Vec<_> = quarantined_since(start).collect();
        assert!(
            !released.is_empty(),
            "the secret allocation was not quarantined"
        );
        assert!(
            released
                .iter()
                .all(|(pointer, len)| !contains_marker(*pointer, *len, &marker)),
            "a released allocation retained the secret marker"
        );
    }

    #[test]
    fn secret_vec_growth_clears_each_released_allocation() {
        let marker = [0x5A_u8; 32];
        let start = QUARANTINE_COUNT.load(Ordering::Acquire);
        {
            let mut secret = SecretVec::from_slice(&marker);
            for _ in 0..8 {
                secret.extend_from_slice(&marker);
            }
            std::hint::black_box(secret);
        }

        let released: Vec<_> = quarantined_since(start).collect();
        assert!(
            released.len() >= 2,
            "growth did not produce multiple quarantined allocations"
        );
        assert!(
            released
                .iter()
                .all(|(pointer, len)| !contains_marker(*pointer, *len, &marker)),
            "a growth or final allocation retained the secret marker"
        );
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum SetupStep {
        Map,
        DumpExclusion,
        ForkPolicy,
        Lock,
        Protect,
        Random,
        Flush,
    }

    #[derive(Default)]
    struct FaultModel {
        mapped: bool,
        locked: bool,
        protected: bool,
        live_container: bool,
    }

    impl FaultModel {
        fn construct(fail_at: SetupStep) -> Self {
            let mut model = Self::default();
            for step in [
                SetupStep::Map,
                SetupStep::DumpExclusion,
                SetupStep::ForkPolicy,
                SetupStep::Lock,
                SetupStep::Protect,
                SetupStep::Random,
                SetupStep::Flush,
            ] {
                if step == fail_at {
                    model.rollback();
                    return model;
                }
                match step {
                    SetupStep::Map => model.mapped = true,
                    SetupStep::Lock => model.locked = true,
                    SetupStep::Protect => model.protected = true,
                    SetupStep::DumpExclusion
                    | SetupStep::ForkPolicy
                    | SetupStep::Random
                    | SetupStep::Flush => {}
                }
            }
            model.live_container = true;
            model
        }

        fn rollback(&mut self) {
            self.protected = false;
            self.locked = false;
            self.mapped = false;
            self.live_container = false;
        }
    }

    #[test]
    fn every_required_setup_fault_rolls_back_established_resources() {
        for step in [
            SetupStep::Map,
            SetupStep::DumpExclusion,
            SetupStep::ForkPolicy,
            SetupStep::Lock,
            SetupStep::Protect,
            SetupStep::Random,
            SetupStep::Flush,
        ] {
            let result = FaultModel::construct(step);
            assert!(!result.mapped, "{step:?} failure retained a mapping");
            assert!(!result.locked, "{step:?} failure retained a lock");
            assert!(!result.protected, "{step:?} failure retained protection");
            assert!(
                !result.live_container,
                "{step:?} failure returned live storage"
            );
        }
    }
}
