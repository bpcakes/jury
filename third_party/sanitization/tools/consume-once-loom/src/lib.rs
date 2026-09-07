//! Loom model for the `ConsumeOnceSecret` atomic ownership transition.
//!
//! This tool is intentionally outside the publishable workspace. It mirrors
//! the production `AtomicBool::swap(true, AcqRel)` claim and the cleanup-before-
//! return ordering without adding Loom to the runtime crate's dependency graph.

#[cfg(test)]
mod tests {
    use loom::{
        sync::{
            atomic::{AtomicBool, AtomicUsize, Ordering},
            Arc,
        },
        thread,
    };

    struct ConsumeModel {
        claimed: AtomicBool,
        active: AtomicUsize,
        cleared: AtomicBool,
    }

    impl ConsumeModel {
        fn new() -> Self {
            Self {
                claimed: AtomicBool::new(false),
                active: AtomicUsize::new(0),
                cleared: AtomicBool::new(false),
            }
        }

        fn claim(&self) -> Option<CleanupGuard<'_>> {
            if self.claimed.swap(true, Ordering::AcqRel) {
                return None;
            }

            assert_eq!(
                self.active.fetch_add(1, Ordering::AcqRel),
                0,
                "two accessors entered the protected value"
            );
            Some(CleanupGuard { owner: self })
        }
    }

    struct CleanupGuard<'a> {
        owner: &'a ConsumeModel,
    }

    impl Drop for CleanupGuard<'_> {
        fn drop(&mut self) {
            assert_eq!(self.owner.active.fetch_sub(1, Ordering::AcqRel), 1);
            self.owner.cleared.store(true, Ordering::Release);
        }
    }

    #[test]
    fn exactly_one_racing_consumer_enters_and_cleanup_completes() {
        loom::model(|| {
            let model = Arc::new(ConsumeModel::new());
            let successes = Arc::new(AtomicUsize::new(0));

            let first_model = Arc::clone(&model);
            let first_successes = Arc::clone(&successes);
            let first = thread::spawn(move || {
                if let Some(_guard) = first_model.claim() {
                    first_successes.fetch_add(1, Ordering::AcqRel);
                    thread::yield_now();
                }
            });

            let second_model = Arc::clone(&model);
            let second_successes = Arc::clone(&successes);
            let second = thread::spawn(move || {
                if let Some(_guard) = second_model.claim() {
                    second_successes.fetch_add(1, Ordering::AcqRel);
                    thread::yield_now();
                }
            });

            first.join().unwrap();
            second.join().unwrap();

            assert_eq!(successes.load(Ordering::Acquire), 1);
            assert_eq!(model.active.load(Ordering::Acquire), 0);
            assert!(model.claimed.load(Ordering::Acquire));
            assert!(model.cleared.load(Ordering::Acquire));
        });
    }

    #[test]
    fn cleanup_precedes_the_end_of_the_winning_scope() {
        loom::model(|| {
            let model = ConsumeModel::new();

            {
                let _guard = model.claim().expect("first claim must succeed");
                assert_eq!(model.active.load(Ordering::Acquire), 1);
                assert!(!model.cleared.load(Ordering::Acquire));
                assert!(model.claim().is_none());
            }

            assert_eq!(model.active.load(Ordering::Acquire), 0);
            assert!(model.cleared.load(Ordering::Acquire));
        });
    }
}

#[cfg(test)]
mod secret_pool_tests {
    use loom::{
        sync::{
            atomic::{AtomicBool, AtomicUsize, Ordering},
            Arc,
        },
        thread,
    };

    struct PoolSlotModel {
        used: AtomicBool,
        generation: AtomicUsize,
        active_handles: AtomicUsize,
        cleared: AtomicBool,
    }

    impl PoolSlotModel {
        fn new() -> Self {
            Self {
                used: AtomicBool::new(false),
                generation: AtomicUsize::new(0),
                active_handles: AtomicUsize::new(0),
                cleared: AtomicBool::new(true),
            }
        }

        fn allocate(&self) -> Option<PoolSlotGuard<'_>> {
            if self
                .used
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed)
                .is_err()
            {
                return None;
            }

            assert!(
                self.cleared.load(Ordering::Acquire),
                "a released slot was reused before clearing completed"
            );
            assert_eq!(
                self.active_handles.fetch_add(1, Ordering::AcqRel),
                0,
                "two live handles overlap one slot"
            );
            self.cleared.store(false, Ordering::Relaxed);

            Some(PoolSlotGuard {
                pool: self,
                generation: advance_generation(&self.generation),
            })
        }
    }

    struct PoolSlotGuard<'a> {
        pool: &'a PoolSlotModel,
        generation: usize,
    }

    impl Drop for PoolSlotGuard<'_> {
        fn drop(&mut self) {
            self.pool.cleared.store(true, Ordering::Relaxed);
            assert_eq!(self.pool.active_handles.fetch_sub(1, Ordering::AcqRel), 1);
            self.pool.used.store(false, Ordering::Release);
        }
    }

    fn advance_generation(generation: &AtomicUsize) -> usize {
        let mut current = generation.load(Ordering::Relaxed);
        loop {
            let mut next = current.wrapping_add(1);
            if next == 0 {
                next = 1;
            }
            match generation.compare_exchange_weak(
                current,
                next,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => return next,
                Err(observed) => current = observed,
            }
        }
    }

    #[test]
    fn racing_allocators_never_overlap_one_slot() {
        loom::model(|| {
            let pool = Arc::new(PoolSlotModel::new());

            let first_pool = Arc::clone(&pool);
            let first = thread::spawn(move || {
                let guard = first_pool.allocate();
                thread::yield_now();
                guard.map(|guard| guard.generation)
            });

            let second_pool = Arc::clone(&pool);
            let second = thread::spawn(move || {
                let guard = second_pool.allocate();
                thread::yield_now();
                guard.map(|guard| guard.generation)
            });

            let first_generation = first.join().unwrap();
            let second_generation = second.join().unwrap();

            assert!(
                first_generation.is_some() || second_generation.is_some(),
                "one allocator must claim an initially free slot"
            );
            assert_eq!(pool.active_handles.load(Ordering::Acquire), 0);
            assert!(!pool.used.load(Ordering::Acquire));
            assert!(pool.cleared.load(Ordering::Acquire));
        });
    }

    #[test]
    fn reuse_observes_clear_and_advances_generation() {
        loom::model(|| {
            let pool = Arc::new(PoolSlotModel::new());
            let first_pool = Arc::clone(&pool);
            let first = thread::spawn(move || {
                let guard = first_pool.allocate().expect("first allocation");
                guard.generation
            });
            let first_generation = first.join().unwrap();

            let second_pool = Arc::clone(&pool);
            let second = thread::spawn(move || {
                let guard = second_pool.allocate().expect("reused allocation");
                guard.generation
            });
            let second_generation = second.join().unwrap();

            assert_ne!(first_generation, second_generation);
            assert_ne!(second_generation, 0);
            assert!(pool.cleared.load(Ordering::Acquire));
        });
    }

    #[test]
    fn failed_slot_setup_releases_the_claim_once() {
        loom::model(|| {
            let pool = PoolSlotModel::new();

            let setup = pool.allocate().expect("setup claim");
            drop(setup);

            let retry = pool.allocate().expect("failed setup must release slot");
            assert_eq!(pool.active_handles.load(Ordering::Acquire), 1);
            drop(retry);

            assert_eq!(pool.active_handles.load(Ordering::Acquire), 0);
            assert!(!pool.used.load(Ordering::Acquire));
            assert!(pool.cleared.load(Ordering::Acquire));
        });
    }
}
