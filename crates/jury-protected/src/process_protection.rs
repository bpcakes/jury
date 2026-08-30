use std::fmt;

use crate::{ProtectionPolicy, ProtectionStatus};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CaptureErrorKind {
    CoreSuppression,
    DegradedMemory,
    UnsupportedPlatform,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CaptureError {
    kind: CaptureErrorKind,
}

impl CaptureError {
    #[must_use]
    pub const fn kind(&self) -> CaptureErrorKind {
        self.kind
    }
}

impl fmt::Debug for CaptureError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CaptureError")
            .field("kind", &self.kind)
            .finish()
    }
}

impl fmt::Display for CaptureError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.kind {
            CaptureErrorKind::CoreSuppression => {
                formatter.write_str("process core-dump suppression failed")
            }
            CaptureErrorKind::DegradedMemory => {
                formatter.write_str("strict capture refused degraded memory protection")
            }
            CaptureErrorKind::UnsupportedPlatform => {
                formatter.write_str("process core-dump suppression is unsupported on this platform")
            }
        }
    }
}

impl std::error::Error for CaptureError {}

/// Callback result paired with the exact protection status established first.
#[derive(Debug)]
pub struct ProtectedCapture<T> {
    pub value: T,
    pub status: ProtectionStatus,
}

trait CoreSuppressor {
    fn suppress(&mut self) -> Result<(), CaptureError>;
}

struct PlatformCoreSuppressor;

#[cfg(unix)]
impl CoreSuppressor for PlatformCoreSuppressor {
    fn suppress(&mut self) -> Result<(), CaptureError> {
        rlimit::setrlimit(rlimit::Resource::CORE, 0, 0).map_err(|_| CaptureError {
            kind: CaptureErrorKind::CoreSuppression,
        })
    }
}

#[cfg(not(unix))]
impl CoreSuppressor for PlatformCoreSuppressor {
    fn suppress(&mut self) -> Result<(), CaptureError> {
        Err(CaptureError {
            kind: CaptureErrorKind::UnsupportedPlatform,
        })
    }
}

/// Disables ordinary process core dumps before invoking a private callback.
pub fn capture_after_process_protection<T>(
    policy: ProtectionPolicy,
    status: ProtectionStatus,
    capture: impl FnOnce() -> T,
) -> Result<ProtectedCapture<T>, CaptureError> {
    capture_with(&mut PlatformCoreSuppressor, policy, status, capture)
}

fn capture_with<T>(
    suppressor: &mut impl CoreSuppressor,
    policy: ProtectionPolicy,
    mut status: ProtectionStatus,
    capture: impl FnOnce() -> T,
) -> Result<ProtectedCapture<T>, CaptureError> {
    suppressor.suppress()?;
    status.record_core_suppression();
    if policy == ProtectionPolicy::Strict && status.is_degraded() {
        return Err(CaptureError {
            kind: CaptureErrorKind::DegradedMemory,
        });
    }
    Ok(ProtectedCapture {
        value: capture(),
        status,
    })
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use crate::{MemoryError, ProtectedMemory};

    use super::*;

    fn status(policy: ProtectionPolicy) -> Result<ProtectionStatus, MemoryError> {
        ProtectedMemory::initialize(32, policy, |destination| {
            destination.fill(0xa5);
            Ok::<usize, ()>(destination.len())
        })
        .map(|memory| memory.status().clone())
    }

    struct FakeSuppressor<'a> {
        called: &'a Cell<bool>,
        fail: bool,
    }

    impl CoreSuppressor for FakeSuppressor<'_> {
        fn suppress(&mut self) -> Result<(), CaptureError> {
            self.called.set(true);
            if self.fail {
                Err(CaptureError {
                    kind: CaptureErrorKind::CoreSuppression,
                })
            } else {
                Ok(())
            }
        }
    }

    #[test]
    fn suppression_happens_before_callback() -> Result<(), Box<dyn std::error::Error>> {
        let suppressed = Cell::new(false);
        let capture = capture_with(
            &mut FakeSuppressor {
                called: &suppressed,
                fail: false,
            },
            ProtectionPolicy::Strict,
            status(ProtectionPolicy::Strict)?,
            || suppressed.get(),
        )?;
        assert!(capture.value);
        assert!(capture.status.core_dump_suppressed());
        Ok(())
    }

    #[test]
    fn suppression_failure_blocks_callback() -> Result<(), Box<dyn std::error::Error>> {
        let suppressed = Cell::new(false);
        let callback_called = Cell::new(false);
        let result = capture_with(
            &mut FakeSuppressor {
                called: &suppressed,
                fail: true,
            },
            ProtectionPolicy::Strict,
            status(ProtectionPolicy::Strict)?,
            || callback_called.set(true),
        );
        assert_eq!(
            result.map(|_| ()),
            Err(CaptureError {
                kind: CaptureErrorKind::CoreSuppression
            })
        );
        assert!(suppressed.get());
        assert!(!callback_called.get());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn real_unix_suppression_sets_hard_and_soft_limits_to_zero()
    -> Result<(), Box<dyn std::error::Error>> {
        let capture = capture_after_process_protection(
            ProtectionPolicy::Strict,
            status(ProtectionPolicy::Strict)?,
            || rlimit::getrlimit(rlimit::Resource::CORE),
        )?;
        assert_eq!(capture.value?, (0, 0));
        Ok(())
    }
}
