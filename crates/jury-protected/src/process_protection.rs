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

trait CoreLimits {
    fn set_zero(&mut self) -> Result<(), CaptureError>;
    fn read(&mut self) -> Result<(u64, u64), CaptureError>;
}

struct PlatformCoreLimits;

fn suppression_error() -> CaptureError {
    CaptureError {
        kind: CaptureErrorKind::CoreSuppression,
    }
}

#[cfg(unix)]
impl CoreLimits for PlatformCoreLimits {
    fn set_zero(&mut self) -> Result<(), CaptureError> {
        #[cfg(test)]
        tests::before_set()?;
        rlimit::setrlimit(rlimit::Resource::CORE, 0, 0).map_err(|_| suppression_error())
    }

    fn read(&mut self) -> Result<(u64, u64), CaptureError> {
        #[cfg(test)]
        if let Some(result) = tests::read_override() {
            return result;
        }
        rlimit::getrlimit(rlimit::Resource::CORE).map_err(|_| suppression_error())
    }
}

#[cfg(not(unix))]
impl CoreLimits for PlatformCoreLimits {
    fn set_zero(&mut self) -> Result<(), CaptureError> {
        Err(CaptureError {
            kind: CaptureErrorKind::UnsupportedPlatform,
        })
    }
    fn read(&mut self) -> Result<(u64, u64), CaptureError> {
        Err(CaptureError {
            kind: CaptureErrorKind::UnsupportedPlatform,
        })
    }
}

fn suppress_with(limits: &mut impl CoreLimits) -> Result<(), CaptureError> {
    limits.set_zero()?;
    if limits.read()? != (0, 0) {
        return Err(suppression_error());
    }
    Ok(())
}

#[cfg(target_os = "macos")]
pub(crate) fn suppress_core_dumps() -> Result<(), CaptureError> {
    suppress_with(&mut PlatformCoreLimits)
}

pub(crate) fn core_dump_suppressed() -> bool {
    matches!(PlatformCoreLimits.read(), Ok((0, 0)))
}

/// Disables ordinary process core dumps before invoking a private callback.
pub fn capture_after_process_protection<T>(
    policy: ProtectionPolicy,
    status: ProtectionStatus,
    capture: impl FnOnce() -> T,
) -> Result<ProtectedCapture<T>, CaptureError> {
    capture_with(&mut PlatformCoreLimits, policy, status, capture)
}

fn capture_with<T>(
    suppressor: &mut impl CoreLimits,
    policy: ProtectionPolicy,
    mut status: ProtectionStatus,
    capture: impl FnOnce() -> T,
) -> Result<ProtectedCapture<T>, CaptureError> {
    suppress_with(suppressor)?;
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
#[path = "process_protection_tests.rs"]
pub(crate) mod tests;
