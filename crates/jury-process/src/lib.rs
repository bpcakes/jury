//! Jury-owned child-process containment for Linux.
//!
//! The macOS backend is provisional and retained only for deferred post-`0.x`
//! work; it is not a supported release surface or native validation claim.
//!
//! Unsupported platforms fail before spawn. A successful return proves that
//! the direct child was reaped and the complete process group was repeatedly
//! observed quiescent after termination. Jury remains pre-alpha; this boundary
//! has not received independent security review.
//!
//! The caller's [`std::process::Command`], standard-library spawn buffers,
//! kernel pipe buffers, and child address space may contain copies that this
//! crate neither owns nor zeroizes. Secret-consuming callers must keep values
//! out of argv and the ambient environment and configure streaming redaction
//! before observing or retaining child output.

#![forbid(unsafe_code)]

mod process;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod unix;

pub use process::interaction;
pub use process::{
    BoundedProcessOutput, OwnedProcessObserver, OwnedProcessOutputStream, OwnedProcessTreeError,
    OwnedProcessTreeOutput, PortableExitStatus, ProcessOutputLimits, ProcessOutputOverflowPolicy,
    ProcessOutputRedaction, ProcessSignal, ProcessTreePlatformSupport, format_exit_status,
    process_tree_platform_support, run_owned_process_tree_with_output,
    run_owned_process_tree_with_output_limits,
    run_owned_process_tree_with_output_limits_and_observer,
    run_owned_process_tree_with_output_policy_and_observer,
    run_owned_process_tree_with_redacted_output,
};
