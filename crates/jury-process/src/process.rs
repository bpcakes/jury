#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::io::Read;
use std::process::{Child, ChildStderr, ChildStdout, Command, ExitStatus};
use std::time::{Duration, Instant};

use jury_protected::{ProtectedMemory, StreamingRedactor};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use rustix::process::Signal;
use wait_timeout::ChildExt;

#[cfg(target_os = "linux")]
use crate::unix::linux_process_group_has_live_members;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use crate::unix::{
    ConsecutiveQuiescence, ProcessGroupId, UnreapedChildObservation, observe_unreaped_child,
    signal_process_group,
};
mod input;
pub mod interaction;
mod output;

use input::{ProtectedInputDrain, prepare_process_input};
use output::{OutputDrain, OwnedProcessOutputDrains};

const OWNED_PROCESS_TREE_CLEANUP_TIMEOUT: Duration = Duration::from_millis(500);
#[cfg(any(target_os = "linux", target_os = "macos"))]
const OWNED_PROCESS_TREE_POLL_INTERVAL: Duration = Duration::from_millis(10);
const OWNED_PROCESS_OUTPUT_DRAIN_TIMEOUT: Duration = Duration::from_millis(100);
const OWNED_PROCESS_OUTPUT_LIMIT: usize = 16 * 1024;
#[cfg(any(target_os = "linux", target_os = "macos"))]
const REQUIRED_CONSECUTIVE_PROCESS_GROUP_PROOFS: u8 = 2;
// Output progress warrants a faster retry than idle process polling. A 1 ms
// floor keeps deadline and capture-limit enforcement responsive without
// sustaining thousands of wakeups per second for continuously chatty children.
const ACTIVE_OUTPUT_POLL_INTERVAL: Duration = Duration::from_millis(1);
const TRUNCATED_OUTPUT_POLL_INTERVAL: Duration = Duration::from_millis(2);
const MAX_OUTPUT_READS_PER_POLL: usize = 64;
const MAX_OUTPUT_READS_PER_POLL_AFTER_TRUNCATION: usize = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ProcessDeadline(Instant);

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProcessDeadlineRemaining {
    Time(Duration),
    Elapsed,
}

impl ProcessDeadline {
    fn after(timeout: Duration) -> Option<Self> {
        Instant::now().checked_add(timeout).map(Self)
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn remaining(self) -> ProcessDeadlineRemaining {
        self.0.checked_duration_since(Instant::now()).map_or(
            ProcessDeadlineRemaining::Elapsed,
            ProcessDeadlineRemaining::Time,
        )
    }

    const fn as_instant(self) -> Instant {
        self.0
    }
}

pub fn format_exit_status(status: &ExitStatus) -> String {
    match status.code() {
        Some(code) => format!("exit status {code}"),
        None => "termination by signal".to_string(),
    }
}

pub struct OwnedProcessTreeOutput {
    pub status: ExitStatus,
    pub stdout: Option<BoundedProcessOutput>,
    pub stderr: Option<BoundedProcessOutput>,
}

impl OwnedProcessTreeOutput {
    /// Returns a platform-neutral status while retaining the original status.
    pub fn portable_status(&self) -> PortableExitStatus {
        PortableExitStatus::from(self.status)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PortableExitStatus {
    pub code: Option<i32>,
    pub signal: Option<i32>,
}

impl From<ExitStatus> for PortableExitStatus {
    fn from(status: ExitStatus) -> Self {
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;
            Self {
                code: status.code(),
                signal: status.signal(),
            }
        }
        #[cfg(not(unix))]
        {
            Self {
                code: status.code(),
                signal: None,
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessSignal {
    Hangup,
    Interrupt,
    Quit,
    Terminate,
    User1,
    User2,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl ProcessSignal {
    const fn as_native(self) -> Signal {
        match self {
            Self::Hangup => Signal::HUP,
            Self::Interrupt => Signal::INT,
            Self::Quit => Signal::QUIT,
            Self::Terminate => Signal::TERM,
            Self::User1 => Signal::USR1,
            Self::User2 => Signal::USR2,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessTreePlatformSupport {
    /// Active `0.x` support backed by native Linux tests and release gates.
    LinuxProcessGroups,
    /// Source is retained for deferred work, but this is not a support claim.
    DeferredMacosBackend,
    /// No process-tree containment backend is available.
    Unsupported,
}

/// Reports the release-support status of the current target.
///
/// A deferred backend is not supported, shipped, or validated for active
/// `0.x` use even though provisional source remains available for future work.
pub const fn process_tree_platform_support() -> ProcessTreePlatformSupport {
    #[cfg(target_os = "linux")]
    return ProcessTreePlatformSupport::LinuxProcessGroups;
    #[cfg(target_os = "macos")]
    return ProcessTreePlatformSupport::DeferredMacosBackend;
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    ProcessTreePlatformSupport::Unsupported
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OwnedProcessOutputStream {
    Stdout,
    Stderr,
}

impl std::fmt::Display for OwnedProcessOutputStream {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Stdout => "stdout",
            Self::Stderr => "stderr",
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessOutputOverflowPolicy {
    /// Retain at most the configured limit while continuing to drain the pipe.
    Truncate,
    /// Fail when either final capture exceeds its limit, terminating the owned
    /// process tree promptly when overflow is observed before it exits.
    Error,
}

/// Receives process activity while an owned process tree is supervised.
/// Callbacks run on the supervision thread and should return quickly.
pub trait OwnedProcessObserver {
    fn cancelled(&mut self) -> bool {
        false
    }

    /// Receives already-redacted output. An error is terminal: the supervisor
    /// terminates and reaps the owned process tree instead of silently losing
    /// bytes that the observer promised to deliver.
    fn output(&mut self, _stream: OwnedProcessOutputStream, _bytes: &[u8]) -> std::io::Result<()> {
        Ok(())
    }

    /// Returns one pending signal to forward to the still-pinned process
    /// group. The supervisor observes the unreaped leader immediately before
    /// sending the signal, so a recycled numeric group is never targeted.
    fn signal(&mut self) -> Option<ProcessSignal> {
        None
    }

    fn poll(&mut self, _elapsed: Duration) {}
}

pub struct BoundedProcessOutput {
    pub bytes: Vec<u8>,
    pub truncated: bool,
    pub complete: bool,
}

impl BoundedProcessOutput {
    pub fn to_string_lossy(&self) -> String {
        String::from_utf8_lossy(&self.bytes).into_owned()
    }
}

#[derive(Debug)]
pub enum OwnedProcessTreeError {
    Start(std::io::Error),
    InvalidTimeout,
    TimedOut,
    CancelledBeforeStart,
    Cancelled,
    OutputLimitExceeded(OwnedProcessOutputStream),
    SignalForward(ProcessSignal),
    Stdin,
    Output,
    Await,
    Cleanup,
}

impl OwnedProcessTreeError {
    pub const fn is_cancellation(&self) -> bool {
        match self {
            Self::CancelledBeforeStart | Self::Cancelled => true,
            Self::Start(_)
            | Self::InvalidTimeout
            | Self::TimedOut
            | Self::OutputLimitExceeded(_)
            | Self::SignalForward(_)
            | Self::Stdin
            | Self::Output
            | Self::Await
            | Self::Cleanup => false,
        }
    }
}

impl std::fmt::Display for OwnedProcessTreeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Start(error) => write!(formatter, "the process tree could not start: {error}"),
            Self::InvalidTimeout => {
                formatter.write_str("the process-tree timeout is not representable")
            }
            Self::TimedOut => formatter.write_str("the process tree timed out"),
            Self::CancelledBeforeStart => {
                formatter.write_str("the process tree was cancelled before it started")
            }
            Self::Cancelled => formatter.write_str("the process tree was cancelled"),
            Self::OutputLimitExceeded(stream) => {
                write!(
                    formatter,
                    "the process tree exceeded its {stream} output limit"
                )
            }
            Self::SignalForward(signal) => {
                write!(formatter, "the process tree could not receive {signal:?}")
            }
            Self::Stdin => formatter.write_str("the process input could not be delivered safely"),
            Self::Output => formatter.write_str("the process output could not be captured safely"),
            Self::Await => formatter.write_str("the process tree could not be awaited"),
            Self::Cleanup => formatter.write_str("the process tree could not be cleaned up safely"),
        }
    }
}

impl std::error::Error for OwnedProcessTreeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Start(error) => Some(error),
            _ => None,
        }
    }
}

pub fn run_owned_process_tree_with_output(
    command: &mut Command,
    timeout: Duration,
    cancelled: impl FnMut() -> bool,
) -> std::result::Result<OwnedProcessTreeOutput, OwnedProcessTreeError> {
    run_owned_process_tree_with_output_limits(
        command,
        timeout,
        ProcessOutputLimits::default(),
        cancelled,
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcessOutputLimits {
    pub stdout: usize,
    pub stderr: usize,
}

pub struct ProcessOutputRedaction {
    redactor: StreamingRedactor,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessRunTimeout {
    Bounded(Duration),
    Unbounded,
}

pub struct OwnedProcessTreeOptions {
    pub timeout: ProcessRunTimeout,
    pub limits: ProcessOutputLimits,
    pub overflow_policy: ProcessOutputOverflowPolicy,
    pub redaction: Option<ProcessOutputRedaction>,
    /// Protected stdin has an all-bytes-delivered contract. If the child
    /// closes the pipe before every byte is written, supervision fails with
    /// [`OwnedProcessTreeError::Stdin`] even if the child exits successfully.
    pub stdin: Option<ProtectedMemory>,
}

impl OwnedProcessTreeOptions {
    #[must_use]
    pub const fn bounded(timeout: Duration) -> Self {
        Self {
            timeout: ProcessRunTimeout::Bounded(timeout),
            limits: ProcessOutputLimits {
                stdout: OWNED_PROCESS_OUTPUT_LIMIT,
                stderr: OWNED_PROCESS_OUTPUT_LIMIT,
            },
            overflow_policy: ProcessOutputOverflowPolicy::Truncate,
            redaction: None,
            stdin: None,
        }
    }

    #[must_use]
    pub const fn unbounded() -> Self {
        Self {
            timeout: ProcessRunTimeout::Unbounded,
            limits: ProcessOutputLimits {
                stdout: OWNED_PROCESS_OUTPUT_LIMIT,
                stderr: OWNED_PROCESS_OUTPUT_LIMIT,
            },
            overflow_policy: ProcessOutputOverflowPolicy::Truncate,
            redaction: None,
            stdin: None,
        }
    }
}

impl ProcessOutputRedaction {
    pub fn new(redactor: StreamingRedactor) -> Self {
        Self { redactor }
    }

    fn into_streams(self) -> (StreamingRedactor, StreamingRedactor) {
        let stdout = self.redactor.independent_stream();
        let stderr = self.redactor.independent_stream();
        (stdout, stderr)
    }
}

impl Default for ProcessOutputLimits {
    fn default() -> Self {
        Self {
            stdout: OWNED_PROCESS_OUTPUT_LIMIT,
            stderr: OWNED_PROCESS_OUTPUT_LIMIT,
        }
    }
}

pub fn run_owned_process_tree_with_output_limits(
    command: &mut Command,
    timeout: Duration,
    limits: ProcessOutputLimits,
    mut cancelled: impl FnMut() -> bool,
) -> std::result::Result<OwnedProcessTreeOutput, OwnedProcessTreeError> {
    struct CancellationObserver<'a, F>(&'a mut F);
    impl<F: FnMut() -> bool> OwnedProcessObserver for CancellationObserver<'_, F> {
        fn cancelled(&mut self) -> bool {
            (self.0)()
        }
    }

    run_owned_process_tree_with_output_limits_and_observer(
        command,
        timeout,
        limits,
        &mut CancellationObserver(&mut cancelled),
    )
}

pub fn run_owned_process_tree_with_output_limits_and_observer(
    command: &mut Command,
    timeout: Duration,
    limits: ProcessOutputLimits,
    observer: &mut dyn OwnedProcessObserver,
) -> std::result::Result<OwnedProcessTreeOutput, OwnedProcessTreeError> {
    run_owned_process_tree_with_output_policy_and_observer(
        command,
        timeout,
        limits,
        ProcessOutputOverflowPolicy::Truncate,
        observer,
    )
}

pub fn run_owned_process_tree_with_output_policy_and_observer(
    command: &mut Command,
    timeout: Duration,
    limits: ProcessOutputLimits,
    overflow_policy: ProcessOutputOverflowPolicy,
    observer: &mut dyn OwnedProcessObserver,
) -> std::result::Result<OwnedProcessTreeOutput, OwnedProcessTreeError> {
    run_owned_process_tree_with_redacted_output(
        command,
        timeout,
        limits,
        overflow_policy,
        None,
        observer,
    )
}

pub fn run_owned_process_tree_with_redacted_output(
    command: &mut Command,
    timeout: Duration,
    limits: ProcessOutputLimits,
    overflow_policy: ProcessOutputOverflowPolicy,
    redaction: Option<ProcessOutputRedaction>,
    observer: &mut dyn OwnedProcessObserver,
) -> std::result::Result<OwnedProcessTreeOutput, OwnedProcessTreeError> {
    run_owned_process_tree_with_options(
        command,
        OwnedProcessTreeOptions {
            timeout: ProcessRunTimeout::Bounded(timeout),
            limits,
            overflow_policy,
            redaction,
            stdin: None,
        },
        observer,
    )
}

pub fn run_owned_process_tree_with_options(
    command: &mut Command,
    options: OwnedProcessTreeOptions,
    observer: &mut dyn OwnedProcessObserver,
) -> std::result::Result<OwnedProcessTreeOutput, OwnedProcessTreeError> {
    if observer.cancelled() {
        return Err(OwnedProcessTreeError::CancelledBeforeStart);
    }
    let deadline = match options.timeout {
        ProcessRunTimeout::Bounded(timeout) => {
            Some(ProcessDeadline::after(timeout).ok_or(OwnedProcessTreeError::InvalidTimeout)?)
        }
        ProcessRunTimeout::Unbounded => None,
    };
    let mut process = spawn_owned_process(command).map_err(OwnedProcessTreeError::Start)?;
    let input = match prepare_process_input(&mut process.child, options.stdin) {
        Ok(input) => input,
        Err(_) => {
            return match process.terminate_and_reap() {
                Ok(_) => Err(OwnedProcessTreeError::Stdin),
                Err(_) => Err(OwnedProcessTreeError::Cleanup),
            };
        }
    };
    let Ok(mut drains) =
        OwnedProcessOutputDrains::start(&mut process.child, options.limits, options.redaction)
    else {
        return match process.terminate_and_reap() {
            Ok(_) => Err(OwnedProcessTreeError::Output),
            Err(_) => Err(OwnedProcessTreeError::Cleanup),
        };
    };
    let wait_result = wait_for_owned_process(
        &mut process,
        deadline,
        options.overflow_policy,
        observer,
        &mut drains,
        input,
    );
    let status = finish_owned_process_wait(&mut process, wait_result);
    let (stdout, stderr) = drains
        .finish(OWNED_PROCESS_OUTPUT_DRAIN_TIMEOUT, observer)
        .map_err(|_| OwnedProcessTreeError::Output)?;
    finalize_owned_process_output(status, stdout, stderr, options.overflow_policy)
}

fn finalize_owned_process_output(
    status: std::result::Result<ExitStatus, OwnedProcessTreeError>,
    stdout: Option<BoundedProcessOutput>,
    stderr: Option<BoundedProcessOutput>,
    overflow_policy: ProcessOutputOverflowPolicy,
) -> std::result::Result<OwnedProcessTreeOutput, OwnedProcessTreeError> {
    let status = status?;
    let overflow = match overflow_policy {
        ProcessOutputOverflowPolicy::Truncate => None,
        ProcessOutputOverflowPolicy::Error => [
            (OwnedProcessOutputStream::Stdout, &stdout),
            (OwnedProcessOutputStream::Stderr, &stderr),
        ]
        .into_iter()
        .find_map(|(stream, output)| {
            output
                .as_ref()
                .is_some_and(|output| output.truncated)
                .then_some(stream)
        }),
    };
    if let Some(stream) = overflow {
        return Err(OwnedProcessTreeError::OutputLimitExceeded(stream));
    }
    Ok(OwnedProcessTreeOutput {
        status,
        stdout,
        stderr,
    })
}

enum ProcessPipe {
    Stdout(ChildStdout),
    Stderr(ChildStderr),
}

impl ProcessPipe {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn prepare(&self) -> std::io::Result<()> {
        use std::os::fd::AsFd;

        let descriptor = match self {
            Self::Stdout(reader) => reader.as_fd(),
            Self::Stderr(reader) => reader.as_fd(),
        };
        crate::unix::set_nonblocking(descriptor)
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    fn prepare(&self) -> std::io::Result<()> {
        match self {
            Self::Stdout(reader) => {
                let _ = reader;
            }
            Self::Stderr(reader) => {
                let _ = reader;
            }
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "nonblocking process-pipe reads are unavailable on this platform",
        ))
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn read_available(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Stdout(reader) => reader.read(buffer),
            Self::Stderr(reader) => reader.read(buffer),
        }
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    fn read_available(&mut self, _buffer: &mut [u8]) -> std::io::Result<usize> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "nonblocking process-pipe reads are unavailable on this platform",
        ))
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PinnedProcessGroup {
    id: ProcessGroupId,
}

struct OwnedProcess {
    child: Child,
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    process_group: Option<PinnedProcessGroup>,
    reaped_status: Option<ExitStatus>,
    cleanup_complete: bool,
    cleanup_finalized: bool,
    cleanup_error: Option<StoredProcessCleanupError>,
    cleanup_deadline: Option<Instant>,
}

#[derive(Clone, Debug)]
struct StoredProcessCleanupError {
    kind: std::io::ErrorKind,
    message: String,
}

impl StoredProcessCleanupError {
    fn capture(error: &std::io::Error) -> Self {
        Self {
            kind: error.kind(),
            message: error.to_string(),
        }
    }

    fn to_io_error(&self) -> std::io::Error {
        std::io::Error::new(self.kind, self.message.clone())
    }
}

impl OwnedProcess {
    fn cleanup_deadline(&mut self) -> Instant {
        *self.cleanup_deadline.get_or_insert_with(|| {
            Instant::now()
                .checked_add(OWNED_PROCESS_TREE_CLEANUP_TIMEOUT)
                .unwrap_or_else(Instant::now)
        })
    }

    fn terminate_and_reap(&mut self) -> std::io::Result<ExitStatus> {
        self.terminate_and_reap_with(terminate_owned_process_tree)
    }

    fn terminate_and_reap_with(
        &mut self,
        terminate_tree: impl FnOnce(&mut Self, Instant) -> std::io::Result<()>,
    ) -> std::io::Result<ExitStatus> {
        if self.cleanup_finalized {
            return if self.cleanup_complete {
                self.reaped_status.ok_or_else(|| {
                    std::io::Error::other("owned-process cleanup completed without a leader status")
                })
            } else {
                Err(self
                    .cleanup_error
                    .as_ref()
                    .map(StoredProcessCleanupError::to_io_error)
                    .unwrap_or_else(|| {
                        std::io::Error::other(
                            "owned-process cleanup failed without a retained error",
                        )
                    }))
            };
        }

        let deadline = self.cleanup_deadline();
        let mut tree_cleanup_error = terminate_tree(self, deadline).err();
        let mut direct_fallback_error = None;
        if tree_cleanup_error.is_some() && self.reaped_status.is_none() {
            direct_fallback_error = terminate_owned_process_fallback(self).err();
        }

        let mut reap_error = None;
        if self.reaped_status.is_none() {
            // Every permitted signal is attempted while the direct child's
            // unconsumed wait status still pins its Unix PID/PGID generation.
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .unwrap_or_default();
            match self.child.wait_timeout(remaining) {
                Ok(Some(status)) => {
                    self.reaped_status = Some(status);
                    #[cfg(any(target_os = "linux", target_os = "macos"))]
                    {
                        self.process_group = None;
                    }
                }
                Ok(None) => {
                    reap_error = Some(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "owned-process cleanup timed out while reaping the direct child",
                    ));
                }
                Err(error) => {
                    #[cfg(any(target_os = "linux", target_os = "macos"))]
                    update_owned_process_identity_after_wait_error(self, &error);
                    reap_error = Some(error);
                }
            }
        }

        if let Some(error) = tree_cleanup_error.take() {
            let error = append_process_cleanup_error(
                error,
                "direct-child fallback also failed",
                direct_fallback_error,
            );
            let error =
                append_process_cleanup_error(error, "direct-child reap also failed", reap_error);
            return self.finalize_cleanup(Err(error));
        }
        if let Some(error) = reap_error {
            return self.finalize_cleanup(Err(error));
        }
        let status = self.reaped_status.ok_or_else(|| {
            std::io::Error::other("owned-process cleanup completed without a leader status")
        });
        self.finalize_cleanup(status)
    }

    fn finalize_cleanup(
        &mut self,
        result: std::io::Result<ExitStatus>,
    ) -> std::io::Result<ExitStatus> {
        self.cleanup_finalized = true;
        match result {
            Ok(status) => {
                self.cleanup_complete = true;
                Ok(status)
            }
            Err(error) => {
                self.cleanup_error = Some(StoredProcessCleanupError::capture(&error));
                Err(error)
            }
        }
    }
}

fn append_process_cleanup_error(
    primary: std::io::Error,
    label: &str,
    secondary: Option<std::io::Error>,
) -> std::io::Error {
    match secondary {
        Some(secondary) => {
            std::io::Error::new(primary.kind(), format!("{primary}; {label}: {secondary}"))
        }
        None => primary,
    }
}

impl Drop for OwnedProcess {
    fn drop(&mut self) {
        let _ = self.terminate_and_reap();
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OwnedProcessWait {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    ExitedUnreaped,
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    TimedOut,
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    Cancelled,
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    OutputLimitExceeded(OwnedProcessOutputStream),
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    SignalForward(ProcessSignal),
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    InputFailure,
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    OutputFailure,
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    Unsupported,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn wait_for_owned_process(
    process: &mut OwnedProcess,
    deadline: Option<ProcessDeadline>,
    overflow_policy: ProcessOutputOverflowPolicy,
    observer: &mut dyn OwnedProcessObserver,
    drains: &mut OwnedProcessOutputDrains,
    mut input: Option<ProtectedInputDrain>,
) -> std::io::Result<OwnedProcessWait> {
    let started = Instant::now();
    loop {
        let input_progress = match input.as_mut().map(ProtectedInputDrain::poll).transpose() {
            Ok(input_poll) => input_poll.is_some_and(|poll| poll.made_progress),
            Err(_) => return Ok(OwnedProcessWait::InputFailure),
        };
        let output_poll = match drains.poll(observer) {
            Ok(output_poll) => output_poll,
            Err(_) => return Ok(OwnedProcessWait::OutputFailure),
        };
        if overflow_policy == ProcessOutputOverflowPolicy::Error
            && let Some(stream) = output_poll.overflow
        {
            return Ok(OwnedProcessWait::OutputLimitExceeded(stream));
        }
        observer.poll(started.elapsed());
        if observer.cancelled() {
            return Ok(OwnedProcessWait::Cancelled);
        }
        if let Some(signal) = observer.signal()
            && forward_owned_process_signal(process, signal).is_err()
        {
            return Ok(OwnedProcessWait::SignalForward(signal));
        }
        if observe_owned_process(process)? == UnreapedChildObservation::Exited {
            return Ok(OwnedProcessWait::ExitedUnreaped);
        }

        match deadline.map(ProcessDeadline::remaining) {
            Some(ProcessDeadlineRemaining::Time(remaining)) => {
                if input_progress || output_poll.made_progress {
                    std::thread::sleep(remaining.min(drains.active_poll_interval()));
                } else {
                    std::thread::sleep(remaining.min(Duration::from_millis(10)));
                }
            }
            Some(ProcessDeadlineRemaining::Elapsed) => return Ok(OwnedProcessWait::TimedOut),
            None => {
                if input_progress || output_poll.made_progress {
                    std::thread::sleep(drains.active_poll_interval());
                } else {
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn update_owned_process_identity_after_wait_error(
    process: &mut OwnedProcess,
    error: &std::io::Error,
) {
    // ECHILD proves that this process no longer owns an unconsumed wait status;
    // another SIGCHLD consumer may have reaped the leader and released its
    // PID/PGID. EINVAL, ENOSYS, and other observation errors do not consume the
    // status, so the direct child continues to pin the group identity.
    if error_has_errno(error, rustix::io::Errno::CHILD) {
        process.process_group = None;
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn terminate_owned_process_fallback(process: &mut OwnedProcess) -> std::io::Result<()> {
    if process.process_group.is_none() {
        return Err(std::io::Error::other(
            "owned child identity is no longer pinned; refusing direct fallback",
        ));
    }
    match process.child.kill() {
        Ok(()) => Ok(()),
        Err(error) if error_has_errno(&error, rustix::io::Errno::SRCH) => {
            if observe_owned_process(process)? == UnreapedChildObservation::Exited {
                Ok(())
            } else {
                Err(error)
            }
        }
        Err(error) => Err(error),
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn terminate_owned_process_fallback(_process: &mut OwnedProcess) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "owned process-tree supervision is unavailable on this platform",
    ))
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn wait_for_owned_process(
    _process: &mut OwnedProcess,
    _deadline: Option<ProcessDeadline>,
    _overflow_policy: ProcessOutputOverflowPolicy,
    observer: &mut dyn OwnedProcessObserver,
    drains: &mut OwnedProcessOutputDrains,
    _input: Option<ProtectedInputDrain>,
) -> std::io::Result<OwnedProcessWait> {
    let _ = drains.poll(observer);
    Ok(OwnedProcessWait::Unsupported)
}

fn finish_owned_process_wait(
    process: &mut OwnedProcess,
    wait_result: std::io::Result<OwnedProcessWait>,
) -> std::result::Result<ExitStatus, OwnedProcessTreeError> {
    let outcome = match wait_result {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        Ok(OwnedProcessWait::ExitedUnreaped) => None,
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        Ok(OwnedProcessWait::TimedOut) => Some(Err(OwnedProcessTreeError::TimedOut)),
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        Ok(OwnedProcessWait::Cancelled) => Some(Err(OwnedProcessTreeError::Cancelled)),
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        Ok(OwnedProcessWait::OutputLimitExceeded(stream)) => {
            Some(Err(OwnedProcessTreeError::OutputLimitExceeded(stream)))
        }
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        Ok(OwnedProcessWait::SignalForward(signal)) => {
            Some(Err(OwnedProcessTreeError::SignalForward(signal)))
        }
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        Ok(OwnedProcessWait::InputFailure) => Some(Err(OwnedProcessTreeError::Stdin)),
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        Ok(OwnedProcessWait::OutputFailure) => Some(Err(OwnedProcessTreeError::Output)),
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        Ok(OwnedProcessWait::Unsupported) => Some(Err(OwnedProcessTreeError::Await)),
        Err(_) => Some(Err(OwnedProcessTreeError::Await)),
    };
    // A owned process leader can exit while a background descendant keeps running.
    // End the owned tree on every outcome before reading captured output.
    let cleanup = process.terminate_and_reap();
    if cleanup.is_err() {
        return Err(OwnedProcessTreeError::Cleanup);
    }
    match outcome {
        Some(outcome) => outcome,
        None => cleanup.map_err(|_| OwnedProcessTreeError::Await),
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn terminate_spawn_failure_child(child: &mut Child, deadline: Instant) {
    let _ = child.kill();
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .unwrap_or_default();
    let _ = child.wait_timeout(remaining);
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn spawn_owned_process(command: &mut Command) -> std::io::Result<OwnedProcess> {
    use std::os::unix::process::CommandExt;

    command.process_group(0);
    let mut child = command.spawn()?;
    let Ok(process_group) = ProcessGroupId::try_from(child.id()) else {
        let deadline = Instant::now()
            .checked_add(OWNED_PROCESS_TREE_CLEANUP_TIMEOUT)
            .unwrap_or_else(Instant::now);
        terminate_spawn_failure_child(&mut child, deadline);
        return Err(std::io::Error::other(
            "owned process identifier is not representable",
        ));
    };
    Ok(OwnedProcess {
        child,
        process_group: Some(PinnedProcessGroup { id: process_group }),
        reaped_status: None,
        cleanup_complete: false,
        cleanup_finalized: false,
        cleanup_error: None,
        cleanup_deadline: None,
    })
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn spawn_owned_process(_command: &mut Command) -> std::io::Result<OwnedProcess> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "owned process-tree supervision is unavailable on this platform",
    ))
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn observe_owned_process(process: &mut OwnedProcess) -> std::io::Result<UnreapedChildObservation> {
    let process_group = process
        .process_group
        .ok_or_else(|| std::io::Error::other("owned process-group identity is no longer pinned"))?;
    let status = match observe_unreaped_child(process_group.id) {
        Ok(status) => status,
        Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {
            return Ok(UnreapedChildObservation::Running);
        }
        Err(error) => {
            update_owned_process_identity_after_wait_error(process, &error);
            return Err(error);
        }
    };
    Ok(status)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn forward_owned_process_signal(
    process: &mut OwnedProcess,
    signal: ProcessSignal,
) -> std::io::Result<()> {
    let process_group = process.process_group.ok_or_else(|| {
        std::io::Error::other(
            "owned process-group identity is no longer pinned; refusing to forward a signal",
        )
    })?;
    let observation = observe_owned_process(process)?;
    let process_group = pinned_process_group_for_retry(process, process_group.id.as_raw())?;
    match signal_process_group(process_group.id, signal.as_native()) {
        Ok(()) => Ok(()),
        Err(error)
            if error_has_errno(&error, rustix::io::Errno::SRCH)
                && observation == UnreapedChildObservation::Exited =>
        {
            Ok(())
        }
        Err(error) => Err(error),
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn error_has_errno(error: &std::io::Error, errno: rustix::io::Errno) -> bool {
    error.raw_os_error() == std::io::Error::from(errno).raw_os_error()
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn terminate_owned_process_tree(
    process: &mut OwnedProcess,
    deadline: Instant,
) -> std::io::Result<()> {
    ensure_owned_process_cleanup_budget(deadline, "before process-group termination")?;
    let process_group = process.process_group.ok_or_else(|| {
        std::io::Error::other(
            "owned process-group identity is no longer pinned; refusing to signal it",
        )
    })?;
    confirm_process_group_quiescent(process, process_group.id.as_raw(), deadline)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProcessGroupSignalResult {
    Delivered,
    Inconclusive,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn pinned_process_group_for_retry(
    process: &OwnedProcess,
    expected_process_group: i32,
) -> std::io::Result<PinnedProcessGroup> {
    let process_group = process.process_group.ok_or_else(|| {
        std::io::Error::other(
            "owned process-group identity is no longer pinned; refusing to signal it",
        )
    })?;
    if process_group.id.as_raw() != expected_process_group {
        return Err(std::io::Error::other(format!(
            "owned process-group identity changed from pinned group {expected_process_group} to {}",
            process_group.id.as_raw()
        )));
    }
    Ok(process_group)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn observe_owned_process_before_group_signal_with<T>(
    state: &mut T,
    mut observe: impl FnMut(&mut T) -> std::io::Result<UnreapedChildObservation>,
    signal: impl FnOnce(&mut T, UnreapedChildObservation) -> std::io::Result<ProcessGroupSignalResult>,
) -> std::io::Result<ProcessGroupSignalResult> {
    let observation = observe(state)?;
    signal(state, observation)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn signal_pinned_process_group(
    process: &mut OwnedProcess,
    expected_process_group: i32,
    deadline: Instant,
) -> std::io::Result<ProcessGroupSignalResult> {
    ensure_owned_process_cleanup_budget(deadline, "before process-group SIGKILL")?;
    pinned_process_group_for_retry(process, expected_process_group)?;
    observe_owned_process_before_group_signal_with(
        process,
        observe_owned_process,
        |process, leader_observation| {
            // The exact WNOWAIT observation above must precede every numeric
            // group signal. If another waiter consumed the status, ECHILD has
            // already cleared the cached identity and this closure is never
            // entered.
            ensure_owned_process_cleanup_budget(deadline, "after pre-signal leader observation")?;
            let process_group = pinned_process_group_for_retry(process, expected_process_group)?;
            let error = match signal_process_group(process_group.id, Signal::KILL) {
                Ok(()) => return Ok(ProcessGroupSignalResult::Delivered),
                Err(error) => error,
            };
            if error_has_errno(&error, rustix::io::Errno::SRCH) {
                // ESRCH only says that this pinned generation had no signalable
                // member at this instant. A concurrently starting descendant
                // may still become visible, so only the following platform
                // proof may finish cleanup.
                return Ok(ProcessGroupSignalResult::Inconclusive);
            }
            #[cfg(target_os = "macos")]
            if error_has_errno(&error, rustix::io::Errno::PERM) {
                return resolve_macos_process_group_signal_eperm(error, Ok(leader_observation));
            }
            #[cfg(not(target_os = "macos"))]
            let _ = leader_observation;
            Err(error)
        },
    )
}

#[cfg(target_os = "macos")]
fn resolve_macos_process_group_signal_eperm(
    signal_error: std::io::Error,
    leader_observation: std::io::Result<UnreapedChildObservation>,
) -> std::io::Result<ProcessGroupSignalResult> {
    match leader_observation {
        Ok(UnreapedChildObservation::Exited) => {
            // Darwin can report EPERM for a group containing only its zombie
            // leader, but EPERM is not absence. The confirmation loop must
            // still take a fresh atomic sole-leader snapshot before success.
            Ok(ProcessGroupSignalResult::Inconclusive)
        }
        Ok(UnreapedChildObservation::Running) => Err(signal_error),
        Err(observation_error) => Err(std::io::Error::new(
            observation_error.kind(),
            format!(
                "process-group SIGKILL failed: {signal_error}; failed to verify the pinned leader after EPERM: {observation_error}"
            ),
        )),
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
struct ProcessGroupQuiescence<'a> {
    process_group: i32,
    deadline: Instant,
    required_consecutive_proofs: u8,
    timeout_phase: &'a str,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn confirm_process_group_quiescent_with<T>(
    state: &mut T,
    quiescence: ProcessGroupQuiescence<'_>,
    mut signal: impl FnMut(&mut T, i32, Instant) -> std::io::Result<ProcessGroupSignalResult>,
    mut prove_quiescent: impl FnMut(&mut T, i32, Instant) -> std::io::Result<bool>,
    mut now: impl FnMut() -> Instant,
    mut sleep: impl FnMut(Duration),
) -> std::io::Result<()> {
    let mut consecutive = ConsecutiveQuiescence::new(quiescence.required_consecutive_proofs)
        .map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "owned process-group confirmation requires at least one proof",
            )
        })?;
    loop {
        owned_process_cleanup_remaining_at(quiescence.deadline, now(), quiescence.timeout_phase)?;
        // Signal before every proof. A descendant can become visible in this
        // pinned group after an earlier group signal, so polling alone cannot
        // make a prior SIGKILL authoritative for a later membership snapshot.
        let _signal_result = signal(state, quiescence.process_group, quiescence.deadline)?;
        owned_process_cleanup_remaining_at(
            quiescence.deadline,
            now(),
            "after process-group SIGKILL",
        )?;
        let is_quiescent = prove_quiescent(state, quiescence.process_group, quiescence.deadline)?;
        // Never accept a proof that completed outside the original absolute
        // cleanup budget.
        owned_process_cleanup_remaining_at(
            quiescence.deadline,
            now(),
            "after process-group confirmation",
        )?;
        if consecutive.observe(is_quiescent) {
            return Ok(());
        }

        let remaining = owned_process_cleanup_remaining_at(
            quiescence.deadline,
            now(),
            quiescence.timeout_phase,
        )?;
        sleep(remaining.min(OWNED_PROCESS_TREE_POLL_INTERVAL));
    }
}

#[cfg(target_os = "linux")]
fn confirm_process_group_quiescent(
    process: &mut OwnedProcess,
    process_group: i32,
    deadline: Instant,
) -> std::io::Result<()> {
    confirm_process_group_quiescent_with(
        process,
        ProcessGroupQuiescence {
            process_group,
            deadline,
            required_consecutive_proofs: REQUIRED_CONSECUTIVE_PROCESS_GROUP_PROOFS,
            timeout_phase: "while confirming the Linux process group",
        },
        signal_pinned_process_group,
        |_process, process_group, deadline| {
            linux_process_group_has_live_members(ProcessGroupId::new(process_group)?, deadline)
                .map(|live| !live)
        },
        Instant::now,
        std::thread::sleep,
    )
}

#[cfg(target_os = "macos")]
fn confirm_process_group_quiescent(
    process: &mut OwnedProcess,
    process_group: i32,
    deadline: Instant,
) -> std::io::Result<()> {
    confirm_process_group_quiescent_with(
        process,
        ProcessGroupQuiescence {
            process_group,
            deadline,
            required_consecutive_proofs: REQUIRED_CONSECUTIVE_PROCESS_GROUP_PROOFS,
            timeout_phase: "while confirming the macOS process group",
        },
        signal_pinned_process_group,
        |process, process_group, deadline| {
            pinned_process_group_for_retry(process, process_group)?;
            let leader_exited = observe_owned_process(process)? == UnreapedChildObservation::Exited;
            ensure_owned_process_cleanup_budget(deadline, "after macOS leader observation")?;
            if !leader_exited {
                return Ok(false);
            }
            let sole_pinned_leader =
                macos_process_group_contains_only_pinned_leader(process_group)?;
            ensure_owned_process_cleanup_budget(deadline, "after macOS process-group snapshot")?;
            Ok(sole_pinned_leader)
        },
        Instant::now,
        std::thread::sleep,
    )
}

#[cfg(target_os = "macos")]
fn macos_process_group_contains_only_pinned_leader(process_group: i32) -> std::io::Result<bool> {
    let process_group = ProcessGroupId::new(process_group).map_err(|_| {
        std::io::Error::other("macOS process-group snapshot used a non-positive pinned leader")
    })?;
    crate::unix::macos_process_group_contains_only_pinned_leader(process_group)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn ensure_owned_process_cleanup_budget(deadline: Instant, phase: &str) -> std::io::Result<()> {
    owned_process_cleanup_remaining_at(deadline, Instant::now(), phase).map(|_| ())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn owned_process_cleanup_remaining_at(
    deadline: Instant,
    now: Instant,
    phase: &str,
) -> std::io::Result<Duration> {
    deadline
        .checked_duration_since(now)
        .filter(|remaining| !remaining.is_zero())
        .ok_or_else(|| owned_process_cleanup_timeout(phase))
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn owned_process_cleanup_timeout(phase: &str) -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        format!("owned process-tree cleanup timed out {phase}"),
    )
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn terminate_owned_process_tree(
    _process: &mut OwnedProcess,
    _deadline: Instant,
) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "owned process-tree supervision is unavailable on this platform",
    ))
}

#[cfg(test)]
mod tests;
