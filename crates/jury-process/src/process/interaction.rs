use std::io::Read;
use std::process::{ChildStderr, ChildStdin, Command};
use std::time::{Duration, Instant};

use super::{
    BoundedProcessOutput, OWNED_PROCESS_OUTPUT_LIMIT, OutputDrain, OwnedProcess,
    OwnedProcessObserver, OwnedProcessOutputStream, OwnedProcessTreeError, ProcessDeadline,
    ProcessPipe, spawn_owned_process,
};

struct IgnoreProcessActivity;

impl OwnedProcessObserver for IgnoreProcessActivity {}

#[derive(Debug)]
pub enum OwnedProcessTreeInteractionError {
    Process(OwnedProcessTreeError),
    Interaction(ProcessInteractionFailure),
    InteractionAndCleanup(ProcessInteractionFailure),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessInteractionFailure {
    MissingStdin,
    MissingStdout,
    OutputPreparation,
    Callback,
}

impl std::fmt::Display for ProcessInteractionFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::MissingStdin => "the child stdin was not configured as a pipe",
            Self::MissingStdout => "the child stdout was not configured as a pipe",
            Self::OutputPreparation => "the child output could not be prepared for bounded reads",
            Self::Callback => "the bounded process interaction was rejected",
        })
    }
}

impl std::fmt::Display for OwnedProcessTreeInteractionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Process(error) => error.fmt(formatter),
            Self::Interaction(failure) => {
                write!(formatter, "the process interaction failed: {failure}")
            }
            Self::InteractionAndCleanup(failure) => write!(
                formatter,
                "the process tree could not be cleaned up safely; the process interaction also failed: {failure}"
            ),
        }
    }
}

impl std::error::Error for OwnedProcessTreeInteractionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Process(error) => Some(error),
            Self::Interaction(_) | Self::InteractionAndCleanup(_) => None,
        }
    }
}

pub struct ProcessInteractionStdout {
    pipe: ProcessPipe,
    stderr: Option<OutputDrain>,
}

impl ProcessInteractionStdout {
    fn new(
        stdout: std::process::ChildStdout,
        stderr: Option<ChildStderr>,
    ) -> std::io::Result<Self> {
        let pipe = ProcessPipe::Stdout(stdout);
        pipe.prepare()?;
        let stderr = stderr
            .map(|stderr| {
                OutputDrain::start(
                    ProcessPipe::Stderr(stderr),
                    OWNED_PROCESS_OUTPUT_LIMIT,
                    None,
                )
            })
            .transpose()?;
        Ok(Self { pipe, stderr })
    }

    /// Finishes the bounded stderr preview captured while stdout was polled.
    pub fn take_stderr_output(&mut self) -> Option<BoundedProcessOutput> {
        if let Some(stderr) = &mut self.stderr {
            let _ = stderr.poll(OwnedProcessOutputStream::Stderr, &mut IgnoreProcessActivity);
        }
        self.stderr.take().map(OutputDrain::finish)
    }
}

impl Read for ProcessInteractionStdout {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        if let Some(stderr) = &mut self.stderr {
            let _ = stderr.poll(OwnedProcessOutputStream::Stderr, &mut IgnoreProcessActivity);
        }
        self.pipe.read_available(buffer)
    }
}

/// Runs a cooperatively deadline-bounded exchange against an owned child process.
///
/// The interaction owns the child's stdin and nonblocking stdout and must honor
/// the supplied absolute deadline; this function cannot preempt a synchronous
/// closure that ignores it. Callers should keep writes small because stdin
/// remains a blocking pipe. Returning ends the exchange; the process tree is
/// then terminated and reaped so long-lived protocol servers cannot leak descendants.
/// Callback failures are typed and deliberately carry no caller-supplied text.
pub fn run_owned_process_tree_with_cooperative_interaction<T, F>(
    command: &mut Command,
    timeout: Duration,
    interaction: F,
) -> std::result::Result<T, OwnedProcessTreeInteractionError>
where
    F: FnOnce(
        ChildStdin,
        ProcessInteractionStdout,
        Instant,
    ) -> std::result::Result<T, ProcessInteractionFailure>,
{
    let deadline = ProcessDeadline::after(timeout).ok_or(
        OwnedProcessTreeInteractionError::Process(OwnedProcessTreeError::InvalidTimeout),
    )?;
    let mut process = spawn_owned_process(command)
        .map_err(OwnedProcessTreeError::Start)
        .map_err(OwnedProcessTreeInteractionError::Process)?;
    let Some(stdin) = process.child.stdin.take() else {
        return cleanup_failed_interaction(&mut process, ProcessInteractionFailure::MissingStdin);
    };
    let Some(stdout) = process.child.stdout.take() else {
        drop(stdin);
        return cleanup_failed_interaction(&mut process, ProcessInteractionFailure::MissingStdout);
    };
    let stderr = process.child.stderr.take();
    let stdout = match ProcessInteractionStdout::new(stdout, stderr) {
        Ok(stdout) => stdout,
        Err(_) => {
            drop(stdin);
            return cleanup_failed_interaction(
                &mut process,
                ProcessInteractionFailure::OutputPreparation,
            );
        }
    };

    let outcome = interaction(stdin, stdout, deadline.as_instant());
    finish_interaction(outcome, process.terminate_and_reap().map(|_| ()))
}

fn cleanup_failed_interaction<T>(
    process: &mut OwnedProcess,
    failure: ProcessInteractionFailure,
) -> std::result::Result<T, OwnedProcessTreeInteractionError> {
    finish_interaction(Err(failure), process.terminate_and_reap().map(|_| ()))
}

fn finish_interaction<T>(
    outcome: std::result::Result<T, ProcessInteractionFailure>,
    cleanup: std::io::Result<()>,
) -> std::result::Result<T, OwnedProcessTreeInteractionError> {
    match (outcome, cleanup) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(failure), Ok(())) => Err(OwnedProcessTreeInteractionError::Interaction(failure)),
        (Ok(_), Err(_)) => Err(OwnedProcessTreeInteractionError::Process(
            OwnedProcessTreeError::Cleanup,
        )),
        (Err(failure), Err(_)) => Err(OwnedProcessTreeInteractionError::InteractionAndCleanup(
            failure,
        )),
    }
}
