use super::{OwnedProcessOutputStream, ProcessSignal};

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
    /// The original operation failed and subsequent cleanup also failed.
    /// Kept separate from cancellation so callers cannot report an unproven
    /// cleanup as an ordinary cancelled operation. `source()` retains the cause.
    CleanupAfterFailure(Box<Self>),
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
            | Self::Cleanup
            | Self::CleanupAfterFailure(_) => false,
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
            Self::CleanupAfterFailure(primary) => {
                write!(
                    formatter,
                    "{primary}; the process tree could not be cleaned up safely"
                )
            }
        }
    }
}

impl std::error::Error for OwnedProcessTreeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Start(error) => Some(error),
            Self::CleanupAfterFailure(primary) => Some(primary.as_ref()),
            _ => None,
        }
    }
}
