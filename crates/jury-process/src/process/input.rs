use std::io::Write as _;
use std::process::{Child, ChildStdin};

use jury_protected::ProtectedMemory;

const MAX_INPUT_WRITES_PER_POLL: usize = 64;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct InputPoll {
    pub(super) made_progress: bool,
}

pub(super) struct ProtectedInputDrain {
    writer: Option<ChildStdin>,
    input: ProtectedMemory,
    offset: usize,
}

impl ProtectedInputDrain {
    pub(super) fn start(child: &mut Child, input: ProtectedMemory) -> std::io::Result<Self> {
        use std::os::fd::AsFd as _;

        let writer = child
            .stdin
            .take()
            .ok_or_else(|| std::io::Error::other("protected process input requires piped stdin"))?;
        crate::unix::set_nonblocking(writer.as_fd())?;
        let writer = (!input.is_empty()).then_some(writer);
        Ok(Self {
            writer,
            input,
            offset: 0,
        })
    }

    pub(super) fn poll(&mut self) -> std::io::Result<InputPoll> {
        let Some(writer) = self.writer.as_mut() else {
            return Ok(InputPoll::default());
        };
        let mut poll = InputPoll::default();
        for _ in 0..MAX_INPUT_WRITES_PER_POLL {
            let result = self
                .input
                .expose(|bytes| writer.write(&bytes[self.offset..]))
                .map_err(|_| std::io::Error::other("protected process input is unavailable"))?;
            match result {
                Ok(0) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "protected process input made no progress",
                    ));
                }
                Ok(written) => {
                    self.offset = self.offset.checked_add(written).ok_or_else(|| {
                        std::io::Error::other("protected process input position overflowed")
                    })?;
                    poll.made_progress = true;
                    if self.offset == self.input.len() {
                        self.writer = None;
                        return Ok(poll);
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return Ok(poll),
                Err(error) => return Err(error),
            }
        }
        Ok(poll)
    }
}

pub(super) fn prepare_process_input(
    child: &mut Child,
    input: Option<ProtectedMemory>,
) -> std::io::Result<Option<ProtectedInputDrain>> {
    match input {
        Some(input) => ProtectedInputDrain::start(child, input).map(Some),
        None => {
            // Output-only callers must never accidentally retain a piped stdin
            // writer. An inherited or null stdin has no parent-side handle.
            drop(child.stdin.take());
            Ok(None)
        }
    }
}
