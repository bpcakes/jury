use std::io::Write;
use std::{process::Child, time::Duration};

use jury_protected::StreamingRedactor;

use super::{
    ACTIVE_OUTPUT_POLL_INTERVAL, BoundedProcessOutput, MAX_OUTPUT_READS_PER_POLL,
    MAX_OUTPUT_READS_PER_POLL_AFTER_TRUNCATION, OwnedProcessObserver, OwnedProcessOutputStream,
    ProcessOutputLimits, ProcessOutputRedaction, ProcessPipe, TRUNCATED_OUTPUT_POLL_INTERVAL,
};

pub(super) struct OutputDrain {
    reader: Option<ProcessPipe>,
    redactor: Option<StreamingRedactor>,
    bytes: Vec<u8>,
    limit: usize,
    truncated: bool,
    complete: bool,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct OutputPoll {
    pub(super) made_progress: bool,
    pub(super) overflow: Option<OwnedProcessOutputStream>,
}

struct CaptureSink<'a> {
    stream: OwnedProcessOutputStream,
    observer: &'a mut dyn OwnedProcessObserver,
    bytes: &'a mut Vec<u8>,
    limit: usize,
    truncated: &'a mut bool,
}

impl Write for CaptureSink<'_> {
    fn write(&mut self, visible: &[u8]) -> std::io::Result<usize> {
        self.observer.output(self.stream, visible);
        let remaining = self.limit.saturating_sub(self.bytes.len());
        let retained = remaining.min(visible.len());
        self.bytes.extend_from_slice(&visible[..retained]);
        *self.truncated |= retained < visible.len();
        Ok(visible.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl OutputDrain {
    pub(super) fn start(
        reader: ProcessPipe,
        limit: usize,
        redactor: Option<StreamingRedactor>,
    ) -> std::io::Result<Self> {
        reader.prepare()?;
        Ok(Self {
            reader: Some(reader),
            redactor,
            bytes: Vec::new(),
            limit,
            truncated: false,
            complete: false,
        })
    }

    fn emit(
        &mut self,
        stream: OwnedProcessOutputStream,
        raw: &[u8],
        observer: &mut dyn OwnedProcessObserver,
    ) -> std::io::Result<bool> {
        let was_truncated = self.truncated;
        let mut sink = CaptureSink {
            stream,
            observer,
            bytes: &mut self.bytes,
            limit: self.limit,
            truncated: &mut self.truncated,
        };
        match &mut self.redactor {
            Some(redactor) => redactor.push_chunk(raw, &mut sink)?,
            None => sink.write_all(raw)?,
        }
        Ok(!was_truncated && self.truncated)
    }

    fn finish_redaction(
        &mut self,
        stream: OwnedProcessOutputStream,
        observer: &mut dyn OwnedProcessObserver,
    ) -> std::io::Result<bool> {
        let Some(redactor) = self.redactor.take() else {
            return Ok(false);
        };
        let was_truncated = self.truncated;
        let mut sink = CaptureSink {
            stream,
            observer,
            bytes: &mut self.bytes,
            limit: self.limit,
            truncated: &mut self.truncated,
        };
        redactor.finish(&mut sink)?;
        Ok(!was_truncated && self.truncated)
    }

    pub(super) fn poll(
        &mut self,
        stream: OwnedProcessOutputStream,
        observer: &mut dyn OwnedProcessObserver,
    ) -> std::io::Result<OutputPoll> {
        // A shell can issue thousands of tiny writes. Bound every poll to 64
        // read attempts while the retained output is capped separately. Once
        // capture truncates, tighten the attempt budget to 16.
        let Some(_) = self.reader.as_mut() else {
            return Ok(OutputPoll::default());
        };
        let mut chunk = [0_u8; 4096];
        let mut poll = OutputPoll::default();
        for read_index in 0..MAX_OUTPUT_READS_PER_POLL {
            if self.truncated && read_index >= MAX_OUTPUT_READS_PER_POLL_AFTER_TRUNCATION {
                return Ok(poll);
            }
            let read_result = self
                .reader
                .as_mut()
                .ok_or_else(|| std::io::Error::other("process output reader disappeared"))?
                .read_available(&mut chunk);
            match read_result {
                Ok(0) => {
                    self.reader = None;
                    if self.finish_redaction(stream, observer)? {
                        poll.overflow = Some(stream);
                    }
                    self.complete = true;
                    return Ok(poll);
                }
                Ok(read) => {
                    poll.made_progress = true;
                    if self.emit(stream, &chunk[..read], observer)? {
                        poll.overflow = Some(stream);
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return Ok(poll),
                Err(_) => {
                    // Closing the reader makes an I/O failure terminal and
                    // drops any uncommitted redaction overlap rather than
                    // exposing it as an unredacted suffix.
                    self.reader = None;
                    self.redactor = None;
                    return Ok(poll);
                }
            }
        }
        Ok(poll)
    }

    const fn is_terminal(&self) -> bool {
        self.reader.is_none()
    }

    pub(super) fn finish(self) -> BoundedProcessOutput {
        BoundedProcessOutput {
            bytes: self.bytes,
            truncated: self.truncated,
            complete: self.complete,
        }
    }
}

pub(super) struct OwnedProcessOutputDrains {
    stdout: Option<OutputDrain>,
    stderr: Option<OutputDrain>,
}

impl OwnedProcessOutputDrains {
    pub(super) fn start(
        child: &mut Child,
        limits: ProcessOutputLimits,
        redaction: Option<ProcessOutputRedaction>,
    ) -> std::io::Result<Self> {
        let (stdout_redactor, stderr_redactor) = redaction.map_or((None, None), |redaction| {
            let (stdout, stderr) = redaction.into_streams();
            (Some(stdout), Some(stderr))
        });
        let stdout = child
            .stdout
            .take()
            .map(|reader| {
                OutputDrain::start(ProcessPipe::Stdout(reader), limits.stdout, stdout_redactor)
            })
            .transpose()?;
        let stderr = child
            .stderr
            .take()
            .map(|reader| {
                OutputDrain::start(ProcessPipe::Stderr(reader), limits.stderr, stderr_redactor)
            })
            .transpose()?;
        Ok(Self { stdout, stderr })
    }

    pub(super) fn poll(
        &mut self,
        observer: &mut dyn OwnedProcessObserver,
    ) -> std::io::Result<OutputPoll> {
        let stdout_poll = self.stdout.as_mut().map_or_else(
            || Ok(OutputPoll::default()),
            |drain| drain.poll(OwnedProcessOutputStream::Stdout, observer),
        )?;
        let stderr_poll = self.stderr.as_mut().map_or_else(
            || Ok(OutputPoll::default()),
            |drain| drain.poll(OwnedProcessOutputStream::Stderr, observer),
        )?;
        Ok(OutputPoll {
            made_progress: stdout_poll.made_progress || stderr_poll.made_progress,
            overflow: stdout_poll.overflow.or(stderr_poll.overflow),
        })
    }

    fn is_terminal(&self) -> bool {
        self.stdout.as_ref().is_none_or(OutputDrain::is_terminal)
            && self.stderr.as_ref().is_none_or(OutputDrain::is_terminal)
    }

    pub(super) fn active_poll_interval(&self) -> Duration {
        if self.stdout.as_ref().is_some_and(|drain| drain.truncated)
            || self.stderr.as_ref().is_some_and(|drain| drain.truncated)
        {
            TRUNCATED_OUTPUT_POLL_INTERVAL
        } else {
            ACTIVE_OUTPUT_POLL_INTERVAL
        }
    }

    pub(super) fn finish(
        mut self,
        timeout: Duration,
        observer: &mut dyn OwnedProcessObserver,
    ) -> std::io::Result<(Option<BoundedProcessOutput>, Option<BoundedProcessOutput>)> {
        let deadline = std::time::Instant::now()
            .checked_add(timeout)
            .unwrap_or_else(std::time::Instant::now);
        while !self.is_terminal() && std::time::Instant::now() < deadline {
            let made_progress = self.poll(observer)?.made_progress;
            if !self.is_terminal() {
                if made_progress {
                    std::thread::sleep(self.active_poll_interval());
                } else {
                    std::thread::sleep(Duration::from_millis(2));
                }
            }
        }
        // Dropping an open reader closes the local pipe promptly. Dropping its
        // redactor also zeroizes any incomplete overlap.
        let stdout = self.stdout.map(OutputDrain::finish);
        let stderr = self.stderr.map(OutputDrain::finish);
        Ok((stdout, stderr))
    }
}
