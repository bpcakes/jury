use std::net::Shutdown;
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::os::unix::process::ExitStatusExt;
use std::process::{ChildStdout, ExitStatus};

use super::super::{
    OwnedProcessTreeError, ProcessOutputOverflowPolicy, finalize_owned_process_output,
};
use super::*;

#[derive(Default)]
struct Observer(Vec<u8>);
impl OwnedProcessObserver for Observer {
    fn output(&mut self, _: OwnedProcessOutputStream, bytes: &[u8]) -> std::io::Result<()> {
        self.0.extend_from_slice(bytes);
        Ok(())
    }
}

fn ready_drains(
    bytes: &[u8],
    limit: usize,
    redact: bool,
) -> std::io::Result<OwnedProcessOutputDrains> {
    let (reader, mut writer) = UnixStream::pair()?;
    writer.write_all(bytes)?;
    // Socket shutdown establishes EOF even if another test's concurrent fork
    // briefly inherits a duplicate writer. Merely waiting for a pipe-writing
    // child to exit does not establish that invariant in a parallel test binary.
    writer.shutdown(Shutdown::Write)?;
    let redactor = if redact {
        Some(
            StreamingRedactor::from_patterns([b"ExampleSecret".to_vec()])
                .map_err(std::io::Error::other)?,
        )
    } else {
        None
    };
    Ok(OwnedProcessOutputDrains {
        stdout: Some(OutputDrain::start(
            ProcessPipe::Stdout(ChildStdout::from(OwnedFd::from(reader))),
            limit,
            redactor,
        )?),
        stderr: None,
    })
}

#[test]
fn expired_drain_wait_still_reads_ready_bytes_and_eof() -> std::io::Result<()> {
    let drains = ready_drains(b"ExampleReadyOutput", 128, false)?;
    let (stdout, _) = drains.finish(Duration::ZERO, &mut Observer::default())?;
    let stdout = stdout.ok_or_else(|| std::io::Error::other("missing stdout"))?;
    assert!(stdout.complete);
    assert_eq!(stdout.bytes, b"ExampleReadyOutput");
    Ok(())
}

#[test]
fn expired_drain_redacts_before_capture_and_observation() -> std::io::Result<()> {
    let drains = ready_drains(b"ExampleSecret:Example", 128, true)?;
    let mut observer = Observer::default();
    let (stdout, _) = drains.finish(Duration::ZERO, &mut observer)?;
    let stdout = stdout.ok_or_else(|| std::io::Error::other("missing stdout"))?;
    assert!(stdout.complete);
    assert_eq!(stdout.bytes, b"[REDACTED]:Example");
    assert_eq!(observer.0, stdout.bytes);
    Ok(())
}

#[test]
fn expired_drain_preserves_fatal_overflow() -> std::io::Result<()> {
    let drains = ready_drains(b"ExampleOutput", 4, false)?;
    let (stdout, stderr) = drains.finish(Duration::ZERO, &mut Observer::default())?;
    let result = finalize_owned_process_output(
        Ok(ExitStatus::from_raw(0)),
        stdout,
        stderr,
        ProcessOutputOverflowPolicy::Error,
    );
    assert!(matches!(
        result,
        Err(OwnedProcessTreeError::OutputLimitExceeded(
            OwnedProcessOutputStream::Stdout
        ))
    ));
    Ok(())
}
