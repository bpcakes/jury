//! Shared lifecycle for bounded, single-owner state workers.

use std::{
    sync::mpsc::{self, Sender, SyncSender, TryRecvError},
    thread::{self, JoinHandle},
    time::Duration,
};

use crate::{AdapterError, AdapterErrorKind};

pub(crate) struct StateWorker {
    shutdown: Sender<()>,
    thread: JoinHandle<()>,
}

impl StateWorker {
    pub(crate) fn spawn<C: Send + 'static>(
        name: &str,
        capacity: usize,
        is_abandoned: impl Fn(&C) -> bool + Send + 'static,
        mut dispatch: impl FnMut(C) + Send + 'static,
    ) -> Result<(Self, SyncSender<C>), AdapterError> {
        let (sender, receiver) = mpsc::sync_channel::<C>(capacity.max(1));
        let (shutdown, shutdown_receiver) = mpsc::channel();
        let thread = thread::Builder::new()
            .name(name.to_owned())
            .spawn(move || {
                loop {
                    match shutdown_receiver.try_recv() {
                        Ok(()) | Err(TryRecvError::Disconnected) => break,
                        Err(TryRecvError::Empty) => {}
                    }
                    let command = match receiver.recv_timeout(Duration::from_millis(50)) {
                        Ok(command) => command,
                        Err(mpsc::RecvTimeoutError::Timeout) => continue,
                        Err(mpsc::RecvTimeoutError::Disconnected) => break,
                    };
                    match shutdown_receiver.try_recv() {
                        Ok(()) | Err(TryRecvError::Disconnected) => break,
                        Err(TryRecvError::Empty) => {}
                    }
                    if !is_abandoned(&command) {
                        dispatch(command);
                    }
                }
            })
            .map_err(|_| AdapterError::new(AdapterErrorKind::Io))?;
        Ok((Self { shutdown, thread }, sender))
    }

    pub(crate) fn shutdown(self) -> Result<(), AdapterError> {
        let _ = self.shutdown.send(());
        self.thread
            .join()
            .map_err(|_| AdapterError::new(AdapterErrorKind::Io))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;
    const WAIT: Duration = Duration::from_secs(5);

    struct Command {
        id: u8,
        response: tokio::sync::oneshot::Sender<()>,
    }

    #[test]
    fn queue_is_bounded_and_abandoned_work_is_skipped() -> TestResult {
        let (started, observed) = mpsc::channel();
        let (release, blocked) = mpsc::channel();
        let (worker, sender) = StateWorker::spawn(
            "example-state",
            0,
            |command: &Command| command.response.is_closed(),
            move |command| {
                let _ = started.send(command.id);
                if command.id == 1 {
                    assert!(blocked.recv_timeout(WAIT).is_ok());
                }
                let _ = command.response.send(());
            },
        )?;
        let (response, first) = tokio::sync::oneshot::channel();
        sender.try_send(Command { id: 1, response })?;
        assert_eq!(observed.recv_timeout(WAIT)?, 1);
        let (response, abandoned) = tokio::sync::oneshot::channel();
        sender.try_send(Command { id: 2, response })?;
        let (response, _third) = tokio::sync::oneshot::channel();
        assert!(matches!(
            sender.try_send(Command { id: 3, response }),
            Err(mpsc::TrySendError::Full(_))
        ));
        drop(abandoned);
        release.send(())?;
        first.blocking_recv()?;
        // A blocking send waits for the occupied queue slot, not a guessed delay.
        let (response, fourth) = tokio::sync::oneshot::channel();
        sender.send(Command { id: 4, response })?;
        assert_eq!(observed.recv_timeout(WAIT)?, 4);
        fourth.blocking_recv()?;
        worker.shutdown()?;
        assert!(observed.try_recv().is_err());
        Ok(())
    }

    #[test]
    fn shutdown_finishes_active_work_without_dispatching_queued_work() -> TestResult {
        let (started, observed) = mpsc::channel();
        let (release, blocked) = mpsc::channel();
        let (worker, sender) = StateWorker::spawn(
            "example-state",
            1,
            |_: &u8| false,
            move |command| {
                let _ = started.send(command);
                assert!(blocked.recv_timeout(WAIT).is_ok());
            },
        )?;
        sender.try_send(1)?;
        assert_eq!(observed.recv_timeout(WAIT)?, 1);
        sender.try_send(2)?;
        worker.shutdown.send(())?;
        release.send(())?;
        worker.shutdown()?;
        assert!(observed.try_recv().is_err());
        assert!(matches!(
            sender.try_send(3),
            Err(mpsc::TrySendError::Disconnected(_))
        ));
        Ok(())
    }
}
