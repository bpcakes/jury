use std::{
    sync::mpsc::{self, Sender, SyncSender, TryRecvError, TrySendError},
    thread::{self, JoinHandle},
    time::Duration,
};

use jury_protocol::{vault_v1::Digest32, witness_v1::WitnessStateAnchorV1};

use crate::{
    AdapterError, AdapterErrorKind,
    anchor::{AnchorCasResult, SqliteAnchorRepository},
    runtime::OperationDeadline,
};

#[derive(Clone)]
pub(super) struct AnchorRepositoryHandle {
    sender: SyncSender<QueuedAnchorCommand>,
}

pub(super) struct AnchorRepositoryWorker {
    handle: AnchorRepositoryHandle,
    shutdown: Sender<()>,
    thread: Option<JoinHandle<()>>,
}

struct QueuedAnchorCommand {
    deadline: OperationDeadline,
    command: AnchorCommand,
}

enum AnchorCommand {
    CheckReady(tokio::sync::oneshot::Sender<Result<(), AdapterError>>),
    Read(tokio::sync::oneshot::Sender<Result<Option<WitnessStateAnchorV1>, AdapterError>>),
    CompareAndSwap {
        expected_digest: Option<Digest32>,
        candidate: Box<WitnessStateAnchorV1>,
        response: tokio::sync::oneshot::Sender<Result<AnchorCasResult, AdapterError>>,
    },
}

impl AnchorCommand {
    fn response_is_closed(&self) -> bool {
        match self {
            Self::CheckReady(response) => response.is_closed(),
            Self::Read(response) => response.is_closed(),
            Self::CompareAndSwap { response, .. } => response.is_closed(),
        }
    }
}

impl AnchorRepositoryWorker {
    pub(super) fn spawn(
        mut repository: SqliteAnchorRepository,
        queue_capacity: usize,
    ) -> Result<Self, AdapterError> {
        let (sender, receiver) = mpsc::sync_channel::<QueuedAnchorCommand>(queue_capacity.max(1));
        let (shutdown, shutdown_receiver) = mpsc::channel();
        let thread = thread::Builder::new()
            .name("juryd-anchor-state".to_owned())
            .spawn(move || {
                loop {
                    match shutdown_receiver.try_recv() {
                        Ok(()) | Err(TryRecvError::Disconnected) => break,
                        Err(TryRecvError::Empty) => {}
                    }
                    let queued = match receiver.recv_timeout(Duration::from_millis(50)) {
                        Ok(command) => command,
                        Err(mpsc::RecvTimeoutError::Timeout) => continue,
                        Err(mpsc::RecvTimeoutError::Disconnected) => break,
                    };
                    match shutdown_receiver.try_recv() {
                        Ok(()) | Err(TryRecvError::Disconnected) => break,
                        Err(TryRecvError::Empty) => {}
                    }
                    if queued.command.response_is_closed() {
                        continue;
                    }
                    let deadline = queued.deadline.instant();
                    match queued.command {
                        AnchorCommand::CheckReady(response) => {
                            let result = repository.read_until(deadline).map(|_| ());
                            let _ = response.send(result);
                        }
                        AnchorCommand::Read(response) => {
                            let _ = response.send(repository.read_until(deadline));
                        }
                        AnchorCommand::CompareAndSwap {
                            expected_digest,
                            candidate,
                            response,
                        } => {
                            let _ = response.send(repository.compare_and_swap_until(
                                expected_digest.as_ref(),
                                &candidate,
                                deadline,
                            ));
                        }
                    }
                }
            })
            .map_err(|_| AdapterError::new(AdapterErrorKind::Io))?;
        Ok(Self {
            handle: AnchorRepositoryHandle { sender },
            shutdown,
            thread: Some(thread),
        })
    }

    pub(super) fn handle(&self) -> AnchorRepositoryHandle {
        self.handle.clone()
    }

    pub(super) fn shutdown(mut self) -> Result<(), AdapterError> {
        let _ = self.shutdown.send(());
        self.thread
            .take()
            .ok_or_else(|| AdapterError::new(AdapterErrorKind::Io))?
            .join()
            .map_err(|_| AdapterError::new(AdapterErrorKind::Io))
    }
}

impl AnchorRepositoryHandle {
    pub(super) async fn check_ready(
        &self,
        deadline: OperationDeadline,
    ) -> Result<(), AdapterError> {
        let (response, receiver) = tokio::sync::oneshot::channel();
        self.submit(deadline, AnchorCommand::CheckReady(response))?;
        receive(receiver).await
    }

    pub(super) async fn read(
        &self,
        deadline: OperationDeadline,
    ) -> Result<Option<WitnessStateAnchorV1>, AdapterError> {
        let (response, receiver) = tokio::sync::oneshot::channel();
        self.submit(deadline, AnchorCommand::Read(response))?;
        receive(receiver).await
    }

    pub(super) async fn compare_and_swap(
        &self,
        deadline: OperationDeadline,
        expected_digest: Option<Digest32>,
        candidate: WitnessStateAnchorV1,
    ) -> Result<AnchorCasResult, AdapterError> {
        let (response, receiver) = tokio::sync::oneshot::channel();
        self.submit(
            deadline,
            AnchorCommand::CompareAndSwap {
                expected_digest,
                candidate: Box::new(candidate),
                response,
            },
        )?;
        receive(receiver).await
    }

    fn submit(
        &self,
        deadline: OperationDeadline,
        command: AnchorCommand,
    ) -> Result<(), AdapterError> {
        if deadline.remaining().is_none() {
            return Err(AdapterError::new(AdapterErrorKind::AnchorUnavailable));
        }
        self.sender
            .try_send(QueuedAnchorCommand { deadline, command })
            .map_err(|error| match error {
                TrySendError::Full(_) | TrySendError::Disconnected(_) => {
                    AdapterError::new(AdapterErrorKind::AnchorUnavailable)
                }
            })
    }
}

async fn receive<T>(
    receiver: tokio::sync::oneshot::Receiver<Result<T, AdapterError>>,
) -> Result<T, AdapterError> {
    receiver
        .await
        .unwrap_or(Err(AdapterError::new(AdapterErrorKind::AnchorUnavailable)))
}
