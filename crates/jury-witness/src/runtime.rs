use std::{
    path::PathBuf,
    sync::mpsc::{self, Sender, SyncSender, TryRecvError, TrySendError},
    thread::{self, JoinHandle},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use jury_core::witness_engine::{
    CancellationProgress, WitnessClock, WitnessEngine, WitnessEngineError, WitnessEngineErrorKind,
    WitnessEngineIdentity, WitnessProgress,
};
use jury_protected::OsRandom;
use jury_protocol::{
    vault_v1::VaultId,
    witness_v1::{
        ActionManifestV1, ApprovalDecisionV1, RegistrationBytes, RequestCancellationV1,
        VaultPolicyCheckpointV1, WitnessReasonV1, WitnessRequestV1,
    },
};

use crate::{
    AdapterError, AdapterErrorKind, anchor::HttpExternalAnchor, persistence::SqliteWitnessStore,
    policy_material::PublicPolicyMaterialV1,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeErrorKind {
    Refused(WitnessReasonV1),
    DeadlineExceeded,
    StoreUnavailable,
    AnchorUnavailable,
    InvalidPolicyMaterial,
    InternalFailure,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeError {
    kind: RuntimeErrorKind,
}

impl RuntimeError {
    #[must_use]
    pub const fn kind(self) -> RuntimeErrorKind {
        self.kind
    }

    const fn refused(reason: WitnessReasonV1) -> Self {
        Self {
            kind: RuntimeErrorKind::Refused(reason),
        }
    }

    const fn deadline_exceeded() -> Self {
        Self {
            kind: RuntimeErrorKind::DeadlineExceeded,
        }
    }
}

impl std::fmt::Display for RuntimeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("witness runtime operation failed")
    }
}

impl std::error::Error for RuntimeError {}

#[derive(Clone, Copy, Debug)]
pub struct OperationDeadline(Instant);

impl OperationDeadline {
    #[must_use]
    pub fn after(duration: Duration) -> Self {
        Self(Instant::now() + duration)
    }

    pub(crate) fn instant(self) -> Instant {
        self.0
    }

    pub(crate) fn remaining(self) -> Option<Duration> {
        self.0.checked_duration_since(Instant::now())
    }

    fn ensure_remaining(self) -> Result<(), RuntimeError> {
        if Instant::now() < self.0 {
            Ok(())
        } else {
            Err(RuntimeError::deadline_exceeded())
        }
    }
}

pub struct WitnessRuntime {
    identity: Box<dyn WitnessEngineIdentity>,
    database_path: PathBuf,
    external_anchor: HttpExternalAnchor,
    clock: SystemClock,
}

impl WitnessRuntime {
    #[must_use]
    pub fn new(
        identity: Box<dyn WitnessEngineIdentity>,
        database_path: PathBuf,
        external_anchor: HttpExternalAnchor,
    ) -> Self {
        Self {
            identity,
            database_path,
            external_anchor,
            clock: SystemClock::new(),
        }
    }

    #[must_use]
    pub fn witness_id(&self) -> jury_protocol::vault_v1::PrincipalId {
        self.identity.principal_id()
    }

    pub fn check_ready(&mut self, deadline: OperationDeadline) -> Result<(), RuntimeError> {
        self.with_engine(deadline, |engine| engine.check_ready())
    }

    pub fn register_vault(
        &mut self,
        deadline: OperationDeadline,
        material: &PublicPolicyMaterialV1,
        accepted_registration: RegistrationBytes,
        checkpoint: VaultPolicyCheckpointV1,
    ) -> Result<(), RuntimeError> {
        deadline.ensure_remaining()?;
        let policy = material.replay().map_err(map_adapter_error)?;
        let encoded = material.encode().map_err(map_adapter_error)?;
        self.with_engine(deadline, |engine| {
            engine.register_vault(&policy, accepted_registration, checkpoint, encoded)
        })
    }

    pub fn advance_checkpoint(
        &mut self,
        deadline: OperationDeadline,
        material: &PublicPolicyMaterialV1,
        checkpoint: VaultPolicyCheckpointV1,
    ) -> Result<(), RuntimeError> {
        deadline.ensure_remaining()?;
        let policy = material.replay().map_err(map_adapter_error)?;
        let encoded = material.encode().map_err(map_adapter_error)?;
        self.with_engine(deadline, |engine| {
            engine.advance_checkpoint(&policy, checkpoint, encoded)
        })
    }

    pub fn reserve(
        &mut self,
        deadline: OperationDeadline,
        request: WitnessRequestV1,
        manifest: &ActionManifestV1,
    ) -> Result<WitnessProgress, RuntimeError> {
        self.with_policy_engine(deadline, request.vault_id, |engine, policy| {
            engine.reserve(policy, request, manifest)
        })
    }

    pub fn decide(
        &mut self,
        deadline: OperationDeadline,
        request: &WitnessRequestV1,
        manifest: &ActionManifestV1,
        approvals: &[ApprovalDecisionV1],
    ) -> Result<WitnessProgress, RuntimeError> {
        self.with_policy_engine(deadline, request.vault_id, |engine, policy| {
            engine.decide(policy, request, manifest, approvals)
        })
    }

    pub fn cancel(
        &mut self,
        deadline: OperationDeadline,
        request: &WitnessRequestV1,
        cancellation: &RequestCancellationV1,
    ) -> Result<CancellationProgress, RuntimeError> {
        self.with_policy_engine(deadline, request.vault_id, |engine, policy| {
            engine.cancel(policy, request, cancellation)
        })
    }

    pub fn compact_replay(&mut self, deadline: OperationDeadline) -> Result<usize, RuntimeError> {
        self.with_engine(deadline, |engine| engine.compact_replay())
    }

    fn with_engine<T>(
        &mut self,
        deadline: OperationDeadline,
        operation: impl FnOnce(
            &mut WitnessEngine<
                '_,
                SqliteWitnessStore,
                HttpExternalAnchor,
                SystemClock,
                OsRandom,
                dyn WitnessEngineIdentity,
            >,
        ) -> Result<T, WitnessEngineError>,
    ) -> Result<T, RuntimeError> {
        deadline.ensure_remaining()?;
        let mut store = SqliteWitnessStore::open_until(
            &self.database_path,
            self.identity.principal_id(),
            deadline.instant(),
        )
        .map_err(map_adapter_error)?;
        deadline.ensure_remaining()?;
        let mut anchor = self
            .external_anchor
            .clone()
            .with_deadline(deadline.instant());
        let mut random = OsRandom;
        let mut engine = WitnessEngine::new(
            self.identity.as_ref(),
            &mut store,
            &mut anchor,
            &self.clock,
            &mut random,
        );
        operation(&mut engine).map_err(map_engine_error)
    }

    fn with_policy_engine<T>(
        &mut self,
        deadline: OperationDeadline,
        vault_id: VaultId,
        operation: impl FnOnce(
            &mut WitnessEngine<
                '_,
                SqliteWitnessStore,
                HttpExternalAnchor,
                SystemClock,
                OsRandom,
                dyn WitnessEngineIdentity,
            >,
            &jury_core::policy::PolicyState,
        ) -> Result<T, WitnessEngineError>,
    ) -> Result<T, RuntimeError> {
        deadline.ensure_remaining()?;
        let mut store = SqliteWitnessStore::open_until(
            &self.database_path,
            self.identity.principal_id(),
            deadline.instant(),
        )
        .map_err(map_adapter_error)?;
        deadline.ensure_remaining()?;
        let mut anchor = self
            .external_anchor
            .clone()
            .with_deadline(deadline.instant());
        let mut random = OsRandom;
        {
            let mut engine = WitnessEngine::new(
                self.identity.as_ref(),
                &mut store,
                &mut anchor,
                &self.clock,
                &mut random,
            );
            engine.check_ready().map_err(map_engine_error)?;
        }
        deadline.ensure_remaining()?;
        let persisted = store.load_validated().map_err(map_adapter_error)?;
        let material = persisted
            .logical
            .vaults
            .get(&vault_id)
            .ok_or_else(|| RuntimeError::refused(WitnessReasonV1::StalePolicy))?
            .current_policy_material
            .clone();
        let policy = PublicPolicyMaterialV1::decode(&material)
            .and_then(|material| material.replay())
            .map_err(map_adapter_error)?;
        deadline.ensure_remaining()?;
        let mut engine = WitnessEngine::new(
            self.identity.as_ref(),
            &mut store,
            &mut anchor,
            &self.clock,
            &mut random,
        );
        operation(&mut engine, &policy).map_err(map_engine_error)
    }
}

#[derive(Clone)]
pub struct WitnessRuntimeHandle {
    sender: SyncSender<QueuedCommand>,
}

pub struct WitnessRuntimeWorker {
    handle: WitnessRuntimeHandle,
    shutdown: Sender<()>,
    thread: Option<JoinHandle<()>>,
}

enum RuntimeCommand {
    CheckReady(tokio::sync::oneshot::Sender<Result<(), RuntimeError>>),
    Register {
        material: PublicPolicyMaterialV1,
        accepted_registration: RegistrationBytes,
        checkpoint: VaultPolicyCheckpointV1,
        response: tokio::sync::oneshot::Sender<Result<(), RuntimeError>>,
    },
    AdvanceCheckpoint {
        material: PublicPolicyMaterialV1,
        checkpoint: VaultPolicyCheckpointV1,
        response: tokio::sync::oneshot::Sender<Result<(), RuntimeError>>,
    },
    Reserve {
        request: WitnessRequestV1,
        manifest: ActionManifestV1,
        response: tokio::sync::oneshot::Sender<Result<WitnessProgress, RuntimeError>>,
    },
    Decide {
        request: WitnessRequestV1,
        manifest: ActionManifestV1,
        approvals: Vec<ApprovalDecisionV1>,
        response: tokio::sync::oneshot::Sender<Result<WitnessProgress, RuntimeError>>,
    },
    Cancel {
        request: WitnessRequestV1,
        cancellation: RequestCancellationV1,
        response: tokio::sync::oneshot::Sender<Result<CancellationProgress, RuntimeError>>,
    },
    Compact(tokio::sync::oneshot::Sender<Result<usize, RuntimeError>>),
}

struct QueuedCommand {
    deadline: OperationDeadline,
    command: RuntimeCommand,
}

impl RuntimeCommand {
    fn response_is_closed(&self) -> bool {
        match self {
            Self::CheckReady(response) => response.is_closed(),
            Self::Register { response, .. } => response.is_closed(),
            Self::AdvanceCheckpoint { response, .. } => response.is_closed(),
            Self::Reserve { response, .. } => response.is_closed(),
            Self::Decide { response, .. } => response.is_closed(),
            Self::Cancel { response, .. } => response.is_closed(),
            Self::Compact(response) => response.is_closed(),
        }
    }
}

impl WitnessRuntimeWorker {
    pub fn spawn(mut runtime: WitnessRuntime, queue_capacity: usize) -> Result<Self, AdapterError> {
        let (sender, receiver) = mpsc::sync_channel::<QueuedCommand>(queue_capacity.max(1));
        let (shutdown, shutdown_receiver) = mpsc::channel();
        let thread = thread::Builder::new()
            .name("juryd-security-state".to_owned())
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
                    let deadline = queued.deadline;
                    match queued.command {
                        RuntimeCommand::CheckReady(response) => {
                            let _ = response.send(runtime.check_ready(deadline));
                        }
                        RuntimeCommand::Register {
                            material,
                            accepted_registration,
                            checkpoint,
                            response,
                        } => {
                            let _ = response.send(runtime.register_vault(
                                deadline,
                                &material,
                                accepted_registration,
                                checkpoint,
                            ));
                        }
                        RuntimeCommand::AdvanceCheckpoint {
                            material,
                            checkpoint,
                            response,
                        } => {
                            let _ = response
                                .send(runtime.advance_checkpoint(deadline, &material, checkpoint));
                        }
                        RuntimeCommand::Reserve {
                            request,
                            manifest,
                            response,
                        } => {
                            let _ = response.send(runtime.reserve(deadline, request, &manifest));
                        }
                        RuntimeCommand::Decide {
                            request,
                            manifest,
                            approvals,
                            response,
                        } => {
                            let _ = response
                                .send(runtime.decide(deadline, &request, &manifest, &approvals));
                        }
                        RuntimeCommand::Cancel {
                            request,
                            cancellation,
                            response,
                        } => {
                            let _ =
                                response.send(runtime.cancel(deadline, &request, &cancellation));
                        }
                        RuntimeCommand::Compact(response) => {
                            let _ = response.send(runtime.compact_replay(deadline));
                        }
                    }
                }
            })
            .map_err(|_| AdapterError::new(AdapterErrorKind::Io))?;
        Ok(Self {
            handle: WitnessRuntimeHandle { sender },
            shutdown,
            thread: Some(thread),
        })
    }

    #[must_use]
    pub fn handle(&self) -> WitnessRuntimeHandle {
        self.handle.clone()
    }

    pub fn shutdown(mut self) -> Result<(), AdapterError> {
        let _ = self.shutdown.send(());
        self.thread
            .take()
            .ok_or_else(|| AdapterError::new(AdapterErrorKind::Io))?
            .join()
            .map_err(|_| AdapterError::new(AdapterErrorKind::Io))
    }
}

impl WitnessRuntimeHandle {
    pub(crate) async fn check_ready(
        &self,
        deadline: OperationDeadline,
    ) -> Result<(), RuntimeError> {
        let (response, receiver) = tokio::sync::oneshot::channel();
        self.submit(deadline, RuntimeCommand::CheckReady(response))?;
        receive(receiver).await
    }

    pub async fn register_vault(
        &self,
        deadline: OperationDeadline,
        material: PublicPolicyMaterialV1,
        accepted_registration: RegistrationBytes,
        checkpoint: VaultPolicyCheckpointV1,
    ) -> Result<(), RuntimeError> {
        let (response, receiver) = tokio::sync::oneshot::channel();
        self.submit(
            deadline,
            RuntimeCommand::Register {
                material,
                accepted_registration,
                checkpoint,
                response,
            },
        )?;
        receive(receiver).await
    }

    pub async fn advance_checkpoint(
        &self,
        deadline: OperationDeadline,
        material: PublicPolicyMaterialV1,
        checkpoint: VaultPolicyCheckpointV1,
    ) -> Result<(), RuntimeError> {
        let (response, receiver) = tokio::sync::oneshot::channel();
        self.submit(
            deadline,
            RuntimeCommand::AdvanceCheckpoint {
                material,
                checkpoint,
                response,
            },
        )?;
        receive(receiver).await
    }

    pub async fn reserve(
        &self,
        deadline: OperationDeadline,
        request: WitnessRequestV1,
        manifest: ActionManifestV1,
    ) -> Result<WitnessProgress, RuntimeError> {
        let (response, receiver) = tokio::sync::oneshot::channel();
        self.submit(
            deadline,
            RuntimeCommand::Reserve {
                request,
                manifest,
                response,
            },
        )?;
        receive(receiver).await
    }

    pub async fn decide(
        &self,
        deadline: OperationDeadline,
        request: WitnessRequestV1,
        manifest: ActionManifestV1,
        approvals: Vec<ApprovalDecisionV1>,
    ) -> Result<WitnessProgress, RuntimeError> {
        let (response, receiver) = tokio::sync::oneshot::channel();
        self.submit(
            deadline,
            RuntimeCommand::Decide {
                request,
                manifest,
                approvals,
                response,
            },
        )?;
        receive(receiver).await
    }

    pub async fn cancel(
        &self,
        deadline: OperationDeadline,
        request: WitnessRequestV1,
        cancellation: RequestCancellationV1,
    ) -> Result<CancellationProgress, RuntimeError> {
        let (response, receiver) = tokio::sync::oneshot::channel();
        self.submit(
            deadline,
            RuntimeCommand::Cancel {
                request,
                cancellation,
                response,
            },
        )?;
        receive(receiver).await
    }

    pub async fn compact_replay(&self, deadline: OperationDeadline) -> Result<usize, RuntimeError> {
        let (response, receiver) = tokio::sync::oneshot::channel();
        self.submit(deadline, RuntimeCommand::Compact(response))?;
        receive(receiver).await
    }

    fn submit(
        &self,
        deadline: OperationDeadline,
        command: RuntimeCommand,
    ) -> Result<(), RuntimeError> {
        deadline.ensure_remaining()?;
        self.sender
            .try_send(QueuedCommand { deadline, command })
            .map_err(|error| RuntimeError {
                kind: match error {
                    TrySendError::Full(_) => RuntimeErrorKind::StoreUnavailable,
                    TrySendError::Disconnected(_) => RuntimeErrorKind::InternalFailure,
                },
            })
    }
}

async fn receive<T>(
    receiver: tokio::sync::oneshot::Receiver<Result<T, RuntimeError>>,
) -> Result<T, RuntimeError> {
    receiver.await.unwrap_or(Err(RuntimeError {
        kind: RuntimeErrorKind::InternalFailure,
    }))
}

struct SystemClock {
    started: Instant,
}

impl SystemClock {
    fn new() -> Self {
        Self {
            started: Instant::now(),
        }
    }
}

impl WitnessClock for SystemClock {
    fn wall_time_ms(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|duration| u64::try_from(duration.as_millis()).ok())
            .unwrap_or(0)
    }

    fn monotonic_time_ms(&self) -> u64 {
        u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX)
    }
}

fn map_engine_error(error: WitnessEngineError) -> RuntimeError {
    let kind = match error.kind() {
        WitnessEngineErrorKind::Refused(reason) => RuntimeErrorKind::Refused(reason),
        WitnessEngineErrorKind::StoreUnavailable => RuntimeErrorKind::StoreUnavailable,
        WitnessEngineErrorKind::AnchorUnavailable => RuntimeErrorKind::AnchorUnavailable,
    };
    RuntimeError { kind }
}

fn map_adapter_error(error: AdapterError) -> RuntimeError {
    let kind = match error.kind() {
        AdapterErrorKind::DatabaseUnavailable | AdapterErrorKind::InvalidState => {
            RuntimeErrorKind::StoreUnavailable
        }
        AdapterErrorKind::AnchorUnavailable | AdapterErrorKind::Conflict => {
            RuntimeErrorKind::AnchorUnavailable
        }
        AdapterErrorKind::InvalidPolicyMaterial | AdapterErrorKind::CapacityExhausted => {
            RuntimeErrorKind::InvalidPolicyMaterial
        }
        AdapterErrorKind::InvalidConfiguration
        | AdapterErrorKind::InvalidCredential
        | AdapterErrorKind::InvalidIdentity
        | AdapterErrorKind::AuthenticationFailed
        | AdapterErrorKind::TargetExists
        | AdapterErrorKind::Io => RuntimeErrorKind::InternalFailure,
    };
    RuntimeError { kind }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expired_work_is_rejected_before_it_enters_the_runtime_queue()
    -> Result<(), Box<dyn std::error::Error>> {
        let (sender, receiver) = mpsc::sync_channel(1);
        let handle = WitnessRuntimeHandle { sender };
        let (response, response_receiver) = tokio::sync::oneshot::channel();

        let error = handle
            .submit(
                OperationDeadline::after(Duration::ZERO),
                RuntimeCommand::CheckReady(response),
            )
            .err()
            .ok_or("expired command must not be queued")?;

        assert_eq!(error.kind(), RuntimeErrorKind::DeadlineExceeded);
        assert!(matches!(
            receiver.try_recv(),
            Err(mpsc::TryRecvError::Empty)
        ));
        assert!(response_receiver.blocking_recv().is_err());
        Ok(())
    }

    #[test]
    fn dropped_callers_mark_queued_work_as_abandoned() {
        let (response, receiver) = tokio::sync::oneshot::channel();
        let command = RuntimeCommand::CheckReady(response);
        assert!(!command.response_is_closed());
        drop(receiver);
        assert!(command.response_is_closed());
    }
}
