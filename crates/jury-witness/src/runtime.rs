use std::{
    path::PathBuf,
    sync::mpsc::{self, Sender, SyncSender, TryRecvError, TrySendError},
    thread::{self, JoinHandle},
    time::{Instant, SystemTime, UNIX_EPOCH},
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
}

impl std::fmt::Display for RuntimeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("witness runtime operation failed")
    }
}

impl std::error::Error for RuntimeError {}

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

    pub fn check_ready(&mut self) -> Result<(), RuntimeError> {
        self.with_engine(|engine| engine.check_ready())
    }

    pub fn register_vault(
        &mut self,
        material: &PublicPolicyMaterialV1,
        accepted_registration: RegistrationBytes,
        checkpoint: VaultPolicyCheckpointV1,
    ) -> Result<(), RuntimeError> {
        let policy = material.replay().map_err(map_adapter_error)?;
        let encoded = material.encode().map_err(map_adapter_error)?;
        self.with_engine(|engine| {
            engine.register_vault(&policy, accepted_registration, checkpoint, encoded)
        })
    }

    pub fn advance_checkpoint(
        &mut self,
        material: &PublicPolicyMaterialV1,
        checkpoint: VaultPolicyCheckpointV1,
    ) -> Result<(), RuntimeError> {
        let policy = material.replay().map_err(map_adapter_error)?;
        let encoded = material.encode().map_err(map_adapter_error)?;
        self.with_engine(|engine| engine.advance_checkpoint(&policy, checkpoint, encoded))
    }

    pub fn reserve(
        &mut self,
        request: WitnessRequestV1,
        manifest: &ActionManifestV1,
    ) -> Result<WitnessProgress, RuntimeError> {
        self.with_policy_engine(request.vault_id, |engine, policy| {
            engine.reserve(policy, request, manifest)
        })
    }

    pub fn decide(
        &mut self,
        request: &WitnessRequestV1,
        manifest: &ActionManifestV1,
        approvals: &[ApprovalDecisionV1],
    ) -> Result<WitnessProgress, RuntimeError> {
        self.with_policy_engine(request.vault_id, |engine, policy| {
            engine.decide(policy, request, manifest, approvals)
        })
    }

    pub fn cancel(
        &mut self,
        request: &WitnessRequestV1,
        cancellation: &RequestCancellationV1,
    ) -> Result<CancellationProgress, RuntimeError> {
        self.with_policy_engine(request.vault_id, |engine, policy| {
            engine.cancel(policy, request, cancellation)
        })
    }

    pub fn compact_replay(&mut self) -> Result<usize, RuntimeError> {
        self.with_engine(|engine| engine.compact_replay())
    }

    fn with_engine<T>(
        &mut self,
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
        let mut store = SqliteWitnessStore::open(&self.database_path, self.identity.principal_id())
            .map_err(map_adapter_error)?;
        let mut anchor = self.external_anchor.clone();
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
        let mut store = SqliteWitnessStore::open(&self.database_path, self.identity.principal_id())
            .map_err(map_adapter_error)?;
        let mut anchor = self.external_anchor.clone();
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
    sender: SyncSender<RuntimeCommand>,
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

impl WitnessRuntimeWorker {
    pub fn spawn(mut runtime: WitnessRuntime, queue_capacity: usize) -> Result<Self, AdapterError> {
        let (sender, receiver) = mpsc::sync_channel(queue_capacity.max(1));
        let (shutdown, shutdown_receiver) = mpsc::channel();
        let thread = thread::Builder::new()
            .name("juryd-security-state".to_owned())
            .spawn(move || {
                loop {
                    match shutdown_receiver.try_recv() {
                        Ok(()) | Err(TryRecvError::Disconnected) => break,
                        Err(TryRecvError::Empty) => {}
                    }
                    let command = match receiver.recv_timeout(std::time::Duration::from_millis(50))
                    {
                        Ok(command) => command,
                        Err(mpsc::RecvTimeoutError::Timeout) => continue,
                        Err(mpsc::RecvTimeoutError::Disconnected) => break,
                    };
                    match shutdown_receiver.try_recv() {
                        Ok(()) | Err(TryRecvError::Disconnected) => break,
                        Err(TryRecvError::Empty) => {}
                    }
                    match command {
                        RuntimeCommand::CheckReady(response) => {
                            let _ = response.send(runtime.check_ready());
                        }
                        RuntimeCommand::Register {
                            material,
                            accepted_registration,
                            checkpoint,
                            response,
                        } => {
                            let _ = response.send(runtime.register_vault(
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
                            let _ =
                                response.send(runtime.advance_checkpoint(&material, checkpoint));
                        }
                        RuntimeCommand::Reserve {
                            request,
                            manifest,
                            response,
                        } => {
                            let _ = response.send(runtime.reserve(request, &manifest));
                        }
                        RuntimeCommand::Decide {
                            request,
                            manifest,
                            approvals,
                            response,
                        } => {
                            let _ = response.send(runtime.decide(&request, &manifest, &approvals));
                        }
                        RuntimeCommand::Cancel {
                            request,
                            cancellation,
                            response,
                        } => {
                            let _ = response.send(runtime.cancel(&request, &cancellation));
                        }
                        RuntimeCommand::Compact(response) => {
                            let _ = response.send(runtime.compact_replay());
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
    pub async fn check_ready(&self) -> Result<(), RuntimeError> {
        let (response, receiver) = tokio::sync::oneshot::channel();
        self.submit(RuntimeCommand::CheckReady(response))?;
        receive(receiver).await
    }

    pub async fn register_vault(
        &self,
        material: PublicPolicyMaterialV1,
        accepted_registration: RegistrationBytes,
        checkpoint: VaultPolicyCheckpointV1,
    ) -> Result<(), RuntimeError> {
        let (response, receiver) = tokio::sync::oneshot::channel();
        self.submit(RuntimeCommand::Register {
            material,
            accepted_registration,
            checkpoint,
            response,
        })?;
        receive(receiver).await
    }

    pub async fn advance_checkpoint(
        &self,
        material: PublicPolicyMaterialV1,
        checkpoint: VaultPolicyCheckpointV1,
    ) -> Result<(), RuntimeError> {
        let (response, receiver) = tokio::sync::oneshot::channel();
        self.submit(RuntimeCommand::AdvanceCheckpoint {
            material,
            checkpoint,
            response,
        })?;
        receive(receiver).await
    }

    pub async fn reserve(
        &self,
        request: WitnessRequestV1,
        manifest: ActionManifestV1,
    ) -> Result<WitnessProgress, RuntimeError> {
        let (response, receiver) = tokio::sync::oneshot::channel();
        self.submit(RuntimeCommand::Reserve {
            request,
            manifest,
            response,
        })?;
        receive(receiver).await
    }

    pub async fn decide(
        &self,
        request: WitnessRequestV1,
        manifest: ActionManifestV1,
        approvals: Vec<ApprovalDecisionV1>,
    ) -> Result<WitnessProgress, RuntimeError> {
        let (response, receiver) = tokio::sync::oneshot::channel();
        self.submit(RuntimeCommand::Decide {
            request,
            manifest,
            approvals,
            response,
        })?;
        receive(receiver).await
    }

    pub async fn cancel(
        &self,
        request: WitnessRequestV1,
        cancellation: RequestCancellationV1,
    ) -> Result<CancellationProgress, RuntimeError> {
        let (response, receiver) = tokio::sync::oneshot::channel();
        self.submit(RuntimeCommand::Cancel {
            request,
            cancellation,
            response,
        })?;
        receive(receiver).await
    }

    pub async fn compact_replay(&self) -> Result<usize, RuntimeError> {
        let (response, receiver) = tokio::sync::oneshot::channel();
        self.submit(RuntimeCommand::Compact(response))?;
        receive(receiver).await
    }

    fn submit(&self, command: RuntimeCommand) -> Result<(), RuntimeError> {
        self.sender.try_send(command).map_err(|error| RuntimeError {
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
