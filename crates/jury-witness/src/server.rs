use std::{net::SocketAddr, sync::Arc, thread, time::Duration};

use axum::{
    Json, Router,
    extract::{Extension, Path, State, rejection::JsonRejection},
    http::StatusCode,
    middleware,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use axum_server::{Handle, tls_rustls::RustlsConfig};
use hyper_util::rt::TokioTimer;
use jury_core::witness_engine::{CancellationProgress, WitnessProgress};
use jury_protocol::{
    vault_v1::PrincipalId,
    witness_v1::{
        ActionManifestV1, ApprovalDecisionV1, RegistrationBytes, RequestCancellationV1,
        VaultPolicyCheckpointV1, WitnessReasonV1, WitnessRequestV1, WitnessResponseV1,
    },
};
use serde::{Deserialize, Serialize};
use tower_http::{
    catch_panic::CatchPanicLayer, limit::RequestBodyLimitLayer, timeout::TimeoutLayer,
};

use self::anchor_worker::{AnchorRepositoryHandle, AnchorRepositoryWorker};
use self::request_control::{
    GateState, ProtectedGateState, PublicGateState, ReadinessProbe, protected_gate_request,
    public_gate_request,
};
use crate::{
    AdapterError, AdapterErrorKind,
    anchor::{
        AnchorCasOutcome, AnchorCasRequest, AnchorCasResponse, AnchorCasResult, HttpExternalAnchor,
        SqliteAnchorRepository,
    },
    config::{
        AnchorServiceConfig, IdentityProviderConfig, TlsConfig, TransportLimits,
        WitnessServiceConfig,
    },
    credentials::load_digest,
    identity_provider::{SoftwareFileIdentityProvider, WitnessIdentityProvider as _},
    policy_material::PublicPolicyMaterialV1,
    runtime::{
        OperationDeadline, RuntimeError, RuntimeErrorKind, WitnessRuntime, WitnessRuntimeHandle,
        WitnessRuntimeWorker,
    },
};

mod anchor_worker;
mod request_control;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RegisterRequest {
    policy_material: PublicPolicyMaterialV1,
    accepted_registration: RegistrationBytes,
    checkpoint: VaultPolicyCheckpointV1,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CheckpointRequest {
    policy_material: PublicPolicyMaterialV1,
    checkpoint: VaultPolicyCheckpointV1,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReserveRequest {
    request: WitnessRequestV1,
    manifest: ActionManifestV1,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DecideRequest {
    request: WitnessRequestV1,
    manifest: ActionManifestV1,
    approvals: Vec<ApprovalDecisionV1>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CancelRequest {
    request: WitnessRequestV1,
    cancellation: RequestCancellationV1,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct StatusResponse {
    status: &'static str,
    maturity: &'static str,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct OperationResponse {
    status: &'static str,
    response: Option<WitnessResponseV1>,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct RefusalResponse {
    status: &'static str,
    reason: RefusalReason,
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "kebab-case")]
enum RefusalReason {
    TransportAuthentication,
    RateLimited,
    Invalid,
    Unavailable,
    InternalFailure,
    Protocol(WitnessReasonV1),
}

#[derive(Clone)]
struct WitnessApiState {
    runtime: WitnessRuntimeHandle,
    readiness: Arc<ReadinessProbe>,
}

#[derive(Clone)]
struct AnchorApiState {
    repository: AnchorRepositoryHandle,
    readiness: Arc<ReadinessProbe>,
    witness_id: PrincipalId,
}

pub async fn run_witness_service(config: WitnessServiceConfig) -> Result<(), AdapterError> {
    config.validate()?;
    let identity = match &config.identity {
        IdentityProviderConfig::SoftwareFile {
            identity_file,
            passphrase_file,
        } => SoftwareFileIdentityProvider::new(identity_file.clone(), passphrase_file.clone())
            .load()?,
    };
    if identity.principal_id() != config.witness_id {
        return Err(AdapterError::new(AdapterErrorKind::InvalidConfiguration));
    }
    let anchor_config = config.external_anchor.clone();
    let anchor_timeout = Duration::from_millis(config.limits.request_timeout_ms);
    let witness_id = identity.principal_id();
    let anchor = thread::Builder::new()
        .name("juryd-anchor-client-init".to_owned())
        .spawn(move || {
            HttpExternalAnchor::new(
                &anchor_config.base_url,
                witness_id,
                &anchor_config.ca_certificate_file,
                &anchor_config.write_credential_file,
                anchor_config.allow_insecure_loopback,
                anchor_timeout,
            )
        })
        .map_err(|_| AdapterError::new(AdapterErrorKind::Io))?
        .join()
        .map_err(|_| AdapterError::new(AdapterErrorKind::Io))??;
    let runtime = WitnessRuntime::new(identity, config.database.path.clone(), anchor);
    let worker = WitnessRuntimeWorker::spawn(runtime, config.limits.maximum_concurrency)?;
    let state = WitnessApiState {
        runtime: worker.handle(),
        readiness: Arc::new(ReadinessProbe::new()),
    };
    let gate = GateState::new(&config.limits);
    let public = Router::new()
        .route("/livez", get(live))
        .route("/readyz", get(witness_ready))
        .route_layer(middleware::from_fn_with_state(
            PublicGateState {
                gate: gate.clone(),
                operation_timeout: anchor_timeout,
            },
            public_gate_request,
        ));
    let operator = Router::new()
        .route("/v1/operator/register", post(register))
        .route("/v1/operator/checkpoint", post(checkpoint))
        .route("/v1/operator/replay/compact", post(compact))
        .route_layer(middleware::from_fn_with_state(
            ProtectedGateState {
                gate: gate.clone(),
                credential: load_digest(&config.operator_credential_file)?,
                operation_timeout: anchor_timeout,
            },
            protected_gate_request,
        ));
    let client = Router::new()
        .route("/v1/requests/reserve", post(reserve))
        .route("/v1/requests/decide", post(decide))
        .route("/v1/requests/cancel", post(cancel))
        .route_layer(middleware::from_fn_with_state(
            ProtectedGateState {
                gate,
                credential: load_digest(&config.client_credential_file)?,
                operation_timeout: anchor_timeout,
            },
            protected_gate_request,
        ));
    let app = Router::new()
        .merge(public)
        .merge(operator)
        .merge(client)
        .with_state(state);
    let result = serve(app, config.listen, &config.tls, &config.limits).await;
    let shutdown = worker.shutdown();
    result.and(shutdown)
}

pub async fn run_anchor_service(config: AnchorServiceConfig) -> Result<(), AdapterError> {
    config.validate()?;
    let operation_timeout = Duration::from_millis(config.limits.request_timeout_ms);
    let write_credential = load_digest(&config.write_credential_file)?;
    let worker = AnchorRepositoryWorker::spawn(
        SqliteAnchorRepository::open(&config.database.path, config.witness_id)?,
        config.limits.maximum_concurrency,
    )?;
    let state = AnchorApiState {
        repository: worker.handle(),
        readiness: Arc::new(ReadinessProbe::new()),
        witness_id: config.witness_id,
    };
    let gate = GateState::new(&config.limits);
    let public = Router::new()
        .route("/livez", get(live))
        .route("/readyz", get(anchor_ready))
        .route("/v1/anchors/{witness_id}", get(read_anchor))
        .route_layer(middleware::from_fn_with_state(
            PublicGateState {
                gate: gate.clone(),
                operation_timeout,
            },
            public_gate_request,
        ));
    let protected = Router::new()
        .route("/v1/anchors/{witness_id}", post(compare_and_swap_anchor))
        .route_layer(middleware::from_fn_with_state(
            ProtectedGateState {
                gate,
                credential: write_credential,
                operation_timeout,
            },
            protected_gate_request,
        ));
    let app = Router::new()
        .merge(public)
        .merge(protected)
        .with_state(state);
    let result = serve(app, config.listen, &config.tls, &config.limits).await;
    let shutdown = worker.shutdown();
    result.and(shutdown)
}

async fn serve(
    app: Router,
    listen: SocketAddr,
    tls: &TlsConfig,
    limits: &TransportLimits,
) -> Result<(), AdapterError> {
    let app = app
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            Duration::from_millis(limits.request_timeout_ms),
        ))
        .layer(RequestBodyLimitLayer::new(limits.maximum_request_bytes))
        .layer(CatchPanicLayer::custom(|_| internal_failure()));
    let handle = Handle::new();
    let shutdown_handle = handle.clone();
    let grace = Duration::from_millis(limits.shutdown_grace_ms);
    tokio::spawn(async move {
        shutdown_signal().await;
        shutdown_handle.graceful_shutdown(Some(grace));
    });
    let make_service = app.into_make_service_with_connect_info::<SocketAddr>();
    match (&tls.certificate_file, &tls.private_key_file) {
        (Some(certificate), Some(private_key)) => {
            let rustls = RustlsConfig::from_pem_file(certificate, private_key)
                .await
                .map_err(|_| AdapterError::new(AdapterErrorKind::InvalidConfiguration))?;
            let mut server = axum_server::bind_rustls(listen, rustls);
            server
                .http_builder()
                .http1()
                .timer(TokioTimer::new())
                .header_read_timeout(Duration::from_millis(limits.request_timeout_ms));
            server
                .handle(handle)
                .http1_only()
                .serve(make_service)
                .await
                .map_err(|_| AdapterError::new(AdapterErrorKind::Io))
        }
        (None, None) if tls.allow_insecure_loopback && listen.ip().is_loopback() => {
            let mut server = axum_server::bind(listen);
            server
                .http_builder()
                .http1()
                .timer(TokioTimer::new())
                .header_read_timeout(Duration::from_millis(limits.request_timeout_ms));
            server
                .handle(handle)
                .http1_only()
                .serve(make_service)
                .await
                .map_err(|_| AdapterError::new(AdapterErrorKind::Io))
        }
        _ => Err(AdapterError::new(AdapterErrorKind::InvalidConfiguration)),
    }
}

async fn live() -> impl IntoResponse {
    (
        StatusCode::OK,
        Json(StatusResponse {
            status: "live",
            maturity: jury_core::MATURITY,
        }),
    )
}

async fn witness_ready(
    State(state): State<WitnessApiState>,
    Extension(deadline): Extension<OperationDeadline>,
) -> Response {
    let Some(lease) = state.readiness.acquire() else {
        return readiness_response(state.readiness.last_ready());
    };
    let is_ready = state.runtime.check_ready(deadline).await.is_ok();
    lease.finish(is_ready);
    readiness_response(is_ready)
}

async fn anchor_ready(
    State(state): State<AnchorApiState>,
    Extension(deadline): Extension<OperationDeadline>,
) -> Response {
    let Some(lease) = state.readiness.acquire() else {
        return readiness_response(state.readiness.last_ready());
    };
    let is_ready = state.repository.check_ready(deadline).await.is_ok();
    lease.finish(is_ready);
    readiness_response(is_ready)
}

async fn register(
    State(state): State<WitnessApiState>,
    Extension(deadline): Extension<OperationDeadline>,
    payload: Result<Json<RegisterRequest>, JsonRejection>,
) -> Response {
    let Ok(Json(payload)) = payload else {
        return invalid_request();
    };
    operation_result(
        state
            .runtime
            .register_vault(
                deadline,
                payload.policy_material,
                payload.accepted_registration,
                payload.checkpoint,
            )
            .await
            .map(|()| OperationResponse {
                status: "accepted",
                response: None,
            }),
    )
}

async fn checkpoint(
    State(state): State<WitnessApiState>,
    Extension(deadline): Extension<OperationDeadline>,
    payload: Result<Json<CheckpointRequest>, JsonRejection>,
) -> Response {
    let Ok(Json(payload)) = payload else {
        return invalid_request();
    };
    operation_result(
        state
            .runtime
            .advance_checkpoint(deadline, payload.policy_material, payload.checkpoint)
            .await
            .map(|()| OperationResponse {
                status: "accepted",
                response: None,
            }),
    )
}

async fn compact(
    State(state): State<WitnessApiState>,
    Extension(deadline): Extension<OperationDeadline>,
) -> Response {
    operation_result(
        state
            .runtime
            .compact_replay(deadline)
            .await
            .map(|_| OperationResponse {
                status: "accepted",
                response: None,
            }),
    )
}

async fn reserve(
    State(state): State<WitnessApiState>,
    Extension(deadline): Extension<OperationDeadline>,
    payload: Result<Json<ReserveRequest>, JsonRejection>,
) -> Response {
    let Ok(Json(payload)) = payload else {
        return invalid_request();
    };
    operation_result(
        state
            .runtime
            .reserve(deadline, payload.request, payload.manifest)
            .await
            .map(progress_response),
    )
}

async fn decide(
    State(state): State<WitnessApiState>,
    Extension(deadline): Extension<OperationDeadline>,
    payload: Result<Json<DecideRequest>, JsonRejection>,
) -> Response {
    let Ok(Json(payload)) = payload else {
        return invalid_request();
    };
    operation_result(
        state
            .runtime
            .decide(
                deadline,
                payload.request,
                payload.manifest,
                payload.approvals,
            )
            .await
            .map(progress_response),
    )
}

async fn cancel(
    State(state): State<WitnessApiState>,
    Extension(deadline): Extension<OperationDeadline>,
    payload: Result<Json<CancelRequest>, JsonRejection>,
) -> Response {
    let Ok(Json(payload)) = payload else {
        return invalid_request();
    };
    operation_result(
        state
            .runtime
            .cancel(deadline, payload.request, payload.cancellation)
            .await
            .map(cancellation_response),
    )
}

async fn read_anchor(
    State(state): State<AnchorApiState>,
    Extension(deadline): Extension<OperationDeadline>,
    Path(witness_id): Path<String>,
) -> Response {
    let Ok(witness_id) = parse_principal_id(&witness_id) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if witness_id != state.witness_id {
        return StatusCode::NOT_FOUND.into_response();
    }
    match state.repository.read(deadline).await {
        Ok(Some(anchor)) => (StatusCode::OK, Json(anchor)).into_response(),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(_) => refusal(StatusCode::SERVICE_UNAVAILABLE, RefusalReason::Unavailable),
    }
}

async fn compare_and_swap_anchor(
    State(state): State<AnchorApiState>,
    Extension(deadline): Extension<OperationDeadline>,
    Path(witness_id): Path<String>,
    payload: Result<Json<AnchorCasRequest>, JsonRejection>,
) -> Response {
    let Ok(witness_id) = parse_principal_id(&witness_id) else {
        return invalid_request();
    };
    if witness_id != state.witness_id {
        return invalid_request();
    }
    let Ok(Json(payload)) = payload else {
        return invalid_request();
    };
    match state
        .repository
        .compare_and_swap(
            deadline,
            payload.expected_anchor_digest,
            payload.next_exact_anchor,
        )
        .await
    {
        Ok(AnchorCasResult::Applied(anchor)) => (
            StatusCode::OK,
            Json(AnchorCasResponse {
                outcome: AnchorCasOutcome::Applied,
                exact_anchor: Some(anchor),
            }),
        )
            .into_response(),
        Ok(AnchorCasResult::Conflict(anchor)) => (
            StatusCode::OK,
            Json(AnchorCasResponse {
                outcome: AnchorCasOutcome::Conflict,
                exact_anchor: anchor,
            }),
        )
            .into_response(),
        Err(error) if error.kind() == AdapterErrorKind::InvalidState => invalid_request(),
        Err(_) => refusal(StatusCode::SERVICE_UNAVAILABLE, RefusalReason::Unavailable),
    }
}

fn operation_result(result: Result<OperationResponse, RuntimeError>) -> Response {
    match result {
        Ok(response) => (StatusCode::OK, Json(response)).into_response(),
        Err(error) => runtime_error(error),
    }
}

fn progress_response(progress: WitnessProgress) -> OperationResponse {
    match progress {
        WitnessProgress::Reserved => OperationResponse {
            status: "reserved",
            response: None,
        },
        WitnessProgress::Pending => OperationResponse {
            status: "pending",
            response: None,
        },
        WitnessProgress::Stable(response) => OperationResponse {
            status: "stable",
            response: Some(*response),
        },
    }
}

fn cancellation_response(progress: CancellationProgress) -> OperationResponse {
    match progress {
        CancellationProgress::Cancelled(response) => OperationResponse {
            status: "cancelled",
            response: Some(*response),
        },
        CancellationProgress::TooLate(response) => OperationResponse {
            status: "too-late",
            response: Some(*response),
        },
    }
}

fn runtime_error(error: RuntimeError) -> Response {
    match error.kind() {
        RuntimeErrorKind::Refused(reason) => refusal(
            StatusCode::UNPROCESSABLE_ENTITY,
            RefusalReason::Protocol(reason),
        ),
        RuntimeErrorKind::StoreUnavailable
        | RuntimeErrorKind::AnchorUnavailable
        | RuntimeErrorKind::InvalidPolicyMaterial => {
            refusal(StatusCode::SERVICE_UNAVAILABLE, RefusalReason::Unavailable)
        }
        RuntimeErrorKind::DeadlineExceeded => {
            refusal(StatusCode::REQUEST_TIMEOUT, RefusalReason::Unavailable)
        }
        RuntimeErrorKind::InternalFailure => internal_failure(),
    }
}

fn ready() -> Response {
    (
        StatusCode::OK,
        Json(StatusResponse {
            status: "ready",
            maturity: jury_core::MATURITY,
        }),
    )
        .into_response()
}

fn readiness_response(is_ready: bool) -> Response {
    if is_ready { ready() } else { not_ready() }
}

fn not_ready() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(StatusResponse {
            status: "not-ready",
            maturity: jury_core::MATURITY,
        }),
    )
        .into_response()
}

fn unauthorized() -> Response {
    refusal(
        StatusCode::UNAUTHORIZED,
        RefusalReason::TransportAuthentication,
    )
}

fn invalid_request() -> Response {
    refusal(StatusCode::BAD_REQUEST, RefusalReason::Invalid)
}

fn internal_failure() -> Response {
    refusal(
        StatusCode::INTERNAL_SERVER_ERROR,
        RefusalReason::InternalFailure,
    )
}

fn refusal(status: StatusCode, reason: RefusalReason) -> Response {
    (
        status,
        Json(RefusalResponse {
            status: "refused",
            reason,
        }),
    )
        .into_response()
}

fn parse_principal_id(value: &str) -> Result<PrincipalId, ()> {
    if value.len() != 64 {
        return Err(());
    }
    let mut bytes = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        bytes[index] = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
    }
    PrincipalId::from_bytes(bytes).map_err(|_| ())
}

const fn hex_nibble(byte: u8) -> Result<u8, ()> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(()),
    }
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        let terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate());
        if let Ok(mut terminate) = terminate {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {},
                _ = terminate.recv() => {},
            }
            return;
        }
    }
    let _ = tokio::signal::ctrl_c().await;
}

#[cfg(test)]
mod tests {
    use std::{error::Error, net::IpAddr, os::unix::fs::PermissionsExt as _, time::Instant};

    use jury_protocol::witness_v1::WitnessStateAnchorV1;

    use super::*;

    #[test]
    fn rate_buckets_are_bounded_per_source_address() {
        let gate = GateState::new(&TransportLimits {
            maximum_request_bytes: 1024,
            maximum_concurrency: 1,
            requests_per_second: 1,
            burst_requests: 2,
            request_timeout_ms: 100,
            shutdown_grace_ms: 100,
        });
        let first = IpAddr::from([192, 0, 2, 1]);
        let second = IpAddr::from([192, 0, 2, 2]);

        assert!(gate.allow(first));
        assert!(gate.allow(first));
        assert!(!gate.allow(first));
        assert!(gate.allow(second));
    }

    #[test]
    fn principal_path_parser_accepts_only_canonical_lowercase_ids() {
        let canonical = "ab".repeat(32);
        assert_eq!(
            parse_principal_id(&canonical).map(|id| id.as_bytes()[0]),
            Ok(0xab)
        );
        assert!(parse_principal_id(&canonical.to_uppercase()).is_err());
        assert!(parse_principal_id(&canonical[..62]).is_err());
    }

    #[test]
    fn readiness_probe_allows_only_one_in_flight_check() -> Result<(), Box<dyn Error>> {
        let probe = Arc::new(ReadinessProbe::new());
        let first = probe.acquire().ok_or("first probe should own refresh")?;
        assert!(probe.acquire().is_none());
        assert!(!probe.last_ready());
        first.finish(true);
        drop(first);
        assert!(probe.last_ready());
        assert!(probe.acquire().is_some());
        Ok(())
    }

    #[tokio::test]
    async fn anchor_work_runs_on_the_deadline_aware_owner_thread() -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
        let path = directory.path().join("anchor.sqlite3");
        let witness_id = PrincipalId::from_bytes([11; 32])?;
        SqliteAnchorRepository::initialize(&path)?;
        let repository = SqliteAnchorRepository::open(&path, witness_id)?;
        let worker = AnchorRepositoryWorker::spawn(repository, 1)?;
        let handle = worker.handle();
        let blocker = rusqlite::Connection::open(&path)?;
        blocker.execute_batch("BEGIN IMMEDIATE")?;
        let candidate = WitnessStateAnchorV1 {
            schema: 1,
            witness_id,
            witness_signing_key_fingerprint: jury_protocol::vault_v1::Digest32::new([2; 32]),
            witness_signing_key_epoch: 1,
            state_generation: 1,
            database_state_digest: jury_protocol::vault_v1::Digest32::new([3; 32]),
            vault_high_watermarks: Vec::new(),
            replay_retain_through_ms: 0,
            last_accepted_wall_time_ms: 1,
            predecessor_anchor_digest: jury_protocol::vault_v1::Digest32::new([0; 32]),
            issued_at_ms: 1,
            signature: jury_protocol::vault_v1::Signature64::new([4; 64]),
        };

        let started = Instant::now();
        assert!(
            handle
                .compare_and_swap(
                    OperationDeadline::after(Duration::from_millis(100)),
                    None,
                    candidate,
                )
                .await
                .is_err()
        );
        assert!(started.elapsed() < Duration::from_secs(1));
        blocker.execute_batch("ROLLBACK")?;
        assert_eq!(
            handle
                .read(OperationDeadline::after(Duration::from_secs(1)))
                .await?,
            None
        );
        handle
            .check_ready(OperationDeadline::after(Duration::from_secs(1)))
            .await?;
        worker.shutdown()?;
        Ok(())
    }
}
