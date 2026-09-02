use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use axum::{
    extract::{ConnectInfo, State},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::Response,
};
use tokio::sync::Semaphore;

use super::{RefusalReason, refusal, unauthorized};
use crate::{config::TransportLimits, credentials::CredentialDigest, runtime::OperationDeadline};

const MAX_RATE_KEYS: usize = 4096;

#[derive(Clone)]
pub(super) struct PublicGateState {
    pub(super) gate: GateState,
    pub(super) operation_timeout: Duration,
}

#[derive(Clone)]
pub(super) struct ProtectedGateState {
    pub(super) gate: GateState,
    pub(super) credential: CredentialDigest,
    pub(super) operation_timeout: Duration,
}

#[derive(Clone)]
pub(super) struct GateState {
    rate: Arc<Mutex<RateState>>,
    concurrency: Arc<Semaphore>,
    requests_per_second: f64,
    burst: f64,
}

#[derive(Default)]
struct RateState {
    buckets: HashMap<IpAddr, RateBucket>,
}

struct RateBucket {
    tokens: f64,
    updated: Instant,
}

pub(super) struct ReadinessProbe {
    in_flight: AtomicBool,
    last_ready: AtomicBool,
}

pub(super) struct ReadinessLease(Arc<ReadinessProbe>);

impl GateState {
    pub(super) fn new(limits: &TransportLimits) -> Self {
        Self {
            rate: Arc::new(Mutex::new(RateState::default())),
            concurrency: Arc::new(Semaphore::new(limits.maximum_concurrency)),
            requests_per_second: f64::from(limits.requests_per_second),
            burst: f64::from(limits.burst_requests),
        }
    }

    pub(super) fn allow(&self, address: IpAddr) -> bool {
        let Ok(mut state) = self.rate.lock() else {
            return false;
        };
        let now = Instant::now();
        if !state.buckets.contains_key(&address) && state.buckets.len() >= MAX_RATE_KEYS {
            state
                .buckets
                .retain(|_, bucket| now.duration_since(bucket.updated) < Duration::from_secs(60));
            if state.buckets.len() >= MAX_RATE_KEYS {
                return false;
            }
        }
        let bucket = state.buckets.entry(address).or_insert(RateBucket {
            tokens: self.burst,
            updated: now,
        });
        let elapsed = now.duration_since(bucket.updated).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * self.requests_per_second).min(self.burst);
        bucket.updated = now;
        if bucket.tokens < 1.0 {
            false
        } else {
            bucket.tokens -= 1.0;
            true
        }
    }
}

impl ReadinessProbe {
    pub(super) fn new() -> Self {
        Self {
            in_flight: AtomicBool::new(false),
            last_ready: AtomicBool::new(false),
        }
    }

    pub(super) fn acquire(self: &Arc<Self>) -> Option<ReadinessLease> {
        self.in_flight
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .ok()
            .map(|_| ReadinessLease(Arc::clone(self)))
    }

    pub(super) fn last_ready(&self) -> bool {
        self.last_ready.load(Ordering::Acquire)
    }
}

impl ReadinessLease {
    pub(super) fn finish(&self, ready: bool) {
        self.0.last_ready.store(ready, Ordering::Release);
    }
}

impl Drop for ReadinessLease {
    fn drop(&mut self) {
        self.0.in_flight.store(false, Ordering::Release);
    }
}

pub(super) async fn public_gate_request(
    State(state): State<PublicGateState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    mut request: axum::extract::Request,
    next: Next,
) -> Response {
    request
        .extensions_mut()
        .insert(OperationDeadline::after(state.operation_timeout));
    admit(&state.gate, peer.ip(), request, next).await
}

pub(super) async fn protected_gate_request(
    State(state): State<ProtectedGateState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    mut request: axum::extract::Request,
    next: Next,
) -> Response {
    if !authorized(request.headers(), &state.credential) {
        return unauthorized();
    }
    request
        .extensions_mut()
        .insert(OperationDeadline::after(state.operation_timeout));
    admit(&state.gate, peer.ip(), request, next).await
}

async fn admit(
    gate: &GateState,
    peer: IpAddr,
    request: axum::extract::Request,
    next: Next,
) -> Response {
    if !gate.allow(peer) {
        return refusal(StatusCode::TOO_MANY_REQUESTS, RefusalReason::RateLimited);
    }
    let Ok(permit) = gate.concurrency.clone().try_acquire_owned() else {
        return refusal(StatusCode::TOO_MANY_REQUESTS, RefusalReason::RateLimited);
    };
    let response = next.run(request).await;
    drop(permit);
    response
}

fn authorized(headers: &HeaderMap, credential: &CredentialDigest) -> bool {
    credential.matches_bearer(headers.get(axum::http::header::AUTHORIZATION))
}
