use std::{
    io::Read as _,
    net::{TcpListener, TcpStream},
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use jury_core::{
    identity::{ApproverIdentity, UnlockedIdentity, WitnessIdentity, unlock},
    policy::PolicyState,
    witness_approval::{
        ApprovalDecisionChoice, ApprovalDecisionCreator, ApprovalReviewInput,
        render_complete_approval_review,
    },
    witness_engine::{
        AnchorCompareAndSwap, CancellationProgress, ExternalWitnessAnchor, PersistedWitnessState,
        WitnessAnchorError, WitnessClock, WitnessEngine, WitnessProgress, WitnessStateStore,
        WitnessStoreError,
    },
};
use jury_protected::{OsRandom, ProtectedMemory, ProtectionPolicy};
use jury_protocol::{
    identity_v1::IdentityFileV1,
    vault_v1::{Digest32, PrincipalId, VaultFileV1},
    witness_v1::{
        ActionManifestV1, ApprovalDecisionKindV1, ApprovalDecisionV1, ApprovalPresentationV1,
        OwnerReviewLabelV1, PolicyMaterialBytes, RegistrationBytes, RequestCancellationV1,
        VaultPolicyCheckpointV1, WitnessReasonV1, WitnessRequestV1, WitnessStateAnchorV1,
    },
};
use serde::Deserialize;
use serde_json::json;

use super::native_cli_additional::{encode_hex, initialize_policy_actors};
use super::*;

const OWNER_PASSPHRASE: &str = "OwnerPassphrase1234";
const APPROVER_PASSPHRASE: &str = "ApproverPass1234";
const WITNESS_ONE_PASSPHRASE: &str = "WitnessOnePass1234";
const WITNESS_TWO_PASSPHRASE: &str = "WitnessTwoPass1234";
const CLIENT_TOKEN: &str = "ExampleClientCredential_0123456789abcdef";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestArtifact {
    schema: u16,
    checkpoint: VaultPolicyCheckpointV1,
    request: WitnessRequestV1,
    action_manifest: ActionManifestV1,
    presentation: ApprovalPresentationV1,
    review_labels: Vec<OwnerReviewLabelV1>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReservePayload {
    request: WitnessRequestV1,
    manifest: ActionManifestV1,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DecidePayload {
    request: WitnessRequestV1,
    manifest: ActionManifestV1,
    approvals: Vec<ApprovalDecisionV1>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CancelPayload {
    request: WitnessRequestV1,
    cancellation: RequestCancellationV1,
}

struct MemoryStore {
    state: PersistedWitnessState,
}

impl WitnessStateStore for MemoryStore {
    fn load(&mut self) -> Result<PersistedWitnessState, WitnessStoreError> {
        Ok(self.state.clone())
    }

    fn commit(
        &mut self,
        expected_generation: u64,
        replacement: PersistedWitnessState,
    ) -> Result<(), WitnessStoreError> {
        if self.state.logical.state_generation != expected_generation
            || replacement.logical.state_generation != expected_generation.saturating_add(1)
            || replacement.pending_anchor.is_none()
        {
            return Err(WitnessStoreError::unavailable());
        }
        self.state = replacement;
        Ok(())
    }

    fn mark_anchor_published(
        &mut self,
        candidate_digest: &Digest32,
    ) -> Result<(), WitnessStoreError> {
        let candidate = self
            .state
            .pending_anchor
            .take()
            .ok_or_else(WitnessStoreError::unavailable)?;
        if candidate.digest().ok().as_ref() != Some(candidate_digest) {
            return Err(WitnessStoreError::unavailable());
        }
        self.state.published_anchor = Some(candidate);
        Ok(())
    }
}

#[derive(Default)]
struct MemoryAnchor {
    value: Option<WitnessStateAnchorV1>,
}

impl ExternalWitnessAnchor for MemoryAnchor {
    fn read(&mut self) -> Result<Option<WitnessStateAnchorV1>, WitnessAnchorError> {
        Ok(self.value.clone())
    }

    fn compare_and_swap(
        &mut self,
        expected: Option<&WitnessStateAnchorV1>,
        candidate: &WitnessStateAnchorV1,
    ) -> Result<AnchorCompareAndSwap, WitnessAnchorError> {
        if self.value.as_ref() != expected {
            return Ok(AnchorCompareAndSwap::Conflict);
        }
        self.value = Some(candidate.clone());
        Ok(AnchorCompareAndSwap::Published)
    }
}

struct SystemClock;

impl WitnessClock for SystemClock {
    fn wall_time_ms(&self) -> u64 {
        now_ms().unwrap_or(1)
    }

    fn monotonic_time_ms(&self) -> u64 {
        self.wall_time_ms()
    }
}

struct EngineServerState {
    identity: WitnessIdentity,
    policy: PolicyState,
    store: MemoryStore,
    anchor: MemoryAnchor,
    clock: SystemClock,
    random: OsRandom,
}

struct EngineEndpoint {
    witness_id: PrincipalId,
    address: String,
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<Result<(), String>>>,
}

impl EngineEndpoint {
    fn specification(&self, credential: &Path) -> TestResult<String> {
        Ok(format!(
            "{},http://{},{}",
            encode_hex(self.witness_id.as_bytes()),
            self.address,
            credential.to_str().ok_or("non-UTF-8 credential path")?
        ))
    }

    fn finish(mut self) -> TestResult {
        self.stop.store(true, Ordering::Release);
        let _ = TcpStream::connect(&self.address);
        let worker = self.worker.take().ok_or("missing endpoint worker")?;
        worker
            .join()
            .map_err(|_| "engine endpoint panicked")?
            .map_err(Into::into)
    }
}

impl Drop for EngineEndpoint {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        let _ = TcpStream::connect(&self.address);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn spawn_engine_endpoint(
    identity: WitnessIdentity,
    policy: PolicyState,
    checkpoint: VaultPolicyCheckpointV1,
    policy_material: PolicyMaterialBytes,
) -> TestResult<EngineEndpoint> {
    let witness_id = identity.principal_id();
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let address = listener.local_addr()?.to_string();
    let stop = Arc::new(AtomicBool::new(false));
    let worker_stop = Arc::clone(&stop);
    let worker = thread::spawn(move || {
        let mut server = EngineServerState {
            identity,
            policy,
            store: MemoryStore {
                state: PersistedWitnessState::empty(witness_id),
            },
            anchor: MemoryAnchor::default(),
            clock: SystemClock,
            random: OsRandom,
        };
        WitnessEngine::new(
            &server.identity,
            &mut server.store,
            &mut server.anchor,
            &server.clock,
            &mut server.random,
        )
        .register_vault(
            &server.policy,
            RegistrationBytes::new(vec![1]).map_err(|error| error.to_string())?,
            checkpoint,
            policy_material,
        )
        .map_err(|error| error.to_string())?;
        while !worker_stop.load(Ordering::Acquire) {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    handle_engine_request(&mut stream, &mut server)?;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(error) => return Err(error.to_string()),
            }
        }
        Ok(())
    });
    Ok(EngineEndpoint {
        witness_id,
        address,
        stop,
        worker: Some(worker),
    })
}

fn handle_engine_request(
    stream: &mut TcpStream,
    server: &mut EngineServerState,
) -> Result<(), String> {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|error| error.to_string())?;
    let (path, body, authorized) = read_http_request(stream)?;
    if !authorized {
        return write_http_json(
            stream,
            401,
            &json!({"status":"refused","reason":"transport-authentication"}),
        );
    }
    let mut engine = WitnessEngine::new(
        &server.identity,
        &mut server.store,
        &mut server.anchor,
        &server.clock,
        &mut server.random,
    );
    let response = match path.as_str() {
        "/v1/requests/reserve" => {
            let payload: ReservePayload =
                serde_json::from_slice(&body).map_err(|error| error.to_string())?;
            match engine.reserve(&server.policy, payload.request, &payload.manifest) {
                Ok(progress) => progress_json(progress),
                Err(error) => refusal_json(error.reason()),
            }
        }
        "/v1/requests/decide" => {
            let payload: DecidePayload =
                serde_json::from_slice(&body).map_err(|error| error.to_string())?;
            match engine.decide(
                &server.policy,
                &payload.request,
                &payload.manifest,
                &payload.approvals,
            ) {
                Ok(progress) => progress_json(progress),
                Err(error) => refusal_json(error.reason()),
            }
        }
        "/v1/requests/cancel" => {
            let payload: CancelPayload =
                serde_json::from_slice(&body).map_err(|error| error.to_string())?;
            match engine.cancel(&server.policy, &payload.request, &payload.cancellation) {
                Ok(CancellationProgress::Cancelled(response)) => {
                    (200, json!({"status":"cancelled","response":*response}))
                }
                Ok(CancellationProgress::TooLate(response)) => {
                    (200, json!({"status":"too-late","response":*response}))
                }
                Err(error) => refusal_json(error.reason()),
            }
        }
        _ => (404, json!({"status":"refused","reason":"invalid"})),
    };
    write_http_json(stream, response.0, &response.1)
}

fn progress_json(progress: WitnessProgress) -> (u16, serde_json::Value) {
    match progress {
        WitnessProgress::Reserved => (200, json!({"status":"reserved","response":null})),
        WitnessProgress::Pending => (200, json!({"status":"pending","response":null})),
        WitnessProgress::Stable(response) => (200, json!({"status":"stable","response":*response})),
    }
}

fn refusal_json(reason: WitnessReasonV1) -> (u16, serde_json::Value) {
    (
        422,
        json!({"status":"refused","reason":{"protocol":reason}}),
    )
}

fn read_http_request(stream: &mut TcpStream) -> Result<(String, Vec<u8>, bool), String> {
    const MAX_HTTP_BYTES: usize = 1024 * 1024;
    let mut bytes = Vec::new();
    let mut scratch = [0_u8; 8192];
    let header_end = loop {
        let read = stream
            .read(&mut scratch)
            .map_err(|error| error.to_string())?;
        if read == 0 {
            return Err("unexpected HTTP EOF".to_owned());
        }
        bytes.extend_from_slice(&scratch[..read]);
        if bytes.len() > MAX_HTTP_BYTES {
            return Err("HTTP fixture request exceeded its bound".to_owned());
        }
        if let Some(position) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            break position + 4;
        }
    };
    let headers = std::str::from_utf8(&bytes[..header_end])
        .map_err(|error| error.to_string())?
        .to_owned();
    let path = headers
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .ok_or_else(|| "missing HTTP request path".to_owned())?
        .to_owned();
    let content_length = headers
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().ok())
                .flatten()
        })
        .ok_or_else(|| "missing HTTP content length".to_owned())?;
    if content_length > MAX_HTTP_BYTES {
        return Err("HTTP fixture body exceeded its bound".to_owned());
    }
    while bytes.len().saturating_sub(header_end) < content_length {
        let read = stream
            .read(&mut scratch)
            .map_err(|error| error.to_string())?;
        if read == 0 {
            return Err("unexpected HTTP body EOF".to_owned());
        }
        bytes.extend_from_slice(&scratch[..read]);
    }
    let authorized = headers
        .lines()
        .any(|line| line.eq_ignore_ascii_case(&format!("authorization: Bearer {CLIENT_TOKEN}")));
    Ok((
        path,
        bytes[header_end..header_end + content_length].to_vec(),
        authorized,
    ))
}

fn write_http_json(
    stream: &mut TcpStream,
    status: u16,
    value: &serde_json::Value,
) -> Result<(), String> {
    let body = serde_json::to_vec(value).map_err(|error| error.to_string())?;
    let reason = if status == 200 { "OK" } else { "Unprocessable" };
    let headers = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream
        .write_all(headers.as_bytes())
        .and_then(|()| stream.write_all(&body))
        .and_then(|()| stream.flush())
        .map_err(|error| error.to_string())
}

fn protected(bytes: &[u8]) -> TestResult<ProtectedMemory> {
    Ok(ProtectedMemory::initialize(
        bytes.len(),
        ProtectionPolicy::EmergencyAllowDegraded,
        |destination| {
            destination.copy_from_slice(bytes);
            Ok::<usize, ()>(bytes.len())
        },
    )?)
}

fn unlock_named_identity(
    data: &Path,
    name: &str,
    passphrase: &str,
) -> TestResult<UnlockedIdentity> {
    let path = data
        .join("jury")
        .join("identities")
        .join(format!("{name}.identity.json"));
    let file = IdentityFileV1::parse(&fs::read(path)?)?;
    Ok(unlock(&file, &protected(passphrase.as_bytes())?)?)
}

fn now_ms() -> TestResult<u64> {
    Ok(u64::try_from(
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis(),
    )?)
}

fn wait_for_request(path: &Path) -> TestResult<RequestArtifact> {
    for _ in 0..600 {
        if let Ok(bytes) = fs::read(path)
            && let Ok(artifact) = serde_json::from_slice::<RequestArtifact>(&bytes)
        {
            if artifact.schema != 1 || serde_json::to_vec(&artifact.request)?.is_empty() {
                return Err("invalid request artifact schema".into());
            }
            return Ok(artifact);
        }
        thread::sleep(Duration::from_millis(50));
    }
    Err("foreground request artifact did not appear".into())
}

fn publish_approval(
    path: &Path,
    artifact: &RequestArtifact,
    policy: &PolicyState,
    approver: &ApproverIdentity,
) -> TestResult<String> {
    let issued_at_ms = now_ms()?;
    let review = render_complete_approval_review(ApprovalReviewInput {
        policy,
        checkpoint: &artifact.checkpoint,
        request: &artifact.request,
        manifest: &artifact.action_manifest,
        presentation: &artifact.presentation,
        review_labels: &artifact.review_labels,
        now_ms: issued_at_ms,
    })?;
    let review_text = review.text().to_owned();
    let decision = ApprovalDecisionCreator::new().create(
        policy,
        &artifact.checkpoint,
        &review,
        approver,
        ApprovalDecisionChoice {
            decision: ApprovalDecisionKindV1::Approve,
            reason: WitnessReasonV1::None,
            now_ms: issued_at_ms,
        },
    )?;
    fs::write(path, serde_json::to_vec(&decision)?)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o644))?;
    Ok(review_text)
}

struct ApprovalRunContext<'a> {
    repository: &'a Path,
    data: &'a Path,
    state: &'a Path,
    policy: &'a PolicyState,
    approver: &'a ApproverIdentity,
}

fn run_with_async_approval(
    context: &ApprovalRunContext<'_>,
    arguments: &[String],
    request_path: &Path,
    approval_path: &Path,
) -> TestResult<(Output, String)> {
    let mut child = jury_command(context.repository, context.data, context.state)
        .args(arguments)
        .env("EXAMPLE_AMBIENT_INPUT", "ambient-environment")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    child
        .stdin
        .take()
        .ok_or("foreground stdin unavailable")?
        .write_all(format!("{OWNER_PASSPHRASE}\nambient-stdin\n").as_bytes())?;
    let artifact = wait_for_request(request_path)?;
    let review = publish_approval(approval_path, &artifact, context.policy, context.approver)?;
    Ok((child.wait_with_output()?, review))
}

fn unlock_witness(data: &Path, name: &str, passphrase: &str) -> TestResult<WitnessIdentity> {
    if let UnlockedIdentity::Witness(identity) = unlock_named_identity(data, name, passphrase)? {
        Ok(identity)
    } else {
        Err("identity has the wrong witness role".into())
    }
}

fn unlock_approver(data: &Path, name: &str, passphrase: &str) -> TestResult<ApproverIdentity> {
    if let UnlockedIdentity::Approver(identity) = unlock_named_identity(data, name, passphrase)? {
        Ok(identity)
    } else {
        Err("identity has the wrong approver role".into())
    }
}

fn verify_receipts(repository: &Path, data: &Path, state: &Path, receipts: &[&Path]) -> TestResult {
    for receipt in receipts {
        let verified = success_json(run(
            repository,
            data,
            state,
            &[
                "--json",
                "receipt",
                "verify",
                receipt.to_str().ok_or("non-UTF-8 receipt")?,
            ],
            b"",
        )?)?;
        assert_eq!(verified["verified"], true);
        assert_eq!(verified["contains_contribution_material"], false);
    }
    Ok(())
}

fn assert_tree_omits(path: &Path, forbidden: &[u8]) -> TestResult {
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let metadata = entry.file_type()?;
        if metadata.is_dir() {
            assert_tree_omits(&entry.path(), forbidden)?;
        } else if metadata.is_file() {
            let bytes = fs::read(entry.path())?;
            assert!(
                !bytes
                    .windows(forbidden.len())
                    .any(|window| window == forbidden),
                "protected field value escaped into {}",
                entry.path().display()
            );
        }
    }
    Ok(())
}

include!("witnessed/workflow.rs");
