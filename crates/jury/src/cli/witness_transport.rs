use std::{io::Read as _, path::Path, time::Duration};

use reqwest::{StatusCode, Url, blocking::Client, header::HeaderValue};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize as _, Zeroizing};

use super::*;

const MAX_CREDENTIAL_BYTES: usize = 256;
const MAX_WITNESS_HTTP_BYTES: usize = 64 * 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum TransportProgressKind {
    Reserved,
    Pending,
    Stable,
    Cancelled,
    TooLate,
}

pub(super) struct TransportProgress {
    pub(super) kind: TransportProgressKind,
    pub(super) response: Option<jury_protocol::witness_v1::WitnessResponseV1>,
}

pub(super) struct WitnessEndpointClient {
    pub(super) witness_id: PrincipalId,
    client: Client,
    reserve_url: Url,
    decide_url: Url,
    cancel_url: Url,
    authorization: HeaderValue,
}

#[derive(Serialize)]
struct ReservePayload<'a> {
    request: &'a jury_protocol::witness_v1::WitnessRequestV1,
    manifest: &'a jury_protocol::witness_v1::ActionManifestV1,
}

#[derive(Serialize)]
struct DecidePayload<'a> {
    request: &'a jury_protocol::witness_v1::WitnessRequestV1,
    manifest: &'a jury_protocol::witness_v1::ActionManifestV1,
    approvals: &'a [jury_protocol::witness_v1::ApprovalDecisionV1],
}

#[derive(Serialize)]
struct CancelPayload<'a> {
    request: &'a jury_protocol::witness_v1::WitnessRequestV1,
    cancellation: &'a jury_protocol::witness_v1::RequestCancellationV1,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OperationResponse {
    status: String,
    response: Option<jury_protocol::witness_v1::WitnessResponseV1>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RefusalResponse {
    status: String,
    reason: RefusalReason,
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
enum RefusalReason {
    TransportAuthentication,
    RateLimited,
    Invalid,
    Unavailable,
    InternalFailure,
    Protocol(jury_protocol::witness_v1::WitnessReasonV1),
}

impl WitnessEndpointClient {
    pub(super) fn parse(
        specification: &str,
        allow_insecure_loopback: bool,
    ) -> Result<Self, CliError> {
        let parts = specification.split(',').collect::<Vec<_>>();
        if !(parts.len() == 3 || parts.len() == 4) || parts.iter().any(|part| part.is_empty()) {
            return Err(invalid_witness_endpoint());
        }
        let witness_id = parse_principal_id(parts[0])?;
        let mut base = Url::parse(parts[1]).map_err(|_| invalid_witness_endpoint())?;
        validate_url(&base, allow_insecure_loopback)?;
        if !base.path().ends_with('/') {
            base.set_path(&format!("{}/", base.path()));
        }
        let reserve_url = base
            .join("v1/requests/reserve")
            .map_err(|_| invalid_witness_endpoint())?;
        let decide_url = base
            .join("v1/requests/decide")
            .map_err(|_| invalid_witness_endpoint())?;
        let cancel_url = base
            .join("v1/requests/cancel")
            .map_err(|_| invalid_witness_endpoint())?;
        let mut builder = Client::builder()
            .connect_timeout(REQUEST_TIMEOUT)
            .timeout(REQUEST_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy();
        if base.scheme() == "https" {
            let certificate_path = parts.get(3).ok_or_else(invalid_witness_endpoint)?;
            let certificate_bytes = read_public_file(Path::new(certificate_path), 1024 * 1024)
                .map_err(map_filesystem_error)?;
            let certificate = reqwest::Certificate::from_pem(&certificate_bytes)
                .map_err(|_| invalid_witness_endpoint())?;
            builder = builder.tls_certs_only([certificate]).https_only(true);
        } else {
            builder = builder.https_only(false);
        }
        let client = builder.build().map_err(|_| invalid_witness_endpoint())?;
        let mut credential = Zeroizing::new(
            read_private_file(Path::new(parts[2]), MAX_CREDENTIAL_BYTES + 2)
                .map_err(map_filesystem_error)?,
        );
        while credential
            .last()
            .is_some_and(|byte| matches!(byte, b'\r' | b'\n'))
        {
            credential.pop();
        }
        if !(32..=MAX_CREDENTIAL_BYTES).contains(&credential.len())
            || !credential
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(invalid_witness_credential());
        }
        let mut bearer = b"Bearer ".to_vec();
        bearer.extend_from_slice(&credential);
        let mut authorization =
            HeaderValue::from_bytes(&bearer).map_err(|_| invalid_witness_credential())?;
        bearer.zeroize();
        authorization.set_sensitive(true);
        Ok(Self {
            witness_id,
            client,
            reserve_url,
            decide_url,
            cancel_url,
            authorization,
        })
    }

    pub(super) fn reserve(
        &self,
        request: &jury_protocol::witness_v1::WitnessRequestV1,
        manifest: &jury_protocol::witness_v1::ActionManifestV1,
    ) -> Result<TransportProgress, CliError> {
        self.post(
            self.reserve_url.clone(),
            &ReservePayload { request, manifest },
        )
    }

    pub(super) fn decide(
        &self,
        request: &jury_protocol::witness_v1::WitnessRequestV1,
        manifest: &jury_protocol::witness_v1::ActionManifestV1,
        approvals: &[jury_protocol::witness_v1::ApprovalDecisionV1],
    ) -> Result<TransportProgress, CliError> {
        self.post(
            self.decide_url.clone(),
            &DecidePayload {
                request,
                manifest,
                approvals,
            },
        )
    }

    pub(super) fn cancel(
        &self,
        request: &jury_protocol::witness_v1::WitnessRequestV1,
        cancellation: &jury_protocol::witness_v1::RequestCancellationV1,
    ) -> Result<TransportProgress, CliError> {
        self.post(
            self.cancel_url.clone(),
            &CancelPayload {
                request,
                cancellation,
            },
        )
    }

    fn post(&self, url: Url, payload: &impl Serialize) -> Result<TransportProgress, CliError> {
        let response = self
            .client
            .post(url)
            .header(reqwest::header::AUTHORIZATION, self.authorization.clone())
            .json(payload)
            .send()
            .map_err(|_| witness_unavailable())?;
        if response.status() != StatusCode::OK {
            let refusal: RefusalResponse = bounded_json(response)?;
            if refusal.status != "refused" {
                return Err(invalid_witness_response());
            }
            return Err(map_refusal(refusal.reason));
        }
        let response: OperationResponse = bounded_json(response)?;
        let kind = match response.status.as_str() {
            "reserved" => TransportProgressKind::Reserved,
            "pending" => TransportProgressKind::Pending,
            "stable" => TransportProgressKind::Stable,
            "cancelled" => TransportProgressKind::Cancelled,
            "too-late" => TransportProgressKind::TooLate,
            _ => return Err(invalid_witness_response()),
        };
        let is_terminal = matches!(
            kind,
            TransportProgressKind::Stable
                | TransportProgressKind::Cancelled
                | TransportProgressKind::TooLate
        );
        if is_terminal != response.response.is_some()
            || response
                .response
                .as_ref()
                .is_some_and(|response| response.decision.witness_id != self.witness_id)
        {
            return Err(invalid_witness_response());
        }
        Ok(TransportProgress {
            kind,
            response: response.response,
        })
    }
}

const fn map_refusal(reason: RefusalReason) -> CliError {
    use jury_protocol::witness_v1::WitnessReasonV1;
    match reason {
        RefusalReason::TransportAuthentication => CliError::new(
            CliErrorKind::AuthenticationFailed,
            "witness-transport-authentication-failed",
            "a witness rejected the configured client credential",
        ),
        RefusalReason::Invalid => invalid_witness_response(),
        RefusalReason::Protocol(WitnessReasonV1::Expired) => CliError::new(
            CliErrorKind::Conflict,
            "request-expired",
            "the witnessed request expired",
        ),
        RefusalReason::Protocol(
            WitnessReasonV1::StalePolicy
            | WitnessReasonV1::WitnessBehind
            | WitnessReasonV1::CheckpointFork,
        ) => CliError::new(
            CliErrorKind::Conflict,
            "request-stale",
            "the request or witness checkpoint is stale",
        ),
        RefusalReason::Protocol(WitnessReasonV1::ReplayConflict) => CliError::new(
            CliErrorKind::Conflict,
            "request-replay",
            "the witness rejected a conflicting replay",
        ),
        RefusalReason::Protocol(
            WitnessReasonV1::PolicyDenied
            | WitnessReasonV1::ApprovalDenied
            | WitnessReasonV1::ApprovalConflict,
        ) => CliError::new(
            CliErrorKind::AccessDenied,
            "request-denied",
            "the witness denied this exact request",
        ),
        RefusalReason::Protocol(WitnessReasonV1::Cancelled) => CliError::new(
            CliErrorKind::Conflict,
            "request-cancelled",
            "the witnessed request was cancelled",
        ),
        RefusalReason::Protocol(WitnessReasonV1::InsufficientQuorum) => CliError::new(
            CliErrorKind::Conflict,
            "insufficient-witness-quorum",
            "too few distinct current witnesses approved this request",
        ),
        RefusalReason::RateLimited
        | RefusalReason::Unavailable
        | RefusalReason::InternalFailure
        | RefusalReason::Protocol(_) => witness_unavailable(),
    }
}

fn validate_url(url: &Url, allow_insecure_loopback: bool) -> Result<(), CliError> {
    if url.username() != ""
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(invalid_witness_endpoint());
    }
    let loopback = matches!(url.host_str(), Some("127.0.0.1" | "::1"));
    if url.scheme() != "https" && !(allow_insecure_loopback && url.scheme() == "http" && loopback) {
        return Err(invalid_witness_endpoint());
    }
    Ok(())
}

fn bounded_json<T: serde::de::DeserializeOwned>(
    mut response: reqwest::blocking::Response,
) -> Result<T, CliError> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_WITNESS_HTTP_BYTES as u64)
    {
        return Err(invalid_witness_response());
    }
    let mut bytes = Vec::with_capacity(16 * 1024);
    response
        .by_ref()
        .take((MAX_WITNESS_HTTP_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| witness_unavailable())?;
    if bytes.len() > MAX_WITNESS_HTTP_BYTES {
        return Err(invalid_witness_response());
    }
    serde_json::from_slice(&bytes).map_err(|_| invalid_witness_response())
}

const fn invalid_witness_endpoint() -> CliError {
    CliError::new(
        CliErrorKind::InvalidArguments,
        "invalid-witness-endpoint",
        "witness endpoints require exact ID,URL,credential[,CA] fields and HTTPS or explicit literal-loopback HTTP",
    )
}

const fn invalid_witness_credential() -> CliError {
    CliError::new(
        CliErrorKind::AuthenticationFailed,
        "invalid-witness-credential",
        "the private witness client credential is invalid",
    )
}

pub(super) const fn witness_unavailable() -> CliError {
    CliError::new(
        CliErrorKind::Conflict,
        "witness-unavailable",
        "a configured witness was unavailable or refused transport authentication",
    )
}

pub(super) const fn invalid_witness_response() -> CliError {
    CliError::new(
        CliErrorKind::AuthenticationFailed,
        "invalid-witness-response",
        "a witness returned malformed or wrongly bound response data",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insecure_transport_is_limited_to_explicit_literal_loopback()
    -> Result<(), Box<dyn std::error::Error>> {
        let loopback = Url::parse("http://127.0.0.1:7443")?;
        assert!(validate_url(&loopback, true).is_ok());
        assert!(validate_url(&loopback, false).is_err());
        assert!(validate_url(&Url::parse("http://localhost:7443")?, true).is_err());
        assert!(validate_url(&Url::parse("http://192.0.2.1:7443")?, true).is_err());
        assert!(validate_url(&Url::parse("https://user@example.invalid")?, false).is_err());
        Ok(())
    }
}
