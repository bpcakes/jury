use std::{
    io::{self, Read as _},
    path::Path,
    time::{Duration, Instant},
};

use jury_core::witness_engine::{AnchorCompareAndSwap, ExternalWitnessAnchor, WitnessAnchorError};
use jury_protocol::{
    vault_v1::{Digest32, PrincipalId},
    witness_v1::WitnessStateAnchorV1,
};
use reqwest::{StatusCode, Url, blocking::Client};
use rusqlite::{Connection, OptionalExtension as _, TransactionBehavior, params};
use serde::{Deserialize, Serialize};

use crate::{
    AdapterError, AdapterErrorKind,
    credentials::{BearerCredential, authorization_header, load_bearer},
    persistence::{
        ANCHOR_DATABASE_KIND, backup_managed_database, ensure_adapter_deadline,
        initialize_managed_database, open_managed_database, remaining_busy_timeout,
        restore_managed_database, set_busy_timeout,
    },
};

pub const MAX_ANCHOR_HTTP_BYTES: usize = 1024 * 1024;

pub struct SqliteAnchorRepository {
    connection: Connection,
    witness_id: PrincipalId,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AnchorCasResult {
    Applied(WitnessStateAnchorV1),
    Conflict(Option<WitnessStateAnchorV1>),
}

impl SqliteAnchorRepository {
    pub fn initialize(path: &Path) -> Result<(), AdapterError> {
        initialize_managed_database(path, ANCHOR_DATABASE_KIND, |_| Ok(()))
    }

    pub fn open(path: &Path, witness_id: PrincipalId) -> Result<Self, AdapterError> {
        Ok(Self {
            connection: open_managed_database(path, ANCHOR_DATABASE_KIND)?,
            witness_id,
        })
    }

    pub fn read(&self) -> Result<Option<WitnessStateAnchorV1>, AdapterError> {
        self.read_with_deadline(None)
    }

    pub(crate) fn read_until(
        &self,
        deadline: Instant,
    ) -> Result<Option<WitnessStateAnchorV1>, AdapterError> {
        self.read_with_deadline(Some(deadline))
    }

    fn read_with_deadline(
        &self,
        deadline: Option<Instant>,
    ) -> Result<Option<WitnessStateAnchorV1>, AdapterError> {
        prepare_anchor_deadline(&self.connection, deadline)?;
        let anchor = load_anchor(&self.connection, &self.witness_id)?;
        ensure_anchor_deadline(deadline)?;
        Ok(anchor)
    }

    pub fn compare_and_swap(
        &mut self,
        expected_digest: Option<&Digest32>,
        candidate: &WitnessStateAnchorV1,
    ) -> Result<AnchorCasResult, AdapterError> {
        self.compare_and_swap_with_deadline(expected_digest, candidate, None)
    }

    pub(crate) fn compare_and_swap_until(
        &mut self,
        expected_digest: Option<&Digest32>,
        candidate: &WitnessStateAnchorV1,
        deadline: Instant,
    ) -> Result<AnchorCasResult, AdapterError> {
        self.compare_and_swap_with_deadline(expected_digest, candidate, Some(deadline))
    }

    fn compare_and_swap_with_deadline(
        &mut self,
        expected_digest: Option<&Digest32>,
        candidate: &WitnessStateAnchorV1,
        deadline: Option<Instant>,
    ) -> Result<AnchorCasResult, AdapterError> {
        prepare_anchor_deadline(&self.connection, deadline)?;
        validate_candidate(&self.witness_id, candidate)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(anchor_unavailable)?;
        let current = load_anchor(&transaction, &self.witness_id)?;
        ensure_anchor_deadline(deadline)?;
        if current.as_ref().is_some_and(|current| current == candidate) {
            transaction.commit().map_err(anchor_unavailable)?;
            return Ok(AnchorCasResult::Applied(candidate.clone()));
        }
        let current_digest = current
            .as_ref()
            .map(WitnessStateAnchorV1::digest)
            .transpose()
            .map_err(|_| AdapterError::new(AdapterErrorKind::InvalidState))?;
        let predecessor = expected_digest.cloned().unwrap_or_else(zero_digest);
        let generation = current
            .as_ref()
            .map_or(1, |anchor| anchor.state_generation.saturating_add(1));
        if current_digest.as_ref() != expected_digest
            || candidate.predecessor_anchor_digest != predecessor
            || candidate.state_generation != generation
        {
            transaction.commit().map_err(anchor_unavailable)?;
            return Ok(AnchorCasResult::Conflict(current));
        }
        let digest = candidate
            .digest()
            .map_err(|_| AdapterError::new(AdapterErrorKind::InvalidState))?;
        let encoded = serde_json::to_vec(candidate)
            .map_err(|_| AdapterError::new(AdapterErrorKind::InvalidState))?;
        ensure_anchor_deadline(deadline)?;
        let generation = i64::try_from(candidate.state_generation)
            .map_err(|_| AdapterError::new(AdapterErrorKind::CapacityExhausted))?;
        transaction
            .execute(
                "INSERT INTO anchors(witness_id, generation, digest, anchor_json) \
                 VALUES (?1, ?2, ?3, ?4) \
                 ON CONFLICT(witness_id) DO UPDATE SET \
                     generation = excluded.generation, \
                     digest = excluded.digest, \
                     anchor_json = excluded.anchor_json",
                params![
                    self.witness_id.as_bytes().as_slice(),
                    generation,
                    digest.as_bytes().as_slice(),
                    encoded
                ],
            )
            .map_err(anchor_unavailable)?;
        ensure_anchor_deadline(deadline)?;
        transaction.commit().map_err(anchor_unavailable)?;
        let readback = self
            .read_with_deadline(deadline)?
            .ok_or_else(|| AdapterError::new(AdapterErrorKind::AnchorUnavailable))?;
        if readback != *candidate {
            return Err(AdapterError::new(AdapterErrorKind::Conflict));
        }
        Ok(AnchorCasResult::Applied(readback))
    }
}

fn prepare_anchor_deadline(
    connection: &Connection,
    deadline: Option<Instant>,
) -> Result<(), AdapterError> {
    let timeout = remaining_busy_timeout(deadline).map_err(|_| anchor_deadline_exceeded())?;
    set_busy_timeout(connection, timeout).map_err(|_| anchor_deadline_exceeded())
}

fn ensure_anchor_deadline(deadline: Option<Instant>) -> Result<(), AdapterError> {
    ensure_adapter_deadline(deadline).map_err(|_| anchor_deadline_exceeded())
}

fn anchor_deadline_exceeded() -> AdapterError {
    AdapterError::new(AdapterErrorKind::AnchorUnavailable)
}

pub fn backup_anchor_database(source: &Path, destination: &Path) -> Result<(), AdapterError> {
    backup_managed_database(source, destination, ANCHOR_DATABASE_KIND)
}

pub fn restore_anchor_database(backup: &Path, destination: &Path) -> Result<(), AdapterError> {
    restore_managed_database(backup, destination, ANCHOR_DATABASE_KIND)
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AnchorCasRequest {
    pub expected_anchor_digest: Option<Digest32>,
    pub next_exact_anchor: WitnessStateAnchorV1,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AnchorCasOutcome {
    Applied,
    Conflict,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AnchorCasResponse {
    pub outcome: AnchorCasOutcome,
    pub exact_anchor: Option<WitnessStateAnchorV1>,
}

#[derive(Clone)]
pub struct HttpExternalAnchor {
    client: Client,
    endpoint: Url,
    witness_id: PrincipalId,
    credential: BearerCredential,
    request_timeout: Duration,
    operation_deadline: Option<Instant>,
}

impl HttpExternalAnchor {
    pub fn new(
        base_url: &str,
        witness_id: PrincipalId,
        ca_certificate: &Path,
        credential_file: &Path,
        allow_insecure_loopback: bool,
        request_timeout: Duration,
    ) -> Result<Self, AdapterError> {
        let mut endpoint = Url::parse(base_url)
            .map_err(|_| AdapterError::new(AdapterErrorKind::InvalidConfiguration))?;
        validate_anchor_url(&endpoint, allow_insecure_loopback)?;
        if !endpoint.path().ends_with('/') {
            let path = format!("{}/", endpoint.path());
            endpoint.set_path(&path);
        }
        endpoint = endpoint
            .join(&format!("v1/anchors/{}", hex_id(&witness_id)))
            .map_err(|_| AdapterError::new(AdapterErrorKind::InvalidConfiguration))?;
        let ca_bytes = jury_filesystem::read_public_file(ca_certificate, 1024 * 1024)
            .map_err(|_| AdapterError::new(AdapterErrorKind::InvalidConfiguration))?;
        let certificate = reqwest::Certificate::from_pem(&ca_bytes)
            .map_err(|_| AdapterError::new(AdapterErrorKind::InvalidConfiguration))?;
        let client = Client::builder()
            .tls_certs_only([certificate])
            .connect_timeout(request_timeout)
            .timeout(request_timeout)
            .https_only(!allow_insecure_loopback)
            .no_proxy()
            .build()
            .map_err(|_| AdapterError::new(AdapterErrorKind::InvalidConfiguration))?;
        Ok(Self {
            client,
            endpoint,
            witness_id,
            credential: load_bearer(credential_file)?,
            request_timeout,
            operation_deadline: None,
        })
    }

    #[must_use]
    pub(crate) fn with_deadline(mut self, deadline: Instant) -> Self {
        self.operation_deadline = Some(deadline);
        self
    }

    fn remaining_timeout(&self) -> Result<Duration, AdapterError> {
        remaining_timeout(
            self.request_timeout,
            self.operation_deadline,
            Instant::now(),
        )
    }

    fn read_remote(&self) -> Result<Option<WitnessStateAnchorV1>, AdapterError> {
        let timeout = self.remaining_timeout()?;
        let response = self
            .client
            .get(self.endpoint.clone())
            .timeout(timeout)
            .send()
            .map_err(|_| AdapterError::new(AdapterErrorKind::AnchorUnavailable))?;
        match response.status() {
            StatusCode::NOT_FOUND => Ok(None),
            StatusCode::OK => {
                let anchor: WitnessStateAnchorV1 = bounded_json(response)?;
                validate_candidate(&self.witness_id, &anchor)?;
                Ok(Some(anchor))
            }
            _ => Err(AdapterError::new(AdapterErrorKind::AnchorUnavailable)),
        }
    }
}

fn remaining_timeout(
    request_timeout: Duration,
    operation_deadline: Option<Instant>,
    now: Instant,
) -> Result<Duration, AdapterError> {
    let Some(deadline) = operation_deadline else {
        return Ok(request_timeout);
    };
    deadline
        .checked_duration_since(now)
        .filter(|remaining| !remaining.is_zero())
        .map(|remaining| remaining.min(request_timeout))
        .ok_or_else(|| AdapterError::new(AdapterErrorKind::AnchorUnavailable))
}

impl ExternalWitnessAnchor for HttpExternalAnchor {
    fn ensure_publishable(
        &mut self,
        candidate: &WitnessStateAnchorV1,
    ) -> Result<(), WitnessAnchorError> {
        validate_candidate(&self.witness_id, candidate)
            .map_err(|_| WitnessAnchorError::unavailable())?;
        ensure_bounded_json(&AnchorCasRequest {
            expected_anchor_digest: Some(zero_digest()),
            next_exact_anchor: candidate.clone(),
        })?;
        ensure_bounded_json(&AnchorCasResponse {
            outcome: AnchorCasOutcome::Applied,
            exact_anchor: Some(candidate.clone()),
        })
    }

    fn read(&mut self) -> Result<Option<WitnessStateAnchorV1>, WitnessAnchorError> {
        self.read_remote()
            .map_err(|_| WitnessAnchorError::unavailable())
    }

    fn compare_and_swap(
        &mut self,
        expected: Option<&WitnessStateAnchorV1>,
        candidate: &WitnessStateAnchorV1,
    ) -> Result<AnchorCompareAndSwap, WitnessAnchorError> {
        validate_candidate(&self.witness_id, candidate)
            .map_err(|_| WitnessAnchorError::unavailable())?;
        let request = AnchorCasRequest {
            expected_anchor_digest: expected
                .map(WitnessStateAnchorV1::digest)
                .transpose()
                .map_err(|_| WitnessAnchorError::unavailable())?,
            next_exact_anchor: candidate.clone(),
        };
        ensure_bounded_json(&request)?;
        let timeout = self
            .remaining_timeout()
            .map_err(|_| WitnessAnchorError::unavailable())?;
        let response = self
            .client
            .post(self.endpoint.clone())
            .timeout(timeout)
            .header(authorization_header(), self.credential.authorization())
            .json(&request)
            .send()
            .map_err(|_| WitnessAnchorError::unavailable())?;
        if response.status() != StatusCode::OK {
            return Err(WitnessAnchorError::unavailable());
        }
        let response: AnchorCasResponse =
            bounded_json(response).map_err(|_| WitnessAnchorError::unavailable())?;
        match response.outcome {
            AnchorCasOutcome::Applied if response.exact_anchor.as_ref() == Some(candidate) => {
                Ok(AnchorCompareAndSwap::Published)
            }
            AnchorCasOutcome::Conflict => Ok(AnchorCompareAndSwap::Conflict),
            AnchorCasOutcome::Applied => Err(WitnessAnchorError::unavailable()),
        }
    }
}

struct JsonSizeWriter {
    written: usize,
    capacity_exhausted: bool,
}

impl io::Write for JsonSizeWriter {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        let Some(written) = self.written.checked_add(input.len()) else {
            self.capacity_exhausted = true;
            return Err(io::Error::other("anchor JSON exceeds capacity"));
        };
        if written > MAX_ANCHOR_HTTP_BYTES {
            self.capacity_exhausted = true;
            return Err(io::Error::other("anchor JSON exceeds capacity"));
        }
        self.written = written;
        Ok(input.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn ensure_bounded_json(value: &impl Serialize) -> Result<(), WitnessAnchorError> {
    let mut writer = JsonSizeWriter {
        written: 0,
        capacity_exhausted: false,
    };
    match serde_json::to_writer(&mut writer, value) {
        Ok(()) => Ok(()),
        Err(_) if writer.capacity_exhausted => Err(WitnessAnchorError::capacity_exhausted()),
        Err(_) => Err(WitnessAnchorError::unavailable()),
    }
}

fn load_anchor(
    connection: &Connection,
    witness_id: &PrincipalId,
) -> Result<Option<WitnessStateAnchorV1>, AdapterError> {
    let row: Option<(i64, Vec<u8>, Vec<u8>)> = connection
        .query_row(
            "SELECT generation, digest, anchor_json FROM anchors WHERE witness_id = ?1",
            params![witness_id.as_bytes().as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(anchor_unavailable)?;
    let Some((generation, digest, encoded)) = row else {
        return Ok(None);
    };
    let anchor: WitnessStateAnchorV1 = serde_json::from_slice(&encoded)
        .map_err(|_| AdapterError::new(AdapterErrorKind::InvalidState))?;
    validate_candidate(witness_id, &anchor)?;
    let generation =
        u64::try_from(generation).map_err(|_| AdapterError::new(AdapterErrorKind::InvalidState))?;
    if anchor.state_generation != generation
        || anchor
            .digest()
            .map_err(|_| AdapterError::new(AdapterErrorKind::InvalidState))?
            .as_bytes()
            != digest.as_slice()
    {
        return Err(AdapterError::new(AdapterErrorKind::InvalidState));
    }
    Ok(Some(anchor))
}

fn validate_candidate(
    witness_id: &PrincipalId,
    candidate: &WitnessStateAnchorV1,
) -> Result<(), AdapterError> {
    candidate
        .validate_shape()
        .map_err(|_| AdapterError::new(AdapterErrorKind::InvalidState))?;
    if candidate.witness_id != *witness_id {
        return Err(AdapterError::new(AdapterErrorKind::InvalidState));
    }
    Ok(())
}

fn validate_anchor_url(url: &Url, allow_insecure_loopback: bool) -> Result<(), AdapterError> {
    if url.username() != ""
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(AdapterError::new(AdapterErrorKind::InvalidConfiguration));
    }
    let loopback = matches!(url.host_str(), Some("127.0.0.1" | "localhost" | "::1"));
    if url.scheme() != "https" && !(allow_insecure_loopback && url.scheme() == "http" && loopback) {
        return Err(AdapterError::new(AdapterErrorKind::InvalidConfiguration));
    }
    Ok(())
}

fn bounded_json<T: serde::de::DeserializeOwned>(
    mut response: reqwest::blocking::Response,
) -> Result<T, AdapterError> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_ANCHOR_HTTP_BYTES as u64)
    {
        return Err(AdapterError::new(AdapterErrorKind::CapacityExhausted));
    }
    let mut bytes = Vec::with_capacity(MAX_ANCHOR_HTTP_BYTES.min(16 * 1024));
    response
        .by_ref()
        .take((MAX_ANCHOR_HTTP_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| AdapterError::new(AdapterErrorKind::AnchorUnavailable))?;
    if bytes.len() > MAX_ANCHOR_HTTP_BYTES {
        return Err(AdapterError::new(AdapterErrorKind::CapacityExhausted));
    }
    serde_json::from_slice(&bytes).map_err(|_| AdapterError::new(AdapterErrorKind::InvalidState))
}

fn zero_digest() -> Digest32 {
    Digest32::new([0; 32])
}

fn hex_id(id: &PrincipalId) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(64);
    for byte in id.as_bytes() {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn anchor_unavailable(_: rusqlite::Error) -> AdapterError {
    AdapterError::new(AdapterErrorKind::AnchorUnavailable)
}

#[cfg(test)]
mod tests {
    use std::{error::Error, fs, os::unix::fs::PermissionsExt as _};

    use jury_protocol::{
        vault_v1::{Signature64, VaultId},
        witness_v1::VaultHighWatermarkV1,
    };

    use super::*;

    type TestResult<T = ()> = Result<T, Box<dyn Error>>;

    fn candidate(
        witness_id: PrincipalId,
        generation: u64,
        predecessor_anchor_digest: Digest32,
        marker: u8,
    ) -> WitnessStateAnchorV1 {
        WitnessStateAnchorV1 {
            schema: 1,
            witness_id,
            witness_signing_key_fingerprint: Digest32::new([2; 32]),
            witness_signing_key_epoch: 1,
            state_generation: generation,
            database_state_digest: Digest32::new([marker; 32]),
            vault_high_watermarks: Vec::new(),
            replay_retain_through_ms: 0,
            last_accepted_wall_time_ms: generation,
            predecessor_anchor_digest,
            issued_at_ms: generation,
            signature: Signature64::new([marker; 64]),
        }
    }

    #[test]
    fn repository_allows_only_exact_monotonic_compare_and_swap() -> TestResult {
        let directory = tempfile::tempdir()?;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
        let path = directory.path().join("anchors.sqlite3");
        let witness_id = PrincipalId::from_bytes([1; 32])?;
        SqliteAnchorRepository::initialize(&path)?;
        let mut repository = SqliteAnchorRepository::open(&path, witness_id)?;
        let foreign = candidate(PrincipalId::from_bytes([8; 32])?, 1, zero_digest(), 8);
        assert_eq!(
            repository
                .compare_and_swap(None, &foreign)
                .err()
                .ok_or("foreign witness candidate should fail")?
                .kind(),
            AdapterErrorKind::InvalidState
        );
        let first = candidate(witness_id, 1, zero_digest(), 3);
        assert_eq!(
            repository.compare_and_swap(None, &first)?,
            AnchorCasResult::Applied(first.clone())
        );
        assert_eq!(
            repository.compare_and_swap(None, &first)?,
            AnchorCasResult::Applied(first.clone())
        );

        let first_digest = first.digest()?;
        let wrong = candidate(witness_id, 2, Digest32::new([9; 32]), 4);
        assert_eq!(
            repository.compare_and_swap(Some(&first_digest), &wrong)?,
            AnchorCasResult::Conflict(Some(first.clone()))
        );
        let second = candidate(witness_id, 2, first_digest.clone(), 5);
        assert_eq!(
            repository.compare_and_swap(Some(&first_digest), &second)?,
            AnchorCasResult::Applied(second.clone())
        );
        assert_eq!(repository.read()?, Some(second));
        Ok(())
    }

    #[test]
    fn anchor_backup_restores_independently_without_overwrite() -> TestResult {
        let directory = tempfile::tempdir()?;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
        let source = directory.path().join("source.sqlite3");
        let backup = directory.path().join("backup.sqlite3");
        let restored = directory.path().join("restored.sqlite3");
        let witness_id = PrincipalId::from_bytes([6; 32])?;
        SqliteAnchorRepository::initialize(&source)?;
        let mut repository = SqliteAnchorRepository::open(&source, witness_id)?;
        let first = candidate(witness_id, 1, zero_digest(), 7);
        repository.compare_and_swap(None, &first)?;

        backup_anchor_database(&source, &backup)?;
        restore_anchor_database(&backup, &restored)?;
        assert_eq!(
            SqliteAnchorRepository::open(&restored, witness_id)?.read()?,
            Some(first)
        );
        assert_eq!(
            restore_anchor_database(&backup, &restored)
                .err()
                .ok_or("anchor restore overwrite should fail")?
                .kind(),
            AdapterErrorKind::TargetExists
        );
        Ok(())
    }

    #[test]
    fn anchor_calls_share_the_remaining_operation_budget() -> TestResult {
        let now = Instant::now();
        let request_timeout = Duration::from_secs(5);
        assert_eq!(
            remaining_timeout(request_timeout, Some(now + Duration::from_millis(250)), now,)?,
            Duration::from_millis(250)
        );
        assert_eq!(
            remaining_timeout(request_timeout, Some(now + Duration::from_secs(30)), now,)?,
            request_timeout
        );
        assert_eq!(
            remaining_timeout(request_timeout, Some(now), now)
                .err()
                .ok_or("expired operation should not issue another request")?
                .kind(),
            AdapterErrorKind::AnchorUnavailable
        );
        Ok(())
    }

    #[test]
    fn anchor_wire_artifacts_are_bounded_before_http() -> TestResult {
        let witness_id = PrincipalId::from_bytes([5; 32])?;
        let small = candidate(witness_id, 1, zero_digest(), 7);
        ensure_bounded_json(&AnchorCasRequest {
            expected_anchor_digest: Some(zero_digest()),
            next_exact_anchor: small,
        })
        .map_err(|_| "small anchor should fit")?;

        let mut large = candidate(witness_id, 1, zero_digest(), 8);
        large.vault_high_watermarks = (1_u64..=10_000)
            .map(|index| -> TestResult<VaultHighWatermarkV1> {
                let mut id = [0_u8; 32];
                id[24..].copy_from_slice(&index.to_be_bytes());
                Ok(VaultHighWatermarkV1 {
                    vault_id: VaultId::from_bytes(id)?,
                    genesis_fingerprint: Digest32::new([1; 32]),
                    policy_sequence: index,
                    checkpoint_digest: Digest32::new([2; 32]),
                    highest_retained_request_expiry_ms: index,
                })
            })
            .collect::<TestResult<Vec<_>>>()?;
        assert_eq!(
            ensure_bounded_json(&AnchorCasRequest {
                expected_anchor_digest: Some(zero_digest()),
                next_exact_anchor: large,
            })
            .err()
            .ok_or("large anchor should be rejected")?
            .kind(),
            jury_core::witness_engine::WitnessAnchorErrorKind::CapacityExhausted
        );
        Ok(())
    }
}
