use super::*;
use std::time::Duration;

pub(super) struct ProofPoll {
    previous: Option<Vec<Option<Digest32>>>,
    error: CliError,
    delay: Duration,
    retry_at_ms: Option<u64>,
}

impl Default for ProofPoll {
    fn default() -> Self {
        Self {
            previous: None,
            error: registration_required(),
            delay: Duration::from_millis(200),
            retry_at_ms: None,
        }
    }
}

impl ProofPoll {
    pub(super) fn error(&self) -> CliError {
        self.error
    }
    pub(super) fn delay(&self) -> Duration {
        self.delay
    }

    fn changed(&mut self, hashes: Vec<Option<Digest32>>) -> bool {
        if self.previous.as_ref() == Some(&hashes) {
            self.delay = (self.delay * 2).min(Duration::from_secs(2));
            false
        } else {
            self.previous = Some(hashes);
            self.delay = Duration::from_millis(200);
            true
        }
    }

    pub(super) fn read(
        &mut self,
        root: &HardenedStateRoot,
        draft: &GovernedRolloverDraft,
        owner: &VaultPrincipalIdentity,
        now: u64,
    ) -> Result<Option<Vec<RegistrationProofV1>>, CliError> {
        let mut files = Vec::new();
        for challenge in draft.challenges() {
            let name = format!(
                "{}.proof.json",
                hex(challenge.candidate_descriptor.principal_id.as_bytes())
            );
            files.push(
                match root.read_private_file(Path::new(&name), MAX_REGISTRATION_FILE_BYTES) {
                    Ok(bytes) => Some(bytes),
                    Err(error) if error.kind() == FilesystemErrorKind::NotFound => None,
                    Err(error) => return Err(map_filesystem_error(error)),
                },
            );
        }
        // Permanent rejection stays cached. A future-dated proof gets one
        // retry when its time bounds can become valid; completion checks again.
        let changed = self.changed(
            files
                .iter()
                .map(|bytes| bytes.as_deref().map(sha256_digest))
                .collect(),
        );
        if !changed && !self.retry_at_ms.is_some_and(|time| now >= time) {
            return Ok(None);
        }
        self.retry_at_ms = None;
        let mut proofs = Vec::new();
        let mut failure = None;
        for (challenge, bytes) in draft.challenges().iter().zip(files) {
            let candidate = challenge.candidate_descriptor.principal_id;
            let result = bytes
                .as_deref()
                .ok_or_else(registration_required)
                .and_then(|bytes| {
                    let proof = RegistrationProofV1::parse(bytes).map_err(|_| malformed_proof())?;
                    let valid_from = proof.created_at_ms.max(challenge.issued_at_ms);
                    if valid_from > now && valid_from <= challenge.expires_at_ms {
                        self.retry_at_ms = Some(
                            self.retry_at_ms
                                .map_or(valid_from, |prior| prior.min(valid_from)),
                        );
                    }
                    draft
                        .verify_registration_proof(owner, candidate, &proof, now)
                        .map_err(|_| invalid_proof())?;
                    Ok(proof)
                });
            match result {
                Ok(proof) => proofs.push(proof),
                Err(error) => {
                    // IDs come from the owner-authenticated challenge, never
                    // malformed input. All other diagnostic text is static.
                    if bytes.is_some() {
                        writeln!(
                            std::io::stderr().lock(),
                            "Rollover candidate {}: {}",
                            hex(candidate.as_bytes()),
                            error
                        )
                        .map_err(|_| filesystem_error())?;
                    }
                    // Report an invalid response in preference to a missing one.
                    if failure.is_none() || bytes.is_some() {
                        failure = Some(error);
                    }
                }
            }
        }
        if let Some(error) = failure {
            self.error = error;
            Ok(None)
        } else {
            Ok(Some(proofs))
        }
    }
}

fn malformed_proof() -> CliError {
    CliError::new(
        CliErrorKind::Conflict,
        "rollover-registration-proof-malformed",
        "a candidate proof file is malformed; replace that file in --registration-dir while preparation is running; after timeout use fresh preparation",
    )
}

fn invalid_proof() -> CliError {
    CliError::new(
        CliErrorKind::Conflict,
        "rollover-registration-proof-invalid",
        "a candidate proof does not authenticate this draft, role or challenge at the current time; replace that proof while preparation is running; after timeout use fresh preparation",
    )
}

#[cfg(test)]
pub(in crate::cli) fn exercise_polling_repair(
    draft: &GovernedRolloverDraft,
    owner: &VaultPrincipalIdentity,
    fresh: &RegistrationProofV1,
) -> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::PermissionsExt as _;
    let temporary = tempfile::tempdir()?;
    std::fs::set_permissions(temporary.path(), std::fs::Permissions::from_mode(0o700))?;
    let root = HardenedStateRoot::open_existing(temporary.path(), &[])?;
    let path = temporary.path().join(format!(
        "{}.proof.json",
        hex(fresh.candidate_principal_id.as_bytes())
    ));
    let mut poll = ProofPoll::default();
    assert!(poll.read(&root, draft, owner, 9)?.is_none());
    assert_eq!(poll.error().code(), "rollover-registration-required");
    std::fs::write(&path, b"{")?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    assert!(poll.read(&root, draft, owner, 9)?.is_none());
    assert_eq!(poll.error().code(), "rollover-registration-proof-malformed");
    let mut wrong = fresh.clone();
    wrong.candidate_signature = jury_protocol::vault_v1::Signature64::new([0; 64]);
    std::fs::write(&path, wrong.to_json_bytes()?)?;
    assert!(poll.read(&root, draft, owner, 9)?.is_none());
    assert_eq!(poll.error().code(), "rollover-registration-proof-invalid");
    for _ in 0..5 {
        assert!(poll.read(&root, draft, owner, 9)?.is_none());
    }
    assert_eq!(poll.delay(), Duration::from_secs(2));
    std::fs::write(&path, fresh.to_json_bytes()?)?;
    let accepted = poll
        .read(&root, draft, owner, 9)?
        .ok_or("corrected proof not accepted")?;
    assert_eq!(accepted, vec![fresh.clone()]);
    draft.verify_registration_proofs(owner, &accepted, 9)?;
    let mut skewed = ProofPoll::default();
    let before = fresh
        .created_at_ms
        .checked_sub(1)
        .ok_or("invalid fixture time")?;
    assert!(skewed.read(&root, draft, owner, before)?.is_none());
    assert!(skewed.read(&root, draft, owner, before)?.is_none());
    // Keep exactly the same signed file: only the owner's clock advances.
    let accepted = skewed
        .read(&root, draft, owner, fresh.created_at_ms)?
        .ok_or("unchanged proof was not retried when its timestamp became valid")?;
    assert_eq!(accepted, vec![fresh.clone()]);
    draft.verify_registration_proofs(owner, &accepted, fresh.created_at_ms)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unchanged_rejected_proof_bytes_do_not_retry_verification() {
        let mut poll = ProofPoll::default();
        let bad = vec![Some(sha256_digest(b"ExampleInvalidProof")), None];
        assert!(poll.changed(bad.clone()));
        poll.error = invalid_proof();
        for _ in 0..1000 {
            assert!(!poll.changed(bad.clone()));
        }
        assert_eq!(poll.delay(), Duration::from_secs(2));
        assert_eq!(poll.error().code(), "rollover-registration-proof-invalid");
        assert!(poll.changed(vec![Some(sha256_digest(b"ExampleCorrectedProof")), None]));
        assert_eq!(poll.delay(), Duration::from_millis(200));
        assert!(poll.changed(vec![None, None]));
    }
}
