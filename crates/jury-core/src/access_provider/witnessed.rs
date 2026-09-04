/// Witnessed revision access backed by validated, request-session-bound responses.
///
/// Encrypted contributions are opened only inside this provider. Neither their
/// plaintext shares nor the reconstructed revision secret have an export API.
pub struct WitnessedItemAccessProvider<'a> {
    checkpoint: &'a VaultPolicyCheckpointV1,
    signed_request: &'a WitnessRequestV1,
    manifest: &'a ActionManifestV1,
    responses: &'a [WitnessResponseV1],
    session: &'a RequestSessionIdentity,
    now_ms: u64,
    counted_response_indices: Vec<usize>,
}
impl<'a> WitnessedItemAccessProvider<'a> {
    #[must_use]
    pub fn new(
        checkpoint: &'a VaultPolicyCheckpointV1,
        signed_request: &'a WitnessRequestV1,
        manifest: &'a ActionManifestV1,
        responses: &'a [WitnessResponseV1],
        session: &'a RequestSessionIdentity,
        now_ms: u64,
    ) -> Self {
        Self {
            checkpoint,
            signed_request,
            manifest,
            responses,
            session,
            now_ms,
            counted_response_indices: Vec::new(),
        }
    }

    /// Returns only the independently validated responses whose opened shares
    /// contributed to the successful threshold reconstruction.
    #[must_use]
    pub fn counted_responses(&self) -> Vec<WitnessResponseV1> {
        self.counted_response_indices
            .iter()
            .filter_map(|index| self.responses.get(*index).cloned())
            .collect()
    }
}

impl ItemAccessProvider for WitnessedItemAccessProvider<'_> {
    fn access_revision<T, E>(
        &mut self,
        request: RevisionAccessRequest<'_>,
        consumer: impl FnOnce(&mut ScopedRevisionAccess<'_>) -> Result<T, E>,
    ) -> Result<ItemAccessOutcome<T>, ItemAccessError<E>> {
        self.counted_response_indices.clear();
        if request.cancellation.is_cancelled() {
            return Ok(ItemAccessOutcome::Witnessed(
                WitnessedAccessStatus::Cancelled,
            ));
        }
        let validated = validate_public_request(
            request.policy,
            self.checkpoint,
            self.signed_request,
            self.manifest,
        )
        .map_err(|error| {
            ItemAccessError::Provider(AccessProviderError::new(match error.reason() {
                WitnessReasonV1::StalePolicy
                | WitnessReasonV1::WitnessBehind
                | WitnessReasonV1::CheckpointFork => AccessProviderErrorKind::StalePolicy,
                _ => AccessProviderErrorKind::InvalidRequest,
            }))
        })?;
        preflight_witnessed(&request, self.signed_request).map_err(ItemAccessError::Provider)?;
        if self.signed_request.issued_at_ms > self.now_ms.saturating_add(ACCEPTED_CLOCK_SKEW_MS)
            || self
                .signed_request
                .not_before_ms
                .is_some_and(|time| time > self.now_ms.saturating_add(ACCEPTED_CLOCK_SKEW_MS))
        {
            return Ok(ItemAccessOutcome::Witnessed(WitnessedAccessStatus::Stale));
        }
        if self.now_ms >= self.signed_request.expires_at_ms {
            return Ok(ItemAccessOutcome::Witnessed(WitnessedAccessStatus::Expired));
        }
        if self.session.public_key() != &self.signed_request.request_session_public_key
            || self.session.fingerprint() != &self.signed_request.request_session_key_fingerprint
        {
            return Err(ItemAccessError::Provider(AccessProviderError::new(
                AccessProviderErrorKind::InvalidRequest,
            )));
        }

        let mut approved = BTreeMap::new();
        let mut approved_witnesses = BTreeSet::new();
        let mut terminal_status = None;
        for (response_index, response) in self.responses.iter().enumerate() {
            if validate_witness_response(
                request.policy,
                self.checkpoint,
                self.signed_request,
                self.manifest,
                response,
            )
            .is_err()
            {
                terminal_status = merge_witness_status(
                    terminal_status,
                    WitnessedAccessStatus::Unavailable,
                );
                continue;
            }
            if response.decision.decision == WitnessDecisionKindV1::Approve {
                let Some(share_index) = response.decision.share_index else {
                    terminal_status = merge_witness_status(
                        terminal_status,
                        WitnessedAccessStatus::Unavailable,
                    );
                    continue;
                };
                if !approved_witnesses.insert(response.decision.witness_id)
                    || approved.contains_key(&share_index)
                {
                    terminal_status =
                        merge_witness_status(terminal_status, WitnessedAccessStatus::Replay);
                    continue;
                }
                approved.insert(share_index, (response_index, response));
            } else {
                terminal_status = merge_witness_status(
                    terminal_status,
                    witnessed_status(response.decision.reason),
                );
            }
        }
        let threshold = usize::from(validated.rule.witness_threshold);
        if approved.len() < threshold {
            return Ok(ItemAccessOutcome::Witnessed(
                terminal_status.unwrap_or(WitnessedAccessStatus::InsufficientQuorum),
            ));
        }

        let approved = approved.into_values().collect::<Vec<_>>();
        let Some((secret, counted_response_indices)) = reconstruct_revision_secret(
            self.session,
            self.checkpoint,
            self.signed_request,
            self.manifest,
            &approved,
            threshold,
        )
        .map_err(ItemAccessError::Provider)?
        else {
            return Ok(ItemAccessOutcome::Witnessed(
                terminal_status
                    .unwrap_or(WitnessedAccessStatus::Unavailable)
                    .merge(WitnessedAccessStatus::Unavailable),
            ));
        };
        self.counted_response_indices = counted_response_indices;
        match request.target.content_role {
            ContentRole::Descriptor => {
                open_descriptor(request.envelope, &secret).map_err(|_| {
                    ItemAccessError::Provider(AccessProviderError::new(
                        AccessProviderErrorKind::InvalidSlot,
                    ))
                })?;
            }
            ContentRole::Body => {
                open_body(request.envelope, &secret).map_err(|_| {
                    ItemAccessError::Provider(AccessProviderError::new(
                        AccessProviderErrorKind::InvalidSlot,
                    ))
                })?;
            }
        }
        if request.cancellation.is_cancelled() {
            return Ok(ItemAccessOutcome::Witnessed(
                WitnessedAccessStatus::Cancelled,
            ));
        }
        let mut scoped = ScopedRevisionAccess {
            role: request.target.content_role,
            envelope: request.envelope,
            secret: &secret,
        };
        let consumed = catch_unwind(AssertUnwindSafe(|| consumer(&mut scoped))).map_err(|_| {
            ItemAccessError::Provider(AccessProviderError::new(
                AccessProviderErrorKind::ConsumerPanicked,
            ))
        })?;
        let value = consumed.map_err(ItemAccessError::Consumer)?;
        Ok(ItemAccessOutcome::Complete {
            authority: AccessCompletion::WitnessedApproved,
            value,
        })
    }
}

fn preflight_witnessed(
    request: &RevisionAccessRequest<'_>,
    signed: &WitnessRequestV1,
) -> Result<(), AccessProviderError> {
    let target = &request.target;
    if target.suite != SUITE
        || target.vault_id != request.policy.vault_id()
        || target.item_id != request.envelope.item_id
        || target.principal_id != signed.requester_principal_id
        || target.item_id != signed.item_id
        || target.key_epoch != signed.key_epoch
        || target.content_role != signed.content_role
        || target.revision != signed.revision
        || target.revision_seal_id != signed.revision_seal_id
        || target.policy_sequence != signed.vault_policy_sequence
        || target.policy_revision_hash != *request.policy.terminal_revision_hash()
        || target.access_role != signed.requested_access_role
        || target.item_access_mode != signed.item_access_mode
        || request.capability != operation_capability(signed.operation)
    {
        return Err(AccessProviderError::new(
            AccessProviderErrorKind::InvalidRequest,
        ));
    }
    verify_item_ancestry(request.envelope, |principal_id| {
        request.policy.verification_key(&principal_id)
    })
    .map_err(|_| AccessProviderError::new(AccessProviderErrorKind::InvalidAncestry))?;
    let item = request
        .policy
        .item(&target.item_id)
        .ok_or_else(|| AccessProviderError::new(AccessProviderErrorKind::InvalidRequest))?;
    let current_hash = request
        .envelope
        .current_revision
        .recomputed_hash()
        .map_err(|_| AccessProviderError::new(AccessProviderErrorKind::InvalidAncestry))?;
    if item.key_epoch != target.key_epoch
        || item.descriptor != request.envelope.descriptor
        || item.current_item_revision_hash != current_hash
        || item.access_mode() != Some(target.item_access_mode)
    {
        return Err(AccessProviderError::new(
            AccessProviderErrorKind::InvalidAncestry,
        ));
    }
    let explanation =
        request
            .policy
            .access(&target.item_id, &target.principal_id, request.capability);
    if !explanation.allowed
        || explanation.effective_role != Some(target.access_role)
        || explanation.reason != AccessReason::Allowed
        || !matches!(explanation.path, AccessPath::Witnessed | AccessPath::Mixed)
    {
        return Err(AccessProviderError::new(
            AccessProviderErrorKind::Unauthorized,
        ));
    }
    Ok(())
}

fn reconstruct_revision_secret(
    session: &RequestSessionIdentity,
    checkpoint: &VaultPolicyCheckpointV1,
    request: &WitnessRequestV1,
    manifest: &ActionManifestV1,
    responses: &[(usize, &WitnessResponseV1)],
    threshold: usize,
) -> Result<Option<(ProtectedRevisionSecret, Vec<usize>)>, AccessProviderError> {
    let request_digest = request
        .digest()
        .map_err(|_| AccessProviderError::new(AccessProviderErrorKind::InvalidRequest))?;
    let manifest_digest = manifest
        .digest()
        .map_err(|_| AccessProviderError::new(AccessProviderErrorKind::InvalidRequest))?;
    let checkpoint_digest = checkpoint
        .digest()
        .map_err(|_| AccessProviderError::new(AccessProviderErrorKind::InvalidRequest))?;
    let mut shares = Zeroizing::new(Vec::with_capacity(responses.len()));
    let mut counted_response_indices = Vec::with_capacity(threshold);
    for (response_index, response) in responses {
        let Some(contribution) = response
            .contribution
            .as_ref()
        else {
            continue;
        };
        let mut info = jce("jury-witness-v1/contribution/info");
        info.extend_from_slice(request_digest.as_bytes());
        info.extend_from_slice(manifest_digest.as_bytes());
        info.extend_from_slice(contribution.response_id.as_bytes());
        info.extend_from_slice(response.decision.witness_id.as_bytes());
        info.extend_from_slice(request.witness_policy_digest.as_bytes());
        info.extend_from_slice(checkpoint_digest.as_bytes());
        info.extend_from_slice(contribution.share_commitment.as_bytes());
        info.push(contribution.share_index);
        let mut aad = jce("jury-witness-v1/contribution/aad");
        aad.extend_from_slice(contribution.capsule_set_digest.as_bytes());
        aad.extend_from_slice(contribution.capsule_context_digest.as_bytes());
        aad.extend_from_slice(request.request_session_key_fingerprint.as_bytes());
        aad.extend_from_slice(&request.expires_at_ms.to_be_bytes());
        let Ok(share) = crypto::open_hpke(
            &session.private_key,
            &contribution.encapsulation,
            contribution.ciphertext.as_bytes(),
            &info,
            &aad,
            33,
        ) else {
            continue;
        };
        let Ok(valid) = share.expose(|bytes| {
                let mut digest = Sha256::new();
                digest.update(jce("jury-witness-v1/share/commitment"));
                digest.update(contribution.capsule_context_digest.as_bytes());
                digest.update(bytes);
                bytes.first().copied() == Some(contribution.share_index)
                    && bool::from(
                        digest
                            .finalize()
                            .as_slice()
                            .ct_eq(contribution.share_commitment.as_bytes()),
                    )
            })
        else {
            continue;
        };
        if !valid {
            continue;
        }
        let Ok(share_bytes) = share.expose(<[u8]>::to_vec) else {
            continue;
        };
        shares.push(share_bytes);
        counted_response_indices.push(*response_index);
        if shares.len() == threshold {
            break;
        }
    }
    if shares.len() < threshold {
        return Ok(None);
    }
    let reconstructed = Zeroizing::new(
        Gf256::combine_bytes(shares.as_slice())
            .map_err(|_| AccessProviderError::new(AccessProviderErrorKind::ProviderFailure))?,
    );
    if reconstructed.len() != 32 {
        return Err(AccessProviderError::new(
            AccessProviderErrorKind::ProviderFailure,
        ));
    }
    let bytes = ProtectedMemory::initialize(32, session.protection_policy(), |output| {
        output.copy_from_slice(&reconstructed);
        Ok::<usize, ()>(output.len())
    })
    .map_err(|_| AccessProviderError::new(AccessProviderErrorKind::ProviderFailure))?;
    Ok(Some((
        ProtectedRevisionSecret { bytes },
        counted_response_indices,
    )))
}

const fn witnessed_status(reason: WitnessReasonV1) -> WitnessedAccessStatus {
    match reason {
        WitnessReasonV1::MissingApproval | WitnessReasonV1::NotYetValid => {
            WitnessedAccessStatus::Pending
        }
        WitnessReasonV1::ApprovalDenied
        | WitnessReasonV1::ApprovalConflict
        | WitnessReasonV1::PolicyDenied
        | WitnessReasonV1::WrongOperation
        | WitnessReasonV1::WorkloadExceeded
        | WitnessReasonV1::DirectDowngrade => WitnessedAccessStatus::Denied,
        WitnessReasonV1::Expired => WitnessedAccessStatus::Expired,
        WitnessReasonV1::StalePolicy
        | WitnessReasonV1::WitnessBehind
        | WitnessReasonV1::CheckpointFork
        | WitnessReasonV1::WrongScope => WitnessedAccessStatus::Stale,
        WitnessReasonV1::ReplayConflict | WitnessReasonV1::CancellationTooLate => {
            WitnessedAccessStatus::Replay
        }
        WitnessReasonV1::Cancelled => WitnessedAccessStatus::Cancelled,
        WitnessReasonV1::InsufficientQuorum => WitnessedAccessStatus::InsufficientQuorum,
        WitnessReasonV1::Unavailable
        | WitnessReasonV1::UnsafeClock
        | WitnessReasonV1::AnchorConflict
        | WitnessReasonV1::CapacityExhausted
        | WitnessReasonV1::RestoredStateUnsafe
        | WitnessReasonV1::InternalFailure
        | WitnessReasonV1::Invalid
        | WitnessReasonV1::UnsupportedVersion
        | WitnessReasonV1::InvalidSignature
        | WitnessReasonV1::InvalidContribution
        | WitnessReasonV1::None => WitnessedAccessStatus::Unavailable,
    }
}

const fn status_priority(status: WitnessedAccessStatus) -> u8 {
    match status {
        WitnessedAccessStatus::Cancelled => 8,
        WitnessedAccessStatus::Expired => 7,
        WitnessedAccessStatus::Stale => 6,
        WitnessedAccessStatus::Replay => 5,
        WitnessedAccessStatus::Denied => 4,
        WitnessedAccessStatus::Unavailable => 3,
        WitnessedAccessStatus::InsufficientQuorum => 2,
        WitnessedAccessStatus::Pending => 1,
    }
}

fn merge_witness_status(
    current: Option<WitnessedAccessStatus>,
    next: WitnessedAccessStatus,
) -> Option<WitnessedAccessStatus> {
    Some(current.map_or(next, |current| current.merge(next)))
}
