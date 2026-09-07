use super::*;
use jury_core::access_provider::ScopedRevisionAccess;
use jury_protocol::witness_v1::OperationBytes;

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct AccessPlan {
    version: u16,
    total_wait_seconds: u64,
    entries: Vec<Entry>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    item_id: String,
    content_role: ContentRole,
    checkpoint: PathBuf,
    request_out: PathBuf,
    receipt: PathBuf,
    #[serde(default)]
    approvals: Vec<PathBuf>,
    witnesses: Vec<String>,
    #[serde(default)]
    allow_insecure_loopback: bool,
    wait_seconds: u64,
}

struct PreparedEntry {
    entry: Entry,
    checkpoint: VaultPolicyCheckpointV1,
    endpoints: Vec<WitnessEndpointClient>,
    receipt: PreparedWitnessReceiptDestination,
}

pub(super) struct RolloverAccess<'a> {
    context: &'a VaultPrincipalContext,
    direct: BTreeSet<ItemId>,
    entries: BTreeMap<(ItemId, u8), PreparedEntry>,
    deadline: std::time::Instant,
    destination: OperationBytes,
    protection: ProtectionPolicy,
    error: Option<CliError>,
}

impl<'a> RolloverAccess<'a> {
    pub(super) fn new(
        context: &'a VaultPrincipalContext,
        arguments: &VaultRolloverArgs,
        protection: ProtectionPolicy,
    ) -> Result<Self, CliError> {
        let mut direct = BTreeSet::new();
        let mut required = BTreeSet::new();
        for (id, item) in context.policy.items() {
            if item.witnessed_state.is_none()
                || (arguments.direct_source
                    && item
                        .direct_slots
                        .iter()
                        .any(|slot| slot.recipient_principal_id == context.identity.principal_id()))
            {
                direct.insert(*id);
            } else {
                required.insert((*id, ContentRole::Descriptor.tag()));
                required.insert((*id, ContentRole::Body.tag()));
            }
        }
        let plan = match &arguments.administrative_access {
            Some(path) => serde_json::from_slice::<AccessPlan>(
                &read_public_file(path, 1024 * 1024).map_err(map_filesystem_error)?,
            )
            .map_err(|_| invalid_plan())?,
            None if required.is_empty() => AccessPlan {
                version: 1,
                total_wait_seconds: 300,
                entries: Vec::new(),
            },
            None => return Err(invalid_plan()),
        };
        if plan.version != 1
            || !(1..=86400).contains(&plan.total_wait_seconds)
            || plan.entries.len() != required.len()
        {
            return Err(invalid_plan());
        }
        let mut entries = BTreeMap::new();
        let mut outputs = BTreeSet::new();
        for entry in plan.entries {
            let key = (parse_item_id(&entry.item_id)?, entry.content_role.tag());
            if !required.remove(&key) || entry.wait_seconds > 900 || entry.witnesses.is_empty() {
                return Err(invalid_plan());
            }
            for path in [&entry.request_out, &entry.receipt] {
                if !outputs.insert(path.clone()) {
                    return Err(invalid_plan());
                }
                for boundary in context
                    .home
                    .repository()
                    .map(RepositoryLocation::worktree_path)
                    .into_iter()
                    .chain(context.home.detached_path())
                    .chain([
                        arguments.out.as_path(),
                        arguments.backup_out.as_path(),
                        arguments.transfer_out.as_path(),
                    ])
                {
                    validate_path_separation(&[boundary, path]).map_err(|_| invalid_plan())?;
                }
            }
            let receipt = prepare_witness_receipt_destination(&entry.receipt)?;
            prepare_witness_receipt_destination(&entry.request_out)?;
            let checkpoint = read_checkpoint(&entry.checkpoint)?;
            let endpoints = entry
                .witnesses
                .iter()
                .map(|spec| WitnessEndpointClient::parse(spec, entry.allow_insecure_loopback))
                .collect::<Result<Vec<_>, _>>()?;
            entries.insert(
                key,
                PreparedEntry {
                    entry,
                    checkpoint,
                    endpoints,
                    receipt,
                },
            );
        }
        if !required.is_empty() {
            return Err(invalid_plan());
        }
        let destination = OperationBytes::new(
            arguments
                .out
                .join("vault.json")
                .as_os_str()
                .as_encoded_bytes()
                .to_vec(),
        )
        .map_err(|_| invalid_plan())?;
        Ok(Self {
            context,
            direct,
            entries,
            deadline: std::time::Instant::now()
                + std::time::Duration::from_secs(plan.total_wait_seconds),
            destination,
            protection,
            error: None,
        })
    }

    pub(super) fn finish(&mut self) -> Result<(), CliError> {
        if let Some(error) = self.error.take() {
            return Err(error);
        }
        if !self.entries.is_empty() {
            return Err(invalid_plan());
        }
        Ok(())
    }

    pub(super) fn preflight_requests(&self) -> Result<(), CliError> {
        for ((item_id, _), input) in &self.entries {
            let prepared = WitnessRequestCreator::new(self.protection)
                .create_recovery_reseal(
                    WitnessRequestContext {
                        policy: &self.context.policy,
                        checkpoint: &input.checkpoint,
                        requester: &self.context.identity,
                        review_labels: review_labels_for_item(
                            self.context,
                            item_id,
                            input.entry.content_role,
                        )?,
                        now_ms: timestamp_ms()?,
                    },
                    *item_id,
                    input.entry.content_role,
                    &self.destination,
                )
                .map_err(|_| invalid_plan())?;
            validate_endpoint_set(&input.endpoints, &prepared.request)?;
        }
        Ok(())
    }

    fn collect(
        &mut self,
        item_id: ItemId,
        role: ContentRole,
    ) -> Result<
        (
            CollectedWitnessAuthorization,
            PreparedWitnessReceiptDestination,
        ),
        CliError,
    > {
        let input = self
            .entries
            .remove(&(item_id, role.tag()))
            .ok_or_else(invalid_plan)?;
        let prepared = WitnessRequestCreator::new(self.protection)
            .create_recovery_reseal(
                WitnessRequestContext {
                    policy: &self.context.policy,
                    checkpoint: &input.checkpoint,
                    requester: &self.context.identity,
                    review_labels: review_labels_for_item(self.context, &item_id, role)?,
                    now_ms: timestamp_ms()?,
                },
                item_id,
                role,
                &self.destination,
            )
            .map_err(|_| invalid_plan())?;
        let authorization = collect_prepared_witness_authorization(
            self.context,
            prepared,
            &input.endpoints,
            &WitnessActionFiles {
                checkpoint: &input.entry.checkpoint,
                request_out: &input.entry.request_out,
                approvals: &input.entry.approvals,
                wait_seconds: input.entry.wait_seconds,
            },
            input.checkpoint,
            Some(self.deadline),
        )?;
        Ok((authorization, input.receipt))
    }
}

impl ItemAccessProvider for RolloverAccess<'_> {
    fn access_revision<T, E>(
        &mut self,
        request: RevisionAccessRequest<'_>,
        consumer: impl FnOnce(&mut ScopedRevisionAccess<'_>) -> Result<T, E>,
    ) -> Result<ItemAccessOutcome<T>, ItemAccessError<E>> {
        if self.error.is_some() {
            return Ok(ItemAccessOutcome::Witnessed(
                WitnessedAccessStatus::Unavailable,
            ));
        }
        if self.direct.contains(&request.target.item_id) {
            return DirectItemAccessProvider::new(&self.context.identity)
                .access_revision(request, consumer);
        }
        let (mut authorization, receipt) =
            match self.collect(request.target.item_id, request.target.content_role) {
                Ok(value) => value,
                Err(error) => {
                    self.error = Some(error);
                    return Ok(ItemAccessOutcome::Witnessed(
                        WitnessedAccessStatus::Unavailable,
                    ));
                }
            };
        let now = match timestamp_ms() {
            Ok(value) => value,
            Err(error) => {
                self.error = Some(error);
                return Ok(ItemAccessOutcome::Witnessed(
                    WitnessedAccessStatus::Unavailable,
                ));
            }
        };
        let mut provider = WitnessedItemAccessProvider::new(
            &authorization.checkpoint,
            &authorization.prepared.request,
            &authorization.prepared.manifest,
            &authorization.responses,
            &authorization.prepared.session,
            now,
        );
        let outcome = provider.access_revision(request, consumer);
        let counted = provider.counted_responses();
        match &outcome {
            Ok(ItemAccessOutcome::Witnessed(status)) => {
                self.error = Some(map_witnessed_status(
                    authorization
                        .failure_status
                        .map_or(*status, |failure| status.merge(failure)),
                ));
            }
            Err(ItemAccessError::Provider(error)) => {
                self.error = Some(map_witness_provider(error.kind()));
            }
            Ok(ItemAccessOutcome::Complete {
                authority: AccessCompletion::Direct,
                ..
            }) => {
                self.error = Some(invalid_witness_response());
            }
            _ => {}
        }
        if matches!(
            &outcome,
            Ok(ItemAccessOutcome::Complete {
                authority: AccessCompletion::WitnessedApproved,
                ..
            })
        ) {
            authorization.responses = counted;
            // The constructor consumes any returned plaintext immediately into
            // protected staging. A receipt failure is retained and forbids draft
            // completion; no plaintext-bearing generic return value is discarded.
            if let Err(error) = publish_witness_receipt(self.context, &authorization, receipt) {
                self.error = Some(error);
            }
        }
        outcome
    }
}

fn invalid_plan() -> CliError {
    CliError::new(
        CliErrorKind::AccessDenied,
        "invalid-rollover-administrative-access",
        "the source policy must permit whole-item Recovery; provide one descriptor/body authorization entry for each governed item without an explicitly selected direct slot, unique absent request/receipt paths, and bounded waits",
    )
}
