use super::*;
use jury_core::witness_operations::{CheckpointPropagationPhase, verify_checkpoint_propagation};
use jury_protocol::witness_v1::RegistrationBytes;

pub(super) struct DestinationRegistration {
    material: ReceiptPolicyMaterialV1,
    checkpoint: Option<VaultPolicyCheckpointV1>,
    endpoints: Vec<(WitnessEndpointClient, RegistrationBytes)>,
}

impl DestinationRegistration {
    pub(super) fn checkpoint(&self) -> Option<&VaultPolicyCheckpointV1> {
        self.checkpoint.as_ref()
    }

    pub(super) fn restore(
        vault: &VaultFileV1,
        catalog: &TransferPublicCatalogV1,
        arguments: &VaultRolloverArgs,
        checkpoint: Option<VaultPolicyCheckpointV1>,
    ) -> Result<Self, CliError> {
        let material = ReceiptPolicyMaterialV1 {
            schema: 1,
            journal: vault.policy.clone(),
            witness_policies: catalog.witness_policies.clone(),
        };
        let policy = material.replay().map_err(|_| invalid_registration())?;
        material.encode().map_err(|_| invalid_registration())?;
        let mut endpoints = Vec::new();
        for endpoint in preflight_endpoints(&policy, arguments)? {
            let proof = catalog
                .registration_proofs
                .iter()
                .find(|proof| proof.candidate_principal_id == endpoint.witness_id)
                .ok_or_else(invalid_registration)?;
            endpoints.push((
                endpoint,
                RegistrationBytes::new(proof.to_json_bytes().map_err(|_| invalid_registration())?)
                    .map_err(|_| invalid_registration())?,
            ));
        }
        if endpoints.is_empty() != checkpoint.is_none() {
            return Err(invalid_registration());
        }
        if let Some(checkpoint) = &checkpoint {
            verify_checkpoint_propagation(&policy, checkpoint, &[])
                .map_err(|_| invalid_registration())?;
            if checkpoint.predecessor_checkpoint_digest != Digest32::new([0; 32])
                || checkpoint.issuer_owner_id != vault.policy.genesis.owner.principal_id
            {
                return Err(invalid_registration());
            }
        }
        Ok(Self {
            material,
            checkpoint,
            endpoints,
        })
    }
    pub(super) fn prepare(
        vault: &VaultFileV1,
        catalog: &TransferPublicCatalogV1,
        owner: &jury_core::identity::VaultPrincipalIdentity,
        arguments: &VaultRolloverArgs,
        now_ms: u64,
    ) -> Result<Self, CliError> {
        let material = ReceiptPolicyMaterialV1 {
            schema: 1,
            journal: vault.policy.clone(),
            witness_policies: catalog.witness_policies.clone(),
        };
        let policy = material.replay().map_err(|_| invalid_vault())?;
        material.encode().map_err(|_| invalid_registration())?;
        let mut endpoints = Vec::new();
        for endpoint in preflight_endpoints(&policy, arguments)? {
            let proof = catalog
                .registration_proofs
                .iter()
                .find(|proof| proof.candidate_principal_id == endpoint.witness_id)
                .ok_or_else(invalid_registration)?;
            let registration =
                RegistrationBytes::new(proof.to_json_bytes().map_err(|_| invalid_registration())?)
                    .map_err(|_| invalid_registration())?;
            endpoints.push((endpoint, registration));
        }
        let checkpoint = if endpoints.is_empty() {
            None
        } else {
            Some(
                VaultPolicyCheckpointCreator::create(
                    &policy,
                    Digest32::new([0; 32]),
                    owner,
                    now_ms,
                )
                .map_err(|_| invalid_registration())?,
            )
        };
        Ok(Self {
            material,
            checkpoint,
            endpoints,
        })
    }

    pub(super) fn register_all(
        &self,
        root: &HardenedStateRoot,
        protection: ProtectionPolicy,
        vault_already_published: bool,
    ) -> Result<(), CliError> {
        let saved_complete = self.verify_saved(root)?;
        if vault_already_published && saved_complete {
            return Ok(());
        }
        let Some(checkpoint) = &self.checkpoint else {
            return Ok(());
        };
        let policy = self.material.replay().map_err(|_| invalid_registration())?;
        let mut acknowledgements = Vec::new();
        for (endpoint, registration) in &self.endpoints {
            let acknowledgement = endpoint
                .register_vault(&self.material, registration, checkpoint)
                .map_err(|_| incomplete_rollover())?;
            let path = format!(
                "witness-{}-registration.json",
                hex(endpoint.witness_id.as_bytes())
            );
            self.publish_acknowledgement(root, &path, &acknowledgement, protection)?;
            acknowledgements.push(acknowledgement);
        }
        let status = verify_checkpoint_propagation(&policy, checkpoint, &acknowledgements)
            .map_err(|_| invalid_registration())?;
        if status.phase != CheckpointPropagationPhase::DurablyAccepted {
            return Err(incomplete_rollover());
        }
        publish_private(
            root,
            "witness.checkpoint.json",
            &serde_json::to_vec(checkpoint).map_err(|_| invalid_registration())?,
            protection,
        )?;
        Ok(())
    }

    /// Retained signed acknowledgements prove the observed registration result,
    /// not continuing global freshness. Cleanup retries need no new remote write.
    pub(super) fn verify_saved(&self, root: &HardenedStateRoot) -> Result<bool, CliError> {
        let Some(checkpoint) = &self.checkpoint else {
            return Ok(true);
        };
        let checkpoint_bytes =
            match root.read_private_file(Path::new("witness.checkpoint.json"), 64 * 1024) {
                Ok(bytes) => Some(bytes),
                Err(error) if error.kind() == FilesystemErrorKind::NotFound => None,
                Err(error) => return Err(map_filesystem_error(error)),
            };
        let expected_checkpoint =
            serde_json::to_vec(checkpoint).map_err(|_| invalid_registration())?;
        if checkpoint_bytes
            .as_ref()
            .is_some_and(|bytes| bytes != &expected_checkpoint)
        {
            return Err(invalid_registration());
        }
        let mut acknowledgements = Vec::new();
        for (endpoint, _) in &self.endpoints {
            let name = format!(
                "witness-{}-registration.json",
                hex(endpoint.witness_id.as_bytes())
            );
            let bytes = match root.read_private_file(Path::new(&name), 64 * 1024) {
                Ok(bytes) => bytes,
                Err(error) if error.kind() == FilesystemErrorKind::NotFound => continue,
                Err(error) => return Err(map_filesystem_error(error)),
            };
            let acknowledgement: jury_protocol::witness_v1::WitnessCheckpointAcknowledgementV1 =
                serde_json::from_slice(&bytes).map_err(|_| invalid_registration())?;
            if acknowledgement.witness_id != endpoint.witness_id {
                return Err(invalid_registration());
            }
            acknowledgements.push(acknowledgement);
        }
        let status = verify_checkpoint_propagation(
            &self.material.replay().map_err(|_| invalid_registration())?,
            checkpoint,
            &acknowledgements,
        )
        .map_err(|_| invalid_registration())?;
        Ok(checkpoint_bytes.is_some()
            && status.phase == CheckpointPropagationPhase::DurablyAccepted)
    }

    fn publish_acknowledgement(
        &self,
        root: &HardenedStateRoot,
        path: &str,
        acknowledgement: &jury_protocol::witness_v1::WitnessCheckpointAcknowledgementV1,
        protection: ProtectionPolicy,
    ) -> Result<(), CliError> {
        let bytes = serde_json::to_vec(acknowledgement).map_err(|_| invalid_registration())?;
        match root.read_private_file(Path::new(path), 64 * 1024) {
            Ok(prior) if prior == bytes => Ok(()),
            Ok(prior) => {
                let prior: jury_protocol::witness_v1::WitnessCheckpointAcknowledgementV1 =
                    serde_json::from_slice(&prior).map_err(|_| invalid_registration())?;
                if prior.witness_id != acknowledgement.witness_id {
                    return Err(invalid_registration());
                }
                verify_checkpoint_propagation(
                    &self.material.replay().map_err(|_| invalid_registration())?,
                    self.checkpoint.as_ref().ok_or_else(invalid_registration)?,
                    &[prior],
                )
                .map_err(|_| invalid_registration())?;
                let prepared = PreparedPrivateFile::prepare_state(
                    root,
                    Path::new(path),
                    &protect(&bytes, protection)?,
                    PublicationPolicy::ReplaceExisting,
                )
                .map_err(map_filesystem_error)?;
                require_synced(prepared.publish().map_err(map_filesystem_error)?)?;
                if root
                    .read_private_file(Path::new(path), bytes.len())
                    .map_err(map_filesystem_error)?
                    != bytes
                {
                    return Err(incomplete_rollover());
                }
                Ok(())
            }
            Err(error) if error.kind() == FilesystemErrorKind::NotFound => {
                publish_private(root, path, &bytes, protection)
            }
            Err(error) => Err(map_filesystem_error(error)),
        }
    }
}

pub(super) fn preflight_endpoints(
    policy: &PolicyState,
    arguments: &VaultRolloverArgs,
) -> Result<Vec<WitnessEndpointClient>, CliError> {
    let required = policy
        .active_witness_policies()
        .map_err(|_| invalid_vault())?
        .iter()
        .flat_map(|policy| &policy.witness_descriptors)
        .filter(|descriptor| descriptor.status == jury_core::policy::DescriptorStatus::Active)
        .map(|descriptor| descriptor.witness_id)
        .collect::<BTreeSet<_>>();
    let mut observed = BTreeSet::new();
    let mut endpoints = Vec::new();
    for specification in &arguments.destination_witness {
        let endpoint =
            WitnessEndpointClient::load(specification, arguments.allow_insecure_loopback)?;
        if !required.contains(&endpoint.witness_id) || !observed.insert(endpoint.witness_id) {
            return Err(invalid_registration());
        }
        endpoints.push(endpoint);
    }
    if observed != required {
        return Err(invalid_registration());
    }
    Ok(endpoints)
}

pub(super) fn publish_private(
    root: &HardenedStateRoot,
    name: &str,
    bytes: &[u8],
    protection: ProtectionPolicy,
) -> Result<(), CliError> {
    match root.read_private_file(Path::new(name), bytes.len()) {
        Ok(prior) if prior == bytes => return Ok(()),
        Ok(_) => return Err(incomplete_rollover()),
        Err(error) if error.kind() == FilesystemErrorKind::NotFound => {}
        Err(error) => return Err(map_filesystem_error(error)),
    }
    let prepared = PreparedPrivateFile::prepare_state(
        root,
        Path::new(name),
        &protect(bytes, protection)?,
        PublicationPolicy::CreateNew,
    )
    .map_err(map_filesystem_error)?;
    require_synced(prepared.publish().map_err(map_filesystem_error)?)?;
    if root
        .read_private_file(Path::new(name), bytes.len())
        .map_err(map_filesystem_error)?
        != bytes
    {
        return Err(incomplete_rollover());
    }
    Ok(())
}

fn invalid_registration() -> CliError {
    CliError::new(
        CliErrorKind::InvalidArguments,
        "invalid-rollover-witness-registration",
        "provide exactly the destination policy's active witnesses, fresh accepted proofs and operator credentials for initial registration",
    )
}
