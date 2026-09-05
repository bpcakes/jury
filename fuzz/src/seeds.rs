//! Generic corpus inputs derived from frozen fixtures, never from user state.
use ed25519_dalek::{Signer as _, SigningKey};
use jury_core::{
    policy::replay_policy,
    registration::{
        RegistrationChallengeV1, RegistrationProofV1, RegistrationRoleDescriptorV1,
        RegistrationRoleProfileV1,
    },
    transfer::{TransferPublicCatalogV1, ValidatedTransfer},
    witness_receipt::ReceiptPolicyMaterialV1,
};
use jury_protocol::{
    backup_v1::{BACKUP_PREFIX_BYTES, BackupEnvelopeV1, BackupHeaderV1, bucket_bytes},
    identity_v1::{
        IdentityFileV1, IdentityHeaderV1, KdfProfile, ProtectionMode, ProviderKind,
        ProviderMetadata,
    },
    transfer_v1::{TransferCatalogBytes, TransferEnvelopeV1, TransferVaultBytes},
    vault_v1::{
        ApprovalId, CancellationId, Digest32, DirectCiphertext48, EmptyGenesisEntryV1,
        Encapsulation1120, IdentityPayloadCiphertext149, ItemDescriptorV1, ItemId, ItemStateV1,
        LabelId, Nonce12, PolicyGenesisV1, PolicyJournalV1, PrincipalDescriptorV1, PrincipalId,
        PrincipalKind, ReceiptId, RecipientPublicKey1216, RecoveryId, RevisionSealId,
        RootWrapCiphertext48, RotationId, Salt16, Signature64, VaultFileV1, VaultHeaderV1,
        VerificationPublicKey32, WitnessPolicyId,
    },
    witness_v1::{
        ActionManifestV1, ApprovalDecisionKindV1, ApprovalDecisionV1, ApprovalModeV1,
        ApprovalTargetEntryV1, ApprovalTargetV1, CancellerRoleV1, OperationContextV1, OutputSinkV1,
        OwnerReviewLabelV1, PlatformAssuranceV1, PresentationSubjectV1, PublicReceiptScopeV1,
        ReceiptAcknowledgementV1, ReceiptCompletionV1, ReceiptOutcomeV1, RequestBytes,
        RequestCancellationV1, ReviewLabelBytes, StdinModeV1, VaultPolicyCheckpointV1,
        WitnessDatabaseStateV1, WitnessDecisionKindV1, WitnessDecisionV1, WitnessDescriptorBytes,
        WitnessPolicyRotationV1, WitnessReasonV1, WitnessReceiptMaterialV1, WitnessReceiptV1,
        WitnessRecoveryV1, WitnessRequestV1, WitnessResponseV1, WitnessRotationItemV1,
        WitnessRotationReasonV1, WitnessStateAnchorV1,
    },
};
use sha2::{Digest as _, Sha256};

type SeedResult<T> = Result<T, Box<dyn std::error::Error>>;

pub struct Seed {
    pub target: &'static str,
    pub name: &'static str,
    pub bytes: Vec<u8>,
}

pub fn seeds() -> SeedResult<Vec<Seed>> {
    let vault_bytes = include_bytes!("../../conformance/vault-v1/example-vault.json");
    let vault = VaultFileV1::parse(vault_bytes)?;
    let body = ItemStateV1 {
        plaintext_schema: 1,
        fields: Vec::new(),
    };
    let corpus: serde_json::Value =
        serde_json::from_str(include_str!("../../conformance/witness-v1/vectors.json"))?;
    let preimage = decode_hex(
        corpus["vectors"]["witness_request"]["preimage_hex"]
            .as_str()
            .ok_or("missing witness preimage")?,
    )?;
    let request = WitnessRequestV1::from_signature_preimage(&preimage, Signature64::new([0; 64]))?;
    let header = BackupHeaderV1 {
        backup_format: 1,
        backup_id: RecoveryId::from_bytes([1; 32])?,
        created_at_ms: 1,
        vault_id: vault.header.vault_id,
        genesis_fingerprint: vault.header.genesis_fingerprint.clone(),
        source_public_revision_hash: Digest32::new([2; 32]),
        owner_principal_id: request.requester_principal_id,
        owner_descriptor_fingerprint: Digest32::new([3; 32]),
        kdf_profile: KdfProfile::PortableV1,
        argon2_version: 0x13,
        memory_kib: KdfProfile::PortableV1.memory_kib(),
        passes: 3,
        lanes: 4,
        salt: Salt16::new([4; 16]),
        storage_algorithm: 1,
        nonce: Nonce12::new([5; 12]),
        target_bucket_id: 1,
        payload_ciphertext_length: u32::try_from(bucket_bytes(1)? - BACKUP_PREFIX_BYTES)?,
        payload_digest: Digest32::new([6; 32]),
    };
    let envelope = BackupEnvelopeV1::new(
        header.clone(),
        vec![0; usize::try_from(header.payload_ciphertext_length)?],
    )?;
    let mut identity_header = IdentityHeaderV1 {
        identity_format: 1,
        principal_id: PrincipalId::from_bytes([0x61; 32])?,
        principal_kind: PrincipalKind::Human,
        recipient_public_key: RecipientPublicKey1216::new([0x62; 1216]),
        verification_public_key: VerificationPublicKey32::new([0x63; 32]),
        descriptor_fingerprint: Digest32::new([0; 32]),
        created_at_ms: 1,
        kdf_profile: KdfProfile::PortableV1,
        argon2_version: 0x13,
        memory_kib: KdfProfile::PortableV1.memory_kib(),
        passes: 3,
        lanes: 4,
        salt: Salt16::new([0x64; 16]),
        protection_mode: ProtectionMode::Portable,
        provider_kind: ProviderKind::new(Vec::new())?,
        provider_metadata: ProviderMetadata::new(Vec::new())?,
        root_wrap_algorithm: 1,
        root_wrap_nonce: Nonce12::new([0x65; 12]),
        payload_algorithm: 1,
        payload_nonce: Nonce12::new([0x66; 12]),
    };
    identity_header.descriptor_fingerprint = identity_header.recomputed_descriptor_fingerprint()?;
    let identity = IdentityFileV1 {
        magic: "jury-identity".to_owned(),
        header: identity_header,
        root_wrap_ciphertext: RootWrapCiphertext48::new([0x67; 48]),
        payload_ciphertext: IdentityPayloadCiphertext149::new([0x68; 149]),
    };
    let catalog = TransferPublicCatalogV1 {
        version: 1,
        registration_proofs: Vec::new(),
        witness_policies: Vec::new(),
        review_label_sets: Vec::new(),
    };
    let catalog_bytes = catalog.to_json_bytes()?;
    let transfer = TransferEnvelopeV1 {
        magic: "jury-transfer".to_owned(),
        version: 1,
        transfer_id: Digest32::new([0x69; 32]),
        created_at_ms: 1,
        source_vault_id: vault.header.vault_id,
        source_genesis_fingerprint: vault.header.genesis_fingerprint.clone(),
        source_public_revision_hash: vault.header.genesis_fingerprint.clone(),
        vault_digest: Digest32::new(Sha256::digest(vault_bytes).into()),
        catalog_digest: Digest32::new(Sha256::digest(&catalog_bytes).into()),
        exporting_principal_id: request.requester_principal_id,
        vault_json: TransferVaultBytes::new(vault_bytes.to_vec())?,
        public_catalog_json: TransferCatalogBytes::new(catalog_bytes.clone())?,
        exporter_signature: Signature64::new([0x6a; 64]),
    };
    let candidate_signing_key = SigningKey::from_bytes(&[0x6b; 32]);
    let mut candidate_descriptor = PrincipalDescriptorV1 {
        descriptor_version: 1,
        principal_id: PrincipalId::from_bytes([0x6c; 32])?,
        principal_kind: PrincipalKind::Human,
        recipient_public_key: RecipientPublicKey1216::new([0x6d; 1216]),
        verification_public_key: VerificationPublicKey32::new(
            candidate_signing_key.verifying_key().to_bytes(),
        ),
        self_signature: Signature64::new([0; 64]),
    };
    candidate_descriptor.self_signature = Signature64::new(
        candidate_signing_key
            .sign(&candidate_descriptor.self_signature_preimage()?)
            .to_bytes(),
    );
    let transfer_vault_id = jury_protocol::vault_v1::VaultId::from_bytes([0x75; 32])?;
    let mut transfer_genesis = PolicyGenesisV1 {
        vault_id: transfer_vault_id,
        policy_sequence: 0,
        previous_policy_hash: Digest32::new([0; 32]),
        created_at_ms: 1,
        suite: 1,
        owner: candidate_descriptor.clone(),
        source_attestation: None,
        item_inventory: Vec::<EmptyGenesisEntryV1>::new(),
        direct_grants: Vec::<EmptyGenesisEntryV1>::new(),
        owner_signature: Signature64::new([0; 64]),
    };
    transfer_genesis.owner_signature = Signature64::new(
        candidate_signing_key
            .sign(&transfer_genesis.signature_preimage()?)
            .to_bytes(),
    );
    let transfer_journal = PolicyJournalV1 {
        genesis: transfer_genesis,
        revisions: Vec::new(),
    };
    let transfer_genesis_fingerprint = transfer_journal.genesis.recomputed_fingerprint()?;
    let transfer_vault = VaultFileV1 {
        header: VaultHeaderV1 {
            magic: "jury-vault".to_owned(),
            version: 1,
            vault_id: transfer_vault_id,
            created_at_ms: 1,
            suite: 1,
            policy_schema: 1,
            item_schema: 1,
            identity_schema: 1,
            genesis_fingerprint: transfer_genesis_fingerprint.clone(),
        },
        policy: transfer_journal,
        items: Vec::new(),
        suite_migration: None,
    };
    transfer_vault.validate()?;
    let transfer_catalog = TransferPublicCatalogV1::empty();
    let transfer_vault_bytes = transfer_vault.to_json_bytes()?;
    let transfer_catalog_bytes = transfer_catalog.to_json_bytes()?;
    let transfer_policy = replay_policy(&transfer_vault.policy)?;
    let mut valid_transfer_envelope = TransferEnvelopeV1 {
        magic: "jury-transfer".to_owned(),
        version: 1,
        transfer_id: Digest32::new([0x76; 32]),
        created_at_ms: 2,
        source_vault_id: transfer_vault_id,
        source_genesis_fingerprint: transfer_genesis_fingerprint,
        source_public_revision_hash: transfer_policy.terminal_revision_hash().clone(),
        vault_digest: Digest32::new(Sha256::digest(&transfer_vault_bytes).into()),
        catalog_digest: Digest32::new(Sha256::digest(&transfer_catalog_bytes).into()),
        exporting_principal_id: candidate_descriptor.principal_id,
        vault_json: TransferVaultBytes::new(transfer_vault_bytes)?,
        public_catalog_json: TransferCatalogBytes::new(transfer_catalog_bytes)?,
        exporter_signature: Signature64::new([0; 64]),
    };
    valid_transfer_envelope.exporter_signature = Signature64::new(
        candidate_signing_key
            .sign(&valid_transfer_envelope.signature_preimage())
            .to_bytes(),
    );
    let valid_transfer_bytes = valid_transfer_envelope.to_json_bytes()?;
    ValidatedTransfer::parse(&valid_transfer_bytes)?;
    let policy_material = ReceiptPolicyMaterialV1 {
        schema: 1,
        journal: transfer_vault.policy.clone(),
        witness_policies: Vec::new(),
    }
    .encode()?;
    let challenge = RegistrationChallengeV1 {
        version: 1,
        vault_id: vault.header.vault_id,
        genesis_fingerprint: vault.header.genesis_fingerprint.clone(),
        owner_principal_id: request.requester_principal_id,
        candidate_descriptor: candidate_descriptor.clone(),
        role_profile: RegistrationRoleProfileV1::VaultPrincipal,
        challenge_id: Digest32::new([0x6e; 32]),
        issued_at_ms: 1,
        expires_at_ms: 2,
        candidate_encapsulation: Encapsulation1120::new([0x6f; 1120]),
        candidate_ciphertext: DirectCiphertext48::new([0x70; 48]),
        owner_encapsulation: Encapsulation1120::new([0x71; 1120]),
        owner_ciphertext: DirectCiphertext48::new([0x72; 48]),
        owner_signature: Signature64::new([0x73; 64]),
    };
    let proof = RegistrationProofV1 {
        version: 1,
        challenge: challenge.clone(),
        challenge_digest: challenge.digest()?,
        candidate_principal_id: candidate_descriptor.principal_id,
        role_descriptor: RegistrationRoleDescriptorV1::VaultPrincipal,
        response_mac: Digest32::new([0x74; 32]),
        created_at_ms: 2,
        candidate_signature: Signature64::new([0x75; 64]),
    };
    let mut seeds = vec![
        Seed {
            target: "input_boundaries",
            name: "jury-identity-list",
            bytes: b"identity\0list".to_vec(),
        },
        Seed {
            target: "input_boundaries",
            name: "identity-name",
            bytes: b"ExamplePrincipal".to_vec(),
        },
        Seed {
            target: "input_boundaries",
            name: "field-selector",
            bytes: b"ExampleSecret\0token".to_vec(),
        },
        Seed {
            target: "input_boundaries",
            name: "domain-identifiers",
            bytes: b"0101010101010101010101010101010101010101010101010101010101010101".to_vec(),
        },
        Seed {
            target: "input_boundaries",
            name: "witness-config",
            bytes: include_bytes!("../../deploy/juryd/witness.example.json").to_vec(),
        },
        Seed {
            target: "input_boundaries",
            name: "anchor-config",
            bytes: include_bytes!("../../deploy/juryd/anchor.example.json").to_vec(),
        },
        Seed {
            target: "protocol",
            name: "vault",
            bytes: vault_bytes.to_vec(),
        },
        Seed {
            target: "protocol",
            name: "identity",
            bytes: identity.to_json_bytes()?,
        },
        Seed {
            target: "protocol",
            name: "transfer",
            bytes: transfer.to_json_bytes()?,
        },
        Seed {
            target: "protocol",
            name: "descriptor",
            bytes: ItemDescriptorV1::new("ExampleSecret".to_owned())?
                .encode()
                .to_vec(),
        },
        Seed {
            target: "protocol",
            name: "body",
            bytes: body.to_canonical_bytes()?,
        },
        Seed {
            target: "protocol",
            name: "body-framed",
            bytes: body.frame(1)?,
        },
        Seed {
            target: "protocol",
            name: "backup-header",
            bytes: header.canonical_bytes()?.to_vec(),
        },
        Seed {
            target: "protocol",
            name: "backup-envelope",
            bytes: envelope.to_bytes()?,
        },
        Seed {
            target: "witness",
            name: "request-preimage",
            bytes: preimage,
        },
        Seed {
            target: "witness",
            name: "request-json",
            bytes: serde_json::to_vec(&request)?,
        },
        Seed {
            target: "core_artifacts",
            name: "catalog",
            bytes: catalog_bytes,
        },
        Seed {
            target: "core_artifacts",
            name: "registration-challenge",
            bytes: challenge.to_json_bytes()?,
        },
        Seed {
            target: "core_artifacts",
            name: "registration-proof",
            bytes: proof.to_json_bytes()?,
        },
        Seed {
            target: "core_artifacts",
            name: "validated-transfer",
            bytes: valid_transfer_bytes,
        },
        Seed {
            target: "core_artifacts",
            name: "receipt-policy-material",
            bytes: policy_material.as_bytes().to_vec(),
        },
    ];
    seeds.extend(witness_json_seeds(&request, policy_material)?);
    Ok(seeds)
}

fn witness_json_seeds(
    request: &WitnessRequestV1,
    policy_material: jury_protocol::witness_v1::PolicyMaterialBytes,
) -> SeedResult<Vec<Seed>> {
    let digest = |byte| Digest32::new([byte; 32]);
    let principal = |byte| PrincipalId::from_bytes([byte; 32]);
    let mut seeds = Vec::new();
    macro_rules! json_seed {
        ($name:literal, $value:expr) => {
            seeds.push(Seed {
                target: "witness",
                name: $name,
                bytes: serde_json::to_vec(&$value)?,
            });
        };
    }

    let presentation_digest = digest(0x0d);
    let approval_target = ApprovalTargetV1 {
        entries: vec![ApprovalTargetEntryV1 {
            item_id: request.item_id,
            field_id: None,
            presentation_commitment: digest(0x0e),
        }],
        presentation_digest: presentation_digest.clone(),
    };
    let approval_target_digest = approval_target.digest()?;
    json_seed!(
        "action-manifest-json",
        ActionManifestV1 {
            schema: 1,
            request_id: request.request_id,
            vault_id: request.vault_id,
            genesis_fingerprint: request.genesis_fingerprint.clone(),
            item_id: request.item_id,
            key_epoch: request.key_epoch,
            item_access_mode: request.item_access_mode,
            slot_id: request.slot_id,
            content_role: request.content_role,
            revision: request.revision,
            revision_seal_id: request.revision_seal_id,
            vault_policy_sequence: request.vault_policy_sequence,
            vault_policy_hash: request.vault_policy_hash.clone(),
            witness_policy_id: request.witness_policy_id,
            witness_policy_revision: request.witness_policy_revision,
            witness_policy_digest: request.witness_policy_digest.clone(),
            requester_principal_id: request.requester_principal_id,
            requested_access_role: request.requested_access_role,
            operation: jury_protocol::witness_v1::WitnessOperationV1::ReadStdout,
            operation_context: OperationContextV1::ReadStdout,
            approval_target,
            approval_target_digest,
            executable_identity: None,
            arguments: Vec::new(),
            working_directory_commitment: None,
            environment_injections: Vec::new(),
            stdin_target: None,
            stdin_mode: StdinModeV1::None,
            output_sink: OutputSinkV1::Stdout,
            output_sink_commitment: None,
            platform_assurance: PlatformAssuranceV1::NormalizedPathOnly,
            timeout_ms: 30_000,
            output_limit_bytes: 4_096,
            issued_at_ms: request.issued_at_ms,
            not_before_ms: request.not_before_ms,
            expires_at_ms: request.expires_at_ms,
            presentation_digest,
        }
    );

    let approval = ApprovalDecisionV1 {
        schema: 1,
        approval_id: ApprovalId::from_bytes([0x10; 32])?,
        request_id: request.request_id,
        request_digest: request.digest()?,
        action_manifest_digest: request.action_manifest_digest.clone(),
        presentation_digest: digest(0x11),
        witness_policy_id: request.witness_policy_id,
        witness_policy_revision: request.witness_policy_revision,
        witness_policy_digest: request.witness_policy_digest.clone(),
        approver_id: principal(0x12)?,
        approver_key_fingerprint: digest(0x13),
        approver_key_epoch: 1,
        approval_mode: ApprovalModeV1::Human,
        decision: ApprovalDecisionKindV1::Approve,
        reason: WitnessReasonV1::None,
        issued_at_ms: request.issued_at_ms + 1,
        not_before_ms: None,
        expires_at_ms: request.expires_at_ms,
        nonce: ApprovalId::from_bytes([0x14; 32])?,
        intended_witness_set_digest: request.intended_witness_set_digest()?,
        signature: Signature64::new([0x15; 64]),
    };
    json_seed!("approval-decision-json", approval);

    let cancellation = RequestCancellationV1 {
        schema: 1,
        cancellation_id: CancellationId::from_bytes([0x16; 32])?,
        request_signature_preimage: RequestBytes::new(request.signature_preimage()?)?,
        client_signature: request.client_signature.clone(),
        request_id: request.request_id,
        request_digest: request.digest()?,
        canceller_id: request.requester_principal_id,
        canceller_key_fingerprint: request.requester_signing_key_fingerprint.clone(),
        canceller_key_epoch: request.requester_signing_key_epoch,
        canceller_role: CancellerRoleV1::OriginalRequester,
        issued_at_ms: request.issued_at_ms + 1,
        reason: WitnessReasonV1::Cancelled,
        nonce: CancellationId::from_bytes([0x17; 32])?,
        signature: Signature64::new([0x18; 64]),
    };
    json_seed!("request-cancellation-json", cancellation);

    let checkpoint = VaultPolicyCheckpointV1 {
        schema: 1,
        vault_id: request.vault_id,
        genesis_fingerprint: request.genesis_fingerprint.clone(),
        vault_policy_sequence: request.vault_policy_sequence,
        vault_policy_hash: request.vault_policy_hash.clone(),
        witness_policy_id: request.witness_policy_id,
        witness_policy_revision: request.witness_policy_revision,
        witness_policy_digest: request.witness_policy_digest.clone(),
        witness_set_digest: digest(0x19),
        approver_set_digest: digest(0x1a),
        review_label_set_digest: digest(0x1b),
        predecessor_checkpoint_digest: digest(0),
        issued_at_ms: request.issued_at_ms,
        issuer_owner_id: principal(0x1c)?,
        issuer_key_fingerprint: digest(0x1d),
        issuer_key_epoch: 1,
        signature: Signature64::new([0x1e; 64]),
    };
    json_seed!("policy-checkpoint-json", checkpoint);

    let decision = WitnessDecisionV1 {
        schema: 1,
        response_id: jury_protocol::vault_v1::ResponseId::from_bytes([0x20; 32])?,
        request_id: request.request_id,
        request_digest: request.digest()?,
        action_manifest_digest: request.action_manifest_digest.clone(),
        witness_id: principal(0x21)?,
        witness_signing_key_fingerprint: digest(0x22),
        witness_signing_key_epoch: 1,
        witness_policy_id: request.witness_policy_id,
        witness_policy_revision: request.witness_policy_revision,
        witness_policy_digest: request.witness_policy_digest.clone(),
        policy_checkpoint_digest: request.policy_checkpoint_digest.clone(),
        state_generation: 1,
        decision: WitnessDecisionKindV1::Deny,
        reason: WitnessReasonV1::PolicyDenied,
        issued_at_ms: request.issued_at_ms + 1,
        expires_at_ms: request.expires_at_ms,
        contribution_digest: None,
        share_index: None,
        share_commitment: None,
        signature: Signature64::new([0x23; 64]),
    };
    json_seed!("witness-decision-json", decision);
    json_seed!(
        "witness-response-json",
        WitnessResponseV1 {
            decision: decision.clone(),
            contribution: None,
        }
    );
    json_seed!(
        "witness-receipt-json",
        WitnessReceiptV1 {
            schema: 1,
            receipt_id: ReceiptId::from_bytes([0x49; 32])?,
            request_signature_preimage: RequestBytes::new(request.signature_preimage()?)?,
            client_signature: request.client_signature.clone(),
            request_digest: request.digest()?,
            action_manifest_digest: request.action_manifest_digest.clone(),
            presentation_digest: digest(0x4a),
            public_scope: PublicReceiptScopeV1::from_request(request),
            approval_decisions: Vec::new(),
            witness_decisions: vec![decision.clone()],
            policy_checkpoint: checkpoint.clone(),
            witness_policy_material: policy_material,
            approval_threshold: 0,
            witness_threshold: 2,
            counted_approver_ids: Vec::new(),
            counted_witness_ids: Vec::new(),
            outcome: ReceiptOutcomeV1::Denied,
            reason: WitnessReasonV1::PolicyDenied,
            issued_at_ms: request.issued_at_ms + 1,
            expires_at_ms: request.expires_at_ms,
            endpoint_acknowledgement: None,
            endpoint_completion: None,
        }
    );

    let anchor = WitnessStateAnchorV1 {
        schema: 1,
        witness_id: principal(0x24)?,
        witness_signing_key_fingerprint: digest(0x25),
        witness_signing_key_epoch: 1,
        state_generation: 1,
        database_state_digest: digest(0x26),
        vault_high_watermarks: Vec::new(),
        replay_retain_through_ms: request.expires_at_ms,
        last_accepted_wall_time_ms: request.issued_at_ms,
        predecessor_anchor_digest: digest(0),
        issued_at_ms: request.issued_at_ms,
        signature: Signature64::new([0x27; 64]),
    };
    json_seed!("witness-anchor-json", anchor);
    json_seed!(
        "witness-database-json",
        WitnessDatabaseStateV1 {
            schema: 1,
            witness_id: principal(0x24)?,
            state_generation: 1,
            vault_states: Vec::new(),
            replay_records: Vec::new(),
            last_accepted_wall_time_ms: request.issued_at_ms,
        }
    );

    let rotation_item = WitnessRotationItemV1 {
        item_id: ItemId::from_bytes([0x28; 32])?,
        prior_key_epoch: 1,
        next_key_epoch: 2,
        next_descriptor_revision: 1,
        next_descriptor_revision_seal_id: RevisionSealId::from_bytes([0x29; 32])?,
        next_descriptor_capsule_set_digest: digest(0x2a),
        next_body_revision: 1,
        next_body_revision_seal_id: RevisionSealId::from_bytes([0x2b; 32])?,
        next_body_capsule_set_digest: digest(0x2c),
    };
    json_seed!(
        "witness-rotation-json",
        WitnessPolicyRotationV1 {
            schema: 1,
            rotation_id: RotationId::from_bytes([0x2d; 32])?,
            vault_id: request.vault_id,
            genesis_fingerprint: request.genesis_fingerprint.clone(),
            prior_vault_policy_sequence: 1,
            prior_vault_policy_hash: digest(0x2e),
            next_vault_policy_sequence: 2,
            next_vault_policy_hash: digest(0x2f),
            prior_witness_policy_id: WitnessPolicyId::from_bytes([0x30; 32])?,
            prior_witness_policy_revision: 1,
            prior_witness_policy_digest: digest(0x31),
            next_witness_policy_id: WitnessPolicyId::from_bytes([0x32; 32])?,
            next_witness_policy_revision: 1,
            next_witness_policy_digest: digest(0x33),
            reason: WitnessRotationReasonV1::WitnessMembership,
            affected_items: vec![rotation_item],
            issued_at_ms: request.issued_at_ms,
            owner_id: principal(0x34)?,
            owner_key_fingerprint: digest(0x35),
            owner_key_epoch: 1,
            signature: Signature64::new([0x36; 64]),
        }
    );
    json_seed!(
        "witness-recovery-json",
        WitnessRecoveryV1 {
            schema: 1,
            recovery_id: RecoveryId::from_bytes([0x37; 32])?,
            vault_id: request.vault_id,
            genesis_fingerprint: request.genesis_fingerprint.clone(),
            unavailable_prior_witness_id: Some(principal(0x38)?),
            new_witness_descriptor: WitnessDescriptorBytes::new(vec![0x39])?,
            new_registration_digest: digest(0x3a),
            prior_checkpoint_digest: digest(0x3b),
            next_checkpoint_digest: digest(0x3c),
            rotation_record_digest: digest(0x3d),
            statement: 1,
            issued_at_ms: request.issued_at_ms,
            owner_id: principal(0x34)?,
            owner_key_fingerprint: digest(0x35),
            owner_key_epoch: 1,
            signature: Signature64::new([0x3e; 64]),
        }
    );

    json_seed!(
        "owner-review-label-json",
        OwnerReviewLabelV1 {
            schema: 1,
            label_id: LabelId::from_bytes([0x40; 32])?,
            label_revision: 1,
            subject_kind: PresentationSubjectV1::Item,
            vault_id: request.vault_id,
            genesis_fingerprint: request.genesis_fingerprint.clone(),
            item_id: Some(request.item_id),
            field_id: None,
            subject_commitment: None,
            public_label: ReviewLabelBytes::new(b"ExampleSecret".to_vec())?,
            vault_policy_sequence: request.vault_policy_sequence,
            issued_at_ms: request.issued_at_ms,
            expires_at_ms: None,
            issuer_owner_id: principal(0x34)?,
            issuer_key_fingerprint: digest(0x35),
            issuer_key_epoch: 1,
            signature: Signature64::new([0x41; 64]),
        }
    );

    let acknowledgement = ReceiptAcknowledgementV1 {
        schema: 1,
        receipt_id: ReceiptId::from_bytes([0x42; 32])?,
        receipt_core_digest: digest(0x43),
        request_digest: request.digest()?,
        endpoint_principal_id: request.requester_principal_id,
        endpoint_key_fingerprint: request.requester_signing_key_fingerprint.clone(),
        endpoint_key_epoch: 1,
        started_at_ms: request.issued_at_ms,
        signature: Signature64::new([0x44; 64]),
    };
    json_seed!("receipt-acknowledgement-json", acknowledgement);
    json_seed!(
        "receipt-completion-json",
        ReceiptCompletionV1 {
            schema: 1,
            receipt_id: ReceiptId::from_bytes([0x42; 32])?,
            receipt_core_digest: digest(0x43),
            acknowledgement_digest: Some(acknowledgement.digest()?),
            endpoint_principal_id: request.requester_principal_id,
            endpoint_key_fingerprint: request.requester_signing_key_fingerprint.clone(),
            endpoint_key_epoch: 1,
            outcome: ReceiptOutcomeV1::Approved,
            reason: WitnessReasonV1::None,
            completed_at_ms: request.issued_at_ms + 1,
            signature: Signature64::new([0x45; 64]),
        }
    );
    json_seed!(
        "receipt-material-json",
        WitnessReceiptMaterialV1 {
            schema: 1,
            receipt_id: ReceiptId::from_bytes([0x42; 32])?,
            request_digest: request.digest()?,
            action_manifest_digest: request.action_manifest_digest.clone(),
            presentation_digest: digest(0x46),
            policy_checkpoint_digest: request.policy_checkpoint_digest.clone(),
            witness_policy_digest: request.witness_policy_digest.clone(),
            approval_threshold: 0,
            witness_threshold: 2,
            counted_approver_ids: Vec::new(),
            counted_witness_ids: vec![principal(0x47)?, principal(0x48)?],
            reason: WitnessReasonV1::None,
            issued_at_ms: request.issued_at_ms,
            expires_at_ms: request.expires_at_ms,
        }
    );
    Ok(seeds)
}

fn decode_hex(value: &str) -> SeedResult<Vec<u8>> {
    if !value.len().is_multiple_of(2) {
        return Err("odd corpus hex length".into());
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair)?;
            Ok(u8::from_str_radix(text, 16)?)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    #[test]
    fn every_seed_reaches_an_accepted_path() -> Result<(), Box<dyn std::error::Error>> {
        let mut protocol_paths = 0;
        let mut witness_paths = 0;
        let mut core_paths = 0;
        let mut input_paths = 0;
        for seed in super::seeds()? {
            let count = match seed.target {
                "protocol" => {
                    protocol_paths |= crate::protocol::coverage(&seed.bytes);
                    crate::protocol::exercise(&seed.bytes)
                }
                "witness" => {
                    witness_paths |= crate::witness::coverage(&seed.bytes);
                    crate::witness::exercise(&seed.bytes)
                }
                "core_artifacts" => {
                    core_paths |= crate::core_artifacts::coverage(&seed.bytes);
                    crate::core_artifacts::exercise(&seed.bytes)
                }
                "input_boundaries" => {
                    input_paths |= crate::input_boundaries::coverage(&seed.bytes);
                    crate::input_boundaries::exercise(&seed.bytes)
                }
                _ => return Err("unknown seed target".into()),
            };
            assert!(count > 0, "seed {} has no accepted path", seed.name);
        }
        assert_eq!(protocol_paths, crate::protocol::ALL_ACCEPTED_PATHS);
        assert_eq!(witness_paths, crate::witness::ALL_ACCEPTED_PATHS);
        assert_eq!(core_paths, crate::core_artifacts::ALL_ACCEPTED_PATHS);
        assert_eq!(input_paths, crate::input_boundaries::ALL_ACCEPTED_PATHS);
        Ok(())
    }
}
