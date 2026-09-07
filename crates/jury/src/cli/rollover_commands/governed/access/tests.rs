use super::*;
use jury_core::{
    item::{NewItem, RekeyedItem},
    witness_approval::{OwnerReviewLabelCreator, OwnerReviewLabelInput, ReviewLabelSubject},
};
use std::{fs, os::unix::fs::PermissionsExt as _};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const PROTECTION: ProtectionPolicy = ProtectionPolicy::EmergencyAllowDegraded;

fn governed_context(root: &Path) -> TestResult<VaultPrincipalContext> {
    let mut context = super::super::super::test_support::context(root)?;
    let passphrase = protect(b"ExampleRolePassphrase", PROTECTION)?;
    let mut proofs = Vec::new();
    let mut additions = Vec::new();
    for (kind, coordinate) in [
        (PrincipalKind::Approver, None),
        (PrincipalKind::Witness, Some(1)),
        (PrincipalKind::Witness, Some(2)),
    ] {
        let created =
            IdentityCreator::new()
                .create(kind, KdfProfile::PortableV1, 3, &passphrase, |_| false)?;
        let role = unlock(&created.file, &passphrase)?;
        let challenge = RegistrationCreator::new(PROTECTION).create_challenge(
            &context.policy,
            &context.identity,
            created.descriptor.clone(),
            4,
            60_000,
            coordinate,
        )?;
        let proof =
            jury_core::registration::answer_challenge(&context.policy, &role, &challenge, 5)?;
        let digest = jury_core::registration::verify_proof(
            &context.policy,
            &context.identity,
            &challenge,
            &proof,
            6,
        )?;
        additions.push(PolicyOperationV1::PrincipalAdd {
            descriptor: created.descriptor,
            display_label: "ExampleRole".into(),
            registration_proof_digest: digest,
        });
        proofs.push(proof);
    }
    let registered = context
        .policy
        .prepare_revision(&context.identity, 6, additions)?;
    context.vault.policy.revisions.push(registered.revision);
    context.policy = registered.state;
    let body = ItemStateV1 {
        plaintext_schema: 1,
        fields: Vec::new(),
    };
    let descriptor = ItemDescriptorV1::new("ExampleItem".into())?;
    let created = ItemCreator::new(PROTECTION).prepare_create(
        &context.policy,
        &context.identity,
        7,
        NewItem {
            kind: jury_protocol::vault_v1::ItemKind::Canonical,
            descriptor: descriptor.clone(),
            state: body.clone(),
            bucket_id: 1,
            access: ItemAccessPlan {
                grants: Vec::new(),
                direct_recipient_ids: vec![context.identity.principal_id()],
                witness_policy_digest: None,
            },
        },
        &ItemArtifactInventory::default(),
    )?;
    context.vault.policy.revisions.push(created.policy.revision);
    context.policy = created.policy.state;
    context.vault.items.push(created.envelope);
    let now = timestamp_ms()?;
    let labels =
        jury_core::transfer::ReviewLabelSetV1::new(vec![OwnerReviewLabelCreator::new().create(
            OwnerReviewLabelInput {
                policy: &context.policy,
                owner: &context.identity,
                label_revision: 1,
                subject: ReviewLabelSubject::Item(context.vault.items[0].item_id),
                public_label: jury_protocol::witness_v1::ReviewLabelBytes::new(
                    b"ExampleItem".to_vec(),
                )?,
                target_policy_sequence: context.policy.sequence() + 1,
                issued_at_ms: now,
                expires_at_ms: Some(now + 3_600_000),
            },
            |_| false,
        )?])?;
    let witness = WitnessPolicy {
        schema: 1,
        witness_policy_id: jury_protocol::vault_v1::WitnessPolicyId::from_bytes([9; 32])?,
        revision: 1,
        predecessor_policy_digest: Digest32::new([0; 32]),
        vault_id: context.policy.vault_id(),
        genesis_fingerprint: context.policy.genesis_fingerprint().clone(),
        vault_policy_sequence: context.policy.sequence() + 1,
        vault_policy_hash: context.policy.terminal_revision_hash().clone(),
        construction: 1,
        suite: 1,
        approver_descriptors: proofs
            .iter()
            .filter_map(|proof| match &proof.role_descriptor {
                RegistrationRoleDescriptorV1::Approver { descriptor } => Some(descriptor.clone()),
                _ => None,
            })
            .collect(),
        witness_descriptors: proofs
            .iter()
            .filter_map(|proof| match &proof.role_descriptor {
                RegistrationRoleDescriptorV1::Witness { descriptor } => Some(*descriptor.clone()),
                _ => None,
            })
            .collect(),
        witness_threshold: 2,
        operation_rules: vec![jury_core::policy::OperationRule {
            operation: jury_core::policy::WitnessOperation::Recovery,
            eligible_approver_ids: proofs
                .iter()
                .filter_map(|proof| match &proof.role_descriptor {
                    RegistrationRoleDescriptorV1::Approver { descriptor } => {
                        Some(descriptor.approver_id)
                    }
                    _ => None,
                })
                .collect(),
            approval_threshold: 1,
            allowed_request_lifetime_ms: 300_000,
            max_timeout_ms: 30_000,
            max_output_bytes: 1_048_576,
            max_target_count: 1,
            required_platform_assurance: jury_core::policy::PlatformAssurance::NormalizedPathOnly,
            automatic_read_targets: Vec::new(),
        }],
        review_label_set_digest: labels.digest.clone(),
        direct_fallback: false,
    };
    let mut witness = witness;
    witness
        .witness_descriptors
        .sort_by_key(|descriptor| descriptor.witness_id);
    let policy =
        replay_policy_with_witness_policies(&context.vault.policy, std::slice::from_ref(&witness))?;
    let rekeyed = ItemCreator::new(PROTECTION).prepare_rekey(
        &policy,
        &context.identity,
        now,
        &context.vault.items[0],
        RekeyedItem {
            descriptor,
            state: body,
            bucket_id: 1,
            access: ItemAccessPlan {
                grants: Vec::new(),
                direct_recipient_ids: Vec::new(),
                witness_policy_digest: Some(witness.digest()?),
            },
            principal_replacement: None,
            principal_registration: None,
            owner_change: None,
        },
        &ItemArtifactInventory::from_vault(&context.vault)?,
    )?;
    context.vault.policy.revisions.push(rekeyed.policy.revision);
    context.vault.items[0] = rekeyed.envelope;
    context.policy = rekeyed.policy.state;
    proofs.sort_by_key(|proof| proof.candidate_principal_id);
    context
        .catalog
        .merge_transfer(&TransferPublicCatalogV1::with_review_label_sets(
            proofs,
            vec![witness],
            vec![labels],
        )?)?;
    Ok(context)
}

#[test]
fn preparation_preserves_label_error_and_adapter_failures_with_valid_unused_requests() -> TestResult
{
    let temporary = tempfile::tempdir()?;
    let root = temporary.path();
    fs::set_permissions(root, fs::Permissions::from_mode(0o700))?;
    let context = governed_context(root)?;
    let checkpoint = VaultPolicyCheckpointCreator::create(
        &context.policy,
        Digest32::new([0; 32]),
        &context.identity,
        timestamp_ms()?,
    )?;
    let checkpoint_path = root.join("ExampleCheckpoint.json");
    fs::write(&checkpoint_path, serde_json::to_vec(&checkpoint)?)?;
    fs::set_permissions(&checkpoint_path, fs::Permissions::from_mode(0o600))?;
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let credential = root.join("ExampleCredential");
    fs::write(&credential, b"ExampleCredential_0123456789abcdef")?;
    fs::set_permissions(&credential, fs::Permissions::from_mode(0o600))?;
    let address = listener.local_addr()?;
    let endpoints = context.policy.active_witness_policies()?[0]
        .witness_descriptors
        .iter()
        .map(|witness| {
            format!(
                "{},http://{},{}",
                hex(witness.witness_id.as_bytes()),
                address,
                credential.display()
            )
        })
        .collect::<Vec<_>>();
    let plan = root.join("ExampleAccess.json");
    let entries = [ContentRole::Descriptor, ContentRole::Body].into_iter().map(|role| serde_json::json!({
        "item_id": hex(context.vault.items[0].item_id.as_bytes()), "content_role": role, "checkpoint": checkpoint_path,
        "request_out": root.join(format!("ExampleRequest{}", role.tag())), "receipt": root.join(format!("ExampleReceipt{}", role.tag())),
        "approvals": [], "witnesses": endpoints, "allow_insecure_loopback": true, "wait_seconds": 1,
    })).collect::<Vec<_>>();
    fs::write(
        &plan,
        serde_json::to_vec(
            &serde_json::json!({ "version": 1, "total_wait_seconds": 1, "entries": entries }),
        )?,
    )?;
    fs::set_permissions(&plan, fs::Permissions::from_mode(0o600))?;
    let cli = Cli::try_parse_from([
        "jury",
        "vault",
        "rollover",
        "--adopt-new-lineage",
        "--out",
        root.join("ExampleOut").to_str().ok_or("invalid path")?,
        "--backup-out",
        root.join("ExampleBackup").to_str().ok_or("invalid path")?,
        "--transfer-out",
        root.join("ExampleTransfer")
            .to_str()
            .ok_or("invalid path")?,
        "--administrative-access",
        plan.to_str().ok_or("invalid path")?,
        "--registration-dir",
        root.join("ExampleRegistration")
            .to_str()
            .ok_or("invalid path")?,
    ])?;
    let Command::Vault {
        command: VaultCommand::Rollover(arguments),
    } = cli.command
    else {
        return Err("wrong command".into());
    };
    let validated_access = RolloverAccess::new(&context, &arguments, PROTECTION)?;
    validated_access.preflight_requests()?;
    assert_eq!(validated_access.entries.len(), 2);
    drop(validated_access);
    let source = RolloverSource::validate(&context.vault, &context.catalog.witness_policies)?;
    let error = super::super::prepare(
        &source,
        &context,
        &arguments,
        None,
        timestamp_ms()?,
        PROTECTION,
    )
    .err()
    .ok_or("short labels accepted")?;
    assert_eq!(error.code(), "rollover-review-label-lifetime");
    assert!(error.to_string().contains("refresh the source labels"));
    let provider = RolloverAccess::new(&context, &arguments, PROTECTION)?;
    assert_eq!(provider.entries.len(), 2);
    assert_eq!(
        provider
            .finish(Ok(()))
            .err()
            .ok_or("unused requests accepted")?
            .code(),
        "invalid-rollover-administrative-access"
    );
    let mut provider = RolloverAccess::new(&context, &arguments, PROTECTION)?;
    provider.error = Some(invalid_witness_response());
    assert_eq!(
        provider
            .finish::<()>(Err(error))
            .err()
            .ok_or("adapter failure lost")?
            .code(),
        invalid_witness_response().code()
    );
    let mut provider = RolloverAccess::new(&context, &arguments, PROTECTION)?;
    provider.entries.clear(); // Model complete consumption for the finalizer's success contract.
    assert_eq!(provider.finish(Ok(7))?, 7);
    assert_eq!(
        listener
            .accept()
            .err()
            .ok_or("unexpected HTTP request")?
            .kind(),
        std::io::ErrorKind::WouldBlock
    );
    assert!(
        !arguments.out.exists()
            && !arguments
                .registration_dir
                .ok_or("missing registration")?
                .exists()
    );
    for role in [ContentRole::Descriptor, ContentRole::Body] {
        assert!(!root.join(format!("ExampleRequest{}", role.tag())).exists());
        assert!(!root.join(format!("ExampleReceipt{}", role.tag())).exists());
    }
    Ok(())
}
