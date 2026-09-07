use super::*;
use jury_core::rollover::{GovernedRolloverOptions, RolloverSource};
use std::os::unix::fs::PermissionsExt as _;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn draft_proof_requires_source_authentication_and_external_destination_pin() -> TestResult {
    let protection = ProtectionPolicy::EmergencyAllowDegraded;
    let passphrase = protect(b"ExamplePassphrase", protection)?;
    let created_owner = IdentityCreator::new().create(
        PrincipalKind::Human,
        KdfProfile::PortableV1,
        1,
        &passphrase,
        |_| false,
    )?;
    let UnlockedIdentity::VaultPrincipal(owner) = unlock(&created_owner.file, &passphrase)? else {
        return Err("unexpected owner kind".into());
    };
    let created_role = IdentityCreator::new().create(
        PrincipalKind::Approver,
        KdfProfile::PortableV1,
        2,
        &passphrase,
        |_| false,
    )?;
    let role = unlock(&created_role.file, &passphrase)?;
    let created = PolicyCreator::new().create(&owner, 3, |_| false)?;
    let challenge = RegistrationCreator::new(protection).create_challenge(
        &created.state,
        &owner,
        created_role.descriptor.clone(),
        4,
        60_000,
        None,
    )?;
    let proof = answer_challenge(&created.state, &role, &challenge, 5)?;
    let digest = verify_proof(&created.state, &owner, &challenge, &proof, 6)?;
    let admitted = created.state.prepare_revision(
        &owner,
        6,
        vec![PolicyOperationV1::PrincipalAdd {
            descriptor: created_role.descriptor,
            display_label: "ExampleApprover".into(),
            registration_proof_digest: digest,
        }],
    )?;
    let mut vault = VaultFileV1 {
        header: VaultHeaderV1 {
            magic: "jury-vault".into(),
            version: 1,
            vault_id: created.state.vault_id(),
            created_at_ms: 3,
            suite: 1,
            policy_schema: 1,
            item_schema: 1,
            identity_schema: 1,
            genesis_fingerprint: created.state.genesis_fingerprint().clone(),
        },
        policy: created.journal,
        items: Vec::new(),
        suite_migration: None,
    };
    vault.policy.revisions.push(admitted.revision);
    let portable =
        TransferPublicCatalogV1::with_review_label_sets(vec![proof], Vec::new(), Vec::new())?;
    let mut catalog = PolicyCatalogV1::empty();
    catalog.merge_transfer(&portable)?;
    let source = RolloverSource::validate(&vault, &[])?;
    let draft = source.prepare_governed(
        &portable,
        &owner,
        &mut DirectItemAccessProvider::new(&owner),
        GovernedRolloverOptions {
            created_at_ms: 7,
            registration_lifetime_ms: 60_000,
            protection,
        },
        &NeverCancelled,
    )?;
    let temporary = tempfile::tempdir()?;
    let draft_path = temporary.path().join("ExampleDraft.json");
    let draft_bytes = serde_json::to_vec(draft.registration_journal())?;
    std::fs::write(&draft_path, &draft_bytes)?;
    std::fs::set_permissions(&draft_path, std::fs::Permissions::from_mode(0o600))?;
    let initial = source.verify_registration_draft(draft.registration_journal())?;
    let mut arguments = IdentityProveArgs {
        challenge: temporary.path().join("ExampleChallenge.json"),
        rollover_draft: Some(draft_path.clone()),
        expected_rollover_genesis: Some(hex(initial.genesis_fingerprint().as_bytes())),
        out: temporary.path().join("ExampleProof.json"),
        overwrite: false,
    };
    let fresh = answer_rollover_proof(
        &arguments,
        &vault,
        &catalog,
        &role,
        &draft.challenges()[0],
        8,
    )?;
    draft.verify_registration_proof(&owner, fresh.candidate_principal_id, &fresh, 9)?;
    crate::cli::rollover_commands::exercise_polling_repair(&draft, &owner, &fresh)?;
    let mut wrong = fresh.clone();
    wrong.candidate_signature = jury_protocol::vault_v1::Signature64::new([0; 64]);
    assert!(
        draft
            .verify_registration_proof(&owner, fresh.candidate_principal_id, &wrong, 9)
            .is_err()
    );
    draft.verify_registration_proofs(&owner, &[fresh], 9)?;
    let expected = arguments.expected_rollover_genesis.take();
    for incorrect in [None, Some("00".repeat(32)), Some("invalid".into())] {
        arguments.expected_rollover_genesis = incorrect;
        let error = answer_rollover_proof(
            &arguments,
            &vault,
            &catalog,
            &role,
            &draft.challenges()[0],
            8,
        )
        .err()
        .ok_or("incorrect destination pin accepted")?;
        assert_eq!(error.code(), "rollover-genesis-fingerprint-mismatch");
    }
    arguments.expected_rollover_genesis = expected;
    let mut modified = draft.registration_journal().clone();
    modified.genesis.owner_signature = jury_protocol::vault_v1::Signature64::new([0; 64]);
    std::fs::write(&draft_path, serde_json::to_vec(&modified)?)?;
    assert!(
        answer_rollover_proof(
            &arguments,
            &vault,
            &catalog,
            &role,
            &draft.challenges()[0],
            8
        )
        .is_err()
    );
    std::fs::write(&draft_path, &draft_bytes)?;
    assert!(
        answer_rollover_proof(
            &arguments,
            &vault,
            &PolicyCatalogV1::empty(),
            &role,
            &draft.challenges()[0],
            8
        )
        .is_err()
    );
    assert!(!arguments.out.exists()); // This helper signs; only the command publishes.
    Ok(())
}
