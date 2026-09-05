#[test]
fn checkpoint_consumers_preserve_binding_checks_and_error_classification() -> TestResult {
    use crate::witness_operations::{
        CheckpointStatusErrorKind as Status, verify_checkpoint_propagation,
    };

    let fixture = fixture()?;
    let check = |checkpoint: &VaultPolicyCheckpointV1| {
        (
            validate_checkpoint_public(&fixture.policy, checkpoint)
                .map(|_| ())
                .map_err(WitnessEngineError::reason),
            verify_checkpoint_propagation(&fixture.policy, checkpoint, &[])
                .map(|_| ())
                .map_err(|error| error.kind()),
        )
    };
    assert_eq!(check(&fixture.checkpoint), (Ok(()), Ok(())));

    let mutations: &[fn(&mut VaultPolicyCheckpointV1) -> TestResult] = &[
        |c| {
            c.vault_id = VaultId::from_bytes([0x71; 32])?;
            Ok(())
        },
        |c| {
            c.genesis_fingerprint = Digest32::new([0x71; 32]);
            Ok(())
        },
        |c| {
            c.vault_policy_sequence += 1;
            Ok(())
        },
        |c| {
            c.vault_policy_hash = Digest32::new([0x71; 32]);
            Ok(())
        },
        |c| {
            c.witness_policy_id = WitnessPolicyId::from_bytes([0x71; 32])?;
            Ok(())
        },
        |c| {
            c.witness_policy_revision += 1;
            Ok(())
        },
        |c| {
            c.witness_policy_digest = Digest32::new([0x71; 32]);
            Ok(())
        },
        |c| {
            c.witness_set_digest = Digest32::new([0x71; 32]);
            Ok(())
        },
        |c| {
            c.approver_set_digest = Digest32::new([0x71; 32]);
            Ok(())
        },
        |c| {
            c.review_label_set_digest = Digest32::new([0x71; 32]);
            Ok(())
        },
    ];
    for (index, mutate) in mutations.iter().enumerate() {
        let mut checkpoint = fixture.checkpoint.clone();
        mutate(&mut checkpoint)?;
        assert_ne!(
            checkpoint, fixture.checkpoint,
            "mutation {index} must change input"
        );
        assert_eq!(
            check(&checkpoint),
            (
                Err(WitnessReasonV1::CheckpointFork),
                Err(Status::InvalidCheckpoint)
            ),
            "binding mutation {index}"
        );
    }

    let mut checkpoint = fixture.checkpoint.clone();
    checkpoint.issuer_owner_id = PrincipalId::from_bytes([0x71; 32])?;
    assert_eq!(
        check(&checkpoint),
        (
            Err(WitnessReasonV1::InvalidSignature),
            Err(Status::InvalidCheckpoint)
        )
    );
    // A binding failure takes precedence over the missing owner on both paths.
    checkpoint.vault_policy_hash = Digest32::new([0x71; 32]);
    assert_eq!(
        check(&checkpoint),
        (
            Err(WitnessReasonV1::CheckpointFork),
            Err(Status::InvalidCheckpoint)
        )
    );
    checkpoint.schema = 2;
    assert_eq!(
        check(&checkpoint),
        (
            Err(WitnessReasonV1::Invalid),
            Err(Status::InvalidCheckpoint)
        )
    );

    for mutate in [
        (|c: &mut VaultPolicyCheckpointV1| c.issuer_key_epoch += 1)
            as fn(&mut VaultPolicyCheckpointV1),
        |c| c.issuer_key_fingerprint = Digest32::new([0x71; 32]),
        |c| c.signature = Signature64::new([0x71; 64]),
    ] {
        let mut checkpoint = fixture.checkpoint.clone();
        mutate(&mut checkpoint);
        assert_eq!(
            check(&checkpoint),
            (
                Err(WitnessReasonV1::InvalidSignature),
                Err(Status::InvalidSignature)
            )
        );
    }
    Ok(())
}
