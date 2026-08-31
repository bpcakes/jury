use std::collections::BTreeMap;

use jury_protocol::vault_v1::{Digest32, ItemId, PrincipalId, RevisionSealId, VaultId};
use serde_json::Value;

use super::*;

fn digest(byte: u8) -> Digest32 {
    Digest32::new([byte; 32])
}

fn scope() -> LocalStateScope {
    let Ok(vault_id) = VaultId::from_bytes([0x11; 32]) else {
        panic!("fixture vault ID is invalid");
    };
    let Ok(principal_id) = PrincipalId::from_bytes([0x13; 32]) else {
        panic!("fixture principal ID is invalid");
    };
    LocalStateScope {
        vault_id,
        genesis_fingerprint: digest(0x12),
        principal_id,
    }
}

fn item_id(byte: u8) -> ItemId {
    let Ok(item_id) = ItemId::from_bytes([byte; 32]) else {
        panic!("fixture item ID is invalid");
    };
    item_id
}

fn candidate(scope: &LocalStateScope, policy: &[(u64, u8)]) -> CheckpointCandidate {
    CheckpointCandidate::from_test_parts(
        scope,
        policy
            .iter()
            .map(|(sequence, hash)| (*sequence, digest(*hash)))
            .collect::<BTreeMap<_, _>>(),
    )
}

fn context() -> PrincipalLocalState {
    let Ok(context) = PrincipalLocalState::from_test_seed(&[0x21; 32], scope()) else {
        panic!("fixture local keys did not derive");
    };
    context
}

fn pretty_json(value: &Value) -> Result<Vec<u8>, serde_json::Error> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn item_read_draft(operation: u8) -> AuditEventDraft {
    AuditEventDraft {
        timestamp_ms: u64::from(operation) + 10,
        operation_id: digest(operation),
        policy_sequence: 0,
        action: AuditAction::ItemRead,
        outcome: AuditOutcome::Success,
        item: Some(AuditItemScope {
            item_id: item_id(0x31),
            permitted_item_name: None,
        }),
        witness: None,
    }
}

#[test]
fn local_state_error_is_value_free() {
    let error = LocalStateError::new(LocalStateErrorKind::AuditTampered);
    assert_eq!(error.kind(), LocalStateErrorKind::AuditTampered);
    assert_eq!(
        format!("{error:?}"),
        "LocalStateError { kind: AuditTampered }"
    );
}

#[test]
fn audit_checkpoint_and_receipts_round_trip_without_private_values()
-> Result<(), Box<dyn std::error::Error>> {
    let context = context();
    let candidate = candidate(context.scope(), &[(0, 0x12)]);
    let mut state = context.initialize(&candidate, 1)?;
    context.append_event(&mut state, item_read_draft(0x23))?;

    let witness = WitnessAuditLink {
        request_digest: digest(0x51),
        decision_digest: Some(digest(0x52)),
        receipt_digest: Some(digest(0x53)),
        policy_revision_hash: digest(0x12),
        revision_seal_id: RevisionSealId::from_bytes([0x33; 32])?,
    };
    context.append_event(
        &mut state,
        AuditEventDraft {
            timestamp_ms: 60,
            operation_id: witness.operation_id(),
            policy_sequence: 0,
            action: AuditAction::Verification,
            outcome: AuditOutcome::Success,
            item: Some(AuditItemScope {
                item_id: item_id(0x31),
                permitted_item_name: None,
            }),
            witness: Some(witness),
        },
    )?;
    context.record_receipt(
        &mut state,
        ReceiptUpdate::Transfer(TransferReceipt {
            transfer_id: digest(0x61),
            captured_public_revision_hash: digest(0x12),
            timestamp_ms: 61,
            output_digest: digest(0x62),
        }),
    )?;
    context.record_receipt(
        &mut state,
        ReceiptUpdate::Backup(BackupReceipt {
            backup_id: digest(0x63),
            captured_public_revision_hash: digest(0x12),
            timestamp_ms: 62,
            payload_digest: digest(0x64),
        }),
    )?;
    context.record_receipt(
        &mut state,
        ReceiptUpdate::BackupVerification(BackupVerificationReceipt {
            backup_id: digest(0x63),
            captured_public_revision_hash: digest(0x12),
            timestamp_ms: 63,
            payload_digest: digest(0x64),
        }),
    )?;
    context.record_receipt(
        &mut state,
        ReceiptUpdate::RestoreDrill(RestoreDrillReceipt {
            backup_id: digest(0x63),
            captured_public_revision_hash: digest(0x12),
            timestamp_ms: 64,
            output_digest: digest(0x65),
        }),
    )?;

    let files = context.serialize(&state)?;
    let combined = [files.audit(), files.checkpoint(), files.receipts()].concat();
    for forbidden in [
        b"ExamplePrivateItem".as_slice(),
        b"ExampleSecretValue".as_slice(),
        b"/Example/Private/Path".as_slice(),
        b"manifest".as_slice(),
        b"contribution".as_slice(),
    ] {
        assert!(
            !combined
                .windows(forbidden.len())
                .any(|window| window == forbidden)
        );
    }
    assert!(format!("{files:?}").contains("[REDACTED]"));

    let lines = files
        .audit()
        .split_inclusive(|byte| *byte == b'\n')
        .collect::<Vec<_>>();
    let mut changed_witness: Value = serde_json::from_slice(lines[2])?;
    changed_witness["witness"]["request_digest"] = serde_json::to_value(digest(0x54))?;
    let mut changed_audit = [lines[0], lines[1]].concat();
    changed_audit.extend_from_slice(&serde_json::to_vec(&changed_witness)?);
    changed_audit.push(b'\n');
    assert!(
        context
            .verify_files(
                Some(&changed_audit),
                Some(files.checkpoint()),
                Some(files.receipts())
            )
            .is_err()
    );

    let mut changed_receipts: Value = serde_json::from_slice(files.receipts())?;
    changed_receipts["latest_transfer"]["output_digest"] = serde_json::to_value(digest(0x66))?;
    assert!(
        context
            .verify_files(
                Some(files.audit()),
                Some(files.checkpoint()),
                Some(&pretty_json(&changed_receipts)?)
            )
            .is_err()
    );

    let verified = context.verify_files(
        Some(files.audit()),
        Some(files.checkpoint()),
        Some(files.receipts()),
    )?;
    assert_eq!(verified.audit().event_count, 3);
    assert_eq!(
        verified.audit().evidence_kind,
        AuditEvidenceKind::CurrentJuryV1Local
    );
    assert!(verified.audit().local_activity_only);
    assert!(!verified.audit().remote_freshness_verified);
    assert_eq!(verified.audit_events_after_checkpoint(), 0);
    assert_eq!(
        verified.checkpoint().accepted_public_revision_hash(),
        &digest(0x12)
    );
    assert_eq!(
        verified
            .receipts()
            .latest_backup()
            .map(|receipt| &receipt.backup_id),
        Some(&digest(0x63))
    );
    assert!(verified.receipts().latest_backup_verification().is_some());
    assert!(verified.receipts().latest_restore_drill().is_some());
    Ok(())
}

#[test]
fn authenticated_audit_tail_rebinds_without_duplicate_event()
-> Result<(), Box<dyn std::error::Error>> {
    let context = context();
    let candidate = candidate(context.scope(), &[(0, 0x12)]);
    let mut state = context.initialize(&candidate, 1)?;
    let before = context.serialize(&state)?;
    context.append_event(&mut state, item_read_draft(0x24))?;
    let after_intent = context.serialize(&state)?;

    let mut interrupted = context.verify_files(
        Some(after_intent.audit()),
        Some(before.checkpoint()),
        Some(before.receipts()),
    )?;
    assert_eq!(interrupted.audit_events_after_checkpoint(), 1);
    let event_count = interrupted.audit().event_count;
    context.accept_audit_tail(&mut interrupted, 40)?;
    assert_eq!(interrupted.audit_events_after_checkpoint(), 0);
    assert_eq!(interrupted.audit().event_count, event_count);

    let recovered = context.serialize(&interrupted)?;
    let verified = context.verify_files(
        Some(recovered.audit()),
        Some(recovered.checkpoint()),
        Some(recovered.receipts()),
    )?;
    assert_eq!(verified.audit_events_after_checkpoint(), 0);
    assert_eq!(verified.audit().event_count, event_count);
    Ok(())
}

#[test]
fn audit_rejects_edits_reordering_truncation_blank_lines_and_wrong_keys()
-> Result<(), Box<dyn std::error::Error>> {
    let context = context();
    let candidate = candidate(context.scope(), &[(0, 0x12)]);
    let mut state = context.initialize(&candidate, 1)?;
    context.append_event(&mut state, item_read_draft(0x23))?;
    let files = context.serialize(&state)?;

    let mut changed_checkpoint: Value = serde_json::from_slice(files.checkpoint())?;
    changed_checkpoint["updated_at_ms"] = Value::from(61_u64);
    assert!(
        context
            .verify_files(
                Some(files.audit()),
                Some(&pretty_json(&changed_checkpoint)?),
                Some(files.receipts())
            )
            .is_err()
    );

    let mut edited = files.audit().to_vec();
    let Some(position) = edited.iter().position(|byte| *byte == b'1') else {
        panic!("audit has no numeric version");
    };
    edited[position] = b'2';
    assert_eq!(
        context
            .verify_files(
                Some(&edited),
                Some(files.checkpoint()),
                Some(files.receipts())
            )
            .err()
            .map(LocalStateError::kind),
        Some(LocalStateErrorKind::AuditTampered)
    );

    let lines = files
        .audit()
        .split_inclusive(|byte| *byte == b'\n')
        .collect::<Vec<_>>();
    for damaged in [
        [lines[1], lines[0]].concat(),
        lines[0].to_vec(),
        [files.audit(), b"\n"].concat(),
        files.audit()[..files.audit().len() - 1].to_vec(),
    ] {
        assert!(
            context
                .verify_files(
                    Some(&damaged),
                    Some(files.checkpoint()),
                    Some(files.receipts())
                )
                .is_err()
        );
    }

    let wrong_key = PrincipalLocalState::from_test_seed(&[0x25; 32], scope())?;
    assert!(
        wrong_key
            .verify_files(
                Some(files.audit()),
                Some(files.checkpoint()),
                Some(files.receipts())
            )
            .is_err()
    );
    let mut wrong_scope = scope();
    wrong_scope.genesis_fingerprint = digest(0x26);
    let wrong_scope = PrincipalLocalState::from_test_seed(&[0x21; 32], wrong_scope)?;
    assert!(
        wrong_scope
            .verify_files(
                Some(files.audit()),
                Some(files.checkpoint()),
                Some(files.receipts())
            )
            .is_err()
    );
    for (checkpoint, receipts) in [
        (
            {
                let mut bytes = files.checkpoint().to_vec();
                bytes[1] ^= 1;
                bytes
            },
            files.receipts().to_vec(),
        ),
        (files.checkpoint().to_vec(), {
            let mut bytes = files.receipts().to_vec();
            bytes[1] ^= 1;
            bytes
        }),
    ] {
        assert!(
            context
                .verify_files(Some(files.audit()), Some(&checkpoint), Some(&receipts))
                .is_err()
        );
    }
    assert_eq!(
        context
            .verify_files(None, Some(files.checkpoint()), Some(files.receipts()))
            .err()
            .map(LocalStateError::kind),
        Some(LocalStateErrorKind::IncompleteState)
    );
    Ok(())
}

#[test]
fn crash_split_is_recoverable_only_when_audit_is_ahead_of_checkpoint()
-> Result<(), Box<dyn std::error::Error>> {
    let context = context();
    let candidate = candidate(context.scope(), &[(0, 0x12)]);
    let mut state = context.initialize(&candidate, 1)?;
    let before = context.serialize(&state)?;
    context.append_event(&mut state, item_read_draft(0x23))?;
    let after = context.serialize(&state)?;

    let recovered = context.verify_files(
        Some(after.audit()),
        Some(before.checkpoint()),
        Some(before.receipts()),
    )?;
    assert_eq!(recovered.audit_events_after_checkpoint(), 1);
    assert!(
        context
            .verify_files(
                Some(before.audit()),
                Some(after.checkpoint()),
                Some(after.receipts())
            )
            .is_err()
    );
    Ok(())
}

#[test]
fn checkpoint_accepts_only_equal_or_authenticated_descendant_history()
-> Result<(), Box<dyn std::error::Error>> {
    let context = context();
    let base = candidate(context.scope(), &[(0, 0x12)]);
    let mut state = context.initialize(&base, 1)?;
    assert_eq!(
        context.accept_candidate(&mut state, &base, 2)?,
        CheckpointRelation::Equal
    );

    let descendant = candidate(context.scope(), &[(0, 0x12), (1, 0x42)]);
    assert_eq!(
        context.accept_candidate(&mut state, &descendant, 3)?,
        CheckpointRelation::StrictDescendant
    );
    assert_eq!(
        state.checkpoint().accepted_public_revision_hash(),
        &digest(0x42)
    );

    for rejected in [
        candidate(context.scope(), &[(0, 0x12)]),
        candidate(context.scope(), &[(0, 0x12), (1, 0x52), (2, 0x53)]),
    ] {
        assert_eq!(
            context
                .accept_candidate(&mut state, &rejected, 4)
                .map_err(|error| error.kind()),
            Err(LocalStateErrorKind::CheckpointDiverged)
        );
    }
    assert_eq!(
        state.checkpoint().accepted_public_revision_hash(),
        &digest(0x42)
    );
    Ok(())
}

#[test]
fn frozen_local_kdf_and_mac_vectors_match_exact_preimages() -> Result<(), Box<dyn std::error::Error>>
{
    let corpus: Value = serde_json::from_str(include_str!(
        "../../../docs/security/vectors/jury-v1-suite.json"
    ))?;
    let decode = |value: &Value| -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        Ok(hex::decode(value.as_str().ok_or("expected hex string")?)?)
    };
    let fixed = |value: &Value| -> Result<[u8; 32], Box<dyn std::error::Error>> {
        Ok(decode(value)?.try_into().map_err(|_| "expected 32 bytes")?)
    };
    let identifiers = &corpus["fixture_identifiers"];
    let vector_scope = LocalStateScope {
        vault_id: VaultId::from_bytes(fixed(&identifiers["ExampleVault"])?)?,
        genesis_fingerprint: Digest32::new(fixed(&Value::String(
            "7c8d7ba1b6bdb4e5808f62b0625923165bd6c3adc0461c9d8b9baf4cc08cb1be".into(),
        ))?),
        principal_id: PrincipalId::from_bytes(fixed(&identifiers["ExamplePrincipalOwner"])?)?,
    };
    let hkdf = &corpus["hkdf_sha256"];
    let seed = fixed(&hkdf["kdf_audit_mac"]["ikm_hex"])?;
    let context = PrincipalLocalState::from_test_seed(&seed, vector_scope.clone())?;
    for (key, protected) in [
        ("kdf_audit_mac", &context.audit_key),
        ("kdf_checkpoint_mac", &context.checkpoint_key),
        ("kdf_receipt_mac", &context.receipts_key),
    ] {
        let expected_info = decode(&corpus["preimages"][key]["hex"])?;
        assert_eq!(
            key_info(
                corpus["preimages"][key]["domain"]
                    .as_str()
                    .ok_or("domain")?,
                &vector_scope
            ),
            expected_info
        );
        let expected_key = decode(&hkdf[key]["output_hex"])?;
        assert!(protected.expose(|bytes| bytes == expected_key)?);
    }

    let item = AuditItemScope {
        item_id: ItemId::from_bytes(fixed(&identifiers["ExampleSecret"])?)?,
        permitted_item_name: Some("ExampleSecret".into()),
    };
    let operation_id = fixed(&Value::String(
        "1055902e7ad146e703e6f65e09928375466692462394659331481dc464dd07f2".into(),
    ))?;
    let previous_mac = fixed(&Value::String(
        "2d8a0eaf7c883b84d39329291385920419052e3d949d245a524486bd97d4d082".into(),
    ))?;
    let audit_preimage = audit::event_mac_preimage(
        1,
        vector_scope.principal_id.as_bytes(),
        vector_scope.vault_id.as_bytes(),
        vector_scope.genesis_fingerprint.as_bytes(),
        1,
        &operation_id,
        AuditAction::ItemRead,
        Some(&item),
        AuditOutcome::Success,
        &previous_mac,
    );
    assert_eq!(
        audit_preimage,
        decode(&corpus["preimages"]["audit_event_mac"]["hex"])?
    );
    assert_eq!(
        crypto::hmac_sha256(&context.audit_key, &audit_preimage)?.as_slice(),
        decode(&corpus["hmac_sha256"]["audit_event_mac"]["tag_hex"])?.as_slice()
    );

    let accepted = Digest32::new(fixed(&Value::String(
        "e266d32a691590b70db12f01c13fbf36c5bcc75287c6e832c6eb8c19ddf8bcc4".into(),
    ))?);
    let latest = Digest32::new(fixed(&corpus["hmac_sha256"]["audit_event_mac"]["tag_hex"])?);
    let genesis = Digest32::new(fixed(&Value::String(
        "b4753c79338be5c14961bf700a701cc1860e39a2bcfd732a04c030f7317307e6".into(),
    ))?);
    let checkpoint_preimage = checkpoint::checkpoint_mac_preimage(
        1,
        &vector_scope,
        &accepted,
        &latest,
        &genesis,
        0x6b49_d203,
    );
    assert_eq!(
        checkpoint_preimage,
        decode(&corpus["preimages"]["checkpoint_file_mac"]["hex"])?
    );
    assert_eq!(
        crypto::hmac_sha256(&context.checkpoint_key, &checkpoint_preimage)?.as_slice(),
        decode(&corpus["hmac_sha256"]["checkpoint_file_mac"]["tag_hex"])?.as_slice()
    );

    let transfer = TransferReceipt {
        transfer_id: Digest32::new(operation_id),
        captured_public_revision_hash: accepted,
        timestamp_ms: 0x6b49_d204,
        output_digest: Digest32::new(fixed(&Value::String(
            "6c04869f2ea8ade884dec08b74e56bd8f240e744aaf077a1d0f4cc3dee8736cb".into(),
        ))?),
    };
    let receipt_preimage = receipts::receipt_mac_preimage(
        1,
        &vector_scope,
        vec![receipts::ReceiptEntry::from_transfer(&transfer)],
    );
    assert_eq!(
        receipt_preimage,
        decode(&corpus["preimages"]["receipt_file_mac"]["hex"])?
    );
    assert_eq!(
        crypto::hmac_sha256(&context.receipts_key, &receipt_preimage)?.as_slice(),
        decode(&corpus["hmac_sha256"]["receipt_file_mac"]["tag_hex"])?.as_slice()
    );
    Ok(())
}
