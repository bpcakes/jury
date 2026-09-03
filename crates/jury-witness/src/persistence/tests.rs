#[cfg(test)]
mod tests {
    use std::{error::Error, fs, os::unix::fs::PermissionsExt as _};

    use jury_core::witness_engine::WitnessStateStore as _;
    use jury_protocol::{
        vault_v1::{Digest32, PrincipalId, Signature64},
        witness_v1::WitnessStateAnchorV1,
    };

    use super::state_codec::{StateCodecError, encode_json_bounded};
    use super::*;

    type TestResult = Result<(), Box<dyn Error>>;

    fn anchor(witness_id: PrincipalId, generation: u64) -> WitnessStateAnchorV1 {
        WitnessStateAnchorV1 {
            schema: 1,
            witness_id,
            witness_signing_key_fingerprint: Digest32::new([2; 32]),
            witness_signing_key_epoch: 1,
            state_generation: generation,
            database_state_digest: Digest32::new([3; 32]),
            vault_high_watermarks: Vec::new(),
            replay_retain_through_ms: 0,
            last_accepted_wall_time_ms: 1,
            predecessor_anchor_digest: Digest32::new([0; 32]),
            issued_at_ms: 1,
            signature: Signature64::new([4; 64]),
        }
    }

    #[test]
    fn witness_store_commits_and_marks_one_pending_candidate() -> TestResult {
        let directory = tempfile::tempdir()?;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
        let path = directory.path().join("witness.sqlite3");
        let witness_id = PrincipalId::from_bytes([1; 32])?;
        SqliteWitnessStore::initialize(&path, witness_id)?;
        let mut store = SqliteWitnessStore::open(&path, witness_id)?;
        let mut replacement = PersistedWitnessState::empty(witness_id);
        replacement.logical.state_generation = 1;
        let candidate = anchor(witness_id, 1);
        let digest = candidate.digest()?;
        replacement.pending_anchor = Some(candidate.clone());

        store
            .commit(0, replacement)
            .map_err(|_| "store commit failed")?;
        assert_eq!(
            store
                .load()
                .map_err(|_| "store load failed")?
                .pending_anchor,
            Some(candidate.clone())
        );
        store
            .mark_anchor_published(&digest)
            .map_err(|_| "store mark failed")?;
        let published = store.load().map_err(|_| "store load failed")?;
        assert_eq!(published.pending_anchor, None);
        assert_eq!(published.published_anchor, Some(candidate));
        assert_eq!(published.logical.state_generation, 1);
        Ok(())
    }

    #[test]
    fn backup_and_restore_are_validated_atomic_and_no_clobber() -> TestResult {
        let directory = tempfile::tempdir()?;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
        let source = directory.path().join("source.sqlite3");
        let backup = directory.path().join("backup.sqlite3");
        let restored = directory.path().join("restored.sqlite3");
        let witness_id = PrincipalId::from_bytes([5; 32])?;
        SqliteWitnessStore::initialize(&source, witness_id)?;

        backup_witness_database(&source, &backup)?;
        assert_eq!(
            backup_witness_database(&source, &backup)
                .err()
                .ok_or("backup overwrite should fail")?
                .kind(),
            AdapterErrorKind::TargetExists
        );
        restore_witness_database(&backup, &restored)?;
        assert_eq!(
            SqliteWitnessStore::open(&restored, witness_id)?
                .load_validated()?
                .logical
                .state_generation,
            0
        );
        assert_eq!(
            restore_witness_database(&backup, &restored)
                .err()
                .ok_or("restore overwrite should fail")?
                .kind(),
            AdapterErrorKind::TargetExists
        );
        Ok(())
    }

    #[test]
    fn offline_audit_is_value_free_and_never_claims_external_freshness() -> TestResult {
        let directory = tempfile::tempdir()?;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
        let path = directory.path().join("witness.sqlite3");
        let witness_id = PrincipalId::from_bytes([6; 32])?;
        SqliteWitnessStore::initialize(&path, witness_id)?;
        drop(SqliteWitnessStore::open(&path, witness_id)?);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o400))?;
        let before_bytes = fs::read(&path)?;
        let before_mode = fs::metadata(&path)?.permissions().mode();
        let wal = path.with_file_name("witness.sqlite3-wal");
        let shared_memory = path.with_file_name("witness.sqlite3-shm");
        assert!(!wal.exists());
        assert!(!shared_memory.exists());

        let snapshot = audit_witness_database(&path, witness_id)?;
        assert_eq!(snapshot.scope, "offline-witness-database-only");
        assert!(!snapshot.external_anchor_compared);
        assert!(!snapshot.contribution_readiness_claimed);
        let encoded = serde_json::to_vec(&snapshot)?;
        for forbidden in [
            b"policy_material".as_slice(),
            b"accepted_registration".as_slice(),
            b"request_signature_preimage".as_slice(),
            b"approval_decisions".as_slice(),
            b"contribution_envelope".as_slice(),
            b"passphrase".as_slice(),
        ] {
            assert!(
                !encoded
                    .windows(forbidden.len())
                    .any(|window| window == forbidden)
            );
        }
        assert_eq!(fs::read(&path)?, before_bytes);
        assert_eq!(fs::metadata(&path)?.permissions().mode(), before_mode);
        assert!(!wal.exists());
        assert!(!shared_memory.exists());

        fs::write(&wal, b"uncheckpointed-wal-placeholder")?;
        assert!(audit_witness_database(&path, witness_id).is_err());
        assert_eq!(fs::read(&wal)?, b"uncheckpointed-wal-placeholder");
        Ok(())
    }

    #[test]
    fn initialization_and_open_are_distinct_lifecycle_operations() -> TestResult {
        let directory = tempfile::tempdir()?;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
        let path = directory.path().join("witness.sqlite3");
        let witness_id = PrincipalId::from_bytes([9; 32])?;

        assert!(SqliteWitnessStore::open(&path, witness_id).is_err());
        assert!(!path.exists());
        SqliteWitnessStore::initialize(&path, witness_id)?;
        assert_eq!(
            SqliteWitnessStore::initialize(&path, witness_id)
                .err()
                .ok_or("reinitialization should fail")?
                .kind(),
            AdapterErrorKind::TargetExists
        );
        assert_eq!(
            SqliteWitnessStore::open(&path, witness_id)?
                .load_validated()?
                .logical
                .state_generation,
            0
        );
        Ok(())
    }

    #[test]
    fn persisted_state_encoding_and_loading_have_hard_byte_caps() -> TestResult {
        let compact =
            encode_json_bounded(&vec!["abcd"], 16).map_err(|_| "small state should serialize")?;
        assert_eq!(compact, br#"["abcd"]"#);
        assert_eq!(
            encode_json_bounded(&vec!["abcd"], 7),
            Err(StateCodecError::CapacityExhausted)
        );
        assert_eq!(
            validate_state_length((MAX_PERSISTED_WITNESS_STATE_BYTES + 1) as i64)
                .err()
                .ok_or("oversized persisted state should fail before loading")?
                .kind(),
            AdapterErrorKind::CapacityExhausted
        );
        Ok(())
    }

    #[test]
    fn database_lock_wait_cannot_outlive_the_operation_deadline() -> TestResult {
        let directory = tempfile::tempdir()?;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
        let path = directory.path().join("witness.sqlite3");
        let witness_id = PrincipalId::from_bytes([10; 32])?;
        SqliteWitnessStore::initialize(&path, witness_id)?;
        let mut store = SqliteWitnessStore::open(&path, witness_id)?;
        let blocker = Connection::open(&path)?;
        blocker.execute_batch("BEGIN IMMEDIATE")?;
        let mut replacement = PersistedWitnessState::empty(witness_id);
        replacement.logical.state_generation = 1;
        replacement.pending_anchor = Some(anchor(witness_id, 1));

        store.deadline = Some(Instant::now() + Duration::from_millis(100));
        let started = Instant::now();
        assert!(store.commit(0, replacement).is_err());
        assert!(started.elapsed() < Duration::from_secs(1));
        blocker.execute_batch("ROLLBACK")?;
        assert_eq!(
            SqliteWitnessStore::open(&path, witness_id)?
                .load_validated()?
                .logical
                .state_generation,
            0
        );
        Ok(())
    }
}
