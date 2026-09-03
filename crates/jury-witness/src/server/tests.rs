#[cfg(test)]
mod tests {
    use std::{error::Error, net::IpAddr, os::unix::fs::PermissionsExt as _, time::Instant};

    use jury_protocol::witness_v1::WitnessStateAnchorV1;

    use super::*;

    #[test]
    fn rate_buckets_are_bounded_per_source_address() {
        let gate = GateState::new(&TransportLimits {
            maximum_request_bytes: 1024,
            maximum_concurrency: 1,
            requests_per_second: 1,
            burst_requests: 2,
            request_timeout_ms: 100,
            shutdown_grace_ms: 100,
        });
        let first = IpAddr::from([192, 0, 2, 1]);
        let second = IpAddr::from([192, 0, 2, 2]);

        assert!(gate.allow(first));
        assert!(gate.allow(first));
        assert!(!gate.allow(first));
        assert!(gate.allow(second));
    }

    #[test]
    fn principal_path_parser_accepts_only_canonical_lowercase_ids() {
        let canonical = "ab".repeat(32);
        assert_eq!(
            parse_principal_id(&canonical).map(|id| id.as_bytes()[0]),
            Ok(0xab)
        );
        assert!(parse_principal_id(&canonical.to_uppercase()).is_err());
        assert!(parse_principal_id(&canonical[..62]).is_err());
    }

    #[test]
    fn readiness_probe_allows_only_one_in_flight_check() -> Result<(), Box<dyn Error>> {
        let probe = Arc::new(ReadinessProbe::new());
        let first = probe.acquire().ok_or("first probe should own refresh")?;
        assert!(probe.acquire().is_none());
        assert!(!probe.last_ready());
        first.finish(true);
        drop(first);
        assert!(probe.last_ready());
        assert!(probe.acquire().is_some());
        Ok(())
    }

    #[tokio::test]
    async fn anchor_work_runs_on_the_deadline_aware_owner_thread() -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
        let path = directory.path().join("anchor.sqlite3");
        let witness_id = PrincipalId::from_bytes([11; 32])?;
        SqliteAnchorRepository::initialize(&path)?;
        let repository = SqliteAnchorRepository::open(&path, witness_id)?;
        let worker = AnchorRepositoryWorker::spawn(repository, 1)?;
        let handle = worker.handle();
        let blocker = rusqlite::Connection::open(&path)?;
        blocker.execute_batch("BEGIN IMMEDIATE")?;
        let candidate = WitnessStateAnchorV1 {
            schema: 1,
            witness_id,
            witness_signing_key_fingerprint: jury_protocol::vault_v1::Digest32::new([2; 32]),
            witness_signing_key_epoch: 1,
            state_generation: 1,
            database_state_digest: jury_protocol::vault_v1::Digest32::new([3; 32]),
            vault_high_watermarks: Vec::new(),
            replay_retain_through_ms: 0,
            last_accepted_wall_time_ms: 1,
            predecessor_anchor_digest: jury_protocol::vault_v1::Digest32::new([0; 32]),
            issued_at_ms: 1,
            signature: jury_protocol::vault_v1::Signature64::new([4; 64]),
        };

        let started = Instant::now();
        assert!(
            handle
                .compare_and_swap(
                    OperationDeadline::after(Duration::from_millis(100)),
                    None,
                    candidate,
                )
                .await
                .is_err()
        );
        assert!(started.elapsed() < Duration::from_secs(1));
        blocker.execute_batch("ROLLBACK")?;
        assert_eq!(
            handle
                .read(OperationDeadline::after(Duration::from_secs(1)))
                .await?,
            None
        );
        handle
            .check_ready(OperationDeadline::after(Duration::from_secs(1)))
            .await?;
        worker.shutdown()?;
        Ok(())
    }
}
