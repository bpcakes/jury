use super::*;
use std::fs;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const PROTECTION: ProtectionPolicy = ProtectionPolicy::EmergencyAllowDegraded;

fn descendant(
    context: &VaultPrincipalContext,
    label: &str,
) -> TestResult<(VaultFileV1, PolicyState)> {
    let prepared = context.policy.prepare_revision(
        &context.identity,
        4,
        vec![PolicyOperationV1::PrincipalLabelChange {
            principal_id: context.identity.principal_id(),
            prior_label: context
                .policy
                .principal(&context.identity.principal_id())
                .ok_or("missing owner")?
                .display_label
                .clone(),
            next_label: label.into(),
        }],
    )?;
    let mut vault = context.vault.clone();
    vault.policy.revisions.push(prepared.revision);
    Ok((vault, prepared.state))
}

#[test]
fn publication_reauthenticates_shared_checkpoint_and_retains_lock() -> TestResult {
    let temporary = tempfile::tempdir()?;
    let mut context = super::super::test_support::context(temporary.path())?;
    let source_bytes = read_vault(&context.home)?;
    let guard = lock_current_source(&context, &source_bytes)?;
    assert!(
        context.state.try_lock().is_err(),
        "publication must retain the source lock"
    );
    drop(guard);
    let (newer, policy) = descendant(&context, "ExampleNewOwner")?;
    let (fork, fork_policy) = descendant(&context, "ExampleForkOwner")?;
    // Another clone accepts a signed descendant in the shared state directory;
    // the selected source worktree and prepared context remain unchanged.
    let candidate = CheckpointCandidate::from_validated(&policy, &newer.policy, &newer.items)?;
    advance_principal_checkpoint(
        &context.state,
        &context.local,
        &candidate,
        &context.identity.principal_id(),
        5,
        PROTECTION,
    )?;
    assert_eq!(read_vault(&context.home)?, source_bytes);
    let error = lock_current_source(&context, &source_bytes)
        .err()
        .ok_or("stale source accepted")?;
    assert_eq!(error.code(), checkpoint_conflict().code());
    assert!(
        context.state.try_lock().is_ok(),
        "refusal must release the lock"
    );
    let VaultHomeLocation::Detached { path, .. } = &context.home else {
        return Err("unexpected home".into());
    };
    let path = path.join("vault.json");
    context.vault = fork;
    context.policy = fork_policy;
    let fork_bytes = context.vault.to_json_bytes()?;
    fs::write(&path, &fork_bytes)?;
    assert_eq!(
        lock_current_source(&context, &fork_bytes)
            .err()
            .ok_or("fork accepted")?
            .code(),
        checkpoint_conflict().code()
    );
    context.vault = newer;
    context.policy = policy;
    let current_bytes = context.vault.to_json_bytes()?;
    fs::write(&path, &current_bytes)?;
    drop(lock_current_source(&context, &current_bytes)?);
    assert_eq!(
        lock_current_source(&context, &source_bytes)
            .err()
            .ok_or("changed source accepted")?
            .code(),
        checkpoint_conflict().code()
    );
    Ok(())
}

#[test]
fn publication_authenticates_all_local_files_and_accepts_valid_audit_tail() -> TestResult {
    let temporary = tempfile::tempdir()?;
    let context = super::super::test_support::context(temporary.path())?;
    let source_bytes = read_vault(&context.home)?;
    let candidate =
        CheckpointCandidate::from_validated(&context.policy, &context.vault.policy, &[])?;
    let mut verified = context.local.initialize(&candidate, 3)?;
    let before = context.local.serialize(&verified)?;
    context.local.append_event(
        &mut verified,
        AuditEventDraft {
            timestamp_ms: 4,
            operation_id: Digest32::new([7; 32]),
            policy_sequence: 0,
            action: AuditAction::Verification,
            outcome: AuditOutcome::Success,
            item: None,
            witness: None,
        },
    )?;
    let after = context.local.serialize(&verified)?;
    let locked = context.state.try_lock()?;
    require_synced(
        locked
            .prepare(
                context.identity.principal_id().as_bytes(),
                PrincipalStateFile::Audit,
                &protect(after.audit(), PROTECTION)?,
            )?
            .publish()?,
    )?;
    drop(locked);
    drop(lock_current_source(&context, &source_bytes)?);
    for (kind, valid) in [
        (PrincipalStateFile::Audit, after.audit()),
        (PrincipalStateFile::Checkpoint, before.checkpoint()),
        (PrincipalStateFile::Receipts, before.receipts()),
    ] {
        let locked = context.state.try_lock()?;
        require_synced(
            locked
                .prepare(
                    context.identity.principal_id().as_bytes(),
                    kind,
                    &protect(b"{}", PROTECTION)?,
                )?
                .publish()?,
        )?;
        drop(locked);
        assert!(lock_current_source(&context, &source_bytes).is_err());
        let locked = context.state.try_lock()?;
        require_synced(
            locked
                .prepare(
                    context.identity.principal_id().as_bytes(),
                    kind,
                    &protect(valid, PROTECTION)?,
                )?
                .publish()?,
        )?;
    }
    drop(lock_current_source(&context, &source_bytes)?);
    Ok(())
}
