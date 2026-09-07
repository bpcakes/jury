use super::*;
use jury_core::rollover::{
    GovernedRolloverDraft, GovernedRolloverOptions, PreparedGovernedRollover,
};

mod access;
mod proofs;
#[cfg(test)]
pub(in crate::cli) use proofs::exercise_polling_repair;

pub(super) fn preflight_directory(path: &Path) -> Result<HardenedStateRoot, CliError> {
    let parent =
        HardenedStateRoot::open_existing(path.parent().ok_or_else(rollover_target_error)?, &[])
            .map_err(map_filesystem_error)?;
    if parent
        .private_child_exists(Path::new(
            path.file_name().ok_or_else(rollover_target_error)?,
        ))
        .map_err(map_filesystem_error)?
    {
        return Err(CliError::new(
            CliErrorKind::Conflict,
            "rollover-registration-directory-exists",
            "--registration-dir already exists; if preparation ended before publication, retain it for explicit cleanup and choose a new absent registration directory for fresh preparation; --resume requires a saved destination candidate",
        ));
    }
    Ok(parent)
}

pub(super) fn prepare(
    source: &RolloverSource<'_>,
    context: &VaultPrincipalContext,
    arguments: &VaultRolloverArgs,
    migration: Option<VaultSuite>,
    now_ms: u64,
    protection: ProtectionPolicy,
) -> Result<GovernedRolloverDraft, CliError> {
    if !arguments.dry_run && arguments.registration_dir.is_none() {
        return Err(registration_required());
    }
    let catalog = context.catalog.transfer_catalog(&context.vault)?;
    let mut provider = access::RolloverAccess::new(context, arguments, protection)?;
    let options = GovernedRolloverOptions {
        created_at_ms: now_ms,
        registration_lifetime_ms: 86_400_000,
        protection,
    };
    let result = if let Some(suite) = migration {
        source.prepare_governed_migration(
            suite,
            &catalog,
            &context.identity,
            &mut provider,
            options,
            &NeverCancelled,
        )
    } else {
        source.prepare_governed(
            &catalog,
            &context.identity,
            &mut provider,
            options,
            &NeverCancelled,
        )
    }
    .map_err(map_rollover_error);
    provider.finish()?;
    let mut draft = result?;
    draft
        .renew_registration_challenges(&context.identity, timestamp_ms()?, 86_400_000)
        .map_err(map_rollover_error)?;
    Ok(draft)
}

pub(super) fn complete(
    source: &RolloverSource<'_>,
    context: &VaultPrincipalContext,
    arguments: &VaultRolloverArgs,
    draft: GovernedRolloverDraft,
    protection: ProtectionPolicy,
) -> Result<PreparedGovernedRollover, CliError> {
    let path = arguments
        .registration_dir
        .as_ref()
        .ok_or_else(registration_required)?;
    let parent = preflight_directory(path)?;
    let root = parent
        .create_private_child_new(Path::new(
            path.file_name().ok_or_else(rollover_target_error)?,
        ))
        .map_err(map_filesystem_error)?;
    for challenge in draft.challenges() {
        let name = format!(
            "{}.challenge.json",
            hex(challenge.candidate_descriptor.principal_id.as_bytes())
        );
        registration::publish_private(
            &root,
            &name,
            &challenge
                .to_json_bytes()
                .map_err(|error| map_registration_error(error.kind()))?,
            protection,
        )?;
    }
    // Publish the authenticated context last. A candidate observing the journal
    // must also be able to read its already durable matching challenge.
    registration::publish_private(
        &root,
        "journal.json",
        &serde_json::to_vec(draft.registration_journal()).map_err(|_| invalid_vault())?,
        protection,
    )?;
    let genesis = draft
        .registration_journal()
        .genesis
        .recomputed_fingerprint()
        .map_err(|_| invalid_vault())?;
    writeln!(std::io::stderr().lock(), "Rollover draft genesis: {}. Each candidate must authenticate journal.json against the source and this expected genesis, then write <principal-id>.proof.json into --registration-dir.", hex(genesis.as_bytes())).map_err(|_| filesystem_error())?;
    let deadline = std::time::Instant::now()
        + std::time::Duration::from_secs(arguments.registration_wait_seconds);
    let mut polling = proofs::ProofPoll::default();
    loop {
        let now = timestamp_ms()?;
        if let Some(proofs) = polling.read(&root, &draft, &context.identity, now)? {
            return draft
                .complete(
                    source,
                    &context.catalog.transfer_catalog(&context.vault)?,
                    &context.identity,
                    proofs,
                    now,
                    &NeverCancelled,
                )
                .map_err(map_rollover_error);
        }
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            return Err(polling.error());
        }
        std::thread::sleep(polling.delay().min(remaining));
    }
}

pub(super) fn preview(
    source: &RolloverSource<'_>,
    context: &VaultPrincipalContext,
    arguments: &VaultRolloverArgs,
    destination_suite: VaultSuite,
    protection: ProtectionPolicy,
) -> Result<CommandOutput, CliError> {
    let catalog = context.catalog.transfer_catalog(&context.vault)?;
    for proof in &catalog.registration_proofs {
        source
            .source_registration_role(&catalog, proof.candidate_principal_id)
            .map_err(map_rollover_error)?;
    }
    let access = access::RolloverAccess::new(context, arguments, protection)?;
    access.preflight_requests()?;
    Ok(CommandOutput::Safe {
        operation: if destination_suite.id() == context.policy.suite() { "vault-rollover" } else { "vault-migrate-suite" }, fields: serde_json::json!({
            "source_suite": context.policy.suite(), "destination_suite": destination_suite.id(),
            "dry_run": true, "published": false, "source_access_validated": false,
            "role_proofs_required": catalog.registration_proofs.len(), "registration_pending": true,
            "backup_published": false, "transfer_published": false, "local_owner_adopted": false,
            "witness_registration_checked": false, "destination_ready": false,
        }), lines: vec!["Governed public source and Recovery request preflight passed. Source access, fresh role proofs, destination witness registration, backup and publication remain required. No witness request was sent or destination published.".into()],
    })
}

fn registration_required() -> CliError {
    CliError::new(
        CliErrorKind::Conflict,
        "rollover-registration-required",
        "governed rollover requires an absent --registration-dir and fresh valid candidate proofs before the configured wait expires; no complete destination has been published",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    #[test]
    fn abandoned_registration_directory_has_an_actionable_retry_error()
    -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        std::fs::set_permissions(temporary.path(), std::fs::Permissions::from_mode(0o700))?;
        let path = temporary.path().join("ExampleRegistration");
        preflight_directory(&path)?;
        std::fs::create_dir(&path)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))?;
        std::fs::write(path.join("journal.json"), b"ExampleAbandonedDraft")?;
        let error = preflight_directory(&path)
            .err()
            .ok_or("occupied registration accepted")?;
        assert_eq!(error.code(), "rollover-registration-directory-exists");
        assert!(error.to_string().contains("--registration-dir"));
        assert!(path.join("journal.json").exists());
        preflight_directory(&temporary.path().join("ExampleFreshRegistration"))?;
        Ok(())
    }
}
