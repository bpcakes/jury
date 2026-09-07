fn preview_after_bootstrap_role_removal(
    context: &ApprovalRunContext<'_>, home: &Path,
    catalog: &jury_core::transfer::TransferPublicCatalogV1,
) -> TestResult {
    let UnlockedIdentity::VaultPrincipal(owner) = unlock_named_identity(context.data, "default", OWNER_PASSPHRASE)? else {
        return Err("unexpected owner".into());
    };
    let path = home.join("vault.json");
    let mut vault = VaultFileV1::parse(&fs::read(&path)?)?;
    let policy = jury_core::policy::replay_policy_with_witness_policies(&vault.policy, &catalog.witness_policies)?;
    let removed = catalog.registration_proofs[0].candidate_principal_id;
    let mut operations = policy.items().map(|(id, item)| jury_protocol::vault_v1::PolicyOperationV1::ItemDelete {
        item_id: *id, final_descriptor_digest: item.descriptor.ciphertext_digest.clone(),
        final_item_revision_hash: item.current_item_revision_hash.clone(), deletion_policy_sequence: policy.sequence() + 1,
    }).collect::<Vec<_>>();
    operations.push(jury_protocol::vault_v1::PolicyOperationV1::PrincipalRemove {
        principal_id: removed, removal_reason: jury_protocol::vault_v1::RemovalReason::Retirement,
    });
    // Construct a real signed descendant. Historical role proofs remain in the
    // destination's local catalog while no live items require remote access.
    vault.policy.revisions.push(policy.prepare_revision(&owner, now_ms()?, operations)?.revision);
    vault.items.clear();
    fs::write(&path, vault.to_json_bytes()?)?;
    let portable = catalog.for_vault(&vault)?;
    assert_eq!(portable.registration_proofs.len(), catalog.registration_proofs.len());
    let source = jury_core::rollover::RolloverSource::validate(&vault, &catalog.witness_policies)?;
    let out = home.parent().ok_or("missing parent")?.join("ExampleNextVault");
    let backup = home.parent().ok_or("missing parent")?.join("ExampleOffline/ExampleNextBackup");
    let transfer = home.parent().ok_or("missing parent")?.join("ExampleNextTransfer");
    let preview = success_json(run(context.repository, context.data, context.state,
        &["--json", "--home", home.to_str().ok_or("invalid home")?, "--passphrase-stdin", "--allow-degraded-protection",
          "vault", "rollover", "--dry-run", "--out", out.to_str().ok_or("invalid output")?,
          "--backup-out", backup.to_str().ok_or("invalid backup")?, "--transfer-out", transfer.to_str().ok_or("invalid transfer")?],
        format!("{OWNER_PASSPHRASE}\n").as_bytes())?)?;
    let draft = source.prepare_governed(&portable, &owner, &mut jury_core::access_provider::DirectItemAccessProvider::new(&owner),
        jury_core::rollover::GovernedRolloverOptions { created_at_ms: now_ms()?, registration_lifetime_ms: 86_400_000,
            protection: ProtectionPolicy::EmergencyAllowDegraded }, &jury_core::access_provider::NeverCancelled)?;
    assert_eq!(preview["role_proofs_required"], 2);
    assert_eq!(preview["role_proofs_required"], draft.challenges().len());
    assert!(draft.challenges().iter().all(|challenge| challenge.candidate_descriptor.principal_id != removed));
    assert!(!out.exists() && !backup.exists() && !transfer.exists());
    Ok(())
}
