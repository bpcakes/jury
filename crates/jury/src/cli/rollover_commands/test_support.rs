use super::*;
use std::{fs, os::unix::fs::PermissionsExt as _};
type TestResult<T> = Result<T, Box<dyn std::error::Error>>;
const PROTECTION: ProtectionPolicy = ProtectionPolicy::EmergencyAllowDegraded;

pub(super) fn context(root: &Path) -> TestResult<VaultPrincipalContext> {
    let passphrase = protect(b"ExamplePassphrase", PROTECTION)?;
    let created = IdentityCreator::new().create(
        PrincipalKind::Human,
        KdfProfile::PortableV1,
        1,
        &passphrase,
        |_| false,
    )?;
    let UnlockedIdentity::VaultPrincipal(identity) = unlock(&created.file, &passphrase)? else {
        return Err("unexpected identity".into());
    };
    let created = PolicyCreator::new().create(&identity, 2, |_| false)?;
    let vault = VaultFileV1 {
        header: VaultHeaderV1 {
            magic: "jury-vault".into(),
            version: 1,
            vault_id: created.state.vault_id(),
            created_at_ms: 2,
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
    let path = root.join("ExampleVault");
    fs::create_dir(&path)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
    fs::write(path.join("vault.json"), vault.to_json_bytes()?)?;
    fs::set_permissions(path.join("vault.json"), fs::Permissions::from_mode(0o600))?;
    let home = VaultHomeLocation::Detached {
        path,
        source: HomeSource::Explicit,
    };
    let local = PrincipalLocalState::for_vault_principal(
        &identity,
        vault.header.vault_id,
        vault.header.genesis_fingerprint.clone(),
    )?;
    let candidate =
        CheckpointCandidate::from_validated(&created.state, &vault.policy, &vault.items)?;
    let state = initialize_principal_state(PrincipalStateInitialization {
        state_root: &root.join("ExampleState"),
        home: &home,
        vault: &vault,
        local: &local,
        candidate: &candidate,
        principal_id: &identity.principal_id(),
        timestamp: 3,
        protection: PROTECTION,
    })?;
    Ok(VaultPrincipalContext {
        home,
        vault,
        policy: created.state,
        catalog_before: PolicyCatalogV1::empty(),
        catalog_before_bytes: None,
        catalog: PolicyCatalogV1::empty(),
        identity,
        state,
        local,
        protection_degraded: true,
    })
}
