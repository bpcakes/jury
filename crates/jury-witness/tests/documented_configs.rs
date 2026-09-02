#![cfg(target_os = "linux")]

use jury_witness::config::{AnchorServiceConfig, WitnessServiceConfig};

#[test]
fn checked_in_linux_configs_match_the_strict_schema_and_separation_contract()
-> Result<(), serde_json::Error> {
    let witness: WitnessServiceConfig =
        serde_json::from_str(include_str!("../../../deploy/juryd/witness.example.json"))?;
    let anchor: AnchorServiceConfig =
        serde_json::from_str(include_str!("../../../deploy/juryd/anchor.example.json"))?;

    assert!(!witness.tls.allow_insecure_loopback);
    assert!(!witness.external_anchor.allow_insecure_loopback);
    assert!(!anchor.tls.allow_insecure_loopback);
    assert_eq!(witness.witness_id, anchor.witness_id);
    assert_eq!(witness.external_anchor.authority, anchor.database.authority);
    assert_eq!(
        witness.external_anchor.write_authority,
        anchor.write_authority
    );
    assert_ne!(witness.database.authority, anchor.database.authority);
    assert_ne!(
        witness.database.authority.failure_domain,
        anchor.database.authority.failure_domain
    );
    Ok(())
}
