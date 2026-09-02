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

#[test]
fn checked_in_systemd_units_create_owner_only_state_directories() {
    for unit in [
        include_str!("../../../deploy/juryd/juryd.service"),
        include_str!("../../../deploy/juryd/juryd-anchor.service"),
    ] {
        assert!(unit.lines().any(|line| line == "StateDirectoryMode=0700"));
    }
}
