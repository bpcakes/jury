use jury_core::domain::{
    Capability, Grant, ItemId, ItemRevision, ItemRole, KeyEpoch, PolicyRevision, PrincipalId,
    RevisionError, Role,
};

#[test]
fn roles_and_grants_make_scope_constraints_unrepresentable()
-> Result<(), Box<dyn std::error::Error>> {
    let principal_id = PrincipalId::from_bytes([0x21; 32])?;
    let item_id = ItemId::from_bytes([0x31; 32])?;
    let owner = Grant::VaultOwner { principal_id };
    let writer = Grant::Item {
        principal_id,
        item_id,
        role: ItemRole::Writer,
    };

    assert_eq!(owner.role(), Role::Owner);
    assert_eq!(writer.role(), Role::Writer);
    assert!(Role::Owner.permits(Capability::Administer));
    assert!(Role::Writer.permits(Capability::Read));
    assert!(Role::Writer.permits(Capability::Write));
    assert!(!Role::Writer.permits(Capability::Administer));
    assert!(!Role::Reader.permits(Capability::Write));

    let encoded = serde_json::to_string(&writer)?;
    assert_eq!(serde_json::from_str::<Grant>(&encoded)?, writer);
    assert!(encoded.contains("\"scope\":\"item\""));
    assert!(!encoded.contains("git"));

    let owner_with_item = format!(
        r#"{{"scope":"vault_owner","principal_id":"{principal_id}","item_id":"{item_id}"}}"#
    );
    assert!(serde_json::from_str::<Grant>(&owner_with_item).is_err());
    Ok(())
}

#[test]
fn revisions_have_explicit_origins_and_checked_advancement()
-> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(PolicyRevision::GENESIS.get(), 0);
    assert_eq!(PolicyRevision::GENESIS.next()?.get(), 1);
    assert_eq!(KeyEpoch::INITIAL.get(), 1);
    assert_eq!(ItemRevision::INITIAL.get(), 1);
    assert_eq!(KeyEpoch::new(0), Err(RevisionError::Zero));
    assert_eq!(ItemRevision::new(0), Err(RevisionError::Zero));
    assert_eq!(
        PolicyRevision::new(u64::MAX).next(),
        Err(RevisionError::Exhausted)
    );
    assert_eq!(
        KeyEpoch::new(u64::MAX)?.next(),
        Err(RevisionError::Exhausted)
    );
    assert!(serde_json::from_str::<KeyEpoch>("0").is_err());
    assert_eq!(
        serde_json::from_str::<ItemRevision>("1")?,
        ItemRevision::INITIAL
    );
    Ok(())
}
