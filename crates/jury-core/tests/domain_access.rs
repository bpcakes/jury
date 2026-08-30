use jury_core::domain::{
    AccessibleCatalog, AccessibleCatalogEntry, AccessibleField, Capability, CatalogError,
    FieldName, FieldNameInput, Grant, ItemId, ItemName, ItemRevision, ItemRole, ItemSelector,
    ItemUnavailable, KeyEpoch, PolicyRevision, PrincipalId, RevisionError, Role,
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
    Ok(())
}

#[test]
fn inaccessible_and_nonexistent_names_have_one_result() -> Result<(), Box<dyn std::error::Error>> {
    let visible = AccessibleCatalogEntry::from_decrypted(
        ItemId::from_bytes([0x41; 32])?,
        ItemName::parse("ExampleVisible")?,
        Role::Reader,
    );
    let catalog = AccessibleCatalog::try_new(vec![visible])?;

    let inaccessible = catalog.resolve(&ItemSelector::parse("ExampleHidden")?);
    let nonexistent = catalog.resolve(&ItemSelector::parse("ExampleMissing")?);
    assert_eq!(inaccessible, Err(ItemUnavailable));
    assert_eq!(nonexistent, Err(ItemUnavailable));
    assert_eq!(inaccessible.map(|_| ()), nonexistent.map(|_| ()));
    assert_eq!(ItemUnavailable.to_string(), "requested item is unavailable");

    let found = catalog.resolve(&ItemSelector::parse("ExampleVisible")?)?;
    assert_eq!(found.item_id(), ItemId::from_bytes([0x41; 32])?);
    assert_eq!(found.name().to_string(), "ExampleVisible");
    assert_eq!(found.role(), Role::Reader);
    assert!(!format!("{found:?}").contains("ExampleVisible"));
    Ok(())
}

#[test]
fn accessible_catalog_rejects_duplicate_ids_and_names() -> Result<(), Box<dyn std::error::Error>> {
    let item_id = ItemId::from_bytes([0x51; 32])?;
    let first = AccessibleCatalogEntry::from_decrypted(
        item_id,
        ItemName::parse("ExampleItem")?,
        Role::Reader,
    );
    let duplicate_id = AccessibleCatalogEntry::from_decrypted(
        item_id,
        ItemName::parse("ExampleOther")?,
        Role::Writer,
    );
    assert_eq!(
        AccessibleCatalog::try_new(vec![first.clone(), duplicate_id]),
        Err(CatalogError::DuplicateItemId)
    );

    let duplicate_name = AccessibleCatalogEntry::from_decrypted(
        ItemId::from_bytes([0x52; 32])?,
        ItemName::parse("ExampleItem")?,
        Role::Writer,
    );
    assert_eq!(
        AccessibleCatalog::try_new(vec![first, duplicate_name]),
        Err(CatalogError::DuplicateItemName)
    );
    Ok(())
}

#[test]
fn field_display_requires_a_decrypted_accessible_projection()
-> Result<(), Box<dyn std::error::Error>> {
    let field = AccessibleField::from_decrypted(FieldName::parse("EXAMPLE_FIELD")?);
    assert_eq!(field.name().to_string(), "EXAMPLE_FIELD");
    assert!(field.matches(&FieldNameInput::parse("EXAMPLE_FIELD")?));
    assert!(!field.matches(&FieldNameInput::parse("EXAMPLE_OTHER")?));
    assert!(!format!("{field:?}").contains("EXAMPLE_FIELD"));
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
