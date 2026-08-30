use std::fmt;
use std::path::PathBuf;

use jury_core::adapter::{
    AbsoluteVaultHome, ExternalReferenceAdapter, MAX_EXTERNAL_HOME_BYTES, StorageContext,
    StorageContextError,
};
use jury_core::domain::{FieldSelector, ItemId, NameError, PrincipalId, VaultId};
use serde::Serialize;

struct FixtureReference<'a> {
    external_uri: &'a str,
    repository: &'a str,
    revision: &'a str,
    author: &'a str,
    reviewed: bool,
}

#[derive(Debug)]
enum FixtureAdapterError {
    InvalidReference,
    InvalidName(NameError),
}

impl fmt::Display for FixtureAdapterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidReference => formatter.write_str("external reference is invalid"),
            Self::InvalidName(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for FixtureAdapterError {}

struct FixtureAdapter;

impl ExternalReferenceAdapter for FixtureAdapter {
    type Reference = FixtureReference<'static>;
    type Error = FixtureAdapterError;

    fn translate(&self, reference: &Self::Reference) -> Result<FieldSelector, Self::Error> {
        let _non_authoritative_context = (
            reference.repository,
            reference.revision,
            reference.author,
            reference.reviewed,
        );
        let body = reference
            .external_uri
            .strip_prefix("jig://")
            .ok_or(FixtureAdapterError::InvalidReference)?;
        let (item, field) = body
            .split_once('/')
            .ok_or(FixtureAdapterError::InvalidReference)?;
        if field.contains('/') {
            return Err(FixtureAdapterError::InvalidReference);
        }
        FieldSelector::parse(item, field).map_err(FixtureAdapterError::InvalidName)
    }
}

#[derive(Serialize)]
struct NativeSignedIdentity {
    vault_id: VaultId,
    principal_id: PrincipalId,
    item_id: ItemId,
}

#[test]
fn external_and_git_context_cannot_enter_native_identity_or_selector()
-> Result<(), Box<dyn std::error::Error>> {
    let adapter = FixtureAdapter;
    let first = FixtureReference {
        external_uri: "jig://ExampleItem/EXAMPLE_FIELD",
        repository: "ExampleRepository",
        revision: "refs/heads/example-a",
        author: "ExampleAuthorA",
        reviewed: false,
    };
    let second = FixtureReference {
        external_uri: "jig://ExampleItem/EXAMPLE_FIELD",
        repository: "ExampleOtherRepository",
        revision: "refs/heads/example-b",
        author: "ExampleAuthorB",
        reviewed: true,
    };

    let translated_first = adapter.translate(&first)?;
    let translated_second = adapter.translate(&second)?;
    let direct = FieldSelector::parse("ExampleItem", "EXAMPLE_FIELD")?;
    let first_json = serde_json::to_string(&translated_first)?;

    assert_eq!(translated_first, translated_second);
    assert_eq!(translated_first, direct);
    assert_eq!(
        format!("{translated_first:?}"),
        "FieldSelector(<unconfirmed>)"
    );
    for forbidden in ["jig://", "ExampleRepository", "refs/heads", "ExampleAuthor"] {
        assert!(!first_json.contains(forbidden));
    }

    let identity = NativeSignedIdentity {
        vault_id: VaultId::from_bytes([0x61; 32])?,
        principal_id: PrincipalId::from_bytes([0x62; 32])?,
        item_id: ItemId::from_bytes([0x63; 32])?,
    };
    let identity_json = serde_json::to_string(&identity)?;
    assert_eq!(identity_json, serde_json::to_string(&identity)?);
    assert!(!identity_json.contains("ExampleRepository"));
    assert!(!identity_json.contains("ExampleAuthor"));
    Ok(())
}

#[test]
fn native_selectors_cannot_store_uri_or_path_syntax() {
    for item in [
        "jig://ExampleItem",
        "jury://ExampleItem",
        "/ExampleItem",
        "Example/Item",
        "Example\\Item",
    ] {
        assert!(FieldSelector::parse(item, "EXAMPLE_FIELD").is_err());
    }
    assert!(FieldSelector::parse("ExampleItem", "EXAMPLE/FIELD").is_err());

    assert!(
        serde_json::from_str::<FieldSelector>(
            r#"{"item":"ExampleItem","field":"EXAMPLE_FIELD","route":"ExampleRoute"}"#,
        )
        .is_err()
    );
}

#[test]
fn storage_context_is_bounded_redacted_and_non_domain() -> Result<(), Box<dyn std::error::Error>> {
    let home_path = std::env::temp_dir().join("ExampleVault");
    let home = AbsoluteVaultHome::new(home_path.clone())?;
    let context = StorageContext::Explicit(home.clone());

    assert_eq!(home.as_path(), home_path);
    assert_eq!(format!("{home:?}"), "AbsoluteVaultHome(<redacted>)");
    assert_eq!(
        format!("{context:?}"),
        "StorageContext::Explicit(<redacted-home>)"
    );
    assert!(!format!("{context:?}").contains("ExampleVault"));

    assert_eq!(
        AbsoluteVaultHome::new(PathBuf::new()),
        Err(StorageContextError::Empty)
    );
    assert_eq!(
        AbsoluteVaultHome::new(std::env::temp_dir().join("Example\0Vault")),
        Err(StorageContextError::Nul)
    );
    assert_eq!(
        AbsoluteVaultHome::new(PathBuf::from("relative/ExampleVault")),
        Err(StorageContextError::NotAbsolute)
    );
    assert_eq!(
        AbsoluteVaultHome::new(std::env::temp_dir().join("ExampleVault/../Other")),
        Err(StorageContextError::Traversal)
    );
    assert_eq!(
        AbsoluteVaultHome::new(PathBuf::from(format!(
            "/{}",
            "a".repeat(MAX_EXTERNAL_HOME_BYTES)
        ))),
        Err(StorageContextError::TooLong {
            maximum: MAX_EXTERNAL_HOME_BYTES,
            actual: MAX_EXTERNAL_HOME_BYTES + 1,
        })
    );
    Ok(())
}
