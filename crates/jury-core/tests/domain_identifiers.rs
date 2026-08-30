use std::str::FromStr;

use jury_core::domain::{IDENTIFIER_HEX_LENGTH, IdentifierError, ItemId, PrincipalId, VaultId};
use proptest::prelude::*;

#[test]
fn typed_identifiers_have_one_exact_encoding() -> Result<(), Box<dyn std::error::Error>> {
    let vault = VaultId::from_bytes([0x11; 32])?;
    let principal = PrincipalId::from_bytes([0x22; 32])?;
    let item = ItemId::from_bytes([0xab; 32])?;

    assert_eq!(vault.to_string(), "11".repeat(32));
    assert_eq!(principal.to_string(), "22".repeat(32));
    assert_eq!(item.to_string(), "ab".repeat(32));
    assert_eq!(vault.to_string().len(), IDENTIFIER_HEX_LENGTH);
    assert_eq!(VaultId::from_str(&vault.to_string())?, vault);
    assert_eq!(PrincipalId::from_str(&principal.to_string())?, principal);
    assert_eq!(ItemId::from_str(&item.to_string())?, item);
    Ok(())
}

#[test]
fn identifiers_reject_sentinels_and_noncanonical_text() {
    assert_eq!(VaultId::from_bytes([0; 32]), Err(IdentifierError::Zero));
    assert_eq!(
        VaultId::from_str(&"AA".repeat(32)),
        Err(IdentifierError::NonCanonicalEncoding)
    );
    assert_eq!(
        VaultId::from_str("01"),
        Err(IdentifierError::WrongLength {
            expected: IDENTIFIER_HEX_LENGTH,
            actual: 2,
        })
    );
    assert_eq!(
        IdentifierError::WrongLength {
            expected: IDENTIFIER_HEX_LENGTH,
            actual: 2,
        }
        .to_string(),
        "identifier must be exactly 64 hexadecimal characters, got 2"
    );
    assert_eq!(
        VaultId::from_str(&format!("{}0g", "01".repeat(31))),
        Err(IdentifierError::NonCanonicalEncoding)
    );
}

#[test]
fn serde_revalidates_identifier_invariants() -> Result<(), Box<dyn std::error::Error>> {
    let identifier = VaultId::from_bytes([0x45; 32])?;
    let encoded = serde_json::to_string(&identifier)?;

    assert_eq!(serde_json::from_str::<VaultId>(&encoded)?, identifier);
    assert!(serde_json::from_str::<VaultId>(&format!("\"{}\"", "00".repeat(32))).is_err());
    assert!(serde_json::from_str::<VaultId>(&format!("\"{}\"", "AB".repeat(32))).is_err());
    Ok(())
}

proptest! {
    #[test]
    fn identifier_text_and_json_round_trip(bytes in any::<[u8; 32]>()) {
        if bytes.iter().all(|byte| *byte == 0) {
            prop_assert_eq!(VaultId::from_bytes(bytes), Err(IdentifierError::Zero));
        } else {
            let parsed = VaultId::from_bytes(bytes);
            prop_assert!(parsed.is_ok());

            if let Ok(identifier) = parsed {
                let canonical = identifier.to_canonical_string();
                prop_assert_eq!(VaultId::from_str(&canonical), Ok(identifier));

                let json = serde_json::to_value(identifier);
                let expected = serde_json::Value::String(canonical.clone());
                prop_assert!(json.as_ref().is_ok_and(|value| value == &expected));

                let decoded = serde_json::from_value::<VaultId>(serde_json::Value::String(canonical));
                prop_assert!(matches!(decoded, Ok(value) if value == identifier));
            }
        }
    }
}
