use jury_core::domain::{
    FieldName, ItemName, MAX_FIELD_NAME_BYTES, MAX_ITEM_NAME_BYTES, NameError,
};
use proptest::prelude::*;

#[test]
fn canonical_names_accept_only_the_documented_profile() -> Result<(), Box<dyn std::error::Error>> {
    for value in [
        "ExampleItem",
        "EXAMPLE_FIELD",
        "Example-1",
        "Example.Item_2",
    ] {
        let item = ItemName::parse(value)?;
        let field = FieldName::parse(value)?;
        assert_eq!(serde_json::to_value(item)?, value);
        assert_eq!(serde_json::to_value(field)?, value);
    }

    let item = ItemName::parse("ExampleSecret")?;
    assert_eq!(format!("{item:?}"), "<redacted-item-name>");
    Ok(())
}

#[test]
fn empty_boundary_separator_and_oversized_names_are_rejected() {
    assert_eq!(ItemName::parse(""), Err(NameError::Empty));
    for value in [
        "-Example",
        "Example_",
        ".",
        "Example/Field",
        "Example\\Field",
        "Example:Field",
        "Example Field",
        "Example\0Field",
    ] {
        assert!(
            ItemName::parse(value).is_err(),
            "unexpectedly accepted {value:?}"
        );
        assert!(
            FieldName::parse(value).is_err(),
            "unexpectedly accepted {value:?}"
        );
    }

    assert!(ItemName::parse("A".repeat(MAX_ITEM_NAME_BYTES)).is_ok());
    assert_eq!(
        ItemName::parse("A".repeat(MAX_ITEM_NAME_BYTES + 1)),
        Err(NameError::TooLong {
            maximum: MAX_ITEM_NAME_BYTES,
            actual: MAX_ITEM_NAME_BYTES + 1,
        })
    );
    assert!(FieldName::parse("A".repeat(MAX_FIELD_NAME_BYTES)).is_ok());
    assert!(FieldName::parse("A".repeat(MAX_FIELD_NAME_BYTES + 1)).is_err());
}

#[test]
fn unicode_normalization_and_confusable_inputs_never_collapse() {
    let unicode_cases = [
        "Café",
        "Cafe\u{301}",
        "Exаmple",
        "Εxample",
        "Ｅxample",
        "Example\u{202e}Field",
    ];

    for value in unicode_cases {
        assert_eq!(ItemName::parse(value), Err(NameError::NonAscii));
        assert_eq!(FieldName::parse(value), Err(NameError::NonAscii));
    }

    assert_ne!(ItemName::parse("Example"), ItemName::parse("example"));
    assert_eq!(ItemName::parse(" Example"), Err(NameError::InvalidBoundary));
    assert_eq!(ItemName::parse("Example "), Err(NameError::InvalidBoundary));
}

fn canonical_ascii_name() -> impl Strategy<Value = String> {
    let endpoint = prop_oneof![(b'A'..=b'Z'), (b'a'..=b'z'), (b'0'..=b'9')];
    let middle = prop_oneof![
        (b'A'..=b'Z'),
        (b'a'..=b'z'),
        (b'0'..=b'9'),
        Just(b'-'),
        Just(b'.'),
        Just(b'_'),
    ];

    prop_oneof![
        endpoint
            .clone()
            .prop_map(|value| char::from(value).to_string()),
        (
            endpoint.clone(),
            prop::collection::vec(middle, 0..=62),
            endpoint,
        )
            .prop_map(|(first, middle, last)| {
                let mut value = String::with_capacity(middle.len() + 2);
                value.push(char::from(first));
                value.extend(middle.into_iter().map(char::from));
                value.push(char::from(last));
                value
            }),
    ]
}

#[test]
fn serde_rejects_names_over_the_domain_bound() {
    let oversized = format!("\"{}\"", "A".repeat(MAX_ITEM_NAME_BYTES + 1));
    assert!(serde_json::from_str::<ItemName>(&oversized).is_err());

    let escaped = format!("\"{}\"", "\\u0041".repeat(MAX_FIELD_NAME_BYTES + 1));
    assert!(serde_json::from_str::<FieldName>(&escaped).is_err());
}

proptest! {
    #[test]
    fn canonical_name_parse_and_serde_are_idempotent(source in canonical_ascii_name()) {
        let item = ItemName::parse(source.clone());
        prop_assert!(item.is_ok());

        if let Ok(item) = item {
            let json = serde_json::to_value(&item);
            let expected = serde_json::Value::String(source.clone());
            prop_assert!(json.as_ref().is_ok_and(|value| value == &expected));
            let decoded = serde_json::from_value::<ItemName>(serde_json::Value::String(source));
            prop_assert!(matches!(decoded, Ok(value) if value == item));
        }
    }
}
