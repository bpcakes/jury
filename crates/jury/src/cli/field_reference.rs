use super::{CliError, CliErrorKind, FieldSelector};
use jury_protocol::witness_v1::MAX_PUBLIC_REVIEW_LABEL_BYTES;

const MAX_JSON_REFERENCE_BYTES: usize = 12 * MAX_PUBLIC_REVIEW_LABEL_BYTES + 16;

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(super) struct FieldReference {
    pub(super) item: String,
    pub(super) field: String,
}

/// Slash cannot occur in either canonical name. Dot shorthand is retained
/// only when its single separator cannot be confused with a name's dots.
pub(super) fn parse(value: &str) -> Result<FieldReference, CliError> {
    if value.starts_with('[') {
        if value.len() > MAX_JSON_REFERENCE_BYTES {
            return Err(invalid_reference());
        }
        let (reference, end) = parse_json_prefix(value.as_bytes())?;
        if !value[end..].bytes().all(|byte| byte.is_ascii_whitespace()) {
            return Err(invalid_reference());
        }
        return Ok(reference);
    }
    let (item, field) = if value.contains('/') {
        value.split_once('/').ok_or_else(invalid_reference)?
    } else {
        let pair = value.split_once('.').ok_or_else(invalid_reference)?;
        if pair.1.contains('.') {
            return Err(invalid_reference());
        }
        pair
    };
    FieldSelector::parse(item.to_owned(), field.to_owned()).map_err(|_| invalid_reference())?;
    Ok(FieldReference {
        item: item.to_owned(),
        field: field.to_owned(),
    })
}

/// A JSON pair addresses exact public labels outside the native name profile.
/// The consumed byte count lets templates distinguish their closing braces
/// from braces occurring inside a quoted label, without unbounded parsing.
pub(super) fn parse_json_prefix(bytes: &[u8]) -> Result<(FieldReference, usize), CliError> {
    let bounded = &bytes[..bytes.len().min(MAX_JSON_REFERENCE_BYTES)];
    let mut stream = serde_json::Deserializer::from_slice(bounded).into_iter::<[String; 2]>();
    let [item, field] = stream
        .next()
        .ok_or_else(invalid_reference)?
        .map_err(|_| invalid_reference())?;
    for label in [&item, &field] {
        if label.is_empty()
            || label.len() > MAX_PUBLIC_REVIEW_LABEL_BYTES
            || label.bytes().any(|byte| byte.is_ascii_control())
        {
            return Err(invalid_reference());
        }
    }
    Ok((FieldReference { item, field }, stream.byte_offset()))
}

fn invalid_reference() -> CliError {
    CliError::new(
        CliErrorKind::InvalidArguments,
        "invalid-field-reference",
        "use ITEM/FIELD for native names or a JSON pair [\"item label\",\"field label\"] for exact public labels; ITEM.FIELD shorthand requires names without dots",
    )
}
