use serde::{Serialize, de::DeserializeOwned};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct LengthOverflow;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum JsonError {
    InvalidJson,
    ArtifactTooLarge,
}

pub(crate) fn jce_v1(domain: &str) -> Vec<u8> {
    let mut output = Vec::with_capacity(domain.len() + 3);
    output.extend_from_slice(domain.as_bytes());
    output.extend_from_slice(&[0, 0, 1]);
    output
}

pub(crate) fn bytes_field(output: &mut Vec<u8>, value: &[u8]) -> Result<(), LengthOverflow> {
    let length = u32::try_from(value.len()).map_err(|_| LengthOverflow)?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}

pub(crate) fn list_bytes(output: &mut Vec<u8>, values: &[Vec<u8>]) -> Result<(), LengthOverflow> {
    let count = u32::try_from(values.len()).map_err(|_| LengthOverflow)?;
    output.extend_from_slice(&count.to_be_bytes());
    for value in values {
        bytes_field(output, value)?;
    }
    Ok(())
}

pub(crate) fn list_fixed<T>(
    output: &mut Vec<u8>,
    values: impl IntoIterator<Item = T>,
    mut append: impl FnMut(&mut Vec<u8>, T),
) -> Result<(), LengthOverflow> {
    let values = values.into_iter().collect::<Vec<_>>();
    let count = u32::try_from(values.len()).map_err(|_| LengthOverflow)?;
    output.extend_from_slice(&count.to_be_bytes());
    for value in values {
        append(output, value);
    }
    Ok(())
}

pub(crate) fn deserialize_json<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, JsonError> {
    serde_json::from_slice(bytes).map_err(|_| JsonError::InvalidJson)
}

pub(crate) fn validate_json_input(bytes: &[u8], maximum_bytes: usize) -> Result<(), JsonError> {
    if bytes.len() > maximum_bytes {
        Err(JsonError::ArtifactTooLarge)
    } else {
        Ok(())
    }
}

pub(crate) fn compact_json_bytes(
    value: &impl Serialize,
    maximum_bytes: Option<usize>,
) -> Result<Vec<u8>, JsonError> {
    let output = serde_json::to_vec(value).map_err(|_| JsonError::InvalidJson)?;
    if maximum_bytes.is_some_and(|maximum| output.len() > maximum) {
        return Err(JsonError::ArtifactTooLarge);
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_primitives_preserve_suite_and_collection_encoding() -> Result<(), &'static str> {
        let mut output = jce_v1("jury-example");
        bytes_field(&mut output, b"ab").map_err(|_| "short field")?;
        list_bytes(&mut output, &[b"c".to_vec()]).map_err(|_| "short list")?;
        list_fixed(&mut output, *b"de", |output, value| {
            output.push(value);
        })
        .map_err(|_| "short fixed list")?;

        assert_eq!(
            output,
            b"jury-example\0\0\x01\0\0\0\x02ab\0\0\0\x01\0\0\0\x01c\0\0\0\x02de"
        );
        Ok(())
    }

    #[test]
    fn compact_json_helper_preserves_exact_bytes_and_bounds() -> Result<(), &'static str> {
        let value = [1_u8, 2];
        let bytes = compact_json_bytes(&value, Some(5)).map_err(|_| "bounded JSON")?;
        assert_eq!(bytes, b"[1,2]");
        assert_eq!(
            deserialize_json::<[u8; 2]>(&bytes).map_err(|_| "valid JSON")?,
            value
        );
        assert_eq!(
            compact_json_bytes(&value, Some(4)),
            Err(JsonError::ArtifactTooLarge)
        );
        assert_eq!(
            validate_json_input(&bytes, 4),
            Err(JsonError::ArtifactTooLarge)
        );
        Ok(())
    }
}
