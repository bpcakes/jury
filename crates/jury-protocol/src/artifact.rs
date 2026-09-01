use serde::{Serialize, de::DeserializeOwned};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum JsonError {
    ArtifactTooLarge,
    ConflictMarker,
    InvalidJson,
}

pub(crate) fn contains_conflict_marker(bytes: &[u8]) -> bool {
    bytes.split(|byte| *byte == b'\n').any(|line| {
        line.starts_with(b"<<<<<<<") || line.starts_with(b"=======") || line.starts_with(b">>>>>>>")
    })
}

pub(crate) fn validate_json_input(bytes: &[u8], maximum_bytes: usize) -> Result<(), JsonError> {
    if bytes.len() > maximum_bytes {
        return Err(JsonError::ArtifactTooLarge);
    }
    if contains_conflict_marker(bytes) {
        return Err(JsonError::ConflictMarker);
    }
    Ok(())
}

pub(crate) fn deserialize_json<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, JsonError> {
    serde_json::from_slice(bytes).map_err(|_| JsonError::InvalidJson)
}

pub(crate) fn pretty_json_bytes(
    value: &impl Serialize,
    maximum_bytes: usize,
) -> Result<Vec<u8>, JsonError> {
    let mut output = serde_json::to_vec_pretty(value).map_err(|_| JsonError::InvalidJson)?;
    output.push(b'\n');
    if output.len() > maximum_bytes {
        return Err(JsonError::ArtifactTooLarge);
    }
    Ok(output)
}

pub(crate) fn compact_json_bytes(value: &impl Serialize) -> Result<Vec<u8>, JsonError> {
    serde_json::to_vec(value).map_err(|_| JsonError::InvalidJson)
}

#[cfg(test)]
mod tests {
    use serde::{Deserialize, Serialize};

    use super::*;

    #[derive(Deserialize, Serialize)]
    struct Example {
        value: u8,
    }

    #[test]
    fn json_helpers_preserve_bounds_conflicts_and_pretty_newline_form() -> Result<(), &'static str>
    {
        let bytes = pretty_json_bytes(&Example { value: 7 }, 32).map_err(|_| "pretty JSON")?;
        assert_eq!(bytes, b"{\n  \"value\": 7\n}\n");
        assert_eq!(
            compact_json_bytes(&Example { value: 7 }).map_err(|_| "compact JSON")?,
            b"{\"value\":7}"
        );
        assert_eq!(
            deserialize_json::<Example>(&bytes)
                .map_err(|_| "valid JSON")?
                .value,
            7
        );
        assert_eq!(
            validate_json_input(&bytes, bytes.len() - 1),
            Err(JsonError::ArtifactTooLarge)
        );
        assert_eq!(
            validate_json_input(b"<<<<<<< current\n", 64),
            Err(JsonError::ConflictMarker)
        );
        Ok(())
    }
}
