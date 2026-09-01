use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::artifact;
use zeroize::Zeroize;

use super::bytes::{BoundedBytes, FieldId};

pub const ITEM_DESCRIPTOR_PLAINTEXT_BYTES: usize = 256;
pub const MAX_FIELD_VALUE_BYTES: usize = 1024 * 1024;
pub const MAX_ITEM_FIELDS: usize = 1_024;
pub const MIN_CONCEALED_VALUE_BYTES: usize = 4;

pub type ItemFieldValue = BoundedBytes<MAX_FIELD_VALUE_BYTES>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlaintextError {
    DescriptorLength,
    DescriptorPadding,
    InvalidName,
    UnknownSchema,
    UnknownBucket,
    BodyLength,
    BodyPadding,
    InvalidJson,
    NonCanonicalJson,
    TooManyFields,
    DuplicateField,
    ValueLength,
    ConcealedValueTooShort,
    TimestampOrder,
}

impl fmt::Display for PlaintextError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::DescriptorLength => "item descriptor length differs",
            Self::DescriptorPadding => "item descriptor padding differs",
            Self::InvalidName => "item or field name is invalid",
            Self::UnknownSchema => "item plaintext schema is unknown",
            Self::UnknownBucket => "item plaintext bucket is unknown",
            Self::BodyLength => "item plaintext logical length differs",
            Self::BodyPadding => "item plaintext padding differs",
            Self::InvalidJson => "item plaintext JSON is invalid",
            Self::NonCanonicalJson => "item plaintext JSON is not canonical",
            Self::TooManyFields => "item plaintext has too many fields",
            Self::DuplicateField => "item plaintext repeats a field name or ID",
            Self::ValueLength => "item field value length differs",
            Self::ConcealedValueTooShort => "concealed item field is below the safe minimum",
            Self::TimestampOrder => "item field timestamps are out of order",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for PlaintextError {}

#[derive(Clone, Eq, PartialEq)]
pub struct ItemDescriptorV1 {
    name: String,
}

impl ItemDescriptorV1 {
    pub fn new(name: String) -> Result<Self, PlaintextError> {
        validate_name(&name)?;
        Ok(Self { name })
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Overwrites the decrypted descriptor name before releasing its buffer.
    pub fn clear_sensitive(&mut self) {
        self.name.zeroize();
    }

    #[must_use]
    pub fn encode(&self) -> [u8; ITEM_DESCRIPTOR_PLAINTEXT_BYTES] {
        let mut output = [0_u8; ITEM_DESCRIPTOR_PLAINTEXT_BYTES];
        output[0] = 1;
        output[1..3].copy_from_slice(&(self.name.len() as u16).to_be_bytes());
        output[3..3 + self.name.len()].copy_from_slice(self.name.as_bytes());
        output
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, PlaintextError> {
        let bytes: &[u8; ITEM_DESCRIPTOR_PLAINTEXT_BYTES] = bytes
            .try_into()
            .map_err(|_| PlaintextError::DescriptorLength)?;
        if bytes[0] != 1 {
            return Err(PlaintextError::UnknownSchema);
        }
        let length = usize::from(u16::from_be_bytes([bytes[1], bytes[2]]));
        if length > 64 {
            return Err(PlaintextError::InvalidName);
        }
        if bytes[3 + length..].iter().any(|byte| *byte != 0) {
            return Err(PlaintextError::DescriptorPadding);
        }
        let name =
            std::str::from_utf8(&bytes[3..3 + length]).map_err(|_| PlaintextError::InvalidName)?;
        Self::new(name.to_owned())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ItemFieldKind {
    Text,
    Concealed,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ItemFieldV1 {
    pub name: String,
    pub field_id: FieldId,
    pub value: ItemFieldValue,
    pub decoded_length: u32,
    pub kind: ItemFieldKind,
    pub created_at_ms: u64,
    pub updated_at_ms: u64,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ItemStateV1 {
    pub plaintext_schema: u8,
    pub fields: Vec<ItemFieldV1>,
}

impl ItemStateV1 {
    /// Overwrites decrypted names and values before releasing their buffers.
    pub fn clear_sensitive(&mut self) {
        for field in &mut self.fields {
            field.name.zeroize();
            field.value.clear_sensitive();
        }
        self.fields.clear();
    }

    pub fn validate(&self) -> Result<(), PlaintextError> {
        if self.plaintext_schema != 1 {
            return Err(PlaintextError::UnknownSchema);
        }
        if self.fields.len() > MAX_ITEM_FIELDS {
            return Err(PlaintextError::TooManyFields);
        }
        let mut previous_name = None;
        let mut field_ids = BTreeSet::new();
        for field in &self.fields {
            validate_name(&field.name)?;
            if previous_name
                .as_ref()
                .is_some_and(|previous: &&String| previous.as_bytes() >= field.name.as_bytes())
                || !field_ids.insert(field.field_id)
            {
                return Err(PlaintextError::DuplicateField);
            }
            previous_name = Some(&field.name);
            if usize::try_from(field.decoded_length).ok() != Some(field.value.len()) {
                return Err(PlaintextError::ValueLength);
            }
            if field.kind == ItemFieldKind::Concealed
                && field.value.len() < MIN_CONCEALED_VALUE_BYTES
            {
                return Err(PlaintextError::ConcealedValueTooShort);
            }
            if field.updated_at_ms < field.created_at_ms {
                return Err(PlaintextError::TimestampOrder);
            }
        }
        Ok(())
    }

    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, PlaintextError> {
        self.validate()?;
        artifact::compact_json_bytes(self).map_err(|_| PlaintextError::InvalidJson)
    }

    pub fn parse_canonical(bytes: &[u8]) -> Result<Self, PlaintextError> {
        let state: Self =
            artifact::deserialize_json(bytes).map_err(|_| PlaintextError::InvalidJson)?;
        state.validate()?;
        if state.to_canonical_bytes()? != bytes {
            return Err(PlaintextError::NonCanonicalJson);
        }
        Ok(state)
    }

    pub fn frame(&self, bucket_id: u8) -> Result<Vec<u8>, PlaintextError> {
        let body = self.to_canonical_bytes()?;
        let bucket = bucket_length(bucket_id)?;
        let logical_length = u32::try_from(body.len()).map_err(|_| PlaintextError::BodyLength)?;
        if body.len().saturating_add(4) > bucket {
            return Err(PlaintextError::BodyLength);
        }
        let mut output = vec![0_u8; bucket];
        output[..4].copy_from_slice(&logical_length.to_be_bytes());
        output[4..4 + body.len()].copy_from_slice(&body);
        Ok(output)
    }

    pub fn parse_framed(bucket_id: u8, plaintext: &[u8]) -> Result<Self, PlaintextError> {
        if plaintext.len() != bucket_length(bucket_id)? || plaintext.len() < 4 {
            return Err(PlaintextError::BodyLength);
        }
        let logical_length = usize::try_from(u32::from_be_bytes(
            plaintext[..4]
                .try_into()
                .map_err(|_| PlaintextError::BodyLength)?,
        ))
        .map_err(|_| PlaintextError::BodyLength)?;
        let end = logical_length
            .checked_add(4)
            .filter(|end| *end <= plaintext.len())
            .ok_or(PlaintextError::BodyLength)?;
        if plaintext[end..].iter().any(|byte| *byte != 0) {
            return Err(PlaintextError::BodyPadding);
        }
        Self::parse_canonical(&plaintext[4..end])
    }
}

fn bucket_length(bucket_id: u8) -> Result<usize, PlaintextError> {
    match bucket_id {
        1..=12 => 4_096_usize
            .checked_shl(u32::from(bucket_id - 1))
            .ok_or(PlaintextError::UnknownBucket),
        _ => Err(PlaintextError::UnknownBucket),
    }
}

fn validate_name(name: &str) -> Result<(), PlaintextError> {
    let bytes = name.as_bytes();
    if bytes.is_empty()
        || bytes.len() > 64
        || !bytes[0].is_ascii_alphanumeric()
        || !bytes[bytes.len() - 1].is_ascii_alphanumeric()
        || bytes
            .iter()
            .any(|byte| !(byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_')))
    {
        return Err(PlaintextError::InvalidName);
    }
    Ok(())
}
