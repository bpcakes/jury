use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use zeroize::Zeroize;

/// Maximum canonical item-name length in bytes.
pub const MAX_ITEM_NAME_BYTES: usize = 64;

/// Maximum canonical field-name length in bytes.
pub const MAX_FIELD_NAME_BYTES: usize = 64;

/// Failure to construct a canonical item or field name.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NameError {
    /// Names cannot be empty.
    Empty,
    /// The byte length exceeded the type's fixed bound.
    TooLong { maximum: usize, actual: usize },
    /// Only the stable ASCII profile is accepted.
    NonAscii,
    /// Names must begin and end with an ASCII letter or digit.
    InvalidBoundary,
    /// A character was outside the canonical alphanumeric, dash, dot, and
    /// underscore profile.
    InvalidCharacter,
}

impl fmt::Display for NameError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("name cannot be empty"),
            Self::TooLong { maximum, actual } => {
                write!(formatter, "name exceeds {maximum} bytes (got {actual})")
            }
            Self::NonAscii => formatter.write_str("name must use the canonical ASCII profile"),
            Self::InvalidBoundary => {
                formatter.write_str("name must begin and end with an ASCII letter or digit")
            }
            Self::InvalidCharacter => formatter.write_str(
                "name may contain only ASCII letters, digits, dash, dot, and underscore",
            ),
        }
    }
}

impl std::error::Error for NameError {}

fn validate_name(value: &str, maximum: usize) -> Result<(), NameError> {
    if value.is_empty() {
        return Err(NameError::Empty);
    }
    if value.len() > maximum {
        return Err(NameError::TooLong {
            maximum,
            actual: value.len(),
        });
    }
    if !value.is_ascii() {
        return Err(NameError::NonAscii);
    }

    let bytes = value.as_bytes();
    if !bytes[0].is_ascii_alphanumeric() || !bytes[bytes.len() - 1].is_ascii_alphanumeric() {
        return Err(NameError::InvalidBoundary);
    }
    if bytes
        .iter()
        .any(|byte| !byte.is_ascii_alphanumeric() && !matches!(*byte, b'-' | b'.' | b'_'))
    {
        return Err(NameError::InvalidCharacter);
    }

    Ok(())
}

macro_rules! canonical_name {
    ($name:ident, $input:ident, $confirmed:ident, $maximum:expr, $redacted:literal) => {
        #[doc = concat!("A bounded canonical ", stringify!($name), ".")]
        #[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(String);

        impl $name {
            /// Parses an already-canonical name without trimming, folding, or
            /// normalization.
            pub fn parse(value: impl Into<String>) -> Result<Self, NameError> {
                Self::parse_owned(value.into())
            }

            fn parse_borrowed(value: &str) -> Result<Self, NameError> {
                validate_name(value, $maximum)?;
                Ok(Self(value.to_owned()))
            }

            fn parse_owned(value: String) -> Result<Self, NameError> {
                validate_name(&value, $maximum)?;
                Ok(Self(value))
            }

            pub(crate) fn as_str(&self) -> &str {
                &self.0
            }

            #[allow(dead_code, reason = "only decrypted catalog name variants need wiping")]
            pub(crate) fn clear_sensitive(&mut self) {
                self.0.zeroize();
            }
        }

        impl FromStr for $name {
            type Err = NameError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::parse_borrowed(value)
            }
        }

        impl TryFrom<String> for $name {
            type Error = NameError;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                Self::parse_owned(value)
            }
        }

        impl TryFrom<&str> for $name {
            type Error = NameError;

            fn try_from(value: &str) -> Result<Self, Self::Error> {
                Self::parse_borrowed(value)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str($redacted)
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(&self.0)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                struct NameVisitor;

                impl<'de> de::Visitor<'de> for NameVisitor {
                    type Value = $name;

                    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                        write!(
                            formatter,
                            "a canonical ASCII name containing at most {} bytes",
                            $maximum
                        )
                    }

                    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
                    where
                        E: de::Error,
                    {
                        $name::parse_borrowed(value).map_err(E::custom)
                    }

                    fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
                    where
                        E: de::Error,
                    {
                        $name::parse_owned(value).map_err(E::custom)
                    }
                }

                deserializer.deserialize_string(NameVisitor)
            }
        }

        #[doc = concat!("Unconfirmed caller input for a ", stringify!($name), ".")]
        #[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $input($name);

        impl $input {
            /// Validates caller input without making it a confirmed catalog name.
            pub fn parse(value: impl Into<String>) -> Result<Self, NameError> {
                $name::parse(value).map(Self)
            }

            pub(crate) fn as_name(&self) -> &$name {
                &self.0
            }
        }

        impl fmt::Debug for $input {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str($redacted)
            }
        }

        #[doc = concat!("A ", stringify!($name), " confirmed by decrypted accessible state.")]
        #[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $confirmed($name);

        impl $confirmed {
            #[allow(
                dead_code,
                reason = "field catalog construction lands with field projections"
            )]
            pub(crate) fn from_accessible_name(name: $name) -> Self {
                Self(name)
            }

            pub(crate) fn as_name(&self) -> &$name {
                &self.0
            }

            #[allow(dead_code, reason = "only populated catalog variants need wiping")]
            pub(crate) fn clear_sensitive(&mut self) {
                self.0.clear_sensitive();
            }
        }

        impl fmt::Display for $confirmed {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(self.0.as_str())
            }
        }

        impl fmt::Debug for $confirmed {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str($redacted)
            }
        }
    };
}

canonical_name!(
    ItemName,
    ItemNameInput,
    ConfirmedItemName,
    MAX_ITEM_NAME_BYTES,
    "<redacted-item-name>"
);
canonical_name!(
    FieldName,
    FieldNameInput,
    ConfirmedFieldName,
    MAX_FIELD_NAME_BYTES,
    "<redacted-field-name>"
);
