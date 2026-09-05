use std::fmt::{self, Write as _};
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

mod generator;

pub use generator::{
    IDENTIFIER_COLLISION_RETRY_ATTEMPTS, IDENTIFIER_ZERO_RETRY_ATTEMPTS, IdentifierGenerationError,
    NativeIdGenerator,
};

/// Exact byte length of every native opaque identifier.
pub const IDENTIFIER_BYTES: usize = 32;

/// Exact canonical lowercase-hex length of every native opaque identifier.
pub const IDENTIFIER_HEX_LENGTH: usize = IDENTIFIER_BYTES * 2;

/// Failure to construct a canonical native identifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentifierError {
    /// The encoded identifier did not have the exact required length.
    WrongLength { expected: usize, actual: usize },
    /// The encoding was not canonical lowercase hexadecimal.
    NonCanonicalEncoding,
    /// The all-zero value is reserved and cannot identify a domain object.
    Zero,
}

impl fmt::Display for IdentifierError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongLength { expected, actual } => {
                write!(
                    formatter,
                    "identifier must be exactly {expected} hexadecimal characters, got {actual}"
                )
            }
            Self::NonCanonicalEncoding => {
                formatter.write_str("identifier must use canonical lowercase hexadecimal")
            }
            Self::Zero => formatter.write_str("the all-zero identifier is reserved"),
        }
    }
}

impl std::error::Error for IdentifierError {}

fn decode_identifier(encoded: &str) -> Result<[u8; IDENTIFIER_BYTES], IdentifierError> {
    if encoded.len() != IDENTIFIER_HEX_LENGTH {
        return Err(IdentifierError::WrongLength {
            expected: IDENTIFIER_HEX_LENGTH,
            actual: encoded.len(),
        });
    }

    let mut bytes = [0_u8; IDENTIFIER_BYTES];
    for (index, pair) in encoded.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        let high = decode_nibble(pair[0]).ok_or(IdentifierError::NonCanonicalEncoding)?;
        let low = decode_nibble(pair[1]).ok_or(IdentifierError::NonCanonicalEncoding)?;
        bytes[index] = (high << 4) | low;
    }

    validate_identifier(bytes)
}

fn decode_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn validate_identifier(
    bytes: [u8; IDENTIFIER_BYTES],
) -> Result<[u8; IDENTIFIER_BYTES], IdentifierError> {
    if bytes.iter().all(|byte| *byte == 0) {
        Err(IdentifierError::Zero)
    } else {
        Ok(bytes)
    }
}

fn write_identifier(
    bytes: &[u8; IDENTIFIER_BYTES],
    formatter: &mut fmt::Formatter<'_>,
) -> fmt::Result {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    for byte in bytes {
        formatter.write_char(char::from(HEX[usize::from(byte >> 4)]))?;
        formatter.write_char(char::from(HEX[usize::from(byte & 0x0f)]))?;
    }
    Ok(())
}

fn encode_identifier(bytes: &[u8; IDENTIFIER_BYTES]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    let mut encoded = String::with_capacity(IDENTIFIER_HEX_LENGTH);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

trait GeneratedIdentifier: Sized {
    fn from_nonzero_bytes(bytes: [u8; IDENTIFIER_BYTES]) -> Self;
}

macro_rules! opaque_identifier {
    ($name:ident) => {
        #[doc = concat!("A typed, nonzero 256-bit ", stringify!($name), ".")]
        #[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name([u8; IDENTIFIER_BYTES]);

        impl $name {
            /// Parses an identifier from exact native bytes.
            ///
            /// This constructor exists for authenticated input, import, and
            /// deterministic vectors. Ordinary creation uses
            /// [`NativeIdGenerator`] so callers cannot choose new IDs.
            pub fn from_bytes(bytes: [u8; IDENTIFIER_BYTES]) -> Result<Self, IdentifierError> {
                validate_identifier(bytes).map(Self)
            }

            /// Returns the exact native bytes used in signed and stored state.
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; IDENTIFIER_BYTES] {
                &self.0
            }

            /// Returns the canonical lowercase-hex representation.
            #[must_use]
            pub fn to_canonical_string(self) -> String {
                encode_identifier(&self.0)
            }
        }

        impl GeneratedIdentifier for $name {
            fn from_nonzero_bytes(bytes: [u8; IDENTIFIER_BYTES]) -> Self {
                debug_assert!(bytes.iter().any(|byte| *byte != 0));
                Self(bytes)
            }
        }

        impl TryFrom<[u8; IDENTIFIER_BYTES]> for $name {
            type Error = IdentifierError;

            fn try_from(bytes: [u8; IDENTIFIER_BYTES]) -> Result<Self, Self::Error> {
                Self::from_bytes(bytes)
            }
        }

        impl FromStr for $name {
            type Err = IdentifierError;

            fn from_str(encoded: &str) -> Result<Self, Self::Err> {
                decode_identifier(encoded).map(Self)
            }
        }

        impl TryFrom<&str> for $name {
            type Error = IdentifierError;

            fn try_from(encoded: &str) -> Result<Self, Self::Error> {
                encoded.parse()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write_identifier(&self.0, formatter)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_tuple(stringify!($name))
                    .field(&format_args!("{self}"))
                    .finish()
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(&encode_identifier(&self.0))
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                struct IdentifierVisitor;

                impl<'de> de::Visitor<'de> for IdentifierVisitor {
                    type Value = $name;

                    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                        write!(
                            formatter,
                            "exactly {IDENTIFIER_HEX_LENGTH} lowercase hexadecimal characters"
                        )
                    }

                    fn visit_str<E>(self, encoded: &str) -> Result<Self::Value, E>
                    where
                        E: de::Error,
                    {
                        encoded.parse().map_err(E::custom)
                    }
                }

                deserializer.deserialize_str(IdentifierVisitor)
            }
        }
    };
}

opaque_identifier!(VaultId);
opaque_identifier!(PrincipalId);
opaque_identifier!(ItemId);
