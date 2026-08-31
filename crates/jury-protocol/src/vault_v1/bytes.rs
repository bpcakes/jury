use std::fmt;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use zeroize::Zeroize;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ByteStringError {
    WrongLength { expected: usize, actual: usize },
    TooLong { maximum: usize, actual: usize },
    NonCanonical,
    ZeroIdentifier,
}

impl fmt::Display for ByteStringError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongLength { expected, actual } => {
                write!(formatter, "expected {expected} bytes, got {actual}")
            }
            Self::TooLong { maximum, actual } => {
                write!(formatter, "maximum is {maximum} bytes, got {actual}")
            }
            Self::NonCanonical => formatter.write_str("non-canonical byte encoding"),
            Self::ZeroIdentifier => formatter.write_str("the all-zero identifier is reserved"),
        }
    }
}

impl std::error::Error for ByteStringError {}

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct FixedBytes<const N: usize>([u8; N]);

impl<const N: usize> FixedBytes<N> {
    pub const fn new(bytes: [u8; N]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; N] {
        &self.0
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self, ByteStringError> {
        let actual = bytes.len();
        let bytes = bytes.try_into().map_err(|_| ByteStringError::WrongLength {
            expected: N,
            actual,
        })?;
        Ok(Self(bytes))
    }
}

impl<const N: usize> fmt::Debug for FixedBytes<N> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "FixedBytes<{N}>")
    }
}

impl<const N: usize> Serialize for FixedBytes<N> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&STANDARD.encode(self.0))
    }
}

impl<'de, const N: usize> Deserialize<'de> for FixedBytes<N> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct FixedBytesVisitor<const N: usize>;

        impl<const N: usize> de::Visitor<'_> for FixedBytesVisitor<N> {
            type Value = FixedBytes<N>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(formatter, "canonical padded base64 for exactly {N} bytes")
            }

            fn visit_str<E>(self, encoded: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                let maximum_encoded = N.div_ceil(3) * 4;
                if encoded.len() != maximum_encoded {
                    return Err(E::custom(ByteStringError::WrongLength {
                        expected: maximum_encoded,
                        actual: encoded.len(),
                    }));
                }
                let decoded = STANDARD
                    .decode(encoded)
                    .map_err(|_| E::custom(ByteStringError::NonCanonical))?;
                if STANDARD.encode(&decoded) != encoded {
                    return Err(E::custom(ByteStringError::NonCanonical));
                }
                FixedBytes::from_slice(&decoded).map_err(E::custom)
            }
        }

        deserializer.deserialize_str(FixedBytesVisitor::<N>)
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct BoundedBytes<const MAX: usize>(Vec<u8>);

impl<const MAX: usize> BoundedBytes<MAX> {
    pub fn new(bytes: Vec<u8>) -> Result<Self, ByteStringError> {
        if bytes.len() > MAX {
            return Err(ByteStringError::TooLong {
                maximum: MAX,
                actual: bytes.len(),
            });
        }
        Ok(Self(bytes))
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Overwrites and releases sensitive plaintext held by this buffer.
    pub fn clear_sensitive(&mut self) {
        self.0.zeroize();
    }
}

impl<const MAX: usize> fmt::Debug for BoundedBytes<MAX> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "BoundedBytes<{MAX}>({} bytes)", self.0.len())
    }
}

impl<const MAX: usize> Serialize for BoundedBytes<MAX> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&STANDARD.encode(&self.0))
    }
}

impl<'de, const MAX: usize> Deserialize<'de> for BoundedBytes<MAX> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct BoundedBytesVisitor<const MAX: usize>;

        impl<const MAX: usize> de::Visitor<'_> for BoundedBytesVisitor<MAX> {
            type Value = BoundedBytes<MAX>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(formatter, "canonical padded base64 for at most {MAX} bytes")
            }

            fn visit_str<E>(self, encoded: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                let maximum_encoded = MAX.div_ceil(3) * 4;
                if encoded.len() > maximum_encoded {
                    return Err(E::custom(ByteStringError::TooLong {
                        maximum: maximum_encoded,
                        actual: encoded.len(),
                    }));
                }
                let decoded = STANDARD
                    .decode(encoded)
                    .map_err(|_| E::custom(ByteStringError::NonCanonical))?;
                if STANDARD.encode(&decoded) != encoded {
                    return Err(E::custom(ByteStringError::NonCanonical));
                }
                BoundedBytes::new(decoded).map_err(E::custom)
            }
        }

        deserializer.deserialize_str(BoundedBytesVisitor::<MAX>)
    }
}

fn decode_hex(encoded: &str) -> Result<[u8; 32], ByteStringError> {
    if encoded.len() != 64 {
        return Err(ByteStringError::WrongLength {
            expected: 64,
            actual: encoded.len(),
        });
    }
    let mut bytes = [0_u8; 32];
    for (index, pair) in encoded.as_bytes().chunks_exact(2).enumerate() {
        let high = nibble(pair[0]).ok_or(ByteStringError::NonCanonical)?;
        let low = nibble(pair[1]).ok_or(ByteStringError::NonCanonical)?;
        bytes[index] = (high << 4) | low;
    }
    if bytes.iter().all(|byte| *byte == 0) {
        return Err(ByteStringError::ZeroIdentifier);
    }
    Ok(bytes)
}

fn nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn encode_hex(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(64);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

macro_rules! identifier {
    ($name:ident) => {
        #[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name([u8; 32]);

        impl $name {
            pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, ByteStringError> {
                if bytes.iter().all(|byte| *byte == 0) {
                    Err(ByteStringError::ZeroIdentifier)
                } else {
                    Ok(Self(bytes))
                }
            }

            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(stringify!($name))
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(&encode_hex(&self.0))
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let encoded = <&str>::deserialize(deserializer)?;
                decode_hex(encoded).map(Self).map_err(de::Error::custom)
            }
        }
    };
}

identifier!(VaultId);
identifier!(PrincipalId);
identifier!(ItemId);
identifier!(FieldId);
identifier!(RevisionSealId);
identifier!(SlotId);
identifier!(WitnessPolicyId);
identifier!(MigrationId);
identifier!(RolloverId);
identifier!(ResponseId);

pub type Digest32 = FixedBytes<32>;
pub type Signature64 = FixedBytes<64>;
pub type Nonce12 = FixedBytes<12>;
pub type RecipientPublicKey1216 = FixedBytes<1216>;
pub type VerificationPublicKey32 = FixedBytes<32>;
pub type Encapsulation1120 = FixedBytes<1120>;
pub type DirectCiphertext48 = FixedBytes<48>;
pub type RootWrapCiphertext48 = FixedBytes<48>;
pub type ShareCiphertext49 = FixedBytes<49>;
pub type DescriptorCiphertext272 = FixedBytes<272>;
pub type IdentityPayloadCiphertext149 = FixedBytes<149>;
pub type Salt16 = FixedBytes<16>;
pub type ItemCiphertext = BoundedBytes<8_388_624>;
