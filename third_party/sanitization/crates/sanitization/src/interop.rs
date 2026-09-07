#[cfg(all(feature = "serde", feature = "alloc"))]
use alloc::{string::String, vec::Vec};
#[cfg(feature = "serde")]
use core::fmt;

#[allow(unused_imports)]
use crate::*;

#[cfg(feature = "zeroize-interop")]
mod zeroize_interop {
    use super::*;

    impl<const N: usize> zeroize::Zeroize for SecretBytes<N> {
        #[inline]
        fn zeroize(&mut self) {
            self.secure_clear();
        }
    }

    impl<const N: usize> zeroize::ZeroizeOnDrop for SecretBytes<N> {}

    #[cfg(feature = "alloc")]
    impl zeroize::Zeroize for SecretVec {
        #[inline]
        fn zeroize(&mut self) {
            self.clear_secret();
        }
    }

    #[cfg(feature = "alloc")]
    impl zeroize::ZeroizeOnDrop for SecretVec {}

    #[cfg(feature = "alloc")]
    impl zeroize::Zeroize for SecretBoxBytes {
        #[inline]
        fn zeroize(&mut self) {
            self.clear_secret();
        }
    }

    #[cfg(feature = "alloc")]
    impl zeroize::ZeroizeOnDrop for SecretBoxBytes {}

    #[cfg(feature = "alloc")]
    impl<const MAX: usize> zeroize::Zeroize for BoundedSecretVec<MAX> {
        #[inline]
        fn zeroize(&mut self) {
            self.clear_secret();
        }
    }

    #[cfg(feature = "alloc")]
    impl<const MAX: usize> zeroize::ZeroizeOnDrop for BoundedSecretVec<MAX> {}

    #[cfg(feature = "alloc")]
    impl zeroize::Zeroize for SecretString {
        #[inline]
        fn zeroize(&mut self) {
            self.clear_secret();
        }
    }

    #[cfg(feature = "alloc")]
    impl zeroize::ZeroizeOnDrop for SecretString {}

    #[cfg(feature = "alloc")]
    impl<const MAX: usize> zeroize::Zeroize for BoundedSecretString<MAX> {
        #[inline]
        fn zeroize(&mut self) {
            self.clear_secret();
        }
    }

    #[cfg(feature = "alloc")]
    impl<const MAX: usize> zeroize::ZeroizeOnDrop for BoundedSecretString<MAX> {}

    impl<T: SecureSanitize> zeroize::Zeroize for Secret<T> {
        #[inline]
        fn zeroize(&mut self) {
            self.secure_sanitize();
        }
    }

    impl<T: SecureSanitize> zeroize::ZeroizeOnDrop for Secret<T> {}

    impl<T: SecureSanitize> zeroize::Zeroize for ConsumeOnceSecret<T> {
        #[inline]
        fn zeroize(&mut self) {
            self.secure_sanitize();
        }
    }

    impl<T: SecureSanitize> zeroize::ZeroizeOnDrop for ConsumeOnceSecret<T> {}

    #[cfg(feature = "split-secret")]
    impl<const N: usize, const SHARES: usize> zeroize::Zeroize for SplitSecretBytes<N, SHARES> {
        #[inline]
        fn zeroize(&mut self) {
            self.secure_sanitize();
        }
    }

    #[cfg(feature = "split-secret")]
    impl<const N: usize, const SHARES: usize> zeroize::ZeroizeOnDrop for SplitSecretBytes<N, SHARES> {}

    #[cfg(feature = "memory-lock")]
    impl<const N: usize> zeroize::Zeroize for LockedSecretBytes<N> {
        #[inline]
        fn zeroize(&mut self) {
            self.secure_clear();
        }
    }

    #[cfg(feature = "memory-lock")]
    impl<const N: usize> zeroize::ZeroizeOnDrop for LockedSecretBytes<N> {}

    #[cfg(all(feature = "memory-lock", not(target_arch = "wasm32")))]
    impl zeroize::Zeroize for LockedSecretVec {
        #[inline]
        fn zeroize(&mut self) {
            self.clear_secret();
        }
    }

    #[cfg(all(feature = "memory-lock", not(target_arch = "wasm32")))]
    impl zeroize::ZeroizeOnDrop for LockedSecretVec {}

    #[cfg(all(feature = "memory-lock", not(target_arch = "wasm32")))]
    impl<const MAX: usize> zeroize::Zeroize for BoundedLockedSecretVec<MAX> {
        #[inline]
        fn zeroize(&mut self) {
            self.clear_secret();
        }
    }

    #[cfg(all(feature = "memory-lock", not(target_arch = "wasm32")))]
    impl<const MAX: usize> zeroize::ZeroizeOnDrop for BoundedLockedSecretVec<MAX> {}

    #[cfg(all(feature = "memory-lock", not(target_arch = "wasm32")))]
    impl zeroize::Zeroize for LockedSecretString {
        #[inline]
        fn zeroize(&mut self) {
            self.clear_secret();
        }
    }

    #[cfg(all(feature = "memory-lock", not(target_arch = "wasm32")))]
    impl zeroize::ZeroizeOnDrop for LockedSecretString {}

    #[cfg(all(feature = "memory-lock", not(target_arch = "wasm32")))]
    impl<const MAX: usize> zeroize::Zeroize for BoundedLockedSecretString<MAX> {
        #[inline]
        fn zeroize(&mut self) {
            self.clear_secret();
        }
    }

    #[cfg(all(feature = "memory-lock", not(target_arch = "wasm32")))]
    impl<const MAX: usize> zeroize::ZeroizeOnDrop for BoundedLockedSecretString<MAX> {}

    #[cfg(all(feature = "guard-pages", not(all(miri, test))))]
    impl zeroize::Zeroize for GuardedSecretVec {
        #[inline]
        fn zeroize(&mut self) {
            self.clear_secret();
        }
    }

    #[cfg(all(feature = "guard-pages", not(all(miri, test))))]
    impl zeroize::ZeroizeOnDrop for GuardedSecretVec {}

    #[cfg(all(feature = "guard-pages", not(all(miri, test))))]
    impl<const MAX: usize> zeroize::Zeroize for BoundedGuardedSecretVec<MAX> {
        #[inline]
        fn zeroize(&mut self) {
            self.clear_secret();
        }
    }

    #[cfg(all(feature = "guard-pages", not(all(miri, test))))]
    impl<const MAX: usize> zeroize::ZeroizeOnDrop for BoundedGuardedSecretVec<MAX> {}

    #[cfg(all(feature = "guard-pages", not(all(miri, test))))]
    impl zeroize::Zeroize for GuardedSecretString {
        #[inline]
        fn zeroize(&mut self) {
            self.clear_secret();
        }
    }

    #[cfg(all(feature = "guard-pages", not(all(miri, test))))]
    impl zeroize::ZeroizeOnDrop for GuardedSecretString {}

    #[cfg(all(feature = "guard-pages", not(all(miri, test))))]
    impl<const MAX: usize> zeroize::Zeroize for BoundedGuardedSecretString<MAX> {
        #[inline]
        fn zeroize(&mut self) {
            self.clear_secret();
        }
    }

    #[cfg(all(feature = "guard-pages", not(all(miri, test))))]
    impl<const MAX: usize> zeroize::ZeroizeOnDrop for BoundedGuardedSecretString<MAX> {}
}

#[cfg(feature = "subtle-interop")]
mod subtle_interop {
    use super::*;
    use subtle::{Choice, ConstantTimeEq};

    impl<const N: usize> ConstantTimeEq for SecretBytes<N> {
        #[inline]
        fn ct_eq(&self, other: &Self) -> Choice {
            Choice::from(self.constant_time_eq_secret(other) as u8)
        }
    }

    #[cfg(feature = "alloc")]
    impl ConstantTimeEq for SecretVec {
        #[inline]
        fn ct_eq(&self, other: &Self) -> Choice {
            Choice::from(
                self.with_secret(|left| {
                    other.with_secret(|right| constant_time_eq_slices(left, right))
                }) as u8,
            )
        }
    }

    #[cfg(feature = "alloc")]
    impl ConstantTimeEq for SecretBoxBytes {
        #[inline]
        fn ct_eq(&self, other: &Self) -> Choice {
            Choice::from(
                self.with_secret(|left| {
                    other.with_secret(|right| constant_time_eq_slices(left, right))
                }) as u8,
            )
        }
    }

    #[cfg(feature = "alloc")]
    impl<const MAX: usize> ConstantTimeEq for BoundedSecretVec<MAX> {
        #[inline]
        fn ct_eq(&self, other: &Self) -> Choice {
            Choice::from(
                self.with_secret(|left| {
                    other.with_secret(|right| constant_time_eq_slices(left, right))
                }) as u8,
            )
        }
    }

    #[cfg(feature = "alloc")]
    impl ConstantTimeEq for SecretString {
        #[inline]
        fn ct_eq(&self, other: &Self) -> Choice {
            Choice::from(constant_time_eq_slices(&self.inner, &other.inner) as u8)
        }
    }

    #[cfg(feature = "alloc")]
    impl<const MAX: usize> ConstantTimeEq for BoundedSecretString<MAX> {
        #[inline]
        fn ct_eq(&self, other: &Self) -> Choice {
            Choice::from(constant_time_eq_slices(&self.inner.inner, &other.inner.inner) as u8)
        }
    }

    #[cfg(feature = "memory-lock")]
    impl<const N: usize> ConstantTimeEq for LockedSecretBytes<N> {
        #[inline]
        fn ct_eq(&self, other: &Self) -> Choice {
            match self.try_expose_secret(|left| {
                other.try_expose_secret(|right| {
                    Choice::from(constant_time_eq_slices(left, right) as u8)
                })
            }) {
                Ok(Ok(choice)) => choice,
                Ok(Err(_)) | Err(_) => Choice::from(0),
            }
        }
    }

    #[cfg(all(feature = "memory-lock", not(target_arch = "wasm32")))]
    impl ConstantTimeEq for LockedSecretVec {
        #[inline]
        fn ct_eq(&self, other: &Self) -> Choice {
            match self.try_with_secret(|left| {
                other.try_with_secret(|right| {
                    Choice::from(constant_time_eq_slices(left, right) as u8)
                })
            }) {
                Ok(Ok(choice)) => choice,
                Ok(Err(_)) | Err(_) => Choice::from(0),
            }
        }
    }

    #[cfg(all(feature = "memory-lock", not(target_arch = "wasm32")))]
    impl<const MAX: usize> ConstantTimeEq for BoundedLockedSecretVec<MAX> {
        #[inline]
        fn ct_eq(&self, other: &Self) -> Choice {
            match self.try_with_secret(|left| {
                other.try_with_secret(|right| {
                    Choice::from(constant_time_eq_slices(left, right) as u8)
                })
            }) {
                Ok(Ok(choice)) => choice,
                Ok(Err(_)) | Err(_) => Choice::from(0),
            }
        }
    }

    #[cfg(all(feature = "memory-lock", not(target_arch = "wasm32")))]
    impl ConstantTimeEq for LockedSecretString {
        #[inline]
        fn ct_eq(&self, other: &Self) -> Choice {
            self.inner.ct_eq(&other.inner)
        }
    }

    #[cfg(all(feature = "memory-lock", not(target_arch = "wasm32")))]
    impl<const MAX: usize> ConstantTimeEq for BoundedLockedSecretString<MAX> {
        #[inline]
        fn ct_eq(&self, other: &Self) -> Choice {
            match self.try_with_secret(|left| {
                other.try_with_secret(|right| {
                    Choice::from(constant_time_eq_slices(left.as_bytes(), right.as_bytes()) as u8)
                })
            }) {
                Ok(Ok(choice)) => choice,
                Ok(Err(_)) | Err(_) => Choice::from(0),
            }
        }
    }

    #[cfg(all(feature = "guard-pages", not(all(miri, test))))]
    impl ConstantTimeEq for GuardedSecretVec {
        #[inline]
        fn ct_eq(&self, other: &Self) -> Choice {
            match self.try_with_secret(|left| {
                other.try_with_secret(|right| {
                    Choice::from(constant_time_eq_slices(left, right) as u8)
                })
            }) {
                Ok(Ok(choice)) => choice,
                Ok(Err(_)) | Err(_) => Choice::from(0),
            }
        }
    }

    #[cfg(all(feature = "guard-pages", not(all(miri, test))))]
    impl<const MAX: usize> ConstantTimeEq for BoundedGuardedSecretVec<MAX> {
        #[inline]
        fn ct_eq(&self, other: &Self) -> Choice {
            match self.try_with_secret(|left| {
                other.try_with_secret(|right| {
                    Choice::from(constant_time_eq_slices(left, right) as u8)
                })
            }) {
                Ok(Ok(choice)) => choice,
                Ok(Err(_)) | Err(_) => Choice::from(0),
            }
        }
    }

    #[cfg(all(feature = "guard-pages", not(all(miri, test))))]
    impl ConstantTimeEq for GuardedSecretString {
        #[inline]
        fn ct_eq(&self, other: &Self) -> Choice {
            self.inner.ct_eq(&other.inner)
        }
    }

    #[cfg(all(feature = "guard-pages", not(all(miri, test))))]
    impl<const MAX: usize> ConstantTimeEq for BoundedGuardedSecretString<MAX> {
        #[inline]
        fn ct_eq(&self, other: &Self) -> Choice {
            match self.try_with_secret(|left| {
                other.try_with_secret(|right| {
                    Choice::from(constant_time_eq_slices(left.as_bytes(), right.as_bytes()) as u8)
                })
            }) {
                Ok(Ok(choice)) => choice,
                Ok(Err(_)) | Err(_) => Choice::from(0),
            }
        }
    }
}

#[cfg(feature = "serde")]
mod serde_impls {
    use super::*;
    use serde::{
        de::{Error as DeError, IgnoredAny, SeqAccess, Visitor},
        Deserialize, Deserializer, Serialize, Serializer,
    };

    const REDACTED: &str = "<redacted>";

    impl<const N: usize> Serialize for SecretBytes<N> {
        #[inline]
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            serializer.serialize_str(REDACTED)
        }
    }

    impl<'de, const N: usize> Deserialize<'de> for SecretBytes<N> {
        #[inline]
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            deserializer.deserialize_bytes(SecretBytesVisitor::<N>)
        }
    }

    struct SecretBytesVisitor<const N: usize>;

    impl<'de, const N: usize> Visitor<'de> for SecretBytesVisitor<N> {
        type Value = SecretBytes<N>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(formatter, "exactly {N} secret bytes")
        }

        fn visit_bytes<E>(self, bytes: &[u8]) -> Result<Self::Value, E>
        where
            E: DeError,
        {
            if bytes.len() != N {
                return Err(E::invalid_length(bytes.len(), &self));
            }

            let mut secret = SecretBytes::<N>::zeroed();
            secret.copy_from_slice(bytes).map_err(E::custom)?;
            Ok(secret)
        }

        fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let mut secret = SecretBytes::<N>::zeroed();
            let mut index = 0;
            while index < N {
                let Some(byte) = sequence.next_element::<u8>()? else {
                    return Err(A::Error::invalid_length(index, &self));
                };
                secret.store(index, byte);
                index += 1;
            }

            if sequence.next_element::<IgnoredAny>()?.is_some() {
                return Err(A::Error::invalid_length(N.saturating_add(1), &self));
            }

            secret.after_secret_write();
            Ok(secret)
        }
    }

    #[cfg(feature = "alloc")]
    impl Serialize for SecretVec {
        #[inline]
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            serializer.serialize_str(REDACTED)
        }
    }

    #[cfg(feature = "alloc")]
    impl Serialize for SecretBoxBytes {
        #[inline]
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            serializer.serialize_str(REDACTED)
        }
    }

    #[cfg(feature = "alloc")]
    impl<'de> Deserialize<'de> for SecretBoxBytes {
        #[inline]
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            deserializer.deserialize_bytes(SecretBoxBytesVisitor)
        }
    }

    #[cfg(feature = "alloc")]
    struct SecretBoxBytesVisitor;

    #[cfg(feature = "alloc")]
    impl<'de> Visitor<'de> for SecretBoxBytesVisitor {
        type Value = SecretBoxBytes;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("fixed-allocation secret bytes")
        }

        fn visit_bytes<E>(self, bytes: &[u8]) -> Result<Self::Value, E>
        where
            E: DeError,
        {
            SecretBoxBytes::try_from_slice(bytes, DEFAULT_SECRET_VEC_SERDE_MAX_LEN)
                .map_err(E::custom)
        }

        fn visit_byte_buf<E>(self, bytes: Vec<u8>) -> Result<Self::Value, E>
        where
            E: DeError,
        {
            // Own the plaintext through a clear-on-drop type before invoking
            // generic error conversion or allocating the destination.
            let temporary = SecretVec::from_vec(bytes);
            temporary.with_secret(|bytes| {
                SecretBoxBytes::try_from_slice(bytes, DEFAULT_SECRET_VEC_SERDE_MAX_LEN)
                    .map_err(E::custom)
            })
        }

        fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let capacity = sequence
                .size_hint()
                .unwrap_or(0)
                .min(DEFAULT_SECRET_VEC_SERDE_MAX_LEN)
                .min(SECRET_VEC_SERDE_MAX_PREALLOC);
            let mut temporary = SecretVec::with_capacity(capacity);

            while temporary.len() < DEFAULT_SECRET_VEC_SERDE_MAX_LEN {
                let Some(byte) = sequence.next_element::<u8>()? else {
                    return temporary.with_secret(|bytes| {
                        SecretBoxBytes::try_from_slice(bytes, DEFAULT_SECRET_VEC_SERDE_MAX_LEN)
                            .map_err(A::Error::custom)
                    });
                };
                temporary.extend_from_slice(&[byte]);
            }

            if sequence.next_element::<IgnoredAny>()?.is_some() {
                return Err(A::Error::custom(SecretVecLimitError {
                    maximum: DEFAULT_SECRET_VEC_SERDE_MAX_LEN,
                    actual: DEFAULT_SECRET_VEC_SERDE_MAX_LEN.saturating_add(1),
                }));
            }

            temporary.with_secret(|bytes| {
                SecretBoxBytes::try_from_slice(bytes, DEFAULT_SECRET_VEC_SERDE_MAX_LEN)
                    .map_err(A::Error::custom)
            })
        }
    }

    #[cfg(feature = "alloc")]
    impl<'de> Deserialize<'de> for SecretVec {
        #[inline]
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            deserializer.deserialize_bytes(SecretVecVisitor)
        }
    }

    #[cfg(feature = "alloc")]
    struct SecretVecVisitor;

    #[cfg(feature = "alloc")]
    const SECRET_VEC_SERDE_MAX_PREALLOC: usize = 4096;

    #[cfg(feature = "alloc")]
    fn validate_default_secret_vec_len<E: DeError>(actual: usize) -> Result<(), E> {
        if actual > DEFAULT_SECRET_VEC_SERDE_MAX_LEN {
            Err(E::custom(SecretVecLimitError {
                maximum: DEFAULT_SECRET_VEC_SERDE_MAX_LEN,
                actual,
            }))
        } else {
            Ok(())
        }
    }

    #[cfg(feature = "alloc")]
    impl<'de> Visitor<'de> for SecretVecVisitor {
        type Value = SecretVec;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("secret bytes")
        }

        fn visit_bytes<E>(self, bytes: &[u8]) -> Result<Self::Value, E>
        where
            E: DeError,
        {
            validate_default_secret_vec_len::<E>(bytes.len())?;
            Ok(SecretVec::from_slice(bytes))
        }

        fn visit_byte_buf<E>(self, mut bytes: Vec<u8>) -> Result<Self::Value, E>
        where
            E: DeError,
        {
            if let Err(error) = validate_default_secret_vec_len::<E>(bytes.len()) {
                crate::owned::sanitize_vec_capacity(&mut bytes);
                return Err(error);
            }
            Ok(SecretVec::from_vec(bytes))
        }

        fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let capacity = sequence
                .size_hint()
                .unwrap_or(0)
                .min(DEFAULT_SECRET_VEC_SERDE_MAX_LEN)
                .min(SECRET_VEC_SERDE_MAX_PREALLOC);
            let mut secret = SecretVec::with_capacity(capacity);

            while secret.len() < DEFAULT_SECRET_VEC_SERDE_MAX_LEN {
                let Some(byte) = sequence.next_element::<u8>()? else {
                    return Ok(secret);
                };
                secret.extend_from_slice(&[byte]);
            }

            if sequence.next_element::<IgnoredAny>()?.is_some() {
                return Err(A::Error::custom(SecretVecLimitError {
                    maximum: DEFAULT_SECRET_VEC_SERDE_MAX_LEN,
                    actual: DEFAULT_SECRET_VEC_SERDE_MAX_LEN.saturating_add(1),
                }));
            }

            Ok(secret)
        }
    }

    #[cfg(feature = "alloc")]
    impl<const MAX: usize> Serialize for BoundedSecretVec<MAX> {
        #[inline]
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            serializer.serialize_str(REDACTED)
        }
    }

    #[cfg(feature = "alloc")]
    impl<'de, const MAX: usize> Deserialize<'de> for BoundedSecretVec<MAX> {
        #[inline]
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            deserializer.deserialize_bytes(BoundedSecretVecVisitor::<MAX>)
        }
    }

    #[cfg(feature = "alloc")]
    struct BoundedSecretVecVisitor<const MAX: usize>;

    #[cfg(feature = "alloc")]
    impl<'de, const MAX: usize> Visitor<'de> for BoundedSecretVecVisitor<MAX> {
        type Value = BoundedSecretVec<MAX>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(formatter, "at most {MAX} secret bytes")
        }

        fn visit_bytes<E>(self, bytes: &[u8]) -> Result<Self::Value, E>
        where
            E: DeError,
        {
            BoundedSecretVec::from_slice(bytes).map_err(E::custom)
        }

        fn visit_byte_buf<E>(self, bytes: Vec<u8>) -> Result<Self::Value, E>
        where
            E: DeError,
        {
            BoundedSecretVec::from_vec(bytes).map_err(E::custom)
        }

        fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let capacity = sequence
                .size_hint()
                .unwrap_or(0)
                .min(MAX)
                .min(SECRET_VEC_SERDE_MAX_PREALLOC);
            let mut secret = SecretVec::with_capacity(capacity);

            while secret.len() < MAX {
                let Some(byte) = sequence.next_element::<u8>()? else {
                    return Ok(BoundedSecretVec { inner: secret });
                };
                secret.extend_from_slice(&[byte]);
            }

            if sequence.next_element::<IgnoredAny>()?.is_some() {
                return Err(A::Error::custom(SecretVecLimitError {
                    maximum: MAX,
                    actual: MAX.saturating_add(1),
                }));
            }

            Ok(BoundedSecretVec { inner: secret })
        }
    }

    #[cfg(feature = "alloc")]
    impl Serialize for SecretString {
        #[inline]
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            serializer.serialize_str(REDACTED)
        }
    }

    #[cfg(feature = "alloc")]
    impl<'de> Deserialize<'de> for SecretString {
        #[inline]
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            deserializer.deserialize_string(SecretStringVisitor)
        }
    }

    #[cfg(feature = "alloc")]
    struct SecretStringVisitor;

    #[cfg(feature = "alloc")]
    fn validate_default_secret_string_len<E: DeError>(actual: usize) -> Result<(), E> {
        if actual > DEFAULT_SECRET_STRING_SERDE_MAX_LEN {
            Err(E::custom(SecretStringLimitError {
                maximum: DEFAULT_SECRET_STRING_SERDE_MAX_LEN,
                actual,
            }))
        } else {
            Ok(())
        }
    }

    #[cfg(feature = "alloc")]
    impl<'de> Visitor<'de> for SecretStringVisitor {
        type Value = SecretString;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("secret UTF-8 text")
        }

        fn visit_str<E>(self, text: &str) -> Result<Self::Value, E>
        where
            E: DeError,
        {
            validate_default_secret_string_len::<E>(text.len())?;
            Ok(SecretString::from_secret_str(text))
        }

        fn visit_string<E>(self, mut text: String) -> Result<Self::Value, E>
        where
            E: DeError,
        {
            if let Err(error) = validate_default_secret_string_len::<E>(text.len()) {
                text.secure_sanitize();
                return Err(error);
            }
            Ok(SecretString::from_string(text))
        }
    }

    #[cfg(feature = "alloc")]
    impl<const MAX: usize> Serialize for BoundedSecretString<MAX> {
        #[inline]
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            serializer.serialize_str(REDACTED)
        }
    }

    #[cfg(feature = "alloc")]
    impl<'de, const MAX: usize> Deserialize<'de> for BoundedSecretString<MAX> {
        #[inline]
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            deserializer.deserialize_string(BoundedSecretStringVisitor::<MAX>)
        }
    }

    #[cfg(feature = "alloc")]
    struct BoundedSecretStringVisitor<const MAX: usize>;

    #[cfg(feature = "alloc")]
    impl<'de, const MAX: usize> Visitor<'de> for BoundedSecretStringVisitor<MAX> {
        type Value = BoundedSecretString<MAX>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(formatter, "at most {MAX} UTF-8 bytes of secret text")
        }

        fn visit_str<E>(self, text: &str) -> Result<Self::Value, E>
        where
            E: DeError,
        {
            BoundedSecretString::from_secret_str(text).map_err(E::custom)
        }

        fn visit_string<E>(self, text: String) -> Result<Self::Value, E>
        where
            E: DeError,
        {
            BoundedSecretString::from_string(text).map_err(E::custom)
        }
    }

    impl<T> Serialize for Secret<T>
    where
        T: SecureSanitize,
    {
        #[inline]
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            serializer.serialize_str(REDACTED)
        }
    }

    impl<'de, T> Deserialize<'de> for Secret<T>
    where
        T: SecureSanitize + Deserialize<'de>,
    {
        #[inline]
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            T::deserialize(deserializer).map(Secret::new)
        }
    }

    impl<T> Serialize for ConsumeOnceSecret<T>
    where
        T: SecureSanitize,
    {
        #[inline]
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            serializer.serialize_str(REDACTED)
        }
    }

    impl<'de, T> Deserialize<'de> for ConsumeOnceSecret<T>
    where
        T: SecureSanitize + Deserialize<'de>,
    {
        #[inline]
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            T::deserialize(deserializer).map(ConsumeOnceSecret::new)
        }
    }

    #[cfg(all(test, feature = "alloc"))]
    mod tests {
        use super::*;
        use serde::de::value::Error as ValueError;
        use std::panic::{catch_unwind, AssertUnwindSafe};

        #[derive(Debug)]
        struct PanickingError;

        impl fmt::Display for PanickingError {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("panicking serde error")
            }
        }

        impl std::error::Error for PanickingError {}

        impl DeError for PanickingError {
            fn custom<T: fmt::Display>(_message: T) -> Self {
                panic!("exercise serde error unwind")
            }
        }

        #[test]
        fn default_secret_vec_limit_rejects_excess_length() {
            assert!(validate_default_secret_vec_len::<ValueError>(
                DEFAULT_SECRET_VEC_SERDE_MAX_LEN
            )
            .is_ok());
            assert!(validate_default_secret_vec_len::<ValueError>(
                DEFAULT_SECRET_VEC_SERDE_MAX_LEN.saturating_add(1)
            )
            .is_err());
        }

        #[test]
        fn default_secret_string_limit_rejects_excess_length() {
            assert!(validate_default_secret_string_len::<ValueError>(
                DEFAULT_SECRET_STRING_SERDE_MAX_LEN
            )
            .is_ok());
            assert!(validate_default_secret_string_len::<ValueError>(
                DEFAULT_SECRET_STRING_SERDE_MAX_LEN.saturating_add(1)
            )
            .is_err());
        }

        #[test]
        fn secret_box_owned_buffer_is_guarded_before_error_conversion() {
            let bytes = alloc::vec![0xA5; DEFAULT_SECRET_VEC_SERDE_MAX_LEN + 1];

            let result = catch_unwind(AssertUnwindSafe(|| {
                let _ = SecretBoxBytesVisitor.visit_byte_buf::<PanickingError>(bytes);
            }));

            assert!(result.is_err());
        }
    }
}
