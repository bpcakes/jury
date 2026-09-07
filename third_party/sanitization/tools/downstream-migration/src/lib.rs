#![deny(unsafe_code)]

use sanitization::{
    define_secret_storage_policy, SecretBytes, SecureSanitize, StableMutableSecretStorage,
    StableSharedSecretStorage,
};

#[derive(SecureSanitize)]
pub struct FixedCredentials {
    key: SecretBytes<32>,
    nonce: [u8; 12],
    #[sanitization(skip, reason = "public protocol identifier")]
    protocol: u16,
}

// STORAGE CONTRACT: every secret-bearing field has fixed inline storage.
// Shared methods do not mutate it and mutable methods overwrite it in place.
impl StableSharedSecretStorage for FixedCredentials {}
impl StableMutableSecretStorage for FixedCredentials {}

define_secret_storage_policy! {
    MigrationStoragePolicy {
        FixedCredentials => "downstream fixture reviewed fixed inline storage",
    }
}

impl FixedCredentials {
    pub fn new(key: [u8; 32], nonce: [u8; 12], protocol: u16) -> Self {
        Self {
            key: SecretBytes::from_array(key),
            nonce,
            protocol,
        }
    }

    pub fn protocol(&self) -> u16 {
        self.protocol
    }

    pub fn key(&self) -> &SecretBytes<32> {
        &self.key
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use arrayvec::ArrayVec;
    use core::sync::atomic::{AtomicU64, Ordering};
    use sanitization::ct::{
        Choice, ConditionallySelectable as CtConditionallySelectable,
        ConstantTimeEq as CtConstantTimeEq,
    };
    use sanitization::{
        AllowlistedSecret, ConditionallySelectable, ConstantTimeEq, ProtectionRequest,
        Requirement,
    };
    use sanitization_arrayvec::SecretArrayVec;
    use sanitization_bytes::SecretBytesMut;
    use sanitization_crypto_interop::{blake3, hmac_sha2, sha2};

    #[derive(Clone, Copy, ConstantTimeEq, ConditionallySelectable)]
    struct Tag {
        left: [u8; 16],
        right: [u8; 16],
    }

    fn next_fixture_nonce() -> [u8; 12] {
        static SEQUENCE: AtomicU64 = AtomicU64::new(1);

        let sequence = SEQUENCE.fetch_add(1, Ordering::Relaxed).to_le_bytes();
        let process = std::process::id().to_le_bytes();
        core::array::from_fn(|index| {
            sequence[index % sequence.len()] ^ process[index % process.len()]
        })
    }

    #[test]
    fn generic_storage_contract_and_derive_work_downstream() {
        let mut secret =
            AllowlistedSecret::<FixedCredentials, MigrationStoragePolicy>::new(
                FixedCredentials::new([7; 32], next_fixture_nonce(), 0x0304),
            );
        assert_eq!(secret.with_secret(FixedCredentials::protocol), 0x0304);
        secret.with_secret_mut(|credentials| credentials.nonce[0] = 3);
        assert_eq!(secret.with_secret(|credentials| credentials.nonce[0]), 3);
    }

    #[test]
    fn ct_derive_requires_explicit_declassification() {
        let a = Tag {
            left: [1; 16],
            right: [2; 16],
        };
        let b = Tag {
            left: [1; 16],
            right: [2; 16],
        };
        assert!(a.ct_eq(&b).declassify("test tag equality is public"));
        let selected = Tag::conditional_select(&a, &b, Choice::TRUE);
        assert!(selected
            .ct_eq(&b)
            .declassify("test selection result is public"));
    }

    #[test]
    fn crypto_helpers_accept_direct_secret_exposure() {
        let credentials = FixedCredentials::new([0x42; 32], next_fixture_nonce(), 1);
        credentials.key().expose_secret(|key| {
            let tag = hmac_sha2::hmac_sha256(key, b"migration");
            assert!(hmac_sha2::hmac_sha256_verify(key, b"migration", &tag));

            let digest = blake3::blake3_keyed_digest(key, b"migration");
            assert!(blake3::blake3_keyed_digest_verify(
                key,
                b"migration",
                &digest
            ));
        });

        let mut hasher = sha2::SanitizedSha512::new();
        hasher.update(b"migration");
        let digest = hasher.finalize();
        assert_ne!(digest, [0; 64]);
    }

    #[test]
    fn companion_storage_paths_are_bounded() {
        let source = ArrayVec::<u8, 8>::from_iter([1, 2, 3]);
        let mut inline = SecretArrayVec::from_arrayvec(source);
        inline.push_or_sanitize(4).unwrap();
        assert_eq!(inline.as_slice(), &[1, 2, 3, 4]);

        let mut bytes = SecretBytesMut::with_capacity(8);
        let capacity = bytes.capacity();
        bytes.extend_from_slice(&vec![7; capacity]).unwrap();
        assert!(bytes.extend_from_slice(&[8]).is_err());
    }

    #[test]
    fn serde_ingestion_uses_secret_leaf_type() {
        let secret: SecretBytes<4> = serde_json::from_str("[1,2,3,4]").unwrap();
        assert!(secret.constant_time_eq(&[1, 2, 3, 4]));
        assert_eq!(serde_json::to_string(&secret).unwrap(), "\"<redacted>\"");
    }

    #[test]
    fn protection_policy_is_distinct_from_runtime_result() {
        let request = ProtectionRequest::locked();
        assert_eq!(request.memory_lock, Requirement::Required);
        assert_ne!(request.guard_pages, Requirement::Required);
    }
}
