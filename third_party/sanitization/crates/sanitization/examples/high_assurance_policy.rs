use sanitization::{define_secret_storage_policy, AllowlistedSecret, SecretBytes};

mod approved_storage {
    use super::{define_secret_storage_policy, SecretBytes};

    define_secret_storage_policy! {
        pub(crate) HighAssuranceStoragePolicy {
            SecretBytes<32> =>
                "fixed inline key; no interior mutation or ownership extraction",
            SecretBytes<12> =>
                "fixed inline nonce; no interior mutation or ownership extraction",
        }
    }
}

type ProtectedKey =
    AllowlistedSecret<SecretBytes<32>, approved_storage::HighAssuranceStoragePolicy>;
type ProtectedNonce =
    AllowlistedSecret<SecretBytes<12>, approved_storage::HighAssuranceStoragePolicy>;

fn main() {
    let key = ProtectedKey::new(SecretBytes::zeroed());
    let nonce = ProtectedNonce::new(SecretBytes::zeroed());

    assert_eq!(
        ProtectedKey::policy_rationale(),
        "fixed inline key; no interior mutation or ownership extraction"
    );
    assert_eq!(
        ProtectedNonce::policy_rationale(),
        "fixed inline nonce; no interior mutation or ownership extraction"
    );
    drop((key, nonce));
}
