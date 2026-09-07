use sanitization::{
    define_secret_storage_policy, AllowlistedSecret, SecretBytes, SecureSanitize,
    StableMutableSecretStorage, StableSharedSecretStorage,
};

struct FixedCredentials {
    key: SecretBytes<32>,
    nonce: [u8; 12],
}

impl SecureSanitize for FixedCredentials {
    fn secure_sanitize(&mut self) {
        self.key.secure_sanitize();
        self.nonce.secure_sanitize();
    }
}

// STORAGE CONTRACT: all secret storage is inline and fixed-size. Shared methods
// only inspect fields; mutable methods overwrite fields in place.
impl StableSharedSecretStorage for FixedCredentials {}
impl StableMutableSecretStorage for FixedCredentials {}

define_secret_storage_policy! {
    DeploymentStoragePolicy {
        FixedCredentials => "reviewed fixed inline credentials storage",
    }
}

fn require_stable_storage<T: StableMutableSecretStorage>(value: &mut T) {
    value.secure_sanitize();
}

fn main() {
    let credentials = FixedCredentials {
        key: SecretBytes::from_array([7; 32]),
        nonce: [9; 12],
    };
    let mut secret =
        AllowlistedSecret::<FixedCredentials, DeploymentStoragePolicy>::new(credentials);

    assert_eq!(secret.with_secret(|value| value.nonce[0]), 9);
    secret.with_secret_mut(require_stable_storage);
    assert_eq!(secret.with_secret(|value| value.nonce[0]), 0);
}
