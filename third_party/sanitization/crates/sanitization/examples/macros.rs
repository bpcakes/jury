use sanitization::{secure_drop_struct, SecretBytes};

secure_drop_struct! {
    struct SessionCredentials {
        private_key: SecretBytes<32>,
        nonce: SecretBytes<12>,
    }
}

fn main() {
    let credentials = SessionCredentials {
        private_key: SecretBytes::from_array([1; 32]),
        nonce: SecretBytes::from_array([2; 12]),
    };

    assert!(credentials.private_key.constant_time_eq(&[1; 32]));
    assert!(credentials.nonce.constant_time_eq(&[2; 12]));
}
