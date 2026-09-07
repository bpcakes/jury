#[cfg(feature = "alloc")]
use sanitization::{BoundedSecretString, SecretString, SecretVec};

fn main() {
    #[cfg(feature = "alloc")]
    {
        let mut token = SecretString::from_string(String::from("bearer-token"));
        assert_eq!(token.try_with_secret(str::len), Ok(12));

        token = SecretString::with_capacity(32);
        token.push_str("bearer-token");
        token
            .try_with_secret_mut(|text| text.make_ascii_uppercase())
            .unwrap();
        assert_eq!(token.try_with_secret(str::len), Ok(12));

        let mut bytes = SecretVec::from_vec(vec![115, 101, 99, 114, 101, 116]);
        assert_eq!(bytes.with_secret(|value| value.len()), 6);

        bytes = SecretVec::with_capacity(16);
        bytes.extend_from_slice(b"secret");
        assert_eq!(bytes.with_secret(|value| value.len()), 6);

        let text = SecretString::from_secret_vec(bytes).unwrap();
        assert!(text.constant_time_eq("secret"));

        let mut bounded = BoundedSecretString::<16>::from_secret_string(text).unwrap();
        bounded.push_str("-token").unwrap();
        assert!(bounded.constant_time_eq("secret-token"));
    }
}
