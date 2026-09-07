#[cfg(feature = "std")]
use sanitization::ExpiringSecretBytes;
#[cfg(all(
    feature = "memory-lock",
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
use sanitization::LockedSecretBytes;
#[cfg(all(
    feature = "memory-lock",
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64"),
    not(miri)
))]
use sanitization::LockedSecretString;
#[cfg(feature = "cache-flush")]
use sanitization::{cache_flush::cache_flush_sanitize_bytes, SecretBytes};
#[cfg(all(
    feature = "guard-pages",
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64"),
    not(miri)
))]
use sanitization::{GuardedSecretString, GuardedSecretVec};

fn main() {
    #[cfg(feature = "std")]
    {
        let mut key =
            ExpiringSecretBytes::<32>::from_array([7; 32], std::time::Duration::from_secs(300));
        assert_eq!(key.try_constant_time_eq(&[7; 32]), Ok(true));
        key.replace_from_array([8; 32]);
        key.try_replace_from_fn(|_| Ok::<u8, &'static str>(9))
            .unwrap();
        assert_eq!(key.try_constant_time_eq(&[9; 32]), Ok(true));
    }

    #[cfg(all(
        feature = "memory-lock",
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    {
        let mut key = LockedSecretBytes::<32>::from_fn(|_| 9).unwrap();
        assert_eq!(key.try_constant_time_eq(&[9; 32]), Ok(true));
        key.try_replace_from_array([8; 32]).unwrap();
        key.try_replace_from_fallible_fn(|_| Ok::<u8, &'static str>(7))
            .unwrap();
        assert_eq!(key.try_constant_time_eq(&[7; 32]), Ok(true));
        key.into_cleared();
    }

    #[cfg(all(
        feature = "memory-lock",
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64"),
        not(miri)
    ))]
    {
        let mut token = LockedSecretString::from_secret_str("session-token").unwrap();
        token.try_push_str("-v2").unwrap();
        assert_eq!(token.try_constant_time_eq("session-token-v2"), Ok(true));
    }

    #[cfg(feature = "cache-flush")]
    {
        let mut scratch = [0xA5; 32];
        let scratch_result = cache_flush_sanitize_bytes(&mut scratch);
        assert_eq!(scratch, [0; 32]);

        let mut key = SecretBytes::<32>::from_array([1; 32]);
        let key_result = key.secure_clear_and_flush();
        assert!(key.constant_time_eq(&[0; 32]));
        assert_eq!(scratch_result.is_ok(), key_result.is_ok());
    }

    #[cfg(all(
        feature = "guard-pages",
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64"),
        not(miri)
    ))]
    {
        let mut token = GuardedSecretVec::from_slice(b"session-key").unwrap();
        token.try_extend_from_slice(b"-v2").unwrap();
        assert_eq!(token.try_with_secret(|bytes| bytes.len()), Ok(14));
        token
            .try_replace_from_fn(11, |index| b"session-key"[index])
            .unwrap();
        token
            .try_replace_from_fallible_fn(12, |index| {
                Ok::<u8, &'static str>(b"session-key!"[index])
            })
            .unwrap();
        assert_eq!(token.try_constant_time_eq(b"session-key!"), Ok(true));
        token.into_cleared();

        let mut text = GuardedSecretString::from_secret_str("session-token").unwrap();
        text.try_push_str("-v2").unwrap();
        assert_eq!(text.try_constant_time_eq("session-token-v2"), Ok(true));
    }

    #[cfg(all(
        feature = "guard-pages",
        feature = "memory-lock",
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64"),
        not(miri)
    ))]
    {
        let mut token =
            GuardedSecretVec::locked_from_fn(11, |index| b"session-key"[index]).unwrap();
        assert!(token.is_memory_locked());
        assert_eq!(token.try_constant_time_eq(b"session-key"), Ok(true));
        token
            .try_replace_from_fallible_fn(12, |index| {
                Ok::<u8, &'static str>(b"session-key!"[index])
            })
            .unwrap();
        assert!(token.is_memory_locked());
        assert_eq!(token.try_constant_time_eq(b"session-key!"), Ok(true));
    }
}
