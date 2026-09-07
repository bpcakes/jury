use sanitization::SecretBytes;

fn main() {
    let key = SecretBytes::<32>::from_fn(|index| index as u8);

    let key_len = key.expose_secret(|bytes| bytes.len());
    assert_eq!(key_len, 32);
}
