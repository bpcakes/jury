use sanitization::wipe::{self, WipeOnDrop};

fn main() {
    let mut bytes = [0xA5; 32];
    wipe::bytes(&mut bytes);
    assert_eq!(bytes, [0; 32]);

    let secret = WipeOnDrop::new([1_u8, 2, 3, 4]);
    assert_eq!(secret.with_secret(|bytes| bytes.len()), 4);
}
