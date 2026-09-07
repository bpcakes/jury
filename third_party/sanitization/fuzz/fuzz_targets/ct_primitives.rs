#![no_main]

use libfuzzer_sys::fuzz_target;
use sanitization::ct::{self, Choice, SecretIndex};

fuzz_target!(|data: &[u8]| {
    let mut left = [0_u8; 32];
    let mut right = [0_u8; 32];
    for (index, byte) in data.iter().copied().enumerate() {
        if index % 2 == 0 {
            left[(index / 2) % left.len()] ^= byte;
        } else {
            right[(index / 2) % right.len()] ^= byte;
        }
    }

    let choice = Choice::from_u8(data.first().copied().unwrap_or(0));
    let _ = ct::eq_fixed(&left, &right);
    let _ = ct::cmp_fixed(&left, &right);
    ct::conditional_copy(&mut left, &right, choice).expect("fixed lengths");
    ct::conditional_swap(&mut left, &mut right, choice).expect("fixed lengths");
    let _ = ct::oblivious_lookup(&left, SecretIndex::new(data.len()), &0);
});
