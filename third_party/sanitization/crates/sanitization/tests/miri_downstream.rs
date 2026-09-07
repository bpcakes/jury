#![cfg(miri)]

use sanitization::{ct::ConstantTimeEq, SecretBytes};

#[test]
fn default_comparison_uses_the_portable_backend_under_downstream_miri() {
    let left = SecretBytes::<4>::from_array([1, 2, 3, 4]);
    let same = SecretBytes::<4>::from_array([1, 2, 3, 4]);
    let different = SecretBytes::<4>::from_array([1, 2, 3, 0]);

    assert!(left
        .ct_eq(&same)
        .declassify("test verifies downstream Miri equality"));
    assert!(!left
        .ct_eq(&different)
        .declassify("test verifies downstream Miri inequality"));
}
