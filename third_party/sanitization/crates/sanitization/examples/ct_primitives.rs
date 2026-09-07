use sanitization::ct::{
    self, Choice, ConditionallySelectable, ConstantTimeEq, ConstantTimeOrd, PublicCtOption,
    PublicCtResult, SecretCtOption, SecretCtResult, SecretIndex,
};
use sanitization::SecureSanitize;

fn main() {
    let left = [7u8; 32];
    let right = [7u8; 32];

    let equal = left.ct_eq(&right);
    assert!(equal.declassify("example equality result is public"));

    let ordering = 10u32.ct_cmp(&20);
    assert!(ordering
        .is_less()
        .declassify("example ordering result is public"));

    let selected = u32::conditional_select(&10, &20, Choice::TRUE);
    assert_eq!(selected, 20);

    let maybe = PublicCtOption::some(41u8).map(|value| value.wrapping_add(1));
    assert_eq!(maybe.unwrap_or(&0), 42);
    assert_eq!(
        maybe.declassify("example option presence is public"),
        Some(42)
    );

    let checked = PublicCtResult::new(7u8, 0u8, Choice::TRUE).map(|value| value.wrapping_add(1));
    assert_eq!(checked.unwrap_or(&0), 8);
    assert_eq!(checked.declassify("example result is public"), Ok(8));

    let table = [10u8, 20, 30, 40];
    let value = ct::oblivious_lookup(&table, SecretIndex::new(2usize), &0);
    assert_eq!(value, 30);

    let maybe_secret = SecretCtOption::secret([7u8; 4], Choice::TRUE);
    let mut secret = maybe_secret
        .declassify("example secret presence is public")
        .expect("secret is present");
    secret.secure_sanitize();

    let secret_result = SecretCtResult::secret_success([9u8; 4], "invalid", Choice::FALSE);
    assert!(secret_result
        .declassify("example secret result is public")
        .is_err());

    let mut destination = [0u8; 4];
    let a = [1u8, 2, 3, 4];
    let b = [9u8, 8, 7, 6];
    ct::select_slice(&mut destination, &a, &b, Choice::TRUE).unwrap();
    assert_eq!(destination, b);

    let mut swap_left = [1u8, 1, 1, 1];
    let mut swap_right = [2u8, 2, 2, 2];
    ct::conditional_swap(&mut swap_left, &mut swap_right, Choice::TRUE).unwrap();
    assert_eq!(swap_left, [2u8; 4]);
    assert_eq!(swap_right, [1u8; 4]);
}
