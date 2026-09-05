//! Development-only parser oracles. Inputs must be synthetic public fixtures.
#![forbid(unsafe_code)]

pub mod core_artifacts;
pub mod input_boundaries;
pub mod protocol;
pub mod seeds;
pub mod witness;

// Panic messages identify the violated oracle without printing input bytes.
fn require<T, E>(result: Result<T, E>) -> T {
    match result {
        Ok(value) => value,
        Err(_) => panic!("accepted parser value failed its round-trip oracle"),
    }
}

fn identical(left: &[u8], right: &[u8]) {
    assert!(left == right, "canonical round trip changed bytes");
}
