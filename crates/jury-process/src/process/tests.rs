include!("tests/setup_and_io.rs");
include!("tests/output_and_interaction.rs");
include!("tests/cleanup_and_platform.rs");
include!("tests/native_containment.rs");

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[path = "tests/native_churn.rs"]
mod native_churn;

#[cfg(target_os = "macos")]
#[path = "tests/native_proof_churn.rs"]
mod native_proof_churn;

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[path = "tests/combined_failures.rs"]
mod combined_failures;
