#![no_std]
#![deny(unsafe_code)]
#![deny(unsafe_op_in_unsafe_fn)]

//! Dependency-free secret memory sanitization for `no_std` Rust.
//!
//! The primary type is [`SecretBytes`], a fixed-size clear-on-drop container
//! designed for secrets that are controlled from creation through destruction.
//!
//! Clearing routes through a small internal volatile-write backend. That backend
//! uses one isolated unsafe boundary so the optimizer cannot remove secret
//! clearing as a dead store.
//!
//! The [`ct`] module provides dependency-free data-oblivious primitives such as
//! [`ct::Choice`], [`ct::ConstantTimeEq`], and explicit
//! [`ct::Choice::declassify`] boundaries. Secret-controlled indexes and
//! scalars use clear-on-drop [`ct::SecretIndex`] and [`ct::SecretScalar`]
//! owners, while [`ct::SecretCtOption`] and [`ct::SecretCtResult`] manage
//! secret-bearing dummy and unselected state. Its claim is no secret-dependent
//! control flow or memory access under documented conditions, not identical
//! wall-clock timing on every target.
//!
//! Important limits:
//! - Safe Rust cannot soundly scrub old stack frames created by prior moves.
//! - Process abort prevents destructors and post-closure cleanup from running.
//!   Under `std`, [`sanitize_then_abort`] clears one explicitly supplied root
//!   before a deliberate abort; it does not intercept arbitrary abort paths.
//! - SIMD stores, broad memory policy, and target-specific hardening need
//!   target-specific unsafe code and platform policy.
//! - Platform memory locking is available only through the explicit
//!   `memory-lock` feature on supported Linux, Android, macOS, iOS, Windows,
//!   and BSD targets. On WASM, `memory-lock` must be paired with `wasm-compat`
//!   to expose volatile-only compatibility types without host memory locking.
//!   The same feature also enables pooled slots with [`SecretPool`] on
//!   supported targets. The crate's own Miri unit tests use a test-only
//!   aligned-allocation model for lifecycle and clear-before-release checks;
//!   modeled report states do not prove that an OS protection was applied.
//!   Downstream Miri execution of native mapped constructors is unsupported.
//! - Locked, pooled, and guarded canary integrity checks are available only
//!   through the explicit `canary-check` feature on supported targets.
//! - OS-CSPRNG canary generation is available only through the explicit
//!   `random-canary` feature.
//! - The dependency-free default enables `asm-compare`, selecting the reviewed
//!   x86_64/AArch64 assembly equality backend where available. Builds using
//!   `default-features = false` retain the weaker portable fallback unless they
//!   explicitly enable `asm-compare`.
//! - Fail-closed assembly-backed equal-length byte comparison is available
//!   through `strict-compare`. This feature does not strengthen ordering,
//!   selection, lookup, or caller code. Other fail-closed profiles include
//!   `strict-canary-check` and `require-fork-exclusion`.
//! - Named native profiles bundle reviewed capabilities without claiming that
//!   runtime protections succeeded. Use [`ProtectionRequest`] to inspect the
//!   policy and [`ProtectionReport`] to inspect achieved controls.
//! - Checked x86_64 cache-line eviction is available through the explicit
//!   `cache-flush` feature. Other architectures and Miri return a structured
//!   unsupported result after sanitizing helpers have still cleared memory.
//! - Proc-macro derives are available only through the explicit `derive`
//!   feature. The default build remains dependency-free.
//! - `zeroize`, `subtle`, and `serde` integration are available only through
//!   explicit `zeroize-interop`, `subtle-interop`, and `serde` features. They
//!   are off by default.
//! - UTF-8 validation, serde size-limit rejection, and public-length mismatch
//!   handling are not data-oblivious operations. Callers must treat validity
//!   and length as public metadata when using text or variable-length APIs.
//! - Fixed-size lifetime enforcement is available only through the `std`
//!   feature and [`ExpiringSecretBytes`].
//! - Guard-page allocation is available only through the explicit
//!   `guard-pages` feature on supported Linux, Android, macOS, iOS, Windows,
//!   and BSD targets.
//! - WASM has no kernel page table, `mlock`, `mprotect`, or native volatile
//!   semantics. Base secret containers compile on WASM. `memory-lock` exposes
//!   volatile-only compatibility types on WASM only when `wasm-compat` is also
//!   enabled, so callers explicitly acknowledge the reduced guarantees.
//!   `guard-pages` is rejected at compile time on WASM.
//!
//! # Migrating From 1.x
//!
//! Version 2 makes storage stability, CT declassification, derive safety,
//! mapped integrity, and runtime protection outcomes explicit. The complete
//! source-change inventory and replacement examples are maintained in
//! [`docs/MIGRATION_2.0.md`](https://github.com/valkyoth/sanitization/blob/main/docs/MIGRATION_2.0.md).
//! Generic `Secret<T>` exposure is governed by the conditional contracts in
//! [`docs/STORAGE_CONTRACTS.md`](https://github.com/valkyoth/sanitization/blob/main/docs/STORAGE_CONTRACTS.md),
//! and native hardening policy/report semantics are defined in
//! [`docs/PROTECTION_REPORT.md`](https://github.com/valkyoth/sanitization/blob/main/docs/PROTECTION_REPORT.md).

#[cfg(all(miri, test, not(debug_assertions)))]
compile_error!(
    "sanitization: the Miri protection simulator is restricted to debug test artifacts and must not be compiled into a release artifact"
);

#[cfg(all(
    any(
        feature = "profile-hardened-native",
        feature = "profile-guarded-native",
        feature = "profile-hardened-linux"
    ),
    target_arch = "wasm32"
))]
compile_error!(
    "sanitization: native hardening profiles are unavailable on wasm32; use wasm-compat and inspect ProtectionReport for the explicit reduced-guarantee compatibility backend"
);

#[cfg(all(feature = "profile-hardened-linux", not(target_os = "linux")))]
compile_error!(
    "sanitization: profile-hardened-linux requires a Linux target because its fork-exclusion policy is Linux-specific"
);

#[cfg(all(
    any(
        feature = "profile-hardened-native",
        feature = "profile-guarded-native"
    ),
    not(target_arch = "wasm32"),
    not(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "ios",
        target_os = "android",
        target_os = "windows",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly"
    ))
))]
compile_error!(
    "sanitization: native hardening profiles require a reviewed native memory-lock backend"
);

#[cfg(all(
    feature = "memory-lock",
    target_arch = "wasm32",
    not(feature = "wasm-compat")
))]
compile_error!(
    "sanitization: memory-lock on wasm32 requires the wasm-compat feature; WASM has no mlock/mprotect, so this is an explicit reduced-guarantee compatibility backend"
);

#[cfg(all(feature = "guard-pages", target_arch = "wasm32"))]
compile_error!(
    "sanitization: the guard-pages feature is not supported on wasm32 because WASM linear memory has no page protection or mprotect equivalent"
);

#[cfg(all(
    feature = "canary-check",
    not(feature = "random-canary"),
    target_arch = "wasm32"
))]
compile_error!(
    "sanitization: canary-check on wasm32 requires random-canary because deterministic WASM canaries have no ASLR-backed entropy"
);

#[cfg(all(
    feature = "strict-compare",
    not(any(target_arch = "x86_64", target_arch = "aarch64")),
    not(miri)
))]
compile_error!(
    "sanitization: strict-compare requires an assembly comparison backend; currently supported on x86_64 and aarch64"
);

#[cfg(all(feature = "require-fork-exclusion", target_arch = "wasm32"))]
compile_error!(
    "sanitization: require-fork-exclusion is not supported on wasm32 because WASM has no fork inheritance policy"
);

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(any(test, feature = "std"))]
extern crate std;

#[cfg(feature = "derive")]
pub use sanitization_derive::{
    ConditionallySelectable, ConstantTimeEq, SecureSanitize, SecureSanitizeOnDrop,
};

#[cfg(feature = "random-canary")]
#[allow(unsafe_code)]
#[cfg_attr(all(miri, test), allow(dead_code))]
mod canary;

mod platform;
#[cfg(all(
    feature = "asm-compare",
    any(target_arch = "x86_64", target_arch = "aarch64"),
    not(miri)
))]
pub(crate) use platform::compare_asm;
#[allow(unused_imports)]
pub use platform::*;

#[allow(unsafe_code)]
mod wipe_backend;

/// Safe direct wiping helpers for ordinary buffers.
pub mod wipe;

/// Data-oblivious primitives for secret-handling code.
///
/// This module intentionally uses the familiar `ct` name, but its documented
/// claim is narrower than "identical wall-clock time": APIs here are designed
/// to avoid secret-dependent control flow and secret-dependent memory access
/// under documented compiler, target, feature, and release-profile conditions.
///
/// Lengths, allocation behavior, panics, page faults, scheduling, and the final
/// decision to branch on a secret-derived result are public effects. Use
/// [`ct::Choice::declassify`] at that boundary so reviewers can search for it.
pub mod ct;

mod owned;
pub use owned::*;
#[allow(unused_imports)]
pub(crate) use owned::{
    constant_time_eq_equal_len, constant_time_eq_slices, portable_constant_time_eq_equal_len,
};

mod mapped;
#[allow(unused_imports)]
pub use mapped::*;

mod interop;

#[cfg(test)]
mod tests;
