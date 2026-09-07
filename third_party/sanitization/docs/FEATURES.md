# Feature Reference

The default `sanitization` build is dependency-free and `no_std`, and enables
`asm-compare` so reviewed x86_64/AArch64 targets use assembly-backed equality.
Other features are opt-in capabilities; platform features do not by themselves
prove that the operating system established a requested protection. For that distinction, see
[`FEATURE_PROFILES.md`](FEATURE_PROFILES.md) and
[`PROTECTION_REPORT.md`](PROTECTION_REPORT.md).

## Core And Integration

| Feature | Purpose |
| --- | --- |
| `alloc` | Enables `SecretBoxBytes`, `SecretVec`, `SecretString`, and bounded byte/text containers. |
| `std` | Enables `alloc` and `ExpiringSecretBytes<N>`. |
| `derive` | Re-exports sanitization derives for structs. Proc-macro dependencies remain opt-in. |
| `serde` | Secret loading with redacted serialization; use bounded containers for untrusted input sizes. |
| `zeroize-interop` | Implements compatible `zeroize` traits for crate-owned containers. |
| `subtle-interop` | Implements compatible `subtle::ConstantTimeEq` traits where representable. |

## Mapped And Platform Storage

| Feature | Purpose |
| --- | --- |
| `memory-lock` | Enables native locked fixed, dynamic, permanently bounded dynamic/text, and pooled storage on supported targets. |
| `wasm-compat` | Enables explicit reduced-guarantee WASM compatibility for memory-lock APIs. It does not provide host memory locking. |
| `guard-pages` | Enables guarded byte/text mappings and permanently bounded wrappers on supported native targets. Rejected on WASM. |
| `page-seal` | Enables review-candidate fixed mappings that are inaccessible between scoped accesses. Implies `guard-pages`. |
| `canary-check` | Adds prefix/suffix integrity canaries to supported mapped storage. Implies `memory-lock`. |
| `random-canary` | Uses the OS CSPRNG for canary values. Implies `canary-check`. |
| `strict-canary-check` | Requires OS-random canaries instead of deterministic address-derived canaries. |
| `require-fork-exclusion` | Requires fork-inheritance exclusion on Linux (`MADV_DONTFORK`) and macOS (`minherit`, `VM_INHERIT_NONE`). |

## Data-Oblivious And Post-Use Controls

| Feature | Purpose |
| --- | --- |
| `asm-compare` | Selects reviewed x86_64/AArch64 assembly for equal-length byte equality. Enabled by default; `default-features = false` restores the portable fallback unless this feature is re-enabled. |
| `strict-compare` | Rejects non-Miri targets without the reviewed assembly equality backend. |
| `cache-flush` | Adds checked clear-and-cache-line-evict helpers where supported. |
| `register-scrub` | Adds best-effort architecture-specific SIMD/vector register scrubbing with an outcome report. |
| `multi-pass-clear` | Adds explicit zero/ones/zero volatile overwrite helpers for policy compatibility. |

## Specialized Facilities

| Feature | Purpose |
| --- | --- |
| `hardware-secrets` | Adds dependency-free traits for external HSM, TEE, enclave, or keystore providers. |
| `split-secret` | Adds N-of-N XOR split storage for fixed-size secrets. |

## Named Profiles

| Profile | Capabilities and policy |
| --- | --- |
| `profile-hardened-native` | Memory locking, OS-random strict canaries, and strict assembly equality. Memory lock and canaries are required; dump and fork exclusion are preferred. |
| `profile-guarded-native` | Extends hardened native with required guard pages. |
| `profile-hardened-linux` | Extends hardened native with required Linux fork exclusion. |

Prefer the corresponding type-associated constructors:

```rust,no_run
# #[cfg(all(feature = "profile-hardened-native", feature = "profile-guarded-native"))]
# {
use sanitization::{GuardedSecretVec, LockedSecretBytes, LockedSecretVec, SecretPool};

let fixed = LockedSecretBytes::<32>::zeroed_hardened_native()?;
let dynamic = LockedSecretVec::with_capacity_hardened_native(4096)?;
let pool = SecretPool::<32, 128>::new_hardened_native()?;
let guarded = GuardedSecretVec::with_capacity_guarded_native(4096)?;
# Ok::<(), sanitization::ProtectionError>(())
# }
```

Custom deployments can use `*_with_protection` and an explicit
`ProtectionRequest`. A successful constructor with preferred controls still
requires inspection of `ProtectionReport`; feature names describe compiled
capability, not achieved runtime state.

## Companion Crates

| Crate | Purpose |
| --- | --- |
| `sanitization-derive` | Optional struct derives for sanitization and conservative CT traits. |
| `sanitization-arrayvec` | Clear-on-drop `ArrayVec` integration. |
| `sanitization-bytes` | Fixed-capacity `BytesMut` integration that refuses reallocating growth. |
| `sanitization-crypto-interop` | Cleanup-aware SHA-2/BLAKE3 wrappers and HMAC-SHA2 helpers; forwards dependency-free `asm-compare` by default. |

Companion crates reuse the core clearing boundary rather than defining a second
volatile wipe implementation.
