# Feature Profiles And Crate Boundaries

This document defines the named feature profiles introduced for sanitization
2.0 and the ownership boundary between the core crate and its companions.
For the complete feature inventory, see [`FEATURES.md`](FEATURES.md).

## Capability, Policy, And Result

These are separate concepts:

1. Cargo features compile capabilities into the program.
2. `ProtectionRequest` states whether each runtime control is required,
   preferred, or not requested.
3. `ProtectionReport` records which controls were actually established.

A profile name is not proof that the operating system accepted memory locking,
dump exclusion, fork exclusion, or guard-page setup. Required failures return a
structured error. Preferred failures may return a container only when its
report records the reduced result.

The normative request, failure, rollback, and report semantics are documented
in `docs/PROTECTION_REPORT.md`.

## Named Native Profiles

| Profile | Compiled capabilities | Matching request policy |
| --- | --- | --- |
| `profile-hardened-native` | `memory-lock`, OS-random canaries, strict canary checks, assembly-backed strict equality | Memory lock and canary required; dump and fork exclusion preferred |
| `profile-guarded-native` | `profile-hardened-native` plus guard pages | Hardened-native policy plus guard pages required |
| `profile-hardened-linux` | `profile-hardened-native` plus required fork exclusion | Hardened-native policy with Linux fork exclusion required |

The normal type-associated constructors are:

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

`LockedSecretString` and `GuardedSecretString` provide the corresponding text
constructors. The Linux profile exposes matching `*_hardened_linux`
constructors on locked fixed, dynamic, text, and pool storage. Each shortcut is
available only when its matching profile feature is enabled.

For custom deployment policies, retain the explicit request boundary:

```rust,no_run
# #[cfg(feature = "memory-lock")]
# {
use sanitization::{LockedSecretBytes, ProtectionRequest};

let request = ProtectionRequest::locked();
let fixed = LockedSecretBytes::<32>::zeroed_with_protection(request)?;
# Ok::<(), sanitization::ProtectionError>(())
# }
```

The associated constructors select policy; they do not turn `Preferred`
controls into runtime guarantees. Inspect `protection_report()` once and use
`protection_request()` with `report.satisfies(request)` when validating the
complete profile. Applications may use `report.is_degraded()` for a concise
fail-closed startup decision.

`strict-compare` is intentionally narrower than a general constant-time
profile. It strengthens equal-length byte equality on reviewed x86_64 and
AArch64 assembly backends. It does not strengthen ordering, lookup, selection,
allocation, text validation, or caller code.

## Target Rejection

Known-incompatible combinations fail at compile time:

- every native hardening profile is rejected on `wasm32`;
- `profile-hardened-linux` is rejected on non-Linux targets;
- native profiles are rejected where no reviewed native memory-lock backend
  exists;
- `strict-compare` rejects non-Miri architectures without a reviewed assembly
  comparison backend.

This keeps strict profile names from silently degrading into compatibility
behavior.

## WASM Compatibility

WASM remains an explicit reduced-guarantee target:

```toml
sanitization = {
    version = "2",
    features = ["memory-lock", "wasm-compat", "random-canary"],
}
```

WASM compatibility containers preserve API shape and clear their owned linear
memory on drop. They do not provide host `mlock`, dump exclusion, fork policy,
guard pages, or a native volatile-store guarantee across a JIT boundary.
`ProtectionRequest::wasm_compatibility()` and the resulting report make those
outcomes explicit.

## Companion Ownership

The core `sanitization` crate owns the volatile clearing backend. Companion
crates integrate external representations without duplicating that primitive.

| Crate | Boundary |
| --- | --- |
| `sanitization-derive` | Generates calls to core traits; it has no runtime dependency on the core crate |
| `sanitization-arrayvec` | Exposes `arrayvec` storage and delegates clearing to `sanitization::wipe` |
| `sanitization-bytes` | Enforces fixed-capacity `BytesMut` use and delegates clearing to `sanitization::wipe` |
| `sanitization-crypto-interop` | Uses upstream hasher cleanup traits and core secret containers; it does not define a second memory-wipe backend |

Every companion dependency on `sanitization` sets `default-features = false`.
The crypto-interop companion explicitly forwards the dependency-free
`asm-compare` feature by default because it owns fixed-length verification
helpers; its `strict-compare` feature remains the fail-closed profile.
The proc-macro crate intentionally does not depend on the runtime crate.
Conversely, the runtime's optional `sanitization-derive` dependency is pinned
to the exact same release. Generated code may reference runtime APIs introduced
by that release, so Cargo must not resolve an independently newer proc macro
with an older runtime. The release script publishes and waits for the derive
crate before publishing the matching runtime.

## Default Core Graph

The default core feature set contains only the dependency-free `asm-compare`
feature. It selects the reviewed equal-length comparison backend on x86_64 and
AArch64 and does not add a runtime dependency. All third-party runtime
dependencies remain optional, so:

```bash
cargo tree -p sanitization --no-default-features --edges normal
```

must contain only the core crate itself.

`scripts/verify-feature-profiles.py` enforces the profile expansion, package
metadata, default dependency policy, and companion clearing boundary.
