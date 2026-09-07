> **Maintained in Jury:** edit this provider in `third_party/sanitization`.
> Read [AGENTS.md](AGENTS.md) and [CONTRIBUTING.md](CONTRIBUTING.md) for local
> development. Workspace metadata records the imported fork and upstream base;
> Jury's Git history binds current source. The upstream documentation and
> historical evidence below do not certify Jury, which remains pre-alpha and
> unsuitable for real secrets.

<p align="center">
  <b>Dependency-free, no_std-first secret memory sanitization for Rust.</b><br>
  Redacted secret containers, volatile clearing, data-oblivious helpers, and optional native hardening.
</p>

<div align="center">
  <a href="https://docs.rs/sanitization">Docs.rs</a>
  |
  <a href="https://github.com/valkyoth/sanitization/blob/main/docs/FEATURES.md">Features</a>
  |
  <a href="https://github.com/valkyoth/sanitization/blob/main/docs/ADVANCED_USAGE.md">Advanced Usage</a>
  |
  <a href="https://github.com/valkyoth/sanitization/blob/main/docs/THREAT_MODEL.md">Threat Model</a>
  |
  <a href="https://github.com/valkyoth/sanitization/blob/main/docs/GUARANTEES.md">Guarantees</a>
  |
  <a href="https://github.com/valkyoth/sanitization/blob/main/docs/NON_GUARANTEES.md">Non-Guarantees</a>
  |
  <a href="https://github.com/valkyoth/sanitization/blob/main/SECURITY.md">Security</a>
</div>

<br>

<p align="center">
  <a href="https://github.com/valkyoth/sanitization">
    <img src="https://raw.githubusercontent.com/valkyoth/sanitization/main/.github/images/sanitization.webp" alt="sanitization Rust crate overview">
  </a>
</p>

# sanitization

`sanitization` provides redacted, non-`Copy`, clear-on-drop secret containers
for Rust. The default crate is dependency-free and `no_std`; heap storage,
derive macros, ecosystem interop, memory locking, guard pages, and other
hardening are explicit opt-ins.

Every crate-owned clearing path reaches one audited internal volatile-write
backend. The crate reduces accidental retention and exposure. It does not make
an entire process, operating system, compiler, or hardware platform secret.

The 2.0 line has intentional breaking changes. Existing 1.x users should read
the [2.0 migration guide](https://github.com/valkyoth/sanitization/blob/main/docs/MIGRATION_2.0.md).

## Start Here

Choose the narrowest type that matches the storage requirement:

| Need | Start with |
| --- | --- |
| Fixed-size key, nonce, or token | `SecretBytes<N>` |
| Runtime-length bytes with fixed capacity | `SecretBoxBytes` with `alloc` |
| Growable secret bytes | `SecretVec` with `alloc` |
| Secret UTF-8 text | `SecretString` with `alloc` |
| Untrusted input with a public maximum | `BoundedSecretVec<MAX>` or `BoundedSecretString<MAX>` |
| Fallible generated dynamic input | `try_from_fn_bounded` or `try_from_chars_bounded` |
| Custom value needing current-value clearing only | `Secret<T>` where `T: SecureSanitize` |
| Generic shared exposure with reviewed stable storage | `Secret<T>` where `T: StableSharedSecretStorage` |
| Generic mutable exposure with reviewed stable storage | `Secret<T>` where `T: StableMutableSecretStorage` |
| Closed production storage allow-list | `AllowlistedSecret<T, PrivatePolicy>` |
| Fixed key that should avoid swap/pagefiles | `LockedSecretBytes<N>` with `memory-lock` |
| Dynamic locked bytes or text | `LockedSecretVec` or `LockedSecretString` |
| Permanently bounded locked bytes or text | `BoundedLockedSecretVec<MAX>` or `BoundedLockedSecretString<MAX>` |
| Many same-size locked keys | `SecretPool<N, SLOTS>` |
| Guarded dynamic mapping | `GuardedSecretVec` or `GuardedSecretString` |
| Permanently bounded guarded bytes or text | `BoundedGuardedSecretVec<MAX>` or `BoundedGuardedSecretString<MAX>` |
| Fixed mapping sealed between scoped accesses | `SealedSecretBytes<N>` with `page-seal` |
| Secret-derived control flow | `ct::Choice`, fixed CT helpers, and explicit declassification |
| One successful scoped access | `ConsumeOnceSecret<T>` |
| Existing ordinary byte storage | `sanitization::wipe` |
| Existing ecosystem trait bounds | `zeroize-interop`, `subtle-interop`, or a companion crate |

Use the API in three levels:

1. **Essentials:** ordinary owned containers and direct wiping.
2. **Protected operations:** data-oblivious comparison and recommended locked storage.
3. **Advanced hardening:** custom protection policy, guard pages, sealing,
   classified CT ownership, cache/register controls, and specialized backends.

Most applications should begin at level 1 and add only the level 2 controls
required by their threat model.

## Install

Fixed-size `no_std` secrets need no feature flags:

```toml
[dependencies]
sanitization = "2.0.4"
```

Heap-backed byte and text containers:

```toml
[dependencies]
sanitization = { version = "2.0.4", features = ["alloc"] }
```

Recommended native hardening profile:

```toml
[dependencies]
sanitization = { version = "2.0.4", features = ["profile-hardened-native"] }
```

This profile includes OS-random canaries and `strict-canary-check`. Enabling
`canary-check` alone uses deterministic address-derived words intended to catch
accidental corruption; it is not an attacker-resistant integrity control.

Optional derives:

```toml
[dependencies]
sanitization = { version = "2.0.4", features = ["derive"] }
```

See the complete [feature reference](https://github.com/valkyoth/sanitization/blob/main/docs/FEATURES.md) before combining
platform features.

## Level 1: Essential Secret Ownership

### Fixed-Size Secrets

Use `SecretBytes<N>` when the size is known at compile time. Generate directly
into the container where possible instead of first creating an ordinary secret
buffer.

```rust
use sanitization::SecretBytes;

let mut key = SecretBytes::<32>::from_fn(|index| index as u8);

let first = key.expose_secret(|bytes| bytes[0]);
assert_eq!(first, 0);
assert!(key.constant_time_eq(&[
    0, 1, 2, 3, 4, 5, 6, 7,
    8, 9, 10, 11, 12, 13, 14, 15,
    16, 17, 18, 19, 20, 21, 22, 23,
    24, 25, 26, 27, 28, 29, 30, 31,
]));

key.replace_from_fn(|index| 31 - index as u8);
key.secure_clear();
assert!(key.constant_time_eq(&[0; 32]));
```

`SecretBytes<N>` does not implement `Clone`, `Copy`, `Deref`, `AsRef<[u8]>`,
or secret-printing `Debug`. `expose_secret` directly borrows owned storage. Use
the reason-bearing `export_secret_copy` only when an external API requires an
independent temporary copy.

```rust
use sanitization::SecretBytes;

let key = SecretBytes::<32>::from_array([7; 32]);
let public_identifier = key.export_secret_copy(
    "protocol callback returns public key identifier byte",
    |bytes| bytes[0],
);
assert_eq!(public_identifier, 7);
```

The crate clears that temporary on normal return and unwinding, but cannot
clear copies made by the callback or copies surviving process abort.

### Heap Bytes And Text

Enable `alloc` for runtime-length secrets:

```rust
use sanitization::{SecretBoxBytes, SecretString, SecretVec};

let fixed = SecretBoxBytes::from_slice(b"fixed-token");
assert!(fixed.constant_time_eq(b"fixed-token"));

let mut bytes = SecretVec::from_slice(b"session-key");
bytes.extend_from_slice(b"-v2");
assert!(bytes.constant_time_eq(b"session-key-v2"));

let mut text = SecretString::from_secret_str("bearer-token");
text.push_str("-v2");
assert!(text.constant_time_eq("bearer-token-v2"));

let generated = SecretVec::try_from_fn_bounded(32, 4096, |index| {
    Ok::<u8, &'static str>(index as u8)
})?;
assert_eq!(generated.len(), 32);
# Ok::<(), sanitization::SecretGenerateError<&'static str>>(())
```

Choose deliberately:

- `SecretBoxBytes` has one runtime-length allocation whose capacity cannot grow.
- `SecretVec` and `SecretString` use managed growth that clears replaced
  allocations before releasing them.
- bounded variants reject public lengths above `MAX`, including during serde
  ingestion.
- `try_with_capacity` returns `SecretAllocationError`; generated constructors
  return `SecretGenerateError<E>` so allocation and generator failures remain
  distinct.
- `try_from_slice_bounded` and `try_from_secret_str_bounded` enforce public byte
  limits before allocation. `try_from_fn_bounded` does the same for byte count;
  `try_from_chars_bounded` checks worst-case UTF-8 byte capacity with checked
  arithmetic before allocation or callback execution.
- infallible `with_capacity`, `from_fn`, and `from_chars` are for trusted,
  already-bounded public sizes and retain ordinary allocation panic/abort
  behavior.
- ownership-taking constructors such as `from_vec` and `from_string` avoid a
  second heap allocation but make the supplied allocation secret storage.

### Direct Wiping

Use the sealed `wipe` module only when a secret already exists in ordinary
supported storage:

```rust
use sanitization::wipe;

let mut bytes = [0xA5; 32];
wipe::bytes(&mut bytes);
assert_eq!(bytes, [0; 32]);
```

Use `wipe::maybe_uninit` for non-live `MaybeUninit<T>` storage such as an
allocator or fixed-capacity container's spare slots. It performs volatile
writes without constructing references to uninitialized byte values.

With `alloc`, `wipe::vec` and `wipe::string` clear the reachable allocation.
`WipeOnDrop<T>` is available only for audited built-in byte/text types. Custom
structured types should implement `SecureSanitize` and use `Secret<T>` or the
optional derives.

### Custom Structs

The `derive` feature generates field-wise struct sanitization:

```rust
use sanitization::{SecretBytes, SecureSanitize, SecureSanitizeOnDrop};

#[derive(SecureSanitize, SecureSanitizeOnDrop)]
struct Credentials {
    key: SecretBytes<32>,
    nonce: SecretBytes<12>,
}
```

`SecureSanitizeOnDrop` requires `DropSafeSanitize + Unpin` and invokes the
complete sanitizer, preserving aggregate cleanup such as external storage and
ordering. `#[derive(SecureSanitize)]` supplies the drop-safe contract for its
generated field-wise sanitizer. A reviewed manual aggregate sanitizer must
implement `DropSafeSanitize` explicitly. For generic drop structs, declare
`T: SecureSanitize + Unpin` on the struct itself. Pinned secret owners require
a reviewed pin-aware manual design.

Enum derives are rejected. Safe generated code cannot reach inactive enum
representation bytes after variant transitions. Model secret storage with a
stable struct layout and keep public state in a separate tag.

## Level 2: Protected Operations

### Data-Oblivious Final Decisions

The native `ct` module aims to avoid secret-dependent control flow and memory
access under documented target and compiler conditions. It does not promise
identical wall-clock timing on every machine.

For a final fixed-size authentication decision, use the reason-bearing helper:

```rust
use sanitization::ct::declassified_eq_fixed;

let expected = [7u8; 32];
let received = [7u8; 32];

let accepted = declassified_eq_fixed(
    &expected,
    &received,
    "authentication comparison result is public",
);
assert!(accepted);
```

Use `eq_fixed`, `cmp_fixed`, and `Choice` when the result must remain inside
the data-oblivious domain for further composition. `eq_public_len` and
`declassified_eq_public_len` treat length as public and may return immediately
on mismatch.

Declassification reasons are review labels, not authorization. This repository
runs `scripts/lint-declassification-reasons.py` to reject dynamic, placeholder,
and generic reasons. High-assurance downstream projects can run the same lint.

### Locked Native Storage

`memory-lock` provides private native mappings backed by `mlock`/`VirtualLock`
or platform equivalents. Generate or decode directly into locked storage when
possible:

```rust,no_run
# #[cfg(feature = "memory-lock")]
# {
use sanitization::LockedSecretBytes;

let mut key = LockedSecretBytes::<32>::try_from_fill(|output| {
    output.fill(7);
    Ok::<(), std::io::Error>(())
})?;

assert_eq!(key.try_constant_time_eq(&[7; 32]), Ok(true));
key.try_replace_from_fallible_fill(|output| {
    output.fill(9);
    Ok::<(), std::io::Error>(())
})?;
# Ok::<(), Box<dyn std::error::Error>>(())
# }
```

When a custom protection request is needed, initialize the resulting mapping
without an intermediate array:

```rust,no_run
# #[cfg(feature = "memory-lock")]
# {
use sanitization::{LockedSecretBytes, ProtectionRequest};

let request = ProtectionRequest::profile_hardened_native();
let key = LockedSecretBytes::<32>::zeroed_with_protection(request)?
    .try_init_with(|output| {
        // Decode, derive, or ask an RNG to write directly into `output`.
        output.fill(7);
        Ok::<(), std::io::Error>(())
    })?;

assert_eq!(key.try_constant_time_eq(&[7; 32]), Ok(true));
# Ok::<(), Box<dyn std::error::Error>>(())
# }
```

Runtime-length decoders should use the policy-aware dynamic constructor. The
mapping and every `Required` control are established before the callback runs;
decoder failure, excessive output length, invalid integrity canaries, and the
unreported tail are cleared before an error or value is returned. The callback
receives exactly the requested capacity, initialized to zero and without live
canary material:

```rust,no_run
# #[cfg(feature = "memory-lock")]
# {
use sanitization::{
    BoundedLockedSecretVec, ForkProtectionRequest, ProtectionRequest, Requirement,
};

const MAX_DECODED_SECRET_BYTES: usize = 4096;
let decoder_capacity = 4096; // Validate the protocol length before this point.
let request = ProtectionRequest {
    memory_lock: Requirement::Required,
    dump_exclusion: Requirement::Required,
    fork: ForkProtectionRequest::exclude(Requirement::Required),
    guard_pages: Requirement::NotRequested,
    canary: Requirement::Required,
    cache_policy: Requirement::NotRequested,
};
let decoded = BoundedLockedSecretVec::<MAX_DECODED_SECRET_BYTES>::try_from_capacity_with_protection(
    decoder_capacity,
    request,
    |output| {
        output[..5].copy_from_slice(b"token");
        Ok::<usize, std::io::Error>(5)
    },
)?;

assert_eq!(decoded.try_constant_time_eq(b"token"), Ok(true));
# Ok::<(), Box<dyn std::error::Error>>(())
# }
```

`BoundedGuardedSecretVec<MAX>` provides the same lifetime invariant with guard
pages. `BoundedLockedSecretString<MAX>` and
`BoundedGuardedSecretString<MAX>` enforce the same permanent maximum in UTF-8
bytes and clear the mapping when the initialized prefix is not valid UTF-8.

The one-shot `*_bounded_with_protection` constructors on the growable mapped
types enforce admission only; the returned `LockedSecretVec`,
`GuardedSecretVec`, or string wrapper can still grow later. Use the const-generic
bounded mapped types when the maximum must remain enforced for the value's
entire lifetime. They keep the growable owner private and check construction,
append, and replacement before allocation or generator execution. Unbounded
constructors accept only trusted, already-limited capacities.

`profile_hardened_native()` permits explicit degraded success for dump and
fork exclusion; use a custom request like the one above when plaintext must not
be materialized without them.

Prefer direct final-storage generation through `try_from_fn`, `try_from_fill`,
or `try_init_with`. Avoid `Clone`, `to_vec`, formatting, and temporary arrays
for secret material. Keep unavoidable cryptographic scratch buffers in
clear-on-drop owners, and keep mutable exposure closures as short as possible.
These practices reduce avoidable copies; they cannot prove that compiler moves
or register spills never create historical copies.

For the reviewed native bundle, enable `profile-hardened-native` and use its
type-associated constructor:

```rust,no_run
# #[cfg(feature = "profile-hardened-native")]
# {
use sanitization::LockedSecretBytes;

let key = LockedSecretBytes::<32>::zeroed_hardened_native()?;
let request = key.protection_request();

if !key.protection_report().satisfies(request) {
    return Err("preferred runtime protections were unavailable".into());
}
# Ok::<(), Box<dyn std::error::Error>>(())
# }
```

Cargo features compile capabilities; they do not prove that runtime controls
succeeded. Required failures return `ProtectionError`. Preferred failures are
visible in `ProtectionReport`. Validate the report once at startup according
to deployment policy.

Locked memory does not by itself control hibernation images, every crash-dump
path, privileged reads, DMA, firmware, or external copies. Platform coverage
and fork/dump behavior are documented in
[`TARGETS.md`](https://github.com/valkyoth/sanitization/blob/main/docs/TARGETS.md) and
[`PROTECTION_REPORT.md`](https://github.com/valkyoth/sanitization/blob/main/docs/PROTECTION_REPORT.md).

## Level 3: Advanced Hardening

Advanced facilities are intentionally separate from the normal path:

| Requirement | Facility | Read first |
| --- | --- | --- |
| Custom required/preferred runtime controls | `ProtectionRequest` and `ProtectionReport` | [Protection reports](https://github.com/valkyoth/sanitization/blob/main/docs/PROTECTION_REPORT.md) |
| Guard pages around dynamic storage | `GuardedSecretVec`, `GuardedSecretString` | [Advanced usage](https://github.com/valkyoth/sanitization/blob/main/docs/ADVANCED_USAGE.md) |
| Inaccessible pages between accesses | `SealedSecretBytes<N>` | [Safety](https://github.com/valkyoth/sanitization/blob/main/docs/SAFETY.md) |
| Secret-bearing optional/result CT state | `SecretValue`, `SecretCtOption`, `SecretCtResult` | [Guarantees](https://github.com/valkyoth/sanitization/blob/main/docs/GUARANTEES.md) |
| Cache-line eviction after clearing | `cache-flush` | [Barrier strategy](https://github.com/valkyoth/sanitization/blob/main/docs/BARRIERS.md) |
| Best-effort vector-register clearing | `register-scrub` | [Barrier strategy](https://github.com/valkyoth/sanitization/blob/main/docs/BARRIERS.md) |
| Many fixed secrets under one lock quota | `SecretPool<N, SLOTS>` | [Advanced usage](https://github.com/valkyoth/sanitization/blob/main/docs/ADVANCED_USAGE.md) |
| N-of-N fixed split storage | `SplitSecretBytes<N, SHARES>` | [Threat model](https://github.com/valkyoth/sanitization/blob/main/docs/THREAT_MODEL.md) |
| HSM, TEE, enclave, or keystore adapters | `hardware-secrets` traits | [Advanced usage](https://github.com/valkyoth/sanitization/blob/main/docs/ADVANCED_USAGE.md) |

Do not enable advanced features merely because they sound stronger. Each one
has separate target assumptions, failure modes, and residual risks. The
[advanced usage guide](https://github.com/valkyoth/sanitization/blob/main/docs/ADVANCED_USAGE.md) provides short recipes and links
to the normative documents.

Page-sealed callers that must observe final mapping cleanup should call
`SealedSecretBytes::try_close()` before drop. It reports page normalization,
unlock, and unmap failures without exposing bytes, addresses, or canary values;
cleanup makes each page writable, erases it, and reseals it independently.
If any page transition fails, successfully processed pages are already erased
and resealed, while the uncertain page, mapping, and any established lock are
retained without attempting unmap. `Drop` follows the same security-first
retention policy and remains the final best-effort fallback.

High-assurance applications should use `AllowlistedSecret<T, P>` as their
internal production alias, keep `P` private or `pub(crate)`, and run
`scripts/lint-storage-policies.py` over sensitive modules. The lint rejects
direct `Secret<T>`, unapproved storage-marker implementations, and public
policy types. See [`STORAGE_CONTRACTS.md`](https://github.com/valkyoth/sanitization/blob/main/docs/STORAGE_CONTRACTS.md) and the
compile-checked `high_assurance_policy` example.

## Feature And Platform Reference

The dependency-free, `no_std` default enables `asm-compare`, selecting the
reviewed equal-length assembly backend on x86_64 and AArch64 and falling back
portably elsewhere. `default-features = false` disables that default backend.
The other major opt-in groups are:

- allocation and integration: `alloc`, `std`, `derive`, `serde`,
  `zeroize-interop`, `subtle-interop`;
- mapped storage: `memory-lock`, `guard-pages`, `page-seal`, `canary-check`,
  `random-canary`;
- CT and post-use controls: `asm-compare`, `strict-compare`, `cache-flush`,
  `register-scrub`;
- named profiles: `profile-hardened-native`, `profile-guarded-native`, and
  `profile-hardened-linux`.

See [FEATURES.md](https://github.com/valkyoth/sanitization/blob/main/docs/FEATURES.md) for every feature, implication, companion
crate, and profile policy. Native profiles fail to compile on WASM rather than
silently degrading.

WASM compatibility is explicit and reduced-guarantee. Pair `memory-lock` with
`wasm-compat` only when API compatibility is required; WASM linear memory has
no host `mlock`, `mprotect`, fork policy, or native volatile guarantee across a
JIT boundary. See [FEATURE_PROFILES.md](https://github.com/valkyoth/sanitization/blob/main/docs/FEATURE_PROFILES.md).

## Trust Dashboard

| Area | Status |
| --- | --- |
| License | `MIT OR Apache-2.0` |
| MSRV | Rust `1.90.0` |
| Pinned toolchain | Rust `1.98.1` |
| Default target | `no_std` |
| Default external runtime dependencies | zero |
| Unsafe policy | denied at crate root and isolated in documented modules |
| Clear primitive | volatile writes by default |
| Proc macros | optional `derive` feature |
| Formal evidence | bounded Kani harnesses for selected properties |
| Main guarantee | narrow ownership, redaction, and clear-on-drop hygiene |

High-assurance users should read these documents in order:

1. [Threat model](https://github.com/valkyoth/sanitization/blob/main/docs/THREAT_MODEL.md)
2. [Guarantees](https://github.com/valkyoth/sanitization/blob/main/docs/GUARANTEES.md)
3. [Non-guarantees](https://github.com/valkyoth/sanitization/blob/main/docs/NON_GUARANTEES.md)
4. [Safety and unsafe boundaries](https://github.com/valkyoth/sanitization/blob/main/docs/SAFETY.md)
5. [Target tiers](https://github.com/valkyoth/sanitization/blob/main/docs/TARGETS.md)
6. [Evidence](https://github.com/valkyoth/sanitization/blob/main/docs/EVIDENCE.md)
7. [Error handling](https://github.com/valkyoth/sanitization/blob/main/docs/ERROR_HANDLING.md)
8. [Deployment hardening](https://github.com/valkyoth/sanitization/blob/main/docs/DEPLOYMENT_HARDENING.md)

## Rust Version Support

The MSRV is Rust `1.90.0`. Release development is pinned to Rust `1.98.1`, and
the release gate checks compatibility from `1.90.0` through the pinned stable
toolchain. The online release preflight also verifies that the pin is the
current stable patch release without changing the MSRV.

## Ecosystem Integration

The core crate remains dependency-free by default. Opt-in integration is split
by ownership boundary:

| Integration | Use |
| --- | --- |
| `sanitization-derive` | Struct derives for sanitization and conservative CT traits |
| `zeroize-interop` | Existing APIs requiring `zeroize` trait bounds |
| `subtle-interop` | Existing APIs requiring `subtle::ConstantTimeEq` |
| `sanitization-arrayvec` | `ArrayVec` storage |
| `sanitization-bytes` | Fixed-capacity `BytesMut` storage |
| `sanitization-crypto-interop` | SHA-2/BLAKE3 cleanup wrappers and HMAC-SHA2 helpers |

The optional derive dependency is exact-pinned to the runtime's version because
generated code may reference runtime traits introduced by that same release.
The release script publishes and waits for the derive crate before the core.

`zeroize` remains broader for retrofitting existing ecosystem types.
`sanitization` focuses on ownership, lifecycle, explicit exposure, and optional
platform protection. Interop features bridge trait bounds without replacing the
core clearing backend.

## Verification And Release Checks

Run the local gate before release-sensitive changes:

```bash
scripts/checks.sh
```

It covers formatting, feature matrices, docs, examples, linting, negative
fixtures, downstream migration, codegen inspection, leakage smoke checks,
Loom, lifecycle probes, API snapshots, package archives, and optional Kani/Miri
when installed. Native target evidence and timing runs are documented in
[`EVIDENCE.md`](https://github.com/valkyoth/sanitization/blob/main/docs/EVIDENCE.md) and
[`LEAKAGE_TESTS.md`](https://github.com/valkyoth/sanitization/blob/main/docs/LEAKAGE_TESTS.md).

Release publication is staged through:

```bash
scripts/release_crates.py --version 2.0.4 --prepare-only
scripts/release_crates.py --require-tag
```

The script publishes the five crates in dependency order and pauses while
crates.io indexes dependencies.

## Limits

Important limits include:

- safe Rust cannot reliably scrub historical stack frames or compiler-created
  copies;
- destructors do not run after process abort;
- exposure closures and external libraries can copy, log, export, or retain
  secret data;
- memory locking does not solve every swap, hibernation, dump, debugger,
  privileged-read, DMA, firmware, or VM snapshot threat;
- data-oblivious source structure is not a universal hardware timing guarantee;
- cache flush and register scrub helpers cover only their documented target
  subsets;
- Core Miri unit tests model locked-container lifecycle and verify
  clear-before-release, but do not prove native OS protection. Downstream Miri
  uses portable comparison code, while mapped constructors remain unsupported;
  Kani does not prove real concurrency.

See [NON_GUARANTEES.md](https://github.com/valkyoth/sanitization/blob/main/docs/NON_GUARANTEES.md),
[THREAT_MODEL.md](https://github.com/valkyoth/sanitization/blob/main/docs/THREAT_MODEL.md), and [SECURITY.md](https://github.com/valkyoth/sanitization/blob/main/SECURITY.md) before
using this crate for high-assurance secret handling.
