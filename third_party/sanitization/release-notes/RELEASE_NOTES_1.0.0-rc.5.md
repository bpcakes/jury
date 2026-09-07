# Release 1.0.0-rc.5

- Made volatile clearing the default clear path through one internal audited
  unsafe backend.
- Simplified `SecretBytes<N>` storage from atomic/`Cell` byte storage to plain
  `[u8; N]` with volatile clearing on drop.
- Changed `SecretVec`, `SecretString`, `Secret<T>`, byte slices, and byte arrays
  to use volatile clearing by default.
- Added `SecureSanitize` implementations for scalar primitives, generic arrays
  and slices, `Option<T>`, `Result<T, E>`, and, with `alloc`, `Box<T>`,
  `Vec<T>`, and `String`.
- Added `SecretVec::replace_from_slice` and
  `SecretString::replace_from_secret_str` for whole-value rotation without
  copying previous dynamic secrets during growth.
- Added `SecretVec::from_fn` and `SecretVec::replace_from_fn` for direct
  dynamic byte generation into clear-on-drop storage.
- Added `SecretBytes::try_from_fn`, `SecretVec::try_from_fn`, and
  `SecretVec::try_replace_from_fn` for fallible direct byte generation with
  partial-output clearing on error.
- Added `SecretBytes::transform`, `try_transform`, `derive`, and `try_derive`
  for in-container fixed-size mutation and derivation without an
  `expose_secret` stack copy.
- Added `ReadOnceSecret<T>` for atomic shared-reference one-time access
  followed by immediate clearing.
- Added the optional `multi-pass-clear` feature with explicit three-pass
  volatile overwrite helpers for policy or audit compatibility.
- Added `MonotonicClock` and `MonotonicExpiringSecretBytes<N, C>` for no-`std`
  fixed-size secret lifetime enforcement with caller-defined ticks.
- Added CI and local check coverage for mapped memory backends across Linux,
  Android, macOS, iOS, Windows, BSD, WASM, and embedded no-`std` target builds.
- Added a `memory-lock` WASM compatibility backend for
  `LockedSecretBytes<N>` and `SecretPool<N, SLOTS>` using volatile-only
  WASM-owned storage, with documentation that no actual host memory lock is
  applied.
- Added explicit `guard-pages` compile-time rejection on WASM targets because
  WASM linear memory has no module-level page protection.
- Added WASI preview1 `random_get` support for `random-canary`, while keeping
  unsupported WASM random backends as explicit `Random` operation failures.
- Added a WASM-specific volatile clear call boundary to reduce runtime
  optimizer visibility, documented as best-effort rather than equivalent to
  native volatile semantics.
- Added full raw allocation wiping for generic `Vec<T>: SecureSanitize`,
  dependency-free errno capture for Unix C ABI mapped backends, and FreeBSD
  `MADV_NOCORE` core-dump exclusion.
- Added `LockedSecretBytes::try_from_fn`, `GuardedSecretVec::try_from_fn`, and
  `GuardedSecretVec::locked_try_from_fn` for fallible high-assurance direct
  byte generation.
- Expanded `LockedSecretBytes<N>` and `GuardedSecretVec` platform availability
  beyond Linux to supported Android, macOS, iOS, Windows, FreeBSD, OpenBSD,
  NetBSD, and DragonFly BSD targets.
- Added `SecretPool<N, SLOTS>` for pooled same-size fixed secrets inside one
  locked platform mapping, reducing page-granule memory-lock quota overhead
  when many secrets are live at once.
- Added the optional `canary-check` feature for non-empty
  `LockedSecretBytes<N>` mappings, `SecretPool<N, SLOTS>` slots, and
  `GuardedSecretVec` writable mappings, with prefix/suffix canary verification,
  checked access APIs, and fail-closed clearing on corruption.
- Added the optional `random-canary` feature to generate those canary words
  from OS CSPRNG backends without adding external dependencies.
- Added `GuardedSecretVec::replace_from_fn` and
  `GuardedSecretVec::try_replace_from_fn` for generated guarded whole-value
  rotation while preserving lock state.
- Added `ExpiringSecretBytes::try_from_fn`, `replace_from_fn`, and
  `try_replace_from_fn` for fallible generation and generated rotation with
  lifetime-window restart semantics.
- Added `SecretString::from_chars`, `try_from_chars`, `replace_from_chars`, and
  `try_replace_from_chars` for UTF-8-safe generated secret text.
- Added `LockedSecretBytes::replace_from_slice`, `replace_from_fn`, and
  `try_replace_from_fn` for staged whole-value rotation inside locked storage.
- Added `SecretBytes::replace_from_fn` and `try_replace_from_fn` for staged
  generated fixed-size rotation.
- Added `SecretBytes::replace_from_array`,
  `ExpiringSecretBytes::replace_from_array`, and
  `LockedSecretBytes::replace_from_array` for owned-array rotation with input
  clearing.
- Added `SecretVec::replace_from_vec` and
  `SecretString::replace_from_string` for owned heap-allocation rotation without
  copying the new value.
- Added `SecretVec::from_vec` and `SecretString::from_string` as explicit
  ownership-taking constructors for existing heap allocations.
- Added a dedicated GitHub Actions Miri workflow for nightly interpreter
  verification of default, `alloc`, and all-features builds.
- Added `ExpiringSecretBytes::try_expose_secret_volatile` for fallible
  volatile-named temporary exposure with lifetime enforcement.
- Added `SecretString::try_with_secret_mut` for closure-scoped mutable `&mut str`
  access without exposing mutable raw bytes.
- Added `Default` for `SecretVec` and `SecretString`, producing empty
  clear-on-drop heap secret containers.
- Added `Default` for `Secret<T>` when `T: SecureSanitize + Default`.
- Added `SecretVec::capacity` and `SecretString::capacity` for heap allocation
  metadata.
- Added `SecretBytes::into_cleared` for consuming fixed-size secrets after an
  explicit clear.
- Added `ExpiringSecretBytes::into_cleared` for consuming lifetime-enforced
  fixed-size secrets after an explicit clear.
- Added `into_cleared` consume helpers for `LockedSecretBytes<N>` and
  `GuardedSecretVec`.
- Added `Display` for `LengthError` and `std::error::Error::source` chaining
  for wrapper errors when `std` is enabled.
- Configured docs.rs to build documentation with all crate features enabled.
- Documented the current `secure_sanitize_struct!` and `secure_drop_struct!`
  macro syntax limits.
- Clarified README unsafe-policy wording for optional feature-gated hardening
  modules.
- Documented portable comparison timing limits and fixed-size exposure stack
  usage.
- Fixed a guarded mapping cleanup path so theoretical address-computation
  errors unmap before returning.
- Added explicit `Send` implementations for Linux mapped secret containers while
  keeping them intentionally non-`Sync`.
- Kept the `unsafe-wipe` feature as a no-op compatibility flag for older
  release-candidate dependency declarations.
- Kept `unsafe_wipe` public helper APIs available for explicit ordinary-buffer
  wiping.
- Added a release LLVM IR codegen check for volatile byte-zero stores.
- Expanded release codegen checks to verify x86_64 assembly comparison and
  cache-flush instruction paths.
- Added optional bounded Kani proof harnesses for selected fixed-size clearing,
  equality, and capacity properties.
- Added a dedicated GitHub workflow for the bounded Kani harness matrix.
- Added an optional Miri verification script for the wipe boundary and feature
  matrix.
- Added the optional Linux `memory-lock` feature with `LockedSecretBytes<N>` for
  fixed-size secrets backed by private `mmap` storage and `mlock`.
- Added `MADV_DONTDUMP` setup for Linux memory-locked secret mappings.
- Added `MADV_DONTFORK` setup for Linux memory-locked secret mappings.
- Added `LockedSecretBytes::from_slice` for direct runtime-buffer loading.
- Added `LockedSecretBytes::from_fn` for direct byte generation inside locked
  storage.
- Added the optional x86_64 `asm-compare` feature for assembly-backed
  equal-length byte comparison with portable fallback elsewhere.
- Added the optional x86_64 `cache-flush` feature for explicit volatile-clear
  plus `clflush`/`mfence` cache-line eviction helpers.
- Added `std`-only `ExpiringSecretBytes<N>` for fixed-size secret lifetime
  enforcement.
- Added the optional Linux `guard-pages` feature with `GuardedSecretVec` for
  dynamic byte secrets stored between inaccessible pages.
- Added `GuardedSecretVec` locked constructors when both `guard-pages` and
  `memory-lock` are enabled.
- Added `GuardedSecretVec::from_fn` and `GuardedSecretVec::locked_from_fn` for
  direct byte generation inside guarded mappings.
- Added `GuardedSecretVec::replace_from_slice` for whole-value rotation without
  copying the previous guarded bytes during growth.
- Added `GuardedSecretVec::clear_secret_and_flush` and `CacheFlushSanitize`
  support when both `guard-pages` and x86_64 `cache-flush` are enabled.
- Changed Linux `aarch64` mapping length rounding to detect `AT_PAGESZ` from
  `/proc/self/auxv` with raw syscalls, falling back to 64 KiB when detection is
  unavailable.
- Expanded the local check matrix and examples for optional high-assurance
  features.
- Updated README, safety notes, and threat model for the new clearing model.
