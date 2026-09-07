# Release 1.1.0

- Added `LockedSecretVec` for native dynamic-length memory-locked byte storage
  without guard-page overhead.
- Added `register-scrub` for explicit best-effort SIMD/vector register
  scrubbing on x86_64 and AArch64.
- Added `hardware-secrets` provider traits for external HSM, TEE, enclave,
  platform-keystore, or other backend integration crates without adding vendor
  dependencies to the main crate.
- Added `split-secret` with `SplitSecretBytes<N, SHARES>` for dependency-free
  N-of-N XOR split storage.
- Added separate optional `sanitization-arrayvec` and `sanitization-bytes`
  wrapper crates, keeping the main `sanitization` crate dependency-free by
  default.
- Hardened `register-scrub` after review: x86_64 now uses AVX runtime/OS
  detection, uses `vzeroall` on non-Windows AVX targets, uses ABI-safe
  `vzeroupper` on Windows AVX targets, and documents AVX-512/AArch64 residual
  register gaps.
- Changed `sanitization-bytes::SecretBytesMut::extend_from_slice` to return a
  capacity error instead of reallocating, preventing old secret-bearing
  allocations from being freed before they can be wiped.
- Added split-secret misuse guardrails and documentation for deterministic or
  low-entropy mask generators.
- Documented the cache-timing limits of the optional `cache-flush` feature.
- Updated README, safety notes, threat model, and roadmap for the 1.1.0
  feature set.
