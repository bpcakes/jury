# Barrier Strategy

This document explains the optimizer and backend barriers used by the crate.
It does not turn any one primitive into a universal cryptographic guarantee.
The guarantees are the combination of API shape, implementation discipline,
target-specific codegen, and release evidence.

## Clearing Barriers

Memory clearing uses a single audited architecture:

- safe callers use `sanitization::wipe`;
- internal containers dispatch through the private `wipe_backend`;
- a sealed internal `ErasureBackend` prevents downstream backend injection;
- volatile byte writes prevent native LLVM dead-store elimination of the clear;
- `compiler_fence(Ordering::SeqCst)` prevents compiler reordering around the
  wipe boundary;
- `fence(Ordering::SeqCst)` provides a hardware ordering boundary where the
  target supports it;
- the wipe function is kept behind a non-inlined boundary for easier codegen
  inspection.

CP-10 deliberately retains the 1.x ordering policy: two compiler
`SeqCst` fences and one hardware `SeqCst` fence per pass. No fence was removed
because the checkpoint did not produce target-specific evidence proving that a
weaker boundary preserves the documented handoff and peripheral-ordering use
cases.

The public API does not expose backend selection. Names suggesting a weaker
best-effort mode, a separate volatile mode, or caller-visible unsafe wiping
were removed because they all selected the same reviewed backend.

On WASM, volatile writes survive Rust-to-WASM lowering, but the WASM memory
model does not encode volatility. The crate uses a non-inlined function-pointer
style boundary as a best-effort mitigation, and documents WASM as a weaker
target tier.

## Data-Oblivious Barriers

The native `ct` module starts with source-level data-oblivious structure:

- branchless bitwise and arithmetic operations;
- public fixed loop bounds;
- no secret-dependent indexing inside the provided primitives;
- explicit `declassify(reason)` when a secret-derived value becomes public.

`core::hint::black_box` may be used to reduce optimizer visibility, but it is
not treated as a cryptographic primitive. Release evidence must still inspect
the generated code shape for reviewed targets.

## Assembly Backends

The default feature set enables `asm-compare`, selecting target-specific
equal-length comparison backends on x86_64 and AArch64. Builds using
`default-features = false` retain the portable fallback unless `asm-compare`
is explicitly re-enabled. The `strict-compare` feature fails closed on
unsupported targets instead of silently falling back for equal-length byte
equality. The shared dispatch backs `ct::eq_fixed`, `ct::eq_public_len`, byte
slice and array trait implementations, native secret-container equality, and
the crypto-interop HMAC and BLAKE3 verification helpers. Release codegen probes
trace each of those representative paths to the assembly backend.

Assembly backends are useful because they reduce compiler freedom in the most
sensitive comparison loop. They still do not prove complete hardware timing
behavior, and they do not protect arbitrary caller code around the comparison.
Ordering, selection, copying, swapping, and oblivious lookup retain their
portable implementations when `strict-compare` is enabled.

Repeated 2.0 release-candidate measurements rejected the portable equality
fallback as timing evidence on AArch64 Linux. It remains a source-level
data-oblivious fallback for portability, but it is not part of the AArch64
native timing claim.

## Cache And Register Helpers

`cache-flush` and `register-scrub` are explicit hardening helpers:

- cache sanitization helpers zero first, then use CPUID-gated x86_64 eviction
  and return a structured report or error;
- register scrub helpers return the documented subset of SIMD/vector state
  actually covered, or an explicit unsupported result.

These helpers reduce post-use residency. They are not defenses against an
attacker who already has cache-timing, register-save-area, or privileged
observation during the secret's active lifetime.

## Release Evidence

For release candidates that change barriers, comparison code, unsafe code, or
target support, run and record:

```bash
scripts/checks.sh
scripts/verify-codegen.sh
scripts/verify-miri.sh
scripts/verify-kani.sh
scripts/verify-evidence.py
```

`scripts/verify-codegen.sh` is a regression gate. It checks that important
symbols and instruction patterns remain present, but it is not a replacement
for manual review of release artifacts.
