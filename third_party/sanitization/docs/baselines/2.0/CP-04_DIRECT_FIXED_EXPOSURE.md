# CP-04 Direct Fixed-Secret Exposure

Status: implementation review record

Base commit: `a06c2b1`

Checkpoint: `CP-04`

CP-04 removes the mandatory full-size stack copy from normal fixed-secret
exposure. Copy creation remains available only through explicitly named APIs.

## Direct Exposure

`SecretBytes<N>::expose_secret` now passes `&self.bytes` directly to the
closure. It does not intentionally construct another `[u8; N]`.

The same direct naming is used for:

- native and WASM-compat `LockedSecretBytes<N>`;
- native and WASM-compat `SecretPoolSlot<N, SLOTS>`;
- `ExpiringSecretBytes<N>`;
- `MonotonicExpiringSecretBytes<N, C>`.

Locked and pooled paths verify canaries before direct exposure. Checked
exposure returns `CanaryCorruptedError`; unchecked exposure preserves the
existing fail-closed panic policy.

Dynamic locked and guarded containers already borrowed their initialized
storage directly through `with_secret`, so CP-04 does not create a second
dynamic exposure vocabulary for them.

## Explicit Copy Exposure

The following APIs visibly create temporary plaintext copies:

- `SecretBytes::expose_secret_copy`;
- `ExpiringSecretBytes::try_expose_secret_copy`;
- `MonotonicExpiringSecretBytes::try_expose_secret_copy`;
- `LockedSecretBytes::expose_secret_copy`;
- `SecretPoolSlot::expose_secret_copy`;
- checked copy variants for canary-enabled fixed mapped storage;
- `SplitSecretBytes::expose_secret_copy`.

The shared copy helper creates `[u8; N]`, copies the source, and installs an
RAII guard. It clears eagerly on normal return and during unwinding. It cannot
clear after process abort.

Split-secret storage exposes only explicit copy behavior because contiguous
plaintext does not exist in its stored representation.

## Residual Limits

Direct exposure reduces intentional stack duplication but does not guarantee
that rustc, LLVM, the calling convention, register allocation, closure code, or
downstream libraries never copy or spill bytes. Exposure closures remain
reviewed declassification boundaries.

Copy exposure creates stack plaintext and depends on normal return or unwinding
for cleanup. `panic = "abort"`, process termination, hardware faults, and WASM
traps that do not unwind prevent cleanup.

## Verification

The checkpoint includes:

- pointer-identity tests proving direct inline exposure uses owned storage;
- pointer-separation tests for explicit copy exposure;
- unwind cleanup coverage for the temporary-array guard;
- borrow-escape compile-fail rustdoc;
- fixed locked, pooled, expiring, split, and checked-canary tests;
- an optimized 4096-byte codegen probe that rejects a full-size alloca or
  memcpy in the direct path and requires one in the copy path;
- normal repository checks and the Rust 1.90.0 MSRV check.
