# Non-Guarantees

This document states what `sanitization` does not claim. These limits are part
of the security model, not fine print.

The category-specific erasure decision is described in
`docs/ERASURE_BACKENDS.md`.

The conditional downstream obligations behind generic storage attestations and
mapped runtime outcomes are described in `docs/STORAGE_CONTRACTS.md` and
`docs/PROTECTION_REPORT.md`.

`AllowlistedSecret` centralizes an application's accepted concrete types but
does not prove that a storage attestation is correct. A public policy type also
does not define a closed set; keep deployment policies private or
`pub(crate)` when external extension must be prevented.

## Timing And Microarchitecture

The crate does not guarantee exact identical wall-clock timing. It also does
not guarantee complete protection against every microarchitectural channel,
including:

- cache contention during the secret's active lifetime;
- branch predictor effects outside the provided primitives;
- SMT sibling observation;
- transient execution attacks;
- power, EM, thermal, or frequency side channels;
- hardware instructions with data-dependent latency on targets where that has
  not been reviewed.

The stronger claim for the native `ct` module is narrower: the provided
primitives try to avoid secret-dependent control flow and secret-dependent
memory access under documented target, feature, compiler, and release-profile
conditions.

UTF-8 validation, serde size-limit rejection, and variable-length mismatch
handling are not included in that claim. UTF-8 validators may stop at the first
invalid byte, and length checks may return immediately. Text validity and
variable lengths must therefore be public metadata. Protocols that need to hide
those properties should use a fixed-size representation and perform any
necessary validation outside the secret-dependent path.

## Arbitrary Caller Code

The crate cannot make arbitrary closures or third-party cryptographic
implementations data-oblivious. If caller code branches, indexes, allocates,
formats, panics, divides, performs floating-point operations, or calls external
APIs based on secret data, that behavior is outside the crate's guarantee.

Exposure closures are a boundary of responsibility. Keep them small and avoid:

- branching on secret bytes;
- indexing by secret bytes;
- early returns from secret-derived failure;
- secret-dependent allocation sizes or iterator lengths;
- formatting/logging/debug printing secrets;
- panics whose path depends on secret data;
- floating point on secrets;
- division/modulo on secrets unless the target has been reviewed.

## Compiler, Profile, And Runtime Limits

The crate's strongest data-oblivious claims are for documented release
profiles and targets. Debug builds may introduce instrumentation, overflow
checks, assertions, or code shape that is not representative of release
behavior.

`core::hint::black_box` is a useful optimizer barrier but is not a
cryptographic guarantee. The crate treats it as one component of a broader
barrier and evidence strategy, not as proof by itself.

Miri cannot execute or validate the native OS facilities behind memory locking,
private mappings, page protection, dump/fork policy, CSPRNG access, or guard
pages. The core crate's `cfg(all(miri, test))` unit-test backend models
locked-container allocation and lifecycle transitions with ordinary aligned
allocations and verifies clear-before-release; its successful protection report
states are simulated and do not establish an OS guarantee. Downstream Miri
uses portable comparison code, but execution of mapped constructors remains
unsupported. A release build that forges both `cfg(miri)` and `cfg(test)` is
rejected, and the release helper refuses ambient `RUSTFLAGS` and
`CARGO_ENCODED_RUSTFLAGS`. These controls assume a trusted Rust toolchain and
build invocation; they are not protection against a malicious compiler or an
operator who deliberately changes the source or release process. Native tests
are required to exercise the actual platform paths.

Kani performs bounded functional verification and treats configured harnesses
sequentially. It does not model real thread scheduling, concurrent atomic
interleavings, or concurrent kernel behavior. A passing Kani run is not a proof
of concurrency correctness.

WASM has special limits. Rust/LLVM preserves volatile writes while emitting
WASM, but the WASM specification has no volatile-memory instruction. Browser
and Node JIT runtimes may optimize the generated native code again. For WASM,
the crate provides API compatibility and best-effort clearing, not strong
native-equivalent clearing or timing claims.

The ordinary RAM wipe backend is not claimed to erase MMIO, synchronize with a
DMA device, clean non-coherent target caches, or persist erasure across a
persistent-memory power-failure domain. Version 2.0 intentionally exposes no
generic target-provided backend because those categories require different
unsafe contracts.

## Process, OS, And Hardware Limits

The crate does not protect against:

- privileged reads such as debuggers, `ptrace`, `/proc/<pid>/mem`, kernel
  compromise, hypervisor compromise, or administrative crash dump tools;
- DMA, malicious firmware, physical bus probing, or cold-boot attacks after the
  platform has already exposed memory;
- hibernation files or platform snapshots outside the crate's control;
- host runtime copies of WASM linear memory;
- logs, tracing systems, telemetry, panic messages, or formatters that receive
  secret bytes;
- external copies made before data enters a crate-owned container.

Memory locking reduces swap/pagefile exposure for the crate's owned locked
storage when the OS accepts the lock. It does not make RAM unreadable to the OS
or to privileged attackers.

The crate cannot force destructors to run after `SIGKILL`, aborting OOM,
`panic = "abort"`, `process::abort`, `mem::forget`, `Box::leak`, or
`ManuallyDrop` misuse. The supplied storage-policy lint can reject the latter
three source patterns inside application-designated sensitive roots, but the
application controls those roots and exemptions. See
`docs/DEPLOYMENT_HARDENING.md` for the deployment responsibility matrix.

A compiled feature or successful mapping allocation does not prove that every
requested control was established. Callers must inspect `ProtectionReport`.
Even a report showing established locking, dump exclusion, an exclude or
wipe-child fork policy, and guard pages does not cover hibernation, privileged
reads, hypervisor snapshots, DMA, firmware, or every platform-specific
crash-dump mechanism.

## Rust Move And Stack History

Rust moves may copy bytes. The crate tries to reduce avoidable copies by using
owned containers, closure exposure, in-place transforms, and replacement APIs,
but it does not soundly scrub old stack frames or all historical move copies.

For the highest assurance, construct secrets directly inside crate-owned
containers, use in-place APIs, keep exposure closures small, and avoid passing
secret material through ordinary temporary arrays, strings, or vectors.

Direct mapped initialization avoids a source-level temporary owned by the API,
but it does not guarantee that a decoder, RNG, KDF, compiler, or calling
convention never uses scratch memory or spills registers. Callers remain
responsible for clear-on-drop ownership of unavoidable scratch buffers and for
avoiding `Clone`, `to_vec`, formatting, or long-lived exposed slices.

`ConsumeOnceSecret<T>` means one successful access through that wrapper. It
does not prove the value was never copied before construction, prevent the
winning closure from copying or exporting bytes, clear values deliberately
returned by caller code, or guarantee cleanup after `panic = "abort"`. Cleanup
also depends on `T::secure_sanitize` honoring its documented non-panicking
implementer contract; a downstream sanitizer that panics can leave partial
cleanup and can abort if it panics during unwinding.

`SecretPoolSlotId` is not a capability, revocation token, or globally unique
identifier. Its `usize` generation eventually wraps after the complete counter
range. Retaining an identifier does not retain access; retaining a live safe
slot handle across release is prevented by ownership and lifetimes.

`SecretPool::arena_report()` is point-in-time accounting, not a reservation or
quota forecast. Operating-system limits can change and other mappings can
consume quota concurrently. Variable-size arena allocation is not provided in
2.0; fragmentation and allocator metadata secrecy remain outside the fixed
pool's guarantees.

`SealedSecretBytes<N>` does not make a secret inaccessible while its access
closure is running. The closure may copy or export bytes, trigger signals, call
unsafe reentry paths, or abort the process before the unwind guard runs.
No-access page protection does not stop privileged remapping, kernel or
hypervisor access, DMA, hibernation, or external copies.

Canaries are corruption detectors, not memory authentication. Pre/post checks
can observe adjacent damage before or after normal scoped access, but cannot
prevent arbitrary modification by an attacker who can also rewrite owner
metadata. Keeping a MAC key in the same compromised process does not close that
gap. Random expected canary material owned by the crate is clear-on-drop and is
borrowed rather than explicitly copied by verification, but compiler spills,
register copies, historical moves, aborts, and leaked values remain outside the
clearing guarantee.

If `Drop` cannot change an already sealed page back to read/write, it cannot
perform the normal volatile clear. It intentionally retains the poisoned
mapping and any established memory lock until process termination instead of
releasing unwiped physical pages. The feature therefore does not claim an
infallible final wipe under page-protection failure. CP-16 acceptance also
requires native target evidence and external unsafe review; otherwise the
feature will be deferred from 2.0 stable.

POSIX permits a failed protection update to have changed only part of a
multi-page range. After any failed page-seal transition, the implementation
therefore treats the mapping as poisoned. Cleanup handles pages independently:
each page that can be made writable is immediately erased and resealed before
cleanup advances. A failed page remains uncertain, but does not prevent later
pages from receiving the same treatment. If any transition fails, the
implementation does not unlock or unmap the poisoned mapping. It may remain
allocated and locked until a checked cleanup retry succeeds or the process
exits, without being exposed again through safe APIs. This does not guarantee
that the failed page was erased. After every page is confirmed erased, an unmap
failure may retain the mapping but cleanup may remove its lock.

`try_close()` makes these cleanup outcomes observable and retryable while the
mapping remains live. It does not make the operating-system operations
infallible, guarantee that a page whose transition failed was wiped, or recover
a mapping after unmap has succeeded. `Drop` cannot return the report and remains
best effort; on a page-transition failure it deliberately retains the poisoned
mapping until process exit rather than releasing uncertain pages.

Linux default constructors require wipe-on-fork. Fork-capable targets without
a reviewed equivalent do not claim that a page-sealed access window is
fork-safe; callers can only select ordinary inheritance through an explicit
protection request after accepting that another thread's fork may preserve the
exposed child mapping. Windows process creation does not clone this address
space and is not affected by that POSIX fork race.

Accordingly, `SealedSecretBytes<N>` does not claim infallible `SecureSanitize`
or zeroize compatibility. Callers must handle the result of
`try_secure_sanitize()` or `clear_secret()`.

## Serialization And Interop

Serde support serializes secret-owning types as redacted strings. Deserializing
into the crate's own leaf secret types keeps ingestion on the secret-aware path.
For generic `Secret<T>` or `ConsumeOnceSecret<T>`, secrecy during deserialization
depends on `T`'s own `Deserialize` implementation and any intermediate buffers
it creates.
`SecretVec` and `SecretString` use 1 MiB default serde ceilings.
Use `BoundedSecretVec<MAX>` or `BoundedSecretString<MAX>` at untrusted dynamic
boundaries that require a protocol-specific limit, while retaining transport
and parser limits. The crate's limit takes effect only when the deserializer
calls its visitor; a parser may already have allocated or copied the input.

Infallible dynamic constructors retain ordinary Rust allocation behavior and
may panic on capacity overflow or invoke the allocation error handler. They are
not an untrusted-length boundary. Use `try_with_capacity`, `try_from_fn`, or
`try_from_chars` for allocation errors. Use `try_from_slice_bounded`,
`try_from_secret_str_bounded`, or the corresponding bounded generator when an
application byte maximum must be enforced before any allocation or callback
execution.

Moving an owned `String` into `SecretString` transfers that allocation without
copying, but it cannot clear JSON input buffers, parser scratch allocations, or
other copies created before the string reaches the secret container.

Optional `zeroize`, `subtle`, `arrayvec`, and `bytes` interop is feature-gated
and exists to fit existing ecosystems. It does not extend this crate's
guarantees to the internals of those third-party crates.
