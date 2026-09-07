# CP-02 Sanitization And Storage Contracts

Status: implementation review record

Base checkpoint: accepted `CP-01`

Checkpoint: `CP-02`

CP-02 separates current-value sanitization from storage-stability claims. It
adds security contracts but does not yet restrict `Secret<T>` exposure; those
API changes belong to CP-03.

## Contracts

`SecureSanitize` is normative for the currently reachable owned value.
Implementations must be idempotent, avoid allocation and avoid panicking where
reasonably possible, leave a valid later sanitize/drop path, clear currently
owned secret elements and reachable secret-bearing capacity, clear before
release or replacement, and document storage they cannot reach.

`StableSharedSecretStorage` asserts that safe operations supplied by the type
and reachable through `&self` cannot release, transfer, replace, or schedule
later release of secret-bearing storage without clearing it first.

`StableMutableSecretStorage` extends the assertion to safe operations supplied
by the type and reachable through `&mut self`.

Both marker contracts include inherent and trait methods, interior mutation,
returned guards and their destructors, method-initiated callbacks, and deferred
cleanup. Caller-authored copying, logging, `mem::replace`, or external calls
inside an exposure closure remain caller responsibility.

The markers are normal traits. Incorrect downstream implementations violate a
security promise but are never relied on for Rust memory safety. Generic
guarantees are conditional on correct implementations.

## Audited Implementations

CP-02 certifies:

- supported integer, boolean, character, and floating-point scalars;
- unit, slices, and fixed arrays when their elements carry the matching
  contract;
- tuples through arity 12 when every field carries the matching contract;
- `PhantomData<T>`;
- `SecretBytes<N>`;
- `SplitSecretBytes<N, SHARES>` with `split-secret`;
- `ExpiringSecretBytes<N>` with `std`;
- native and WASM-compat `LockedSecretBytes<N>`;
- native and WASM-compat `SecretPool<N, SLOTS>` and its lifetime-bound slots.

Tuple fields are sanitized from left to right. Field-wise cleanup does not
claim to clear tuple representation padding.

## Deliberate Exclusions

CP-02 does not certify:

- `Vec<T>`, `String`, or `Box<T>`;
- `Option<T>` or `Result<T, E>`;
- references, `Rc`, `Arc`, or other shared ownership;
- `Cell`, `RefCell`, mutexes, locks, or arbitrary interior mutation;
- dynamic crate containers that can replace allocations;
- `Secret<T>` or `ReadOnceSecret<T>`;
- arbitrary third-party containers.

Those exclusions are conservative. A future checkpoint may add a dedicated
reviewed implementation for a specific type, but no blanket assumption follows
from `SecureSanitize`.

No stability derive is added. A derive can verify field bounds but cannot prove
the behavior of inherent methods, trait methods, callbacks, guards, or deferred
cleanup. Manual implementations require complete safe-API review and an
explicit `STORAGE CONTRACT` rationale.

## Verification

The checkpoint includes:

- compile-pass rustdoc and an example for a reviewed manual implementation;
- compile-fail rustdoc for interior-mutable and reallocating types;
- compile-time assertions for built-in shared and mutable contracts;
- tuple cleanup-order coverage through the maximum supported arity;
- native and WASM compile coverage for fixed mapped and pooled storage;
- the normal repository test, clippy, rustdoc, target, codegen, Kani, evidence,
  and checkpoint-history gates.
