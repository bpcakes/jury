# Unsafe Boundary

The crate root uses `#![deny(unsafe_code)]` and
`#![deny(unsafe_op_in_unsafe_fn)]`.

Representation wiping and target-memory categories are documented in
`docs/ERASURE_BACKENDS.md`.

The complete normative storage-marker checklist is in
`docs/STORAGE_CONTRACTS.md`. Runtime mapped-protection policy and rollback
semantics are in `docs/PROTECTION_REPORT.md`.

## Safe Security Contracts

`SecureSanitize` and the storage-stability markers are safe traits, but their
implementations carry security obligations.

`SecureSanitize` means that the currently reachable owned secret value can be
cleared. Implementations must be idempotent, avoid allocation and avoid
panicking where reasonably possible, leave the value valid to sanitize and
drop again, clear reachable secret-bearing capacity, and clear storage before
releasing or replacing it. When called from a destructor path, an
implementation must not trigger destruction of that same value while the
sanitization call is active. Implementations must document copies, shared or
external storage, padding, allocator metadata, platform copies, or historical
allocations they cannot reach.

`DropSafeSanitize` is the explicit contract for calling a complete sanitizer
from its owner's destructor. It requires the sanitizer to preserve aggregate
cleanup and not replace, destroy, or recursively enter destruction of `Self`.
The trait is safe and downstream-implementable because a false implementation
violates security or availability guarantees, not Rust memory safety. Manual
implementations require review and should carry a `DROP SANITIZE CONTRACT`
comment.

`SecureSanitizeOnDrop` and `secure_drop_struct!` require their complete struct
to implement `DropSafeSanitize + Unpin`, then invoke its complete sanitizer.
`#[derive(SecureSanitize)]` and `secure_sanitize_struct!` automatically provide
the marker for their generated field-wise implementations. This preserves
reviewed external-storage, ordering, and platform cleanup without silently
reopening structural-pinning or recursive-drop assumptions. Address-sensitive
`!Unpin` owners require a reviewed pin-aware manual sanitization and destructor
design.

`StableSharedSecretStorage` asserts that safe operations supplied by a type and
reachable through `&self` cannot release, transfer, replace, or defer release
of secret-bearing storage without first clearing it.
`StableMutableSecretStorage` extends the assertion to operations reachable
through `&mut self`. These contracts include inherent and trait methods,
interior mutation, returned guards and their destructors, callbacks initiated
by methods, and deferred cleanup.

These are normal traits, not unsafe traits. A false implementation breaks the
documented security guarantee but is never a premise for Rust memory safety.
Generic guarantees are therefore conditional on downstream implementations
being correct. Manual implementations require review of the type's complete
safe API and should carry a `STORAGE CONTRACT` comment.

The marker contracts do not prevent a caller from deliberately copying,
logging, replacing, or exporting a secret inside an exposure closure. They
describe the marked type's own safe operations, not arbitrary caller code.

Fixed-size `expose_secret` methods directly borrow their container storage and
do not intentionally build a full-size stack array. This is a source and
reviewed-codegen property, not a promise that the compiler, calling convention,
closure, or downstream code will never spill or copy bytes. Explicit
`SecretBytes::export_secret_copy` creates a reason-bearing temporary plaintext
array that is volatile-cleared on normal return and unwinding but remains
uncleared if the process aborts. Other mapped containers document their own
copy exposure boundaries.

### Strict-Assurance Use

The storage markers are public, safe attestations so downstream fixed-storage
types can participate without becoming dependencies of this crate. A type
checking the trait bound is not evidence that its implementation received an
independent review.

Deployments with a closed or military-controlled assurance profile should:

- define a private or crate-visible `SecretStoragePolicy` with
  `define_secret_storage_policy!` and use `AllowlistedSecret<T, P>` at generic
  application boundaries;
- avoid public APIs that accept arbitrary downstream implementations of the
  marker traits;
- review exposure closures as declassification boundaries and reject closures
  that copy, log, export, replace, allocate from, or otherwise persist secret
  values;
- prefer this crate's audited fixed and dedicated dynamic containers over
  manual marker implementations where possible.
- run `scripts/lint-storage-policies.py` over sensitive application roots so
  direct `Secret<T>`, marker implementations outside approved files, and
  externally nameable policy types fail CI.

Sealing the traits in the core crate would prevent legitimate downstream
fixed-storage implementations and is therefore not the general API policy.
`AllowlistedSecret` composes the public attestation with an application-owned
exact-type policy. Keep that policy private or `pub(crate)`; publishing the
policy type can permit dependencies to name it and may allow approvals for
dependency-owned storage types under Rust's orphan rules.

The policy lint is defense in depth, not semantic proof. It is intentionally
conservative and text-based; repository review must prevent generated code,
aliases, exemptions, or build-time source generation from bypassing the
designated sensitive-root policy.

The core crate intentionally does not certify `Vec<T>`, `String`, `Box<T>`,
references, shared ownership, standard interior-mutability wrappers, or
arbitrary third-party containers. Generic `Secret<T>` exposure is therefore
unavailable for those types, although ownership, explicit clearing, and
clear-on-drop remain available. The core crate does not provide a derive for
these markers: a derive can inspect fields but cannot prove the behavior of
inherent or trait methods, interior mutation, returned guards, callbacks, or
deferred cleanup. The policy macro centralizes reviewed acceptance but does not
turn those attestations into automatically proven properties.

`SecretBoxBytes` is an audited exception for runtime-length heap storage. Its
private `Vec<u8>` is reserved only during construction; safe methods cannot
grow it, shrink it, or extract it. Exposure returns only slices, and every
replacement requires the same public length. Replacement constructs a separate
clear-on-drop allocation before clearing and exchanging the old allocation.
`clear_secret` wipes the private vector's full capacity while preserving its
fixed public length, before drop releases the allocation. Bounded constructors
use `try_reserve_exact` before initialization so untrusted public lengths can
return an allocation error instead of entering an infallible growth path.

`SecretVec::try_with_capacity` and `SecretString::try_with_capacity` also use
`try_reserve_exact`. Their fallible generator constructors keep partial output
inside a clear-on-drop owner. `SecretAllocationError` distinguishes public
limits, explicit capacity arithmetic, and reservation failure;
`SecretGenerateError<E>` keeps those build failures separate from generator
failure. The bounded copy and generation forms validate the caller's public
byte maximum before allocation or generator execution; secret-string
worst-case UTF-8 capacity uses checked multiplication.

Unsafe code is allowed only inside narrow, reviewable implementation modules:

- `wipe_backend`, the default volatile clear backend;
- `canary`, the optional operating-system CSPRNG adapter;
- `mapped::memory_lock`, available with the `memory-lock` feature on supported native
  Linux, Android, macOS, iOS, Windows, and BSD targets, and as a volatile-only
  compatibility backend on WASM only when `wasm-compat` is also enabled.
- `platform::compare_asm`, available only with the `asm-compare` feature on x86_64 and
  AArch64 outside Miri.
- `platform::cache_flush`, available with the `cache-flush` feature. It emits
  `clflush` only on x86_64 outside Miri after runtime capability and line-size
  validation; other targets return a structured unsupported result.
- `platform::register_scrub`, available with the `register-scrub` feature. It emits
  architecture-specific register-zeroing instructions on x86_64 and AArch64
  outside Miri, and is a fenced no-op elsewhere. x86_64 uses runtime AVX OS
  support detection before emitting AVX instructions.
- `mapped::guard_pages`, available only with the `guard-pages` feature on supported
  Linux, Android, macOS, iOS, Windows, and BSD targets outside Miri. The
  feature is rejected at compile time on WASM.
- `owned::consume_once`, which uses `UnsafeCell` behind an atomic one-consumer
  state machine.

Public APIs in `sanitization::wipe` are safe wrappers around the private,
sealed `wipe_backend`.

### Built-in zero-valid representations

Location: `wipe_backend::ZeroValidPlainData`

Purpose: constrain the full-representation wipe used by primitive scalar
`SecureSanitize` implementations.

Invariant:

- the marker is private and unsafe, so downstream crates cannot extend the
  reviewed set;
- every implementation is `Copy`, has no destructor, ownership, pointer
  provenance, interior mutability, or invalid all-zero representation;
- the complete stable implementation set is the primitive integer types,
  `bool`, `char`, `f32`, and `f64`;
- each implementation supplies a typed zero constant whose representation is
  all zero; one typed volatile write avoids transient invalid values such as an
  invalid intermediate `char`;
- arbitrary arrays, aggregates, pointers, references, unions, enums,
  `NonZero*`, and `MaybeUninit<T>` are not representation-wiped through this
  path;
- safe user-defined sanitization remains field-wise through
  `SecureSanitize`.

A public target-provided backend is not part of 2.0. Safe APIs dispatch only
through the crate's private ordinary-RAM backend.

### `sanitization-arrayvec` complete inline backing wipe

Location: `sanitization_arrayvec::backing_wipe`

Purpose: clear historical bytes left in an `ArrayVec<T, CAP>` inline backing
region after elements have been popped, truncated, cleared, reused, or moved
into the wrapper.

Invariant:

- `ArrayVec::spare_capacity_mut()` is the stable upstream API used to obtain
  only non-live `MaybeUninit<T>` slots.
- Live values are sanitized and dropped before a complete post-clear backing
  wipe. Pop and truncate operations similarly remove values before their stale
  slots enter the spare region.
- The spare slice is exclusively borrowed and writable for its complete
  lifetime.
- `sanitization::wipe::maybe_uninit` accepts the `MaybeUninit<T>` slice
  directly and performs raw volatile byte writes without constructing a
  reference to potentially uninitialized `u8` values.
- `core::mem::size_of_val` computes the complete slice byte length without
  separate `CAP * size_of::<T>()` arithmetic.
- Zero-sized element storage produces a zero byte length and performs no
  volatile write.
- No `T` is reconstructed from the cleared backing bytes.
- If a user-provided `SecureSanitize` implementation or destructor panics,
  ordinary Rust unwinding rules apply; the wrapper never raw-zeroes a still-live
  value to force cleanup through a panic.

## Unsafe Operations

### `ptr::write_volatile`

Location: `wipe_backend::ordered_volatile_store`

Purpose: force one byte store per address so clearing ordinary mutable buffers
is not optimized away as dead memory writes. The private sealed backend uses
the same primitive for every pass, including the optional `0xFF` middle pass
under `multi-pass-clear`.

Invariant:

- The raw pointer and length must come from a live mutable slice or the full
  capacity of an owned contiguous allocation.
- Every computed pointer is allocated and writable for exactly one byte write,
  including spare capacity that is not initialized.
- The function never reads through the raw pointer.
- The caller-facing APIs provide exclusive mutable access while wiping.
- For `Vec<u8>` and `String`, the pointer and length passed to the raw wipe
  cover the full allocation capacity, not only the initialized length. This
  writes zero bytes into allocated but possibly uninitialized spare capacity
  without reading it.
- With `multi-pass-clear`, the same pointer validity rules apply to all three
  passes: zero, `0xFF`, zero.
- On WASM, the volatile loop is called through an `#[inline(never)]`
  function-pointer boundary to reduce runtime optimizer visibility. This is a
  best-effort WASM mitigation, not a WASM specification-level volatile
  guarantee.

### `String::as_mut_ptr`

Location: `wipe::string`

Purpose: obtain a raw pointer to the `String` allocation so its full capacity
can be passed to `wipe_backend::erase` before calling `clear()`.

Invariant:

- `text.as_mut_ptr()` provides a pointer valid for `text.capacity()` bytes.
- Every byte in the allocation capacity is overwritten with `0`.
- `0` is valid UTF-8, so initialized string contents remain valid during and
  after wiping.
- Exclusive `&mut String` access prevents concurrent reads or writes while the
  allocation is wiped.
- The raw pointer is not exposed to the caller.

### Platform memory-lock mappings and mapped-memory references

Location: `mapped::memory_lock`

Purpose: provide dependency-free platform memory locking for
`LockedSecretBytes<N>`, native `LockedSecretVec`, and pooled
`SecretPool<N, SLOTS>` slots without routing secret bytes through the Rust
global allocator. Linux uses raw syscalls; Android, macOS, iOS, and BSD use
system C ABI entry points; Windows uses Kernel32 virtual memory APIs. WASM uses
a separate compatibility backend with inline WASM-owned fixed-size storage and
no host memory lock only when `wasm-compat` is explicitly enabled.

Operations:

- `ProtectionRequest` separates required, preferred, and unrequested controls.
  `ProtectionReport` records achieved state and non-secret mapping metadata.
  A required setup failure returns `ProtectionError` with the partial report
  and explicit rollback outcomes.
- Linux: `mmap` creates a private anonymous read/write mapping,
  `madvise(MADV_DONTDUMP)` asks the kernel to exclude that mapping from
  ordinary Linux core dumps. Explicit fork policy either permits inheritance,
  uses `madvise(MADV_DONTFORK)` to exclude the mapping, or uses
  `madvise(MADV_WIPEONFORK)` to present zero-filled pages in the child.
  `mlock` locks the mapping, and `munlock`/`munmap` release it.
- Android, macOS, iOS, and BSD: system `mmap` creates a private anonymous
  read/write mapping, `mlock` locks it, and `munlock`/`munmap` release it.
  FreeBSD additionally requests core-dump exclusion with `MADV_NOCORE`.
  macOS applies `minherit` with `VM_INHERIT_NONE` to the complete writable
  mapping for `ForkPolicy::Exclude`, before locking or any caller fill. Other
  non-Linux Unix targets do not apply fork-inheritance exclusion. macOS
  per-mapping dump exclusion and `WipeChild` remain unsupported.
- Windows: `VirtualAlloc` creates a private read/write region, `VirtualLock`
  locks it, and `VirtualUnlock`/`VirtualFree` release it.
- raw pointers from the mapping are converted to byte slices and fixed-size
  byte-array references while the mapping is live.
- WASM: `UnsafeCell` owns inline fixed-size storage for `LockedSecretBytes<N>`
  and each `SecretPool<N, SLOTS>` slot. The backend exposes the same safe API
  surface where possible, volatile-clears on drop, and intentionally reports no
  locked byte count for pools.

Invariant:

- A report marks a control `Established` only after the corresponding platform
  operation succeeds. Unsupported or failed preferred controls remain visible
  in the retained report.
- A required failure cannot return a live container. The backend attempts
  rollback and records unlock and unmap independently, so a cleanup failure is
  not hidden behind the original setup failure.
- Protection diagnostics contain no secret-derived data, mapping addresses, or
  canary material.
- The module is compiled only for supported OS targets with the `memory-lock`
  feature enabled, or for `wasm32` with both `memory-lock` and `wasm-compat`.
  Linux support is limited to `x86_64` and `aarch64` raw syscall ABIs.
- Linux syscall register assignments follow the Linux syscall ABI for the
  target architecture.
- Non-Linux Unix targets use C ABI declarations without adding a Rust `libc`
  crate dependency.
- Windows targets use Kernel32 ABI declarations without adding a Rust Windows
  bindings dependency.
- The mapped pointer is non-null and owned by exactly one `LockedSecretBytes<N>`
  or `LockedSecretVec` value, or by one `SecretPool<N, SLOTS>` pool.
- The Rust value stores only pointer metadata, so moving it does not move or
  copy the secret byte allocation.
- The fixed-size mapping length is at least `N` bytes when `N > 0`. The dynamic
  `LockedSecretVec` mapping length is at least its requested capacity when
  capacity is non-zero.
- With `canary-check`, non-empty `LockedSecretBytes<N>` and `LockedSecretVec`
  mappings reserve an 8-byte prefix canary and 8-byte suffix canary around the
  initialized secret bytes. The checked payload length includes both canaries
  and is rounded to the platform page granule. The public data pointer is
  offset past the prefix canary.
- With `canary-check`, non-empty `SecretPool<N, SLOTS>` slots reserve the same
  8-byte prefix and suffix canaries inside each slot stride. Allocation writes
  fresh canaries before returning a slot handle, and slot drop clears the full
  stride before releasing the atomic bitmap flag.
- `canary-check` derives standalone expected canaries from the mapping base
  address and a fixed mask. Pooled slots additionally mix a per-slot allocation
  generation into the slot base address, so successive occupants do not reuse
  the same deterministic canary. This avoids RNG and dependency requirements
  while retaining mapping-specific blind-overwrite detection under ASLR.
  Disclosure of one deterministic canary reveals the expected value for that
  live mapping or slot occupancy, allowing an attacker who can also write
  memory to forge it. Use `random-canary` where ASLR is disabled, weakened,
  canary disclosure is in scope, or deterministic canaries are not acceptable
  for the threat model.
- With `random-canary`, the expected canary is generated once from the
  operating-system CSPRNG and stored in a private non-`Copy`, clear-on-drop
  owner inside the Rust value or slot handle. Verification and canary writes
  borrow that owner rather than constructing explicit array copies. Custom
  pool and page-sealed teardown clears this material before publishing slot
  availability or bypassing the guarded value's normal destructor. The prefix
  and suffix copies remain in the locked or guarded mapping beside the secret
  bytes. Random generation failure is reported as a `Random` platform operation
  error where the API can return one. `SecretPool::try_allocate` and all
  `try_allocate_from_*` initialization helpers preserve random generation
  failure separately from ordinary exhaustion. There are no lossy pool
  allocation convenience methods. Compiler-created spills and historical Rust
  moves remain outside this guarantee.
- Canary writes happen only after platform mapping setup and locking succeed.
- On WASM, there is no platform mapping setup or locking. `canary-check`
  requires `random-canary` at compile time because deterministic inline-storage
  canaries have no ASLR-backed mapping address. `random-canary` uses WASI
  preview1 `random_get` where available and otherwise returns a `Random`
  operation error.
- Canary verification compares both prefix and suffix with the expected value
  using the crate constant-time slice comparison helper and boolean `&`, so both
  canaries are checked without data-dependent early exit at this layer.
- Scoped locked and pooled exposure verifies integrity before access and again
  after the closure returns normally. Mutable exposure places a compiler fence
  before the post-access check.
- If canary verification fails, the full mapping is volatile-cleared before
  the ordinary operation returns `CanaryCorruptedError` or
  `SecretIntegrityError`. Standalone locked owners remain permanently poisoned
  even if a later clear rewrites the physical canary words. Explicitly named
  `_or_panic` helpers retain panic-on-corruption behavior for compatibility and
  trait bridges.
- Pool-slot destruction verifies both canary regions before any clear operation
  can rewrite them. A mismatch clears and permanently quarantines the slot;
  only an intact slot is cleared and returned to the available bitmap.
- Secret bytes are not copied into the mapping until platform setup succeeds:
  Linux dump exclusion, the requested fork policy, and `mlock`;
  macOS requested `minherit` fork exclusion and `mlock`; FreeBSD core-dump
  exclusion and `mlock`; Android/iOS/other-BSD `mlock`; Windows `VirtualLock`.
- Fallible direct generation writes only after mapping setup succeeds; partial
  generated bytes are owned by `LockedSecretBytes<N>` and are volatile-cleared
  on error return.
- `from_fill` and `try_from_fill` initialize the final locked payload rather
  than requiring a caller-owned array. `try_init_with` provides the same path
  after a custom protection request has created the mapping. These operations
  invoke the configured integrity check before and after mutable initialization;
  with `canary-check`, both canary regions are verified. They clear partial
  output on a returned generator error and retain clear-on-drop ownership
  during panic unwinding.
- Policy-aware dynamic fill constructors establish every required control
  before invoking the callback. Bounded variants reject capacities above the
  caller's application maximum before mapping; unbounded variants require a
  trusted, already-limited capacity. The callback sees exactly the requested
  public capacity, including when guard-page allocation rounds the writable
  payload upward. Before exposure, the payload is erased to remove the suffix
  canary installed for the initial empty value and to ensure callback input is
  zeroed. During filling, the suffix canary is placed at that advertised
  boundary and verified afterward. Fill, integrity, and
  excessive-length failures clear the mapping; success clears the complete
  unreported tail before moving the suffix canary to the initialized length.
  Protected text wrappers then validate UTF-8 without reallocating and clear
  invalid input.
- Const-generic bounded mapped wrappers retain `MAX` for their entire lifetime,
  keep the underlying growable owner private, and expose no conversion that
  removes the bound. Construction, append, and replacement verify existing
  integrity first, then use checked length arithmetic and reject an excessive
  result before allocation or caller-provided generation. Mutable exposure can
  change initialized bytes but cannot change the initialized length.
- Replacement helpers stage the new value in a fresh locked mapping before
  clearing and swapping out the old mapping. Filled replacement mappings are
  integrity-checked after the callback and before the swap. If mapping setup,
  integrity verification, or generation fails, the old locked value remains
  unchanged.
- Mapping setup failures attempt to unmap before returning. If setup and unmap
  both fail, the unmap error takes precedence because the mapping may remain
  live; the compact stable error representation cannot carry both OS errors.
- `LockedSecretVec` zero-capacity values use a dangling non-null pointer and
  never offset that pointer to create zero-length slices.
- `LockedSecretVec` growth stages a replacement mapping, copies initialized
  bytes into it, writes canaries if enabled, then clears and swaps the old
  mapping.
- `&mut self` is required for mutation and clearing.
- Drop volatile-clears the full mapping before attempting platform unlock and
  release.
- Under `cfg(all(miri, test))`, the core crate's unit-test build replaces native
  syscall and CSPRNG boundaries with a test-only aligned-allocation model. The
  model exercises mapped ownership, replacement, growth, canary, quarantine,
  rollback, and drop paths, and asserts that every simulated mapping is
  entirely zero before deallocation. Modeled `Established` report states do not
  mean an OS control was applied. A normal build with `--cfg miri` uses the
  native backend, and a release build that also forges `cfg(test)` is rejected.
  Comparison code uses its portable backend whenever Miri is active so ordinary
  downstream secret comparisons remain interpretable. Downstream Miri execution
  of mapped constructors, guard pages, and page sealing remains unsupported.
  Compiler cfgs and rustflags are trusted build inputs; the release helper
  rejects ambient `RUSTFLAGS` and `CARGO_ENCODED_RUSTFLAGS` rather than claiming
  to defend against a hostile compiler invocation.
- Drop ignores unlock/unmap errors because destructors cannot report failure.
- `SecretPool<N, SLOTS>` owns exactly one locked mapping. `N * SLOTS` is
  checked for overflow before mapping, then rounded to the platform page
  granule.
- The pool tracks live slots with `[AtomicBool; SLOTS]`. Slot allocation uses a
  compare-exchange from unused to used, preventing two live safe handles for the
  same slot.
- Every backend tracks a per-slot atomic allocation generation. Allocation
  advances that generation only after the bitmap grants exclusive ownership.
  The live handle exposes `(slot_index, generation)` as diagnostic identity.
  Deterministic canary mode also mixes that generation into the
  address-derived canary so successive occupants receive different values.
- Each `SecretPoolSlot` carries a lifetime-bound shared borrow of the pool, so
  Rust prevents the pool from being dropped or mutably cleared while slots are
  live.
- Slot pointer arithmetic is constrained to `slot_index * N`, where
  `slot_index < SLOTS` and construction already checked the total size.
- Slot mutation requires `&mut SecretPoolSlot`; read-only exposure uses
  closure-based access.
- Dropping a slot volatile-clears exactly that slot before marking it available
  again with release ordering.
- Acquire ordering on the next successful claim observes the previous release
  after clearing. The repository's Loom model checks non-overlap,
  clear-before-reuse, generation advance, and failed-setup release.
- Canary failure volatile-clears the affected slot and permanently quarantines
  it for the pool's lifetime. Quarantined slots are skipped before and after
  bitmap claim. A claim abandoned because setup or generation failed without
  an integrity violation releases the bitmap exactly once.
- `arena_report()` derives payload, live, quarantine, reserved, mapped, locked,
  and overhead counts without exposing secret bytes, mapping addresses, or
  canary values. Its live and quarantine counts are point-in-time observations.
- Dropping the pool requires no live slots, volatile-clears the full mapping,
  then unlocks and releases it with the same platform backend as
  `LockedSecretBytes<N>`.
- Variable-size arena allocation is not part of the 2.0 stable design.

### SIMD/vector register scrub instructions

Location: `platform::register_scrub`

Purpose: provide an explicit best-effort register clearing boundary after
cryptographic code that may leave secret material in SIMD/vector registers.

Operation:

- x86_64 checks CPUID OSXSAVE/AVX and XCR0 XMM/YMM state before emitting AVX
  instructions. Non-Windows x86_64 emits `vzeroall` when AVX is available, and
  Windows x64 emits `vzeroupper` plus caller-saved XMM0-XMM5 clears to preserve
  ABI-required XMM6-XMM15 lower halves. The non-AVX fallback emits
  `pxor xmmN, xmmN` for caller-saved XMM0-XMM5.
- AArch64 emits `eor vN.16b, vN.16b, vN.16b` for caller-saved V0-V7 and
  V16-V31.
- Unsupported targets and Miri use a fenced no-op and return an explicit
  report that no architecture instructions executed.

Invariant:

- The assembly writes only declared current-thread caller-saved architectural
  registers and does not read or write memory.
- AVX-512 opmask registers and ZMM16-ZMM31 are not scrubbed. AArch64 V8-V15
  upper halves are not scrubbed because Rust inline assembly cannot express a
  safe partial-register clobber for those ABI-split registers.
- The public function is `#[inline(never)]` and fenced before and after the
  register instructions.
- This does not guarantee whole-process register secrecy. It does not clear
  compiler spills, unrelated registers outside the implemented set, kernel
  context-switch buffers, other threads, or memory copies.

### x86_64/AArch64 inline assembly comparison

Location: `platform::compare_asm`

Purpose: provide the default compiler boundary for equal-length byte comparison
on x86_64 and AArch64 without adding dependencies or requiring `std`.

Operation:

- The public comparison helper checks length equality before calling the
  assembly path.
- The assembly loop reads one byte from each slice, XORs them, ORs the result
  into an accumulator, then advances both pointers.
- The loop count is the already-checked public slice length.
- Unsupported targets, Miri, and builds that disable default features without
  re-enabling `asm-compare` use the portable Rust fallback.

Invariant:

- Both slices are valid for the same number of readable bytes.
- The assembly loop does not write memory.
- The zero-length path does not dereference either pointer.
- All output registers are initialized on every branch path.
- The low byte carries the OR accumulator; Rust masks the accumulator with
  `0xFF` before testing equality so the post-assembly contract is explicit.
- Length remains public metadata and mismatched lengths return before the
  assembly path.

### x86_64 cache-line flush instructions

Location: `platform::cache_flush`

Purpose: provide explicit volatile-clear plus cache-line eviction helpers for
call sites that need x86_64 cache hardening.

Operation:

- Public sanitization helpers first route through the crate's volatile wipe
  backend, before capability or range checks can return an error.
- The x86_64 backend checks CPUID `CLFSH`, reads the reported cache-line flush
  size, and rejects zero, non-power-of-two, or unreasonable values.
- The module aligns the provided address range down to the validated line-size
  boundary with checked end-address arithmetic.
- The module executes `clflush` for every covered cache line, followed by
  `mfence`.
- `GuardedSecretVec::try_clear_secret_and_flush` clears the full writable data
  region before flushing the cache lines covering that same region.
- Unsupported CPUs, architectures, and Miri expose the checked API but do not
  execute `clflush`.

Invariant:

- The pointer and length come from a live slice or owned contiguous allocation.
- The zero-length path does not execute `clflush`.
- `clflush` does not read or write through the Rust pointer; it asks the CPU to
  evict the addressed cache line.
- CPUID capability and line-size checks occur before the first `clflush`, so an
  unsupported CPU cannot reach an illegal instruction.
- Alignment can flush adjacent bytes in the same cache line but does not read
  or write them through Rust references.
- Address-range overflow returns `CacheFlushError::AddressRangeOverflow`; a
  sanitizing helper has already wiped before surfacing that error.
- `mfence` orders the flush operations before later memory operations.

### Platform guard-page mappings

Location: `mapped::guard_pages`

Purpose: provide dynamic byte storage between inaccessible pages without using
the Rust global allocator for secret bytes.

Operations:

- Linux/Android/macOS/iOS/BSD: `mmap(PROT_NONE)` creates one private
  anonymous mapping containing a leading guard page, writable data pages, and a
  trailing guard page. `mprotect(PROT_READ | PROT_WRITE)` enables access only
  for the middle data pages.
- Windows: `VirtualAlloc(PAGE_NOACCESS)` creates one private region containing
  leading guard pages, writable data pages, and trailing guard pages.
  `VirtualProtect(PAGE_READWRITE)` enables access only for the middle data
  pages.
- Raw pointers from the writable middle region are converted into slices for
  initialized length or full writable capacity.
- Linux applies an explicitly requested inherit, exclude, or wipe-child fork
  policy independently of memory locking.
- macOS applies `minherit(data, writable_len, VM_INHERIT_NONE)` to the entire
  writable middle region before caller initialization. The C ABI is the SDK
  `int minherit(void *, size_t, int)`; both guard pages remain inaccessible.
- When `memory-lock` is also enabled, locked constructors apply supported
  platform lock and dump policies on the writable data pages before copying
  secret bytes into them. Linux applies `MADV_DONTDUMP`; FreeBSD applies
  `MADV_NOCORE`.
- `from_fn` constructors generate bytes directly into the writable data pages
  after mapping setup and optional lock policies have succeeded.
- `try_from_fn` constructors generate bytes directly into the writable data
  pages and clear the full writable region on generator errors.
- Guarded mapping setup failures attempt to unmap before returning. If setup and
  unmap both fail, the unmap error takes precedence because the mapping may
  remain live; the compact stable error representation cannot carry both OS
  errors.
- With `canary-check`, guarded mappings reserve an 8-byte prefix canary before
  the payload and an 8-byte suffix canary immediately after the initialized
  payload. Public payload pointers are offset past the prefix canary. Exposure,
  mutation, growth, replacement, and comparison verify both canaries before
  reading or modifying the secret payload. Scoped exposure also verifies after
  normal closure return; mutable exposure fences before that check.
- Canary failure volatile-clears and permanently poisons the guarded owner.
  Reinitializing canary bytes during a later clear does not restore access.
- `try_replace_from_slice` either clears the current writable region before
  in-place replacement, or creates a new guarded mapping without permitting a
  previously established preferred control to downgrade and clears the old
  mapping before it is unmapped.
- Generated replacement applies the same protection-continuity rule before
  clearing the old mapping. Fallible generated replacement leaves the old
  value, request, and report unchanged if setup or generation fails.
- Growth allocates a new guarded mapping, copies initialized bytes into it,
  volatile-clears the old writable region, swaps metadata, and lets the old
  mapping unlock and unmap during drop. A control accepted as established (or
  as not applicable for empty storage) becomes required for the replacement
  attempt. The successful replacement retains the caller's original request.
- Drop volatile-clears the full writable region, unlocks locked mappings, and
  then releases the platform mapping.

Invariant:

- The module is compiled only for supported OS targets with the `guard-pages`
  feature enabled outside Miri. Linux support is limited to `x86_64` and
  `aarch64` raw syscall ABIs.
- Linux syscall register assignments follow the Linux syscall ABI for the
  target architecture.
- The base mapping pointer is owned by exactly one `GuardedSecretVec`.
- The writable data pointer is one platform page granule after the mapping
  base.
- The writable data length is rounded to a platform page granule. Linux uses
  4 KiB on `x86_64`. Linux `aarch64` reads `AT_PAGESZ` from
  `/proc/self/auxv` with raw syscalls, bounds interrupted-read retries, caches
  the result, and falls back to 64 KiB if detection fails or returns an invalid
  value. Android/macOS/iOS/BSD use `getpagesize`; Windows uses `GetSystemInfo`.
- `len <= data_capacity` is preserved before any slice is created.
- The `locked` flag is set only after platform lock setup succeeds. On Linux
  this includes `MADV_DONTDUMP`, `MADV_DONTFORK`, and `mlock`.
  On FreeBSD this includes `MADV_NOCORE` and `mlock`. Other non-Linux Unix
  targets currently apply `mlock` only.
- Guard pages are not locked because they never contain secret bytes.
- `&mut self` is required for mutation and clearing.
- Drop ignores unlock and unmap/free errors because destructors cannot report
  failure.

### Page-sealed fixed mappings

Location: `mapped::guard_pages::SealedSecretBytes`

Purpose: keep a fixed-size secret's middle data pages inaccessible between
explicit scoped accesses.

Invariant:

- `page-seal` reuses the existing guarded mapping backend and does not define a
  second syscall ABI.
- Construction initializes a fixed `N`-byte payload while the middle pages are
  writable, then changes those pages back to `PROT_NONE` or `PAGE_NOACCESS`.
- Every public access requires `&mut self`. The type is `Send` but deliberately
  does not implement `Sync`.
- An access-state transition rejects reentry while the page is exposed.
- A lifetime-bound unwind guard owns the exclusive borrow for the complete
  access window. All payload access goes through that guard, which attempts to
  reseal on normal return and during panic unwinding before the borrow is
  released.
- Canary verification occurs only after the page becomes readable and is
  repeated before the access window is resealed. Corruption clears the writable
  region, leaves the underlying guarded owner poisoned, and returns an
  integrity error after resealing.
- A failed unseal, reseal, or initial seal may have changed only part of the
  requested range. The state becomes poisoned immediately. Cleanup handles
  each page independently: it makes one page writable, erases the complete
  page, restores no-access, and then advances. Processing continues after a
  page failure, so every successfully transitioned page is erased and resealed
  immediately while the failed page remains uncertain.
- If any page transition fails, cleanup does not unlock or unmap the mapping.
  The mapping remains poisoned and any established memory lock remains active
  so a later checked cleanup can retry without first releasing uncertain
  physical pages.
- `try_close()` exposes the same per-page clear-and-reseal, mapping
  release, and fallback unlock path used by `Drop`. Its report contains only
  operation names and platform error codes. Mapping release is attempted only
  after every payload page was confirmed erased. A failed release
  may then unlock the erased mapping; a successful release retires the value.
- Default constructors require Linux `MADV_WIPEONFORK`. Fork-policy syscalls
  are independent of memory locking because `madvise` does not require
  `mlock`. Windows process creation does not clone the address space. Other
  fork-capable targets fail the default constructor and require an explicit
  lower-assurance protection request.
- Drop uses the same per-page writable transition, immediate volatile clear,
  reseal, release, and fallback-unlock helper as `try_close()`, but necessarily
  discards its report. If any page transition fails, Drop intentionally retains
  the poisoned mapping and any established lock until process exit rather than
  returning uncertain physical pages to the operating system.
- Because making a sealed page writable is fallible, this type exposes
  `try_secure_sanitize()` and does not implement infallible sanitization,
  zeroize-on-drop, or stable-storage marker traits.
- Signal-handler reentry, process abort, and privileged page-table changes are
  outside this Rust ownership boundary.

## Consume-Once Secrets

`ConsumeOnceSecret<T>` uses an `AtomicBool` claim flag and an `UnsafeCell<T>`.
The unsafe boundary is intentionally small:

- `consume` first claims access with `AtomicBool::swap(true,
  Ordering::AcqRel)`.
- Only the caller that observes the previous value as `false` receives access
  to the inner `T`; every later caller receives `AlreadyConsumedError`.
- Exposure is scoped and shared. The wrapper does not move ownership of `T`
  out, and it intentionally provides no mutable consume method.
- `consume` requires `T: StableSharedSecretStorage`, so safe operations reached
  through the shared reference may not release uncleared secret storage.
- The successful caller installs a private cleanup guard before invoking caller
  code. The guard clears the inner value after normal return or during unwind,
  even if another `Arc` or owner keeps the wrapper alive after `catch_unwind`.
- A closure return value, including an application-level error, is produced
  before the guard clears the wrapped value and the method returns.
- The cleanup guard runs only after the closure frame and its borrow of the
  inner value have ended. Process abort remains outside destructor guarantees.
- `ConsumeOnceSecret<T>` is `Sync` when `T: Send`, following the same runtime
  exclusivity principle as lock-like containers: shared references may race to
  claim the value, but only one can access it.
- `secure_sanitize` and `into_cleared` mark the value claimed before clearing
  it, so later consume attempts fail closed.
- The winning closure can deliberately copy, log, or export data. Rust moves,
  optimizer-created temporaries, and register residue remain outside this
  ownership guarantee.

## Safe Temporary Buffers

`SecretBytes::replace_from_array`, `ExpiringSecretBytes::replace_from_array`,
and `LockedSecretBytes::try_replace_from_array` take ownership of a `[u8; N]`,
copy it into the target secret storage, and clear the owned input array with
the volatile wipe backend. Locked array replacement uses a fresh locked mapping;
if mapping setup fails, the owned input array is still cleared and the old
locked value remains unchanged.

`SecretBytes::replace_from_fn` and `try_replace_from_fn` stage generated bytes
inside a fresh clear-on-drop `SecretBytes<N>` value before clearing and swapping
out the old value. If generation returns an error or unwinds, the old value
remains unchanged and partial generated bytes are cleared.

`SecretVec::from_vec`, `SecretString::from_string`,
`SecretVec::replace_from_vec`, and `SecretString::replace_from_string` take
ownership of an existing heap allocation without copying the new bytes. For
replacement, the old allocation is cleared first. In all cases, the transferred
allocation becomes owned by the secret container, so its full capacity is
covered by later clear/drop operations.

`SecretString::from_secret_vec` validates UTF-8 and transfers the existing
`SecretVec` allocation with `mem::take`; `SecretString::into_secret_vec`
performs the inverse transfer. Neither conversion reallocates. Invalid byte
input is explicitly cleared before `Utf8Error` is returned.

`BoundedSecretString<MAX>` delegates storage and clearing to `SecretString`.
Length checks use UTF-8 byte length. Owned strings or existing secret
containers that fail the limit are cleared before the error is returned.

`SecretString::from_chars`, `try_from_chars`, `replace_from_chars`, and
`try_replace_from_chars` generate valid UTF-8 by accepting `char` values. Each
character is encoded through a four-byte stack buffer, copied into the secret
heap allocation, and then the stack buffer is immediately cleared with the same
volatile wipe backend used elsewhere in the crate. Fallible generation keeps
partial text inside a clear-on-drop `SecretString` local, so generated heap
bytes are cleared if the generator returns an error or unwinds.
`try_from_chars` additionally reports worst-case capacity overflow and
allocation refusal; `try_from_chars_bounded` rejects excessive worst-case UTF-8
byte capacity before allocation or generator execution.

`SecretString::try_with_secret_mut` exposes mutable text as `&mut str` rather
than mutable bytes. This keeps UTF-8 validity enforced by safe Rust while still
allowing in-place text edits through closure-scoped access.

`LockedSecretString` and `GuardedSecretString` contain the corresponding byte
container directly. They introduce no raw-pointer operations of their own.
Construction from an existing mapped byte container validates UTF-8 before
wrapping it and clears invalid input. Safe mutable exposure is limited to
`&mut str`, so the UTF-8 invariant cannot be invalidated through the wrapper.
Their ordinary access validates mapping integrity first and reports invalid
payload UTF-8 separately.

## Non-Goals

This unsafe boundary intentionally does not implement stack scanning, cache
flushes for non-x86_64 targets, SIMD clearing, or broad platform memory
policy. Memory locking is explicit, feature-gated, platform-limited, and still
does not protect against crash dumps, hibernation, privileged reads, DMA, or
external copies.
Assembly-backed comparison is x86_64-only and does not make length private.
Cache-line eviction is explicit, x86_64-only, and does not prove full CPU-cache
or microarchitectural side-channel secrecy.
Guard pages are feature-gated, platform-limited, and detect crossings outside
the writable mapped data pages; they do not catch logical overreads that remain
inside capacity.

## Thread Safety

`LockedSecretBytes<N>`, `LockedSecretVec`, and `GuardedSecretVec` explicitly
implement `Send`
because each value exclusively owns its private platform mapping. Moving the
Rust value to another thread moves only pointer metadata; it does not move or
copy the mapped secret bytes. Mutation and clearing still require `&mut self`.
The locked and guarded text wrappers inherit these properties from their
contained byte mappings.

These mapped containers intentionally do not implement `Sync`. Concurrent
shared access should be provided by caller-owned synchronization such as
`Mutex<T>` when cross-thread sharing is required.

## Darwin fork-exclusion validation

The private native tests query the exact original writable range in a forked
child while the parent keeps its owner alive. macOS uses `mach_vm_region` to
prove the next mapping starts after the range (or no later region exists).
Darwin `mincore` is unsuitable: its residency results do not distinguish holes.
Linux queries each page with `mincore` and requires `ENOMEM`. An inherited
zero-filled mapping is a negative control. The child emits only an exit status;
timeouts kill and reap it. No core file or child payload read is used.

Private test-only injection covers mapping, guards, inheritance, lock, and
canary setup failures before the fill closure. Cleanup observations occur while
the writable region is still owned, immediately before native unmap. Guarded
Drop performs a final volatile wipe after clear_secret resets live canaries,
so the entire writable range, including canaries, is zero before unlock/unmap.
