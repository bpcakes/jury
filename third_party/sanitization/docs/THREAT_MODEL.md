# Threat Model

This crate focuses on reducing secret lifetime and accidental disclosure inside
Rust applications.

Generic ownership guarantees depend on the downstream attestations defined in
`docs/STORAGE_CONTRACTS.md`. Mapped runtime protection claims depend on the
request and achieved outcome described in `docs/PROTECTION_REPORT.md`.

## In Scope

- Clear-on-drop containers for fixed-size and heap-allocated secrets.
- Avoiding accidental `Copy`, `Clone`, direct slice exposure, equality, and
  secret-printing `Debug` implementations for crate-owned secret types.
- Closure-based accessors that keep normal use sites narrow.
- Volatile clearing for ordinary mutable byte slices.
- Volatile clearing of `SecretVec` and `SecretString` initialized bytes and
  spare heap capacity before freeing their allocations.
- Fixed-allocation runtime-length byte storage through `SecretBoxBytes`, whose
  safe operations cannot resize or extract the private backing allocation and
  whose clear path wipes its full capacity.
- Const-generic `BoundedSecretVec<MAX>` enforcement for dynamic secret input
  whose length must be limited at an application trust boundary.
- Const-generic `BoundedSecretString<MAX>` enforcement for secret UTF-8 input
  whose encoded byte length must be limited at an application trust boundary.
- Explicit volatile helper APIs for existing ordinary buffers.
- Optional platform memory locking for `LockedSecretBytes<N>` when the
  `memory-lock` feature is enabled on supported Linux, Android, macOS, iOS,
  Windows, and BSD targets.
- Optional dynamic platform memory locking for `LockedSecretVec` when the
  `memory-lock` feature is enabled on supported native targets.
- Optional UTF-8-safe dynamic memory locking for `LockedSecretString`, backed
  by `LockedSecretVec`.
- Optional pooled platform memory locking for many same-size fixed secrets with
  `SecretPool<N, SLOTS>` when the `memory-lock` feature is enabled on supported
  targets.
- Explicit WASM API compatibility for `LockedSecretBytes<N>` and
  `SecretPool<N, SLOTS>` when both `memory-lock` and `wasm-compat` are enabled
  on `wasm32`, using volatile-only WASM-owned storage without claiming host
  memory locking.
- Optional prefix/suffix canary integrity checks for non-empty
  `LockedSecretBytes<N>` mappings, pooled slots, and guarded dynamic mappings
  when the `canary-check` feature is enabled.
- Optional Linux `MADV_DONTDUMP` on locked secret mappings to reduce ordinary
  core-dump exposure.
- Optional Linux `MADV_DONTFORK` on locked secret mappings to reduce accidental
  inheritance across `fork`.
- Optional x86_64 assembly-backed equal-length comparison when the
  `asm-compare` feature is enabled.
- Optional x86_64 volatile-clear plus cache-line eviction when the
  `cache-flush` feature is enabled.
- Optional best-effort SIMD/vector register scrubbing on x86_64 and AArch64
  when the `register-scrub` feature is enabled.
- Optional explicit three-pass volatile overwrite helpers when the
  `multi-pass-clear` feature is enabled.
- Optional N-of-N XOR split fixed-size storage when the `split-secret` feature
  is enabled.
- Optional hardware-backed provider traits when the `hardware-secrets` feature
  is enabled.
- Optional `std` lifetime enforcement for fixed-size secrets with
  `ExpiringSecretBytes<N>`.
- Optional platform guard-page storage for dynamic byte secrets with
  `GuardedSecretVec` on supported Linux, Android, macOS, iOS, Windows, and BSD
  targets.
- Optional UTF-8-safe guard-page storage with `GuardedSecretString`, backed by
  `GuardedSecretVec`.
- Optional fixed-size page-sealed storage with `SealedSecretBytes<N>`, whose
  data pages are inaccessible between scoped mutable-borrow access windows.
- Optional platform memory locking for `GuardedSecretVec` when both
  `guard-pages` and `memory-lock` are enabled.

## Out of Scope

- Preventing secrets from entering hibernation files, crash dumps, logs, tracing
  systems, or external libraries.
- Preventing swap/pagefile exposure on unsupported targets or for values not
  stored inside native `LockedSecretBytes<N>`, `LockedSecretVec`,
  `LockedSecretString`, `SecretPool`, or locked `GuardedSecretVec`/
  `GuardedSecretString` storage.
- Preventing host-runtime copies, swapping, snapshots, dumps, or browser memory
  inspection for WASM linear memory.
- Preventing disclosure through a debugger, `/proc/<pid>/mem`, ptrace, kernel
  compromise, DMA, malicious firmware, or privileged co-tenants.
- Revoking external copies after a secret has already been exposed to caller
  code or third-party libraries.
- Treating the ordinary coherent-RAM wipe backend as sufficient for MMIO,
  non-coherent DMA buffers, persistent memory, or hardware-keystore handles.
- Preventing a deserializer or transport from allocating its own input before
  the 1 MiB `SecretVec`/`SecretString` ceilings or a caller-selected bounded
  byte/text container receives visitor control.
- Hiding UTF-8 validity, invalid-byte position, serde acceptance/rejection, or
  variable secret length. Validation and length mismatch behavior treats those
  values as public metadata and is not claimed to be data-oblivious.
- Using Miri as evidence for native memory-lock, mapping, page-protection,
  dump/fork-policy, CSPRNG, or guard-page syscalls. The core crate's Miri unit
  tests exercise a test-only allocation model for locked-container lifecycle
  and clear-before-release invariants. Downstream comparison uses portable code,
  while downstream mapped constructors and the real OS paths still require
  native platform tests.
- Using Kani as proof of real concurrent execution or atomic interleavings.
  Kani's configured harnesses provide bounded sequential functional evidence.
- Soundly scrubbing old stack frames, prior Rust move copies, all CPU
  registers, unrelated CPU cache lines, allocator metadata, or third-party
  library copies. The `register-scrub` feature is only an explicit best-effort
  current-thread SIMD/vector register clearing boundary.
- Clearing temporary stack copies after process abort. Closure helpers clear
  their temporaries on normal return and unwinding paths only; `panic = "abort"`
  and other abort paths skip destructors and post-closure cleanup.
  `sanitize_then_abort` helps only when the application deliberately routes a
  fatal path through that helper and supplies every secret-owning root.
- Cache-line flushing outside x86_64.
- Detecting corruption that changes only the secret bytes and does not reach a
  canary word.

## Design Position

The default API tries to avoid creating hard-to-clear copies in the first place.
`SecretBytes<N>` is the strongest default path because the storage is controlled
by this crate from initialization to drop. `SecretVec`, `SecretString`, and
their bounded variants are more practical for dynamic integration boundaries
but still cannot control copies made before data enters the container.

Volatile byte writes improve clearing resistance against compiler optimization,
but they do not solve broader process, OS, hardware, or allocator threats.
On WASM, this guarantee is weaker than on native targets: Rust/LLVM preserves
`ptr::write_volatile` while emitting WASM, but the WASM specification has no
volatile-memory operation. A runtime JIT or AOT compiler sees ordinary WASM
stores. The crate uses an `#[inline(never)]` function-pointer boundary on
WASM as a best-effort optimizer barrier, but this is not equivalent to native
volatile semantics. Building with WASM atomics/shared-memory support can give
runtimes stronger observable side effects, but that is a deployment property
outside this crate.

With the `multi-pass-clear` feature, the crate exposes explicit three-pass
volatile overwrite helpers using zero, `0xFF`, and zero patterns. For ordinary
volatile RAM, single-pass volatile zeroing is the normal security boundary and
is consistent with modern sanitization guidance for DRAM. Multi-pass clearing
is provided for policy, audit, or legacy compliance language such as
DoD 5220.22-M-style overwrite procedures; it should not be interpreted as
meaningfully stronger protection for live process memory.

With the `memory-lock` feature on supported Linux, Android, macOS, iOS,
Windows, and BSD targets, `LockedSecretBytes<N>` and native `LockedSecretVec`
use private platform mappings and memory locking to reduce the chance that
secret storage reaches swap or pagefiles. `SecretPool<N, SLOTS>` uses the same
backend but sub-allocates many fixed-size slots from one locked mapping,
reducing page-granule quota overhead for applications that keep many same-size
secrets. Linux also applies `MADV_DONTDUMP`; callers can explicitly allow fork
inheritance, request `MADV_DONTFORK` exclusion, or request
`MADV_WIPEONFORK` zero-filled child pages. This is a high-assurance building
block, not a complete OS secrecy guarantee. Resource
limits or policy can make setup fail, and locked memory can still be exposed
through hibernation, nonstandard crash dump mechanisms, debuggers, privileged
reads, DMA, malicious firmware, or copies made before data enters the locked
container. Leaking a slot with `core::mem::forget` also leaks that slot's
allocation state and skips its drop-time clearing, just as leaking any
secret-owning value skips its destructor.

Feature selection indicates compiled capability, not achieved runtime
protection. `ProtectionRequest` classifies each control as required, preferred,
or not requested. Mapped containers retain a `ProtectionReport` describing the
actual result. Required failures roll back the mapping and return a
`ProtectionError` containing the partial pre-rollback state and separate
unlock/unmap outcomes. Preferred failures may return reduced-protection storage
only when the report marks the control failed, unsupported, or
compatibility-only. Reports expose operational sizes and platform error codes,
but never secret bytes, canary values, or mapping addresses.

For runtime-length decoders and generators, the bounded policy-aware
constructors on locked or guarded dynamic storage reject capacities above an
application maximum, then establish required controls before invoking user
code. This prevents resource consumption driven by an untrusted length and
prevents the
crate from intentionally materializing plaintext into a mapping after a
required lock, guard, dump, fork, or canary control failed. Controls marked
`Preferred` may still degrade by design, so high-assurance callers must mark
pre-materialization requirements as `Required`. Unsafe decoder code, privileged
in-process writes, and copies created by the callback remain outside the
library's authority; boundary canaries are detection rather than prevention.
The unbounded variants require a trusted, already-limited capacity. Anonymous
mapping overcommit and later page-touching cleanup make successful allocation
an insufficient resource-admission policy by itself.

The `maximum` argument accepted by one-shot bounded constructors governs only
initial admission; their ordinary mapped return types remain growable. When a
maximum must remain invariant, use `BoundedLockedSecretVec<MAX>`,
`BoundedGuardedSecretVec<MAX>`, or the corresponding bounded mapped UTF-8
wrapper. These types retain the policy as a const generic, keep the growable
owner private, and reject oversized safe mutations before allocation or caller
code runs. The application remains responsible for selecting an appropriate
public `MAX` and rate-limiting repeated accepted allocations.

The named native profiles preserve this separation. They bundle reviewed
features and expose matching `ProtectionRequest` constructors; they do not turn
Cargo feature resolution into proof of runtime protection.
`profile-hardened-native` requires locking and random canaries while preferring
dump/fork exclusion, `profile-guarded-native` additionally requires guard
pages, and `profile-hardened-linux` requires Linux fork exclusion. Native
profiles are rejected on WASM.

Neither a successful report nor a named feature profile claims protection from
privileged process inspection, hibernation, VM or hypervisor snapshots, DMA,
firmware, or every crash-dump mechanism. Deployment policy must evaluate those
channels separately.

`LockedSecretString` is a UTF-8-safe wrapper over `LockedSecretVec`; it does not
add a second mapping or allocation. Moving an ordinary `String` into locked
text requires copying into the platform mapping, after which the source string
allocation is cleared. Converting an existing locked byte container validates
UTF-8 without reallocating and clears invalid input before returning an error.

With both `memory-lock` and `wasm-compat` on WASM targets,
`LockedSecretBytes<N>` and `SecretPool<N, SLOTS>` are exposed as volatile-only
compatibility containers. They keep API-level code portable and still clear
their owned WASM storage on drop, but they do not call `mlock`, do not create
protected mappings, do not exclude host dumps or snapshots, and cannot prevent
the runtime from copying or moving linear memory. `memory-lock` without
`wasm-compat` is rejected at compile time on WASM to avoid silently degrading
native memory-lock expectations. `SecretPool::locked_len()` returns `0` on WASM
to avoid misrepresenting host memory as pinned. `guard-pages` is not available
on WASM because WASM linear memory has no `mprotect`-style page protection
available to the module.

With the `canary-check` feature, non-empty `LockedSecretBytes<N>` mappings,
`LockedSecretVec` mappings, and `SecretPool<N, SLOTS>` slots place an 8-byte
canary before and after the secret bytes. `GuardedSecretVec` places one canary
before the payload and one immediately after the initialized payload. Exposure,
mutation, replacement, and comparison APIs verify both canaries before reading
or modifying the secret. Scoped exposure APIs also verify them after the
closure returns normally. Ordinary APIs clear the mapping or slot and return
`CanaryCorruptedError` or `SecretIntegrityError`; explicitly named
`_or_panic` helpers preserve panic-on-corruption behavior. This can detect overwrites
that stay inside the writable mapping but reach the canary words, including
some overrun/underrun cases that do not reach a guard page. It does not detect
corruption entirely inside the secret bytes and does not provide authenticity
against an attacker who can read and rewrite the full process memory image.
The locked and guarded UTF-8 wrappers expose checked text access through
`SecretTextIntegrityError`, which distinguishes canary corruption from invalid
UTF-8 payload bytes.

By default, standalone mapped canary words are derived from mapping addresses
and a fixed mask. Deterministic pooled canaries additionally mix in a per-slot
allocation generation so a disclosed value is not reused by the next occupant
of that slot. This mode assumes ASLR or otherwise unpredictable mapping
addresses and is intended for blind-overwrite resistance. Disclosure of a live
deterministic canary still reveals the expected value for that mapping or slot
occupancy, so an attacker who can both read and write memory can forge it. Use
`random-canary` when ASLR is disabled, weakened, canary disclosure is in scope,
or deterministic canaries are not acceptable for the threat model. With
`random-canary`, canaries are generated from the operating-system CSPRNG using
dependency-free platform backends. Crate-owned expected canary material is
non-`Copy`, is borrowed for verification and writes, and is volatile-cleared
during owner, pool-slot, and page-sealed teardown. Random canaries improve blind
overwrite detection and audit posture, but they still do not authenticate
memory against an attacker who can read and rewrite both the owner metadata and
mapped canary bytes. Compiler-created spills and historical moves are not
claimed to be recoverable or clearable.
`strict-canary-check` is a named profile for environments where deterministic
canaries are not acceptable; it enables `random-canary` and therefore fails
construction on targets without a supported dependency-free random backend
instead of falling back to address-derived canaries.
On WASM, deterministic canaries are rejected at compile time because fallback
storage lives inline with the Rust value or pool and has no ASLR-backed mapping
address. `canary-check` on WASM must be paired with both `wasm-compat` and
`random-canary`. WASI preview1 uses `random_get`; bare
`wasm32-unknown-unknown`, Emscripten-style WASM, and WASI preview2 currently
return a `Random` operation error for random canary generation in this
dependency-free implementation.

The default feature set enables `asm-compare`. On x86_64 and AArch64,
equal-length comparisons,
including `ct::eq_fixed`, native secret-container `ct::ConstantTimeEq`
implementations, and crypto-interop verification helpers, use the shared
inline-assembly loop. This gives the comparison body a stronger compiler
boundary, but it does not hide length metadata and does not claim protection
against all microarchitectural side channels. With `strict-compare`, unsupported
non-Miri targets fail at compile time instead of using the portable Rust
equality fallback. The portable equality fallback remains available to builds
using `default-features = false` without re-enabling `asm-compare`, but it
relies on source-level data-oblivious structure plus optimizer barriers rather
than a target-specific assembly boundary. It is not included in the AArch64
Linux timing-evidence claim after repeated release-candidate leakage failures.
`strict-compare` does not strengthen ordering, selection, copying, swapping,
lookup, or caller code.

Mapped-container comparison claims are conditioned on intact canaries. Native
and `subtle` trait comparisons fail closed with a false choice as soon as an
integrity check reports corruption, so their runtime may distinguish the
public operational state "mapping corrupted" from "mapping intact." This does
not reveal a compared secret byte, and canary state is not classified as
secret data. Callers that need typed incident handling must use the checked
comparison methods and treat integrity failure as a security event rather than
as an ordinary authentication mismatch.

With the `cache-flush` feature, explicit clear-and-flush helpers volatile-clear
the target storage before attempting eviction. On x86_64, the backend verifies
CPUID `CLFSH`, validates the reported line size, and executes `clflush` over the
overflow-checked covered range followed by `mfence`. Unsupported CPUs,
architectures, and Miri return a structured error after sanitizing helpers have
still wiped. This can evict addressed lines from CPU caches, but it does not
prove all historical copies are gone, guarantee eviction from every private
buffer, or solve general microarchitectural side channels. When combined with
`guard-pages`, `GuardedSecretVec` can explicitly clear and flush its full
writable data region. `clflush` itself is an unprivileged instruction commonly
used in cache-timing attacks such as Flush+Reload; this feature reduces post-use
residency but does not protect against an attacker who can observe cache timing
while the secret is live.

With the `register-scrub` feature, explicit helpers clear selected
current-thread SIMD/vector registers on x86_64 and AArch64 and return the
architectural subset actually covered. Unsupported targets and Miri return an
explicit no-instruction result. This is a local post-crypto hygiene boundary,
not proof that all general-purpose, callee-saved, interrupt, signal, stack,
spill, kernel, or other-thread copies have been removed. AVX-512 opmask
registers, ZMM16-ZMM31, and AArch64 V8-V15 upper halves remain outside the
implemented scrub path.

With the `split-secret` feature, `SplitSecretBytes<N, SHARES>` stores a
fixed-size secret as N-of-N XOR shares. This can reduce the impact of a single
contiguous memory disclosure only when shares are placed and protected
separately by the application. It is not threshold cryptography, not Shamir
secret sharing, and depends on the caller supplying cryptographically random
mask bytes. Construction rejects trivially constant mask shares in all build
profiles, including a trivially constant combined mask accumulator, but that is
only a misuse guardrail and does not validate entropy.

With the `hardware-secrets` feature, the crate exposes traits for backend
crates that integrate HSMs, TEEs, platform keystores, enclaves, or similar
providers. The core crate does not implement or certify any hardware backend.

With the `std` feature, `ExpiringSecretBytes<N>` checks a configured maximum age
at access time. Expired values are cleared before access is rejected. This is an
API-level policy control; it does not revoke bytes that callers copied out
before expiration and does not run in the background.

With the `guard-pages` feature on supported Linux, Android, macOS, iOS,
Windows, and BSD targets, `GuardedSecretVec` stores dynamic secret bytes
between inaccessible pages. This can turn linear overreads or overwrites beyond
the mapped data pages into faults, but it does not catch logical overreads
inside the writable capacity and does not protect copies made before data
enters the guarded container.

`GuardedSecretString` applies the same mapping and guard-page properties while
restricting safe access to UTF-8. Converting an existing guarded byte container
does not remap or copy it; invalid UTF-8 is cleared before rejection.

Explicit Linux guarded requests apply inherit, exclude, or wipe-child fork
policy independently of memory locking. When both `guard-pages` and
`memory-lock` are enabled, `GuardedSecretVec` locked constructors also lock the
writable data pages and request `MADV_DONTDUMP`. This combines guard-page fault
isolation with swap/pagefile reduction for dynamic secrets, but all memory-lock
limits still apply.

On macOS, explicit exclude uses `minherit(..., VM_INHERIT_NONE)` on the
complete writable region before initialization. Wipe-child remains unsupported.
Other non-Linux Unix targets report both exclude and wipe-child unsupported.
An explicit inherit policy succeeds because ordinary platform fork behavior
inherits the mapping. Applications using prefork servers or worker pools on
those unsupported targets must clear secrets before forking or isolate
secret-owning work into processes created before secrets are loaded.
FreeBSD requests core-dump exclusion with `MADV_NOCORE`; Android, macOS, iOS,
OpenBSD, NetBSD, and DragonFly BSD do not apply crate-level dump exclusion.
With `require-fork-exclusion`, named locked constructors request exclusion as
required and fail on targets where it is unavailable. Explicit requests can
instead require wipe-child behavior. This feature is intended for deployments
where accidental fork inheritance is an audit blocker.

With `page-seal`, fixed-size secret data pages are changed to no-access between
scoped accesses. The access window itself remains readable/writable, requires
`&mut self`, and is guarded against ordinary reentry. Normal return and panic
unwinding attempt to reseal. Cleanup after a failed transition processes every
page independently: each page made writable is erased and resealed immediately, and
processing continues after individual failures. If any page remains uncertain,
cleanup retains the poisoned mapping and any established memory lock without
attempting release. A checked cleanup call may retry every page. Default
constructors require Linux
`MADV_WIPEONFORK`, preventing an unrelated thread's fork during the access
window from retaining readable child bytes. Fork-capable targets without a
reviewed equivalent require an explicit lower-assurance policy; Windows
process creation does not clone the current address space. Signals, process
abort, privileged remapping, DMA, and failure to make a sealed page writable
during `Drop` remain explicit residual risks.
The type therefore exposes fallible explicit sanitization and does not
implement infallible sanitization or zeroize-on-drop traits.

`SecretBytes::expose_secret` directly borrows the owned fixed-size storage and
does not intentionally construct a full-size temporary array. This reduces
stack remanence but does not prevent compiler spills, register copies, caller
copies, or copies created by external code.

`SecretBytes::export_secret_copy` explicitly creates a full-size temporary
stack array. It volatile-clears that copy on normal return and unwinding, but
cannot clear it after process abort. The same direct-versus-copy distinction
applies to fixed locked storage and pool slots. Split-secret plaintext cannot
be borrowed directly because it does not exist contiguously at rest.

`SecretBoxBytes` prevents safe in-place growth and rejects length-changing
replacement. It does not lock allocator-backed pages, prevent swap or
hibernation copies, control allocator metadata, or recover allocations and
copies created before bytes enter the container. Use mapped locked or guarded
types when those platform protections are required. Infallible constructors
still require a trusted, bounded public length; use the bounded fallible
constructors for untrusted length metadata and availability-sensitive code.

Mapped and locked constructors consume process and kernel resources such as
mapping entries and locked-memory quota. Do not create one locked or guarded
mapping per untrusted network event without an application-level bound and rate
limit. For many same-size secrets on an untrusted or high-volume path,
pre-allocate a bounded `SecretPool<N, SLOTS>` during trusted startup and treat
pool exhaustion as an explicit availability policy.

Canary corruption clears and permanently poisons standalone locked or guarded
owners. Rewriting canaries during a later clear does not make those owners
usable again. Pool-slot destruction checks integrity before clearing can rewrite
the canary words, so corruption clears and permanently quarantines the affected
slot even when no later accessor runs. This reduces usable capacity until the
pool is replaced. `quarantined_slots()` and
`arena_report().quarantined_slots` expose only aggregate public telemetry so an
application can reject service or terminate under its own policy. They do not
expose mapping addresses, canary values, or secret bytes.

Fixed pool generations make slot reuse visible and are mixed into deterministic
pooled canaries. They do not prevent a privileged attacker from modifying
metadata, are not unforgeable tokens, and eventually wrap. The safe stale-handle
defense is the lifetime-bound non-clone slot handle plus the atomic allocation
bitmap.

Operational controls for abort paths, destructor bypass, privileged attackers,
WASM, swap/hibernation, and canary response are separated by responsibility in
`docs/DEPLOYMENT_HARDENING.md`. Those controls do not expand the library's
claims against a compromised kernel or process.

`arena_report()` helps operators compare payload capacity with reserved,
mapped, and locked bytes. It does not read `RLIMIT_MEMLOCK`, Windows working-set
policy, or future system pressure, and therefore cannot guarantee that another
allocation will succeed.

`ConsumeOnceSecret<T>` protects against accidental repeated access through the
same wrapper, including racing consumers. It uses scoped shared exposure and
clears after return or unwind. It does not defend against a malicious winning
closure, copies made before construction, process abort, or residual compiler
and register copies.

## macOS mapping inheritance

On macOS, an established `ForkPolicy::Exclude` uses `VM_INHERIT_NONE` to omit
the protected writable region from an ordinary fork child. This is distinct
from copying and then clearing child bytes. It does not establish per-mapping
core-dump exclusion: that report remains `Unsupported`. Applications requiring
ordinary process core suppression must establish and verify their own process
policy before creating private material. No privileged acquisition, suspend,
hibernation, or kernel-compromise protection is claimed by these controls.
