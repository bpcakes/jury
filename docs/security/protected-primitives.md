# Protected primitives

Jury is a pre-alpha scaffold. These controls do not establish that Jury
protects secrets, and Jury must not be used with real secrets. The work was
implemented and re-run in a solo session; it has not received independent
security review.

## Protected memory provider

`jury-protected` pins the authorized `featherenvy/sanitization` fork at immutable
Git revision `3f0a72c5640b4919dec93799725c7573b2878a8c` (package 2.0.4),
with MIT OR Apache-2.0 licensing. The fork is based on upstream v2.0.4 commit
`0f95eec55aa16562be9dc3a08ee60a043d7a0da8`. Since the J02 v2.0.3 audit
(`ffcb211cd931c6966b2e767ce5edffa4b47c4f07`, package checksum
`75e43f2762b31232062e8ba7bfbdfcbd33c80c43bf7a306a7e195c3c4f734e0f`),
upstream prevents established preferred controls from degrading during
replacement. M01 adds Darwin mapping inheritance exclusion and a final guarded
wipe after live canaries are reset. The patch and its native tests are in the
provider; Jury does not contain native FFI. These are solo source review and
behavior tests, not independent review.

Jury disables default features and enables only `std`, `profile-guarded-native`,
and `require-fork-exclusion`. The workspace Rust floor is 1.90. Third-party
license and attribution details are in [NOTICE.md](../../NOTICE.md).

The reviewed safe `BoundedGuardedSecretVec` API supplies a dedicated mapping,
inaccessible surrounding guard pages, required random canaries, page locking,
dump exclusion, fork exclusion, in-place initialization, checked access,
zeroization before unmap, rollback reporting, and a permanent application
maximum. Unsafe native operations stay inside the pinned dependency; Jury
retains `unsafe_code = "forbid"`.

For this exact provider pin, accounting reports the page-rounded locked writable
region separately from the complete mapping. Strict status requires a nonzero
page granule, locked bytes covering the requested bytes and divisible by that
granule, and mapped bytes covering the locked region. Native boundary tests
check the real accounting on both 4 KiB and 16 KiB page hosts. A provider update
must preserve these meanings or explicitly revise their integration.

Jury wraps the provider with a 1 MiB hard maximum for compact allocations and a
separate explicit 16 MiB maximum for authenticated large value buckets. Callers
select the logical capacity because native mappings are page-rounded. Provider
handles, raw pointers, guards, and errors are private. Secret bytes are exposed
only during checked callbacks and are never returned as owned vectors, strings,
Serde values, or public provider guards.

The historical J02 provider audit ran all 196 upstream feature-combination tests and all 150
tests for Jury's selected feature set. A Rust 1.90 probe constructed a strict
guarded owner and established lock, dump, fork, guard, and canary controls. This
is dependency evidence and solo verification, not independent review.

## Strict and emergency policy

`ProtectionPolicy::Strict` requires a dedicated mapping, page locking, fork
exclusion, guard pages, and canaries before the caller initializer runs. Linux
also requires established per-mapping dump exclusion. On macOS, strict
construction first sets both process `RLIMIT_CORE` limits to zero and verifies
an immediate `(0, 0)` readback before entering the provider constructor. All
compact, large, supported-capacity, and random constructors share this check.
The macOS provider requests per-mapping dump exclusion as preferred and reports
it truthfully as `Unsupported`. Only this state paired with verified process
suppression satisfies Darwin's ordinary-core requirement; `Failed`,
`NotRequested`, and `CompatibilityOnly` do not. The mandatory mapping, lock,
fork, guard, and canary controls must still be established.
Construction fails without an ordinary heap fallback.

`ProtectionPolicy::EmergencyAllowDegraded` keeps the dedicated guarded mapping
and canary mandatory but permits lock, dump-exclusion, or fork-exclusion
failure only as a stable `ProtectionStatus`. The status is serializable and the
TUI renders the same `PROTECTION DEGRADED` fact. This is the only degraded
override; callers cannot silently opt into pageable compact secrets.

The pinned provider's `ForkProtectionReport.policy` records the requested fork
behavior; its separate `state` records establishment. Preferred exclusion
failure therefore remains `Exclude` with a failed or unsupported state, and
Emergency retains the owner with that degraded state. Jury checks that the
provider retained its requested policy in both modes; this check does not
require successful exclusion in Emergency. The provider's
`native_preferred_control_failures_remain_visible_after_fill` test exercises
the failed preferred-control path.

On Unix, capture first sets both `RLIMIT_CORE` limits to zero through the safe
`rlimit` API and immediately reads back both limits. A failed set/read or a
nonzero limit blocks the callback. Every Unix allocation records its observed
`(0, 0)` state, including emergency allocations. Linux standalone strict memory
construction retains its per-mapping contract; strict capture additionally
requires process suppression. Lowering the hard limit is
process-wide and intentionally irreversible for the rest of that process.
Strict capture also refuses a degraded memory report before invoking the
private callback.

## Platform status

The first `0.x` release supports Linux only. The macOS and Windows rows preserve
development/audit observations for deferred platform work; they are not active
support, packaging, CI, or release claims.

| Platform | Current J02 statement |
| --- | --- |
| Linux x86-64 | Runtime-tested locally: guarded mapping, page rounding, lock, `MADV_DONTDUMP`, fork exclusion, canary checks, in-place entropy, and `RLIMIT_CORE=0`. Capability traversal, links, identity replacement, modes, file/parent sync, and publication were also runtime-tested. |
| macOS | M01 provider uses `minherit(..., VM_INHERIT_NONE)` on the complete writable region before fill. Strict Jury allocation verifies process core suppression first. Per-mapping dump exclusion remains `Unsupported`. Native validation is tracked by M01; full native CLI support remains separate work. |
| Windows | The protected-memory provider has a maintained native backend. J02 private filesystem publication deliberately reports unsupported because owner-only ACL and reparse guarantees have not yet been runtime-proven here. |
| Other targets | No guarantee is made. Unsupported controls return typed failure rather than a pageable compact-secret fallback. |

## Explicit nonclaims

The controls do not prevent observation through privileged process access,
kernel compromise, DMA, hibernation or suspend images, hypervisor snapshots,
CPU registers, compiler-created temporary copies, side channels, or an
already-compromised process. `MADV_DONTDUMP` and verified soft/hard `RLIMIT_CORE=(0, 0)` concern
ordinary supported dump paths, not every forensic acquisition mechanism.
Canaries detect some boundary corruption; they are not authentication.
Zeroization cannot prove the absence of every historical copy outside the
owned mapping.

Redaction is a bounded output safety net, not an authorization boundary or a
proof that every encoding is covered. Short values below four bytes are not
registered because matching them would destroy ordinary output. Streaming
state is independent per logical stream, so a value split between stdout and
stderr is intentionally not matched across streams.

OS randomness comes only from pinned `getrandom` 0.4.3. The public trait fills
caller-owned storage and reports one value-free error. When it fills protected
memory, allocation happens first and a partial entropy failure causes provider
cleanup; no owner or partial bytes are returned.

Filesystem authority uses `cap-std` and `cap-fs-ext` 4.0.3, with crates.io
checksums `c1ec78e242cfa2cfe276807ac2ecc00315a6c97786977414bcd1c3963b6c91b8`
and `56ff379b70af8e08307a8f65e7040c7301cb4a572538ade16b4984f0da77847f`.
Their packaged sources matched Bytecode Alliance revision
`b7acf8e8807fe3fab991884d2208b7e03d35a409` and tag `v4.0.3` during the J02
audit. Jury retains opened directory and file capabilities and uses no-follow
operations; canonical or normalized strings are discovery input, not retained
filesystem authority.
