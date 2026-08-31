# Protected primitives

Jury is a pre-alpha scaffold. These controls do not establish that Jury
protects secrets, and Jury must not be used with real secrets. The work was
implemented and re-run in a solo session; it has not received independent
security review.

## Protected memory provider

`jury-protected` pins `sanitization` 2.0.3 with crates.io checksum
`75e43f2762b31232062e8ba7bfbdfcbd33c80c43bf7a306a7e195c3c4f734e0f`.
The packaged source matched upstream revision
`ffcb211cd931c6966b2e767ce5edffa4b47c4f07` and tag `v2.0.3` during the J02
audit. Its license is MIT OR Apache-2.0. Jury disables default features and
enables only `std`, `profile-guarded-native`, and
`require-fork-exclusion`. The workspace Rust floor is 1.90.

The reviewed safe `BoundedGuardedSecretVec` API supplies a dedicated mapping,
inaccessible surrounding guard pages, required random canaries, page locking,
dump exclusion, fork exclusion, in-place initialization, checked access,
zeroization before unmap, rollback reporting, and a permanent application
maximum. Unsafe native operations stay inside the pinned dependency; Jury
retains `unsafe_code = "forbid"`.

Jury wraps the provider with a 1 MiB hard maximum for compact allocations and a
separate explicit 8 MiB maximum for authenticated large value buckets. Callers
select the logical capacity because native mappings are page-rounded. Provider
handles, raw pointers, guards, and errors are private. Secret bytes are exposed
only during checked callbacks and are never returned as owned vectors, strings,
Serde values, or public provider guards.

The provider audit ran all 196 upstream feature-combination tests and all 150
tests for Jury's selected feature set. A Rust 1.90 probe constructed a strict
guarded owner and established lock, dump, fork, guard, and canary controls. This
is dependency evidence and solo verification, not independent review.

## Strict and emergency policy

`ProtectionPolicy::Strict` requires mapping, page locking, dump exclusion,
fork exclusion, guard pages, and canaries before initialization returns.
Construction fails without an ordinary heap fallback.

`ProtectionPolicy::EmergencyAllowDegraded` keeps the dedicated guarded mapping
and canary mandatory but permits lock, dump-exclusion, or fork-exclusion
failure only as a stable `ProtectionStatus`. The status is serializable and the
TUI renders the same `PROTECTION DEGRADED` fact. This is the only degraded
override; callers cannot silently opt into pageable compact secrets.

On Unix, capture first sets both `RLIMIT_CORE` limits to zero through the safe
`rlimit` API. Failure blocks the callback. Lowering the hard limit is
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
| macOS | Provider and capability code compile behind maintained upstream support. Verified fixed aliases `/var`, `/tmp`, and `/etc` are normalized before no-follow walking. Runtime tests were not available in this Linux session. |
| Windows | The protected-memory provider has a maintained native backend. J02 private filesystem publication deliberately reports unsupported because owner-only ACL and reparse guarantees have not yet been runtime-proven here. |
| Other targets | No guarantee is made. Unsupported controls return typed failure rather than a pageable compact-secret fallback. |

## Explicit nonclaims

The controls do not prevent observation through privileged process access,
kernel compromise, DMA, hibernation or suspend images, hypervisor snapshots,
CPU registers, compiler-created temporary copies, side channels, or an
already-compromised process. `MADV_DONTDUMP` and `RLIMIT_CORE=0` concern
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
