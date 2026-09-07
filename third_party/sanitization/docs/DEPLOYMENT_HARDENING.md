# Deployment Hardening

This guide separates controls enforced by `sanitization` from controls that
must be established by an application, operating system, or hardware platform.
It is a deployment checklist, not an expansion of the crate's threat model.

## Responsibility Matrix

| Property | Responsibility | Scope |
| --- | --- | --- |
| Volatile clearing of the current owned allocation | Library-enforced | Subject to the documented compiler and target limits |
| Clear-on-drop during normal return and unwinding | Library and Rust runtime | Destructors must run and sanitizers must honor their contracts |
| Checked mapped initialization and integrity errors | Library-enforced | Ordinary checked APIs preserve allocation, RNG, generator, length, and integrity failures |
| Canary pre/post checks and corruption quarantine | Library-enforced | Detects canary damage, not arbitrary payload modification |
| Memory locking, dump exclusion, fork policy, guard pages | OS-dependent | Required controls fail construction; actual outcomes are recorded in `ProtectionReport` |
| Private storage allow-lists and lifecycle-source bans | Caller-enforced with supplied CI lints | The application chooses sensitive roots and controls exemptions |
| Core-dump, swap, hibernation, debugger, and crash-upload policy | Deployment-enforced | Outside a library's authority |
| Root-key isolation in an HSM, TPM, enclave, or service | Deployment architecture | Recommended when privileged or physical attackers are in scope |
| Cleanup after `SIGKILL`, aborting OOM, process abort, or deliberate leaks | Not enforceable after the event | Prevent or contain these paths before they occur |
| Protection from a compromised kernel, hypervisor, firmware, or DMA path | Not provided | Keep root secrets outside ordinary process memory |

## Abort And Destructor Bypass

`Drop` cannot run after `SIGKILL`, an aborting OOM, `panic = "abort"`,
`process::abort`, or a deliberately leaked owner. Applications that require
cleanup during recoverable panics should select `panic = "unwind"` in their
final binary profile and verify that this is compatible with their runtime.
Dependency crates cannot select that policy for the final application.

For fatal paths the application controls, aggregate critical owners into a
small secret root, sanitize that root, and then call `sanitize_then_abort`.
This helps only before the process has irreversibly entered an abort path. Do
not attempt to traverse and wipe arbitrary Rust objects from a signal handler;
that is not generally async-signal-safe.

For closed high-assurance modules, run:

```sh
python3 scripts/lint-storage-policies.py \
  --root crates/application/src/high_assurance \
  --policy-file crates/application/src/approved_storage.rs \
  --allow-marker-file crates/application/src/approved_storage_types.rs
```

The gate rejects `mem::forget`, `Box::leak`, and `ManuallyDrop` in designated
sensitive roots in addition to enforcing private storage policies. It is a
conservative lexical review gate, so applications must control exemptions,
generated source, and the exact roots passed to it. Short-lived isolated worker
processes provide an additional containment boundary for key operations.

## Privileged And Physical Attackers

The crate does not claim to defeat an already-compromised kernel or
hypervisor. When privileged, DMA, debugger, or physical threats are in scope:

- keep root keys in an HSM, TPM, enclave, or dedicated cryptographic service;
- retain only short-lived working keys in application memory;
- enable IOMMU and secure or measured boot where the platform supports them;
- restrict `ptrace`, process inspection, and administrative dump access;
- disable core dumps and unapproved crash uploaders;
- disable swap and hibernation, or apply an approved encryption policy; and
- use least privilege and process isolation.

Memory locking reduces swap or pagefile exposure only after the OS accepts the
request. It does not make RAM unreadable to privileged software or prevent all
hibernation, snapshot, firmware, or crash-dump paths.

## WASM

Treat WASM clearing as best effort. WASM linear memory exposes no native
`mlock`, `mprotect`, dump-exclusion, or guard-page control to the module, and
the WASM specification has no volatile store. Do not keep high-value,
long-lived secrets in a browser or general-purpose WASM runtime.

The `wasm-compat` feature names this reduced-guarantee backend explicitly.
Native hardened profiles reject WASM at compile time. A high-assurance
deployment should require a native container and validate its retained
`ProtectionReport`; API compatibility on WASM is not an achieved native
protection state.

## Canary Policy

Canaries detect accidental adjacent corruption and some blind overwrites. They
do not authenticate the payload against arbitrary process-memory writes.
Enable `random-canary` or `strict-canary-check` when deterministic canaries are
not acceptable. The expected randomized value is held in owner metadata,
outside the mapped payload region.

Checked exposure verifies canaries before access and again after the closure
returns normally. A mismatch clears the mapping. Standalone mapped owners are
then permanently poisoned; pool slots are permanently quarantined. Applications
should treat the typed integrity error as a security event and may terminate
under their own policy without logging secret bytes, addresses, or canary
values.

A MAC does not solve arbitrary in-process compromise when its authentication
key is available in the same compromised process. Use hardware or process
isolation when that attacker is in scope.

## Initialization And Cleanup

Prefer generation directly into final locked storage through `from_fill`,
`try_from_fill`, or `try_init_with`. Keep unavoidable cryptographic scratch
buffers under clear-on-drop ownership, avoid `Clone`, `to_vec`, and formatting,
and keep exposure closures short.

For dynamic decoders, use
`LockedSecretVec::try_from_capacity_bounded_with_protection` or
`GuardedSecretVec::try_from_capacity_bounded_with_protection` whenever the
capacity is influenced by untrusted input. Do not decode first and inspect
`ProtectionReport` afterward when plaintext must never exist under degraded
controls. Mark those controls `Required`; a preferred control is explicit
permission for degraded construction. Protected string wrappers provide the
same fill ordering and reject invalid UTF-8 after clearing it.

The unbounded variants are for trusted, already-limited capacities. A large
anonymous mapping may succeed under virtual-memory overcommit and become
expensive only when tail clearing or `Drop` touches its pages; fallible mapping
alone is therefore not an application-level resource bound.

Those methods bound construction, not the lifetime of the returned growable
container. Use `BoundedLockedSecretVec<MAX>`,
`BoundedGuardedSecretVec<MAX>`, or their `String` counterparts when production
policy requires a permanent maximum. The wrappers do not expose the underlying
growable owner and preflight all safe append and replacement paths before
allocation or generator invocation. `MAX` is a reviewed application policy;
choosing an excessive constant still permits excessive resource consumption.

The repository's `lint-fail-closed-initialization.py` gate rejects `try_*`
results discarded through `drop(...)`, `.ok()`, or unhandled underscore
bindings, plus lossy pool `allocate()` calls in production source. Run it over
every application root that initializes hardened storage. Pool exhaustion,
allocation/RNG failure, length mismatch, generator failure, and integrity
failure remain distinct outcomes.

This remains a dependency-free lexical gate. Aliases, re-exports, macros,
generated code, and later data flow from an ordinary named binding require
human review or an application-selected AST-aware lint.

Page-sealed storage provides `try_close()` for observable cleanup. It processes
pages independently, immediately erasing and resealing each page that becomes
writable. If any page transition fails, the value remains poisoned, access is
rejected, and no unlock or unmap is attempted. The caller may retry cleanup or
terminate according to policy. `Drop` follows the same retention policy but
cannot report failure because Rust destructors cannot return errors.
