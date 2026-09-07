# CP-23 Release Preparation

CP-23 originally started from the then-accepted CP-22 implementation state:

```text
b41c1cb8e0622eb8637261a1b62b47ba66a03183
```

The checkpoint may change only:

- workspace and internal dependency versions;
- crates.io-facing README and companion-crate documentation;
- changelog and 2.0 release notes;
- release evidence records and target-tier wording;
- package archive validation; and
- publication tooling and checkpoint state.

That restriction was explicitly reopened when later security findings and
approved 2.0 API corrections required source changes. Those changes must not be
represented as covered by the original CP-22 review. Public API changes require
refreshed semantic snapshots; behavioral macro restrictions require dedicated
compile-failure evidence.

The freeze was most recently reopened to prevent mapped constructors from
suppressing CSPRNG or canary failures, make dynamic secret generation report
capacity and allocation failure, verify canaries after normal mapped exposure,
and permanently poison corrupted standalone mapped owners. The refreshed
candidate also verifies pool-slot integrity during destruction, clears
crate-owned random-canary metadata, routes the native CT and crypto verification
surfaces through strict assembly equality, adds path-specific codegen evidence,
and retains fail-closed lifecycle and initialization source gates plus an
explicit deployment responsibility matrix. The final remediation also adds a
typed `MaybeUninit<T>` wipe path and routes ArrayVec spare-capacity cleanup
through it, eliminating references to uninitialized byte values. It also
raises the `sanitization-bytes` dependency floor to patched `bytes 1.11.1` and
enforces that published requirement in the companion-boundary gate. Final
derive hardening requires `SecureSanitizeOnDrop` and `secure_drop_struct!`
owners to implement `DropSafeSanitize + Unpin`. Their destructors call the
complete sanitizer, preserving aggregate cleanup while requiring manual
sanitizers to explicitly attest non-recursive destructor safety. The runtime
also exact-pins the derive crate to the same version, and release preflight
enforces that generated/runtime API lockstep. It
therefore requires another full-range review before a permanent report can be
accepted.

The final CP-23 candidate is the exact commit immediately preceding the
permanent pentest report. After all implementation, remediation, documentation,
and merge work is complete, review that candidate again. Then commit
`security/pentest/v2.0.0.md` alone with that exact parent as `Reviewed-Commit`.
Any later change invalidates the report and requires another close-out review.
