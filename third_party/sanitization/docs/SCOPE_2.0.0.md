# Sanitization 2.0 Scope Freeze

This document records the CP-22 disposition of every optional additive area in
the 2.0 roadmap. It prevents an experimental idea from becoming an implied
stable guarantee merely because related implementation work exists.

## Included In The Freeze Candidate

The following additive facilities are included because their assigned
checkpoints implemented the documented contract, tests, and evidence boundary:

| Facility | Stable scope |
| --- | --- |
| `SecretBoxBytes` | Fixed runtime-length allocation with no growth or extraction of the private backing allocation. |
| `ConsumeOnceSecret<T>` | Exactly one scoped shared access for stable shared storage, followed by cleanup. |
| `ProtectionRequest` and `ProtectionReport` | Explicit required/preferred policy separated from achieved runtime outcomes. |
| Checked cache flushing | Structured capability, success, and unsupported/error reporting; no complete cache-secrecy claim. |
| Fixed `SecretPool<N, SLOTS>` evolution | Fixed-size slots, generations, quarantine-on-failure behavior, and public efficiency reporting. |
| `SealedSecretBytes<N>` | Opt-in page-sealed fixed bytes with fallible transitions, poisoning/retirement, and documented target limits. |
| Built-in representation erasure | Private, reviewed implementation set only; no downstream marker contract. |

Inclusion does not upgrade target evidence. `docs/TARGETS.md`,
`docs/EVIDENCE.md`, and `docs/NON_GUARANTEES.md` remain authoritative for each
target and runtime claim. Page sealing remains opt-in and its fallible cleanup
contract must not be described as infallible sanitization.

## Explicitly Deferred

The following concepts are not part of the 2.0 public API or stable claim:

### Public `ZeroValidPlainData`

The internal built-in-only classification remains private. A downstream
implementation could make representation wiping unsound or misleading by
including provenance, ownership, invalid zero representations, padding, or
drop behavior. A future public marker requires a separate unsafe-contract
design and external review.

### Target-Provided Erasure Backends

No public generic callback or backend trait is exposed for DMA, MMIO,
non-coherent caches, persistent memory, or hardware keystores. Those categories
have materially different ordering and persistence contracts. Future support
belongs in target-specific reviewed APIs or companion crates.

### Variable-Size Secure Arenas

2.0 keeps only fixed-size `SecretPool<N, SLOTS>`. Variable-size allocation is
deferred until fragmentation, metadata secrecy, stale-offset behavior, quota
accounting, and wipe-before-reuse invariants have a reviewed design.

### Expanded Platform Hardening

Non-x86 cache maintenance, broader register-state coverage, and native runtime
evidence beyond the minimum target matrix remain future work. Existing APIs
return structured unsupported or limited reports where applicable; no omitted
platform is silently treated as equivalent to a reviewed native backend.

## Freeze Rule

After CP-22 acceptance:

- no new public type, trait, feature, companion crate, or security concept may
  enter 2.0.0;
- finding remediation may change implementation only when the API contract is
  preserved, or the freeze must be explicitly reopened and re-reviewed;
- CP-23 may change coordinated version, release-note, package, and publication
  metadata only; and
- every post-freeze source or feature change must update the semantic API
  snapshot and repeat the close-out review.

The original freeze was later explicitly reopened for finding remediation and
approved 2.0 API corrections. The rules above apply again once the final
candidate is refrozen: refreshed snapshots do not replace the required final
full-range review and immediate-parent pentest report.

Deferred work may target a later 2.x minor or a separately reviewed companion
crate. It is not a hidden release blocker for 2.0.0.
