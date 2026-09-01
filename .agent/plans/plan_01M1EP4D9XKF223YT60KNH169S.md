# Unify validated Rust abstractions

Consumer: the implementation and verification of DU-001 through DU-014 and the
follow-up transfer review repairs requested in this session. The named feature surfaces are the canonical public-policy
catalog, authenticated local-state documents, witness-v1 mapping boundary,
protocol artifact parsing, CLI mutation-error mapping, and owned-process
observation, canonical byte encoders and enum tags, protected-memory allocation,
mutation-plan assembly and completion, filesystem snapshots, canonical JSON, and
local-state scope traversal, portable catalog authentication, transfer installation
recovery, and bounded public export. The observed defect classes are divergent
validation invariants, repeated persistence/authentication mechanics, scattered
version-bound mappings, duplicate adapters, split durable commit points, and trust
boundaries hidden behind overly broad shared types. Remove this plan from active
work by closing it after all clusters and review repairs are implemented, committed
as independent slices, repository gates pass, and the diff is reviewed. No runtime
code may depend on this plan.

## Progress

- [x] Validate the six duplicate-abstraction clusters against callers and boundaries.
- [x] DU-001: select one catalog type and preserve persisted-input compatibility.
- [x] DU-002: extract private authenticated-document helpers without changing bytes.
- [x] DU-003: centralize exhaustive core/witness-v1 conversions without merging types.
- [x] DU-004: centralize conflict-marker detection.
- [x] DU-005: delegate transfer mutation errors to the shared mapping.
- [x] DU-006: use one unreaped-child observation enum.
- [x] DU-007: give canonical wire enum tags one protocol owner.
- [x] DU-008: centralize crate-private canonical byte-encoding primitives.
- [x] DU-009: centralize protected-memory size dispatch.
- [x] DU-010: share the validated core item-batch assembly tail.
- [x] DU-011: share CLI mutation-plan completion.
- [x] DU-012: use one filesystem regular-file snapshot type.
- [x] DU-013: centralize canonical JSON mechanics without merging formats.
- [x] DU-014: share vault-scope state-root traversal and bounded file mechanics.
- [x] Run formatting, targeted tests, Clippy, repository tests, and review the diff.
- [x] Resolve transfer-review open questions from the J16 contract and source invariants.
- [x] Commit the previously staged J16 transfer baseline independently.
- [ ] Commit DU-001 through DU-014 as one behavior-preserving refactor slice.
- [ ] Bind portable role metadata to policy-authenticated registration proofs.
- [ ] Make first-install import deterministic, recoverable, and shared-artifact-last.
- [ ] Separate bounded public export from protected-memory publication and contain destinations.
- [ ] Make post-publication receipt failure explicit, remove repeated parsing, and correct diagnostics/display/docs.
- [ ] Run the full repository gates, review the commit series, close J16, and finish this plan.

## Surprises & Discoveries

- The local policy catalog accepts unique entries in any order, while the transfer
  catalog requires strict ordering. Current writers sort entries, but persisted
  input is a compatibility boundary and cannot simply become invalid.
- The existing worktree contains the completed, uncommitted J16 transfer slice;
  DU-001 intentionally builds on those files rather than treating them as unrelated.
- `TransferPublicCatalogV1` already has a public constructor and fields, so using it
  directly in the CLI preserves that API better than moving it behind a new wrapper.
- Jig's aggregate `verify` evidence is fresh and all five configured targets passed
  for the current worktree. Plan completion remains blocked because individual gate
  applicability is `unknown` while the pre-existing staged J16 versions differ from
  both the plan baseline and this task's unstaged versions. Resolving that requires
  changing the user's index state.

## Decision Log

- Use the existing public `jury-core` transfer catalog as the canonical type so its
  constructor, fields, error type, and module path remain unchanged.
- Normalize legacy unordered catalog input at the local persistence boundary, while
  keeping the signed transfer format strict and canonical.
- Keep versioned protocol enums distinct from non-versioned domain enums; centralize
  conversion and parity checks instead of merging nominal types.
- Keep local checkpoint and receipt formats distinct; share only private mechanics.
- Keep canonical codec helpers crate-private. The protocol exposes only canonical
  enum tags because `jury-core` consumes those exact wire enum values.
- Keep pretty-newline protocol JSON and compact core JSON as separate helpers;
  sharing their implementation would erase a persisted-format distinction.
- Preserve J16's explicit refusal of direct-slot introductions during existing-home
  import. Correct public wording and diagnostics rather than adding an override.
- Treat the signed policy journal, not the exporter, as registration authority.
  Portable catalogs must carry the exact registration proofs whose digests appear
  in authenticated principal-add or replacement operations; the local cache remains
  a compatibility boundary and is no longer the portable trust representation.
- Treat 32 MiB as the transfer format and public-I/O bound. Encrypted public output
  must use a bounded public writer and must not consume secret-memory capacity.
- Treat the shared vault publication as the first-install commit point. Publish a
  deterministic, retry-compatible local installation first and reconcile exact
  partial local files; once the shared artifact exists, report local follow-up
  failures as committed recovery states rather than ordinary failures.

## Outcomes & Retrospective

DU-001 through DU-014 are consolidated without merging the intentional wire/domain,
local-document schema, JSON-format, filesystem-capability, or process-safety
boundaries. Focused crate tests, exact frozen-vector tests, formatting, Clippy,
workspace tests, the repository contract, and the aggregate `verify` profile all
pass. The follow-up duplicate scan finds the former parallel owners removed; the
remaining highest-scored similarities are thin format-specific adapters over the
shared mechanics. The plan cannot be closed in Jig while required-gate applicability
is unknown for the user's pre-existing partially staged J16 files. No staging or
unstaging was performed, so that index state remains preserved.

## Context and orientation

The root workspace has eight Rust packages. `jury-core` owns domain and local-state
invariants, `jury-protocol` owns versioned wire formats, `jury` owns CLI adaptation,
and `jury-process` owns process containment. Persisted JSON and J19-bound canonical
encodings must remain byte-identical unless an explicit compatibility path is used.

## Plan of work

Implement DU-001 through DU-014 sequentially. For each cluster, add or strengthen
the narrow regression test first, make the smallest consolidation, and run the
affected crate tests before proceeding to the next cluster.

## Concrete steps

1. Reuse the `jury-core` transfer catalog representation in the CLI, add local-input
   normalization, retain the public transfer type path, and migrate CLI mutation methods.
2. Extract private canonical-JSON and HMAC helpers used by checkpoints and receipts.
3. Add a private bridge for witness operation, approval mode, and platform assurance.
4. Move conflict-marker detection to one crate-private protocol helper.
5. Remove repeated transfer-import mutation-error branches.
6. Remove the process-layer observation enum and reuse the Unix observation type.
7. Reuse protocol-owned wire enum tags and centralize private canonical byte codecs.
8. Move automatic compact/large protected-memory dispatch to `jury-protected`.
9. Extract the shared core item-batch assembly tail and CLI plan-completion tail.
10. Share the filesystem regular-file snapshot and vault-scope traversal helpers.
11. Extract private canonical JSON helpers for the existing pretty and compact formats.
12. Run `scripts/jig check fmt`, affected crate tests, `scripts/jig check clippy`,
   `scripts/jig check test`, and `scripts/jig work check`.

## Validation and acceptance

Success means persisted catalog compatibility is tested, serialized and authenticated
bytes remain unchanged, witness-v1 mappings are exhaustively checked, each duplicate
implementation named above is removed, protected-memory boundary behavior remains
unchanged, filesystem capability distinctions remain intact, and all configured
backend gates pass.

## Idempotence and recovery

All source edits are ordinary Git worktree changes. If a step fails, retain the
preceding passing cluster, fix the failing cluster in place, and rerun its targeted
tests. Do not regenerate conformance vectors or weaken assertions.

## Interfaces and dependencies

No dependency changes are expected. Public compatibility is preserved through the
existing `jury_core::transfer::TransferPublicCatalogV1` name. No Jig artifact is a
runtime dependency.
