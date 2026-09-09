# Make the Jury command hierarchy and onboarding predictable

This living ExecPlan follows `.agent/PLANS.md`. The consumer is the Jury CLI maintainer reviewing the four requested UX fixes. It gates identity setup guidance, item/field discovery, request workflow discoverability, and consistent item/output arguments. The observed defects are generic missing-identity errors, missing item/field entrypoints, misleading detached-request sequencing, and inconsistent selectors. Delete this temporary work plan after the change is merged and its required verification is retained in the existing Jig receipts; no additional report is needed.

## Purpose

A new user can follow a missing-identity error to set up the selected identity, list accessible items with `jury item list`, manage fields with `jury field`, and learn the real foreground approval workflow from help. Policy and privacy operations accept positional ITEM; witness checkpoint and policy-material use --out. Existing command spellings keep working for scripts.

## Progress

- [x] 2026-09-09: Read the four requested fixes and confirm the current parser, handlers, guides, and clean baseline.
- [x] 2026-09-09: Implement parser, routing, initialization diagnostics, and help changes.
- [x] 2026-09-09: Add parser and native-binary regression coverage for identity guidance, canonical forms, aliases, and discovery before/after witnessed-only conversion; parser and focused onboarding/witnessed catalog tests pass. The existing full direct lifecycle also exercises field mutations and revocation.
- [x] 2026-09-09: Update README, witness walkthrough, owner guide, and self-hosting export examples.
- [x] 2026-09-09: Focused tests, final workspace tests, formatting, Clippy, contract and file-budget verification passed. Evidence and gates matched the current inputs. Reviewed the diff, closed jury-enf, flushed the tracker, and finished the Jig work session.

## Surprises & Discoveries

The CLI root file is already 785 lines, near its 800-line policy maximum. Move its field argument definitions into a sibling module while giving fields a top-level entrypoint. Missing identity-root and missing selected-file failures currently both flow through a generic filesystem error. A detached request discards its protected session key by design; it must remain non-executable. The existing additional CLI test file exceeded 800 lines, so its request-artifact helpers moved intact into a sibling file as they gained canonical preview/output coverage. A pre-existing invalid /tmp/.git marker interfered with initial new fixtures; creating real Git repositories inside the disposable fixtures isolates their home selection. Explicit identity fixtures must also use a sibling directory outside the repository, as required by the existing containment rules.

## Decision Log

2026-09-09: Preserve old CLI spellings, JSON operation labels, access restrictions, and cryptographic/session behavior. These are public scripting and security boundaries. Make `jury request preview` the visible name for detached inspection artifacts; retain `request create` as a hidden compatibility alias and hide `request execute` from the ordinary command list with explicit help pointing to `jury read`. New `jury item list` uses the existing directly accessible catalog and reports operation item-list. New `jury field` reuses the existing field handlers; nested vault field remains accepted. Policy and privacy prefer positional ITEM with a hidden --item compatibility alternative; supplying both is an error. Witness checkpoint and policy-material both prefer --out with --output as a compatibility alias. Initialization errors retain the existing not-found JSON code and exit status, remain value-free, and distinguish missing roots, named identities, and explicit-file selection through actionable message text.

## Outcomes & Retrospective

All four UX changes and maintained guides are implemented. Parser/help, onboarding, direct lifecycle, and witnessed-policy/catalog regressions passed, followed by the full five-target verify profile. Final compatibility review retained the existing not-found JSON error code while preserving the identity-specific diagnostic text; the final `scripts/jig check test --plan-id plan_01M23JBJPQKPM24A3TSAWPSV1J` workspace run passed. All remaining verification targets passed against current inputs, and the tracker issue and Jig work session are closed. No required work remains. No commit or push was made. Clippy found three expect_err calls in new tests during development; fallible error extraction fixed them without changing assertions.

## Context and Orientation

`crates/jury/src/cli.rs` defines the clap parser; its `cli/dispatch.rs` routes to handlers. `cli/vault_commands.rs` loads the owner identity before initializing a vault. `cli/access_commands.rs::access_list` already filters the discoverable item catalog to direct access. `cli/item_commands.rs` owns field handlers and forwards governed reads to `request_execute`. `cli/witness_args.rs` declares request and checkpoint arguments; `cli/policy_args.rs` declares policy/privacy arguments. `cli/tests.rs` contains parser/help tests and `crates/jury/tests/native_cli` exercises actual binaries with synthetic identities and vaults. README and the witness/owner guides teach the current commands.

## Plan of Work

First implement the parser and diagnostics together. Introduce a shared positional-or-legacy item selector for policy and privacy, enforce exactly one spelling through clap and the accessor, and update handlers to resolve it before credential capture. Extract field arguments to stay inside the root source-file budget. Route top-level field commands through the existing mutation/read rules. Extract the existing accessible-item listing into a shared handler used by item list and access list --me, preserving all disclosure restrictions and existing JSON labels.

Then rename detached request creation in help to preview, retain legacy parsing, and direct normal request help and guided examples to foreground read/inject/exec/run. Preserve fresh-session creation, expiry, approval, cancellation, and retry behavior. Normalize checkpoint and policy-material output spelling without changing publication.

Add real binary regressions for missing roots/files (default, named, environment, explicit file), errors other than absence, successful canonical item/field operations, and non-disclosure after access revocation or witnessed-only conversion. Exercise positional policy operations and old aliases, checking ambiguity rejection before mutation. Reuse established synthetic lifecycle tests where appropriate. Update maintained guides and add a compact command reference explaining canonical forms and compatibility.

## Concrete Steps

Work from `/home/aa/Documents/jury`. Use `cargo test --locked -p jury --lib cli::` for parser tests and filtered `cargo test --locked -p jury --test native_cli NAME` for focused binary regressions. Run `cargo fmt --all` after edits. Use `scripts/jig work check --plan-id plan_01M23JBJPQKPM24A3TSAWPSV1J` to run the verify profile (fmt, Clippy, workspace tests, contract, file budget), then inspect `scripts/jig work evidence` and `scripts/jig work gates` for that plan. Finish backend verification with `scripts/jig check test --plan-id plan_01M23JBJPQKPM24A3TSAWPSV1J` when it has not already been recorded as the final relevant backend verification; reuse valid gate receipts rather than repeating passing tests without cause. Inspect actual --help output and `git diff --check` and close the work with `scripts/jig work finish` after all requirements pass.

## Validation and Acceptance

Both init spellings must fail with an identity-specific, value-free setup instruction when the selected identity is absent; a user can run identity init with the same selectors and retry successfully. Permission/corruption failures must not become missing-identity guidance. Item list and field list must not reveal unauthorized names, IDs, values, or locked-item counts; tests must include both a discoverable item and an inaccessible or witnessed-only item. New field set/list/remove must affect the actual vault and remain compatible with the nested spellings. Help must make preview non-executable, point users to foreground commands, and keep legacy create/execute usable. Policy/privacy positional selectors and checkpoint --out must perform the same operations as existing flags; absent and conflicting selectors must fail before mutation. Maintained examples must use canonical forms. All configured verification gates must pass. No security-review or real-secret protection claim is added.

## Idempotence and Recovery

The change does not migrate persisted vaults, identities, policy artifacts, or request sessions. Tests create disposable state with synthetic inputs. Existing command and JSON contracts remain accepted. A failed verification is investigated and rerun only after a relevant fix. Do not alter gate policy or fixtures merely to make validation pass. Do not commit or push unless asked.

## Interfaces and Dependencies

Use existing clap and domain APIs; no new dependency or cryptographic code is needed. Alias routing must reach the same field/access/request handlers. A shared parsed item selector provides one validated item string to policy/privacy handlers; it cannot silently prefer one spelling over another. Preserve existing protected identity reads and map only filesystem NotFound at the identity-loading boundary to setup guidance.

2026-09-09 update: Recorded the implemented interfaces, the second witness output flag, test isolation findings, focused passes, and the remaining full verification.

2026-09-09 compatibility review: Preserve the existing not-found machine code for initialization failures; only the explanatory message changes. The full verify profile passed before this final compatibility adjustment, and final checks are running.

2026-09-09 validation update: Final workspace tests passed after the error-code compatibility adjustment. The full direct native lifecycle passed with canonical field mutations and item listing before/after revocation; the witnessed catalog journey passed with both a visible and a governed item. Manual help inspection confirmed canonical argument usage and hidden request compatibility routes.

2026-09-09 completion: `scripts/jig work evidence` and `scripts/jig work gates` reported fresh passing verification; `scripts/jig work finish` closed the plan and session after tracker closure.
