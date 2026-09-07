# Repair the Linux 0.0.1 QA blockers and repeat real CLI QA


This living ExecPlan follows `.agent/PLANS.md`. Its consumer is the maintainer requesting repairs and repeated Linux QA; it gates the 0.0.1 candidate because actual CLI execution exposed wrong-field selection, inconsistent input sources and terminal value echo. Retire it when the repairs and replacement candidate pass the relevant journeys. It earns no product-capability credit by itself.

## Purpose


Users must be able to reference every valid item/field name consistently, automate all identity-authenticated commands with the documented passphrase sources, and enter field values at a terminal without exposing them on screen. Then repeat the original failing probes, the existing direct/witnessed workflows and exploratory QA until no functional/UX finding remains. Publication prerequisites (public security-reporting channel and signing identity) remain part of release readiness and have been requested from the operator; no private credential is required in the repository.

## Progress


- [x] Revalidated the current tree, open findings and repository guides on 2026-09-06.
- [x] Implement one unambiguous field-reference parser with real CLI regression coverage.
- [x] Unify identity/new-passphrase sources and verify explicit stdin precedence.
- [x] Implement protected terminal field entry, cancellation cleanup and truthful help with real PTY tests.
- [x] Repeat failing and broader host Linux journeys; repair every newly reproduced in-scope finding.
- [x] Update documentation and close QA-14 through QA-17 after successful real regressions.
- [x] First fresh package reproduced both binaries; all nine Debian 12 CLI journeys and packaged HTTPS passed.
- [x] Found and fixed QA-18: the native archive omitted linked self-hosting setup files. Real-source packaging regression passes, including a missing-config negative control.
- [x] Rebuilt the complete package; exact setup files and owned guide links pass, previous package fails the link control, all nine Debian 12 journeys and HTTPS pass. QA-18 closed.
- [x] Found QA-19 on both the old and repaired packages: policy-accepted public labels exceed the native reference profile. Added bounded JSON pairs and real approved witnessed delivery/receipt tests, including the 256-byte boundary and malformed refusal.
- [ ] Build the public-label candidate and repeat ten packaged journeys, HTTPS, J25 checks and all final gates; J26 remains open.
- [ ] Run final repository and security-input checks against settled source, inspect fresh receipts, and finish only with supported conclusions.

## Surprises & Discoveries


The prior QA found that canonical names permit dots, but template references split at the first dot and process references reject additional dots. The reference syntax must change without changing persisted names or cryptographic formats. Temporary signal-hook registrations do not restore default signal handlers when unregistered, so that approach was rejected. The terminal adapter instead uses pinned nix 0.31.3 safe pthread signal masking/signalfd plus existing rustix termios/poll. Field mutation has no worker threads; the PTY regression verifies this constraint. No unsafe code or crypto changes were introduced. Both workspace lockfiles now include nix; the first locked fuzz attempt correctly refused its stale lockfile. The prior audit also exposed that Jig work check runs both legacy checks and the verify profile; avoid separately launching full workspace tests while editing, and do not count repeated runs as independent evidence.

The first input regression used an incorrect guessed error-code string for absent passphrase input; it was corrected to the established `passphrase-input-opt-in-required` contract, retaining the exact exit/error assertion. Approval/descriptor journeys initially timed out because their PTY driver waited for the former `Passphrase:` label. It now waits for the actual `Identity passphrase:` label while preserving the hidden-input, signed-output and scope assertions. Both journeys passed fresh reruns. The original exploratory driver's already documented guessed exit codes were corrected against the CLI error mapping before renewed execution; it now fails the process if any assertion fails.

## Decision Log


Use `ITEM/FIELD` as the canonical combined CLI reference because slash is excluded from both native names. Keep `ITEM.FIELD` for names with exactly one separator dot; reject multi-dot shorthand before a sink/child starts. This preserves existing unambiguous invocations and every stored name. Templates use the same parser inside braces, and env/stdin/anonymous-file bindings use it directly.

Use JURY_IDENTITY_PASSPHRASE for existing identity authentication and JURY_NEW_PASSPHRASE for identity creation or passphrase replacement, preserving hidden prompts and confirmations when environment sources are absent. Explicit --passphrase-stdin remains authoritative for every prompt.

Provide real hidden terminal field input, including without --value-stdin; retain --value-stdin as the explicit opt-in for pipes and accept it at terminals too. EOF completes the exact field bytes (no trimming); show safe input instructions after echo is disabled. Cancellation must restore terminal settings and prevent a vault mutation. Piped binary input keeps its existing exact byte contract. No protocol, vault name profile, authority or cryptographic construction is changed.

## Outcomes & Retrospective


Reference, environment-source, terminal-entry and help repairs are implemented. Real CLI/PTY regressions pass, including colliding names across six child channels, exact long and multiline input, signal cancellation, explicit stdin precedence, and old-passphrase rejection after replacement. The three existing passphrase-input native tests pass; clippy and direct/witnessed input gates pass. HTTPS lifecycle, exploratory CLI QA, scoped leak scan and alternate-provider conformance passed. All eight broader host journeys passed, with fresh approval/descriptor reruns after the documented prompt-driver fix. The four bounded fuzz targets passed: 13,230 / 47,727 / 108,901 / 3,293 executed units and peak RSS 379 / 459 / 482 / 376 MiB; these are smoke budgets, not exhaustive coverage. The first package passed all runtime journeys, but a final owned-guide link check found QA-18. The package now includes deployment configs/units and linked reference material and refuses missing local guide targets. Nine release-helper tests pass. One complete workspace test pass, fmt and clippy passed before this packaging edit; the running second profile pass was cancelled and will be replaced with final checks. The complete-package profile subsequently passed, but a further real old/new package probe exposed pre-existing QA-19. The initial attribution to a new regression was corrected after reading the old parser and running the old binary. The JSON-pair extension and its public-label regression now pass, along with the old input suite and clippy. A replacement public-label package, final repository checks and operator publication choices remain pending; J26 remains open.

## Context and Work


The adapter is `crates/jury`: `cli/template_commands.rs` and `cli/execution_commands/support.rs` parse combined references, `cli/identity_commands.rs` and `cli/vault_commands.rs` authenticate identities, and `secret_input.rs` currently masks passphrase echo. `cli/item_commands.rs::field_set` reads value bytes after that masking ends, through `cli/mutation_commands.rs::read_bounded_standard_input`. Move shared reference parsing into a small CLI module. Add bounded, signal-aware terminal input support and route field capture through it. Keep business/crypto logic in existing owning crates. The nearest instructions are `crates/AGENTS.md`; read more specific guides if edits expand into another crate.

Native Rust integration tests are wired by `crates/jury/tests/native_cli.rs`; use real processes and synthetic state for new regressions. Add a Linux PTY driver under `scripts/` if needed for controlling-terminal lifecycle assertions, and execute it with the actual binaries in CI. No mock, weakened assertion, regenerated golden or success-only fixture may replace a required behavior.

## Validation and Acceptance


Run from `/home/aa/Documents/jury`. First add regressions showing different values in `Example.Group/ExampleField` and `Example/Group.ExampleField`, then prove exact inject, exec env-file, run env, stdin and anonymous-file delivery for both. Plain multi-dot shorthand must leave output/child markers absent. Include existing dot-free shorthand controls and witnessed paths through the same shared parser.

Environment-only vault init, audit verification, public identity/proof operations and identity passphrase changes must work with the documented source; wrong/absent sources fail before state mutation. Retain the existing `native_cli::passphrase_input` exact stdin regression cases. Terminal tests must verify echo disabled, absence of field and passphrase bytes from captured output, exact binary/piped and multiline/terminal values, EOF, Ctrl-C/SIGTERM cleanup and unchanged vault state on cancellation.

Use targeted cargo tests during implementation, followed by `cargo build --locked --release -p jury -p jury-witness` and all eight existing `scripts/check-linux-*` journeys with explicit --jury/--juryd paths, the new terminal/reference regression driver, and the synthetic HTTPS lifecycle. Read driver assertions and inspect real outputs; previous QA reproductions are under `target/qa-linux-0.0.1-do73vlcw/`. Repeat exploratory user journeys after repairs, rather than declaring green from only the new assertions.

Read `docs/linux-release.md` and run `scripts/build-linux-release build --allow-dirty --output ABSENT_PATH` with the vendor archive from the first repaired package after checking its previously verified checksum digest; the provider graph is unchanged by QA-18. The QA-18 rebuild matched both earlier binary hashes. QA-19 changes the parser, so do not require that old jury hash; require the new candidate's two clean builds to match each other. This produces an unsigned local candidate, compares clean offline builds, audits dependencies and packages notices; it does not publish. Exercise the new package on Debian 12 as an unprivileged user. No earlier package binds the repaired code. If further QA changes code, repeat affected validation and rebuild the candidate.

Finish edits and tracked QA notes before `scripts/jig work check --plan-id PLAN_ID`, then inspect `work evidence`, `work gates` and `work finish`. Its configured backend checks include `scripts/jig check test`'s cargo workspace test command. Also run the unchanged direct/witness input gates and relevant J25 checks for the candidate; never alter accepted crypto inputs merely to obtain green results. Append final verification summaries via the authorized work finish record so a report edit does not invalidate the just-completed check.

## Compatibility, Recovery and Limits


Only CLI input syntax and input capture change. Existing stored names, vault/identity files, signed requests, approval scope, checkpoint and recovery formats remain intact. Parsing resolves to the same separate names before request creation; requests/approvals/receipts continue to bind the existing exact item/field IDs and bytes. Rejected/cancelled input must not reach vault mutation or child creation. Terminal settings and the calling thread's prior signal mask are restored on handled exits; original signal handlers are never changed. Normal pipe input is never buffered past its required consumer.

Use fresh synthetic directories for every journey and remove only owned fixtures. Preserve the existing uncommitted work. Do not commit or publish without user authorization. The desired result is repaired capability with repeatable QA, not an independent security certification or a claim that Jury protects real secrets. Missing operator publication choices must remain explicit and must not be silently treated as resolved.
