# Repository Guidelines

<!-- BEGIN JIG MANAGED BLOCK -->
This repository uses the shared `jig.sh` workflow. Keep repo-local business rules and ownership guidance in backend-level guides; keep generic agent workflow and repo policy here.

## Start Here

- Use this file for repo-wide defaults.
- Open [agent-map.md](./agent-map.md) before backend work.
- Read the nearest backend-level `AGENTS.md` before changing a package or crate when one exists.
- Use `.agent/PLANS.md` when writing an ExecPlan for a complex feature or refactor.
- Use `scripts/jig` for the typed repo contract and `scripts/jig mcp` for MCP clients.
- On a fresh machine, run `scripts/jig doctor`; follow its next step, including `scripts/jig agent bootstrap` when Jig Codex skills are missing.
- For substantial work, use `scripts/jig work start`, `scripts/jig work check`, `scripts/jig work evidence`, `scripts/jig work gates`, and `scripts/jig work finish` to keep plans, receipts, and required gates connected.
- A plan captures an exact Git baseline. Default `work check` runs required gates whose configured path policy applies and records explicit not-applicable evidence for the rest; use `--gate <id>` only when deliberately force-running one gate.
- `jig-contract` validates Jig harness wiring, not the application's API contract.
- Treat `.agent/state/*.jsonl` as append-only repo memory.

## Compatibility And Cutovers

- Prefer direct cutovers only for internal code-only changes that can ship in one coordinated deploy.
- Preserve compatibility or stage rollouts for persisted database state, queued job types, public API contracts, bookmarked routes, webhook boundaries, or source-of-truth moves that can straddle deploys.




## Backend Defaults



- Treat `.` as Rust crate roots.
- Add crate-level `AGENTS.md` files when a crate has meaningful ownership, entrypoint, or invariant guidance that should travel with that crate.
- Keep transport logic thin and business logic in the owning crate.




## Frontend Defaults

No web apps are configured in `.jig.toml`.


## Preferred Commands

- `scripts/jig bootstrap`
- `scripts/jig doctor`
- `scripts/jig dev`
- `scripts/jig check test`
- `scripts/jig check fmt`


- `scripts/jig check clippy`

- `scripts/jig work status`
- `scripts/jig work evidence`



- `scripts/jig check contract`

## Done Means

- Run the relevant local verification for the area you changed.
- For backend changes, finish with `scripts/jig check test`.


- Review the generated diff for stale docs, policy drift, or missing dependent updates.

## Backend Guide Conventions

When a backend package or crate has an `AGENTS.md`, use these sections:

- `## Purpose`
- `## Key entrypoints`
- `## Edit here for X`
- `## Invariants`
- `## Common commands`
<!-- END JIG MANAGED BLOCK -->

## Honest Work and Anti-Ceremony (binding for agents and humans alike)

The purpose of agent work here is working, deployable capability. Process
serves that outcome and never becomes the product.

- A process artifact (certificate, ledger, dashboard, matrix, meta-report,
  speculative check) may be created only if it names a concrete consumer,
  the named feature it gates, the observed defect class justifying it, and
  its deletion condition. Otherwise it does not get created. Boundary test:
  if running code branches on it, it is product; if only humans and status
  reports read it, it is process and the creation-gate rule above applies;
  code written just to flip this answer counts as the pathology, not as a
  consumer. Sole exception: a minimal
  integrity/recovery control (crash-recovery state, provenance snapshot) is
  legitimate when it prevents a named evidence-loss or corruption mode and
  is necessary and minimal.
- Real code + real tests in the same unit of work. Forbidden: faked tests,
  fixtures/mocks presented as live proof, weakened assertions, golden
  regeneration to force green, hard-coded success paths, placeholder macros
  in commits, editing the spec instead of implementing it, narrowing scope
  while claiming full success.
- A typed refusal beats a fabricated result and is less valuable than the
  real capability; refusal-only work stays open and says so.
- Truthful null results ("checked X, found no material increment") are
  successful outcomes. Unsupported claims are worse than silence.
- Metrics predeclare denominator and countermetric; agreement between
  agents may raise confidence but is never independent evidence; never
  silence stderr in evidence-bearing commands.
- Name these pathologies when they occur (gate self-weakening, proof-class
  inflation, golden regeneration, tolerance widening, suppression-pragma
  laundering, refusal farming, follow-up laundering); the names are the
  deterrent. The full catalog with countermeasures lives in the
  just-say-no-to-process-porn-and-ceremony skill; ask the operator for it
  if you cannot resolve that reference.

## Jury Security Boundary

- Jury is currently a pre-alpha scaffold. Never claim that it protects secrets.
- Do not use real credentials, customer identifiers, private project names, or
  operational details in source, tests, plans, issues, or generated evidence.
- Jury must not depend on Jig at runtime; Jig is development harnessing and a
  future downstream consumer only.
- Cryptographic implementation requires the applicable gate in
  `docs/architecture.md` to be satisfied first. J01A/J01B gate shared and direct
  primitives. J19A-J19C freeze the witnessed construction, protocol, vectors,
  and bounded endpoint-retention model; J19 binds those exact
  pre-implementation inputs after a fresh solo verification pass before
  witnessed/distributed
  implementation lands. J26 binds the exact security-critical implementation,
  gate verifier, and release build after J25 and a fresh solo release-candidate
  verification pass. These controls prevent drift; they are not independent
  security review or certification. J19R/J19D and J19E are deferred optional
  external-review work and do not gate the active `0.x` release. They may become
  release gates only through an explicit scope revision after a qualified
  reviewer and budget actually exist. AI/model review, another coding agent,
  self-review, automated tests, and a clean rebuild are never described as
  independent review.
  Witnessed open is the defining active `0.x` release path, not a future add-on.
- Keep secrets, private keys, decrypted payloads, and passphrases out of logs,
  errors, snapshots, receipts, telemetry, and test output.
- Use generic fixtures such as `ExampleVault`, `ExamplePrincipal`, and
  `ExampleSecret`.

## Marketing site

The public site lives in `web/`. It is allowed to describe the intended product
and required to repeat the pre-alpha warning. It must not claim that Jury
protects secrets, is open source, has independent review, or already ships
witnessed or distributed authority. Commands shown there are design targets
until the CLI implements them.

## Beads Workflow

This repository uses beads_rust. Use `br` only; do not mix tracker command
families in this workspace. Issues are stored under `.beads/`.

1. Start with `bv --robot-triage --format toon` for graph-aware triage.
2. Verify a candidate with `br show <id> --json` or
   `br ready --type task --json`. For the release epic, add
   `--epic jury-qv4`.
3. Claim it with `br update <id> --status=in_progress --json`.
4. Close completed work with `br close <id> --reason="Completed" --json`.
5. Run `br sync --flush-only` after tracker mutations.

Use only `bv --robot-*` commands; bare `bv` launches an interactive interface.
The six `jury-qv4` feature records are non-executable rollup containers. Never
claim them as implementation work merely because an unfiltered `br ready`
includes them.

Unscoped `bv` rankings may include deferred or standalone work. They are useful
for repository-wide hygiene, not for active-release sequencing; use the
epic-scoped `br ready --epic jury-qv4 --type task --json` result to determine
claimable release work.

<!-- bv-agent-instructions-v4 -->

---

## Beads Workflow Integration

This project uses a Beads tracker—either the Go `bd` CLI or the Rust `br` CLI—for issue tracking, plus [beads_viewer](https://github.com/Dicklesworthstone/beads_viewer) (`bv`) for graph-aware triage. Issues are stored in `.beads/`. `bv` auto-discovers supported JSONL exports, including `.beads/issues.jsonl` and legacy `.beads/beads.jsonl`.

**Choose the tracker CLI from this repository's instructions and configuration.** Use `bd` commands in a Go Beads workspace and `br` commands in a beads_rust workspace. Do not run both trackers against the same workspace or infer the tracker solely from the JSONL filename.

### Using bv as an AI sidecar

bv is a graph-aware triage engine for Beads projects. Instead of parsing .beads/issues.jsonl / .beads/beads.jsonl directly or hallucinating graph traversal, use robot flags for deterministic, dependency-aware outputs with precomputed metrics (PageRank, betweenness, critical path, cycles, HITS, eigenvector, k-core).

**Scope boundary:** bv handles *what to work on* (triage, priority, planning). The selected tracker CLI (`bd` or `br`) handles creating, claiming, modifying, and closing beads.

**CRITICAL: Use ONLY --robot-* flags. Bare bv launches an interactive TUI that blocks your session.**

#### The Workflow: Start With Triage

**`bv --robot-triage` is your single entry point.** It returns everything you need in one call:
- `quick_ref`: at-a-glance counts + top 3 picks
- `recommendations`: ranked actionable items with scores, reasons, unblock info
- `quick_wins`: low-effort high-impact items
- `blockers_to_clear`: items that unblock the most downstream work
- `project_health`: status/type/priority distributions, graph metrics
- `commands`: copy-paste shell commands for next steps

```bash
bv --robot-triage        # THE MEGA-COMMAND: start here
bv --robot-next          # Minimal: just the single top pick + claim command

# Token-optimized output (TOON) for lower LLM context usage:
bv --robot-triage --format toon
```

Before claiming, verify current state with the selected tracker: `br show <id> --json`/`br ready --type task --json` or `bd show <id> --json`/`bd ready --json`. For Jury release work, scope the Rust command with `--epic jury-qv4`. `recommendations` can include graph-important blocked or assigned work; only task records in `quick_ref.top_picks` with non-empty `claim_command` fields represent claimable work.

#### Other bv Commands

| Command | Returns |
|---------|---------|
| `--robot-plan` | Parallel execution tracks with unblocks lists |
| `--robot-priority` | Priority misalignment detection with confidence |
| `--robot-insights` | Full metrics: PageRank, betweenness, HITS, eigenvector, critical path, cycles, k-core |
| `--robot-alerts` | Stale issues, blocking cascades, priority mismatches |
| `--robot-suggest` | Hygiene: duplicates, missing deps, label suggestions, cycle breaks |
| `--robot-diff --diff-since <ref>` | Changes since ref: new/closed/modified issues |
| `--robot-graph [--graph-format=json\|dot\|mermaid]` | Dependency graph export |

#### Scoping & Filtering

```bash
bv --robot-plan --label backend              # Scope to label's subgraph
bv --robot-insights --as-of HEAD~30          # Historical point-in-time
bv --recipe actionable --robot-plan          # Pre-filter: ready to work (no blockers)
bv --recipe high-impact --robot-triage       # Pre-filter: top PageRank scores
```

### Tracker Commands for Issue Management

Use exactly one command family, matching the tracker configured for the repository.

#### Rust beads_rust (`br`)

```bash
br ready --type task --json           # Show executable tasks ready to work
br ready --epic jury-qv4 --type task --json # Scope to Jury release work
br list --status=open --json          # All open issues
br show <id> --json                   # Full issue details with dependencies
br create --title="..." --type=task --priority=2 --json
br update <id> --status=in_progress --json
br close <id> --reason="Completed" --json
br close <id1> <id2> --reason="Completed" --json
br sync --flush-only                  # Export DB to JSONL after Beads mutations
```

#### Go Beads (`bd`)

```bash
bd ready --json                       # Show issues ready to work
bd show <id> --json                   # Full issue details
bd create "..." -t task -p 2 --json
bd update <id> --claim --json         # Atomically claim work
bd close <id> --json
bd dep add <issue> <depends-on>
bd export --no-memories -o .beads/beads.jsonl  # Refresh the export read by bv
```

### Workflow Pattern

1. **Triage**: Run `bv --robot-triage` to find the highest-impact actionable work
2. **Verify**: Check the selected tracker's `show`/`ready` output before claiming
3. **Claim**: Use `br update <id> --status=in_progress --json` or `bd update <id> --claim --json`
4. **Work**: Implement the task
5. **Complete**: Use the selected tracker's `close` command
6. **Refresh for bv**: Run `br sync --flush-only` or the `bd export` command above so the JSONL export is current

### Key Concepts

- **Dependencies**: Issues can block other issues. `br ready --type task --json`
  and `bd ready --json` show unblocked executable work; unfiltered Jury feature
  parents are rollup containers, not claim candidates.
- **Priority**: P0=critical, P1=high, P2=medium, P3=low, P4=backlog (use numbers 0-4, not words)
- **Types**: task, bug, feature, epic, chore, docs, question
- **Blocking**: Use `br dep add <issue> <depends-on>` or `bd dep add <issue> <depends-on>` to add dependencies

### Git Policy

Tracker commands do not grant permission to commit or push application code. Follow this repository's own git and tracker instructions before staging, committing, syncing, or pushing. If the repository says "commit only when asked," that rule overrides any generic workflow advice.

<!-- end-bv-agent-instructions -->
