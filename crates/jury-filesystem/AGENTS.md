## Purpose

Own Jury's capability-held repository discovery, separate private state root,
cross-worktree locks, and private atomic publication.

## Key entrypoints

- `src/repository.rs`: hardened repository discovery and `.jury` access
- `src/state_root.rs`: owner-only state-root capability
- `src/private_output.rs`: identity-bound private atomic publication
- `src/lock.rs`: state-root-only exclusive lock

## Edit here for X

- Add generic filesystem invariants here; vault formats and domain identifiers
  belong in their owning crates.
- Worktree publication is only for encrypted shared artifacts. Private or
  plaintext material accepts only a `HardenedStateRoot` capability.

## Invariants

- Keep `unsafe_code = "forbid"` and use safe capability APIs.
- Never treat a canonical path string as authority after validation.
- Reject links, multi-link files, aliases, containment overlap, and identity
  changes before private work.
- Errors and `Debug` omit private paths and contents.
- This crate has no Jig, CLI, TUI, protocol, or witness dependency.

## Common commands

- `cargo test -p jury-filesystem --all-targets`
- `scripts/jig check clippy`
