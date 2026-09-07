# Sanitization 1.2.x Backport Register

Status: active while 2.0 is developed

The breaking 2.0 work happens on `temp-dev-2.0.0`. Urgent 1.2.x security,
correctness, and documentation fixes remain on `main` and are merged back into
the development branch when relevant.

This register dispositions the non-breaking backport candidates identified by
the 2.0 roadmap. It does not authorize mixing a 1.2.x patch into a 2.0
checkpoint review range without clearly identifying the integration commit in
the temporary review handoff.

## Required 1.2.x Patch Work

### Redact `CtOption` And `CtResult` Debug Output

Disposition: schedule for the next 1.2.x patch before `CP-07`.

The 1.2.5 types derive `Debug`, so generic backing values may be printed. The
patch should replace derived output with redacted implementations and add
regression tests. This is a non-breaking security-hardening change.

### Correct ArrayVec Historical-Storage Documentation

Disposition: schedule for the next 1.2.x patch before `CP-09`.

The current statement that spare inline storage has never held a `T` is
incorrect after pop, truncate, clear, or reuse. The patch must remove that
claim even if complete backing cleanup cannot be backported.

### Strengthen Existing-Boundary Documentation

Disposition: schedule for the next 1.2.x documentation patch before `CP-03`,
`CP-06`, and `CP-08`.

Clarify:

- generic `Secret<T>` exposure and interior mutation;
- generic `Secret<Vec<T>>` historical allocation limits;
- `ct::Secret<T>` as a control marker rather than a clear-on-drop owner;
- raw `Choice` extraction as a declassification boundary;
- enum transition and inactive-variant storage risks;
- checked canary APIs as the preferred high-assurance path.

## Conditional 1.2.x Patch Work

### Complete ArrayVec Backing Cleanup

Disposition: investigate on `main` as part of the ArrayVec patch.

Backport only if the supported `arrayvec` API exposes the complete post-clear
`MaybeUninit<T>` storage under a stable, reviewable contract. The
implementation must:

- drop live values before raw byte clearing;
- cover historical inline bytes;
- handle zero-sized and drop-bearing types;
- pass Miri and an unsafe-code review;
- preserve the existing public API.

If those conditions are not met, 1.2.x receives the documentation correction
only and the implementation remains assigned to `CP-09`.

## Deferred To 2.0

The following changes are intentionally not backported because they remove APIs,
change generic bounds, alter derive defaults, or may break downstream
`deny(warnings)` builds:

- shared and mutable storage-stability trait bounds;
- removal of unrestricted generic exposure;
- removal of raw `Choice`, mask, and ordering extraction;
- replacement of `ct::Secret<T>`;
- clear-on-drop secret CT option/result ownership;
- strict enum derives and mandatory skip reasons;
- `strict-ct` to `strict-compare`;
- wipe API removals and renames;
- `ReadOnceSecret<T>` replacement;
- infallible cache-flush API replacement;
- broad deprecation attributes on 1.2.x public APIs.

## Patch Workflow

For a 1.2.x patch:

1. switch to `main`;
2. implement, pentest, document, version, tag, and publish through the normal
   patch-release gate;
3. return to `temp-dev-2.0.0`;
4. merge or cherry-pick the patch according to whether its exact history must
   remain visible;
5. identify that integration explicitly when handing the next commit range to
   the reviewer;
6. resolve the matching register item without weakening its 2.0 checkpoint.

No urgent patch should wait for the completion of 2.0.
