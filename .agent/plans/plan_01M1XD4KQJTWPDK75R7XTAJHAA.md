# Refresh user and release documentation after Linux QA

Purpose: help Linux 0.0.1 users and maintainers use the committed CLI and daemon. The observed defects are stale pending-QA status, incomplete setup examples, and navigation that sends new users directly into design plans. This plan gates this documentation refresh and can be retired when a successor documentation pass replaces it.

## Progress
- [x] Compare current user, operator, recovery, contributor and release guidance with CLI/source and recorded QA.
- [x] Repair stale status, command examples and navigation without changing frozen protocol inputs or claiming publication.
- [x] Exercise documented command surfaces and verify links, packaging compatibility and required repository checks.

## Surprises & Discoveries
The completed candidate QA is recorded in repository memory, but the historical QA report still describes final verification as pending. Ignored local package artifacts have been removed since that run. The operator guide claimed that rerunning policy require witnessed could rotate an already witnessed-only item; an actual command returned exit 6 / item-unavailable without changing the vault. The current CLI has no governed rekey input for this command. The guide now distinguishes same-identity service restore from unavailable witness replacement and label renewal. No runtime capability or release gate was changed. The checkout has no web/ marketing site; its repository guidance now states that fact. The required Jig verification profile runs workspace tests even for this documentation change. Its first run was interrupted after final wording corrections made its recorded snapshot stale; the interrupted record is retained and a fresh run follows against settled files.

## Decision Log
Keep historical evidence as history, publish one clear current status, and retain the unconfigured security-reporting and signing prerequisites. Do not change runtime code or frozen cryptographic documents to simplify documentation work.

## Outcomes & Retrospective
Updated user/operator/recovery/release/contributor guidance, current QA status, architecture boundaries and roadmap status. The README shell blocks passed with real hidden terminal field capture and exact file/template/child results. The verbatim operator-post.py example passed against both real witnesses and was followed by exact read, receipt verification, restart and cancellation. The role-onboarding and three-role recovery journey passed. The final link scan resolved 99 local links and fragments in 48 owned Markdown files, including multiline link labels; nine release-helper tests passed. All 24 shell blocks in changed user and maintainer guides parsed. AGENTS.md contains placeholder command templates and was excluded from shell parsing. The native release build passed. The final Jig work check passed, including the full workspace verification profile. Frozen inputs and runtime files are unchanged. This refresh does not publish a release or implement witness replacement.

## Validation
Use the committed CLI parser/help and existing real command journeys as the command contract. Check Markdown links and package documentation with the existing release helper. Run the required Jig gates, including the configured verification profile; retain its workspace test result separately from the end-user documentation checks.
