# Prepare the final Linux 0.0.1 candidate

Consumer: J26 release maintainer. Feature: exact experimental Linux release publication. Observed defect: reporting and signer documentation changed after the previous candidate, invalidating its source binding. This minimal recovery record preserves the exact candidate and verification scope across the required browser handoff. Delete it when the candidate is superseded.

## Progress

- [x] Confirm security-alert email settings with the maintainer and verify the selected GitHub signing identity using a synthetic Sigstore signature.
- [x] Commit public signer and reporting documentation as f06b040.
- [x] Repair reproduced closed-pipe and asynchronous-approval test races without weakening existing behavior assertions; commits 9b9bdbd and c4edd62.
- [x] Build clean source c4edd6221389e4c63774bfacf66ccbee35c9c54c twice, compare binaries, generate SBOMs and audit both dependency graphs.
- [x] Pass all required Jig gates, final scripts/jig check test, fresh J25 checks and complete direct/witnessed/rollover/suite-2 conformance.
- [x] Pass 93 packaged help surfaces, 26 native CLI cases and three self-hosted integration cases against the extracted final binaries.
- [x] Pass all ten packaged Debian 12 journeys plus the TLS lifecycle and untrusted-CA refusal.
- [x] Prepare customer-facing release notes at target/j26-signing/release-notes.md.

Remaining J26 work outside local preparation: final manifest signing needs browser authentication; Rust CLI CI is still running; publication remains separately approved. J26 stays in_progress. No release signature, tag or publication has been created.

## Surprises & Discoveries

The f06b040 candidate exposed a real closed-pipe test isolation race: concurrent forks could inherit a pipe reader briefly, so reaping the intended child did not prove the last reader was gone. The unchanged test passed alone. The fix runs the four original closed-pipe cases in a separate test process and checks that exactly one test ran successfully. The failed run remains in target/j26-final/packaged-integration.log.

A later 9b9bdbd workspace run exposed an asynchronous approval publication race. The fixture wrote directly to the polled destination then chmodded it; the actual shell umask 0002 permitted a transient group-writable file, and direct writing could expose incomplete JSON. c4edd62 prepares a sibling NamedTempFile, sets final permissions, and publishes complete bytes with persist_noclobber. Existing assertions remain unchanged. The failed run is target/j26-release/work-check-recovery.log, and the first repaired 29-case integration pass is target/j26-release/approval-fix-validation.log. These are fixture defects, not evidence that the CLI accepted unsafe approvals or bypassed policy.

Changing the Beads notes invalidated broad Jig receipts. One refresh passed application tests but its file-budget target failed while cleaning up a Git process. A standalone file-budget retry passed; attaching it with check --plan-id was rejected because the prepared run plan had no plan ID. The standard work check subsequently passed on c4edd62, recovering all six required gates. These harness failures remain in target/j26-release/final-work-check.log and file-budget-*.json. No gate policy was weakened.

## Decision Log

The maintainer selected public certificate identity 96315340+featherenvy@users.noreply.github.com and exact issuer https://github.com/login/oauth; a synthetic bundle verified both. Do not substitute the previously discussed email or accept wildcard matching. Keep the final candidate immutable after signing; provenance signed/published flags describe build-time state. Workflow and tracker bookkeeping are excluded from the packaged source inventory. The earlier f06b040 and 9b9bdbd archives are historical and must not be signed as the final candidate.

## Outcomes & Retrospective

The final candidate is target/linux-release/0.0.1-c4edd62, bound to clean source c4edd6221389e4c63774bfacf66ccbee35c9c54c. SHA256SUMS digest: c19f0090749b77c6230cd97fcb70ff1ddd9734be2c26b027bf2476e9cc7e4493. Reproduced jury SHA-256: 63f0a4203e73fd7ea3a0a8a6358980a8f042d13956f4e2473255c811b862f5ae; juryd: c0a065fad8a792d09aa677d216acc101e202fd9b944f7d9c898df5510b42c2ef. Both dependency audits report zero vulnerabilities and zero warnings. Security CI run 34359454322 passed all six jobs, including 21 release-helper tests against the exact-revision container. Repo Policy, Agent Map and maintained-provider CI pass. Rust CI 34359454615 has passed fmt, Clippy and libraries; CLI remains running at the signing handoff. Automated and model checks are not independent security review. Jury remains externally unreviewed pre-alpha and unsuitable for real secrets.

## Validation and recovery

Logs and extracted binaries are under target/j26-signing; ignored local outputs may need regeneration. Run scripts/build-linux-release verify with the exact checksum digest above before signing. The packaged journey driver has two groups; logs journeys-0.log and journeys-1.log preserve command output and failures. It ran unprivileged in the pinned Debian 12 build image, without network and with read-only source. Host integration tests selected the extracted binaries through JURY_TEST_BINARY and JURYD_TEST_BINARY; embedded CLI quorum fixtures are not packaged-daemon persistence evidence. Fresh J25 measurements bind source c4edd62 and working-tree digest 747998c500c0c50ff6750a9e1c0086524cd9bf5beff8401f4b757d6ce212a26b. Complete suite-2 verification used --boringssl-root /tmp/jury-j01b-boringssl. work-check.log, final-test.log, j25.log, packaged-integration.log and help.log record their respective checks.

Follow docs/linux-release.md for signing and exact identity verification. A browser callback must complete on this machine; never send authentication codes through chat. Rebuild and repeat the affected checks if included source changes. Do not close J26 or claim publication while signing, CI, or publication approval remains outstanding. Push the bookkeeping commit after the source CI completes to avoid cancelling it; the release source and future tag must identify c4edd62, not that bookkeeping commit.
