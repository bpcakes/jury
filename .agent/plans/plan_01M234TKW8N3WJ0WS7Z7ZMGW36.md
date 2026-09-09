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

J26 publication completed after the maintainer approved and all release-source CI passed. The signed experimental v0.0.1 prerelease is public at https://github.com/bpcakes/jury/releases/tag/v0.0.1, with its tag bound to c4edd6221389e4c63774bfacf66ccbee35c9c54c. All ten public downloads passed verification. The handoff observations below are historical.

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

## Verified signing and draft handoff

The maintainer completed browser authentication. Cosign verified SHA256SUMS.sigstore.json against 96315340+featherenvy@users.noreply.github.com and https://github.com/login/oauth. Bundle SHA-256: e02cbee1b4f2981659e8649ef6644bfeeadccfb74392a05d02053acf6448e213. The manifest digest and every artifact remain unchanged. The local artifact verifier explicitly does not verify signatures; Cosign verification was performed separately and succeeded.

GitHub draft release ID 385570274, proposed tag v0.0.1, is https://github.com/bpcakes/jury/releases/tag/untagged-773a1c2d106d3487a195. API inspection confirmed draft=true, prerelease=true, target_commitish=c4edd6221389e4c63774bfacf66ccbee35c9c54c, all ten uploaded asset digests matching local files, and no v0.0.1 Git ref. All draft assets were downloaded to target/j26-signing/github-draft-downloads; exact-identity Cosign verification, SHA256SUMS checks and source/artifact verification passed again on those downloaded bytes.

At the publication handoff, Rust CI 34359454615 still has its CLI job running; other jobs and all other workflows have passed. Do not publish unless that CI passes and the maintainer approves this exact experimental prerelease. If a failure requires changing included source, the approval cannot cover an altered candidate: rebuild, retest, sign, replace the draft only after verification, and present it again. Push bookkeeping commits only after the source CI finishes to avoid cancellation.

## Publication outcome

The maintainer approved publication and pushed the local bookkeeping commits. Exact source c4edd6221389e4c63774bfacf66ccbee35c9c54c passed all five workflows, including every job in Rust CI 34359454615. Before publication, the signature, source/artifact binding, draft body, ten asset digests and successful source CI were checked again. Release 385570274 was published as the experimental v0.0.1 prerelease, without marking it Latest.

Unauthenticated public API access confirmed draft=false, prerelease=true, the expected release body and asset digests, and the v0.0.1 tag resolving to c4edd6221389e4c63774bfacf66ccbee35c9c54c. All ten assets were downloaded without credentials to target/j26-signing/published-downloads. Exact-identity Cosign verification, all checksum entries, and source/artifact verification passed on those public downloads. The checksum manifest, bundle and build-time provenance remain unchanged.

J26 and the completed active release rollups are closed. Deferred macOS, TUI and optional external-review work remains deferred; automated checks and publication do not constitute independent review or establish secret protection. The release remains externally unreviewed pre-alpha and supports synthetic data only.
