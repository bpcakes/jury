Consumer: Linux release maintainer. Gates the container distribution fixes for unchecked moving documentation links and image compilation blocking binding checks. Remove this recovery plan when the fixes and verification no longer need recovery. Baseline includes previously staged work; change only packaging, its regression tests, container instructions, and CI. Validate missing targets and immutable revision links, build a fresh image, run release-helper tests and repository checks.

Completed: container packaging requires a full source commit, rejects absent
relative targets, and preserves that revision in repository URLs and the OCI
image label. CI checks the image in its own job with a 30-minute timeout.
The build instructions describe the required revision for checkouts and archives.

Validation: fresh `juryd:review-pinned-docs` image built successfully; all 19
release-helper tests passed against its actual documents and destinations.
The previous image fails the expanded check because it lacks the revision label.
Immutable-action checks and whitespace checks passed. All six work gates passed.
The initial unoptimized workspace test run was interrupted after roughly ten
minutes; the successful complete rerun used `CARGO_PROFILE_TEST_OPT_LEVEL=1`,
`CARGO_PROFILE_TEST_DEBUG_ASSERTIONS=true`, and
`CARGO_PROFILE_TEST_OVERFLOW_CHECKS=true`, matching the preceding validation.
No test assertions, scope, or timeouts were relaxed. The local image uses the
baseline revision and uncommitted source; it is development validation, not a
published release or a reproduction of a committed release artifact.
