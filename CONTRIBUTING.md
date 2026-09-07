# Contributing to Jury

Jury is source-available under [Elastic License 2.0](LICENSE.md). It is pre-alpha,
does not yet protect secrets, and must not be used with real credentials. Use
generic fixtures such as `ExampleVault`, `ExamplePrincipal`, and `ExampleSecret`.

Bug reports and proposals are welcome through the repository's issues. Follow
[SECURITY.md](SECURITY.md) for security reports; never include secrets or private
operational details in an issue or pull request.

## Rights to contributions

Before outside code or documentation contributions can be accepted, the
contributor and, where applicable, their employer must have an executed
contributor agreement with Banana Pancakes. It must let contributors retain
copyright while granting Banana Pancakes the copyright and patent rights needed
to use, modify, distribute, sublicense, offer hosted or managed services, and
license the contribution under ELv2 or separate commercial terms.

An ELv2 contribution alone does not grant those broader commercial rights.
Opening a pull request or signing off a commit is not a substitute for that
agreement. This repository does not yet provide a contributor agreement or a
signing workflow; contact the maintainers through an issue to arrange one before
submitting a contribution. Maintainers must confirm the executed agreement
covers the contribution before merging it. Existing third-party material must
retain its license and notices and must be identified in the contribution.

## Development

Read [AGENTS.md](AGENTS.md), [agent-map.md](agent-map.md), and the nearest
crate guide before changing code. Linux x86_64 is the tested release platform;
use Git, a C/C++ toolchain, Rust/Cargo, and Python 3 for the command journeys.
The release builder pins Rust 1.97.0; the workspace declares an MSRV of 1.90.

```sh
scripts/jig doctor
cargo build --locked --release -p jury -p jury-witness
target/release/jury --help
target/release/juryd --help
```

Follow `doctor`'s next step if the local development harness needs bootstrap.
Jig is development tooling; installed `jury` and `juryd` do not depend on it.

Include meaningful tests for behavior changes and run the applicable checks:

```sh
scripts/jig check fmt
scripts/jig check clippy
scripts/jig check test
```

The [Linux QA commands](docs/linux-release.md#repeat-the-linux-cli-qa) exercise
actual CLI processes, witnesses and approval terminals; substitute
`target/release/jury` and `target/release/juryd` for a development build. Native
CLI regression tests live under `crates/jury/tests/native_cli/`. The scripts
cover behavior that parser/help checks alone cannot establish.

For documentation changes, compare examples with the actual `--help` and run
the affected synthetic journey. If a guide ships in the binary package, run
`python3 scripts/test-linux-release.py` to check its local links and setup
files. Keep historical QA results distinct from current release status. A green
check does not permit a claim of independent review or suitability for real
secrets. Preserve frozen files under `docs/security` and `conformance` unless
the corresponding construction gate is explicitly being reopened.

Use the repository's `br` tracker and the scoped release workflow in
`AGENTS.md`. For substantial changes, connect the plan and required checks with
`scripts/jig work start`, `work check`, `work evidence`, `work gates`, and
`work finish`. Source changes, verification and tracker updates belong in the
same reviewable change.

See [the licensing guide](docs/open-source.md) for self-hosting and commercial
service boundaries.
