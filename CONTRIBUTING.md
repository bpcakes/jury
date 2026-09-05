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

Read [AGENTS.md](AGENTS.md) and the nearest crate guide before making changes.
Include meaningful tests for behavior changes and run the relevant checks:

```sh
scripts/jig check fmt
scripts/jig check clippy
scripts/jig check test
```

See [the licensing guide](docs/open-source.md) for self-hosting and commercial
service boundaries.
