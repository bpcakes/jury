# Linux 0.0.1 candidate

Jury is externally unreviewed pre-alpha software and unsuitable for real
secrets. Version 0.0.1 has not been published. The package contains the `jury`
CLI and self-hosted `juryd` daemon for Linux x86_64. Debian 12 with glibc 2.36
is the tested runtime baseline. No macOS, Windows, ARM, or TUI artifact is
included. This is a hard cutover of an unreleased format; recreate synthetic
development vaults and identities instead of migrating them.

## Current status

The 2026-09-08 audit findings QA-20 through QA-23 are addressed after pulling
upstream `635f078`. The maintainer explicitly included J18 rollover and suite
migration in Linux 0.0.1; both now gate J26 under their full acceptance criteria.
The repaired fuzz lockfile passes the unchanged seed tests and four bounded fuzz
targets. Real CLI checks verify the backup-drill state-parent diagnostic and
successful recovery, and both TLS services now explain unsafe certificate files.
The repair evidence and historical candidate hashes are in
`docs/qa-linux-0.0.1.md` in the source checkout. These repairs require a new bound
release candidate; the earlier `cd8eeac` package is not the repaired artifact.

The native implementation committed as `16ab899` passed the 2026-09-06 Linux
QA: ten packaged CLI journeys on Debian 12, installation/removal, HTTPS,
workspace checks and the bounded adversarial checks. The detailed historical
record is `docs/qa-linux-0.0.1.md` in the source checkout/archive. The witness
operator guide also states the current CLI policy replacement and recovery
limits; passing QA covers the exercised operations, not every protocol-defined
future operation.

That candidate was local and unsigned. Files under ignored `target/` are not
release downloads and may have been removed. Changing source, packaged guides,
provider inputs or the verifier requires a newly bound candidate. The reporting
channel and signing identity below remain unconfigured; passing QA alone does
not publish or approve a release.

## Prepare a local candidate

Use Linux x86_64, Git, Python 3.11.4+, Docker, and Cargo 1.90 or newer.
Install the pinned advisory scanner:

```sh
cargo install cargo-audit --version 0.22.2 --locked
scripts/build-linux-release build --output /absolute/fresh/candidate
```

The recipe builds cargo-cyclonedx 0.5.9 inside the pinned Rust 1.97.0 image.
It generates the SBOMs there with the same Cargo/Rust resolver as the binaries.

The script checks dirtiness over the packaged source (excluding workflow state and the marketing site), and refuses changes unless `--allow-dirty` is explicitly
supplied for a local unsigned candidate. It does not sign, tag, or publish.
Initial vendoring, advisory refresh, acquisition of the pinned build image and
installation of the pinned SBOM tool need network access. The two compilation containers run offline with read-only source and
vendor inputs, separate empty build directories, and fixed compiler paths.
The runs use eight and four Cargo build jobs. Both binaries must match byte for byte. This checks repeatability under the pinned environment; it does not establish independence from arbitrary compiler, user-ID, or host changes. The script then runs real owner-change
CLI and daemon processes, including human approval terminals, in Debian 12.
It fails if the source changes before completion. The final output directory appears only after verification succeeds; failed builds remove their temporary output. Choose an output outside the checkout or under its ignored `target/` directory.

The output includes the native package, exact native-source archive (excluding workflow state and the marketing site), vendored provider
sources, two CycloneDX 1.5 SBOMs, the current dependency advisory report,
provenance, and `SHA256SUMS`. Advisory filtering or ignored advisories are
refused; vulnerabilities or warnings stop preparation. The package
includes Jury's license, third-party notices checked for every vendored package,
Rust standard-library notices, operating/security documentation, and the
`deploy/juryd` example configurations and systemd units used by the self-hosting
guide. Local links in the shipped guides are checked before packaging; the
architecture and provider references they link to are included for reading.
Missing upstream crate notices are supplemented with revision and digest bindings
under `licenses/vendor-supplements`; the full development workspace and historical
QA report are available in the accompanying source archive. Use that source
archive for container or conformance builds. The
SBOMs cover target-specific Cargo dependencies, including build dependencies;
they are not an inventory of every package in the build container. The pinned
container digest separately identifies that build environment.

To reproduce from the same checkout, first verify the published checksums and
signature, then rerun with `--vendor-archive /absolute/path/to/jury-0.0.1-vendor.tar.gz`,
`--vendor-sha256 EXPECTED_SHA256_FROM_VERIFIED_CHECKSUMS`, and a fresh `--output`.
The archive must match before extraction; the provider mappings come from
Cargo.lock. Supply `--expect-binary-sha256 jury=EXPECTED_SHA256` and
`--expect-binary-sha256 juryd=EXPECTED_SHA256` from the separately authenticated
`reproduced_binaries` in `provenance.json`; mismatches stop the build. Metadata can differ
between candidates; only the two binaries are asserted to reproduce.

```sh
scripts/build-linux-release verify /absolute/path/to/candidate --checksums-sha256 EXPECTED_AUTHENTICATED_SHA256SUMS_DIGEST
cd /absolute/path/to/candidate
sha256sum --check SHA256SUMS
```

The verifier compares source bytes, executable modes, inventory, and packaged
artifact hashes against the supplied checksum digest. Obtain that digest through a separately authenticated channel, or calculate it only after verifying the signature on `SHA256SUMS`. The local checker does not authenticate a Sigstore bundle; it prints an explicit warning when one is present. Its concrete consumer is the maintainer preparing the J26
Linux release; it detects source/provider/build/artifact drift between QA and
distribution. Replace this recipe and binding when a successor release changes
the supported build or format. Checksums and this local binding establish
consistency, not publisher identity, independent review, or secret protection.

## Repeat the Linux CLI QA

Run from the full source checkout against the **extracted candidate binaries**.
The build recipe runs the owner-change journey as a smoke check; the full
end-user pass consists of these ten journeys. They use synthetic fixtures,
real processes, private temporary directories and PTYs, and require Python 3,
Git, `/proc`, and a Linux account able to run the configured memory protections.

```sh
JURY_BIN=/absolute/extracted/jury-0.0.1-x86_64-unknown-linux-gnu/jury
JURYD_BIN=/absolute/extracted/jury-0.0.1-x86_64-unknown-linux-gnu/juryd
for journey in witness-lifecycle approval-review descriptor-access role-onboarding \
  shared-policies diagnostics owner-changes public-labels; do
  python3 "scripts/check-linux-$journey" --jury "$JURY_BIN" --juryd "$JURYD_BIN" || exit 1
done
python3 scripts/check-linux-shared-policies --disjoint --jury "$JURY_BIN" --juryd "$JURYD_BIN" || exit 1
python3 scripts/check-linux-input-surfaces --jury "$JURY_BIN" || exit 1
```

Use Debian 12 as the native package's runtime baseline and run as an
unprivileged user. Keep stderr and the exit status of every command. The
loopback journeys exercise HTTP with explicit test opt-in; they do not replace
a TLS lifecycle using an explicit synthetic CA for both service links, including
untrusted-certificate refusal. Complete J25 and the repository's required
verification on the exact release source as well. Do not count an old candidate's
result as a check of a replacement archive.

## Release signing and incident handling

Before publication, configure a private security-reporting contact in
`SECURITY.md` and select a release-signing identity. Neither is configured yet.
No current candidate is signed or approved for publication. Perform a fresh
J19 input check, J25 adversarial validation and Linux QA on the exact candidate,
review current dependency advisories, and record the exact verified source and
artifact hashes. An unresolved medium-or-higher finding holds the release.

The proposed signing procedure uses a Sigstore bundle for `SHA256SUMS` after
all artifacts and provenance are final. The maintainer must select the exact
OIDC certificate identity and issuer, keep the identity's account protected,
and publish those exact expected values separately from the download. Do not
use a wildcard identity or accept an unverified key delivered with an artifact.
Follow the current [Sigstore blob-signing instructions](https://docs.sigstore.dev/cosign/signing/signing_with_blobs/)
and [verification instructions](https://docs.sigstore.dev/cosign/verifying/verify/).
No credentials or private signing keys belong in the repository or package.

If the signing account is compromised, stop publication, identify affected
artifact hashes and time ranges, publish a non-sensitive notice through the
established project channel, revoke access to the account, and establish a new
identity through a separately authenticated announcement. Do not silently
replace existing versioned artifacts. Treat reports with synthetic reproductions
as public only when their contents are non-sensitive; handle private reports
through the configured private channel once it exists.

## Install and remove

After verifying the release signature and checksums, run these commands from
the directory containing the native archive:

```sh
tar -xzf jury-0.0.1-x86_64-unknown-linux-gnu.tar.gz
cd jury-0.0.1-x86_64-unknown-linux-gnu
install -Dm755 jury ~/.local/bin/jury
install -Dm755 juryd ~/.local/bin/juryd
export PATH="$HOME/.local/bin:$PATH"
jury --version
jury --help
juryd --help
```

Persist the `PATH` addition in your shell configuration if needed. See the
[witness operator walkthrough](witness-operator-walkthrough.md) for separate
witness and anchor configuration. Remove the two installed binaries to
uninstall. Data and identity directories require an explicit separate decision;
removing binaries does not remove them.

The maintained `sanitization` provider lives in `third_party/sanitization` and
ships in the source archive. Cargo's vendor archive contains external
dependencies; both archives are required for offline reproduction. The binary
notice inventory includes the local provider's original MIT and Apache-2.0
licenses. The source inventory and hashes cover its manifests, implementation,
and tests just as they cover Jury's own source.
