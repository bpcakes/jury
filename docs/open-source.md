# Licensing and self-hosting

Jury is **source-available, free to self-host** under the
[Elastic License 2.0 (ELv2)](../LICENSE.md), SPDX identifier `Elastic-2.0`.
This replaces the earlier proposed permissive-core/AGPL-witness split.

> Jury remains pre-alpha, does not yet protect secrets, and must not be used
> with real credentials. It has not received independent whole-product
> professional security review. License permissions are not a readiness claim.

## Scope

ELv2 covers Jury's core, protocol, CLI, filesystem/process/protected-memory
components, deferred TUI scaffold, witness server (`juryd`), documentation,
examples, and conformance fixtures, except explicitly identified third-party
material. These components are not also offered under a permissive license.
Third-party dependencies retain their own licenses. See [NOTICE.md](../NOTICE.md).

The isolated conformance manifests remain frozen inputs to the J01B and J19
cryptographic gates. Their missing Cargo license fields do not exempt them from
the repository license; changing those manifests requires the corresponding
gate to be reopened and verified.

## Use and redistribution

ELv2 allows use, modification, and redistribution subject to its terms. It
restricts hosted or managed services that give third parties access to a
substantial set of the software's features or functionality, circumvention of
license-key functionality, and removal or obscuring of licensing and other
notices. Copies must include the license; modified copies must prominently
identify that they were modified. The [full license](../LICENSE.md) controls.

Applied to Jury, the following summarizes the intended reading of
[Elastic's usage examples](https://www.elastic.co/licensing/elastic-license/faq):

| Scenario | ELv2 permission, subject to its conditions |
| --- | --- |
| Individuals self-host Jury | Allowed |
| Companies use Jury internally, including production | Allowed by the license; Jury remains unsuitable for real secrets |
| A SaaS company uses Jury internally for its own secrets | Allowed by the license; the same pre-alpha warning applies |
| Developers modify or redistribute Jury | Allowed with the required license and notices |
| Consultants help customers install Jury for internal use | Allowed |
| A provider offers hosted Jury vaults or witnesses to third parties | Prohibited when the service exposes a substantial set of Jury's features or functionality, whether paid or free |

Jury is not open source: ELv2's service restriction is incompatible with the
[Open Source Definition's field-of-use requirement](https://opensource.org/osd).

## Commercial services and contributions

Banana Pancakes intends to offer its own hosted Jury services. Doing so, or
offering separate commercial licenses, requires the necessary rights to all
included code. The company name in a notice does not establish those rights.
Outside contributions require an executed agreement granting the needed
commercial and sublicensing rights; see [CONTRIBUTING.md](../CONTRIBUTING.md).

Standard ELv2 uses a substantial-functionality threshold. It does not establish
blanket exclusivity over every possible witness-related service. The standalone
witness-service boundary should be reviewed with software licensing counsel
before relying on broader exclusivity. No managed service is claimed to ship
with the first experimental `0.x` release.

## Distribution

Include `LICENSE.md`, `NOTICE.md`, and applicable third-party licenses and
notices with source and binary distributions. The `juryd` container installs
Jury's license and notice under `/usr/share/licenses/jury/` and declares
`Elastic-2.0` in its OCI metadata. J26 must also assemble the third-party notices
for the exact release dependencies.
