# Jury

Copyright (c) 2026 Banana Pancakes and Jury contributors.

Jury is licensed under the Elastic License 2.0 (ELv2), SPDX identifier
`Elastic-2.0`. See [LICENSE.md](LICENSE.md) for the complete terms.

Unless a file carries an explicit third-party notice, this license applies to
Jury's source code, documentation, examples, and conformance fixtures, including
the core, protocol, CLI, TUI scaffold, and witness server (`juryd`). No alternative
permissive license is offered for these components.

Third-party dependencies and material retain their respective licenses and
copyright notices. This notice does not relicense them. Distributions must
include the applicable third-party license texts and notices as well as Jury's
license and copyright notice.

The software license does not grant rights to Jury or Banana Pancakes trademarks
beyond applicable law. Do not imply endorsement of a modified distribution or
third-party service by Banana Pancakes.

## Protected-memory provider

Jury uses the MIT OR Apache-2.0 licensed `sanitization` 2.0.4 provider from
[featherenvy/sanitization](https://github.com/featherenvy/sanitization), derived
from [valkyoth/sanitization](https://github.com/valkyoth/sanitization).
The exact dependency revision is recorded in `Cargo.lock`. Its original
[MIT license](https://github.com/featherenvy/sanitization/blob/f4c6d7567c5358a1a6f5aea669406178d618043a/LICENSE-MIT)
and [Apache-2.0 license](https://github.com/featherenvy/sanitization/blob/f4c6d7567c5358a1a6f5aea669406178d618043a/LICENSE-APACHE)
remain applicable. The fork adds macOS mapping fork exclusion, final guarded
canary cleanup, and native tests; it does not imply upstream endorsement.
