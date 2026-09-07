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

Jury maintains the MIT OR Apache-2.0 licensed `sanitization` provider in
`third_party/sanitization`, imported from the owned
[featherenvy/sanitization](https://github.com/featherenvy/sanitization) fork at
`3f0a72c5640b4919dec93799725c7573b2878a8c`, derived from
[valkyoth/sanitization](https://github.com/valkyoth/sanitization) 2.0.4.
Its original MIT and Apache-2.0 license files remain applicable and accompany
the source and binary distributions. Jury's Git commit and release source
hashes bind the maintained provider bytes. The fork adds macOS mapping fork
exclusion, final guarded canary cleanup, and native tests; it does not imply
upstream endorsement.
