# Jury

**A portable secrets vault, exploring fresh approval for each governed open.**

[Quick start](#try-a-direct-vault) · [Witnessed walkthrough](docs/witness-operator-walkthrough.md) ·
[Self-hosting](docs/self-hosting-juryd.md) · [Recovery](docs/recovery.md) ·
[Release status](docs/linux-release.md) · [Security](SECURITY.md)

> [!WARNING]
> Jury is a pre-alpha implementation. It does not yet protect secrets and
> must not be used with real credentials. It has not received independent
> whole-product professional security review.

Jury is an experimental implementation of a portable encrypted vault where
opening a governed item can require fresh approval from a jury. The project
remains on `0.x` releases; the portable artifact and witness protocol both
start at version 1. The defining release path requires signed approval and
witness contributions for the exact item revision and action before an
endpoint can open it. Direct slots remain an explicit unilateral mode and
carry no quorum claim.

## Why Jury?

The design separates carrying a vault from authority to open it. An encrypted
artifact can travel with a Git repository, while private identities and local
state stay outside Git. For governed access, approval is tied to an exact item
revision and action: reading a field, rendering a template, or passing a value
to a child process.

| Concept | Role in the design |
| --- | --- |
| Portable vault | Encrypted items and access policy in a versioned artifact |
| Principal | A human or machine identity with item-scoped grants |
| Approval | A signed decision about the exact requested action |
| Witness | A service that contributes to an authorized governed open |
| Receipt | Signed decision evidence with explicit limits on what it proves |

Witnessed access is the defining goal of the first experimental release.
Direct access is an explicit unilateral mode: a direct recipient can open its
authorized item alone. An item with a direct slot has no quorum claim as a whole.
Neither mode prevents an authorized endpoint or child from retaining plaintext.

## Start here

Version **0.0.1 is not published**. The [2026-09-08 Linux CLI audit](docs/qa-linux-0.0.1.md)
passed ten packaged CLI journeys on Debian 12 (glibc 2.36), including witnessed
access and recovery. Its four follow-up findings are addressed: rollover and
suite migration are explicitly included in 0.0.1, the repaired fuzz lockfile
passes the bounded suite, and recovery/TLS diagnostics explain the required
filesystem layout and permissions. Passing the exercised paths does not establish
security for real secrets. Publication still requires a private reporting
contact, a release-signing identity, and a freshly verified candidate bound to
the final source and documentation.

To build and install both commands from source:

```sh
git clone https://github.com/bpcakes/jury.git
cd jury
cargo build --locked --release -p jury -p jury-witness
install -Dm755 target/release/jury "$HOME/.local/bin/jury"
install -Dm755 target/release/juryd "$HOME/.local/bin/juryd"
export PATH="$HOME/.local/bin:$PATH"
jury --version
juryd --help
```

Use Linux x86_64 with Git, a native C/C++ build toolchain, and Rust/Cargo. The
workspace declares Rust 1.90 as its minimum; the release recipe was tested with
Rust 1.97.0. Both binaries report `0.0.1`. macOS, Windows, ARM release packages,
and the terminal UI are outside the tested release scope. For reproducible
packaging and later binary installation, see
[Linux release preparation](docs/linux-release.md).

### Try a direct vault

Use a disposable shell and synthetic values only. This creates a new Git
repository and keeps its test identities, local state, and output in separate
directories under one private temporary root:

```sh
umask 077
EXAMPLE_ROOT="$(mktemp -d /tmp/ExampleJury.XXXXXX)"
mkdir -m 700 "$EXAMPLE_ROOT/repository" "$EXAMPLE_ROOT/identities" \
  "$EXAMPLE_ROOT/state" "$EXAMPLE_ROOT/output"
export JURY_IDENTITY_HOME="$EXAMPLE_ROOT/identities"
export JURY_STATE_HOME="$EXAMPLE_ROOT/state"
git init --quiet "$EXAMPLE_ROOT/repository"
cd "$EXAMPLE_ROOT/repository"
jury identity init
jury vault init
jury item create ExampleItem --allow-direct
jury vault field set ExampleItem ExampleField
jury read --direct ExampleItem ExampleField --out "$EXAMPLE_ROOT/output/value.txt"
jury vault audit verify
```

Choose and confirm a test identity passphrase. At the field prompt, type
`ExampleSecret` and press **Ctrl-D**; Enter would become part of the value.
The read creates a mode-`0600` file without printing the value. Its destination
must be absent; use `--overwrite` only when replacing that selected output is
intentional. The encrypted shared artifact is `repository/.jury/vault.json`;
identities and local state are outside that repository. Retain the whole test
root while using the vault. Exit the disposable shell when finished so its
path overrides do not affect other vaults.

Direct access is unilateral. For approval-governed access, follow the
[witness operator walkthrough](docs/witness-operator-walkthrough.md) from actor
registration through two-terminal approval and receipt verification. Configure
all needed operations before making the item witnessed-only. That conversion
removes its direct slots; the direct examples above no longer apply to it.
The [operator guide](docs/self-hosting-juryd.md#witness-key-rotation-retirement-and-recovery)
states the current policy replacement and recovery limits.

| Next task | Guide |
| --- | --- |
| Configure and operate witnesses and anchors | [Self-hosting](docs/self-hosting-juryd.md) |
| Add items after governing existing descriptors | [Item creation](docs/item-creation.md) |
| Grant or revoke a vault owner | [Owner changes](docs/owner-changes.md) |
| Back up, restore, or rehearse recovery | [Recovery](docs/recovery.md) |
| Use dotted names or arbitrary public review labels | [Reference syntax](docs/naming.md#native-identifier-and-name-profile) |
| Understand boundaries or planned work | [Architecture](docs/architecture.md), [master plan](docs/jury-v1-master-plan.md) |
| Develop and verify a change | [Contributing](CONTRIBUTING.md#development) |

## What the Linux CLI implements

The native Linux CLI currently handles:

- portable identity and vault setup;
- direct item, field, principal, and access operations with explicit unilateral status;
- witnessed-policy configuration and owner-signed review labels;
- governed witnessed read, template injection, transparent exec, and brokered run;
- request creation, complete inspection, offline status, interactive approval/denial, foreground execution, and cancellation;
- privacy cover and local audit verification;
- direct transparent execution and bounded brokered execution behind `--direct`;
- signed portable-ciphertext export, inspection, and strict import;
- public witness-policy export and per-witness checkpoint propagation status;
- bounded offline inspection and verification of witnessed-decision receipts;
- owner backup creation, full verification, absent-target restore, and real recovery drills;
- public history and capacity status.

For piped field input, `--passphrase-stdin` consumes the identity passphrase
line first and stores only the remaining bytes as the field value. It overrides
all inherited passphrase environment variables, including backup and new-identity
variables: supply every requested passphrase and confirmation in prompt order.
With a terminal attached it still selects stdin and waits for hidden input,
even if an environment variable was previously sufficient. Unattended jobs
should use a pipe with the full input sequence or omit the flag and configure
every required environment source; do not allocate a terminal expecting the
flag to use environment values.
Without that flag, a configured `JURY_IDENTITY_PASSPHRASE` consumes no stdin;
provide only the intended field bytes. Do not mix these input layouts.

`JURY_IDENTITY_PASSPHRASE` authenticates the existing identity for vault init,
audit verification, identity public/prove, and other authenticated commands.
`JURY_NEW_PASSPHRASE` supplies the new passphrase for identity init, passphrase
changes, and restored identities. Without those sources, the CLI prompts and
confirms new passphrases. Keep passphrases out of command arguments and shell history.

At a terminal, `jury vault field set ITEM FIELD` reads hidden input, with or
without `--value-stdin`. Ctrl-D finishes immediately without adding a newline;
Enter adds a newline to the stored value. Backspace erases one byte on the
current line; Ctrl-U clears that line. Ctrl-C cancels without saving and restores
terminal settings. For exact binary bytes, pipe input with `--value-stdin`.

### Templates and child processes

In the direct example above, create templates using exact `ITEM/FIELD`
references. Run these commands from the example repository while its identity
and state overrides are still set:

```sh
printf 'value={{ExampleItem/ExampleField}}\n' > "$EXAMPLE_ROOT/output/template.txt"
jury inject --direct --template "$EXAMPLE_ROOT/output/template.txt" \
  --out "$EXAMPLE_ROOT/output/rendered.txt"
printf 'EXAMPLE_VALUE={{ExampleItem/ExampleField}}\n' > "$EXAMPLE_ROOT/output/child.env"
jury exec --direct --env-file "$EXAMPLE_ROOT/output/child.env" -- \
  /bin/sh -c 'test -n "$EXAMPLE_VALUE"'
jury --json run --direct --stdin ExampleItem/ExampleField --timeout 30 -- /usr/bin/wc -c
```

The child examples check delivery without printing the field: `exec` returns
the child's exit status and `run` reports its captured byte count. Witnessed
operations use the same field references plus the checkpoint, approval,
request/receipt output paths, and exact witness tuples shown in the walkthrough.

Inside a Git worktree, `jury vault init` writes only the encrypted
`.jury/vault.json` artifact and a fixed `.jury/.gitattributes` merge rule.
Identity files and authenticated local state stay in separate Linux data
and state roots. This storage layout is pre-alpha plumbing, not evidence that
Jury protects secrets.

The CLI can configure a witnessed-only policy and perform foreground governed
operations. A foreground operation publishes the complete public request,
retains its fresh protected request-session receiver only in that process,
waits for the declared approval files, obtains signed responses from the exact
witness set, and opens the exact revision only after quorum. A detached
`request create` artifact remains inspectable, approvable, and cancellable, but
cannot later execute: Jury deliberately persists neither its session private
key nor witness contributions. Create a fresh foreground request instead.
Interactive approval renders the complete authenticated manifest, meaningful
item/field/path displays, and a lossless byte-escaped view of the executable,
public arguments, environment names, and typed secret targets. It does not
truncate that review to the terminal width.

`jury transfer export` packages
the exact encrypted vault with the bounded public policy catalog required for
fresh validation; it does not include identities, audit, checkpoints, receipts,
or private item/field names. It does include deliberately public owner-signed
review labels used for meaningful witnessed approval, and `transfer inspect`
reports those labels without unlocking an identity. Public inspection never
reveals field values, and import
accepts only a first installation, an identical artifact, or a complete
authenticated strict descendant that does not introduce unilateral direct slots
or weaken witnessed authority. It never merges branches. `transfer status`
describes only the selected identity's last successful local export and never
claims delivery or synchronization. Witness checkpoint status similarly reports
only the exact per-witness durable acknowledgements supplied to it and never
claims global freshness. Offline receipt verification proves signed public
decisions and their exact request, manifest digest, policy checkpoint, and
witness state generations. With no separately retained checkpoint, it reports
that its trust root is only the internally consistent embedded owner-signed
policy chain. Aggregate receipt reason/time fields are collector metadata unless
a verified endpoint record authenticates the receipt core. It does not prove
endpoint execution, output, non-exfiltration, or forgetting. A witnessed-only
configuration or successful request is not evidence that Jury protects real
secrets.

Artifact publication is the export commit point. If the separate local receipt
cannot be recorded afterward, export still reports the published artifact as a
success with `local_export_receipt_recorded: false` instead of returning an
ambiguous failure.

Jury generates registration descriptors, challenges, and proofs as canonical
JSON artifacts. They are not editable configuration. Jury rejects reformatted
documents, reordered keys, and added fields because registration binds their
exact bytes. Each public registration input must be an absolute, direct path
to a regular file owned by the current effective user. Linked files and files
with group or world write permission fail validation.

For cross-user registration, transfer each generated artifact over an
authenticated channel, then have the receiving operator write a fresh file
owned by the recipient. Both `principal add` and `principal replace` require
`--from DESCRIPTOR` and `--proof PROOF`. Before changing policy, Jury checks
the selected descriptor against the candidate descriptor authenticated by the
proof.

New fields created with `jury vault field set` are concealed by default.
Updating a field preserves its existing classification unless you specify
`--concealed` or `--unconcealed`. Use `--unconcealed` only when that field's
value may appear in child output; its stored value remains encrypted. Existing
fields are not reclassified automatically. Inspect them with `jury vault field list`.
Concealed values must contain at least four bytes; shorter public values require
`--unconcealed`.

In explicit `--direct` mode, `jury exec` inherits the ordinary environment and
stdin, removes every `JURY_*` variable, and filters supplied concealed field
values and supported encodings from the child's stdout and stderr independently.
Unconcealed fields pass through. Redaction cannot guarantee coverage of arbitrary
encodings or transformations and does not prevent an authorized child from
retaining or transmitting plaintext.
`jury run` starts with a small environment allowlist and bounded output capture.
Without `--timeout`, runs use 1,800 seconds, reduced to the witnessed policy
limit when smaller. Witnessed `exec` uses the same policy-bounded default;
transparent direct `exec` remains unbounded. Explicit timeouts above the witnessed policy
limit are refused before publishing a request. Both commands resolve and authorize every
`Item/Field` reference before starting a child. Templates use `{{Item/Field}}`.
The slash separates exact names even when either contains dots: for example,
`{{Example.Group/ExampleField}}` differs from `{{Example/Group.ExampleField}}`.
Legacy `Item.Field` shorthand remains valid only when neither name contains a
dot; multi-dot shorthand is rejected. For public review labels outside the
native name profile, use a JSON pair such as `'["Example Item","Example Field"]'`
as the reference, or `{{["Example Item","Example Field"]}}` inside a template
or dotenv value. JSON escaping preserves exact labels containing quotes,
braces, dots, slashes, spaces, or Unicode. This input syntax does not require
the `--json` output option. Both commands support protected stdin
and sealed anonymous-file delivery, and they own the Linux process group
through cleanup.

Without `--direct`, read, inject, exec, and run use witnessed authority and
require an exact checkpoint, request output, receipt output, and witness
endpoint set. Governed template and child requests currently accept one item
per request, matching the frozen protocol's item scope. Governed child input is
either typed field environment/file injection or one typed stdin field;
uncommitted literal environment values and a combined stdin/environment shape
are refused. An authorized child can copy or retain every plaintext value it
receives.

## Request lifetime and evidence

```console
$ jury request status /absolute/public/path/ExampleRequest.json
$ jury request cancel /absolute/public/path/ExampleRequest.json \
    --out /absolute/public/path/ExampleCancellation.json \
    --witness 'WITNESS_ID,https://127.0.0.1:7443,/absolute/private/client-token,/absolute/public/ca.pem'
```

Each endpoint specification is
`WITNESS_ID,BASE_URL,CREDENTIAL_FILE[,CA_CERTIFICATE]`. HTTPS requires the
explicit CA certificate; plaintext HTTP is accepted only for a literal loopback
IP with `--allow-insecure-loopback`. Redirects are disabled. Credentials and
endpoint routing are deployment-local and never enter the vault, request,
manifest, or receipt.

A verified receipt proves the authenticated policy, exact request/manifest,
counted independent decisions, and witness state generations encoded in it. It
does not prove transport health, global freshness, endpoint execution, output,
non-exfiltration, or forgetting; an authorized endpoint or child may retain
plaintext. Aggregate receipt reason/time remains collector metadata unless an
authenticated endpoint record covers it. These limitations are especially
important because Jury is externally unreviewed pre-alpha software.

## Output and exit status

`jury --json` emits structured command results on stdout and one structured
error on stderr. It is a standalone flag, placed before the child's `--`
separator. `--help` and `--version` always return text with status 0.

| Operation | Output contract |
| --- | --- |
| Metadata commands, including `receipt verify` | Human-readable by default; JSON with `--json` |
| `read` / `inject` with `--out` | Value only in the private file; result metadata may use JSON |
| `read` / `inject` with `--reveal` | Raw value on stdout; `--json` is refused |
| `exec` | Streams child stdout/stderr after configured redaction; `--json` is refused |
| `run` | Bounded captured child output in the result; supports `--json` |
| `juryd` | Human-readable CLI output; its HTTP API uses JSON |

For Jury command failures, exit 2 means invalid arguments or unsupported
platform, 3 means not found, 4 conflict, 5 failed authentication, and 6 denied
access. Other runtime, storage, protection, and validation failures use 1.
Handled field-input cancellation uses `128 + signal`. Successful command status
is 0. `exec` and `run` can propagate a child's nonzero status; distinguish that
from a Jury error using the command result and stderr. Parser errors never
echo supplied argument values. Streaming-command notices use stderr.

## Design constraints

- The portable encrypted vault artifact is the source of truth.
- Inside a Git worktree, the native default is a committed
  `.jury/vault.json`. Git transports and versions the encrypted artifact; Jury
  does not trust Git for authorization, integrity, or freshness.
- Private identities, rollback checkpoints, local audit, recovery material,
  and plaintext stay outside Git.
- Secrets and access policy are scoped per item, not only per vault.
- Human users and machine workloads share one principal model.
- Governed access is revision-scoped. Before opening an item revision, the
  endpoint must obtain fresh approver decisions and witness contributions for
  the exact action manifest.
- Any direct slot is optional and unilateral. An item with one carries
  no quorum claim.
- Implementing witnessed cryptography requires J19A-J19C to freeze the
  construction, protocol, vectors, and bounded endpoint-retention model, then
  J19 to bind that exact corpus after a fresh solo verification pass. This gate
  prevents drift; it is not independent security review. J19R, J19D, and J19E
  are deferred external-review work and do not gate the active `0.x` scope.
- Jury does not claim to stop an authorized endpoint from retaining plaintext
  it receives.
- Jury has no external review budget. Every `0.x` release remains explicitly
  externally unreviewed, pre-alpha, and unsuitable for real secrets.

See [docs/architecture.md](docs/architecture.md) for the initial boundaries and
[docs/naming.md](docs/naming.md) for the deliberately limited product metaphor.
The standalone witness and independent external-anchor deployment are documented
in [docs/self-hosting-juryd.md](docs/self-hosting-juryd.md).
The pre-alpha owner backup, restore, and `ExampleVault` drill procedure is in
[docs/recovery.md](docs/recovery.md).
The implementation sequence and security decisions live in
[docs/jury-v1-master-plan.md](docs/jury-v1-master-plan.md). The downstream Jig
integration remains separate in
[docs/jig-cutover-plan.md](docs/jig-cutover-plan.md).

## Workspace

The first `0.x` release targets Linux through the `jury` CLI and a self-hosted
`juryd`. The active scope defers macOS, Windows, the `jury-tui`,
hardware-backed identity protectors, managed-service topology, semantic Git
merge, and Jig-vault import. J18 rollover and suite migration are included in
Linux 0.0.1 and gate the final release candidate. The implementation has direct
and governed `jury vault rollover` flows with fresh backup,
transfer, explicit local adoption and exact-candidate recovery. Historical
bootstrap validation retains the original role proofs, policies and labels.
The checkout also implements explicit `jury vault migrate-suite --to 2`, using
AES-256-GCM HPKE under the accepted supplemental input gate. It re-encrypts
active items into a new lineage and preserves the original copies. Core direct
and governed migration tests pass, including native backup restore and witnessed
destination reads. These paths remain externally unreviewed pre-alpha software.
Capacity exhaustion
fails closed before mutation. Divergent Git artifacts
require explicit operator recovery.

| Package | Responsibility |
| --- | --- |
| `jury` | The `jury` command-line interface |
| `jury-core` | Vault-domain rules and cryptographic orchestration boundaries |
| `jury-protocol` | Witness request, approval, response, and receipt contracts |
| `jury-tui` | Deferred terminal-interface scaffold; not shipped in the first `0.x` |
| `jury-witness` | `juryd` HTTP, SQLite, identity, and external-anchor adapters |
| `jury-process` | Linux child delivery, redaction, and process-group cleanup |
| `jury-filesystem` | Hardened path, file, and atomic-publication operations |
| `jury-protected` | Bounded protected-memory primitives |

Jury is standalone and must not depend on Jig. Jig may eventually consume Jury
through its public CLI, library, or protocol interfaces.

## Development

```sh
scripts/jig bootstrap
scripts/jig check fmt
scripts/jig check clippy
scripts/jig check test
```

The repository uses Jig for repeatable development checks. Jig is not a
runtime dependency.

## Licensing

Jury is **source-available, free to self-host** under the
[Elastic License 2.0 (ELv2)](LICENSE.md), SPDX identifier `Elastic-2.0`. This applies
to the core, protocol, CLI, TUI scaffold, and witness server. ELv2 permits use,
modification, and redistribution subject to its conditions, including the
restriction on hosted or managed services that expose a substantial set of
Jury's features or functionality to third parties. Jury is not open source.

See the [licensing guide](docs/open-source.md), [copyright and third-party
notice](NOTICE.md), and [contribution requirements](CONTRIBUTING.md). Licensing
permission does not change Jury's pre-alpha status or make it suitable for real
secrets.
