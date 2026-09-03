# Jury

> [!WARNING]
> Jury is a pre-alpha repository scaffold. It does not yet protect secrets and
> must not be used with real credentials.

Jury is an experimental implementation of a portable encrypted vault where
opening a governed item can require fresh approval from a jury. The project
remains on `0.x` releases; the portable artifact and witness protocol both
start at version 1. The defining release path requires signed approval and
witness contributions for the exact item revision and action before an
endpoint can open it. Direct slots remain an explicit unilateral mode and
carry no quorum claim.

## What the Linux CLI implements

The native Linux CLI currently handles:

- portable identity and vault setup;
- direct item, field, principal, and access operations;
- witnessed-policy configuration;
- controlled read and template-injection sinks;
- privacy cover and local audit verification;
- direct transparent execution and bounded brokered execution;
- signed portable-ciphertext export, inspection, and strict import;
- public witness-policy export and per-witness checkpoint propagation status;
- bounded offline inspection and verification of witnessed-decision receipts;
- public history and capacity status.

Representative commands:

```console
$ jury identity init
$ jury vault init
$ jury vault status
$ jury item create ExampleItem --allow-direct
$ jury vault field set ExampleItem ExampleField --value-stdin
$ jury principal challenge --from /absolute/path/descriptor.json \
    --out /absolute/private/path/challenge.json
$ jury access matrix
$ jury policy require witnessed --item ExampleItem \
    --approver PRINCIPAL --approvals 1 \
    --witness WITNESS_ONE --witness WITNESS_TWO --witness-quorum 2 \
    --operation read-stdout --request-lifetime 300
$ jury read ExampleItem ExampleField --out value.txt
$ jury inject --template template.txt --out rendered.txt
$ jury exec --env-file /absolute/path/to/example.env -- example-command
$ jury run --env TOKEN=ExampleItem.ExampleField --timeout 300 -- example-command
$ jury privacy cover --item ExampleItem
$ jury vault audit verify
$ jury history status
$ jury transfer export --out /absolute/path/ExampleTransfer.json
$ jury transfer inspect --in /absolute/path/ExampleTransfer.json
$ jury transfer import --in /absolute/path/ExampleTransfer.json --dry-run
$ jury transfer status
$ jury witness policy-material --output /absolute/path/ExamplePolicyMaterial.json
$ jury witness policy-status \
    --policy-material /absolute/path/ExamplePolicyMaterial.json \
    --checkpoint /absolute/path/ExampleCheckpoint.json \
    --acknowledgement /absolute/path/ExampleWitnessOneAck.json
$ jury receipt inspect /absolute/path/ExampleReceipt.json
$ jury receipt verify /absolute/path/ExampleReceipt.json \
    --checkpoint /absolute/path/ExampleCheckpoint.json
```

Inside a Git worktree, `jury vault init` writes only the encrypted
`.jury/vault.json` artifact and a fixed `.jury/.gitattributes` merge rule.
Identity files and authenticated local state stay in separate Linux data
and state roots. This storage layout is pre-alpha plumbing, not evidence that
Jury protects secrets.

The CLI can configure a witnessed-only policy, but witnessed requests,
approvals, and open execution remain J22 work. `jury transfer export` packages
the exact encrypted vault with the bounded public policy catalog required for
fresh validation; it does not include identities, audit, checkpoints, receipts,
or plaintext names. Public inspection is value-free by default, and import
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
configuration is not yet an operational secret-access path because the
end-user request/open workflow remains J22 work.

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

`jury exec` inherits the ordinary environment and stdin, removes every
`JURY_*` variable, and redacts the child's stdout and stderr independently.
`jury run` starts with a small environment allowlist, an explicit timeout, and
bounded output capture. Both commands resolve and authorize every
`Item.Field` reference before starting a child. They support protected stdin
and sealed anonymous-file delivery, and they own the Linux process group
through cleanup.

These commands implement direct access only. J22 must bind a verified action
manifest and witnessed authorization before this delivery layer may serve the
witnessed path. An authorized child can copy or retain every plaintext value
it receives.

## Target interface

```console
$ jury init
$ jury item create ExampleSecret --allow-direct
$ jury policy require witnessed --item ExampleSecret \
    --approver APPROVER_ONE --approver APPROVER_TWO --approvals 2 \
    --witness WITNESS_ONE --witness WITNESS_TWO --witness-quorum 2 \
    --operation child-environment --request-lifetime 300
$ jury request exec -- example-command
$ jury approve REQUEST_ID
$ jury request run REQUEST_ID
```

The request and approval commands above, including the request-bound execution
spellings, are design targets rather than implemented interfaces. The native
Linux CLI implements direct `jury exec` and `jury run`, along with the item and
policy configuration commands shown earlier.

## Design constraints

- The portable encrypted vault artifact is the source of truth.
- Inside a Git worktree, the intended native default is a committed
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
The implementation sequence and security decisions live in
[docs/jury-v1-master-plan.md](docs/jury-v1-master-plan.md). The downstream Jig
integration remains separate in
[docs/jig-cutover-plan.md](docs/jig-cutover-plan.md).

## Workspace

The first `0.x` release targets Linux through the `jury` CLI and a self-hosted
`juryd`. The active scope defers macOS, Windows, the `jury-tui`,
hardware-backed identity protectors, managed-service topology, semantic Git
merge, and runtime lineage rollover or suite migration. Capacity exhaustion
fails closed before mutation. Divergent Git artifacts require explicit
operator recovery.

| Package | Responsibility |
| --- | --- |
| `jury` | The `jury` command-line interface |
| `jury-core` | Vault-domain rules and cryptographic orchestration boundaries |
| `jury-protocol` | Witness request, approval, response, and receipt contracts |
| `jury-tui` | Deferred terminal-interface scaffold; not shipped in the first `0.x` |
| `jury-witness` | Transport-independent witness engine and `juryd` adapters |

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

[docs/open-source.md](docs/open-source.md) describes the intended licensing
model. The project is intended to become open source, but exact license texts
remain undecided, so this repository is not ready for public redistribution.
