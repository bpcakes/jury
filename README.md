# Jury

**A portable encrypted vault where opening can require a jury.**

Jury is an experimental witnessed-access vault intended to be open source.
Product releases remain `0.x`; the portable artifact and witness protocol both
begin at version 1. The defining release path requires fresh signed approval
and witness contributions before an endpoint can open a governed item revision.
Direct slots remain an explicit unilateral mode, not the product's authority
claim.

> [!WARNING]
> Jury is a pre-alpha repository scaffold. It does not yet protect secrets and
> must not be used with real credentials.

## Available native Linux CLI

The Linux CLI now covers portable identity and vault setup, direct item and
field operations, principal/access administration, witnessed-policy
configuration, controlled read/injection sinks, privacy cover, audit
verification, direct transparent execution, bounded brokered execution, and
public history/capacity status. Representative commands are:

```console
$ jury identity init
$ jury vault init
$ jury vault status
$ jury item create ExampleItem --allow-direct
$ jury vault field set ExampleItem ExampleField --value-stdin
$ jury principal challenge --from descriptor.json --out challenge.json
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
```

Inside a Git worktree, vault initialization writes only encrypted
`.jury/vault.json` and the fixed `.jury/.gitattributes` merge rule. Identities
and authenticated local state stay in their separate Linux data/state roots.
This is still pre-alpha plumbing, not a claim that Jury protects secrets.
Witnessed-only policy can be configured, but witnessed request, approval, and
open execution remain J22 work. The signed public role descriptors and policy
bodies used by the current CLI are local state; J16/J23 own their portable
distribution. Do not treat a witnessed-only configuration as an operational
secret-access path yet.

`jury exec` inherits the ordinary environment and stdin, removes every
`JURY_*` variable, and streams independently redacted child output. `jury run`
starts from a small environment allowlist and uses an
explicit timeout plus bounded captured output. Both commands authorize and
resolve every `Item.Field` reference before starting a child, support protected
stdin and sealed anonymous-file delivery, and own the resulting Linux process
group through cleanup. These are direct-access pre-alpha mechanics, not the
witnessed execution path: J22 must bind a verified action manifest and witnessed
authorization before the same delivery layer may spawn. An authorized child
can copy or retain every plaintext value it receives.

## Intended experience

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

The request and approval commands in this example, including their request-
bound execution spellings, are design targets rather than implemented
interfaces. Direct `jury exec` and `jury run`, plus the item and policy
configuration commands above, are implemented native Linux commands.

## Design principles

- The encrypted vault artifact remains portable and is the source of truth.
- Inside a Git worktree, the intended native default is a committed
  `.jury/vault.json`; Git transports and versions the encrypted artifact but is
  never trusted for Jury authorization, integrity, or freshness.
- Private identities, rollback checkpoints, local audit, recovery material, and
  plaintext remain outside Git.
- Secrets and access policy are scoped per item, not only per vault.
- Human users and machine workloads use the same principal model.
- Governed access is revision-scoped: the endpoint must obtain fresh approver
  decisions and witness contributions for the exact action manifest before it
  can open that item revision.
- Direct slots are optional and unilateral. If an item has one, Jury makes no
  quorum claim for that item.
- Witnessed cryptography may not be implemented until J19A-J19C freeze the
  construction, protocol, vectors, and bounded endpoint-retention model and J19
  binds that exact corpus after a fresh solo verification pass. This
  drift-prevention gate is not independent security review. J19R/J19D/J19E
  external-review work is deferred and does not gate the active `0.x` scope.
- Jury does not claim to prevent an authorized endpoint from retaining
  plaintext it is allowed to receive.
- Jury has no external review budget. Every `0.x` release must remain explicitly
  externally unreviewed, pre-alpha, and unsuitable for real secrets.

See [docs/architecture.md](docs/architecture.md) for the initial boundaries and
[docs/naming.md](docs/naming.md) for the deliberately limited product metaphor.

The implementation sequence and security decisions are in
[docs/jury-v1-master-plan.md](docs/jury-v1-master-plan.md). The downstream Jig
integration is intentionally separate in
[docs/jig-cutover-plan.md](docs/jig-cutover-plan.md).

## Workspace

The first `0.x` release targets Linux through the `jury` CLI and a self-hosted
`juryd`. macOS, Windows, the `jury-tui`, hardware-backed identity protectors,
managed-service topology, semantic Git merge, and runtime lineage rollover or
suite migration are deferred. Capacity exhaustion fails closed before mutation;
divergent Git artifacts require explicit operator recovery.

| Package | Responsibility |
| --- | --- |
| `jury` | The `jury` command-line interface |
| `jury-core` | Vault-domain rules and cryptographic orchestration boundaries |
| `jury-protocol` | Witness request, approval, response, and receipt contracts |
| `jury-tui` | Deferred terminal-interface scaffold; not shipped in the first `0.x` |
| `jury-witness` | Transport-independent witness engine and `juryd` adapters |

Jury is standalone: it must not depend on Jig. Jig may eventually consume Jury
through its public CLI, library, or protocol interfaces.

## Development

```sh
scripts/jig bootstrap
scripts/jig check fmt
scripts/jig check clippy
scripts/jig check test
```

The repository uses the Jig development harness for repeatable checks; that is
tooling, not a runtime product dependency.

## Licensing

The intended licensing model is documented in
[docs/open-source.md](docs/open-source.md). Exact license texts have not yet
been selected, so this repository is not ready for public redistribution.
