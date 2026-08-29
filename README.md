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

## Intended experience

```console
$ jury init
$ jury put ExampleSecret
$ jury policy require --approvers 2 --witnesses 3
$ jury request exec -- example-command
$ jury approve REQUEST_ID
$ jury request run REQUEST_ID
```

These product commands are design targets, not implemented interfaces.
Currently, `jury --help` and `jury --version` only identify the scaffold.

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
  construction, protocol, vectors, and endpoint-retention proof, J19D completes
  independent review, and J19 binds that exact corpus in the machine gate.
- Jury does not claim to prevent an authorized endpoint from retaining
  plaintext it is allowed to receive.

See [docs/architecture.md](docs/architecture.md) for the initial boundaries and
[docs/naming.md](docs/naming.md) for the deliberately limited product metaphor.

The implementation sequence and security decisions are in
[docs/jury-v1-master-plan.md](docs/jury-v1-master-plan.md). The downstream Jig
integration is intentionally separate in
[docs/jig-cutover-plan.md](docs/jig-cutover-plan.md).

## Workspace

| Package | Responsibility |
| --- | --- |
| `jury` | The `jury` command-line interface |
| `jury-core` | Vault-domain rules and cryptographic orchestration boundaries |
| `jury-protocol` | Witness request, approval, response, and receipt contracts |
| `jury-tui` | Keyboard-first terminal interface |
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
