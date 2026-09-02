# Self-hosting `juryd`

> [!WARNING]
> Jury is externally unreviewed pre-alpha software. It does not yet protect
> secrets and must not be used with real credentials, customer identifiers, or
> private operational details.

`juryd` is a standalone Linux witness service. Its correctness path uses only
the in-repository witness engine, SQLite, HTTP/1.1, and Rustls. It has no Jig,
managed-service, or proprietary runtime dependency.

The deployment has two independently operated services:

```text
Jury clients -- TLS + client/operator credentials --> juryd + witness SQLite
                                                       |
                                                       | TLS + anchor-write credential
                                                       v
public anchor reads --------------------------> juryd anchor + anchor SQLite
```

The witness database and external anchor must be on different failure domains,
with different administration, backup, and restore authorities. The anchor
writer must be a fourth authority label. Configuration rejects reused labels
and a reused failure-domain label. These labels are operator declarations, not
proof of real-world separation: assigning different strings to the same root
account, host, hypervisor, backup system, or recovery team violates the model.
Do not place the two services, their backups, or their restore credentials on
the same host merely because an example can run on loopback.

## Build and provision

Build the operator CLI and daemon from the checked-out source:

```console
$ cargo build --locked --release -p jury --bin jury -p jury-witness --bin juryd
$ target/release/juryd --help
```

Create a witness identity at an absolute path owned by the eventual `juryd`
user. The command prompts twice for a passphrase:

```console
$ target/release/jury identity init --kind witness \
    --identity-file /var/lib/juryd/ExampleWitness.identity.json
```

`juryd` currently ships the `software-file` identity adapter. Store the exact
identity passphrase in a separate owner-only file. The object-safe
`WitnessEngineIdentity` boundary supports an embedding-specific hardware
adapter that signs and returns an already request-session-encrypted
contribution without exporting private keys or plaintext shares; this release
does not ship a vendor HSM plugin or a `juryd` HSM configuration value.

Provision separate TLS identities for the witness and anchor hosts. Provision
three unrelated witness-side bearer credentials (client, operator, and anchor
write), each 32–256 ASCII alphanumeric, `-`, or `_` bytes. Copy the same anchor
write value to an independently owned file on the anchor host. Private inputs
must be absolute, owner-only regular files with one link; aliases and symlinks
are rejected. Never place credentials in JSON, command-line arguments, logs, or
the repository.

Start from the checked-in [witness configuration](../deploy/juryd/witness.example.json)
and [anchor configuration](../deploy/juryd/anchor.example.json). Replace every
`Example...` authority/failure-domain label with a truthful, non-sensitive
deployment label, set the public `witness_id` to the identity's exact ID, and
install the files at the absolute paths they name.

On the anchor host:

```console
$ juryd anchor init --config /etc/juryd-anchor/anchor.json
$ juryd anchor serve --config /etc/juryd-anchor/anchor.json
```

After the anchor is ready, on the witness host:

```console
$ juryd database init --config /etc/juryd/witness.json
$ juryd serve --config /etc/juryd/witness.json
```

Initialization creates an absent database atomically; it never opens an
existing target. Serving opens only an already initialized or restored
database and never creates or migrates one as a side effect. Unknown schemas,
wrong database kinds, failed SQLite integrity checks, invalid identity roles,
and unsafe database/anchor combinations fail startup.

The service-manager examples are [juryd.service](../deploy/juryd/juryd.service)
and [juryd-anchor.service](../deploy/juryd/juryd-anchor.service). Install each
unit only on its corresponding independent host. The container example in
[deploy/juryd](../deploy/juryd/README.md) builds the same binary; a container is
not a failure-domain or administrative boundary by itself.

## Transport and health contract

TLS is mandatory unless `allow_insecure_loopback` is explicitly true and the
listener is loopback. Production configurations should leave it false. The
server bounds request bodies, header-read and handler time, concurrent
requests, per-source token buckets, and the number of retained rate keys.
Malformed bodies receive a generic response that does not reflect input.
Missing and wrong credentials are indistinguishable. Protected routes verify
the bearer credential before body deserialization or admission to the shared
rate/concurrency budget. Concurrent readiness probes are single-flighted and
never enqueue duplicate database/anchor checks.

The request timeout is one end-to-end operation budget: it is attached before
handler extraction, retained while work waits in the serialized witness queue,
and shared by every external-anchor attempt. Work whose caller has gone away is
discarded before execution. `shutdown_grace_ms` must be at least
`request_timeout_ms`, so accepted work cannot extend shutdown by a fresh series
of per-step timeouts.

Witness endpoints are:

| Endpoint | Authentication | Purpose |
| --- | --- | --- |
| `GET /livez` | none | Process liveness only |
| `GET /readyz` | none | Exact database/anchor/identity/clock readiness |
| `POST /v1/operator/register` | operator | Register exact public policy material, registration bytes, and checkpoint |
| `POST /v1/operator/checkpoint` | operator | Advance an exact registered checkpoint |
| `POST /v1/operator/replay/compact` | operator | Compact only records past their retention horizon |
| `POST /v1/requests/reserve` | client | Durably reserve one request ID |
| `POST /v1/requests/decide` | client | Evaluate exact request, manifest, and approvals |
| `POST /v1/requests/cancel` | client | Cancel or return the stable too-late response |

Anchor endpoints are `GET /livez`, `GET /readyz`, and
`GET|POST /v1/anchors/{witness_id}`. Each anchor service is bound to the one
public `witness_id` in its configuration; reads for any other ID are absent and
writes are rejected. The API has no list operation. Anchor writes require that
witness's scoped write credential and perform exact authenticated monotonic
compare-and-swap. The witness reads the stored value back byte-for-byte before
acknowledging a mutation. The witness client trusts only the configured anchor
CA and does not merge it with the host's platform trust roots.

Health bodies contain only `status` and the pre-alpha maturity warning. They do
not enumerate principals, policies, vaults, items, requests, generations, or
anchor contents. Readiness may return `503` while liveness remains `200`; do not
replace that distinction with a restart loop.

The SQLite adapter caps the complete serialized witness snapshot at 64 MiB.
It rejects an operation that would cross the cap as protocol capacity
exhaustion and refuses to load an oversized snapshot before materializing its
blob. Operators must compact eligible replay records before reaching this
deployment limit; compaction never shortens the protocol retention horizon.

## Backup, restore, and rollback behavior

Back up each database to a new, absent destination under its own authority:

```console
$ juryd database backup --config /etc/juryd/witness.json \
    --output /independent-witness-backup/ExampleWitness.sqlite3
$ juryd anchor backup --config /etc/juryd-anchor/anchor.json \
    --output /independent-anchor-backup/ExampleAnchor.sqlite3
```

Backups use SQLite's consistent backup API, validate their kind/schema and
integrity, fsync the completed file, and refuse to overwrite a destination.
Do not give either backup authority the other service's backup or restore
credentials. Offline database commands project only the public database fields
from the JSON configuration: they do not open or validate the service identity,
identity passphrase, TLS private key, or bearer-credential files.

Restore with the corresponding service stopped and only to the configured
absent database path:

```console
$ juryd database restore --config /etc/juryd/witness.json \
    --backup /independent-witness-backup/ExampleWitness.sqlite3
$ juryd anchor restore --config /etc/juryd-anchor/anchor.json \
    --backup /independent-anchor-backup/ExampleAnchor.sqlite3
```

Restore never grants readiness. At startup and before request operations, the
engine compares the signed local published marker with the public external
anchor. Missing, older, newer, corrupt, conflicting, wrong-identity, or
wrong-digest state fails closed. The only split-write recovery is one exact
locally committed signed next candidate: `juryd` may publish it with monotonic
CAS, read it back exactly, then mark it published locally. It never forces,
deletes, or decrements an anchor.

SIGINT and SIGTERM stop acceptance, allow the configured grace period for
in-flight requests, and then stop the serialized identity/runtime worker. A
client that loses a response retries the same request ID; stable protocol
responses are persisted rather than recomputed as a new decision.

## Current scope boundary

This adapter can be built and operated now, including an empty ready service
and the public protocol endpoints. The end-user witnessed request/approval/open
workflow remains J22 work. Running `juryd` therefore does not make the current
`jury` client an operational witnessed-secret path and is not evidence that
Jury protects secrets.
