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

This diagram is one witness pair, not the complete quorum. A bounded `0.x`
deployment repeats the pair for each active witness descriptor: 2–32 witnesses,
with a threshold from 2 through the member count. Each `juryd` instance owns one
witness identity, one replay/checkpoint database, and one independently operated
external anchor. Witness instances are also separate from one another and from
the requesting endpoint. A single witness receives only its encrypted share and
cannot reconstruct a threshold-2-or-greater revision secret by itself. These are
declared self-hosting boundaries, not a managed topology or evidence that the
pre-alpha system protects secrets.

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
$ sudo -u juryd-anchor -- juryd anchor init --config /etc/juryd-anchor/anchor.json
$ sudo -u juryd-anchor -- juryd anchor serve --config /etc/juryd-anchor/anchor.json
```

After the anchor is ready, on the witness host:

```console
$ sudo -u juryd -- juryd database init --config /etc/juryd/witness.json
$ sudo -u juryd -- juryd serve --config /etc/juryd/witness.json
```

Initialization creates an absent database atomically; it never opens an
existing target. Serving opens only an already initialized or restored
database and never creates or migrates one as a side effect. Unknown schemas,
wrong database kinds, failed SQLite integrity checks, invalid identity roles,
and unsafe database/anchor combinations fail startup.

The service-manager examples are [juryd.service](../deploy/juryd/juryd.service)
and [juryd-anchor.service](../deploy/juryd/juryd-anchor.service). Install each
unit only on its corresponding independent host. Their `StateDirectoryMode`
is `0700`, matching the database parent's owner-only invariant; run each init
command as the same service account named by its unit. The container example in
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
consumed by SQLite lock acquisition and pre-commit checks, and shared by every
external-anchor attempt. Work whose caller has gone away is discarded before
execution. The anchor database also has one serialized owner thread; public
readiness performs a real bounded repository read without blocking a Tokio
worker. `shutdown_grace_ms` must be at least `request_timeout_ms`, so accepted
work cannot extend shutdown by a fresh series of per-step timeouts.

Witness endpoints are:

| Endpoint | Authentication | Purpose |
| --- | --- | --- |
| `GET /livez` | none | Process liveness only |
| `GET /readyz` | none | Exact database/anchor/identity/clock readiness |
| `POST /v1/operator/register` | operator | Register exact public policy material, registration bytes, and checkpoint |
| `POST /v1/operator/checkpoint` | operator | Advance an exact registered checkpoint |
| `GET /v1/operator/status` | operator | Return value-free state counts and this witness's one signed anchor containing its exact per-vault checkpoint watermarks |
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

Anchor request and response artifacts have one fixed 1 MiB wire cap. The
witness checks both compact CAS directions before committing a new local
candidate, and the anchor service requires that exact request-body limit. An
oversized next anchor is refused as capacity exhaustion without changing local
state, so operators cannot repair it by widening only one transport setting.

Successful register and checkpoint responses contain a signed
`acknowledgement`, report durability as
`witness-database-and-external-anchor-readback`, and set
`global_freshness_claimed` to `false`. Preserve each response as public evidence;
an HTTP success code or operator credential alone is not a checkpoint
acknowledgement.

Health bodies contain only `status` and the pre-alpha maturity warning. They do
not enumerate principals, policies, vaults, items, requests, generations, or
anchor contents. Readiness may return `503` while liveness remains `200`; do not
replace that distinction with a restart loop.

Authenticated operator status is deliberately different from public health. It
reports this witness's state generation, bounded counts, retention horizon, and
per-vault checkpoint acknowledgement, but no registration bytes, policy
material, request IDs, approvals, contributions, or item/principal names. It is
not an aggregate view and always reports `global_freshness_claimed: false`.

For an offline, value-free inventory of a stopped or copied witness database:

```console
$ juryd database audit --config /etc/juryd/witness.json \
    --output /absolute/public/path/ExampleWitnessAudit.json
```

The destination must be absent. The command does not open identity, TLS-key, or
bearer-credential files, does not compare the external anchor, and does not
claim contribution readiness.

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

## Policy distribution and propagation status

Export the exact compact public policy bundle from the vault installation:

```console
$ jury witness policy-material \
    --output /absolute/public/path/ExamplePolicyMaterial.json
```

Distribute that exact file, the signed checkpoint, and the exact registration
or checkpoint request to each independently administered witness. Keep every
accepted response separately. Then classify only the evidence in hand:

```console
$ jury witness policy-status \
    --policy-material /absolute/public/path/ExamplePolicyMaterial.json \
    --checkpoint /absolute/public/path/ExampleCheckpoint.json \
    --acknowledgement /absolute/public/path/ExampleWitnessOneAck.json \
    --acknowledgement /absolute/public/path/ExampleWitnessTwoAck.json
```

With no acknowledgements the status is `proposed`; with a nonempty strict subset
it is `partially-propagated`; only exact signed acknowledgements from every
active witness produce `durably-accepted`. That last state means each named
witness durably committed and read back the supplied checkpoint when it signed
its anchor. It is not a claim that all witnesses remain reachable, mutually
synchronized, or globally fresh afterward.

## Witness key rotation, retirement, and recovery

Signing-key, contribution-key, membership, threshold, or share-index changes
are full prospective rotations. Create and register a fresh witness identity,
then rerun `jury policy require witnessed` for each governed item with the exact
next witness set. The mutation creates a new item key epoch, descriptor and body
seals, shares, and capsules. Distribute the next policy/checkpoint and wait for
the required per-witness acknowledgements before relying on it. Retain old
public policy material, checkpoints, descriptors, and receipts so historical
receipt signatures remain verifiable. Old private keys may still open old
capsules retained in history; rotation does not erase that exposure.

Do not replace the key file underneath an active witness identity or initialize
an empty database for its old ID. A same-identity restore is valid only with the
exact protected identity, replay/checkpoint database, and matching external
anchor described above. If that continuity cannot be proved, recovery uses a
new witness ID, a new initial registration and anchor, an owner-signed
`WitnessRecoveryV1` statement, and the complete owner-signed
`WitnessPolicyRotationV1` item reseal. The old ID is retired from the next active
policy. Missing quorum makes the item unavailable; recovery never lowers the
threshold, resets replay/checkpoint state, synthesizes a share, or adds a direct
slot.

## Retention, compaction, receipts, and transparency

Replay records remain until strictly after request expiry plus 86,400,000 ms,
and only then become eligible for authenticated compaction. A compact operation
is itself committed as a new state generation and externally anchored before
the service responds. Operators may retain records longer but cannot configure
a shorter protocol horizon.

Receipts are bounded public JSON and contain decisions rather than contribution
envelopes. Verify them without a network connection or private identity:

```console
$ jury receipt inspect /absolute/public/path/ExampleReceipt.json
$ jury receipt verify /absolute/public/path/ExampleReceipt.json \
    --checkpoint /absolute/public/path/ExampleCheckpoint.json
```

`inspect` reports unverified structure. `verify` checks the embedded public
policy replay, requester/approver/witness signatures, counted identities,
manifest and checkpoint digests, and witness state generations. It proves those
decisions only—not endpoint execution, output, non-exfiltration, or forgetting.

For additional transparency, operators may publish the exact public policy
bundles, checkpoints, per-witness acknowledgements, signed state anchors,
rotation/recovery records, and receipts to an append-only archive under a
separate authority. The active `0.x` release has no transparency-log service,
global-consistency protocol, managed topology, or freshness oracle. An archive
is useful retained evidence; it does not change authorization or repair a stale
witness.

## Current scope boundary

This adapter and the J23 receipt/operations surfaces can be built and operated
now. The end-user witnessed request/approval/open workflow remains J22 work.
Running `juryd`, collecting acknowledgements, or verifying a receipt therefore
does not make the current `jury` client an operational witnessed-secret path and
is not evidence that Jury protects secrets.
