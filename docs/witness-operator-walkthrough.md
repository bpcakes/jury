# Linux witness operator walkthrough

Jury is externally unreviewed pre-alpha software. Use only synthetic data.
This walkthrough does not establish that Jury protects secrets.

Use the same vault installation for the owner commands below. Create a private
output directory outside the Git worktree with mode `0700` and a separate public
artifact directory, also mode `0700` and outside the worktree. Public artifacts
use the same hardened output checks. For example, set `PUBLIC` to a fresh absolute
path and run `mkdir -m 700 "$PUBLIC"`. Paths below are absolute. Identity passphrases are entered
at hidden terminal prompts. Do not put them in command arguments.

## Register the actors and apply a policy

Initialize the owner and vault if they do not exist:

```sh
jury identity init
jury vault init
jury item create ExampleItem --allow-direct
jury vault field set ExampleItem ExampleField
```

Enter a synthetic value of at least four bytes at the last command, then press
Ctrl-D to finish. Enter adds a newline to the value. For piped input, supply
`--value-stdin`. Save the `item_id` returned
by item creation as `ITEM_ID`. For each actor, run the descriptor/proof exchange
below. Use `ExampleApprover` with kind `approver`, then `ExampleWitnessOne` and
`ExampleWitnessTwo` with kind `witness`. This single-host exercise keeps all
actor keys under the same user account and demonstrates no separation of authority:

```sh
jury identity init --name "$ACTOR" --kind "$KIND"
jury --identity "$ACTOR" identity public --out "$PUBLIC/$ACTOR.descriptor.json"

# Owner: INDEX is 1 or 2 for witnesses; the approver has no share index.
if [ "$KIND" = witness ]; then
  jury principal challenge --from "$PUBLIC/$ACTOR.descriptor.json" \
    --out "$PUBLIC/$ACTOR.challenge.json" --witness-share-index "$INDEX"
else
  jury principal challenge --from "$PUBLIC/$ACTOR.descriptor.json" \
    --out "$PUBLIC/$ACTOR.challenge.json"
fi

jury --identity "$ACTOR" identity prove \
  --challenge "$PUBLIC/$ACTOR.challenge.json" --out "$PUBLIC/$ACTOR.proof.json"
jury principal add --from "$PUBLIC/$ACTOR.descriptor.json" \
  --proof "$PUBLIC/$ACTOR.proof.json"
```

`ACTOR`, `KIND`, `INDEX`, and `PUBLIC` are shell variables set for the selected
actor and your absolute artifact directory. Record the principal ID printed by
each `identity init` as `APPROVER_ID`, `WITNESS_ONE_ID`, or `WITNESS_TWO_ID`.

For separate hosts, complete these registrations **before applying the witnessed
policy**. Each actor creates its identity on its own host and sends its public
descriptor to the owner. After issuing that actor's challenge, the owner supplies
the current encrypted `.jury` vault snapshot and challenge. On the actor host,
initialize a fresh Git worktree, place that snapshot at `.jury`, and run
`identity prove` from that worktree using the actor's own identity. Return the
proof to the owner for `principal add`. Repeat with the current snapshot for each
actor; a snapshot from before another registration can be stale. This initial
bootstrap needs no owner identity or local state. Do not copy private identities
into the public directory. Later onboarding after a witnessed policy is applied
also needs policy material; the remote import procedure under
[Read with two terminals](#read-with-two-terminals) installs it for an already
registered role.

```sh
jury policy require witnessed --item ExampleItem \
  --approver "$APPROVER_ID" --approvals 1 \
  --witness "$WITNESS_ONE_ID" --witness "$WITNESS_TWO_ID" --witness-quorum 2 \
  --operation read-stdout --review-label ExampleItem \
  --field-review-label ExampleField=ExampleField --request-lifetime 300
jury witness policy-material --output "$PUBLIC/ExamplePolicy.json"
jury witness checkpoint --output "$PUBLIC/ExampleCheckpoint.json"
```

The review labels are deliberately public. Using synthetic private names as
public labels is convenient here; do not publish private names in a real design.
The policy removes unilateral access to this item's current descriptor/body.
Choose all needed operations now: for private-file reads include
`--operation write-private-file`; for later owner changes include
`--operation administrative-rekey`. The CLI cannot reopen a witnessed-only item
to replace its policy through another `policy require witnessed` call. See the
[current rotation limits](self-hosting-juryd.md#witness-key-rotation-retirement-and-recovery).
Adding another item afterward needs [descriptor authorization](item-creation.md).

## Start and register each witness

Follow [Build and provision](self-hosting-juryd.md#build-and-provision) for each
witness/anchor pair: install its exact witness identity and private input files,
set its public ID in both configuration files, initialize both databases, then
start the anchor before the witness. Use the example configurations' supported
schema. Separate authority labels alone do not make loopback services separate
authorities. Loopback is only a synthetic exercise.

A running service is not yet registered for the vault. Save the following as
`operator-post.py` outside the worktree. It sends an exact registration or
checkpoint payload, reads the operator credential from a file, and preserves
the complete wrapped acknowledgement in a new file. It never prints credentials
or sends them in process arguments. Supply an explicit CA file for HTTPS. For
synthetic literal-IP loopback HTTP only, set `JURY_EXAMPLE_LOOPBACK=1` and pass
`-` for the CA argument. This flag does not change the service configuration.

```python
import base64
import json
import os
from pathlib import Path
import ssl
import stat
import sys
import urllib.parse
import urllib.request

# action, base URL, credential file, CA file, policy file, checkpoint file,
# accepted witness proof file (or '-' for checkpoint), absent acknowledgement file
(action, base, credential, ca, policy, checkpoint, proof, output) = sys.argv[1:]
if action not in ("register", "checkpoint"):
    raise SystemExit("action must be register or checkpoint")
try:
    url = urllib.parse.urlsplit(base)
    host = url.hostname
    port = url.port
except ValueError:
    raise SystemExit("supply a valid witness origin and port") from None
if not host:
    raise SystemExit("supply a witness origin with a host")
if url.username or url.password or url.query or url.fragment or url.path not in ("", "/"):
    raise SystemExit("supply a witness origin without credentials, path, query or fragment")
if url.scheme != "https":
    loopback = host in ("127.0.0.1", "::1")
    if (url.scheme != "http" or os.environ.get("JURY_EXAMPLE_LOOPBACK") != "1"
            or not loopback):
        raise SystemExit("HTTPS required; HTTP is only for explicitly selected literal-IP loopback")
if url.scheme == "https" and ca == "-":
    raise SystemExit("HTTPS requires an explicit CA certificate file")
context = ssl.create_default_context(cafile=ca) if url.scheme == "https" else None
payload = {"policy_material": json.loads(Path(policy).read_bytes()),
           "checkpoint": json.loads(Path(checkpoint).read_bytes())}
if action == "register":
    # Encode the exact accepted proof file bytes, not a reserialized JSON value.
    payload["accepted_registration"] = base64.b64encode(Path(proof).read_bytes()).decode("ascii")
if not Path(credential).is_absolute():
    raise SystemExit("operator credential must use an absolute path")
try:
    descriptor = os.open(credential, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(descriptor, "rb") as source:
        info = os.fstat(source.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_mode & 0o077 or info.st_uid != os.geteuid()):
            raise SystemExit("operator credential must be an owner-only regular file without links")
        token_bytes = source.read(259)
except OSError:
    raise SystemExit("cannot open the operator credential as a private regular file") from None
if len(token_bytes) > 258:
    raise SystemExit("operator credential file exceeds 258 bytes")
token_bytes = token_bytes.rstrip(b"\r\n")
if (not 32 <= len(token_bytes) <= 256
        or any(byte not in b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
               for byte in token_bytes)):
    raise SystemExit("operator credential must be 32..256 allowed ASCII bytes, with optional trailing CR/LF")
token = token_bytes.decode("ascii")
request = urllib.request.Request(base.rstrip("/") + "/v1/operator/" + action,
    data=json.dumps(payload).encode(), method="POST",
    headers={"Content-Type": "application/json", "Authorization": "Bearer " + token})
# No inherited proxy or redirect: credentials belong to this exact witness origin.
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(),
                                     urllib.request.HTTPSHandler(context=context))
with opener.open(request, timeout=20) as response:
    raw = response.read(1048577)
if len(raw) > 1048576:
    raise SystemExit("acknowledgement exceeds the response bound")
ack = json.loads(raw)
if ack.get("durability") != "witness-database-and-external-anchor-readback":
    raise SystemExit("witness did not acknowledge durable registration/checkpoint")
with open(output, "xb") as destination:
    destination.write(raw)
print("Saved acknowledgement; verify it with jury witness policy-status.")
```

Repeat the registration for each witness with its own URL, operator credential,
CA certificate, proof, and output path. Set `ACTOR` to that witness name,
`WITNESS_URL` to its configured listen origin, `OPERATOR_CREDENTIAL_FILE` to its
configured operator credential file, and `CA_FILE` to the CA that authenticates
its TLS certificate (`-` for the explicit loopback exercise). The proof must
belong to that witness:

```sh
umask 077
python3 operator-post.py register "$WITNESS_URL" "$OPERATOR_CREDENTIAL_FILE" \
  "$CA_FILE" "$PUBLIC/ExamplePolicy.json" "$PUBLIC/ExampleCheckpoint.json" \
  "$PUBLIC/$ACTOR.proof.json" "$PUBLIC/$ACTOR.ack.json"
```

After both witnesses have acknowledged, run once:

```sh
jury --json witness policy-status --policy-material "$PUBLIC/ExamplePolicy.json" \
  --checkpoint "$PUBLIC/ExampleCheckpoint.json" \
  --acknowledgement "$PUBLIC/ExampleWitnessOne.ack.json" \
  --acknowledgement "$PUBLIC/ExampleWitnessTwo.ack.json"
```

Proceed when the status is `durably-accepted`. This verifies the supplied signed
acknowledgements; it does not promise continuing reachability or global freshness.

## Read with two terminals

Before approving on a separate installation, transfer the current signed public
vault and policy catalog. On the owner installation, export after registering
the approver and configuring its witnessed policy:

```sh
jury transfer export --out ./ExampleVault.transfer.json
```

Deliver that public artifact to the approver. On the approver installation,
select its own encrypted identity and import into the intended vault home:

```sh
jury --identity ExampleApprover --expected-genesis "$GENESIS" \
  transfer import --in ./ExampleVault.transfer.json --allow-no-access --dry-run
jury --identity ExampleApprover --expected-genesis "$GENESIS" \
  transfer import --in ./ExampleVault.transfer.json --allow-no-access
jury --identity ExampleApprover vault audit verify
```

Verify `GENESIS` through your separate trusted channel before first import.
Import authenticates the selected registered role and creates its local state;
`--allow-no-access` acknowledges that the approver cannot decrypt item names or
contents. Repeat import with a fresh export when the public policy changes.
A request alone does not update the approver's local policy. Witness identities
can use the same import flow for their own local state; daemon registration and
external-anchor setup remain separate steps.

The two-terminal commands below assume a shared `$PUBLIC` directory. If the
terminals run on separate installations, deliver the request artifact to the
approver, then deliver its signed approval back to the owner's `--approval`
path while the foreground operation is waiting. The paths are local to each
installation; Jury does not transport these files for you.

The owner supplies the **client** credential files in endpoint tuples, not the
operator credentials. HTTPS endpoints require an explicit CA path; only loopback HTTP omits it:
`WITNESS_ID,BASE_URL,CREDENTIAL_FILE[,CA_CERTIFICATE]`. Quote the whole tuple.
Set `WITNESS_ONE_URL` and `WITNESS_TWO_URL` to the registered service origins,
`CLIENT_ONE_FILE` and `CLIENT_TWO_FILE` to their configured client credential
files, and `CA_ONE_FILE` and `CA_TWO_FILE` to their CA files. For loopback HTTP,
omit the fourth tuple component and also supply `--allow-insecure-loopback`
to the owner command.

```sh
# Owner terminal: keep this process running. Use fresh absent artifact paths.
jury read ExampleItem ExampleField --reveal \
  --checkpoint "$PUBLIC/ExampleCheckpoint.json" \
  --request-out "$PUBLIC/ExampleRead.request.json" \
  --approval "$PUBLIC/ExampleRead.approval.json" \
  --receipt "$PUBLIC/ExampleRead.receipt.json" --wait-seconds 300 \
  --witness "$WITNESS_ONE_ID,$WITNESS_ONE_URL,$CLIENT_ONE_FILE,$CA_ONE_FILE" \
  --witness "$WITNESS_TWO_ID,$WITNESS_TWO_URL,$CLIENT_TWO_FILE,$CA_TWO_FILE"

# Approver terminal: read the review, then type approve at confirmation.
# This requires terminal stdin; the passphrase prompt follows confirmation.
jury --identity ExampleApprover approve "$PUBLIC/ExampleRead.request.json" \
  --out "$PUBLIC/ExampleRead.approval.json"

# After the owner read succeeds:
jury receipt verify "$PUBLIC/ExampleRead.receipt.json" \
  --checkpoint "$PUBLIC/ExampleCheckpoint.json"
```

The owner receives raw synthetic field bytes on stdout. For private-file output,
add `write-private-file` when initially setting the policy, then replace
`--reveal` with `--out /absolute/private/ExampleOutput`; its parent must be outside
the worktree and local identity/state trees. Do not use `--json` with `--reveal`.

A detached `jury request create` artifact supports inspection/status/cancellation;
it cannot resume a later execution. `read`, `inject`, `run`, `exec`, and
`request execute` each create a fresh request and retain its session key only in
the running process. Retries need fresh request/approval/receipt paths and fresh
approval. The wait is bounded to 900 seconds and also by request expiry.

To deny, the approver adds `--deny` and types `deny` at the confirmation prompt.
Approval and denial require a terminal; neither accepts a piped confirmation. To cancel a published request, the owner can
run `jury request cancel REQUEST --out ABSENT_CANCELLATION_FILE` with the same
witness tuples (and explicit loopback flag when applicable) in another terminal.
Inspect the reported cancellation phase: `cancelled` means every selected
witness acknowledged; `quorum-precluded` means enough acknowledged to prevent
a quorum; `partial` leaves quorum prevention unconfirmed; `too-late` means a
witness had already responded.
Stopping the foreground process alone does not promise durable cancellation.

## Propagate a later checkpoint

After each individual vault mutation, export new policy material and a checkpoint
chained from the previous one. Propagate before another mutation: skipped vault
policy sequences are refused. Use new output names. Export one checkpoint for
the whole vault revision and distribute that exact file to every active witness,
including when a witness pair serves several item policies. Public label text
may repeat across policies; use `--item-id` and `--field-id` when labels are
ambiguous on read/request commands that expose those flags, or assign distinct
public labels initially. Combined template/child references use exact public
labels, with a JSON pair for labels outside the native name profile, for example
`--stdin '["Example Item","Example Field"]'`. Duplicate public labels cannot be
disambiguated by that pair. Each request still
uses only its selected item policy and its required approvals:

```sh
jury witness policy-material --output "$PUBLIC/ExamplePolicyNext.json"
jury witness checkpoint \
  --predecessor "$PUBLIC/ExampleCheckpoint.json" --output "$PUBLIC/ExampleCheckpointNext.json"
python3 operator-post.py checkpoint "$WITNESS_URL" "$OPERATOR_CREDENTIAL_FILE" \
  "$CA_FILE" "$PUBLIC/ExamplePolicyNext.json" "$PUBLIC/ExampleCheckpointNext.json" \
  - "$PUBLIC/$ACTOR.next-ack.json"
```

Repeat the POST for each witness and verify the new material, checkpoint, and
acknowledgements with `witness policy-status`. A successful HTTP response alone
is not enough. All subsequent requests must use `ExampleCheckpointNext.json`;
keep earlier public artifacts for historical receipt verification.

A witness that first joins an already governed vault uses `register` with its
accepted proof and the same current chained checkpoint delivered to existing
witnesses. Existing witnesses use `checkpoint`. Do not create a separate
zero-predecessor checkpoint for the new member or reset an existing database.
First registration establishes that witness's local starting point; it does not
prove global freshness. Later changes must follow its stored checkpoint exactly.
