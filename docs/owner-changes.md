# Changing vault owners

Jury is externally unreviewed pre-alpha software. Do not use it for real secrets.
These commands describe the current Linux CLI and use synthetic examples.

Register a human principal with `principal challenge`, `identity prove`, and
`principal add` before granting ownership. A current owner runs:

```sh
jury principal grant-owner PRINCIPAL_ID --administrative-access owner-access.json
jury principal revoke-owner PRINCIPAL_ID --administrative-access owner-access.json
```

Each command rotates every item in one vault policy revision. An owner grant
adds descriptor and body slots on items that already have direct access; it
requires `--acknowledge-direct-access` when adding that access. Witnessed-only
items remain witnessed-only. Revocation removes the former owner's direct
slots. Self-revocation and last-owner revocation are refused.

A vault containing only direct items needs no administrative access file.
For every witnessed-only item, provide exactly one descriptor entry and one
body entry. Both require an existing policy operation rule for
`administrative-rekey` with human approvals. Configure that rule when creating
the witnessed policy, alongside other intended operations, for example
`--operation read-stdout --operation administrative-rekey`. Automatic read
authority does not authorize an owner change.

The access file is strict JSON. Repeat the following pair for each
witnessed-only item, using opaque item IDs and unique, absent output paths:

```json
{
  "version": 1,
  "total_wait_seconds": 300,
  "entries": [
    {
      "item_id": "ITEM_ID",
      "content_role": "descriptor",
      "checkpoint": "current.checkpoint.json",
      "request_out": "ExampleItem.descriptor.request.json",
      "receipt": "ExampleItem.descriptor.receipt.json",
      "approvals": ["ExampleItem.descriptor.approval.json"],
      "witnesses": [
        "WITNESS_ID,https://witness.example.test,client.token,ca.pem"
      ],
      "wait_seconds": 60
    },
    {
      "item_id": "ITEM_ID",
      "content_role": "body",
      "checkpoint": "current.checkpoint.json",
      "request_out": "ExampleItem.body.request.json",
      "receipt": "ExampleItem.body.receipt.json",
      "approvals": ["ExampleItem.body.approval.json"],
      "witnesses": [
        "WITNESS_ID,https://witness.example.test,client.token,ca.pem"
      ],
      "wait_seconds": 60
    }
  ]
}
```

Replace the placeholders and list enough witnesses and approval paths to meet
each policy's thresholds. Relative paths resolve from the command's working
directory. `total_wait_seconds` is required (1–86400); it bounds the collection
of witnessed authorizations for the entire batch. Each entry's required
`wait_seconds` is 0–900. Request expiry can end the wait sooner. The optional
`allow_insecure_loopback: true` is for synthetic testing with literal loopback
IP addresses only.

Keep the owner command running. It publishes a fresh descriptor request and
then a fresh body request for each item, in ascending item-ID order. In another
terminal, each required approver reviews and signs the published request:

```sh
jury --identity ExampleApprover approve ExampleItem.descriptor.request.json \
  --out ExampleItem.descriptor.approval.json
```

Repeat for the body and subsequent items as their requests appear. The approval
summary identifies the content role, grant or revoke intent, target principal,
and next vault policy sequence. Public labels and policy terms are retained;
successful changes issue fresh owner-signed labels and successor witness
policies bound to the new revision. Label expiry is preserved. An expired active
label stops the command before requests are published; a label expiring during
collection also prevents the mutation. The current CLI creates labels without
expiry, but imported policies can contain expiring labels. There is no general
CLI renewal command for a witnessed-only item; an expired imported label is an
operational limit, not a reason to reset witnesses or add direct access.

All required content must open successfully before any vault mutation commits.
Denied, expired, or incomplete authorization leaves the vault unchanged.
Already completed authorizations may leave public requests, decisions, and
receipts, including with `--dry-run`. A dry run performs the actual authorized
opens and prepares the mutation without committing it. Use fresh absent
request and receipt paths for each retry.

After a successful change, export a checkpoint with
`jury witness checkpoint --predecessor current.checkpoint.json --out next.checkpoint.json`
and current material with `jury witness policy-material --out next.material.json`.
Propagate them to every active witness before requesting access at the new
revision, following the [operator walkthrough](witness-operator-walkthrough.md).
Witnesses require the next consecutive revision and the exact predecessor.

An authorization proves permission to open the named current content for the
specified intent. It cannot force a compromised endpoint to perform the owner
change or erase content it previously opened. Revocation does not erase copies
already retained by an authorized endpoint.

An offline receipt verifies the content-opening authorization. It does not
prove that the owner mutation committed; inspect the signed vault policy for
that result.
