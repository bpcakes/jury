# Creating an item in a governed vault

Jury is externally unreviewed pre-alpha software. Use only synthetic data;
it does not protect real secrets.

Item creation checks every active canonical name for uniqueness. The owner can
open direct descriptors locally. A witnessed-only descriptor needs a fresh
witnessed read: being the owner does not bypass the item's witness policy.
Bodies and fields are not opened for this check, and no direct slot is added to
an existing item.

For a human-approval policy, permit `read-stdout` and provide owner-signed
item/field review labels when setting up the policy. The approver must check the
prominent content-role line: a name check requests **DESCRIPTOR**, not **BODY**.
The complete manifest is also displayed and bound by the signed decision.

For an automatic policy, `--automatic-read ExampleField` declares two separate
permissions: the exact body field and the item descriptor (name and field
metadata). `--automatic-descriptor` declares descriptor permission alone.
Both require the current principal's entitlement and a fresh live witness quorum.
A descriptor target cannot authorize body contents, and a field target cannot
authorize any other field. Automatic whole-body permission is unsupported.
These are the initial 0.0.1 semantics; old role-implicit policies and the former
`--automatic-read-item` option are rejected without compatibility or migration.

Create a JSON access plan with one entry for every descriptor that is not
directly accessible. Use the item's ID from its creation result, the current
owner-signed checkpoint, and the endpoint tuple documented in the self-hosting
guide. For example:

```json
{
  "version": 1,
  "total_wait_seconds": 300,
  "entries": [{
    "item_id": "ITEM_ID_HEX",
    "checkpoint": "/absolute/public/ExampleCheckpoint.json",
    "request_out": "/absolute/public/ExampleNameRequest.json",
    "receipt": "/absolute/public/ExampleNameReceipt.json",
    "approvals": ["/absolute/public/ExampleNameApproval.json"],
    "witnesses": [
      "WITNESS_ONE_ID,https://witness-one.example:7443,/absolute/private/client-one,/absolute/public/ca-one.pem",
      "WITNESS_TWO_ID,https://witness-two.example:7443,/absolute/private/client-two,/absolute/public/ca-two.pem"
    ],
    "wait_seconds": 300
  }]
}
```

Replace the public ID placeholders and paths with the synthetic installation's
actual values. The file is bounded to 1 MiB and 1,024 entries. `total_wait_seconds` defaults
to 300 and must be 1..=86400; each entry's wait is capped by the remaining batch
budget. No new transport call or approval wait starts after that budget. A
transport call already in progress may finish after it; a completed final
authorization is retained. Use a larger explicit aggregate budget for many
governed items; each individual approval wait remains at most 900 seconds. Unknown fields,
duplicate IDs, extra/missing entries, and repeated output paths are refused.
Request and receipt paths must be absent; an existing destination returns
`already-exists` (exit 4), separately from a malformed plan (exit 2). Approval files may be created while
the command waits. An automatic descriptor permission needs no approval files; this includes the
descriptor permission added by `--automatic-read FIELD`.
`allow_insecure_loopback` defaults to false; it exists only for explicit
synthetic loopback testing.

```console
# Owner terminal: keep this process running while approvals are collected.
jury item create ExampleNext --allow-direct \
  --descriptor-access /absolute/public/ExampleNameAccess.json

# Separate approver terminal, after each request file appears:
jury --identity ExampleApprover approve /absolute/public/ExampleNameRequest.json \
  --out /absolute/public/ExampleNameApproval.json
```

The requests use the existing descriptor `read-stdout` authority. Their
plaintext results are consumed in memory by the owner name check; they are not
printed or cached. Approvers review the exact descriptor target and policy,
not a body field. Each completed descriptor read produces a verifiable public
receipt. A receipt proves a witnessed decision, not that item creation happened.

Directly visible duplicate names and invalid local creation arguments are
rejected before contacting witnesses. All descriptors must be authenticated
before the new item is committed. Reads are sequential: N governed descriptors
need N fresh decisions, and each name check is O(N). A failure discards the
in-memory access state; retrying repeats the earlier reads and approvals.
Completed receipts cannot resume access because they contain no session key or
reusable authority. The batch budget limits waiting, not the cost of retries. A
duplicate name, denial, missing permission, expired request, or unavailable
quorum prevents creation. Requests and completed receipts may remain after a
refusal; retry with fresh output paths. No request-session private key is saved.
`--dry-run` also performs the real authorization/name check but does not write
the vault.

The access plan never grants new authority. A policy built outside the CLI
that lacks a descriptor target still cannot complete this check. Do not reset
witness state or introduce unilateral access to work around a refusal.

Successful item creation advances vault policy. Export and propagate fresh
checkpoints before the next witnessed operation, as for other vault mutations.
