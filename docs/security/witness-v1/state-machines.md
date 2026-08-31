# Jury witness protocol v1 state machines

These transitions are normative for protocol v1 and construction
`jury-witness-v1-shamir-xwing-hpke`. Unknown events or states fail closed. A
typed refusal changes no cryptographic state unless the table explicitly records
and externally anchors a replay/cancellation decision.

## Validation order

Every endpoint, approval client, and witness uses this order. A later step never
repairs or reinterprets an earlier failure.

1. Enforce total-byte and count bounds; parse one known schema/suite/protocol/
   construction with no trailing or unknown fields.
2. Validate fixed lengths, nonzero native IDs, canonical ordering, uniqueness,
   enum tags, time arithmetic, and operation-specific field presence.
3. Validate public vault ancestry, policy/checkpoint ancestry, descriptor/key
   fingerprints, and strict signatures.
4. Recompute every digest available to that role: all roles recompute the public
   request, manifest, target, workload, witness-set, policy, capsule, and
   checkpoint digests; an approval client additionally recomputes the private
   presentation entries and digest.
5. Run the common request/manifest equality check. Stop on any mismatch.
6. At an approval client, open and check every presentation commitment and
   complete meaningful rendering before signing.
7. At a witness, require exact current checkpoint, membership, requester role,
   operation rule, lifetime/workload limits, approval set, replay state, clock,
   and external-anchor readiness.
8. Reserve the request and create the stable decision/contribution inside the
   state-generation transaction.
9. Publish and read back the exact external anchor candidate.
10. Only then release a checkpoint acknowledgement or stable response.

Private-key work does not begin before steps 1 through 7 establish its exact
public context. Denial/error never opens a share capsule.

## Request/manifest mismatch matrix

The request and manifest may each be valid alone and still be invalid together.
The common function compares all rows before display, automatic matching,
approval signing, witness counting, or share work.

| Duplicated meaning | Required equality |
| --- | --- |
| identity | request ID, requester principal and requested access role, vault ID, genesis fingerprint |
| target seal | item ID, key epoch, item access mode, slot ID, content role, revision, `RevisionSealId` |
| policy | vault policy sequence/hash, witness-policy ID/revision/digest |
| action | operation, approval-target digest, target count and IDs |
| workload | recomputed full workload digest, operation context, every command/argument placeholder, working-directory commitment, environment target mapping, stdin target/mode, sink kind/commitment, platform assurance, timeout, output cap |
| lifetime | issuance, optional not-before, expiry |
| presentation | exact presentation digest and every subject commitment |
| witness routing | request set equals the complete active policy set; no manifest field may imply another set |

Any one-bit difference produces `wrong-scope`. A signature over either object
does not let a caller select it as the source of truth.

## Approval client

| State | Event | Next state and output |
| --- | --- | --- |
| `Loaded` | syntax/signature/policy/request-manifest check fails | `Refused`; no display and no signature |
| `Loaded` | complete presentation missing or commitment does not open | `Refused`; no display and no signature |
| `Loaded` | private-name entitlement, owner label, normalized path, or sink check fails | `Refused`; no display and no signature |
| `Loaded` | terminal cannot render every security field without truncation/loss | `Refused`; no partial approval control |
| `Loaded` | all checks pass | `Rendered`; exact complete presentation shown |
| `Rendered` | any bound byte/state changes before decision | `Loaded`; recheck and rerender from the beginning |
| `Rendered` | human approves or denies before expiry | `Signed`; emit one `ApprovalDecisionV1` over exact request, manifest, presentation, policy, and witness set |
| `Rendered` | expiry/cancellation occurs | `Terminal`; emit nothing |
| `Signed` | retry | return identical signed bytes; never mint a new ID, nonce, or expiry |

An automatic decision uses the same public validation and equality function,
then matches the exact typed policy rule. It does not enter `Rendered` and does
not claim meaningful human review. An automatic-only manifest uses the frozen
empty-presentation encoding; a human-eligible manifest must carry complete
openings. Transport login is never an event in this machine.

## Witness request lifecycle

Durable per-request states are `Absent`, `Reserved`, `Approved`, `Denied`, and
`Cancelled`. Terminal states contain one stable signed decision. `Reserved` and
every terminal transition are part of an externally anchored generation.

| Current | Event | Durable result |
| --- | --- | --- |
| `Absent` | invalid request/manifest/signature/policy/time/workload | no reservation; value-free refusal |
| `Absent` | valid cancellation with complete embedded request from requester/owner arrives first | anchor `Cancelled` tombstone through request expiry plus safety horizon; no contribution |
| `Absent` | valid request and service capacity/readiness | reserve exact `(request_id, request_digest)` as `Reserved` in serialized transaction |
| `Absent` | same ID is already known through another concurrent transaction | serialize, then follow the known-state row below |
| `Reserved` | exact duplicate request | no second evaluation while in flight; wait for or return stable result |
| `Reserved` | same request ID, different digest | anchor `Denied(replay-conflict)`; no contribution |
| `Reserved` | valid cancellation before decision creation | anchor `Cancelled`; no contribution |
| `Reserved` | request expires or clock becomes unsafe | anchor `Denied(expired|unsafe-clock)`; no contribution |
| `Reserved` | valid deny or conflicting approval observed, but threshold remains reachable | record the decision/conflict in the next anchored generation; remain `Reserved`; release nothing |
| `Reserved` | approvals plus still-undecided eligible approvers are fewer than threshold | anchor `Denied(approval-denied|approval-conflict)`; no contribution |
| `Reserved` | insufficient approvals and threshold remains reachable | remain `Reserved`; release nothing |
| `Reserved` | exact approval threshold and every policy check passes | open exact capsule, create one response ID and one contribution envelope, seal it in DB, create signed `Approved`, then anchor generation |
| `Approved` | exact duplicate request | after anchor equality, return the identical stored response bytes |
| `Approved` | valid late cancellation | retain `Approved`; report cancellation too late; caller may discard response |
| `Denied` or `Cancelled` | exact duplicate request | return identical terminal decision; never reevaluate or extend expiry |
| any known state | same ID, different digest | `replay-conflict`; never replace known bytes |

There is at most one contribution envelope for a request at a witness. A retry
cannot refresh HPKE encapsulation, response ID, signature, state generation, or
expiry. A different request ID with a replayed client signature fails signature
validation because request ID is signed.

## Approval counting

The witness starts from the exact current `OperationRuleV1`.

1. Validate each decision independently and require the exact request,
   manifest, presentation, policy, witness-set, operation scope, key epoch, and
   time interval.
2. Sort by approver ID. Byte-identical duplicates collapse to one.
3. Two different valid decisions from one approver are a conflict; that
   approver becomes decided but cannot count.
4. A current eligible denial makes that approver decided and does not count.
5. Revoked, unknown, cross-role, wrong-key, wrong-scope, and expired decisions
   are invalid; they never count toward threshold.
6. Deny when valid approvals plus still-undecided eligible approvers are below
   threshold; use `approval-conflict` when any conflict contributed to that
   condition, otherwise `approval-denied`; remain pending when the threshold is
   still reachable.
7. Count distinct current approves. Threshold zero succeeds only through its
   exact automatic read rule. Otherwise count must reach the rule threshold.

The witness does not combine decisions from different policy revisions or pick
a favorable subset that hides a denial/conflict.

## Endpoint quorum assembly

| Condition | Result |
| --- | --- |
| Response has wrong request/session/policy/checkpoint/seal or invalid witness signature | discard as invalid; never count |
| Witness ID duplicated with identical response | count once |
| Witness ID duplicated with different valid response bytes | terminal witness conflict; wipe all shares |
| Deny/error mixed with approvals | denial does not contribute; preserve its public decision in receipt; proceed only if policy permits and `t` distinct approvals still exist |
| Contribution envelope/digest/HPKE open/commitment invalid | discard witness response as invalid and wipe its scratch |
| Fewer than `t` valid shares at deadline | `insufficient-quorum`; wipe all partial material; no direct fallback |
| At least `t` valid shares | select lowest `t` share indexes, interpolate exact revision secret, authenticate target ciphertext, then invoke guarded item access |
| Interpolation or storage authentication fails | `invalid-contribution`; wipe all material; return no plaintext or provider detail |
| Local cancellation at any point | stop collection and wipe; already anchored witness responses remain valid but are not executed locally |

The endpoint never interpolates fewer than `t` shares even though the selected
provider can return a 32-byte value from a smaller set.

## Checkpoint state

Each registered vault at a witness has exactly one current checkpoint.

| Current | Candidate | Result |
| --- | --- | --- |
| absent | valid first checkpoint plus completed registration and operator-confirmed genesis | anchor as initial checkpoint before acknowledgement |
| `C` | byte-identical `C` | idempotent acknowledgement after anchor equality |
| `C` | sequence `C+1` or later with exact predecessor chain and complete intervening owner policy history | validate every link and resulting sets; anchor strict descendant |
| `C` | lower sequence | `stale-policy`; no change |
| `C` | same sequence, different bytes/hash | `checkpoint-fork`; no change |
| `C` | higher sequence with gap/missing predecessor or wrong owner | `witness-behind` or `checkpoint-fork`; no change |
| `C` | different vault/genesis or silent membership/approver/label replacement | `checkpoint-fork`; no change |

A request checkpoint below current yields `stale-policy`; above current yields
`witness-behind`; a same-sequence mismatch yields `checkpoint-fork`. A policy
revocation becomes effective at each witness only after that witness anchors the
descendant checkpoint. No aggregate global-freshness claim follows.

## First registration

| State | Event | Result |
| --- | --- | --- |
| `Unregistered` | malformed, expired, wrong-key, wrong-vault, or invalid owner challenge | refuse; do not open or store per-vault state |
| `Unregistered` | valid challenge but operator has not confirmed genesis fingerprint | remain unregistered; return `stale-policy`/operator action required without a key proof |
| `Unregistered` | valid confirmed challenge | open once, create the exact HMAC key proof and stable signed response, wipe challenge, await owner acceptance |
| `ResponseCreated` | byte-identical challenge retry before expiry | return identical response; never open into a second response |
| `ResponseCreated` | changed challenge with same registration ID | refuse `replay-conflict` |
| `ResponseCreated` | valid owner acceptance matching challenge, response, descriptor, and initial checkpoint | commit registration/current checkpoint as generation one, CAS/read back external anchor, then acknowledge |
| `ResponseCreated` | expiry or mismatched acceptance | terminal refusal; no membership |
| `Registered` | byte-identical complete registration replay | idempotent acknowledgement after anchor equality |
| `Registered` | any other first-registration attempt for that vault | refuse; later changes use checkpoint/rotation records |

Registration transport authentication never replaces the owner/witness
signatures, contribution-key proof, or operator genesis decision.

## State-generation transaction

All replay, cancellation, decision, checkpoint, compaction, registration, and
recovery mutations use one serialized algorithm:

1. Lock the security-state writer and reread the current DB generation and
   exact external anchor.
2. Require DB/anchor equality or first reconcile one permitted crash state.
3. Validate all public inputs and capacity before changing DB state.
4. Apply exactly one logical mutation in a database transaction.
5. If approving, create and durably seal the one stable contribution before it
   is visible to any transport.
6. Compute the complete database-state digest and a signed next anchor with
   generation `g + 1` and predecessor equal to the exact external digest.
7. Store exactly one pending candidate and commit the DB transaction.
8. CAS the external anchor from the predecessor digest to the exact candidate.
9. Read the external object back and require byte equality with the candidate.
10. Mark the pending candidate published as inert local acknowledgement.
11. Only now release response/checkpoint/registration acknowledgement bytes.

Concurrent writers serialize before step 1. On a CAS conflict, the service
reloads the external bytes. If they equal the exact candidate, it follows the
already-published crash case; every other value is `anchor-conflict`. It never
rewrites the committed candidate's predecessor, restarts the logical mutation,
or releases its output.

## Startup and crash reconciliation

| Database | External anchor | Pending candidates | Result |
| --- | --- | --- | --- |
| exact matching generation/digest | same exact bytes | none or inert published marker | serve |
| DB has committed `g+1`; external is exact predecessor `g` | exact predecessor | exactly one signed candidate, no output escaped | repeat CAS and readback, then serve |
| DB has committed `g+1`; external already equals exact candidate | exact candidate | exactly that one candidate | mark published, return stored output idempotently, serve |
| DB behind external | later anchor | any | refuse `anchor-conflict`; old DB cannot overwrite/advance it |
| external behind without the exact one-candidate DB state | earlier anchor | zero, multiple, or wrong predecessor | refuse |
| same generation but different digest/bytes | conflict | any | refuse |
| different predecessor, fork, missing anchor after registration, invalid signature, or multiple unanchored generations | inconsistent | any | refuse |

No second ordinary object under the database restore administrator qualifies as
the external anchor. Anchor loss/conflict is an availability failure, never a
reason to reset replay state.

## Clock and expiry

- Across requests, the witness records its highest accepted wall time in the
  anchored state. A new wall time more than 60 seconds behind it disables
  contribution service with `unsafe-clock` until operator repair restores a
  consistent clock and advances anchored state.
- Within a process, deadline handling uses monotonic duration while signatures
  and restart checks use wall time.
- `issued_at <= now + 60s`; `not_before <= now + 60s`; `now < expires_at`; and
  `1 <= expires-issued <= 900000` are required at decision creation.
- Approval and response expiry never exceed request expiry. Retry never changes
  any time. A forward jump expires requests rather than extending them.
- Replay compaction occurs only after `request_expiry + 86,400,000 ms`, all
  decisions/receipts that refer to it have expired, and a compaction generation
  is externally anchored. Operators may retain longer, never shorter.

## Rotation and pending requests

| Change | Pending requests | Capsule/state action |
| --- | --- | --- |
| Any witness-policy digest change, including approver membership/key/rule, witness signing/contribution key, workload/lifetime rule, label set, witness membership/index/threshold, construction, or suite | all old pending requests invalid; witnesses return stale-policy | full J19A item key-epoch rotation, fresh descriptor/body secrets/seals/shares/capsules; old capsules never rewrapped or reused |
| Add any direct slot | all incompatible pending witnessed requests invalid | explicit owner downgrade and complete item reseal; item-level witnessed claim removed |
| Remove final direct slot while retaining witnessed path | pending old-mode requests invalid | explicit owner transition and complete reseal before witnessed-only claim |

A response remains valid only for the exact policy/seal/request under which it
was signed. Rotation does not make historical plaintext disappear.

## Restore and recovery

| Situation | Result |
| --- | --- |
| Same witness identity, DB and external anchor exact-match | resume after full signature/digest/readiness checks |
| Same identity with the sole permitted pending candidate state | reconcile through the crash table |
| Same identity with missing, older, divergent, or independently reset DB/anchor | contribution service disabled; no reset or checkpoint import repairs it |
| Old identity cannot be restored exactly | create a new witness key/ID, complete owner-authorized recovery registration and full policy/item rotation, then anchor empty replay state for the new identity |
| Fewer than `t` current witness paths and no already-active direct recovery path | item unavailable; never lower threshold or synthesize shares |

Backups of witness keys, database state, and external anchors are separate
operational objects. Restoring one does not authorize rollback of another.

## Direct path and downgrade

The witnessed engine evaluates only an explicitly selected witnessed slot. It
never attempts direct HPKE after timeout, denial, expiry, stale state, invalid
share, insufficient quorum, anchor conflict, or recovery failure. A current
item with any active direct slot is reported as mixed/direct and carries no
item-level quorum claim. Adding or using that slot is visible owner-authorized
behavior, not witness error recovery.

## Terminal data handling

Success releases only the exact revision secret into the guarded item-access
operation. Denial, error, cancellation, timeout, conflict, panic containment,
and insufficient quorum wipe session private keys, opened shares, interpolation
scratch, revision secrets, decrypted presentation material, and provider
buffers. Durable state retains only encrypted contributions and the value-free
public records named in the protocol. No state or message contains an epoch
root or contribution reusable for a different `RevisionSealId`.
