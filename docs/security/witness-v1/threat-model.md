# Jury witnessed v1 threat model

Status: frozen with construction `jury-witness-v1-shamir-xwing-hpke` on
2026-08-31.

Jury is externally unreviewed pre-alpha software. This model does not establish
that Jury protects secrets and it is unsuitable for real credentials or data.

## Security objective

For a witnessed-only item and a later seal `R'`, an endpoint that retained every
byte it could observe during any set of earlier authorized releases cannot
recover the `R'` descriptor/body revision secret unless at least one of these
events occurs:

1. `t` current witnesses authorize and return valid `R'` shares for one accepted,
   unexpired, request-specific session;
2. the attacker compromises `t` applicable witness contribution private keys or
   their plaintext shares;
3. the attacker breaks a named cryptographic assumption, the independent
   entropy assumption, or the writer/plaintext boundary; or
4. an explicit active direct slot provides unilateral access.

The claim is falsified if retained revision-N endpoint state opens a different
`RevisionSealId` without one of those events. J19C must search that property over
the bounded protocol model and include mutations of every bound field.

Authorization freshness is narrower than cryptographic revision separation.
The first event additionally assumes the counted witnesses have current trusted
clock, checkpoint, replay, membership, approval, and external-anchor state.
Jury does not claim universal freshness across witnesses that have not learned a
new checkpoint.

## Actors and trust boundaries

| Actor or system | Trusted for | Not trusted for / compromise result |
| --- | --- | --- |
| Authorized writer | Creating the intended plaintext, independent secrets, correct witnessed capsules, and atomic signed mutation | A malicious writer already knows plaintext and can leak it, choose weak input outside the required entropy boundary, create inconsistent shares, or destroy availability. The construction cannot constrain it. |
| Endpoint | Request construction, local private-key handling, response validation, and using only the selected revision after authorization | The endpoint is expected to retain plaintext, revision secrets, session keys, transcripts, and responses. Endpoint compromise exposes every locally available and previously opened revision. |
| Approver | Protecting its separate signing key and faithfully checking the complete meaningful action manifest | A compromised approver can sign any decision within its policy role. An approver never holds a share and cannot decrypt alone. |
| Witness operator | Protecting one contribution private key, one signing key, durable checkpoint/replay state, clock, and response logic | A compromised witness counts as one share/key plus one signed decision source. Control of one `juryd` host counts as control of that witness. |
| `juryd` core | Enforcing the exact request/approval/policy state machine and releasing a share only after its durable decision | It is not trusted beyond its witness identity. Multiple witness identities on one host or administrative boundary are correlated and must be reported as such. |
| Public vault/storage/Git | Availability and delivery only | It may read, delete, reorder, replay, fork, truncate, or corrupt artifacts. Signatures, hashes, HPKE, checkpoints, and strict-descendant rules detect applicable changes; deletion remains denial of service. |
| Network/transport | Availability only | It may observe, delay, drop, duplicate, reorder, or alter messages. It cannot substitute signatures or HPKE contexts under the named assumptions. Traffic analysis is not hidden. |
| Witness clock | Bounded issuance/not-before/expiry decisions | A clock outside the J19B skew bound disables safe contribution service. Clock correctness does not establish global policy freshness. |
| External rollback anchor | Monotonic witness state generation and exact pending-state reconciliation | It has no decryption authority and does not prove vault-wide latest state. Loss/conflict causes refusal. Compromise together with restored witness state can permit stale authorization. |
| Host OS, root, debugger, hardware | None inside a compromised endpoint or witness boundary | Such compromise exposes that host's plaintext, keys, process memory, and local state and counts as compromise of every role hosted there. |

Role separation is cryptographic, not merely a label. Reusing one machine,
administrator, backup domain, or hardware boundary for multiple witnesses makes
those witnesses a correlated compromise set even when their keys differ.

## Quorum and compromise matrix

Let `a` be the approver threshold, `m` the approver member count, `t` the witness
threshold, and `n` the witness member count. Policies with approval threshold
zero may exist only for operation classes explicitly frozen by J19B; witness
threshold is always at least two.

| Attacker capability | Later witnessed-only revision secret | Authorization/state effect |
| --- | --- | --- |
| Endpoint only, including all earlier endpoint state | No | Can replay/open already released revisions and submit new requests; honest current policy still applies. |
| Fewer than `t` witness contribution keys/shares, no direct slot | No, subject to HPKE and commitment assumptions | Compromised witnesses can deny, equivocate, or return invalid shares; commitments keep them from counting as valid. |
| `t` witness contribution keys or plaintext shares for the target policy/seal | Yes | Can open stored capsules and reconstruct without approvers, endpoint, or online protocol. This is the construction's excluded compromise threshold. |
| One witness signing key but not contribution key | No | Can forge one witness decision but not a valid share; cannot reach witness quorum alone. |
| One witness contribution key but not signing key | Not alone | Can open that witness's stored capsule. A conforming endpoint will not count an unsigned response, but the share still counts toward an offline `t`-share attacker. |
| Fewer than `a` approver keys | No new authorization | Can deny or create insufficient decisions. |
| `a` approver keys, but no valid requester and no witness compromise | No by themselves | Can satisfy the approval portion. Honest witnesses still require a valid permitted requester and all other request/state checks. |
| `a` approver keys plus a valid permitted requester | Yes if `t` honest witnesses accept the policy/request | This is an authorization compromise, not a break of share confidentiality. |
| `t` witness service instances with intact contribution keys but malicious logic | Yes | They can ignore policy and release/reconstruct their target shares. |
| Storage or network only | No | Can deny, fork, replay, corrupt, and reveal public metadata/traffic. |
| Writer, plaintext process, or storage-AEAD key for target seal | Yes | Outside the witnessed release boundary. |
| Endpoint plus fewer than `t` witnesses | No later seal, absent approval/request compromise that causes honest witnesses to release | Already released revisions remain exposed. |
| Compromised external anchor only | No | Can disrupt or misstate monotonic state; honest witness database mismatch fails closed. Combined database/anchor rollback can accept stale policy. |
| Active direct recipient key for the item | Yes through direct capsules | The item is unilateral/mixed and carries no item-level witnessed claim. |

Witness signing and contribution keys are distinct. Approver, principal, writer,
witness signing, witness contribution, and external-anchor keys are also
distinct. One physical operator may hold several, but the resulting correlated
threshold must be disclosed rather than counted as independence.

## Retained endpoint state inventory

The endpoint attacker may retain all rows at once. None is assumed erased.

| Retained material | What it enables | What it does not enable under the objective |
| --- | --- | --- |
| Long-term principal signing keys | New client-signed requests as that principal until revocation reaches witnesses | Does not supply approvals or witness shares by itself. |
| Long-term direct recipient keys | Every historical and later direct capsule addressed to that key | Such a slot removes the item-level witnessed claim; it says nothing about witnessed-only items. |
| Request-specific HPKE private keys | Reopening contribution envelopes for those exact requests | No envelope for a different request/session key. |
| All prior requests, manifests, nonces, approvals, receipts, and witness signatures | Replay attempts, public metadata, and evidence of prior decisions | Requests bind exact seal/policy/session/expiry; replay cannot mint a later-seal share from an honest witness. |
| All prior encrypted contribution envelopes and plaintext 33-byte shares | Reconstruction of their exact earlier revision secret when at least the earlier threshold is retained | Shares come from independent later polynomials and do not interpolate a later secret. |
| All prior revision secrets | Opening the exact descriptor/body ciphertexts sealed with those keys | No derivation path to another independent revision secret. |
| All prior plaintext | Permanent knowledge and arbitrary copying of those revisions | No construction-derived later plaintext; ordinary semantic predictability of user data is not hidden. |
| Current and historical public vault bytes, share commitments, ciphertexts, capsules, policy, and item history | Offline attacks, metadata analysis, rollback/fork attempts, and availability attacks | Fewer than `t` capsule private keys do not expose a witnessed-only revision secret under HPKE; commitments are over uniform 256-bit shares. |
| Process crashes, swap, core dumps, or allocator remnants on a compromised endpoint | Potentially every secret processed on that host | Memory-forensic resistance after host compromise is not claimed. Conforming builds still minimize and wipe live buffers. |

The construction does not ask whether the endpoint *should* retain any row. It
assumes the worst case and limits cross-revision reuse by independent creation.

## Replay, rollback, expiry, and restore

| Condition | Required result | Security limit |
| --- | --- | --- |
| Identical request replay before expiry | Idempotent return of the same durably sealed decision/response, never a new share or extended expiry | The endpoint may retain that exact response forever. |
| Request ID reused with changed bytes | Reject before release | Transport retries cannot choose which version wins. |
| Expired, not-yet-valid, cancelled, wrong-operation, wrong-session, or wrong-seal request | Reject without a contribution | Clock is trusted within the frozen skew bound. |
| Witness behind a client-supplied current checkpoint | Stale refusal | A client cannot force checkpoint advancement without authenticated descendant state. |
| Client behind the witness checkpoint | Stale refusal | The witness's state is not proof that all other witnesses are current. |
| Fork or non-descendant state | Conflict refusal | Semantic merge is outside `0.x`. |
| Restored witness with absent/mismatched replay state or anchor | Contribution service disabled | Availability is lost until exact recovery succeeds. |
| One exact database commit pending external-anchor compare-and-swap | Only the J19B-frozen reconciliation may complete | Any other database/anchor split state refuses. |
| Database and external anchor both maliciously rolled back | Stale authorization may be accepted | This violates the freshness assumption but still releases only capsules present for the requested exact seal. |
| Fresh clone with no external trust input | No universal latest-state knowledge | Operator-supplied genesis/checkpoint trust remains necessary. |

Rollback and replay controls protect authorization freshness and duplicate
release behavior. Independent per-seal secrets protect revision separation even
when old artifacts are replayed. Neither control turns historical revocation
into erasure.

## Revocation and rotation

- Endpoint/principal revocation takes effect for witnessed access only after the
  required witnesses durably accept the new policy checkpoint. It cannot revoke
  copied plaintext or revision secrets.
- Approver revocation has the same propagation limit. Decisions for an exact
  still-valid request remain governed by the J19B transition rules; they never
  transfer to another request or seal.
- Witness membership, threshold, index, construction, or contribution-key
  change requires a new key epoch, fresh descriptor/body secrets and seal IDs,
  new shares/commitments/capsules, and replacement of the complete current slot
  set. No old share is rewrapped into the new policy.
- Old private keys and Git history remain capable of exposing historical
  capsules up to their applicable old threshold. Rotation is prospective.
- Witness signing-key rotation preserves the ability to check old receipts but
  gives the new key no authority before its signed policy activation.
- Suite change is a new authenticated lineage. There is no in-line suite
  negotiation or mixed active suite.

## Availability and recovery

Witnessed release requires at least `t` current witnesses that are online,
reachable, uncompromised in behavior, able to open their exact capsules, and in
acceptable replay/checkpoint/clock/anchor state. It also requires the requester's
keys and whatever approver threshold the policy names. Jury does not guarantee
that condition.

One malicious or offline witness can deny its own share. Up to `n - t` such
witnesses are tolerated if at least `t` other valid responses remain. A bad
share is detectable by its owner-authenticated commitment and does not count.
At fewer than `t` valid shares, the endpoint refuses and wipes partial material.

Recovery options are deliberately narrow:

- restore the same witness identity together with its protected keys, database,
  replay high-water marks, checkpoint, and matching external anchor;
- while a current authorized path still works, perform the complete rotation to
  a new witness policy; or
- use an already-active explicit direct recovery slot, accepting that the item
  is unilateral/mixed and has no item-level witnessed claim. Creating a new
  direct slot still requires a currently authorized path and full reseal.

Recovery cannot lower a threshold, reset replay/checkpoint state, derive a
missing share, make a stale fork current, or silently add direct access. If no
listed path remains, the data is unavailable by design.

## Property-to-assumption map

| Property | Status and assumptions |
| --- | --- |
| Fewer than `t` target-revision shares do not determine the secret | Yes before commitments under Shamir with uniform independent coefficients and distinct nonzero indexes. With public commitments, the full construction additionally assumes SHA-256 preimage resistance over uniform 256-bit shares. |
| Stored share capsules hide shares | Conditional on the exact J01B X-Wing HPKE Base composition, private-key protection, canonical context validation, and entropy assumptions. |
| A returned share belongs to the exact writer-created capsule | Conditional on the owner/item signature, SHA-256 commitment, witness signature, HPKE ciphertext integrity, and exact context equality. Base-mode HPKE does not authenticate the writer. |
| Earlier endpoint state cannot open a later seal | Conditional on independent secret/coefficient/session generation, fewer than `t` later witness compromises, no active direct slot, honest writer/plaintext boundary, exact protocol checks, and the cryptographic assumptions above. |
| One witness lacks unilateral access | Yes for witnessed-only items with `t >= 2`, unless that operator controls additional correlated witness boundaries or the writer/direct path. |
| `t` witnesses can recover the target secret | Yes; this is both intended availability and the confidentiality compromise threshold. |
| Revocation stops future witnessed releases | Conditional and prospective after the required witnesses accept the new checkpoint and later seals exclude old keys/members. |
| Replay does not broaden scope | Conditional on durable request reservation, exact digest/session/seal binding, and state-machine correctness. It does not prevent reopening the same released revision. |
| Witness state is rollback resistant | Conditional on independent external-anchor integrity, durable local state, exact restore/reconciliation, and fail-closed disagreement. It is not universal vault freshness. |
| Network/storage tampering cannot create an accepted secret | Conditional on strict signatures, hashes, HPKE, canonical parsing, and state validation. Deletion and traffic analysis remain possible. |
| Availability with `n - t` failures | Conditional on the remaining `t` witnesses and every requester/approval/clock/anchor dependency being available and valid. No service-level objective is claimed. |

## Explicit nonclaims

Jury witnessed v1 does not claim:

- that an authorized endpoint forgets, cannot copy, or cannot exfiltrate
  plaintext or a released revision secret;
- that a direct or mixed item has quorum-enforced access;
- protection after compromise of the writer/plaintext boundary, target storage
  key, `t` witness contribution keys/shares, required authorization keys, root
  on a threshold of co-hosted witnesses, or an endpoint holding a direct key;
- retroactive revocation, deletion of Git history, recipient forward secrecy,
  proactive share refresh, or recovery after all valid access paths are lost;
- universal latest-policy knowledge, safe operation without an external trust
  input on a fresh clone, semantic fork merge, or availability during
  anchor/clock/network failure;
- anonymity, traffic-flow confidentiality, hidden public policy/membership,
  hidden ciphertext sizes beyond the existing bucket rules, or resistance to
  plaintext predictability;
- post-quantum signature authenticity, a finalized threshold-KEM standard,
  FIPS-validated deployment, constant-time binary behavior, fault resistance,
  formal proof, external cryptographic review, certification, or suitability
  for real secrets.
