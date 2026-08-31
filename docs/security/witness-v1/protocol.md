# Jury witness protocol v1

Status: frozen protocol for construction
`jury-witness-v1-shamir-xwing-hpke`.

This protocol is externally unreviewed pre-alpha work and must not be used for
real secrets. It uses suite `0x0001`, protocol version `1`, construction `1`,
capsule schema `1`, and message schema `1`. Unknown or mismatched values fail
before signatures, private keys, policy evaluation, or fallback. There is no
algorithm negotiation and no implicit direct path.

## Canonical encoding and bounds

Every cryptographic input uses JCE1 exactly as defined by
`docs/security/jury-v1-suite.md`: domain, zero terminator, suite `u16`, then the
ordered fields below. Native IDs are their exact nonzero 32 bytes, never text.
All times are unsigned Unix milliseconds. All lists reject duplicates and use
the order named by their owning schema.

Protocol-wide bounds are exact:

| Value | Bound |
| --- | ---: |
| Witnesses or approvers in one policy | 32 each |
| Witness threshold | `2..=witness_count` |
| Approver threshold per operation | `0..=eligible_approver_count` |
| Request lifetime | `1..=900,000 ms` |
| Accepted wall-clock skew | `60,000 ms` |
| Replay retention after request expiry | at least `86,400,000 ms` |
| Targets/fields in one manifest | 64 |
| Arguments / environment names | 128 / 64 |
| One argument / environment name | 4,096 / 128 bytes |
| Executable, working-directory, or sink descriptor | 4,096 bytes each |
| Public review label | 256 UTF-8 bytes |
| Request / cancellation / manifest core / private presentation | 32 / 48 / 64 / 64 KiB |
| One approval / witness response | 16 / 16 KiB |
| Receipt | 256 KiB |
| Replay records per vault / per witness service | 65,536 / 1,048,576 |

The 16 MiB vault-artifact bound remains authoritative. A service at a replay or
message bound refuses new work before reservation and retains existing safety
state. It never compacts early or widens a bound from input.

The common tags are:

| Type | Tags |
| --- | --- |
| content role | `01 descriptor`, `02 body` |
| item access mode | `01 direct-only`, `02 witnessed-only`, `03 mixed` |
| item access role | `01 reader`, `02 writer`, `03 owner` |
| operation | `01 read-stdout`, `02 write-private-file`, `03 template-injection`, `04 child-environment`, `05 child-stdin`, `06 item-mutation`, `07 backup`, `08 recovery`, `09 administrative-rekey` |
| approval mode | `01 human`, `02 automatic` |
| approval decision | `01 approve`, `02 deny` |
| witness decision | `01 approve`, `02 deny`, `03 error` |
| descriptor status | `01 active`, `02 revoked` |
| presentation kind | `01 entitled-private-name`, `02 owner-review-label`, `03 exact-normalized-display` |
| presentation subject | `01 item`, `02 field`, `03 working-directory`, `04 output-sink` |
| argument | `01 public-literal`, `02 secret-placeholder` |
| stdin mode | `01 none`, `02 secret-bytes`, `03 public-bytes` |
| output sink | `01 stdout`, `02 private-file`, `03 child-stdin`, `04 child-environment`, `05 none` |
| platform assurance | `01 normalized-path-only`, `02 stable-executable-identity` |
| terminal outcome | `01 success`, `02 denied`, `03 cancelled`, `04 failed` |

Value-free reason tags are: `00 none`, `01 policy-denied`, `02
missing-approval`, `03 approval-denied`, `04 approval-conflict`, `05
stale-policy`, `06 witness-behind`, `07 checkpoint-fork`, `08 replay-conflict`,
`09 expired`, `0a not-yet-valid`, `0b cancelled`, `0c wrong-scope`, `0d
wrong-operation`, `0e workload-exceeded`, `0f direct-downgrade`, `10 invalid`,
`11 unsupported-version`, `12 invalid-signature`, `13 invalid-contribution`,
`14 insufficient-quorum`, `15 unavailable`, `16 unsafe-clock`, `17
anchor-conflict`, `18 capacity-exhausted`, `19 restored-state-unsafe`, `1a
internal-failure`, and `1b cancellation-too-late`. `00` is legal only with an
approving decision or successful outcome. Error objects contain only a tag and
public IDs already present in the request; provider strings and offending bytes
never enter them.

Pre-validation transport refusals use canonical `ProtocolRefusalV1`: schema
`u16 = 1`, reason `u8` other than `00`, optional request ID, optional vault ID,
and optional witness ID. It is unsigned and never counts as a decision or
changes state. Once a request is reserved, its stable terminal result is the
signed `WitnessDecisionV1`, not this refusal object.

## Policy and role descriptors

An `ApproverDescriptorV1` canonical body is:

    schema u16 = 1
    approver_id id32
    signing_public_key fixed[32]
    signing_key_fingerprint digest32
    signing_key_epoch u64
    status u8
    approval_mode u8
    allowed_operations list<u8> sorted ascending
    created_at_ms u64

Its fingerprint is SHA-256 of JCE1 domain
`jury-witness-v1/approver-descriptor/fingerprint` and the body as one `bytes`
field. Its self-signature signs domain
`jury-witness-v1/approver-descriptor/self-signature` and that same body. The
canonical descriptor is `body || signature fixed[64]`. Approver keys are
independent of vault-principal and witness keys.

Every protocol signing-key fingerprint is SHA-256 of domain
`jury-witness-v1/signing-key/fingerprint`, protocol key-role tag (`01
vault-principal/requester/owner`, `02 approver`, or `03 witness`), subject ID,
key epoch, and public key. A contribution-key fingerprint is the J01A
recipient-public-bundle fingerprint over the exact 1,216 bytes.
Every embedded fingerprint is recomputed; it is never an alias or lookup key
that can override the embedded public key.

A `WitnessDescriptorV1` canonical body is:

    schema u16 = 1
    witness_id id32
    share_index u8
    signing_public_key fixed[32]
    signing_key_fingerprint digest32
    signing_key_epoch u64
    contribution_public_key fixed[1216]
    contribution_key_fingerprint digest32
    contribution_key_epoch u64
    status u8
    created_at_ms u64

Its fingerprint and self-signature use domains
`jury-witness-v1/witness-descriptor/fingerprint` and
`jury-witness-v1/witness-descriptor/self-signature`, respectively, with the
complete canonical body as one `bytes` field. The canonical descriptor is
`body || signature fixed[64]`. The self-signature proves control of the signing
key and binds the contribution key; registration below also proves that the
contribution private key can open the selected HPKE suite.

An `OperationRuleV1` is:

    operation u8
    eligible_approver_ids list<id32> sorted raw ascending
    approval_threshold u8
    allowed_request_lifetime_ms u64 <= 900000
    max_timeout_ms u64
    max_output_bytes u32
    max_target_count u8 <= 64
    required_platform_assurance u8
    automatic_read_targets list<bytes> sorted by item_id then field_id

An automatic-read target is `item_id || optional<field_id>`. Threshold zero is
legal only for `read-stdout`, requires at least one exact automatic target, and
requires a manifest containing only a subset of those targets, stdout output,
no executable, arguments, working directory, environment, or stdin, and the
rule's lifetime/workload limits. Other operations require threshold at least
one and an empty automatic-target list. Automatic behavior is never inferred
from an empty decision list. A denial does not veto a quorum; it simply does not
count as an approval. A witness denies once the remaining undecided eligible
approvers can no longer make the threshold reachable.

`WitnessPolicyV1` is one canonical body authenticated inside the owner-signed
J01A policy journal:

    schema u16 = 1
    witness_policy_id id32
    revision u64
    predecessor_policy_digest digest32 (zero for first)
    vault_id id32
    genesis_fingerprint digest32
    vault_policy_sequence u64
    vault_policy_hash digest32
    construction u16 = 1
    suite u16 = 1
    approver_descriptors list<bytes> sorted by approver_id
    witness_descriptors list<bytes> sorted by witness_id
    witness_threshold u8
    operation_rules list<bytes> sorted by operation tag
    review_label_set_digest digest32
    direct_fallback bool = false

Its digest is SHA-256 of JCE1 domain
`jury-witness-v1/policy/hash` and the body as one `bytes` field. Active IDs,
keys, and share indexes are unique across their own role; duplicate key material
across roles is rejected. Revoked descriptors may remain for history but never
count. Every active witness set has 2 through 32 entries, distinct indexes in
`1..=32`, and a satisfiable threshold. The exact policy digest is bound by every
request, checkpoint, capsule, decision, response, and receipt.

Every operation-rule approver ID must name an active descriptor whose
`allowed_operations` contains that rule's operation. The active descriptor-set
digests are SHA-256 of domains
`jury-witness-v1/approver-descriptor-set/hash` and
`jury-witness-v1/witness-descriptor-set/hash` with the corresponding complete
canonical active descriptors as sorted `list<bytes>`.

## Meaningful approval without public-name leakage

Witness messages carry stable random item and field IDs, never item/field names
or name-derived hashes. J05 must store a stable independently random nonzero
32-byte `FieldId` beside each `ItemFieldV1` inside encrypted item plaintext.
The ID is not derived from its name or value, is checked against every current
and historical field ID in that item, and is never reused. Item/field names
remain private; the random IDs may be public request selectors.

`OwnerReviewLabelV1` lets an owner publish a deliberately non-secret meaningful
label for an otherwise opaque subject:

    schema u16 = 1
    label_id id32
    label_revision u64
    subject_kind u8
    vault_id id32
    genesis_fingerprint digest32
    item_id optional<id32>
    field_id optional<id32>
    subject_commitment optional<digest32>
    public_label bytes (1..=256 canonical UTF-8 bytes)
    vault_policy_sequence u64
    issued_at_ms u64
    expires_at_ms optional<u64>
    issuer_owner_id id32
    issuer_key_fingerprint digest32
    issuer_key_epoch u64
    signature fixed[64]

The signature covers every preceding field under domain
`jury-witness-v1/review-label/signature`; its digest uses domain
`jury-witness-v1/review-label/hash`, the signature preimage as `bytes`, and the
signature. The normalized label set contains one highest current revision per
label ID; its sorted label digests produce `review_label_set_digest` under
domain `jury-witness-v1/review-label-set/hash`. A changed label, subject, owner,
or policy sequence changes that digest and invalidates pending requests.

Private display material is separated from the public manifest core.
`ApprovalPresentationEntryV1` is:

    subject_kind u8
    item_id optional<id32>
    field_id optional<id32>
    subject_commitment optional<digest32>
    presentation_kind u8
    display_bytes bytes
    source_revision optional<u64>
    source_revision_seal_id optional<id32>
    owner_review_label optional<bytes>
    blinding_nonce id32

Its commitment is SHA-256 of domain
`jury-witness-v1/approval-presentation/commitment` and the complete entry as a
`bytes` field. The complete presentation is a list sorted by subject kind, item
ID, field ID, and commitment; its digest is SHA-256 of domain
`jury-witness-v1/approval-presentation/hash` and that `list<bytes>`.

For working-directory and output-sink entries, `subject_commitment` is SHA-256
of domain `jury-witness-v1/normalized-subject/commitment`, subject kind,
`blinding_nonce`, and the exact normalized descriptor as `bytes`. The nonce is
available only with the private presentation, so the public commitment is not a
stable path digest. Item and field entries require `subject_commitment` absent.

For `entitled-private-name`, the approval client must itself decrypt the exact
descriptor/body revision named by the entry, prove its approver identity is
entitled, and compare the actual canonical item/field ID-to-name mapping with
`display_bytes`. For `owner-review-label`, it verifies the current owner
signature, label-set digest, subject, policy sequence, and expiry, then renders
the non-secret label. For `exact-normalized-display`, used only for a working
directory or output destination, it independently normalizes the actual
descriptor, recomputes `subject_commitment`, and compares the full bytes.
Item/field entries require source revision and seal and forbid a normalized
subject commitment. Directory/sink entries require the blinded subject
commitment, forbid source revision/seal, and use either exact display or a
current owner label. The optional owner-label bytes are present only for the
owner-label kind and `display_bytes` must equal its public label exactly.

Presence is canonical: an item subject has item ID only; a field subject has
item and field IDs; directory and sink subjects have neither ID and require a
subject commitment. A descriptor manifest permits exactly one item subject and
no field subjects. A body manifest permits its item subject, its current field
subjects, or both. Every field ID must exist in the exact opened body revision.
For a manifest eligible for human approval, there is exactly one private
presentation entry for each approval-target entry, plus exactly one directory
or sink entry for each corresponding manifest commitment. Their subject IDs and
presentation commitments must match and no extra entry is accepted.

An `ApprovalTargetEntryV1` in the public manifest is:

    item_id id32
    field_id optional<id32>
    presentation_commitment digest32

`ApprovalTargetV1` is `list<bytes>` of entries sorted by item ID and field ID,
followed by the complete `presentation_digest`; the JCE1 list count is the only
target count. Duplicate item/field pairs fail. No human approval exists from
only this opaque structure. The approval client must possess every committed
presentation entry, run the common request/manifest check before display, open
each commitment, perform one of the checks above, and render every entry without
truncation or hidden security fields before signing. Hashes, IDs, ellipses,
tooltips, scrolling past undisclosed fields, or unauthenticated labels are not
meaningful openings.

An automatic-only manifest has no private presentation. Every target
presentation commitment is 32 zero bytes and `presentation_digest` is the
SHA-256 digest of the canonical empty presentation list under the domain above.
Zero presentation commitments are forbidden when any human approver is
eligible. An automatic decision is valid only from a descriptor whose
`approval_mode` is `02`; a human decision is valid only from mode `01` after
the complete opening rules above. A receipt claims meaningful human review only
when a counted mode-`01` approval is present.

## Action manifest

The public `ActionManifestV1` core is:

    schema u16 = 1
    request_id id32
    vault_id id32
    genesis_fingerprint digest32
    item_id id32
    key_epoch u64
    item_access_mode u8
    slot_id id32
    content_role u8
    revision u64
    revision_seal_id id32
    vault_policy_sequence u64
    vault_policy_hash digest32
    witness_policy_id id32
    witness_policy_revision u64
    witness_policy_digest digest32
    requester_principal_id id32
    requested_access_role u8
    operation u8
    operation_context bytes
    approval_target bytes
    approval_target_digest digest32
    executable_identity optional<bytes>
    arguments list<bytes>
    working_directory_commitment optional<digest32>
    environment_injections list<bytes> sorted by environment name
    stdin_target optional<bytes>
    stdin_mode u8
    output_sink u8
    output_sink_commitment optional<digest32>
    platform_assurance u8
    timeout_ms u64
    output_limit_bytes u32
    issued_at_ms u64
    not_before_ms optional<u64>
    expires_at_ms u64
    presentation_digest digest32

Each argument is tag `01 || literal bytes` or tag `02 || item_id ||
optional<field_id>`; secret bytes never appear. Executable identity contains the
exact normalized executable path and stable executable identity evidence, not a
shell string or argument list.
An `EnvironmentInjectionV1` entry is an environment name `bytes`, item ID, and
optional field ID. Names are canonical portable environment names, are unique,
and match ASCII `[A-Za-z_][A-Za-z0-9_]{0,127}`. They are the only environment
metadata in the child. `stdin_target`, when
present, is item ID plus optional field ID. Every secret argument, environment
reference, and stdin target must name exactly one approval-target entry.
Working-directory and output-sink commitments are SHA-256 of their corresponding
presentation entries; absent fields must be absent for operations that do not
use them. Environment entries carry only names and opaque target selectors,
never values.

`operation_context` is a JCE1 object with the operation-specific domain below.
Every context starts with `schema u16 = 1`; a field not listed for that domain
does not exist.

| Operation/domain suffix | Remaining ordered fields |
| --- | --- |
| `read-stdout`, `write-private-file`, `template-injection`, `child-environment`, `child-stdin` | none |
| `item-mutation` | mutation kind `u8` (`01 descriptor-rename`, `02 body-field-set`, `03 body-field-delete`, `04 item-delete`); affected field IDs `list<id32>` sorted; proposed public revision digest `digest32` |
| `backup` | scope `u8` (`01 current-sealed-item`, `02 current-authorized-item-material`); archive format `u16`; destination commitment `digest32` |
| `recovery` | mode `u8` (`01 open-to-absent-destination`, `02 reseal-to-new-policy`); destination commitment `digest32`; next item-access mode `u8` |
| `administrative-rekey` | next vault-policy sequence `u64`; next vault-policy hash `digest32`; next witness-policy ID/revision/digest; rotation-record digest `digest32` |

The complete domain is `jury-witness-v1/operation-context/` plus the suffix.
Mutation field IDs must exactly equal the affected field approval targets;
descriptor rename and item delete require an empty field list. Backup and
recovery destination commitments must equal `output_sink_commitment`.
Administrative rekey values must equal the candidate policy and rotation
records supplied for approval. These context fields are public security fields
and are rendered in full.

The workload digest is SHA-256 of domain
`jury-witness-v1/workload/hash` and these manifest fields in order: operation,
operation context, executable identity, arguments, working-directory
commitment, complete environment injections, stdin target, stdin mode, output
sink, output-sink commitment, platform assurance,
timeout, and output limit. The approval-target digest is SHA-256 of domain
`jury-witness-v1/approval-target/hash` and `approval_target bytes`.

The action-manifest digest is SHA-256 of domain
`jury-witness-v1/action-manifest/hash` and the entire canonical core as one
`bytes` field. Presentation bytes are not public and are not sent to a witness;
their binding is the collision-resistant commitment set and
`presentation_digest`. A human approver signs that digest after opening all
commitments. An automatic rule may match opaque typed fields but makes no human
review claim.

Required workload shapes are exact:

| Operation | Required fields |
| --- | --- |
| read-stdout | body or descriptor target, sink `stdout`, no executable/working directory/environment/stdin target, stdin `none` |
| write-private-file | target, sink `private-file`, output commitment and meaningful destination presentation, no executable |
| template-injection | target fields, executable identity and arguments with placeholders, working directory, explicit sink |
| child-environment | target fields, executable identity, arguments, environment injections naming those targets, stdin `none`, explicit sink |
| child-stdin | exactly one target, executable identity, arguments, stdin `secret-bytes`, matching stdin target, explicit sink |
| item-mutation | exact item/field targets, matching mutation context, and no child-process fields |
| backup | exact item target, typed backup context, and matching sink commitment; multi-item backup uses one authorized request per item |
| recovery | exact item target, typed recovery context, and matching destination commitment; no implicit direct slot |
| administrative-rekey | exact target item and candidate policy/rotation commitments; no child-process fields |

Extra fields are invalid, not ignored. J13 owns normalization details but cannot
change the committed byte structure.

## Request

`WitnessRequestV1` signs this preimage under domain
`jury-witness-v1/request/signature`:

    schema u16 = 1
    protocol_version u16 = 1
    construction u16 = 1
    request_id id32
    client_nonce id32
    vault_id id32
    genesis_fingerprint digest32
    item_id id32
    key_epoch u64
    item_access_mode u8
    slot_id id32
    content_role u8
    revision u64
    revision_seal_id id32
    vault_policy_sequence u64
    vault_policy_hash digest32
    policy_checkpoint_digest digest32
    witness_policy_id id32
    witness_policy_revision u64
    witness_policy_digest digest32
    requester_principal_id id32
    requester_signing_key_fingerprint digest32
    requester_signing_key_epoch u64
    requested_access_role u8
    operation u8
    approval_target_digest digest32
    action_manifest_digest digest32
    workload_digest digest32
    issued_at_ms u64
    not_before_ms optional<u64>
    expires_at_ms u64
    request_session_public_key fixed[1216]
    request_session_key_fingerprint digest32
    intended_witness_set list<fixed[97]> sorted by witness_id

Each intended-witness entry is `witness_id || share_index || signing-key
fingerprint || contribution-key fingerprint`. The set must equal the exact
active set in the named policy, not merely contain a threshold subset. Its digest
uses domain `jury-witness-v1/intended-witness-set/hash` and the list.

The request is the preimage fields followed by `client_signature fixed[64]`.
Its digest is SHA-256 of domain `jury-witness-v1/request/hash`, the complete
signature preimage as `bytes`, and the signature. The session key is newly
generated for this request. The key fingerprint uses the J01A recipient-bundle
fingerprint domain. The request lifetime is `expires - issued`; `not_before`,
when present, is within that closed interval. Issuance may be at most 60 seconds
in the future at a witness. Expired requests never receive extended copies.
The access mode must be witnessed-only or mixed and must equal current signed
item policy. Direct-only has no witnessed slot. Mixed mode may use this explicit
witnessed path, but the item has no item-level quorum claim.

## Common request/manifest equality check

One pure function accepts a fully public-valid request and manifest core and
requires canonical equality for:

- request ID, vault, genesis, item, key epoch, item access mode, slot, content role, revision, and
  `RevisionSealId`;
- vault policy sequence/hash and witness-policy ID/revision/digest;
- requester principal, requested access role, operation, approval-target digest, issued time,
  not-before, and expiry;
- recomputed manifest digest and workload digest; and
- the operation-specific presence/absence and bound checks above.

Every target entry must name the request item. A descriptor request rejects
field targets; a body request rejects field IDs absent from the exact revision.
The function also checks that every secret placeholder and environment
injection names a target, that the request witness set equals the policy set,
and that the presentation digest
inside `ApprovalTargetV1` equals the manifest field. The approval client, not a
witness, recomputes that digest from the private presentation entries.
Failure is one value-free `wrong-scope` result. This function runs before any
human display, automatic match, approval signature, witness policy evaluation,
or contribution assembly. No caller may choose which duplicate field wins.

## Approval decision

`ApprovalDecisionV1` signs domain
`jury-witness-v1/approval-decision/signature` with:

    schema u16 = 1
    approval_id id32
    request_id id32
    request_digest digest32
    action_manifest_digest digest32
    presentation_digest digest32
    witness_policy_id id32
    witness_policy_revision u64
    witness_policy_digest digest32
    approver_id id32
    approver_key_fingerprint digest32
    approver_key_epoch u64
    approval_mode u8
    decision u8
    reason u8
    issued_at_ms u64
    not_before_ms optional<u64>
    expires_at_ms u64
    nonce id32
    intended_witness_set_digest digest32
    signature fixed[64]

Its digest uses domain `jury-witness-v1/approval-decision/hash`, the signature
preimage as `bytes`, and the signature. An approval never starts before the
request, outlives it, changes its witness set, or extends its scope. A human
approval is legal only after the complete private presentation is checked and
rendered as above. An automatic approval is legal only under the exact typed
rule. The decision's approval mode must equal the current approver descriptor.
Transport authentication, a button press without this signature, and a vault
or witness identity do not count.

Only one decision per approver/request counts. An identical duplicate is
idempotent. Different valid bytes from the same approver for the same request
are an approval conflict at that witness and that approver cannot count. A deny
does not count as approval. The witness emits terminal denial when the number of
approvals plus still-undecided eligible approvers is below the threshold.
Decisions from revoked, wrong-operation, wrong-policy, wrong-key-epoch, expired,
duplicate, or ineligible approvers do not count and cause the exact safe result
defined in the state machine.

## Share capsules and contributions

The context digest for one writer-created share capsule is SHA-256 of domain
`jury-witness-v1/capsule/context` and:

    schema u16 = 1; protocol u16 = 1; construction u16 = 1
    vault_id; genesis_fingerprint; item_id; key_epoch; item_access_mode; slot_id
    content_role; revision; RevisionSealId; vault_policy_sequence
    witness_policy_id; witness_policy_revision; witness_policy_digest
    threshold u8; member_count u8
    witness_id; contribution_key_fingerprint; share_index u8

The share commitment is SHA-256 of domain
`jury-witness-v1/share/commitment`, the context digest, and the exact share
`fixed[33]`. Capsule HPKE Base `info` is domain
`jury-witness-v1/capsule/info` with context digest, witness ID, contribution-key
fingerprint, and share index. AAD is domain
`jury-witness-v1/capsule/aad` with context digest, share commitment,
witness-policy digest, and vault policy sequence.

`WitnessShareCapsuleV1` is the context fields, context digest, share commitment,
HPKE `enc fixed[1120]`, and `ciphertext fixed[49]`. Capsules sort by share index.
The witnessed slot is the following exact canonical composite:

    slot_schema u8 = 1
    slot_algorithm u8 = 2
    suite u16 = 1
    protocol u16 = 1
    construction u16 = 1
    vault_id id32
    genesis_fingerprint digest32
    item_id id32
    key_epoch u64
    item_access_mode u8
    slot_id id32
    content_role u8
    revision u64
    RevisionSealId id32
    vault_policy_sequence u64
    witness_policy_id id32
    witness_policy_revision u64
    witness_policy_digest digest32
    threshold u8
    member_count u8
    capsules list<bytes> sorted by share_index
    capsule_set_digest digest32

The capsule-set digest is SHA-256 of domain
`jury-witness-v1/capsule-set/hash` plus the ordered complete capsules as
`list<bytes>`. Every repeated capsule context must equal the slot context, and
the member count must equal the capsule count. The slot digest is SHA-256 of
domain `jury-witness-v1/slot/hash` with the complete canonical slot composite
as one `bytes` field.

The J01A witnessed-state digest is SHA-256 of domain
`jury-witness-v1/slot-set/hash` with the complete witnessed slots as one
`list<bytes>`, sorted by content role, revision, raw `RevisionSealId`, then raw
slot ID. The set contains at most one slot for each content role and current
seal. It is absent exactly when no witnessed slot exists. This digest is the
`optional<digest32>` carried by J01A `item_create` and `item_slots_replace`;
the owner-signed policy therefore authenticates both descriptor and body slots
without introducing a reusable contribution or epoch root.

For an approved request the witness creates one
`WitnessContributionEnvelopeV1`. Its HPKE Base `info` is domain
`jury-witness-v1/contribution/info` with request digest, manifest digest,
response ID, witness ID, policy digest, checkpoint digest, share commitment, and
share index. AAD is domain `jury-witness-v1/contribution/aad` with capsule-set
digest, capsule context digest, request-session-key fingerprint, and request
expiry. The envelope is:

    schema u16 = 1
    response_id id32
    share_index u8
    share_commitment digest32
    capsule_context_digest digest32
    capsule_set_digest digest32
    request_session_key_fingerprint digest32
    enc fixed[1120]
    ciphertext fixed[49]

Its digest is SHA-256 of domain
`jury-witness-v1/contribution/hash` and the complete envelope as `bytes`. The
plaintext is exactly one 33-byte share. No denial or error has an envelope.

## Witness decision and response

`WitnessDecisionV1` signs domain `jury-witness-v1/decision/signature` with:

    schema u16 = 1
    response_id id32
    request_id id32
    request_digest digest32
    action_manifest_digest digest32
    witness_id id32
    witness_signing_key_fingerprint digest32
    witness_signing_key_epoch u64
    witness_policy_id id32
    witness_policy_revision u64
    witness_policy_digest digest32
    policy_checkpoint_digest digest32
    state_generation u64
    decision u8
    reason u8
    issued_at_ms u64
    expires_at_ms u64
    contribution_digest optional<digest32>
    share_index optional<u8>
    share_commitment optional<digest32>
    signature fixed[64]

The decision digest uses domain `jury-witness-v1/decision/hash`, signature
preimage bytes, and signature. Approve requires all three optional contribution
fields; deny/error requires all absent. Expiry equals request expiry. The
response is the exact signed decision plus the optional complete contribution
envelope whose digest must match. A response for one session cannot be replayed
against another because the envelope AAD and signed request digest bind its
session-key fingerprint.

The endpoint accepts at least `t` approving decisions and matching valid shares
from distinct current witnesses. A denial never contributes. More than `t`
valid shares are reduced to the lowest `t` share indexes. The endpoint checks
each owner-authenticated share commitment before interpolation and validates the
result with the target storage ciphertext. Partial material is wiped on every
terminal path.

## Cancellation

`RequestCancellationV1` signs domain
`jury-witness-v1/cancellation/signature` with:

    schema u16 = 1
    cancellation_id id32
    request_signature_preimage bytes
    client_signature fixed[64]
    request_id id32
    request_digest digest32
    canceller_id id32
    canceller_key_fingerprint digest32
    canceller_key_epoch u64
    canceller_role u8 (`01 original requester`, `02 current owner`)
    issued_at_ms u64
    reason u8 = 0b cancelled
    nonce id32
    signature fixed[64]

The embedded signed request must be complete; its request-only schema,
signature, policy references, time bounds, recomputed ID, and digest must be
valid and equal the duplicated fields. An action manifest is not required to
create a deny-only tombstone and no workload is evaluated on this path. This
lets a witness validate the vault, requester, current owner authority, expiry,
and retention horizon even when the cancellation arrives first. The
cancellation digest uses domain
`jury-witness-v1/cancellation/hash`, the signature-preimage bytes, and the
signature. Only the original requester or an owner in the current accepted
checkpoint may cancel. Cancellation cannot retract a response already
externally anchored or released; that case returns `cancellation-too-late`
locally while the original stable witness decision remains authoritative.

## Policy checkpoint and first registration

`VaultPolicyCheckpointV1` signs domain
`jury-witness-v1/checkpoint/signature` with:

    schema u16 = 1
    vault_id id32
    genesis_fingerprint digest32
    vault_policy_sequence u64
    vault_policy_hash digest32
    witness_policy_id id32
    witness_policy_revision u64
    witness_policy_digest digest32
    witness_set_digest digest32
    approver_set_digest digest32
    review_label_set_digest digest32
    predecessor_checkpoint_digest digest32 (zero at first)
    issued_at_ms u64
    issuer_owner_id id32
    issuer_key_fingerprint digest32
    issuer_key_epoch u64
    signature fixed[64]

Its digest uses domain `jury-witness-v1/checkpoint/hash`, signature-preimage
bytes, and signature. Set digests cover the complete sorted active descriptors,
using the descriptor-set domains above, not only their IDs. Equal checkpoint
bytes are idempotent. Advancement requires
the complete owner-authenticated intervening policy chain and an exact strict
descendant. Gaps, lower sequences, same-sequence changes, different genesis,
forks, and silent set replacement fail.

`WitnessRegistrationV1` is a three-message proof of initial configuration. The
owner samples a 32-byte challenge. HPKE Base `info` is domain
`jury-witness-v1/registration/info` with registration ID, vault/genesis,
witness-descriptor fingerprint, contribution-key fingerprint, and initial
checkpoint digest. AAD is domain `jury-witness-v1/registration/aad` with issue,
expiry, owner ID/key fingerprint/key epoch, and witness ID.

`RegistrationChallengeV1` signs domain
`jury-witness-v1/registration/challenge-signature` with:

    schema u16 = 1
    registration_id id32
    vault_id id32
    genesis_fingerprint digest32
    witness_descriptor bytes
    witness_descriptor_fingerprint digest32
    initial_checkpoint bytes
    initial_checkpoint_digest digest32
    issued_at_ms u64
    expires_at_ms u64
    owner_id id32
    owner_key_fingerprint digest32
    owner_key_epoch u64
    enc fixed[1120]
    ciphertext fixed[48]
    owner_signature fixed[64]

The witness opens the 32-byte challenge and computes HMAC-SHA-256 with that
challenge as the key and JCE1 domain
`jury-witness-v1/registration/key-proof` as the data. Its ordered fields are
registration ID, vault ID, genesis fingerprint, witness-descriptor fingerprint,
initial-checkpoint digest, `enc`, and ciphertext.

`RegistrationResponseV1` signs domain
`jury-witness-v1/registration/response-signature` with:

    schema u16 = 1
    registration_id id32
    challenge_digest digest32
    witness_id id32
    witness_signing_key_fingerprint digest32
    witness_signing_key_epoch u64
    contribution_key_fingerprint digest32
    contribution_key_epoch u64
    key_proof fixed[32]
    issued_at_ms u64
    witness_signature fixed[64]

The owner checks that response time is within the challenge interval and checks
the key proof before returning `RegistrationAcceptanceV1`, which signs domain
`jury-witness-v1/registration/acceptance-signature` with:

    schema u16 = 1
    registration_id id32
    challenge_digest digest32
    response_digest digest32
    witness_descriptor_fingerprint digest32
    initial_checkpoint_digest digest32
    accepted_at_ms u64
    owner_id id32
    owner_key_fingerprint digest32
    owner_key_epoch u64
    owner_signature fixed[64]

The three message digests use the corresponding domain ending `/hash`, the
signature-preimage bytes, and the signature. Every duplicated ID, fingerprint,
epoch, and digest must equal the embedded challenge, descriptor, response, and
checkpoint before acceptance.

The canonical `WitnessRegistrationV1` is the signed challenge `bytes`, signed
response `bytes`, and signed acceptance `bytes` in that order. Its digest uses
domain `jury-witness-v1/registration/hash` and the complete composite as one
`bytes` field.

Registration expires after 15 minutes, is single-use, and occurs only into
empty per-vault witness state after the operator confirms the genesis
fingerprint through an external trust path. The witness wipes the challenge and
anchors the accepted descriptor/checkpoint as its first generation before
acknowledging registration.

## Witness state anchor and external interface

`WitnessStateAnchorV1` signs domain
`jury-witness-v1/state-anchor/signature` with:

    schema u16 = 1
    witness_id id32
    witness_signing_key_fingerprint digest32
    witness_signing_key_epoch u64
    state_generation u64
    database_state_digest digest32
    vault_high_watermarks list<bytes> sorted by vault_id
    replay_retain_through_ms u64
    last_accepted_wall_time_ms u64
    predecessor_anchor_digest digest32 (zero at genesis)
    issued_at_ms u64
    signature fixed[64]

A high-watermark entry is one `fixed[112]`: vault ID, genesis fingerprint,
policy sequence, checkpoint digest, and highest retained request expiry. The
anchor digest uses domain `jury-witness-v1/state-anchor/hash`,
signature-preimage bytes, and signature.

The logical database state has one canonical encoding. A
`WitnessVaultStateV1` is:

    schema u16 = 1
    vault_id id32
    genesis_fingerprint digest32
    accepted_registration bytes
    current_checkpoint bytes
    current_policy_material bytes

A `WitnessReplayRecordV1` is:

    schema u16 = 1
    vault_id id32
    request_id id32
    request_digest digest32
    request_message bytes
    action_manifest_digest digest32
    state u8 (`01 reserved`, `02 approved`, `03 denied`, `04 cancelled`)
    expires_at_ms u64
    retain_through_ms u64
    approval_decisions list<bytes> sorted by approver_id
    cancellation optional<bytes>
    witness_response optional<bytes>

The request message is the exact signature preimage plus client signature.
`Reserved` has no response or cancellation; `Approved` has one approving
response; `Denied` has one denying/error response; and `Cancelled` has one
cancellation plus one stable denying response with reason `cancelled`. Approval
records are the exact accepted decisions, including non-counting denials and
conflicts. A cancellation-first tombstone obtains its request message from the
embedded request in `RequestCancellationV1`.

`WitnessDatabaseStateV1` is:

    schema u16 = 1
    witness_id id32
    state_generation u64
    vault_states list<bytes> sorted by vault_id
    replay_records list<bytes> sorted by vault_id then request_id
    last_accepted_wall_time_ms u64

`current_policy_material` is the complete canonical owner-signed J01A journal
material needed to authenticate the embedded current `WitnessPolicyV1`; a bare
policy body is invalid. The database-state digest is SHA-256 of domain
`jury-witness-v1/database-state/hash` and the complete canonical body as one
`bytes` field. It therefore covers accepted registrations, current checkpoints
and policies, clock state, every
uncompactable replay reservation/cancellation, accepted approval set, stable
decision, and encrypted contribution envelope. Every embedded message and
digest is revalidated before hashing. Derived indexes, capacity counters, and
transport caches are excluded and cannot affect a decision.

The one pending exact anchor candidate and its publication acknowledgement are
stored beside the logical state and excluded to avoid a digest cycle; the
signed candidate authenticates the resulting database-state digest and must
match it exactly. No other unhashed field may affect authorization, replay,
release, compaction, or recovery.

The anchor high-watermark list is the exact projection of the sorted vault
states and replay records. `replay_retain_through_ms` is their maximum retention
time, or zero when no replay record exists, and the anchor's accepted wall time
equals the database field. A mismatch between any projection and the database
is `internal-failure` before candidate publication.

The public self-hostable external anchor exposes exactly:

    read(witness_id) -> absent | exact_anchor_bytes
    compare_and_swap(witness_id,
                     expected_anchor_digest: absent | digest32,
                     next_exact_anchor_bytes)
      -> applied(exact_anchor_bytes) | conflict(current_exact_anchor_bytes)

It has no force-write, delete, decrement, merge, or "latest" heuristic. The
caller verifies exact bytes, witness signature, predecessor digest, generation
increment by one, and readback equality. Its write authority, administrator,
backup, and restore failure domain are separate from the witness database.

## Rotation and recovery records

`WitnessPolicyRotationV1` signs domain
`jury-witness-v1/rotation/signature` with:

    schema u16 = 1
    rotation_id id32
    vault_id id32
    genesis_fingerprint digest32
    prior_vault_policy_sequence u64
    prior_vault_policy_hash digest32
    next_vault_policy_sequence u64
    next_vault_policy_hash digest32
    prior_witness_policy_id id32
    prior_witness_policy_revision u64
    prior_witness_policy_digest digest32
    next_witness_policy_id id32
    next_witness_policy_revision u64
    next_witness_policy_digest digest32
    reason u8
    affected_items list<bytes> sorted by item_id
    issued_at_ms u64
    owner_id id32
    owner_key_fingerprint digest32
    owner_key_epoch u64
    signature fixed[64]

Each affected-item entry is:

    item_id id32
    prior_key_epoch u64
    next_key_epoch u64
    next_descriptor_revision u64
    next_descriptor_revision_seal_id id32
    next_descriptor_capsule_set_digest digest32
    next_body_revision u64
    next_body_revision_seal_id id32
    next_body_capsule_set_digest digest32

The record digest uses domain `jury-witness-v1/rotation/hash`, the
signature-preimage bytes, and the signature. It is valid only beside the atomic
owner-signed policy mutation and complete fresh reseal required by J19A. A
changed witness contribution key is full rotation. Because every capsule binds
the complete witness-policy digest, any change to that digest—including a
signing-key-only, approver-rule, or label-set change—also performs this full
rotation. V1 has no partial capsule reuse optimization.

Rotation reason tags are `01 witness-membership`, `02 witness-threshold`, `03
share-index`, `04 contribution-key`, `05 construction`, `06 suite`, `07
witness-signing-key`, `08 approver-rule-or-label`, and `09 direct-mode`. More
than one change uses the lowest applicable tag and the exact prior/next policy
digests still bind the complete combined change; there is no free-form reason.

`WitnessRecoveryV1` signs domain `jury-witness-v1/recovery/signature` with:

    schema u16 = 1
    recovery_id id32
    vault_id id32
    genesis_fingerprint digest32
    unavailable_prior_witness_id optional<id32>
    new_witness_descriptor bytes
    new_registration_digest digest32
    prior_checkpoint_digest digest32
    next_checkpoint_digest digest32
    rotation_record_digest digest32
    statement u8 = 01 new-identity-no-replay-continuity
    issued_at_ms u64
    owner_id id32
    owner_key_fingerprint digest32
    owner_key_epoch u64
    signature fixed[64]

Its digest uses domain `jury-witness-v1/recovery/hash`, the
signature-preimage bytes, and the signature. It never authorizes the old
identity to resume. Exact restoration of an existing identity uses no recovery
record: its database and external anchor must match under the state-machine
rules.

## Receipt

The endpoint constructs `WitnessReceiptV1` from already signed public evidence:

    schema u16 = 1
    receipt_id id32
    request_signature_preimage bytes
    client_signature fixed[64]
    request_digest digest32
    action_manifest_digest digest32
    presentation_digest digest32
    public_scope bytes
    approval_decisions list<bytes> sorted by approver_id
    witness_decisions list<bytes> sorted by witness_id
    policy_checkpoint_bytes bytes
    witness_policy_material bytes
    approval_threshold u8
    witness_threshold u8
    counted_approver_ids list<id32> sorted
    counted_witness_ids list<id32> sorted
    outcome u8
    reason u8
    issued_at_ms u64
    expires_at_ms u64
    endpoint_acknowledgement optional<bytes>
    endpoint_completion optional<bytes>

`PublicReceiptScopeV1` is an exact projection of the signed request:

    schema u16 = 1
    request_id id32
    vault_id id32
    genesis_fingerprint digest32
    item_id id32
    key_epoch u64
    item_access_mode u8
    slot_id id32
    content_role u8
    revision u64
    revision_seal_id id32
    vault_policy_sequence u64
    vault_policy_hash digest32
    witness_policy_id id32
    witness_policy_revision u64
    witness_policy_digest digest32
    requester_principal_id id32
    requested_access_role u8
    operation u8
    approval_target_digest digest32
    action_manifest_digest digest32
    workload_digest digest32
    issued_at_ms u64
    not_before_ms optional<u64>
    expires_at_ms u64

Every field is recomputed from `request_signature_preimage`; the receipt cannot
override one. The scope contains no presentation entry, label, path, executable,
argument, or sink descriptor. `witness_policy_material` is the complete
canonical owner-signed J01A journal material authenticating the exact embedded
policy. Witness decisions contain the signed contribution digest and commitment
but never the HPKE envelope. The receipt therefore cannot serve as a share
capsule or response replay.

The receipt core ends at `expires_at_ms`. Its digest is SHA-256 of domain
`jury-witness-v1/receipt/core-hash` and those exact fields as one `bytes` value.
Acknowledgement and completion are separate endpoint signatures under domains
`jury-witness-v1/receipt/acknowledgement` and
`jury-witness-v1/receipt/completion`. `ReceiptAcknowledgementV1` signs:

    schema u16 = 1
    receipt_id id32
    receipt_core_digest digest32
    request_digest digest32
    endpoint_principal_id id32
    endpoint_key_fingerprint digest32
    endpoint_key_epoch u64
    started_at_ms u64
    signature fixed[64]

`ReceiptCompletionV1` signs:

    schema u16 = 1
    receipt_id id32
    receipt_core_digest digest32
    acknowledgement_digest optional<digest32>
    endpoint_principal_id id32
    endpoint_key_fingerprint digest32
    endpoint_key_epoch u64
    outcome u8
    reason u8
    completed_at_ms u64
    signature fixed[64]

The endpoint key must be the requester's current signing key. Acknowledgement
and completion contain no output bytes. Their digests use the corresponding
domain ending `/hash`, signature-preimage bytes, and signature. Completion
outcome/reason must equal the core. The final receipt digest is SHA-256 of domain
`jury-witness-v1/receipt/hash` and the complete canonical receipt including
those optional signed records as one `bytes` field. Nothing signs a digest that
contains its own signature.

Offline checking validates the included policy/checkpoint ancestry and every
included signature, reconstructs the signed-request projection, recomputes every
available digest and distinct quorum set, and enforces all bounds. The hidden
manifest and presentation cannot be reconstructed from their digests; the
receipt proves only that the recorded actors signed those exact digests and that
the public request scope agrees. Checking requires no network or private key. A
receipt does not prove faithful display, execution, output, non-exfiltration, or
endpoint forgetting.

Receipts, errors, logs, anchor objects, checkpoints, and durable replay state
never contain presentation bytes, item/field names, paths, environment values,
secret values, plaintext shares, revision secrets, private keys, passphrases,
raw command output, tokens, or provider messages.
