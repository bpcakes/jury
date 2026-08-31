# Jury vault format v1

Status: frozen pre-alpha public format. Jury does not yet protect real secrets.

This document defines the persisted `jury-vault` format version `1`. The Rust
implementation is `jury_protocol::vault_v1`; the language-neutral fixtures are
under `conformance/vault-v1/`. J01A owns shared and direct cryptographic bytes,
and J19 owns witnessed cryptographic bytes. This format embeds those bytes
without changing their domains, field order, widths, or list encodings.

## JSON representation

The artifact is UTF-8 JSON emitted with two-space indentation and one trailing
newline. Struct fields appear in the order below. Binary values use RFC 4648
standard padded base64 with no alternate alphabet or omitted padding. Native
IDs use exactly 64 lowercase hexadecimal characters and must decode to a
nonzero 32-byte value. Unknown fields, duplicate fields, alternate whitespace,
trailing input, Git conflict markers, and a file over 16 MiB are invalid.

The outer object is:

```text
VaultFileV1 {
  header: VaultHeaderV1,
  policy: PolicyJournalV1,
  items: [ItemEnvelopeV1] sorted by item_id,
  suite_migration: SignedSuiteMigrationV1 | null
}
```

The artifact contains no identity private material, passphrase/KDF state,
checkpoint, audit receipt, replay database, lock, transaction state, local
path, private key, revision secret, epoch root, decrypted field, or reusable
witness contribution. The closed schema makes any such field invalid.

## Header and genesis

`VaultHeaderV1` is ordered as `magic`, `version`, `vault_id`, `created_at_ms`,
`suite`, `policy_schema`, `item_schema`, `identity_schema`, and
`genesis_fingerprint`. Magic is `jury-vault`; every version/schema value and
the single lineage suite are `1`. Header identity and time equal genesis.

`PolicyGenesisV1` is ordered as `vault_id`, zero `policy_sequence`, zero
`previous_policy_hash`, `created_at_ms`, suite `1`, one human
`PrincipalDescriptorV1`, optional `source_attestation`, empty
`item_inventory`, empty `direct_grants`, and `owner_signature`. The fingerprint
is recomputed from the exact J01A preimage and must equal the header.

`PrincipalDescriptorV1` stores descriptor version `1`, principal ID, principal
kind, the fixed 1,216-byte recipient key, fixed 32-byte verification key, and
fixed 64-byte self-signature. Its canonical binary form is the exact
1,347-byte J01A descriptor.

The optional source attestation is a closed union:

- `legacy-migration`: source format, migration ID, final preserved legacy-audit
  digest, and verified terminal legacy-audit MAC;
- `rollover`: the complete signed J01A rollover statement.

Both are reserved inputs. The active `0.x` runtime has no command that creates
either.

## Policy journal

The journal stores genesis followed by at most 4,096
`SignedPolicyRevisionV1` entries. Sequences start at one without gaps, each
previous hash equals the recomputed preceding record hash, and every revision
has a nonempty ordered operation list. Each record stores vault ID, sequence,
previous hash, timestamp, author principal ID, operations, resulting normalized
policy-state hash, and fixed signature.

The closed operation union is `principal_add`, `principal_label_change`,
`principal_remove`, `owner_grant`, `owner_revoke`, `item_create`,
`item_rename`, `item_delete`, `item_role_change`,
`item_reader_set_change`, `item_slots_replace`, and `principal_replace`.
Canonical binary operation bytes are exactly section 11.4 of
`jury-v1-suite.md`. Labels are 1 through 256 UTF-8 bytes. Reader lists sort by
raw principal ID. Direct slots sort by content role, recipient ID, then their
complete bytes.

`item_reader_set_change` also carries the replacement descriptor and current
body hash for a cover reseal or witnessed-policy rotation. In that case its
prior and next reader lists are equal, while the epoch, both revision secrets,
both seal IDs, both nonces, ciphertexts, and complete slot set still advance.

`DescriptorMetadataV1` is revision, `RevisionSealId`, 12-byte nonce,
ciphertext length `272`, ciphertext digest, plaintext schema `1`, and key
epoch. Its canonical form is exactly 97 bytes.

## Recipient slots

`DirectSlotV1` has the exact 1,365-byte J01A layout. Schema and algorithm are
`1`, suite is `1`, and KEM/KDF/AEAD are `0x647a`/`1`/`3`. Every context field
must agree with its owning operation. Wrong lengths, algorithms, suites,
contexts, ordering, or duplicated bytes fail before private-key work.

`WitnessShareCapsuleV1`, `WitnessedSlotV1`, and `WitnessedStateV1` use the
exact J19 capsule, slot, and slot-set layouts. Capsules sort by distinct share
index and repeat the slot context byte-for-byte. Their context and capsule-set
digests are recomputed. A witnessed state has exactly one descriptor slot and
one body slot, sorted by role, revision, seal ID, then slot ID; roles and slot
IDs are unique and its slot-set digest is recomputed. Every direct recipient
likewise has exactly one slot for each content role under one access role.

An operation must contain at least one access path. No direct slots means
`witnessed-only`; no witnessed state means `direct-only`; both means `mixed`.
Every embedded mode must agree. A witnessed-only item is valid without a direct
slot. The presence of even one direct slot suppresses the item-level quorum
claim; it is never interpreted as witness fallback.

Unknown slot variants cannot deserialize. There is no per-slot suite choice,
algorithm negotiation, classical fallback, epoch root, or reusable witness
contribution.

## Item envelopes

At most 1,024 item envelopes are stored, sorted by item ID. Each contains item
ID, descriptor metadata, its fixed 272-byte ciphertext, zero or more prior
signed item revisions, exactly one current signed item revision, and current
body ciphertext. The item map identity and every embedded identity agree.

Item revisions start at one without gaps and preserve the complete signed
metadata chain. A record stores vault/item IDs, item revision, previous hash,
key epoch, authorizing policy sequence, author, timestamp, body
`RevisionSealId`, nonce, ciphertext length/digest, plaintext schema `1`, bucket
ID, and signature. Prior records retain no ciphertext. The current ciphertext
length is the selected 4 KiB through 8 MiB plaintext bucket plus the fixed
16-byte storage-AEAD tag, and its digest is recomputed.

Revision seal IDs and nonces are unique across descriptor/body seals in an
artifact. Slot references may repeat a seal only for the identical item, role,
and revision. The artifact permits at most 65,536 item revision proofs. A
single complete replacement set cannot exceed the 16,384-current-slot state
cap; J06 replay owns the aggregate current-state count across items. The total
16 MiB artifact cap remains authoritative for retained history.

The decrypted `ItemDescriptorV1` is exactly 256 bytes: schema byte `1`, a
big-endian `u16` name length, a 64-byte canonical-name region with zero fill,
then zero-reserved bytes. The decoder rejects every other length, schema,
name profile, or nonzero padding byte.

The decrypted `ItemStateV1` is compact canonical JSON containing plaintext
schema `1` and at most 1,024 fields sorted by canonical field name. Each field
contains its private canonical name, an independently random nonzero 32-byte
`FieldId`, a standard-padded-base64 value of at most 1 MiB, the exact decoded
length, `text` or `concealed` kind, and creation/update times. Names and IDs are
unique; update time cannot precede creation; concealed values contain at least
four bytes so the output redactor can represent them safely. Field IDs are not
derived from names or values and are never reused by the state owner.

The canonical item-state JSON is prefixed by its four-byte big-endian logical
length and zero-filled to the smallest selected 4 KiB through 8 MiB bucket.
The decoder requires the exact bucket length, canonical logical bytes, and
all-zero remaining padding. This plaintext framing exists only inside the
authenticated body ciphertext.

## Suite migration

`SignedSuiteMigrationV1` is reserved outside destination genesis to avoid a
hash cycle. It binds the migration ID, old vault/genesis/terminal revision and
suite, new vault/genesis and suite, canonical migrated-item manifest digest,
and signature. Old and new lineages and suites must differ; destination fields
must equal the enclosing header. It never adds a second suite to either
lineage. The first `0.x` runtime can parse this representation but cannot create
or execute it.

## Fixed evidence

The Rust tests consume the exact J01A direct-slot bytes and J19 witnessed-slot
bytes, compare every production preimage builder byte-for-byte, compare the
Rust JSON writer to the standard-library Python fixture encoder, and exercise
the checked-in negative cases. The positive artifact contains only generic
`ExampleVault`-class public fixture bytes.
