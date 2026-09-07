# Authenticated rollover bootstrap, version 1

Status: frozen suite-1 bootstrap input, accepted only while
`scripts/check-rollover-inputs` passes. This supplements the existing direct and
witnessed construction gates; it accepts no second cryptographic suite and is
not independent review. Jury remains externally unreviewed pre-alpha and must
not be used for real secrets.

Consumer: J18's rollover and migration constructor/verifier. This input gates
the bootstrap encoding because the reserved design contained a cycle through
genesis-bound witness ciphertexts. Supersede it when a new rollover format
replaces this one; retain the applicable version while its artifacts are read.

## Commitments and signing order

The existing `SignedRolloverV1` preimage is unchanged. Its
`bootstrap_manifest_digest` is SHA-256 of the exact encoding below. The public
manifest accompanies the statement; it is not an independently trusted file.
Genesis commits the statement and its signature. The acting owner must be an
owner at the exact authenticated terminal source revision, and is the new
genesis owner. Source freshness and external genesis trust remain separate
requirements.

Prepare fresh item identifiers, content secrets, seal identifiers, nonces,
content ciphertexts and initial signed item revisions before signing genesis.
Their existing suite-1 preimages do not contain the genesis fingerprint.
Prepare direct slots and the witnessed policy intent at this stage. The latter
includes complete membership, keys, operation rules and quorums, but excludes
values derived from genesis. Generate and reserve fresh witnessed slot IDs.

Compute the manifest, sign the source bridge, then sign genesis. Now generate
real destination-bound review labels, witness policies and capsules using the
reserved IDs and protected content secrets. Sign the complete first policy
revision with the acting owner. Reconstruct the manifest and verify that exact
first revision, all item ciphertext/signature chains and the complete resulting
policy state. Capsule ciphertexts and commitments are authenticated by that
revision, never inserted into the earlier manifest. Merely omitting the visible
genesis-fingerprint field from capsule bytes would not remove their dependency
on genesis.

This protocol authenticates the owner's asserted provenance and bootstrap. It
does not prove to a reader without plaintext access that the owner copied the
same plaintext, nor establish witness availability or freshness. The constructor
must actually decrypt and re-encrypt every active source item; its end-to-end
tests compare the resulting logical state. Readiness additionally requires all
witness registrations, durable initial replay state and an external anchor.

## Canonical bootstrap manifest

JSON is storage only and is never hashed. The binary preimage begins with
ASCII `jury-v1/rollover/bootstrap` followed by `00 00 01` (JCE1 for suite 1).
This encoding version remains identified explicitly; supporting another
cryptographic suite requires its own accepted suite binding before runtime use.
Integers are unsigned big-endian. IDs and digests are exactly 32 bytes, not
base64 or hexadecimal text. A `bytes` field is a u32 byte length and those bytes.
Every list is a u32 count followed by each entry as one `bytes` field. Booleans
are one byte, zero or one. An optional record is a zero byte when absent or a
one byte followed by the unframed fixed record when present. No sorting or
normalization occurs during verification: noncanonical ordering is rejected.

The top-level fields after the domain are: manifest version u16 (1), destination
suite u16, destination vault ID, creation timestamp u64, acting owner principal
ID, principal list, item list, witness-policy list. The complete preimage is
bounded by the existing 16 MiB vault-artifact limit. The containing vault remains
subject to that same limit independently; construction preflights the complete
encoded output before publication.

Principal entries are sorted by principal ID. Each is principal ID, unsigned
public-descriptor digest, display label as UTF-8 `bytes`, owner boolean. The
descriptor digest is SHA-256 of the existing principal self-signature preimage;
the final descriptor's actual self-signature must also verify. Display labels
retain their existing 256-byte bound. The list contains exactly the active
source principals; the owner booleans reproduce the active source owner set.
External principal identities retain their IDs and public keys. Rollover does
not invent recipient identities or silently replace their keys.

Human and machine principal additions in the bootstrap use SHA-256 of the
source bridge signature preimage as their `registration_proof_digest`: this
records the source owner's authorization to copy an already registered active
identity, not a new identity-registration ceremony or an old proof replay.
Approver and witness roles require new destination-scoped registration proofs.
The bootstrap verifier checks this distinction explicitly.

An entirely empty destination whose sole principal already has the genesis
label `owner` has no bootstrap operations. For this case only, its signed
sequence-one bootstrap revision may have an empty operation list. Its manifest
must commit that exact empty inventory and sole owner. Ordinary empty revisions
remain invalid.

Item entries are sorted by source item ID. Each is source item ID, destination
item ID, item-kind tag u8, existing `DescriptorMetadataV1.canonical_bytes()` as
`bytes`, initial signed item-revision hash, direct-slot-set digest, effective
grant list, optional witnessed item record. Item-kind and access-role tags are
the existing suite tags. Both destination descriptor and body revisions and key
epoch start at one. The signed item-revision hash commits the complete body
ciphertext metadata, including its fresh seal and nonce. That hash can be
computed before genesis; signature bytes themselves are not manifest fields.

The direct-slot-set digest is SHA-256 of a list of each complete canonical
direct slot as a `bytes` record, sorted in existing canonical slot order. Its
empty value is SHA-256 of four zero bytes. Direct-slot ciphertexts have no
genesis dependency. Grants are sorted by principal ID; each is principal ID,
effective access-role tag u8, direct-recipient boolean. They include all active
owners with Owner role and all explicit item readers/writers, including readers
whose only path is witnessed. The optional witnessed record is the fresh
witness-policy ID, fresh descriptor-slot ID and fresh body-slot ID, in that
order. It is absent only for direct-only access. Source item IDs, destination
item IDs and both sets of slots must be unique in their respective scopes;
destination item IDs must differ from every source item ID. The item list
contains exactly active source items, with no tombstones or omitted items.
Legacy items retain owner-only access.

Witness-policy entries are sorted by source witness-policy ID. Each is source
witness-policy ID, fresh destination witness-policy ID, policy-intent digest.
They cover exactly policies referenced by manifest items. Source and destination
policy IDs are unique; destination IDs are distinct from source IDs. Destination
policy revision is one, with no predecessor.

## Witnessed policy intent

The policy-intent digest is SHA-256 of JCE1 domain
`jury-v1/rollover/witness-intent` followed by one `bytes` field containing the
projected canonical `WitnessPolicy` body and a list of projected unsigned
owner-review-label signature preimages. Labels are sorted by label ID and are
exactly the set referenced by that policy's real review-label-set digest.

The projected policy uses the fresh destination vault and policy IDs, sequence
one, revision one, and zero predecessor digest. Genesis fingerprint,
vault-policy hash and review-label-set digest are set to 32 zero bytes.
Approver/witness descriptor self-signatures are set to 64 zero bytes; every
other descriptor field remains exact. All member ordering, role/key epochs,
share indexes, thresholds, operation rules, automatic target scopes and
no-direct-fallback flag remain exact. In each label signature preimage only the
genesis fingerprint is projected to zero. New labels use the destination scope,
sequence one and fresh label IDs. No secret names or plaintext field inventory
are added to public labels.

Projection is not validation. Before accepting a completed destination,
validate its real policy and labels with their existing rules and signatures.
Require actual genesis fingerprint and policy predecessor hash to equal the
new genesis fingerprint, sequence/revision one, zero predecessor policy digest,
and the actual signed label-set digest. Then project those validated objects
and compare the intent digest. Reject missing/extra policy or label material,
stale membership, invalid quorums or any direct fallback. The final signed first
revision binds the unprojected policy digest and every complete capsule; capsule
substitution therefore fails complete artifact authentication even though its
bytes are not pre-genesis inputs.

## Persistence and later verification

The manifest is public provenance carried by the signed rollover attestation.
Its claimed digest must always match its canonical bytes. Its source/target
scope must match the containing statement/genesis. Preserve it unchanged through
normal destination mutations, transfer, backup and restoration. First policy
revision ancestry is retained; its initial item hashes, descriptor metadata,
grants and slots let verifiers bind manifest claims after later item changes or
deletion. Historical witness policies and labels required to replay that first
revision remain in the authenticated portable catalog. An artifact without
those inputs is incomplete and is refused rather than treated as direct-only.

The source vault is immutable. Rollover consumes no new source revision, so a
history at its hard cap can be copied without pruning. Publish only to a hardened
absent destination after full validation and required state/backup durability.
Recovery of partial external registration binds the same destination ID, genesis
and manifest; a retry never regenerates a candidate under old approvals. Every
installation explicitly adopts/trusts the new genesis and receives a fresh
backup/export receipt. Old artifacts retain their original cryptography and
recipient exposure; no Git operation or old-object deletion is implicit.
