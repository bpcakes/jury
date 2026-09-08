# Candidate cryptographic suite 0x0002

Status: J18 construction input, accepted for implementation only while
`scripts/check-suite2-inputs` passes against `jury-v2-crypto-gate.toml`.
This extends the accepted shared/direct and witnessed inputs; it does not
establish runtime readiness. Jury is externally
unreviewed pre-alpha and must not be used for real secrets.

Consumer: J18's explicit suite migration and subsequent item use. This input
prevents an algorithm switch with ambiguous context, partial migration or
provider drift. Supersede it when this suite is retired; preserve applicable
verification rules while artifacts using it remain readable.

## Selection and inherited components

The candidate suite name is
`jury-v2-xwing-hkdfsha256-aes256gcm-aes256gcmsiv-ed25519`. It selects HPKE Base
mode, X-Wing KEM `0x647a`, HKDF-SHA256 KDF `0x0001` and AES-256-GCM AEAD
`0x0002`. Suite 1 uses ChaCha20-Poly1305 AEAD `0x0003`. This is a distinct
cryptographic suite, not another implementation of suite 1. No comparative
security or performance advantage is claimed.

AES-256-GCM uses a 32-byte key, a 12-byte nonce and a 16-byte tag under the
[RFC 9180 AEAD registry](https://www.rfc-editor.org/rfc/rfc9180.html#section-7.3)
and [NIST SP 800-38D](https://csrc.nist.gov/pubs/sp/800/38/d/final). GCM is not
nonce-misuse resistant. Each Jury HPKE ciphertext uses a fresh encapsulation and
a new single-message HPKE context at sequence zero; no context is reused for
another message. The HPKE provider derives the AEAD key and base nonce. Jury
never supplies a separate caller-selected GCM nonce or retries with another AEAD.

The X-Wing key encoding, KEM construction, pinned hybrid HPKE derivation and
key-generation contract remain the accepted suite-1 components. In particular,
the selected Rust HPKE revision uses the explicitly pinned hybrid draft profile;
claiming plain RFC 9180 derivation for that experimental KEM would be incorrect.
X-Wing and the hybrid HPKE profile retain their disclosed draft/non-standard
status. Provider selection must pin the same exact profile on both sides.

All other components remain those of the accepted [suite-1
specification](jury-v1-suite.md): SHA-256, Ed25519, HMAC/HKDF-SHA256, Argon2id,
AES-256-GCM-SIV stored-data encryption, X-Wing recipient identities, Shamir share
construction and protected-memory/use restrictions. Item schema, policy schema,
witness protocol and construction identifiers stay at version one. The suite
identifier selects a composition of these components; it is not a schema version.

Principal identities, role descriptors and registration proofs retain identity
profile 1, including their existing fingerprints, signatures and two registration
challenge capsules. Registration proves possession of the same identity keys for
a fresh destination genesis; it does not encrypt an item or witness share.
Encrypted identity files retain their original protection profile. Migrating a
vault does not rewrite or upgrade an identity file.

Backup format 1 retains its Argon2id/AES-256-GCM-SIV construction, fresh salt,
nonce and private backup material. Its authenticated payload contains the exact
suite-2 vault and public catalog, and its header binds that vault's genesis and
policy position. Backup format 1 has no negotiable HPKE algorithm. Local audit,
receipt and checkpoint encoding remains unchanged and binds the new genesis.

## Exact HPKE context extension

Only these HPKE-related preimage domains use the suite-2 JCE prefix: ASCII domain
name, zero terminator, then big-endian u16 `0x0002`.

- `jury-vault-v1-direct-revision-secret-slot`
- `jury-vault-v1-direct-revision-secret-slot-aad`
- `jury-witness-v1/capsule/context`
- `jury-witness-v1/capsule/info`
- `jury-witness-v1/capsule/aad`
- `jury-witness-v1/contribution/info`
- `jury-witness-v1/contribution/aad`

Every subsequent field and its order is the existing suite-1 preimage for that
domain. Direct slots additionally carry suite 2, KEM `0x647a`, KDF 1 and AEAD 2
in their existing canonical public headers. A witnessed slot carries suite 2;
its capsules inherit that authenticated selection and have no separate
negotiable suite/KEM/KDF/AEAD fields. Capsule schema remains one. The
capsule context digest is recomputed from its suite-2 context preimage. These
headers and ciphertexts remain authenticated by the exact policy revision.

The direct revision-secret plaintext remains 32 bytes, producing 48 bytes of
HPKE ciphertext. A witness share and a request-session contribution remain 33
bytes, producing 49 bytes of ciphertext. Encapsulation remains 1,120 bytes and
recipient public keys remain 1,216 bytes. Truncation or unsupported lengths fail.

Unlisted preimages retain their accepted component-profile-1 encodings. This
includes stored-data AAD and item signatures, genesis/policy signatures, witness
policy/slot/set hashes, share commitments, requests, decisions, review labels,
anchors and receipts. Their algorithms are unchanged. Suite binding is supplied
by the signed genesis/header and the complete signed slot/capsule headers, with
new vault/item/seal identifiers and fresh encryption material on migration.
Witness requests and contributions also bind the exact new genesis, policy,
capsule context, request, session and checkpoint. Do not rewrite all domain
suffixes mechanically or infer an AEAD from a signature-domain suffix.

The authenticated vault suite must match every active direct and witnessed
slot. Capsule validation and opening require the containing witnessed slot's
validated suite explicitly. The protected share retains that selection, which
the sender uses for contribution encryption. The receiver chooses from
its authenticated vault/slot context. A response cannot request an algorithm.
No trial decryption, negotiation or fallback is permitted. Retained source
registration/identity profile-1 records are not active item slots.

## Migration binding and lifecycle

The only suite-changing transition is 1 to 2. Same-suite history rollover
preserves the source suite. Requesting migration 2 to 1, an unknown suite or an
implicit/default destination suite fails before private work. This direction is
an explicit release policy, not a claim that a higher identifier is more secure.

Every newly constructed bootstrap uses manifest version 2. For migration its
mandatory source suite is 1 and destination suite is 2; for a subsequent suite-2
rollover both are 2. The source-aware verifier compares the source suite with
the exact authenticated source header/genesis. All active items, roles, grants
and policy revisions use the accepted rollover mapping and completeness rules.

Prepare fresh content keys, vault/item/field/seal/slot IDs, stored ciphertext,
direct slots and witness intent. Sign the owner source bridge, then destination
genesis, then the complete bootstrap revision with fresh genesis-bound witness
capsules and new role proofs. Migration appends a `SignedSuiteMigrationV1` to
the destination vault after genesis is fixed. Its reserved signature preimage
is unchanged and commits:

- exact old vault ID, genesis, terminal revision and suite 1;
- exact new vault ID, genesis and suite 2;
- `migrated_item_manifest_digest` equal to the complete bootstrap manifest digest.

The signing key is the acting source owner, also the destination genesis owner.
Verify that owner at the exact terminal source state. Historical destination
validation uses the retained genesis owner's key, not a later owner label or
replacement key. This record is outside genesis, so signing it introduces no
genesis cycle. It must be present when the manifest suites differ and absent
when they are equal. Removing it, changing either suite, substituting a different
manifest or attaching a migration record to a same-suite rollover is invalid.

Actual construction opens every active source item under its authenticated
source suite and required Administer authorization, then encrypts fresh material
under suite 2. Copying ciphertext or accepting a direct path when witnessed
authorization is required is invalid. All source bytes remain unchanged. The
new destination is ready only after the complete required witness membership,
durable replay checkpoint and external anchor are registered, plus fresh backup,
adoption and redistribution artifacts. Exact-candidate recovery retains both
signed records and refuses changed source/candidate/suite parameters.

Old vaults, backups, Git objects and receipts retain their old cryptography and
access exposure. No operation deletes them implicitly or upgrades their past
security. Ed25519 authentication remains classical; suite 2 is not post-quantum
authentication, independent review, FIPS validation or a production-security claim.

## Required evidence before runtime adoption

The additional primary specification is NIST SP 800-38D (November 2007),
downloaded from its official publication URL with SHA-256
`d99f3921ccebca049e7522426553aba071dae14ec3d5b6041e8c111a6cb57bba`.
The revision work announced by NIST does not silently replace these pinned
bytes. RFC 9180 is pinned by the existing accepted source inventory. Mutable
hybrid specifications and analyses retain the exact revisions and full hashes
in the suite-1 gate and specification; this extension does not select “latest”.

The following is a construction argument under stated primitive assumptions,
not a new whole-program proof or an independent assessment:

1. For an active classical adversary with public ciphertexts and a decryption
   interface, use the existing X-Wing IND-CCA and HPKE Base-mode analyses pinned
   in suite 1 (`773d00abefd9e88552c8d5f4f04ae95597ff4844b56964d99be76be45632280d`,
   `379bafe1c6efd20f1193f0f1d3d21aa23d87db59cbf980f92372e7e02c4d435f`,
   `73c4980506e4a91e1d8184b117b215b1efb67237cff0718630fbd9d1d5c79f20`).
   The changed AEAD assumption is AES-256 PRP security and GCM confidentiality
   and ciphertext integrity with unique per-key nonces and 128-bit tags, as
   specified by SP 800-38D, including its IV requirements and authentication
   bounds. HKDF-SHA256 and the pinned hybrid profile retain their existing
   assumptions. No HPKE sender-authentication property is inferred from Base mode.
2. HPKE's suite-bound key schedule separates the AEAD identifiers. The seven
   application prefixes additionally separate both profiles. Public validation
   fixes the suite from signed state before private work. A relabeled old
   ciphertext therefore does not become a new-profile ciphertext; neither an
   AEAD retry nor a “first algorithm that opens” rule exists. This is the
   application composition argument; mutation vectors test its implementation
   obligations but do not prove the underlying assumptions.
3. Ed25519 authenticates the exact genesis, policy transition, slot headers and
   ciphertexts under the inherited classical unforgeability assumption. Fresh
   IDs and independent revision secrets bind the copied values to a new lineage.
   The two signed lineage records plus mandatory unequal-suite manifest binding
   prevent accepting a stripped or differently scoped migration as a same-suite
   rollover. Public readers authenticate the owner's provenance claim, not
   concealed plaintext equality; the constructor must perform the actual opens.
4. The witness construction retains its exact sharing, membership, authorization,
   receipt, replay and external-anchor state machine. Replacing both transport
   encryption hops with the selected HPKE profile changes no share threshold or
   authorization rule. A share commitment binds the suite-specific capsule
   context; its request-session envelope additionally binds request, action,
   witness, checkpoint, capsule set and expiry. A direct slot still gives its
   recipient unilateral access. Complete-quorum and freshness claims require the
   actual runtime checks and retain all endpoint-retention limitations.
5. Stored encryption, identity protection, password cost and backup encryption
   retain the suite-1 assumptions and bounds. Static recipient compromise still
   exposes retained capsules; fresh encapsulation does not create recipient-key
   forward secrecy. No new post-compromise-recovery, key-commitment, quantum
   authenticity, quantum chosen-ciphertext-oracle or whole-product security claim
   is introduced. Any record-now/future-quantum confidentiality argument remains
   conditional on the pinned hybrid KEM analysis and quantum security assumptions
   for the selected symmetric components; these tests cannot establish it.

The existing suite-1 construction assumptions and explicit nonclaims remain in
force. The new composition additionally depends on the selected GCM provider's
correct AES/GHASH implementation, single-message HPKE key/nonce uniqueness and
authentication before plaintext release. The gate must pin primary
specifications and analyses by revision/content hash, preserve all suite-1
vectors, and provide a complete argument for these inherited and changed
components. Passing cross-provider vectors is interoperability evidence, not a
proof of this construction's security.

Required conformance includes both Rust-to-BoringSSL and BoringSSL-to-Rust
AES-256-GCM HPKE checks with retained deterministic outputs; canonical direct,
witness-capsule and request-contribution contexts; wrong suite, key, context,
ciphertext and truncation refusal; and unchanged suite-1 compatibility. Pin
provider versions, source revisions, lock data and resolved features. In
particular, enabling `aes-gcm/zeroize` alone does not enable `aes/zeroize` or
`ghash/zeroize`; the selected graph must explicitly enable the required expanded
state cleanup and retain documented limits on compiler/provider copies.

Runtime tests must cover every migrated active item through direct and actual
witnessed paths, registration/anchor readiness, strict suite selection,
substitution and partial migration, subsequent mutations, same-suite rollover,
transfer and backup/restore, source immutability, interruption and exact retry.
The input gate opens only after a fresh solo verification of these exact
pre-implementation inputs. Review and implementation verification still follow;
neither is described as independent security review.
