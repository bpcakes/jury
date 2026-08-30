# Jury v1 provider-neutral cryptographic suite

Status: **candidate J01A freeze awaiting author-distinct reproducibility
verification; pre-alpha; not approved for real secrets**.

This document defines the cryptographic properties and exact shared/direct
construction that J01B must implement and prove. It is not a provider selection,
security certification, FIPS validation, or independent cryptographic review.
The witnessed construction belongs to J19 and is intentionally absent except
where this document constrains its shared inputs and outputs.

## 1. Decision summary

Jury suite identifier `0x0001` is named
`jury-v1-xwing-hkdfsha256-chacha20poly1305-aes256gcmsiv-ed25519`.
The identifier is the two bytes `00 01` in cryptographic encodings and the
unsigned integer `1` in bounded JSON fields.

The suite is indivisible:

| Purpose | Exact selection | Identifier and fixed sizes |
| --- | --- | --- |
| Direct recipient KEM | `MLKEM768-X25519` (the X-Wing-equivalent CG construction) from `draft-ietf-hpke-pq-05` and its pinned transitive drafts | HPKE KEM `0x647a`; public key 1,216 bytes; private seed 32 bytes; encapsulation 1,120 bytes; shared secret 32 bytes |
| Direct recipient encryption | HPKE core `draft-ietf-hpke-hpke-04`, Base mode, single-shot API | mode `0x00`; no sender authentication from HPKE |
| HPKE KDF | HKDF-SHA256 | HPKE KDF `0x0001`; `Nh = 32` |
| HPKE AEAD | ChaCha20-Poly1305 from RFC 8439 | HPKE AEAD `0x0003`; key 32 bytes; nonce 12 bytes; tag 16 bytes |
| Stored-data AEAD | AEAD_AES_256_GCM_SIV from RFC 8452 | AEAD registry `31`; key 32 bytes; nonce 12 bytes; tag 16 bytes |
| Signatures | PureEdDSA Ed25519 from RFC 8032 with the strict validation profile in section 7 | public key 32 bytes; private seed 32 bytes; signature 64 bytes |
| Hash | SHA-256 | output 32 bytes |
| Local authentication | HMAC-SHA-256, untruncated | key 32 bytes; tag 32 bytes |
| General KDF | HKDF-SHA256 from RFC 5869 | output lengths in section 8; no implicit salt |
| Password KDF | Argon2id version 1.3 from RFC 9106 | exact profiles in section 9 |
| Random identifiers, secrets, and nonces | independent full-width OS-CSPRNG draws | exact retry and failure rules in section 10 |

The direct recipient construction uses HPKE Base mode because the selected PQ/T
KEM does not define `AuthEncap` or `AuthDecap`. Sender authenticity is supplied
only by the outer strict Ed25519 policy or challenge signature described below.
A recipient validates that signature, the complete public ancestry, the suite,
and all signed slot metadata before private-key work. There is no classical
fallback, PSK mode, dual wrapping, verify-any behavior, algorithm negotiation,
or retry under another suite.

HNDL confidentiality is required for stored direct slots. Post-quantum
authenticity is not required for Jury v1. A future quantum adversary able to
break Ed25519 can forge new policy, item, transfer, and receipt signatures; this
suite makes no contrary claim. That deliberate limitation avoids inventing a
composite-signature profile before Jury has a stable, interoperable, analyzed
profile to use. A later PQ-authentic suite requires a new suite identifier and a
new authenticated lineage.

## 2. Primary specifications and analyses

Hashes below are SHA-256 over the exact bytes at the linked URL. RFC and FIPS
status is final as named; every Internet-Draft is work in progress even if its
bytes are pinned here.

### 2.1 Normative construction sources

| Source | Status and role | SHA-256 |
| --- | --- | --- |
| [`draft-ietf-hpke-hpke-04.txt`](https://www.ietf.org/archive/id/draft-ietf-hpke-hpke-04.txt) | active Standards Track Internet-Draft, 2026-07-06; HPKE core | `7c3090db36136e58242216c04bcc744f297800a4a615680930c5a4e3ae7cd733` |
| [`draft-ietf-hpke-pq-05.txt`](https://www.ietf.org/archive/id/draft-ietf-hpke-pq-05.txt) | active Standards Track Internet-Draft, 2026-07-06; PQ/T HPKE profile and vectors | `c3afa3981c7e2aacac4912a8b58eca14a92a10c66c4fd4e9ff078195a1ac9c5d` |
| [`draft-irtf-cfrg-concrete-hybrid-kems-03.txt`](https://www.ietf.org/archive/id/draft-irtf-cfrg-concrete-hybrid-kems-03.txt) | Internet-Draft, 2026-03-02; concrete `MLKEM768-X25519` construction | `2292aa51d2b0e3bfe5f46ae67d945855c6fe8df7792f1e9af3cc7477a7b098b5` |
| [`draft-irtf-cfrg-hybrid-kems-12.txt`](https://www.ietf.org/archive/id/draft-irtf-cfrg-hybrid-kems-12.txt) | Internet-Draft, 2026-07-06; effective CG framework and security requirements selected by PQ `-05` | `3357939858dd988cf34d0d8c17c3d8df3cc992cc76e87fec23672f5bbb031b90` |
| [`draft-connolly-cfrg-xwing-kem-10.txt`](https://www.ietf.org/archive/id/draft-connolly-cfrg-xwing-kem-10.txt) | Internet-Draft, 2026-03-02; equivalent X-Wing algorithm and encodings | `530900ac0519e28eb1ff50bf80ecdb7648add22e500db72b465bab4fb6b6a5ec` |
| [`draft-irtf-cfrg-xchacha-03.txt`](https://www.ietf.org/archive/id/draft-irtf-cfrg-xchacha-03.txt) | expired Internet-Draft, 2020-01-10; rejected storage-AEAD comparison profile | `fa796b50265eeee383d40e82fed880267c7835e1b3d64c50c4f06162adaa1cfd` |
| [FIPS 203 PDF](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf) | final, 2024-08-13; ML-KEM | `fe1f12f32a7e44ec9fdebbf400cda843a40b506dee676725234dc6f7923b6cac` |
| [FIPS 202 PDF](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf) | final, 2015-08-04; SHA3-256 and SHAKE256 inside the hybrid KEM | `1592607831ff0908cc590632ce371c6c95e94025bb1a0c8ae90a4d0ec1ed025e` |
| [RFC 7748 text](https://www.rfc-editor.org/rfc/rfc7748.txt) | Standards Track; X25519 | `279ca0ecc5e92e2962e27b846986aeb74729d9dd34bd4a04a362f80dcb596ad3` |
| [RFC 5869 text](https://www.rfc-editor.org/rfc/rfc5869.txt) | Informational; HKDF | `7a40eb3835b35fc947eb12a2ed614db079d43b26e50dbc537c31fba16397089c` |
| [RFC 8439 text](https://www.rfc-editor.org/rfc/rfc8439.txt) | Informational; ChaCha20-Poly1305 | `25bef70fbf7a07ff45c2fe4cb7c6ce954eac687413d8610603268b4e4415324c` |
| [RFC 8452 text](https://www.rfc-editor.org/rfc/rfc8452.txt) | Informational; AES-256-GCM-SIV | `ca48ec466b401ce5d68d6d1628127a1800adcc16f2573646aaa3d7df284d3c17` |
| [RFC 8032 text](https://www.rfc-editor.org/rfc/rfc8032.txt) | Standards Track; Ed25519 | `ed63657ff389301282b169b0abde9b5dd2c7e4d524fdfa5da6ff3094fc93c4c3` |
| [RFC 9106 text](https://www.rfc-editor.org/rfc/rfc9106.txt) | Standards Track; Argon2id | `855c06f060379e34285e83a217e9069b5c72e161a1e54df9af5cd88dbb231f31` |

PQ `-05` has a stale normative citation to HPKE core `-03`, but its vector
procedure calls `EncapDerand`, which core `-04` defines and core `-03` does not.
Core `-04` also fixes DHKEM `Npk`/`Nenc` definitions. PQ `-05` directly cites
hybrid framework `-12`, while concrete-hybrid `-03` still cites framework `-09`.
Framework `-12` fixes pseudocode return ordering and combiner typos present in
`-09`. Jury therefore uses core `-04` and framework `-12`; it does not reproduce
either stale reference. Any revision substitution reopens J01A and requires a
semantic delta review plus complete vector and composition revalidation.

The official PQ HPKE vector corpus is pinned to annotated tag
`draft-ietf-hpke-pq-05`, commit
`6433c8fce0b8b749dfc86c1095081a88698ccfab`, at
[`test-vectors.json`](https://raw.githubusercontent.com/hpkewg/hpke-pq/6433c8fce0b8b749dfc86c1095081a88698ccfab/test-vectors.json),
SHA-256 `35c59f4a0132e5631e50ac039d8ca3a72e99f5e92dfd94d45338d6ae243f613c`.
The selected vector entry is mode `0`, KEM `25722`, KDF `1`, and AEAD `3`.

### 2.2 Security analyses

| Analysis | Claim used here | SHA-256 |
| --- | --- | --- |
| [X-Wing analysis](https://eprint.iacr.org/2024/039.pdf) | classical IND-CCA under the Curve25519 strong-DH assumption when ML-KEM fails; PQ IND-CCA if ML-KEM-768 and SHA3-256 assumptions hold | `773d00abefd9e88552c8d5f4f04ae95597ff4844b56964d99be76be45632280d` |
| [ML-KEM IND-CCA analysis](https://eprint.iacr.org/2024/843.pdf) | ML-KEM-768 IND-CCA assumption cited by the concrete hybrid draft | `a5ed0be5587f26b6849657bd571d364dffd2342972e6520056d79bf5e76fcddc` |
| [Quantum sponge analysis](https://eprint.iacr.org/2025/731.pdf) | quantum indifferentiability assumption for the SHA-3 sponge used by the hybrid KEM | `dadb7c1066290412255ae2db5cd3e6c66452a838600e5e5497cd81dd88e08a1f` |
| [Keeping Up with the KEMs](https://eprint.iacr.org/2023/1933.pdf) | LEAK-BIND-K-PK and LEAK-BIND-K-CT definitions and component results | `d8a4d2b4c9e7306d24f07ad77ca265241f22985d54fb2f5b1a1aa01ef3213a0c` |
| [Analysing the HPKE Standard](https://eprint.iacr.org/2020/1499.pdf) | HPKE composition results and key-compromise cases | `379bafe1c6efd20f1193f0f1d3d21aa23d87db59cbf980f92372e7e02c4d435f` |
| [An Analysis of HPKE](https://eprint.iacr.org/2020/243.pdf) | Base-mode message security under its stated KEM/KDF/AEAD assumptions | `73c4980506e4a91e1d8184b117b215b1efb67237cff0718630fbd9d1d5c79f20` |
| [HPKE PSK analysis](https://eprint.iacr.org/2023/1480.pdf) | supports the reason PSK is not inferred or substituted; Jury does not use PSK mode | `bc825192d1c0274b52cdacb6b855b7763fde03a98dd6ce3e83e598f8b4ce8665` |
| [AES-GCM-SIV analysis](https://eprint.iacr.org/2017/168.pdf) | nonce-misuse-resistant AEAD bounds summarized by RFC 8452 | `0256c61be014e9577183095d3426560765659b9f3d86c872fb0a36538d46dcd1` |
| [Ed25519 paper](https://ed25519.cr.yp.to/ed25519-20110926.pdf) | classical signature design and security rationale, subject to the strict profile and assumptions below | `820dcf8ad51f90849fd60f16971fdcfedaeb5e7aaed0f300154fe39c0d3da0e2` |
| [Argon2 design and analysis](https://www.password-hashing.net/argon2-specs.pdf) | memory-hard password hashing and stated time-memory trade-offs; it does not supply password entropy | `b492f7c05bfb24eb06cd292006e785080ecbde02b8496255fc52ec4f697de979` |

These analyses do not prove Jury's whole design. Each conditional property below
states the additional composition assumptions. J01B must verify that providers
implement the exact algorithms and rejection behavior; automated vectors and a
clean build are not independent cryptographic review.

## 3. Alternative comparison and rationale

### 3.1 Recipient encryption

| Candidate | Public key / encapsulation | HNDL | Classical hedge | Maturity and operational trade-off | Decision |
| --- | ---: | --- | --- | --- | --- |
| RFC 9180 X25519 HPKE | 32 / 32 bytes | No | Yes | final RFC, small and widely implemented; retained slots fall to a future quantum attacker with the recipient key | reject |
| PQ `-05` ML-KEM-768 HPKE | 1,184 / 1,088 bytes | Conditional | No | final ML-KEM primitive but draft HPKE binding; smaller than hybrid; a catastrophic ML-KEM failure loses all recipient confidentiality | reject |
| PQ `-05` MLKEM768-X25519 HPKE | 1,216 / 1,120 bytes | Conditional | Conditional | draft churn and larger artifacts, but official vectors and a peer-reviewed X-Wing-equivalent construction preserve a classical hedge if its assumptions hold | **select** |

The extra hybrid component costs 32 public-key bytes and 32 encapsulation bytes
over pure ML-KEM-768. A direct slot encrypting a 32-byte revision secret contains
1,120 encapsulation bytes and 48 HPKE ciphertext bytes before Jury metadata.
The selected fixed canonical direct-slot encoding is 1,365 bytes.

Operation cost is also cumulative: classical HPKE performs its X25519 work,
pure ML-KEM performs its lattice KEM work, and the selected hybrid performs both
plus SHA3-256 combination. No provider-independent timing number is claimed;
J01B must benchmark the exact candidate builds on supported targets. Classical
HPKE has the broadest mature provider set, pure ML-KEM narrows it, and the exact
hybrid draft narrows it further. The hybrid wins here because long-retained
slots justify that implementation and artifact cost; it is not the default
recommendation for short-lived traffic.

### 3.2 Stored-data AEAD

| Candidate | Key / nonce / tag | Nonce behavior | Portability and vector quality | Decision |
| --- | --- | --- | --- | --- |
| AES-256-GCM-SIV, RFC 8452 | 32 / 12 / 16 | misuse-resistant, but repeated nonce leaks plaintext equality and degrades bounds | final specification and vectors; two-pass encryption; best on platforms with safe constant-time AES/POLYVAL support | **select** |
| ChaCha20-Poly1305, RFC 8439 | 32 / 12 / 16 | distinct-message nonce reuse is catastrophic | final specification and strong portable software performance; one pass | reject for stored seals |
| XChaCha20-Poly1305, `draft-irtf-cfrg-xchacha-03` | 32 / 24 / 16 | larger random nonce lowers collision probability but is not misuse resistance | expired draft and no final IETF profile | reject |

Nonce uniqueness remains mandatory. AES-GCM-SIV is a damage-limiting backstop,
not permission to reuse nonces. Implementations never release unauthenticated
plaintext, including streaming prefixes.

### 3.3 Authenticity

Jury selects strict Ed25519 for classical authenticity and explicitly declines
PQ authenticity in suite `0x0001`. This keeps public descriptors and signatures
at 32 and 64 bytes and uses a final interoperable standard. It also means signed
history is not quantum durable. A composite Ed25519 plus ML-DSA construction was
not selected because J01A found no single final application profile fixing
component ordering, failure combination, encoding, and downgrade behavior that
this release is required to implement. If the threat model later requires PQ
authenticity, verify-all hybrid signatures and new-lineage migration are
mandatory; adding an optional PQ component to `0x0001` is forbidden.

## 4. Security-property matrix

`Conditional` is a positive claim only under every stated assumption. `No` and
`unproven` are nonclaims.

| Property | Result | Security notion, attacker, assumptions, and Jury composition |
| --- | --- | --- |
| Direct-slot confidentiality against a classical active attacker | Conditional | IND-CCA message security. Requires the X-Wing classical analysis (`773d…80d`), HPKE analyses (`379b…35f`, `73c4…f20`), HKDF-SHA256 PRF assumptions, ChaCha20-Poly1305 IND-CPA and INT-CTXT, fresh encapsulation, and exact Base-mode composition. Jury signs and validates all application metadata before decapsulation. Hashes expand in section 2.2. |
| HNDL confidentiality of retained direct slots | Conditional | PQ IND-CCA against a record-now/future-quantum attacker. Requires the X-Wing (`773d…80d`), ML-KEM (`a5ed…dc1`), quantum sponge (`dadb…a1f`), and HPKE (`379b…35f`, `73c4…f20`) analyses and assumptions, plus uncompromised recipient private material. It protects only new hybrid slots, never an older classical lineage. |
| Post-quantum authenticity | No | Ed25519 is classical. A quantum attacker that breaks it can forge signed state. |
| Classical sender authenticity for direct slots | Conditional | Classical signature unforgeability under the Ed25519 design assumptions (`820d…a0e`) and strict verification. HPKE Base contributes none. The owner-signed policy revision covers the exact direct-slot bytes and normalized-state transition; complete chain and authority validation occurs before private work. |
| Recipient-compromise forward secrecy | No | The recipient key is static. Later compromise opens every retained direct slot encrypted to it. Rotation protects later epochs only. |
| Post-compromise recovery for later epochs | Unproven/not claimed | J01A requires fresh keys, independent revision secrets and slots, removal of the old principal, and authenticated ancestry. No whole-application proof exists before J05/J06 implement and validate those transitions; retained earlier artifacts remain exposed regardless. |
| KEM shared-secret binding | Conditional | LEAK-BIND-K-PK and LEAK-BIND-K-CT under the CDM23 analysis (`d8a4…3a0`) and pinned generic-hybrid assumptions. Jury additionally signs the recipient-bundle fingerprint and exact encapsulation/ciphertext bytes. No MAL-level whole-protocol claim is made. |
| Stored-data nonce-misuse resistance | Conditional | RFC 8452 bounds and the AES-GCM-SIV analysis (`0256…cd1`). A repeated key/nonce leaks equality and repeated use worsens bounds. Jury still requires fresh random nonces and rejects duplicate seal tuples. |
| HPKE nonce-misuse resistance | Not required | Each direct slot uses a fresh single-shot HPKE context and one Seal operation. Reusing an encapsulation or context is invalid; ChaCha20-Poly1305 itself is not misuse-resistant. |
| Primitive key commitment | No | The selected HPKE and AEAD profile is not claimed to be key-committing. Signed canonical key fingerprints and context fields provide application key binding only after valid public-chain verification. |
| Rollback and replay resistance | Unproven/not claimed | Not supplied by primitives. J01A freezes the inputs required by complete signed ancestry, unique revision/seal IDs, local checkpoints, and stale-state rejection, but J05/J09/J25 must establish the application property. Deleting both artifact history and retained local state remains outside it. |
| Password guessing resistance | Conditional | Per-guess memory/time cost under the Argon2 analysis (`b492…979`) and exact RFC 9106 Argon2id profile. The attacker has the complete encrypted identity/backup and performs offline guesses. The KDF does not add entropy or make a weak passphrase safe. |
| Constant-time behavior | Unproven until J01B | Every secret-bearing provider and wrapper path has the requirements in section 12, but provider source evidence and platform caveats do not exist yet. Timing tests cannot promote this cell to proof. |
| FIPS-validated deployment | No | FIPS 203 defines ML-KEM; Jury, its provider, build, platform, and operation are not validated. |

One weaker recipient slot defeats an item-level HNDL or quorum claim. Any usable
direct slot is unilateral for its recipient. A classical slot, fallback, mixed
suite, unknown suite, verify-any signature, or dual-wrapped root is invalid.

## 5. Canonical encoding

All J01A preimages use the following `Jury Canonical Encoding 1` (`JCE1`). JSON
bytes are never hashed, signed, MACed, or supplied as AEAD AAD.

Every preimage starts with:

    ASCII domain bytes || 00 || u16be(suite_id) || ordered fields

The zero byte makes every domain prefix-free. Domain strings below contain only
lowercase ASCII letters, digits, `/`, and `-`; the terminator is not part of the
displayed string. Suite `0x0001` always contributes `00 01`.

Field encodings are exact:

- `u8`, `u16`, `u32`, and `u64` are unsigned fixed-width big-endian integers.
- `id32`, digest, fingerprint, MAC, secret, and `RevisionSealId` values are their
  exact fixed-width bytes. IDs are never their 64-character hexadecimal JSON.
- `bytes` and UTF-8 text are `u32be(length) || value`. Length counts bytes.
- `optional<T>` is `00` when absent or `01 || T` when present. Other tags fail.
- `list<T>` is `u32be(count) || concat(encoded elements)`. The owning table
  states the canonical order; duplicates fail before encoding.
- Boolean false and true are `00` and `01`.
- Enum tags are the exact `u8` values in section 6. Unknown tags fail.
- Fixed-size values never receive a length prefix. No alignment or padding is
  implicit.

`list<bytes>` therefore length-prefixes every element as well as the list count;
`list<fixed[N]>` does not. A named canonical composite has the raw field
concatenation defined below and is length-prefixed only where its consumer says
`bytes`. A table entry saying `preimage bytes` means one `bytes` field containing
the complete earlier JCE1 preimage, including its domain terminator and suite
identifier. These rules remove any implicit struct, serializer, or host-language
length encoding.

A preimage whose encoded variable field or list exceeds a bound in section 13
does not exist; the operation fails before hashing or private-key work.

## 6. Common discriminants

| Type | Tags |
| --- | --- |
| principal kind | `01` human, `02` machine, `03` approver, `04` witness |
| item kind | `01` canonical, `02` legacy |
| content role | `01` descriptor, `02` body |
| item access role | `01` reader, `02` writer, `03` owner |
| item access mode | `01` direct-only, `02` witnessed-only, `03` mixed |
| slot algorithm | `01` direct-hpke-v1, `02` witnessed-v1; `02` contents belong to J19 |
| protection mode | `01` portable, `02` device-bound |
| KDF profile | `01` portable-v1, `02` hardened-v1 |
| outcome | `01` success, `02` denied, `03` cancelled, `04` failed |
| item body bucket | `01` 4 KiB, `02` 8 KiB, `03` 16 KiB, `04` 32 KiB, `05` 64 KiB, `06` 128 KiB, `07` 256 KiB, `08` 512 KiB, `09` 1 MiB, `0a` 2 MiB, `0b` 4 MiB, `0c` 8 MiB |
| backup bucket | `01` 4 MiB, `02` 8 MiB, `03` 16 MiB, `04` 32 MiB, `05` 64 MiB |
| storage/root-wrap/payload algorithm | `01` AES-256-GCM-SIV |
| principal removal reason | `01` operator removal, `02` replacement, `03` suspected compromise, `04` retirement |
| local audit action | `01` vault create/import, `02` identity action, `03` policy mutation, `04` item mutation, `05` item read, `06` transfer, `07` backup, `08` restore, `09` execute/inject, `0a` witness request, `0b` verification, `0c` privacy cover |
| audit failure stage | `00` none, `01` public syntax, `02` authorization, `03` private authentication, `04` mutation, `05` durable commit |
| receipt kind | `01` transfer export, `02` owner backup, `03` backup verification, `04` real restore drill |
| receipt verification state | `01` captured, `02` verified, `03` drilled |

Policy operation tags are: `01 principal_add`, `02
principal_label_change`, `03 principal_remove`, `04 owner_grant`, `05
owner_revoke`, `06 item_create`, `07 item_rename`, `08 item_delete`, `09
item_role_change`, `0a item_reader_set_change`, `0b item_slots_replace`, and
`0c principal_replace`. Operations are encoded in caller-declared transaction
order; semantically equivalent reordering is not normalized. Each transaction
must already satisfy J05's legal-combination rules.

## 7. Key generation and canonical key encodings

`VaultId`, `PrincipalId`, and `ItemId` are independently sampled nonzero 32-byte
values. Ordinary creation accepts no caller-chosen ID. Imported artifacts and
test vectors use a separately typed exact-byte constructor.

The recipient public bundle is exactly 1,216 bytes:

    ML-KEM-768 encapsulation key (1184) || X25519 public u-coordinate (32)

The pinned HPKE profile defines `SerializePublicKey` and
`DeserializePublicKey` as the identity on this fixed-length string. Jury does
not add X25519 canonicality, low-order, or all-zero component rejection that the
hybrid KEM does not specify. Encapsulation performs the ML-KEM encapsulation-key
check required by FIPS 203; decapsulation applies ML-KEM implicit rejection and
combines the resulting secret with the X25519 result exactly as specified.
Missing, reordered, or wrongly sized components fail as public syntax. J01B
must match the pinned KEM's exact behavior and must not expose a component-level
validity oracle or silently substitute another KEM algorithm.

The recipient private bundle is the exact 32-byte hybrid-KEM seed. Expanded
component keys may exist only inside the provider's protected opaque object and
must not be serialized.

The verification public bundle is exactly one canonical 32-byte Ed25519 public
key. A signature is exactly `R (32) || S (32)`. Strict verification requires:

- canonical point encodings for the public key and `R` with encoded `y < p`;
- canonical scalar `S < L`;
- rejection of identity, small-order, and non-prime-order public keys and `R`;
- the uncofactored Ed25519 verification equation for the exact PureEdDSA
  message bytes; and
- no Ed25519ctx, Ed25519ph, prehash substitution, signature normalization, or
  verify-any fallback.

Signing keys are independent random 32-byte Ed25519 seeds. They are never
derived from recipient keys, passphrases, IDs, labels, paths, or one another.

`principal_descriptor_body` is the fixed 1,283-byte concatenation of `u16
descriptor_version = 1`, `principal_id`, `principal_kind`, the 1,216-byte
recipient bundle, and the 32-byte verification bundle. Its fingerprint is:

    SHA256(JCE1("jury-v1/principal-descriptor/fingerprint", body fixed[1283]))

Its self-signature signs:

    JCE1("jury-v1/principal-descriptor/self-signature", body fixed[1283])

A canonical principal descriptor is the 1,347-byte concatenation of that body
and its 64-byte self-signature. Where a policy field says canonical descriptor
`bytes`, JCE1 adds a four-byte length of `1,347` before these bytes.

The recipient public-bundle fingerprint used by direct slots is distinct from
the descriptor fingerprint:

    SHA256(JCE1("jury-v1/recipient-public-bundle/fingerprint",
                recipient bundle fixed[1216]))

Labels and timestamps are excluded. Duplicate-key checks compare each canonical
key component rather than fingerprints or principal IDs.

## 8. HKDF schedules

All uses below are RFC 5869 HKDF-SHA256 with `L = 32`. “zero salt” means exactly
32 zero bytes, not an absent or provider-default salt. Each `info` is the named
JCE1 preimage.

| Output key | Extract input | Expand `info` fields |
| --- | --- | --- |
| portable identity-root wrap key | salt = zero salt; IKM = 32-byte Argon2id output | domain `jury-v1/kdf/identity-root-wrap`; identity format `u16`; principal ID; protection mode |
| device-bound identity-root wrap key | salt = 32-byte Argon2id output; IKM = normalized 32-byte provider response | domain `jury-v1/kdf/device-root-wrap`; identity format; principal ID; protection mode; provider kind `bytes`; credential ID `bytes`; provider challenge/salt `bytes` |
| identity private-payload key | salt = zero salt; IKM = random 32-byte identity root | domain `jury-v1/kdf/identity-payload`; identity format; principal ID |
| backup outer key | salt = zero salt; IKM = 32-byte Argon2id output | domain `jury-v1/kdf/backup`; backup format `u16`; vault ID; backup ID `id32`; bucket ID `u8` |
| audit HMAC key | salt = zero salt; IKM = random 32-byte local audit/checkpoint seed | domain `jury-v1/kdf/audit-mac`; vault ID; genesis fingerprint; principal ID |
| checkpoint HMAC key | same seed, independent expansion | domain `jury-v1/kdf/checkpoint-mac`; vault ID; genesis fingerprint; principal ID |
| receipt HMAC key | same seed, independent expansion | domain `jury-v1/kdf/receipt-mac`; vault ID; genesis fingerprint; principal ID |

No HKDF output is used for two rows. Callers receive typed keys and cannot
request arbitrary labels. HKDF output-length, counter, allocation, or provider
failure is fatal before partial output escapes.

## 9. Argon2id profiles and passphrases

Both profiles use Argon2id version `0x13` (1.3), a fresh random 16-byte salt,
three passes, four lanes, and a 32-byte output:

| Profile | Memory | Use |
| --- | ---: | --- |
| `portable-v1` (`01`) | 131,072 KiB | mandatory interoperable default and minimum |
| `hardened-v1` (`02`) | 524,288 KiB | explicit operator choice |

The decoder matches the profile ID and complete parameter tuple before
passphrase capture or memory allocation. Unknown IDs, altered parameters,
arbitrary “within range” values, excessive parallelism, and resource requests
above the selected profile fail.

Passphrases are exact valid UTF-8 byte strings of 12 through 1,024 bytes. There
is no normalization, trimming, case folding, or locale conversion. Interactive
capture removes one terminal line ending; embedded NUL, CR, or LF fails. The
minimum length is not an entropy claim. A profile raises guessing cost but does
not make a weak passphrase safe.

## 10. Randomness, nonces, and secret lifetime

The OS cryptographic random source supplies independent draws for:

- every native ID, recipient private seed, signing seed, identity root, local
  audit seed, Argon2id salt, provider challenge, registration response,
  revision secret, `RevisionSealId`, HPKE encapsulation, and AEAD nonce;
- every replacement, reader-set change, cover reseal, backup, and migration;
  unchanged plaintext does not permit reuse; and
- descriptor and body material independently, even for the same item revision.

ID generation makes at most eight full-width 32-byte draws to avoid all zero.
`EntropyUnavailable` or eight zero draws returns a value-free error and publishes
nothing. After generation, the state owner checks all IDs ever present in the
known lineage, including tombstones. It may request at most eight independently
generated candidates; eight collisions returns `RetryExhausted` and publishes
nothing. `VaultId` has no global registry; worldwide uniqueness is a
probabilistic nonclaim, while every source and destination lineage available to
creation, import, migration, or rollover is checked.

Revision secrets and identity roots are 32 bytes. A revision secret is used as
the AES-256-GCM-SIV key for exactly one descriptor or body seal and is wrapped by
a fresh HPKE encapsulation separately for each direct recipient. AEAD nonces are
12 independent random bytes. Replay validation rejects reuse of any
`(suite, vault, item, epoch, role, revision, RevisionSealId, nonce)` tuple and
rejects a `RevisionSealId` used anywhere earlier in the lineage. A collision
fails the mutation; it is never repaired after encryption by changing metadata.

## 11. Exact shared/direct preimages

Every entry below is JCE1 with the displayed domain. Fixed digest fields are
SHA-256 of the exact referenced bytes. `canonical_*` values use the encodings in
this document; J05 may place them in JSON but may not redefine them.

### 11.1 HPKE and storage AEAD

| Domain | Ordered fields |
| --- | --- |
| `jury-vault-v1-direct-revision-secret-slot` | slot schema `u8`; vault ID; item ID; key epoch `u64`; content role; revision `u64`; `RevisionSealId`; recipient principal ID |
| `jury-vault-v1-direct-revision-secret-slot-aad` | policy sequence `u64`; recipient public-bundle fingerprint; access role; slot algorithm; item access mode |
| `jury-v1/registration/challenge-info` | challenge schema `u8`; vault ID; issuer principal ID; candidate principal ID; challenge ID `id32` |
| `jury-v1/registration/challenge-aad` | candidate descriptor fingerprint; creation time `u64`; expiry time `u64` |
| `jury-vault-v1-item-descriptor` | plaintext schema `u8`; vault ID; item ID; key epoch `u64`; descriptor revision `u64`; `RevisionSealId` |
| `jury-vault-v1-item-body` | plaintext schema `u8`; vault ID; item ID; key epoch `u64`; item revision `u64`; `RevisionSealId`; bucket ID `u8` |
| `jury-v1/identity-root-wrap/aad` | identity format `u16`; complete canonical public identity-header digest; role `01` |
| `jury-v1/identity-payload/aad` | identity format `u16`; complete canonical public identity-header digest; role `02` |
| `jury-v1/backup/aad` | backup format `u16`; canonical public backup-header digest; target bucket ID `u8` |

The direct-slot HPKE call is exactly single-shot Base encryption of the 32-byte
revision secret using KEM `0x647a`, KDF `0x0001`, and AEAD `0x0003`. Its `info`
and AAD are the first two rows. HPKE output is serialized as the 1,120-byte
`enc`, followed by the 48-byte ciphertext/tag.

`direct_slot_v1` is exactly:

    slot_schema u8 = 1
    slot_algorithm u8 = 1
    suite u16 = 1
    kem u16 = 0x647a
    kdf u16 = 1
    aead u16 = 3
    vault_id id32
    item_id id32
    key_epoch u64
    content_role u8
    revision u64
    revision_seal_id id32
    recipient_principal_id id32
    policy_sequence u64
    recipient_public_bundle_fingerprint digest32
    access_role u8
    item_access_mode u8
    enc fixed[1120]
    ciphertext fixed[48]

It is 1,365 bytes. The signed policy operation contains these exact bytes, not a
hash chosen by the serializer. Unknown tags, wrong lengths, mixed suite fields,
or disagreement with the recomputed `info`/AAD fails before decapsulation. The
owner-signed policy revision binds both the complete slot and the independently
computed resulting state hash; the slot AAD does not contain that state hash,
which would create a ciphertext/state-hash cycle.

### 11.2 Registration proof

The owner challenge signature signs domain
`jury-v1/registration/challenge-signature` with: challenge schema, vault ID,
issuer principal ID, candidate descriptor fingerprint, challenge ID, creation
time, expiry time, SHA-256 of `enc || ciphertext`, and a 32-byte response
commitment `SHA256(JCE1("jury-v1/registration/response-commitment", response))`.

Here `response` is fixed[32]. The complete owner-challenge digest is:

    SHA256(JCE1("jury-v1/registration/challenge-hash",
                challenge-signature preimage bytes,
                owner signature fixed[64]))

The candidate response signature signs domain
`jury-v1/registration/response-signature` with: the complete owner-challenge
digest, vault ID, issuer principal ID, candidate principal ID, candidate
descriptor fingerprint, challenge ID, SHA-256 of `enc || ciphertext`, and the
exact recovered 32-byte response. The response never appears in public output,
logs, receipts, or errors. A challenge is single-use and expires without
fallback.

### 11.3 Signed portable history

| Domain | Ordered fields signed by Ed25519 |
| --- | --- |
| `jury-v1/policy-genesis/signature` | vault ID; policy sequence `u64 = 0`; previous policy hash fixed[32] = all zero; creation time `u64`; owner canonical descriptor `bytes`; source attestation `optional<bytes>`; empty item inventory `list<bytes>`; empty grants `list<fixed[65]>` |
| `jury-v1/policy-revision/signature` | vault ID; sequence `u64`; previous revision hash; timestamp `u64`; author principal ID; canonical operation list; resulting normalized policy-state hash |
| `jury-v1/item-revision/signature` | vault ID; item ID; item revision `u64`; previous item-revision hash; key epoch `u64`; policy sequence `u64`; author principal ID; timestamp `u64`; body `RevisionSealId`; nonce fixed[12]; ciphertext length `u32`; ciphertext digest; plaintext schema `u8`; bucket ID `u8` |
| `jury-v1/transfer/signature` | transfer format `u16`; transfer ID `id32`; creation time `u64`; vault ID; source genesis fingerprint; source public revision digest; exact vault byte length `u32`; exact vault-byte digest; exporter principal ID |
| `jury-v1/suite-migration/signature` | migration format `u16`; migration ID `id32`; old vault ID; old genesis fingerprint; old terminal revision hash; old suite `u16`; new vault ID; new genesis fingerprint; new suite `u16`; canonical migrated-item manifest digest |
| `jury-v1/rollover/signature` | rollover format `u16`; rollover ID `id32`; source vault ID; source genesis fingerprint; terminal source revision hash; destination vault ID; destination suite `u16`; canonical unsigned bootstrap-manifest digest; acting owner principal ID |

The signature is never included in its own preimage. Chain hashes cover the
preimage and signature to bind a unique accepted record:

    policy_revision_hash = SHA256(
      JCE1("jury-v1/policy-revision/hash",
           signature_preimage bytes, signature fixed[64]))

    item_revision_hash = SHA256(
      JCE1("jury-v1/item-revision/hash",
           signature_preimage bytes, signature fixed[64]))

    genesis_fingerprint = SHA256(
      JCE1("jury-v1/policy-genesis/fingerprint",
           genesis_signature_preimage bytes, owner_signature fixed[64]))

`source attestation` is absent or one attestation byte string. Legacy migration
is tag `01`, source format `u16`, migration ID, final preserved legacy-audit
digest, and verified terminal legacy-audit MAC; the destination genesis owner
signature authenticates it. Rollover is tag `02 || rollover-signature preimage
bytes || signature fixed[64]`. Other tags and more than one attestation are
invalid. A suite-migration statement includes the destination genesis
fingerprint and is therefore recorded outside that genesis; embedding it in the
genesis would create a hash cycle and is invalid.

### 11.4 Policy operation encodings

Each operation is `tag u8 || ordered fields` and is placed in a
`list<bytes>`.
Canonical principal lists sort by raw 32-byte ID; slot lists sort by content
role, recipient ID, then raw slot bytes; item lists sort by raw item ID.

| Tag | Ordered fields after tag |
| --- | --- |
| `01 principal_add` | canonical descriptor `bytes`; display label `bytes`; registration-proof digest |
| `02 principal_label_change` | principal ID; prior label `bytes`; next label `bytes` |
| `03 principal_remove` | principal ID; removal reason `u8` |
| `04 owner_grant` | principal ID |
| `05 owner_revoke` | principal ID |
| `06 item_create` | item ID; item kind `u8`; key epoch `u64 = 1`; canonical descriptor metadata; canonical current item-revision hash; canonical direct-slot list; witnessed-slot corpus digest `optional<digest32>` |
| `07 item_rename` | item ID; prior descriptor revision `u64`; next canonical descriptor metadata |
| `08 item_delete` | item ID; final descriptor digest; final item-revision hash; deletion policy sequence `u64` |
| `09 item_role_change` | item ID; principal ID; prior role `optional<u8>`; next role `optional<u8>` |
| `0a item_reader_set_change` | item ID; prior epoch `u64`; next epoch `u64`; prior reader-ID list; next reader-ID list; replacement descriptor metadata; replacement current item-revision hash |
| `0b item_slots_replace` | item ID; next epoch `u64`; canonical direct-slot list; witnessed-slot corpus digest `optional<digest32>` |
| `0c principal_replace` | prior principal ID; next canonical descriptor `bytes`; registration-proof digest |

Canonical descriptor metadata is: descriptor revision `u64`, descriptor
`RevisionSealId`, nonce fixed[12], ciphertext length `u32 = 272`, ciphertext
digest, plaintext schema `u8 = 1`, and key epoch `u64`. Canonical normalized
policy state is the ordered concatenation of: suite; vault ID; sequence; active
principal descriptor list; sorted owner-ID list; active item metadata list;
sorted tombstone list; sorted direct grant list; sorted direct-slot list; J19
witnessed-state digest; and expected current item-revision list. Each variable
list uses JCE1 list encoding. The normalized-state hash is SHA-256 of domain
`jury-v1/policy-state/hash` and those fields.

The normalized-state fields and nested entries are exactly:

- suite `u16`; vault ID; sequence `u64`;
- active principals as `list<bytes>` of canonical 1,347-byte descriptors,
  sorted by the raw principal ID at body offset two;
- owners as `list<id32>`, sorted by raw ID;
- items as `list<fixed[171]>`, sorted by item ID. Each entry is item ID, item
  kind `u8`, item access mode `u8`, key epoch `u64`, canonical descriptor
  metadata fixed[97], and expected current item-revision hash;
- tombstones as `list<fixed[104]>`, sorted by item ID. Each entry is item ID,
  deletion policy sequence `u64`, final descriptor digest, and final
  item-revision hash;
- direct grants as `list<fixed[65]>`, sorted by item ID then principal ID. Each
  entry is item ID, principal ID, and access role;
- direct slots as `list<fixed[1365]>`, sorted by item ID, content role,
  recipient principal ID, then complete raw slot bytes;
- the J19 witnessed-state `optional<digest32>`; and
- expected current item revisions as `list<fixed[64]>`, sorted by item ID,
  where each entry is item ID followed by its revision hash.

The J19 witnessed-state digest is `optional<digest32>` and is absent until a J19
corpus is accepted. A state that contains witnessed data while the digest is
absent is invalid. J19 must define and bind the present digest through its own
gate; it may not change any J01A field or domain.

### 11.5 Identity and backup header encodings

The canonical identity header contains, in order: identity format `u16`,
principal ID, principal kind, recipient bundle fixed[1216], verification bundle
fixed[32], descriptor fingerprint, creation time `u64`, KDF profile `u8`, Argon2
version `u8 = 0x13`, memory KiB `u32`, passes `u32`, lanes `u32`, salt fixed[16],
protection mode `u8`, provider kind `bytes`, provider metadata `bytes`, root-wrap
algorithm `u8 = 1`, root-wrap nonce fixed[12], payload algorithm `u8 = 1`, and
payload nonce fixed[12]. Portable protection encodes empty provider-kind and
provider-metadata byte strings. Device provider metadata is exactly
`credential_id bytes || provider_challenge bytes`; the enclosing metadata is
itself one `bytes` field. Its digest is SHA-256 of JCE1 domain
`jury-v1/identity-header/hash` with the complete canonical header as one `bytes`
field.

The canonical backup header contains: backup format `u16`, backup ID, creation
time `u64`, vault ID, genesis fingerprint, source public revision hash, owner
principal ID, owner descriptor fingerprint, KDF profile `u8`, Argon2 version
`u8 = 0x13`, memory KiB `u32`, passes `u32`, lanes `u32`, salt fixed[16], storage
algorithm `u8 = 1`, nonce fixed[12], target bucket ID `u8`, payload ciphertext
length `u32`, and payload digest. Its digest is SHA-256 of JCE1 domain
`jury-v1/backup-header/hash` with the complete canonical header as one `bytes`
field.

### 11.6 Local HMAC records

HMAC tags are always full 32-byte HMAC-SHA-256 outputs. Comparison is
constant-time. A mismatch returns one value-free authentication error and no
partially parsed trusted state.

| Domain | Ordered MAC input fields |
| --- | --- |
| `jury-v1/audit/event-mac` | event schema `u16`; principal ID; vault ID; genesis fingerprint; policy sequence `u64`; operation ID `id32`; action `u8`; optional item ID; optional permitted item name `bytes`; outcome; failure stage `u8`; previous MAC |
| `jury-v1/checkpoint/file-mac` | checkpoint schema `u16`; principal ID; vault ID; genesis fingerprint; accepted public revision hash; latest audit MAC; audit genesis digest; update time `u64` |
| `jury-v1/receipt/file-mac` | receipt schema `u16`; principal ID; vault ID; genesis fingerprint; sorted receipt-entry list |

Receipt entries sort by receipt-kind tag then event time then raw operation ID.
Each contains kind `u8`, operation ID, captured public revision hash, event time
`u64`, output/payload digest, and verification state `u8`. Only transfer export,
owner backup, backup verification, and real restore-drill kinds are admitted.
No trusted path, item name, field metadata, passphrase, key, or value is encoded.
The receipt-entry list is `list<fixed[106]>`. Optional audit item IDs use
`optional<id32>` and optional permitted names use `optional<bytes>`.

## 12. Side-channel and secret-handling contract

J01B must supply source-backed evidence or an explicit bounded nonclaim for each
row. The requirement is independent of whether a timing test detects a problem.

| Operation | Secret inputs | Required behavior and observable boundary |
| --- | --- | --- |
| hybrid key generation and decapsulation | private seed, expanded ML-KEM/X25519 state, shared secrets | no secret-dependent branches or memory addressing in supported targets; exact implicit-rejection/error behavior of the pinned KEM; expanded keys never serialized |
| HPKE setup/open | recipient private key, KEM shared secret, key schedule | one public length/suite validation path before private work; no validity-oracle detail beyond one authentication failure |
| AES-256-GCM-SIV open | key and candidate plaintext | authenticate before any plaintext release; constant-time tag comparison; discard and zero candidate plaintext on failure |
| Ed25519 signing | signing seed, nonce scalar | deterministic RFC 8032 signing with provider protections against timing/fault leakage; no partial signature on failure |
| Ed25519 verification | public inputs | strict rules are mandatory even though inputs are public; no accept-on-normalize path |
| HKDF/HMAC | secret IKM, PRK, HMAC keys | fixed algorithms and output lengths; constant-time MAC comparison; intermediate state zeroized at the wrapper boundary |
| Argon2id | passphrase and workspace | profile validation before allocation/input; no secret output/logging; workspace wiped where provider supports it; timing necessarily reveals the public profile |
| wrapper control flow | all keys, responses, revision secrets | no logs, errors, allocation sizes, retry counts, or memory access depending on secret bytes; public format and resource failures may be distinct before secret work |

The remote attacker can submit arbitrary bounded public artifacts and observe
success/failure, response class, timing, and resource use. A local same-user
attacker may observe process timing and ordinary filesystem metadata but is not
assumed to have debugger/root control. Jury makes no protection claim against
root, an attached debugger, DMA, suspend images, a compromised kernel, or an
authorized child that receives plaintext.

Compact secrets must use the repository's protected-memory contract; bulk body
buffers and Argon2 workspaces are short-lived zeroizing allocations under
process-wide dump suppression. Secrets, passphrases, private keys, decrypted
payloads, and validity details never enter logs, errors, snapshots, receipts,
telemetry, or test output.

## 13. Limits and failures

Cryptographic parsing additionally enforces:

- one suite and one HPKE mode per lineage;
- a 16 MiB complete `vault.json` ceiling, 32 MiB transfer ceiling, 64 MiB
  backup-envelope ceiling, and 256 MiB local-audit ceiling before full parsing
  or cryptographic allocation;
- at most 256 active principals, 1,024 active plus tombstoned items, 16,384
  active direct grants, 16,384 current slots, 4,096 policy revisions, and
  65,536 retained item-revision proofs; the complete 16 MiB vault ceiling still
  wins when these independent counts would permit more;
- at most 1,024 fields in one imported item, 1 MiB decoded bytes per field, 64
  UTF-8 bytes per canonical item-name segment, 256 bytes per public label, and
  four local receipt entries;
- no generic JCE1 `bytes` field above 16 MiB and no generic list count above
  65,536. Tighter owning bounds apply first. A policy revision contains at most
  1,024 operation byte strings; an empty operation list is invalid;
- provider kind at most 64 bytes, credential ID at most 1,024 bytes, provider
  challenge exactly 32 bytes, encoded provider metadata at most 1,064 bytes,
  and a genesis source attestation at most 4,096 bytes;
- recipient bundle exactly 1,216 bytes, verification key 32, signature 64,
  HPKE `enc` 1,120, HPKE ciphertext 48, storage nonce 12, and storage tag 16;
- descriptor plaintext 256 and ciphertext 272 bytes;
- body plaintext bucket IDs `01` through `0c`, mapping exactly to 4 KiB, 8 KiB,
  16 KiB, 32 KiB, 64 KiB, 128 KiB, 256 KiB, 512 KiB, 1 MiB, 2 MiB, 4 MiB, and
  8 MiB respectively;
- a revision secret, identity root, local seed, response, and seal ID exactly 32
  bytes; and
- at most one HPKE Seal per context and one storage-AEAD Seal per revision key.

Public validation happens before passphrase capture, private-key work, KDF
allocation, or candidate plaintext release. The typed internal failures are
`UnsupportedSuite`, `NonCanonicalEncoding`, `InvalidPublicKey`,
`InvalidCiphertext`, `AuthenticationFailed`, `SignatureFailed`,
`EntropyUnavailable`, `RetryExhausted`, `KdfParameters`, `Capacity`,
`ResourceLimit`, and `ProviderFailure`. External private-operation responses collapse malformed
secret-bearing ciphertext, decapsulation, tag, MAC, signature-context, and
padding failures to `AuthenticationFailed` unless the failure was completely
determined by bounded public syntax before secret work. Errors contain no input
bytes, provider validity detail, secrets, guessed names, or secret-dependent
indexes.

## 14. Suite migration

Suite `0x0001` is authenticated at lineage genesis. Unknown identifiers fail
before private work. A suite change creates a new vault ID, genesis fingerprint,
item IDs, keys, revision/seal IDs, nonces, ciphertexts, and slots, then signs the
migration preimage in section 11. The source remains unchanged. No old and new
suite can coexist within one lineage.

Migration protects only the new lineage. A retained old artifact remains
attackable under its old suite. Migration is not retroactive HNDL protection,
revocation, or proof that old copies were deleted.

## 15. Vector corpus and required downstream tests

[`vectors/jury-v1-suite.json`](vectors/jury-v1-suite.json) is the language-neutral
J01A corpus. It contains the source hashes, one official selected HPKE vector
locator, fixture inputs, exact JCE1 preimages and SHA-256/HMAC/HKDF outputs, and
an Ed25519 signature corpus. Its frozen SHA-256 is
`204ff421daa6b56f4b8481291988a0eea9628e016833483720d72d81ccfb7486`.
It contains 46 JCE1 preimages, two independently encapsulated positive direct
slots, a positive registration challenge, both Argon2id profiles, descriptor
and body AES-GCM-SIV examples, portable/device identity headers, absent/legacy/
rollover genesis-attestation variants, twelve signatures, three local MACs, and
explicit negative/fault obligations. Generic fixtures use only `ExampleVault`,
`ExamplePrincipal`, and `ExampleSecret`-style public test values.

The deterministic X-Wing encapsulation seeds are public in the corpus. A
draft-10 implementation reproduced the pinned official PQ `-05` entry before
deriving the three Jury encapsulations; this is solo conformance evidence, not a
provider selection or independent review.

J01B must add provider known-answer tests for every normative algorithm and the
complete selected PQ HPKE vector entry. J05 must compare its production builders
byte-for-byte with every J01A preimage vector. J25 must exercise:

- every positive vector and a one-bit mutation of every field;
- wrong domain, suite, field order, integer width, identifier text, component
  order, key length, KEM/KDF/AEAD ID, role, revision, seal ID, nonce, fingerprint,
  state hash, and signature component;
- malformed ML-KEM/X25519/Ed25519 inputs and the provider's exact rejection
  contract;
- entropy failure, eight zero-ID draws, eight lineage collisions, allocation and
  KDF failure, HPKE/AEAD authentication failure, and zeroization on every exit;
- cross-provider agreement on valid outputs and fail-closed disagreement on
  invalid semantics; and
- migration into a fresh lineage plus rejection of fallback, mixed suite, dual
  wrapping, stale slot, repeated seal, and retained old recipient state.

Golden regeneration to force green, tolerance widening, weakened assertions,
and substituting production builders for the independent fixture encoder are
forbidden. Any vector change reopens J01A; any provider disagreement blocks
J01B.

## 16. Acceptance trace

| J01A requirement | Evidence in this artifact |
| --- | --- |
| exact suite and independent HNDL/PQ-authenticity decisions | sections 1, 3, and 4 |
| exact mutable specifications and applicable analyses | section 2 |
| jointly compatible HPKE core/KEM/mode/KDF/AEAD and outer authentication | sections 1, 2, and 11.1–11.3 |
| storage AEAD, MAC, KDF, hash, signatures, Argon2id, randomness, and failures | sections 1 and 7–13 |
| complete shared/direct domains, field order, lengths, encodings, and slot bytes | sections 5, 6, and 11 |
| exact native identifier bytes and bounded generation | sections 5, 7, and 10 |
| side-channel requirements and attacker observations | section 12 |
| no negotiation/fallback/mixed suite and new-lineage migration | sections 1 and 14 |
| positive, negative, fault, migration, and cross-provider vectors | section 15 and the linked corpus |
| no provider implementation or FIPS-validation claim | document status, sections 2, 4, and 12 |

Closure still requires an author-distinct verifier to cite the exact artifact
revision and independently rerun specification/size/encoding calculations plus
every claim-to-analysis/composition trace. A solo rerun is useful engineering
evidence but is not independent verification or independent cryptographic
review.
