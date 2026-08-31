# Jury witnessed construction v1

Status: selected for the experimental `0.x` implementation path on 2026-08-31.

This is a pre-alpha construction. It has not received external cryptographic
review, it is not a certification, and it must not be used for real secrets.

## Selection

Construction identifier `jury-witness-v1-shamir-xwing-hpke` (`u16 = 1`) is the
only witnessed construction in Jury vault format v1. It combines:

- an independently random 32-byte secret for each descriptor or body
  `RevisionSealId`;
- byte-oriented Shamir secret sharing over GF(2^8), with one 33-byte share per
  witness;
- a public, context-bound SHA-256 commitment to each full share;
- one J01B X-Wing HPKE Base envelope from the writer to each witness; and
- one new J01B X-Wing HPKE Base envelope from each authorizing witness to the
  request-specific endpoint key.

There is no construction-internal epoch root. There is no long-lived witness
share, device share, derived item key, or contribution that works for two seal
identifiers. The only reconstructed value is the exact 32-byte descriptor or
body revision secret already required by the J01A storage construction.

The witnessed policy contains between 2 and 32 witnesses inclusive. Its witness
threshold `t` is between 2 and the member count `n` inclusive. Every member has
a stable, explicit, unique `u8` share index in `1..=32`. Changing membership,
threshold, index assignment, contribution key, construction, or suite is a new
policy and requires the full rotation described below. There is no negotiation,
fallback, or second construction.

## Creation

For each descriptor and body seal independently, the authorized writer does all
of the following before publishing any new state:

1. Obtain independent fallible OS-random draws for the 32-byte revision secret,
   32-byte `RevisionSealId`, storage nonce, and a separate 32-byte share-RNG
   seed. Any failure publishes nothing.
2. Seed the J01B-selected `ChaCha20Rng` with the share-RNG seed. The seed is used
   for this one seal and is then wiped.
3. For every secret byte `s[j]`, sample `t - 1` uniform GF(2^8)
   coefficients and define

       f_j(x) = s[j] + a_j,1*x + ... + a_j,t-1*x^(t-1).

4. For witness index `x_i`, form the exact 33-byte share
   `x_i || f_0(x_i) || ... || f_31(x_i)`.
5. Compute one public SHA-256 share commitment over a JCE1 preimage that binds
   the full 33-byte share and every capsule-context field listed below. The
   writer-signed state authenticates the commitment. This lets an endpoint
   discard a corrupt or substituted witness response before interpolation.
6. HPKE-seal the exact 33-byte share to that witness's distinct contribution
   public key. The complete capsule context is both domain separated and bound
   by HPKE `info`/AAD. Wipe the plaintext share after the capsule is complete.
7. Encrypt the descriptor or body with its exact revision secret, then wipe the
   secret and every coefficient/share buffer after the atomic mutation is
   prepared.

The capsule context contains, without omission:

- construction ID, protocol version, suite and capsule schema;
- vault ID, genesis fingerprint, item ID, key epoch, and slot ID;
- descriptor/body role, revision number, and `RevisionSealId`;
- witnessed-policy ID, revision, digest, threshold, and member count;
- witness ID, contribution-key fingerprint, and share index;
- item policy sequence and the share commitment.

Every `VaultId`, `ItemId`, `PrincipalId`, and other native ID contributes its
exact J03-owned nonzero 32 bytes. A ULID, hexadecimal rendering, display label,
or other textual representation is never a cryptographic input.

J19B owns the byte-exact JCE1 preimages and message encodings. It may add
lengths, hashes, and duplicate consistency fields, but it may not remove or
reinterpret anything above.

## Authorization and release

The endpoint generates a new X-Wing HPKE key pair for every request. The public
key and its fingerprint are signed into the request. The private key is scoped
to that request; it is not a principal recipient key and is never reused.

Each witness independently validates the complete request, current checkpoint,
replay state, expiry, requester signature, action manifest, approver decisions,
and witness policy. On approval, it:

1. opens only its capsule for the exact requested seal;
2. checks the share index and context-bound commitment;
3. HPKE-seals that same 33-byte share to the request-specific endpoint key with
   the request digest, response expiry, witness identity, policy, seal context,
   and share commitment bound into `info`/AAD;
4. signs the response and encrypted-contribution digest;
5. durably commits replay/checkpoint state before releasing the response; and
6. wipes the opened share and HPKE intermediates.

The endpoint accepts responses only from distinct current members for the same
request, policy, threshold, item, role, revision, seal, capsule, and session key.
It opens each contribution into private scratch, checks the public commitment,
and collects at least `t` valid distinct shares. Invalid shares do not count.
When more than `t` valid responses arrive, the endpoint uses the lowest `t`
share indexes, making selection deterministic. It reconstructs exactly one
32-byte revision secret with Lagrange interpolation at zero, validates the
storage ciphertext with that key, and wipes every share and partial result on
success or failure.

Approver threshold and witness threshold are separate. An approver signature is
never a share; a witness transport connection is never an approval; one role
cannot count for another merely because the same operator controls both.

## Why retained endpoint state does not cross revisions

Let `R` and `R'` be different seal identifiers. Their revision secrets,
polynomials, share-RNG seeds, share commitments, capsule encapsulations, storage
nonces, and request session keys are independent. No value is derived from an
epoch secret or an earlier response.

Before public share commitments are considered, fewer than `t` shares of the
`R'` polynomial reveal no information about its constant term under Shamir's
scheme when its coefficients are uniform. Each individual 32-byte share value
is uniform. The commitment makes the complete construction computational rather
than information-theoretic: hiding additionally relies on SHA-256 preimage
resistance over that full-entropy share. Share capsules and contributions rely
on the exact J01B HPKE confidentiality assumptions.

Consequently, an endpoint retaining all state exposed by any number of earlier
authorized requests has no construction path to the secret for `R'`. It must
instead obtain `t` valid `R'` contributions under a currently accepted request,
break the share commitments or HPKE, compromise a threshold of witness
contribution keys, compromise the writer/plaintext boundary, or use an explicit
direct slot. These are the falsifiable alternatives tested by J19C.

The endpoint can always retain and reopen `R` after it was released. Jury does
not claim endpoint forgetting, use-without-view, retroactive revocation, or
control over copied plaintext.

## Provider binding

J19B, J19C, and the J19 construction gate must consume these exact inputs:

| Input | Exact binding |
| --- | --- |
| J01B revision | `560897e90fa7a7dc840458285ec64eff53a0a284` |
| J01B gate | `docs/security/jury-v0-direct-crypto-gate.toml`, SHA-256 `1617609d607487d01a11ce449420ea8bf9f76d1e42450dff89bb46d957998ae9` |
| J01B evidence | `docs/security/jury-v0-provider-evidence.md`, SHA-256 `5ea96dd0f7ec7614566fc168549a5e0f757c4944ebcf0d3bce772d71e426c7f0` |
| Shared suite | suite `0x0001`, X-Wing KEM `0x647a`, HKDF-SHA256 `0x0001`, ChaCha20-Poly1305 `0x0003`, PureEdDSA Ed25519, SHA-256, and the exact providers/features in the J01B gate |
| Share algorithm | Shamir secret sharing independently over every byte in GF(2^8), irreducible polynomial `x^8 + x^4 + x^3 + x + 1` (`0x11b`) |
| Share provider | `vsss-rs = 6.0.1`, crates.io checksum `d6bfc736cfd88115aedb95ba84bc2d428fe351e92a56f69fce090af301402d91`, source commit `50e4fbbad6163fe9a2a6766ef8e8da2c4477d35d` |
| Share features | `default-features = false`, exactly `alloc` and `zeroize` |
| Selected share API | only `Gf256::split_bytes` and `Gf256::combine_bytes`; Feldman, Pedersen, curve, bigint, random-participant-ID, serialization, and stream surfaces are excluded |
| Share source | normalized `Cargo.toml` SHA-256 `4c8ba9aa4c2aeef999dc6daea42b74078a2f3c0c548cb7cb9a4c16e3c8cf2feb`; `src/gf256.rs` `defdf39ee4119314945b395e35c2cf0b5190b1bad36903b368faff16a8b40e37`; `src/shamir.rs` `a5c889504f6eaecb6dd5daf8bf21c85d608dfff478107494f3826b1c6c57fba4`; `src/polynomial.rs` `beed35d468d836e77c41c5017c89c33e17225c97fb1ff88844f33e4cde4f4677` |
| Primary construction reference | A. Shamir, *How to Share a Secret*, DOI `10.1145/359168.359176`; archived paper bytes SHA-256 `d26af0bacb935dbd8bc66b138c2d512837c6fc08e67960d3981d469dd2af7498` |

The selected `vsss-rs` source uses full-field uniform GF(256) coefficients, has
no source `unsafe` blocks, and compiled as a selected-feature consumer on Rust
1.90.0. A narrow probe confirmed 3-of-5 reconstruction, the 33-byte share
shape, mutation sensitivity, and invalid-bound rejection. Its selected lock had
no RustSec warning on 2026-08-31.

The adapter must account for exact provider behavior:

- `Gf256::combine_bytes` does not know `t`. Two shares from a 3-of-5 split
  produce an unrelated 32-byte value rather than `NotEnoughShares`. Jury must
  authenticate and count at least `t` distinct shares before calling it.
- `split_bytes` and `combine_bytes` return ordinary `Vec` values. Jury must
  validate bounds before provider entry, immediately move outputs into
  zeroizing private storage, explicitly wipe the original allocation, and wipe
  every path after interpolation. Provider allocation failure is an
  availability failure and must occur before state publication.
- The crate does not authenticate transported shares. Jury's owner-signed
  share commitments, HPKE contexts, response signatures, and membership checks
  provide that application layer.
- Version 6.0.1 declares no Rust MSRV. The bound claim is only that the selected
  consumer compiled with Rust 1.90.0; J19 must lock the complete product
  dependency graph.
- The upstream README says audits were funded, but no public report was located
  for this exact release. No audit claim is made. The upstream lib-test target
  with only `alloc,zeroize` also references types behind disabled features and
  does not compile; Jury relies on its own selected-feature conformance corpus,
  not that target.

## Candidate comparison

The comparison date is 2026-08-31.

| Candidate | Result | Concrete reason |
| --- | --- | --- |
| Threshold or distributed X-Wing HPKE | Rejected for `0.x` | No maintained provider or finalized specification implements the exact J01B X-Wing HPKE suite with a threshold private key and matching vectors. Thresholdizing only X25519 or ML-KEM would not thresholdize the bound hybrid KEM. |
| NIST Threshold Call KEM previews, including Amber | Rejected for `0.x` | NIST IR 8214C is a call for submissions, and the current NIST page places these designs in the preview/package process. Amber is a special threshold lattice KEM preview, not the locked X-Wing HPKE construction. Adopting it would replace the J01B suite and add unsettled protocol, patent, provider, and vector inputs. |
| Generic MPC/distributed decryption | Rejected | No selected implementation matches Jury's locked suite and bounded self-hosted model. It adds interactive rounds and durable preprocessing without improving the required per-revision retention claim over independent secrets. |
| Independently encrypted revision-scoped Shamir shares | Selected | Shamir is public and simple; the exact J01B HPKE suite protects each share in storage and transit; the endpoint reconstructs only the one random revision secret it is allowed to use; `t-of-n` availability is retained. |
| `n-of-n` XOR shares | Rejected | It can provide the retention separation but every offline witness causes total unavailability and policy cannot express a bounded `t-of-n` quorum. |
| Feldman/Pedersen commitments or distributed generation | Rejected | The writer already legitimately creates and knows each revision secret. These schemes add group/provider/encoding inputs to address a malicious dealer that can already leak plaintext or destroy availability. A full-entropy, owner-authenticated hash commitment is sufficient to reject altered returned shares in this model. |
| Static `HKDF(endpoint_share || witness_share)` or reusable witness share | Rejected | A previously authorized endpoint can retain the witness input and bypass later witness participation. It directly violates the revision-freshness objective. |
| Witness coordination around one full revision secret | Rejected | Any service holding the full secret has unilateral cryptographic access; an API vote does not create a witness threshold. |

The current state of NIST threshold work is documented by [NIST IR
8214C](https://csrc.nist.gov/pubs/ir/8214/c/final), official PDF SHA-256
`de54616748224f5250a42369f64aaf58bebd894453cba9753448e733a6375b18`,
and the [Threshold Call submission
page](https://csrc.nist.gov/Projects/threshold-cryptography/tcall-1). These are
comparison inputs, not cryptographic dependencies of the selected construction.

## Rotation and recovery invariants

Changing any witness member, threshold, share index, witness contribution key,
or witnessed construction advances policy and item key epoch, generates fresh
descriptor and body revision secrets and `RevisionSealId` values, re-encrypts
both ciphertexts, creates entirely new polynomials/commitments/capsules, and
atomically replaces the slot set. Rewrapping an old share is not rotation.

An old witness key can still decrypt capsules preserved in Git history for the
old policy. Rotation protects only later seals. Historical exposure still
requires the old policy threshold, but it is not erased.

Recovery may restore an original witness key and its checkpoint/replay state,
or use an already authorized current access path to perform the full rotation.
It never lowers `t`, synthesizes a missing share, adds an undeclared direct slot,
resets replay state, or treats an external anchor as decryption authority. If
fewer than `t` valid witness paths remain and no already-active explicit direct
recovery path exists, the revision is unavailable.

## Direct and mixed items

A direct slot wraps the same exact revision secret but is unilateral. A current
item containing any active direct slot is a mixed/direct item and has no
item-level quorum or distributed-authority claim, even if its witnessed path is
otherwise valid. Direct access is never an automatic response to witness
denial, timeout, stale state, expiry, or malformed data. Adding a direct slot
requires the ordinary owner-authorized new-epoch replacement and is visible in
signed policy state.
