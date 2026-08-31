# Jury 0.x direct cryptographic provider evidence

Status: **J01B engineering selection; pre-alpha; not independently reviewed;
not approved for real secrets**.

This record selects providers for the exact suite frozen in
[`jury-v1-suite.md`](jury-v1-suite.md). It does not change that suite, establish
whole-product security, or authorize witnessed cryptography before J19. The
machine-readable binding is
[`jury-v0-direct-crypto-gate.toml`](jury-v0-direct-crypto-gate.toml).

Evidence was collected on 2026-08-31 on Linux x86-64 with Rust 1.90 for the
minimum supported build and the current installed toolchain for exploratory
measurements. All fixture values are public test data.

## Selection

The direct suite is represented by Rust types, not runtime algorithm choices:

- HPKE Base mode with X-Wing, HKDF-SHA256, and ChaCha20-Poly1305 uses
  [`rust-hpke`](https://github.com/rozbb/rust-hpke) 0.14.0 at commit
  `57b14d8f156da78be61b23203b962b0985561831` and tree
  `5200f04caaea1965950ee352e8b98ae9157634ca`. The commit is dated 2026-07-20
  and is titled `sec: zeroization fixes for defense in depth (#112)`.
- Stored encryption uses `aes-gcm-siv` 0.12.1.
- Strict signatures use `ed25519-dalek` 3.0.0.
- General derivation and authentication use `hkdf` 0.13.0, `hmac` 0.13.0,
  and `sha2` 0.11.0.
- Password derivation uses `argon2` 0.6.0.
- Fallible OS entropy is converted once into a 32-byte seed for `chacha20`
  0.10.2's `ChaCha20Rng`; `zeroize` 1.9.0 owns wrapper cleanup.

Every direct dependency disables default features. Exact features, registry
checksums, licenses, source revisions, and the isolated lock are in the gate
manifest. The selected tree's lowest declared MSRV is Rust 1.89 because of
`aes` 0.9.3; Jury's workspace MSRV is 1.90. `subtle` 2.6.1 does not declare an
MSRV, so the successful Rust 1.90 build is the bounded evidence for it.

The security-critical transitive set is bound in the manifest. It contains
`aes` 0.9.3, `chacha20poly1305` 0.11.0, `curve25519-dalek` 5.0.0, `ml-kem`
0.3.2, `polyval` 0.7.3, `sha3` 0.11.0 and 0.12.0, `subtle` 2.6.1, `x-wing`
0.1.0, and `x25519-dalek` 3.0.0. The two SHA-3 versions are the only duplicate
security-critical crate: `ml-kem` uses 0.11 while `hpke` and `x-wing` use 0.12.

The selected feature tree contains no direct `getrandom`, PEM, PKCS8, legacy,
SSH, plugin, or general hazmat feature. `rust-hpke` necessarily activates the
provider-internal `x-wing/hazmat` and `ml-kem/hazmat` traits used for
deterministic encapsulation. They are part of the selected construction, are
not re-exported by Jury, and cannot be called through the wrapper contract.

Rejected alternatives:

- BoringSSL implements the selected HPKE KEM and AES-GCM-SIV and was useful as
  a cross-check, but making it the Rust product provider would introduce an FFI
  and native-build boundary for every operation.
- `libcrux-kem` 0.0.9 reproduced the official X-Wing KEM values, but its much
  larger generated/verification-oriented tree and missing selected-key
  zeroization contract make it a cross-check only.
- Enabling `rust-hpke/getrandom` would expose APIs that panic when OS entropy
  fails. Jury instead uses only caller-supplied RNG APIs.

Repository and release activity was inspected at selection time. That is a
maintenance snapshot, not a promise about future maintenance. The exact
selected-only lock contained 74 packages. `cargo audit --deny warnings` found
zero advisories and zero warnings against RustSec database revision
`ba9db2a77a6a0fe93bc63a3d9b730e08b145aff5`; absence from that database is not
an audit.

## Wrapper contract

Raw provider types and errors stay private to one `jury-core` crypto module.
Callers receive fixed-size Jury types and the J01A error vocabulary only.

| Boundary | Required implementation behavior |
| --- | --- |
| Suite selection | Accept only suite `0x0001`, HPKE Base mode, KEM `0x647a`, KDF `1`, HPKE AEAD `3`, and storage AEAD `31`. Reject every unknown or mixed identifier before private work. There is no runtime fallback or negotiation. |
| Public parsing | Enforce every J01A fixed length and public bound before provider deserialization, allocation, setup, or open. This makes provider assertions for wrong modes, oversized `info`, and wrong serialized lengths unreachable. |
| HPKE seal/open | Use only `XWing`, `HkdfSha256`, and `ChaCha20Poly1305` type parameters and the Base-mode in-place single-shot APIs. Preallocate exact output/scratch buffers through a fallible Jury allocation boundary. Never expose provider contexts or permit a second seal. |
| Entropy | Ask J02's fallible entropy boundary for exactly 32 bytes. On failure return `EntropyUnavailable` before constructing an RNG or provider output. Zero the seed after seeding `ChaCha20Rng`; use only `gen_keypair_with_rng` and `single_shot_seal_inout_detached_with_rng`. Never adapt a finite byte buffer into `CryptoRng`. |
| Stored AEAD | Use only AES-256-GCM-SIV with 32-byte key, 12-byte nonce, and 16-byte tag. Decrypt into private scratch, publish only after `Ok`, and wipe scratch on both paths. |
| Ed25519 | Construct fixed 32-byte keys and 64-byte signatures and call `verify_strict`; never call permissive verification or normalization APIs. Signing is deterministic PureEdDSA. |
| HKDF/HMAC | Use SHA-256 and fixed J01A output sizes. HMAC accepts only a full 32-byte tag and calls `verify_slice`; no truncation or ordinary equality. |
| Argon2id | Accept only version 1.3 and the two named J01A profiles. Validate profile, salt, output, and capacity before allocation. Use caller-owned workspace and wipe every block after success or error; do not rely on raw allocation deallocation to wipe. |
| Errors | Collapse secret-bearing decapsulation, tag, MAC, signature-context, and padding failures to `AuthenticationFailed`. Preserve distinct failures only when bounded public validation fully determines them before secret work. Never include provider messages or input bytes. |
| Output | Construct public result objects only after complete success. On error, wipe scratch and return no encapsulation/ciphertext/plaintext/signature prefix. |

`rust-hpke`'s OS-RNG convenience APIs are compiled out because `getrandom` is
off. Its caller-supplied RNG trait is infallible, so directly wrapping a
fallible OS source would still create a panic path. The seeded `ChaCha20Rng`
adapter avoids that mismatch: the sole failure occurs before provider entry,
and the RNG has a 64-bit block counter rather than a small exhausting buffer.
Its selected `zeroize` feature wipes internal output buffers and state on drop.

The provider exposes allocating HPKE helpers, but Jury's wrapper must use the
in-place variants with preallocated exact buffers. The `alloc` feature remains
enabled in the isolated conformance crate to exercise the frozen corpus; it is
not permission for product wrappers to allocate after provider entry.

## Side-channel and secret handling map

These are source-level properties and wrapper constraints. Rust compilation,
CPU behavior, caches, speculative execution, and future dependency changes can
invalidate them. No passing timing run proves constant-time behavior.

| J01A operation | Provider source evidence | Jury invariant and bounded nonclaim |
| --- | --- | --- |
| Hybrid key generation and decapsulation | Pinned `rust-hpke` X-Wing code zeros private seed copies and hybrid intermediates. `ml-kem` performs implicit rejection by deriving both candidate secrets and selecting from a constant-time ciphertext comparison; `x-wing`, `ml-kem`, and X25519 private types enable zeroization. | Expanded private keys never serialize through Jury. Only fixed-size KEM inputs reach the provider. The RustCrypto crates describe constant-time source design, but neither X-Wing nor ML-KEM reports an independent audit and no binary/hardware constant-time proof is claimed. |
| HPKE setup/open | `AeadKey`, nonce, exporter secret, and shared-secret wrappers zero on drop. ChaCha20-Poly1305 verifies its tag before decryption. Provider source documents panics for unsupported modes, oversized `info`, wrong-size deserialization, and OS entropy convenience calls. | Public validation makes those panic preconditions unreachable; `getrandom` is off; only Base and exact type parameters exist. All KEM and AEAD failures normalize to `AuthenticationFailed`. |
| AES-256-GCM-SIV open | `aes-gcm-siv` computes the expected tag and compares with `ctutils::CtEq`. If comparison fails after candidate decryption, it re-encrypts the buffer before returning `Err`. With `zeroize`, derived MAC/encryption keys and temporary blocks are wiped. | Jury decrypts into private scratch, publishes only on `Ok`, then wipes it. The crate says it is designed for constant-time operation through hardware intrinsics or portable multiplication; processors with variable-time multiplication are unsupported. Active 0.x remains Linux x86-64/aarch64 and J04 must retain that target caveat. The crate itself reports no audit. |
| Ed25519 signing | `ed25519-dalek` states that signing is constant-time and selected signing keys zero on drop. PureEdDSA is deterministic. | Return a complete fixed signature or no signature. General physical fault resistance is not provided or claimed; root, debugger, compromised-kernel, and hardware-fault attackers are outside the J01A local boundary. |
| Ed25519 verification | `verify_strict` rejects weak/small-order points and noncanonical scalars; its source explicitly permits variable-time branching because all inputs are public. | Only `verify_strict` is callable. Public validity timing may vary; it never changes error detail or permits accept-on-normalize. |
| HKDF/HMAC | HKDF writes a caller-sized output. HMAC checks full tag length and uses constant-time equality. Selected digest/MAC features zero internal state. | Fixed SHA-256 and output/tag lengths only; caller-owned intermediate/output buffers wipe on every exit. |
| Argon2id | The provider validates parameter and output lengths, exposes `hash_password_into_with_memory`, zeros initial/final temporaries with the selected feature, and can return `OutOfMemory`. Argon2id intentionally has data-dependent accesses after its first half pass. | Validate the public profile before a fallible workspace allocation, provide the workspace, and wipe it explicitly. Timing and memory use reveal the public profile; password-dependent memory behavior is the specified Argon2id algorithm, not an additional Jury claim. |
| Wrapper control flow | Provider comparisons and zeroization above cover primitive internals; selected direct provider sources contain no ambient logging. | Secret bytes never choose logs, errors, allocation sizes, retry counts, provider types, or fallback paths. Public bounds may fail distinctly before secret work. |

A mechanical scan of the exact direct crate sources found no unsafe blocks in
`hpke`, `aes-gcm-siv`, `ed25519-dalek`, `hkdf`, or `hmac`. `argon2`, `chacha20`,
and `sha2` contain internal unsafe allocation/SIMD/assembly dispatch. Their
exact versions and checksums are bound; Jury wrappers remain safe Rust under
the workspace `unsafe_code = "forbid"` policy. This source inventory is not an
unsafe-code audit.

## Conformance results

The committed standalone crate at
[`conformance/direct-crypto`](../../conformance/direct-crypto/) is not a Jury
runtime dependency. Its locked seven-test suite passed on Rust 1.90:

- all three frozen HPKE outputs opened; encapsulation and ciphertext mutations
  failed;
- a fresh seeded X-Wing HPKE round trip succeeded without an exhausting RNG;
- injected entropy failure returned before the provider closure ran and
  produced no output;
- both AES-256-GCM-SIV fixtures opened and mutations failed;
- all seven HKDF and three HMAC fixtures matched, and altered MACs failed;
- all twelve Ed25519 signatures passed `verify_strict`, while the noncanonical
  scalar fixture failed;
- both Argon2id profiles matched.

Pinned `rust-hpke` ran 148 upstream tests plus two doctests with its KAT feature.
Its selected official HPKE entry exactly matched Jury's embedded entry.

Additional cross-implementation checks used no Jury production builder:

- `libcrux-kem` 0.0.9 (crate checksum
  `541a7377fb35060892e0620982e224e47419f10da8c212453bf642dafe529691`)
  independently reproduced the official X-Wing encapsulation and shared
  secret. It remains outside the committed conformance tree because its
  verification-toolchain dependency includes the unmaintained
  `proc-macro-error2` 2.0.1 (`RUSTSEC-2026-0173`).
- BoringSSL commit `a074f282d026a0ebbed7c9efef5a0cf63f72338d` opened both
  Jury AES-GCM-SIV fixtures and all three Jury HPKE fixtures, rejected mutations,
  and released no output on failure. Exact source hashes are retained in the
  following table; this implementation is not a Jury dependency.
- Python `cryptography` 41.0.7 reproduced all seven HKDF outputs and verified
  all twelve Ed25519 signatures; Python's standard HMAC reproduced all three
  tags.
- system `libargon2` package `0~20190702+dfsg-4build1`, binary SHA-256
  `3c593c01d1c3497b1276537a1002c90ce3beb729a3520087608838cf8bbd847d`,
  reproduced both profiles.

| BoringSSL file at the pinned commit | SHA-256 |
| --- | --- |
| `include/openssl/hpke.h` | `f5f945e66c6950aa5d8ccf055c41d464e2f97d97fd6bfca3ee6898798dce03b5` |
| `include/openssl/xwing.h` | `680cde2d69133345374d5a398c5ce12cc483712b0174aaacdd42673146da978b` |
| `crypto/hpke/hpke.cc` | `7091b36d845bfdbb754dad5b0cf3840403b25488bb23a649f9fcb3948d084696` |
| `crypto/xwing/xwing.cc` | `b8c2374da36f5a65fbd5207025d766266241bf9854806a604aa0ce5e1fd1b4cf` |
| `crypto/cipher/e_aesgcmsiv.cc` | `83be363d48e1ef3eefd5c2b531d949deeaf07267dbde4bb3841e319fc35e33fb` |

Exploratory release-mode timings on the current Linux x86-64 host used these
predeclared denominators and countermetrics:

| Operation | Samples and result | Countermetric |
| --- | --- | --- |
| HPKE open | `n=100`, mean 170,839 ns, median 167,486 ns, p95 186,903 ns | invalid KEM vs invalid AEAD, `n=400` each interleaved, Welch `t=0.696` |
| AES-GCM-SIV 4 KiB open | `n=25`, mean 3,137 ns, median 2,864 ns, p95 3,353 ns | invalid first vs last tag byte, `n=50` each interleaved, Welch `t=2.927` |
| Ed25519 strict verify | `n=5,000`, mean 43,459 ns, median 42,535 ns, p95 51,056 ns | public-input operation; no secret-position comparison |
| HKDF | `n=5,000`, mean 1,681 ns, median 1,816 ns, p95 1,956 ns | fixed output and input profile |
| HMAC verify | `n=5,000`, mean 1,581 ns, median 1,466 ns, p95 1,955 ns | invalid first vs last tag byte, `n=20,000` each interleaved, Welch `t=-2.032` |
| Argon2id portable | `n=3`, mean 307,391,980 ns, median 308,310,732 ns | public 128 MiB profile |
| Argon2id hardened | `n=3`, mean 1,260,704,093 ns, median 1,269,786,728 ns | public 512 MiB profile |

These measurements are smoke tests for gross wrapper/provider divergence on
one machine. The small sample counts, scheduler noise, compiler, CPU, and lack
of a leakage model make them unsuitable as constant-time evidence.

## Reproduction

Run the durable checks from the repository root:

```sh
python3 scripts/check-direct-crypto-gate
cargo +1.90.0 test --manifest-path conformance/direct-crypto/Cargo.toml --locked
```

The first command binds the current suite document, entire vector file,
canonical vector sections, specification hash map, direct dependency features,
critical transitive checksums, `rust-hpke` revision, and conformance sources.
The second command executes the provider behavior. Changing any bound input
closes the gate until the selection and evidence are deliberately refreshed.

No result here is a security certification, independent review, FIPS-validated
deployment, constant-time proof, or statement that Jury protects secrets.
