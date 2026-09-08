# Candidate suite-2 provider evidence

Status: J18 pre-implementation evidence bound by `jury-v2-crypto-gate.toml`,
accepted for implementation only while `scripts/check-suite2-inputs` passes.
This is not runtime verification,
independent review or certification. Jury remains externally unreviewed
pre-alpha and must not be used for real secrets.

Consumer: the J18 suite-2 input gate. This record addresses selected-provider,
dependency, feature and canonical-context drift. Retire it with suite 2 while
preserving the inputs needed to read retained artifacts.

## Selected candidate

Rust HPKE remains 0.14.0 at
`57b14d8f156da78be61b23203b962b0985561831`, source tree
`5200f04caaea1965950ee352e8b98ae9157634ca`. The added HPKE AEAD provider is
`aes-gcm` 0.11.0. Its critical implementation dependencies include `aes` 0.9.3,
`ghash` 0.6.0, `polyval` 0.7.3 and `ctr` 0.10.1. Exact registry checksums,
complete transitive versions and declared features reside in the isolated
`conformance/suite-2/Cargo.toml` and `Cargo.lock`; the input gate must bind them.
This standalone crate is not part of the root workspace or a runtime dependency.

The HPKE feature set is `alloc,aes,chacha,mlkem,x25519`, with defaults disabled.
ChaCha support is retained for suite-1 compatibility and cross-AEAD refusal
checks. The allocating helpers are conformance tools only. Runtime wrappers must
use a protected, preallocated in-place single-shot interface, retaining
fallible OS-seed capture and the seeded ChaCha RNG. The existing suite-1
wrapper uses allocating HPKE helpers; replacing those helpers is required
runtime work, not an already observed property. The finite public entropy stream
in the conformance executable is never a runtime randomness adapter.

`aes-gcm/zeroize` clears its initial GHASH-key temporary but does not transitively
enable cleanup of AES expanded keys or GHASH/POLYVAL state. The selected graph
explicitly enables `aes/zeroize` and `ghash/zeroize`; the latter enables
`polyval/zeroize`. Source inspection confirms the AES and POLYVAL Drop cleanup
is conditional on those features. The existing root stored-data provider also
uses AES/POLYVAL, so its selected graph must retain these cleanup features when
the new provider is adopted. Feature presence is bounded source evidence, not
proof that every compiler spill, register or provider temporary is erased.

Post-implementation drift enforcement also follows the actual runtime
`jury-core` → `hpke` dependency closure. `--providers-only` verifies the isolated
graph hash, registry archives and extracted sources, pinned HPKE checkout, and
the runtime AES/GHASH/POLYVAL versions and cleanup features. CI runs this mode
and its negative controls. Feature-forcing runtime dependencies are intentional.
This mode does not run alternate-provider conformance: CI separately builds the
pinned BoringSSL source and runs both retained context consumers. The complete
local gate additionally binds the selected `libcrypto.a` bytes and runs the
Rust 1.90 context consumer; a CI rebuild is not expected to reproduce a local
archive hash across compiler/toolchain differences. Neither mode proves that
runtime secret handling is correct.

The provider README describes hardware AES/CLMUL paths and a portable path whose
timing depends on constant-time processor multiplication. This evidence is from
Linux x86-64; it makes no whole-program constant-time claim and does not extend
support to variable-time-multiply processors. The selected AES-GCM source
computes and compares the tag before applying the decryption keystream. Jury's
wrapper must still keep all output private until complete success and clear its
scratch on failure. A historical audit mentioned by an upstream README is not
an independent review of this version, composition or Jury build.

## Observed checks

BoringSSL at `a074f282d026a0ebbed7c9efef5a0cf63f72338d` is an alternate
implementation only. Its tracked cryptographic and header sources were clean
when the checked-in C++ consumer was compiled. Jury does not link this C++
consumer or BoringSSL into a runtime crate. The evidence below is
cross-implementation agreement, not independent security review.

- Four retained primitive cases cover 32-, 33-, 0- and 256-byte plaintexts.
  Current Rust deterministic seals match the retained bytes; BoringSSL opens
  them and independently reproduces their exact encapsulations/ciphertexts.
  Rust opens the retained alternate-provider outputs. BoringSSL refuses 36
  key/context/ciphertext/truncation mutations; Rust refuses 24 mutations and
  cross-AEAD opens.
- Seven retained canonical contexts cover two direct slots, three witness
  capsules and two request-session contributions. Both providers produce the
  exact same ciphertexts and open them. Each refuses 70 wrong-key, malformed
  length, wrong context, changed ciphertext, suite-prefix and cross-AEAD cases.
  The BoringSSL refusal consumer also requires zero plaintext output length.
- Protocol serialization tests compare the real public direct/capsule and
  contribution encoders with these contexts. The original suite-1 direct,
  witnessed, contribution, signing and rollover preimages still match their
  frozen corpora. These fixtures are not complete artifacts or live quorum proof.
- The context consumer passed on both the installed toolchain and Rust 1.90.0,
  the repository's minimum supported Rust version. This is a bounded observed
  build, not a promise for all platforms or toolchains.
- `cargo audit --file conformance/suite-2/Cargo.lock --deny warnings` exited
  successfully after checking 63 dependencies against RustSec database
  `faedffd5118c1835e13cca3babb6059afb1eb8d0` on 2026-09-07. No reported
  vulnerability or warning is not proof that vulnerabilities are absent.

## Acceptance boundary and remaining runtime work

The input gate binds the exact specification, provider graph, source revisions,
canonical inputs, retained vectors and verifier. A fresh solo source check
confirmed the selected features, registry source/archive equality, pinned Git
provider and exact preimage rules before this binding. The rollover gate's two
shared manifest encoding/test inputs are rebound for the explicit 1-to-2 and
2-to-2 version-2 shapes; its frozen version-1 inputs remain unchanged. That
shared shape extension alone does not authorize a runtime algorithm switch.
The complete input check must pass before private suite-2 crypto is added.
Suite-2 runtime
selection, migration, whole-artifact validation, native direct/witnessed flows
and backup/recovery tests remain required afterward. Do not infer readiness or
close J18 from these conformance results.
