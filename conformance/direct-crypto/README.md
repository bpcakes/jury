# Direct cryptographic conformance

This standalone workspace checks the frozen, generic J01A corpus. It is
development evidence for externally unreviewed pre-alpha software and is not
evidence that Jury protects real secrets.

The Rust tests exercise the selected provider set:

```console
cargo test --manifest-path conformance/direct-crypto/Cargo.toml --locked
```

J25 also checks independently implemented providers. The alternate runner uses
BoringSSL commit `a074f282d026a0ebbed7c9efef5a0cf63f72338d` for HPKE,
AES-256-GCM-SIV, HKDF-SHA256, HMAC-SHA256, and Ed25519, plus the documented
machine's system `libargon2` for both Argon2id profiles. It covers all positive
primitive vectors and malformed key, encapsulation, ciphertext, signature,
domain input, tag, nonce, and length cases with no output on authenticated-open
failure.

Build BoringSSL's `crypto` target and point the check at its root:

```console
BORINGSSL_ROOT=/path/to/boringssl scripts/check-j25-alternate-crypto
```

The script verifies the exact BoringSSL revision and the security-critical
source hashes recorded at J01B. The CI workflow performs the same pinned
checkout and build. Provider agreement is conformance evidence, not independent
review or a side-channel proof.
