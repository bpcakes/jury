# Jury witness-v1 conformance corpus

This directory contains public, implementation-independent fixtures for the
pre-alpha witness-v1 construction and protocol. The values are deterministic
generic test material. They must never be used as credentials or with real
data.

The Rust consumer checks byte encodings, hashes, Ed25519 signatures, X-Wing
HPKE capsule/contribution opening, 2-of-3 GF(256) Shamir assembly, normalized
negative results, crash reconciliation, and the bounded retention model. The
Python standard-library runner independently checks the language-neutral
hash/shape cases, normalized request/presentation/state results, crash cases,
and the same finite retention model.

Run both consumers:

```text
cargo test --manifest-path conformance/witness-v1/Cargo.toml --locked
python3 conformance/witness-v1/alternate_runner.py conformance/witness-v1/vectors.json
```

Check deterministic regeneration without replacing the corpus:

```text
cargo run --manifest-path conformance/witness-v1/Cargo.toml --locked --bin generate -- --check
```

`generate --write` is an explicit maintainer action. A failing consumer is not
permission to regenerate: the protocol/provider input must first be deliberately
changed and the mismatch understood.

## Bounded model

The model fixes one selected construction, three witnesses with threshold two,
two approvers with threshold two, two distinct revision seals, and every
combination of access mode, zero through three compromised witness contribution
keys, zero through two compromised approver keys, and retained prior endpoint
material. It explores request creation, current approvals, replayed approvals
and responses, honest/compromised contributions, direct opening, quorum
assembly, and reopening the earlier revision.

The checked property applies only to witnessed-only items with fewer than two
current witness compromises, no current direct path, an honest writer with
independent per-seal secrets/shares, and the frozen idealized signature, hash,
HPKE, storage-AEAD, and canonical-validation assumptions. Threshold witness
compromise, active direct/mixed access, writer/plaintext compromise, primitive
breaks, correlated roles, and rollback of both witness database and anchor are
enumerated or named exclusions, not silently counted as success.

Exhausting this finite model is engineering evidence only. It is not a formal
proof, security certification, external review, production implementation, or
claim that Jury protects secrets.
