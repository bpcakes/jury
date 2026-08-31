# Jury vault-v1 format vectors

These are public, generic pre-alpha fixtures. They are not suitable for real
secrets.

`example-vault.json` is the exact pretty-printed byte representation of an
empty native Jury vault. `vectors.json` binds its SHA-256 digest, the J01A
direct-slot corpus, the J19 witnessed-slot corpus, and the format-negative
cases consumed by `crates/jury-protocol/tests/vault_v1.rs`.

The standard-library Python encoder is deliberately separate from the Rust
codec. Check deterministic agreement with:

```console
python3 conformance/vault-v1/alternate_encoder.py
cargo test -p jury-protocol --test vault_v1 --locked
```

Regeneration is explicit:

```console
python3 conformance/vault-v1/alternate_encoder.py --write
```
