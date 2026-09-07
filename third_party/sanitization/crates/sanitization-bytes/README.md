<p align="center">
  <b>Fixed-capacity BytesMut secret storage for sanitization.</b><br>
  Clear-on-drop byte buffers that refuse secret-leaking reallocations.
</p>

<div align="center">
  <a href="https://crates.io/crates/sanitization">sanitization crate</a>
  |
  <a href="https://docs.rs/sanitization-bytes">Docs.rs</a>
  |
  <a href="https://github.com/valkyoth/sanitization/blob/main/docs/SAFETY.md">Safety</a>
  |
  <a href="https://github.com/valkyoth/sanitization/blob/main/docs/MIGRATION_2.0.md">2.0 Migration</a>
  |
  <a href="https://github.com/valkyoth/sanitization/blob/main/SECURITY.md">Security</a>
</div>

<br>

<p align="center">
  <a href="https://github.com/valkyoth/sanitization">
    <img src="https://raw.githubusercontent.com/valkyoth/sanitization/main/.github/images/sanitization.webp" alt="sanitization Rust crate overview">
  </a>
</p>

# sanitization-bytes

Small `bytes` integration crate for [`sanitization`](https://crates.io/crates/sanitization).

The main `sanitization` crate stays dependency-free. This sister crate provides
`SecretBytesMut`, a clear-on-drop wrapper around `bytes::BytesMut` for projects
that already use `bytes`. Its manifest requires `bytes 1.12.1` or newer so a
fresh downstream resolution cannot select releases affected by
`RUSTSEC-2026-0007`.

```rust
use sanitization_bytes::SecretBytesMut;

let mut token = SecretBytesMut::with_capacity(16);
token.extend_from_slice(b"session-token").unwrap();
token.extend_from_slice(b"-v2").unwrap();
token.clear_secret();
```

`SecretBytesMut` treats capacity as fixed after construction. Appending beyond
capacity returns an error instead of reallocating, because implicit growth would
free an old allocation that still contains secret bytes.
