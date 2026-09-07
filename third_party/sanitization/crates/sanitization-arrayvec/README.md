<p align="center">
  <b>Fixed-capacity ArrayVec secret storage for sanitization.</b><br>
  Clear-on-drop array-backed buffers for projects that already use `arrayvec`.
</p>

<div align="center">
  <a href="https://crates.io/crates/sanitization">sanitization crate</a>
  |
  <a href="https://docs.rs/sanitization-arrayvec">Docs.rs</a>
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

# sanitization-arrayvec

Small `arrayvec` integration crate for [`sanitization`](https://crates.io/crates/sanitization).

The main `sanitization` crate stays dependency-free. This sister crate provides
`SecretArrayVec<T, CAP>`, a clear-on-drop wrapper around `arrayvec::ArrayVec`
for projects that already use `arrayvec`. Live values are sanitized and
dropped before the wrapper volatile-clears the complete inline
`MaybeUninit<T>` backing region, including bytes left by earlier pop, truncate,
clear, reuse, or wrapping operations.
Spare storage is passed directly to `sanitization::wipe::maybe_uninit`; the
wrapper never constructs references to uninitialized byte values.
`SecretArrayVec::from_arrayvec` is intentionally a runtime constructor in 2.0
because it clears historical spare bytes immediately.

```rust
use sanitization::SecretBytes;
use sanitization_arrayvec::SecretArrayVec;

let mut keys = SecretArrayVec::<SecretBytes<32>, 4>::new();
keys.push(SecretBytes::from_array([7; 32])).unwrap();
keys.clear_secret();
```

If `push` reaches capacity, `arrayvec::CapacityError` returns the original
element unchanged. The caller must securely reuse or sanitize it. Use
`push_or_sanitize` when rejection should consume and clear the element instead;
that method returns a payload-free `SanitizedCapacityError`. `pop` returns the
removed secret to the caller but clears its stale inline slot before returning.
`truncate` sanitizes removed elements before their destructors run.
