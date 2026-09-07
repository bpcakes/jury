# Release 1.0.0

- Promoted the crate family from release candidate to stable `1.0.0`.
- Documented the Rust `Drop` limitation for
  `#[derive(SecureSanitizeOnDrop)]` on generic structs: sanitizable generic
  parameters must carry their `T: SecureSanitize` bounds on the struct
  declaration itself.
- Simplified `SecureSanitizeOnDrop` code generation by using Rust's standard
  split generics rather than a custom generic reconstruction helper.
- Added derive regression coverage for tuple structs,
  `#[sanitization(crate = "...")]`, and observable drop-time sanitization.
- Fixed `SecretPoolSlot::secure_clear()` in both native and WASM memory-lock
  backends so canary words are reinitialized after clearing. Live pooled slots
  now remain canary-valid, zeroed, and reusable after explicit clears or failed
  fallible replacement.
