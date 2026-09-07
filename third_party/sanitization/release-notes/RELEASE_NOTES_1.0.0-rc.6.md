# Release 1.0.0-rc.6

- Added optional `sanitization-derive` proc-macro sister crate.
- Added the `derive` feature to re-export
  `#[derive(SecureSanitize)]` and `#[derive(SecureSanitizeOnDrop)]`.
- Added derive support for structs, tuple structs, enums, skipped fields, and
  explicit custom bounds or crate paths through `#[sanitization(...)]`.
- Added `SecureSanitize` for `core::marker::PhantomData<T>` so generic marker
  fields do not force unnecessary `T: SecureSanitize` bounds.
- Kept default `sanitization` builds dependency-free; proc-macro dependencies
  are pulled in only when `derive` is explicitly enabled.
- Moved the repository to a two-crate workspace layout under
  `crates/sanitization` and `crates/sanitization-derive`.
