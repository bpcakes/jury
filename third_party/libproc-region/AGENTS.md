## Purpose

Own the narrow safe Darwin region-vnode provider used by Jury. See README.md.

## Key entrypoints

- `src/lib.rs`: checked native query and native tests.
- `build.rs`: SDK-generated bindings limited to the main-header accessor and region-vnode query.

## Edit here for X

Keep native calls and ABI handling here; expose only checked owned values.

## Invariants

- Never accept a short kernel response or dereference an input address.
- Decode bounded kernel paths without lossy UTF-8 conversion.
- Preserve the source license and document provider limitations.
- This provider has no file-size exemption or Jury-domain dependencies.

## Common commands

- `cargo test --manifest-path third_party/libproc-region/Cargo.toml --locked`
- `cargo clippy --manifest-path third_party/libproc-region/Cargo.toml --locked --all-targets -- -D warnings`
- `cargo fmt --manifest-path third_party/libproc-region/Cargo.toml -- --check`
