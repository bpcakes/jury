## Purpose

Own the safe Darwin running-image and bounded group-membership provider used by Jury. See README.md.

## Key entrypoints

- `src/lib.rs`: checked running-image query and native tests.
- `src/groups.rs`: fixed-capacity process-group query and response validation.
- `build.rs`: SDK-generated bindings limited to the main-header accessor, region-vnode and process-group queries.

## Edit here for X

Keep native calls and ABI handling here; expose only checked owned values.

## Invariants

- Require exact region response size; never dereference an input address.
- Only a complete exact leader singleton can prove sole group membership.
- Reject invalid group snapshots; saturation must never prove quiescence.
- Do not claim ownership or preemptibility for the synchronous group query.
- Decode bounded kernel paths without lossy UTF-8 conversion.
- Preserve the source license and document provider limitations.
- This provider has no file-size exemption or Jury-domain dependencies.

## Common commands

- `cargo test --manifest-path third_party/darwin-process-info/Cargo.toml --locked`
- `cargo clippy --manifest-path third_party/darwin-process-info/Cargo.toml --locked --all-targets -- -D warnings`
- `cargo fmt --manifest-path third_party/darwin-process-info/Cargo.toml -- --check`
