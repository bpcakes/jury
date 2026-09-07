# performance-baseline

Unpublished CP-20 regression probe for wipe-path performance shape.

The tool reports relative ratios rather than absolute timings. It catches
pathological large-wipe scaling and accidental routing of specialized bulk
byte clearing through the intentionally slower generic per-element array path.
It does not authorize weakening compiler or hardware fence policy.

Run from the repository root:

```bash
cargo run --release --manifest-path tools/performance-baseline/Cargo.toml -- \
  --output target/cp20/performance.json
```
