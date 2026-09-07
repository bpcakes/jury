# Reproducible Dependency Resolution

Published Rust libraries normally use compatible semantic-version ranges. This
allows downstream applications to receive compatible security and correctness
updates, but a library's repository `Cargo.lock` does not constrain the graph
resolved by its consumers.

High-assurance deployments must control the complete application or system
image dependency graph. Exact pins inside this library would not constrain
other dependencies selected by the final application and would prevent normal
compatible security updates.

## Deployment Procedure

1. Commit the final application's `Cargo.lock` and review every dependency
   change.
2. Build and test with the committed resolution:

   ```bash
   cargo test --workspace --all-features --locked
   cargo build --release --locked --frozen
   ```

3. For offline or controlled-source builds, vendor the locked graph:

   ```bash
   cargo vendor --locked vendor
   ```

   Commit or independently archive the vendor tree and configure Cargo source
   replacement using the snippet printed by `cargo vendor`.
4. Run advisory and policy review against the resolved graph, for example with
   `cargo audit`, `cargo deny`, or organization-managed `cargo vet` criteria.
5. Record the Rust toolchain, target, enabled features, lockfile digest, source
   archive or vendor-tree digest, and build profile with the release evidence.

`--locked` rejects lockfile drift. `--frozen` additionally prevents Cargo from
using the network. Neither flag replaces source review, advisory monitoring,
artifact reproducibility controls, or deployment hardening.

This repository pins `cargo-deny 0.20.2` in CI and runs
`scripts/verify-dependency-policy.sh` over every independent Cargo graph. The
policy in `deny.toml` rejects unknown registries, Git dependencies, wildcard
requirements, and unapproved licenses while reporting duplicate versions for
human review.
