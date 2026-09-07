# ct-leakage

Unpublished timing/leakage evidence harness for the native `sanitization::ct`
work.

This is not a proof of identical wall-clock timing. It is a dudect-style
statistical smoke test that tries to falsify the crate's narrower claim for a
specific machine, compiler, feature set, and release profile.

Each case uses a pre-balanced, shuffled class schedule. This prevents one
class from being forced into the end of a run after the other class reaches
its quota, which would confound class timing with scheduler or frequency
drift.

The harness uses architecture cycle counters on x86/x86_64 (`rdtsc`) and
AArch64 (`cntvct_el0`) so release evidence has useful resolution. Hardened
VMs, containers, or kernels that trap those instructions are not supported by
this tool; collect evidence on a host that permits the counter or record the
target as missing measured timing evidence.

Run from the repository root:

```bash
cargo run --release --manifest-path tools/ct-leakage/Cargo.toml -- \
  --samples 200000 \
  --inner 500 \
  --output target/ct-leakage-default.json
```

The default harness uses the crate's default assembly-backed equality on
x86_64 and AArch64. To test the portable fallback explicitly:

```bash
cargo run --release --manifest-path tools/ct-leakage/Cargo.toml --no-default-features -- \
  --samples 200000 \
  --inner 500 \
  --output target/ct-leakage-portable.json
```

For checkpoint/release evidence, use the multi-seed collector instead of
accepting a single passing run:

```bash
scripts/collect-leakage-evidence.py \
  --output-dir target/cp20/leakage \
  --samples 50000 \
  --inner 200
```

The collector uses reproducible seeds, runs both default comparison and
`strict-compare` variants, and hashes each raw report. A primary threshold
excursion is retained and followed by exactly two fresh same-seed
confirmations for diagnosis. The primary excursion always fails the collector,
even when both confirmations pass. This keeps the release decision fail-closed
without weakening the configured threshold or retrying indefinitely.

For high-assurance release evidence, collect output on each target machine and
attach it to the release candidate or pentest handoff. Record CPU isolation,
frequency scaling, turbo/boost, SMT, and scheduler-affinity settings separately
if they were controlled by the operator.
