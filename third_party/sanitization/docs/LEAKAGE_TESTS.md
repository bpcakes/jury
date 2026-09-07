# Leakage Testing

This document describes the leakage-test expectations for the native
`sanitization::ct` work. The repository ships an unpublished dudect-style
statistical timing harness in `tools/ct-leakage`. Until target-specific runs
are collected and attached to a release candidate, target tiers must not imply
measured hardware constant-time behavior.

## Claim Under Test

The crate's data-oblivious claim is:

> No secret-dependent control flow or secret-dependent memory access inside the
> provided primitives, under documented compiler, target, feature, and release
> profile conditions.

Leakage testing should try to falsify that claim on specific target machines.
It should not be described as proof of identical wall-clock timing.

## Required Inputs

A leakage-test run should record:

- crate version or commit hash;
- rustc version and LLVM version where available;
- target triple;
- CPU model and relevant CPU features;
- OS and kernel version;
- Cargo profile and optimization settings;
- enabled crate features;
- whether `asm-compare`, `strict-compare`, `cache-flush`, or `register-scrub` were
  enabled;
- number of samples and statistical threshold;
- whether CPU frequency scaling, turbo boost, SMT, and scheduler affinity were
  controlled.

Without this metadata, timing results are useful for local debugging but should
not promote a target tier.

## Harness Scope

The leakage harness covers fixed-size primitives where inputs can be
randomized cleanly:

- `ct::Choice` normalization and boolean operations;
- `ct::eq_fixed` for `[u8; 16]`, `[u8; 32]`, and `[u8; 64]`;
- `ct::cmp_fixed` for fixed byte arrays;
- `ct::ConstantTimeEq` for `SecretBytes<N>`;
- `ct::ConstantTimeOrd` for integer primitives;
- `ct::oblivious_lookup` with fixed public table length and secret index;
- `ct::conditional_copy`, `ct::conditional_swap`, and `ct::select_slice` with
  fixed public lengths.

Tests should compare distributions such as:

- all bytes equal vs. first byte different;
- all bytes equal vs. last byte different;
- low secret index vs. high secret index;
- true `Choice` vs. false `Choice`;
- success `PublicCtOption`/`PublicCtResult` vs. failure `PublicCtOption`/`PublicCtResult`.

## Out Of Scope For Leakage Harnesses

The initial harness should not claim to cover:

- arbitrary user closures passed to exposure or transform APIs;
- third-party cryptographic implementations;
- deserialization or formatting code;
- OS memory locking behavior;
- guard-page fault behavior;
- WASM browser or Node JIT behavior;
- hardware attacks outside normal userspace timing collection.

## Release Policy

Before a target moves to Tier A for the native `ct` claim, the release should
include either:

- a checked-in leakage harness with a recorded passing run for that target; or
- an explicit rationale explaining why the target is Tier A based on other
  release evidence.

Until then, keep the target at Tier B or Tier C and document the missing
measurement in `docs/EVIDENCE.md` and `docs/ct-evidence.json`.

## Harness

Run the default release-profile leakage pass from the repository root. On
x86_64/AArch64 this uses the default assembly equality backend:

```bash
cargo run --release --manifest-path tools/ct-leakage/Cargo.toml -- \
  --samples 200000 \
  --inner 500 \
  --output target/ct-leakage-default.json
```

Run the portable fallback explicitly for diagnostic evidence. AArch64 Linux
release evidence does not claim this fallback passes timing measurements:

```bash
cargo run --release --no-default-features --manifest-path tools/ct-leakage/Cargo.toml -- \
  --samples 200000 \
  --inner 500 \
  --output target/ct-leakage-portable-fallback.json
```

Run the same harness under the fail-closed strict comparison policy:

```bash
cargo run --release --manifest-path tools/ct-leakage/Cargo.toml --features strict-compare -- \
  --samples 200000 \
  --inner 500 \
  --output target/ct-leakage-strict-compare.json
```

Collect the CP-20 multi-seed default and strict-comparison evidence set:

```bash
scripts/collect-leakage-evidence.py \
  --output-dir target/cp20/leakage \
  --samples 50000 \
  --inner 200 \
  --warmup 1000 \
  --threshold 4.5

scripts/verify-target-evidence.py \
  --leakage-summary target/cp20/leakage/summary.json
```

The collector requires at least three distinct seeds for each of the
`default-compare` and `strict-compare` variants. It records and hashes every
underlying report; one passing seed is not accepted as release evidence. If a
primary run exceeds the threshold, the collector preserves that report and
runs exactly two fresh same-seed confirmations for diagnosis. The primary
excursion remains release-blocking even if both confirmations pass. An
operator must investigate it and produce a new candidate commit or record a
separate reviewed waiver outside this evidence pipeline. This policy does not
increase the threshold or retry until a passing result appears.

`strict-compare` only strengthens equal-length byte equality. Ordering,
selection, copy, swap, and lookup remain portable and are intentionally rerun
under that feature to catch feature-interaction regressions without claiming
an assembly backend for them.

The harness:

- builds in release mode with the exact feature set under review;
- records rustc, OS, architecture, git commit, configured samples, and enabled
  harness features;
- uses architecture cycle counters on x86/x86_64 and AArch64 for measurement
  resolution;
- pre-balances and shuffles the two sample classes before measurement so class
  membership is not correlated with late-run scheduler or frequency drift;
- collects two timing distributions per case;
- computes an absolute Welch's t statistic;
- exits non-zero when the configured threshold is exceeded;
- emits a machine-readable result that can be referenced from
  `docs/ct-evidence.json`.

Some hardened VMs, containers, or kernels can trap `rdtsc` or `cntvct_el0`.
Those environments are not suitable for this harness. Use a host that exposes
the counter, or keep the target tier at a level that does not cite measured
timing evidence.

For a release-candidate evidence run, the operator should separately record
whether the process was pinned to a CPU and whether CPU frequency scaling,
turbo/boost, SMT, or scheduler affinity were controlled. Those settings are
machine-specific and are not changed by the harness itself.

`scripts/verify-leakage-smoke.sh` runs a tiny high-threshold smoke check to keep
the tool compiling and emitting valid JSON. It is not release timing evidence.

This tooling should remain optional for ordinary users. It is release evidence,
not a runtime dependency.
