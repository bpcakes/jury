# CP-06 CT Declassification And Naming Repair

Status: implementation review record

Base commit: `00bdc6e`

Checkpoint: `CP-06`

CP-06 removes ordinary-control-flow bypasses from the data-oblivious control
types and narrows the fail-closed comparison feature name to its actual scope.

## Explicit Declassification

`Choice` no longer implements `Eq` or `PartialEq` and no longer exposes
`unwrap_u8`. Public conversion is limited to:

- `declassify(reason) -> bool`;
- `declassify_u8(reason) -> u8`.

The normalized bit accessor used by branchless primitives remains private to
the `ct` module. Boolean composition and conditional selection use that private
accessor without creating public branch boundaries.

`CtOrdering` also loses ordinary equality. Its less, equal, and greater choices
remain hidden until the caller invokes reason-bearing `declassify`. The custom
`Debug` implementation is redacted, and normalized-state assertions remain in
the internal constructor and public conversion path.

`Mask<T>` no longer implements ordinary equality or exposes an unrestricted raw
value. Public raw-mask conversion requires `declassify(reason)`, while audited
branchless helpers use a private accessor.

## Strict Comparison Scope

The `strict-ct` feature is removed and replaced with:

```toml
strict-compare = ["asm-compare"]
```

`strict-compare` fails closed on non-Miri targets without the x86_64 or AArch64
assembly equality backend. It applies only to equal-length byte equality.
Ordering, conditional selection, copying, swapping, oblivious lookup, and
caller code retain their documented portable implementations and target tiers.

The leakage harness and evidence metadata record the new feature name.

## Repository Enforcement

`scripts/verify-ct-declassification.sh`:

- rejects the legacy extraction method or feature name in active source and
  manifests;
- compile-checks that raw `Choice` extraction is unavailable;
- compile-checks that `Choice` and `CtOrdering` ordinary equality is
  unavailable;
- compile-checks that unrestricted `Mask::expose` is unavailable.

The normal repository gate tests `strict-compare` directly for the crate,
examples, and leakage harness.

## Verification

The checkpoint includes:

- native primitive, ordering, mask, aggregate, derive, and interop tests;
- reason-bearing conversion throughout tests, Kani harnesses, examples, and
  leakage tooling;
- the Rust 1.90.0 all-feature workspace check;
- release codegen and leakage-smoke checks;
- Miri and Kani through the normal repository gate.
