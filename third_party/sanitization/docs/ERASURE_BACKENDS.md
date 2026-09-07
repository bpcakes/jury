# Erasure Backend Boundaries

This document records the CP-17 decision for representation wiping and
target-provided erasure extensions.

## Ordinary Coherent RAM

The core crate's private `wipe_backend` is the only backend used by safe public
wipe and secret-container APIs. It performs volatile byte stores with compiler
and hardware ordering boundaries under the documented native and WASM
conditions.

Primitive scalar representation wiping is restricted by the private unsafe
`ZeroValidPlainData` marker. The reviewed implementation set is:

- unsigned and signed integer primitives, including pointer-sized integers;
- `bool`;
- `char`;
- `f32` and `f64`.

Each listed type is `Copy`, has no destructor or ownership, contains no pointer
provenance or interior mutability, and has a valid all-zero representation.
The implementation writes a reviewed typed zero value with one typed volatile
operation rather than clearing the object byte by byte. This keeps
validity-constrained primitives such as `char` valid throughout the operation.
The marker is not public, cannot be implemented downstream, and is not
implemented generically for arrays, structs, enums, unions, pointers,
references, function pointers, `NonZero*`, `MaybeUninit<T>`, or third-party
types.

User-defined values continue to sanitize field by field through
`SecureSanitize`. The crate does not expose a safe raw-representation wipe for
arbitrary Rust types.

## Distinct Target Memory Categories

The following categories do not share one sufficient erasure contract:

| Category | Additional concerns beyond ordinary volatile stores |
|---|---|
| Non-coherent cacheable RAM | Target cache clean/invalidate operations, line alignment, and completion ordering |
| DMA/shared buffers | Device ownership transfer, coherency domain, bus ordering, and concurrent agent access |
| Persistent memory | Persistence-domain flushes, drain/completion semantics, and power-failure behavior |
| MMIO/device memory | Register-specific write semantics, access widths, side effects, and prohibited read/modify/write behavior |
| Hardware keystore/enclave handles | Vendor lifecycle commands rather than byte-addressable erasure |

An operation suitable for one category can be incorrect or destructive for
another. In particular, the ordinary RAM backend must not be presented as an
MMIO, DMA, or persistent-memory guarantee.

## CP-17 Decision

A public target-provided erasure trait is deferred from 2.0. A precise stable
contract requires concrete target prototypes and external review for each
memory category. Safe core APIs do not dispatch through downstream callbacks
and do not rely on untrusted target implementations for Rust memory safety or
for their documented ordinary-RAM clearing guarantee.

Future target integrations should be separate, explicitly unsafe APIs or
companion crates with:

- a single named memory category;
- target and address-space restrictions;
- pointer validity, alignment, access-width, aliasing, and lifetime contracts;
- explicit cache, device, persistence, and completion semantics;
- structured failure reporting;
- native hardware evidence and external unsafe-code review.

Until those requirements are met, applications must keep device-specific
erasure outside the core crate and treat it as a separate deployment boundary.
