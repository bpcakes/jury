# CP-05 Fixed Allocation And Aggregate Guidance

Status: implementation review record

Base commit: `e3a5cc9`

Checkpoint: `CP-05`

CP-05 adds a runtime-length secret byte container whose backing allocation
cannot grow or shrink after construction. It also corrects aggregate guidance
around generic boxes and vectors.

## `SecretBoxBytes`

`SecretBoxBytes` owns one private fixed-capacity `Vec<u8>` allocation and is
available with `alloc`. The representation supports stable-Rust fallible
reservation, but the public API exposes no growth, shrink, or ownership
extraction operation. Clearing covers the full reserved capacity.

The public lifecycle includes:

- zeroed, boxed-slice, borrowed-slice, infallible generator, and fallible
  generator constructors;
- bounded constructors that reject excessive public lengths and report reserve
  failure;
- direct shared and mutable slice exposure;
- same-length slice, boxed-slice, infallible generator, and fallible generator
  replacement;
- explicit copying into a same-length caller buffer;
- immediate clear, clear-on-drop, and consuming clear;
- native public-length CT equality;
- optional serde, zeroize, and subtle interop.

The type does not implement growth, truncation, append, ownership extraction,
ordinary equality, dereference traits, cloning, copying, or value-printing
debug output.

## Replacement Invariant

Every replacement requires the original public length. A complete
clear-on-drop replacement is constructed before the old allocation is cleared.
Only then are the backing allocations exchanged. Generator failure or panic
leaves the old value unchanged and clears partial replacement storage.

A rejected boxed-slice replacement is first wrapped in `SecretBoxBytes`, so the
rejected allocation is cleared before the length error is returned.

## Serde Ingestion

Borrowed byte inputs use bounded fallible construction. Owned byte buffers are
placed under `SecretVec` ownership before validation, generic error conversion,
or destination allocation, so normal return and unwinding clear their full
capacity. Sequence inputs use `SecretVec` as a managed-growth temporary, copy
once into the final fixed allocation, and clear the temporary on drop. The
existing public 1 MiB default byte limit applies.

This protects crate-owned intermediates. A serializer implementation may have
created ordinary buffers before invoking the visitor.

## Aggregate Guidance

The documentation now distinguishes:

- `SecretBoxBytes` for a fixed runtime length;
- `SecretVec` and `SecretString` for managed wipe-before-grow storage;
- mapped locked and guarded containers for native platform protection.

Generic `Vec<T>` sanitization clears live elements and the current allocation
capacity but cannot recover historical allocations already released by
caller-controlled operations. Generic `Box<T>` sanitization is field-wise and
does not claim to clear unknown representation padding.

## Verification

The checkpoint includes:

- fixed-allocation ownership, exposure, copy, clear, and CT tests;
- same-length replacement and length-rejection tests;
- panic and fallible-generator preservation tests;
- bounded length and allocation-failure tests;
- serde unwind coverage proving owned input is guarded before generic error
  conversion;
- serde redaction and ingestion coverage;
- native storage-contract, zeroize, and subtle interop coverage;
- codegen checks that `SecretBoxBytes::clear_secret` dispatches once to the
  audited wipe path and that compiler/hardware fences remain outside the
  per-byte wipe loop;
- normal repository checks and the Rust 1.90.0 MSRV check.
