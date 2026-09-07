# CP-07 Secret CT Ownership

Status: implementation review record

Base commit: `bf863ae`

Checkpoint: `CP-07`

CP-07 gives secret-derived CT values explicit ownership and cleanup semantics.

## Purpose-Specific Secret Owners

The generic copyable `ct::Secret<T>` marker is removed.

- `SecretIndex` owns a secret-controlled `usize`, is redacted and non-copying,
  clears on drop, and is consumed directly by full-scan lookup.
- `SecretScalar<T>` owns an `Option<T>`, is redacted and non-copying, clears on
  drop, exposes reviewed equality, ordering, and selection operations, and
  permits only consuming reason-bearing declassification.

Consuming declassification takes the value exactly once and leaves the wrapper
empty so its destructor cannot clean moved ownership a second time.

## Classified CT State

`PublicValue<T>` identifies public metadata. `SecretValue<T>` is a
clear-on-drop owner for secret backing data.

`SecretCtOption` and `SecretCtResult`:

- are redacted and non-copying;
- expose hidden state only as `Choice`;
- sanitize absent dummy and unselected secret values;
- keep selected secret values wrapped until unselected cleanup succeeds;
- transfer selected ownership only through reason-bearing declassification;
- map secret backing values by mutable borrow so panic unwind retains a
  clear-on-drop owner;
- create independently owned values during conditional selection.

Public success or error metadata does not require a synthetic
`SecureSanitize` implementation.

## Panic And Ownership Evidence

Native tests cover:

- scalar drop and consuming transfer;
- absent dummy cleanup;
- unselected result cleanup;
- selected values not cleaned by the consumed wrapper;
- option and result mapping panic unwind;
- sanitizer panic without a second sanitization attempt;
- selected secret cleanup when unselected cleanup panics;
- independent selected/source ownership;
- zero-sized secret backing values.

The CT compile-failure gate rejects copying `SecretIndex`, unrestricted scalar
borrowing, and cloning secret CT option state.
