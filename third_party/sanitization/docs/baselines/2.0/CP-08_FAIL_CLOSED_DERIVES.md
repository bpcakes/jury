# CP-08 Fail-Closed Derives

Status: implementation review record

Base commit: `6e7d496`

Checkpoint: `CP-08`

CP-08 makes aggregate sanitization derives reject ambiguous security behavior
by default.

## Enum Policy

`SecureSanitize` enum derives now require:

```rust
#[sanitization(enum_inactive_variant_bytes = "acknowledged")]
```

The diagnostic explains that only the active variant is safely reachable,
previously active larger variants may leave bytes behind, callers should use
`secure_replace` before transitions, and struct-based state machines are
preferred for high-assurance secret state.

The former `strict-enum-derive` feature is removed. There is no default mode
that silently accepts active-variant-only sanitization.

## Skip Policy

Every skipped field now requires a non-empty reason:

```rust
#[sanitization(skip, reason = "public algorithm identifier")]
```

The parser rejects:

- `skip` without `reason`;
- empty or whitespace-only reasons;
- `reason` without `skip`;
- duplicate `skip`, `reason`, `bound`, crate-path, or enum acknowledgement
  options;
- malformed and unsupported helper options;
- enum acknowledgements on structs.

`ConditionallySelectable` continues to reject skipped fields because every
output field must be constructed.

## Aggregate And Generic Coverage

The pass suite covers named, tuple, and unit structs, enum acknowledgement,
`PhantomData`, crate-path substitution, generic CT derives, and
`SecureSanitizeOnDrop` with struct-level `SecureSanitize + Unpin` generic
bounds. Generated drop code requires the complete struct to implement
`DropSafeSanitize + Unpin` and invokes its complete sanitizer. Generated
field-wise `SecureSanitize` implementations receive the marker automatically;
manual aggregate implementations require explicit review and opt-in.

The downstream compile-failure suite covers CT enum rejection, skipped CT
selection fields, unacknowledged enums, missing and malformed skip reasons,
duplicate options, invalid enum acknowledgement, unions, and missing generic
drop bounds. It also rejects `!Unpin` derive and `secure_drop_struct!` inputs.
Unapproved manual aggregate sanitizers are rejected as well.
