# Stable Secret Storage Contracts

`Secret<T>` can clear any `T: SecureSanitize`, but generic exposure is safe
only when `T` also attests that its secret-bearing storage remains under the
wrapper's control. Version 2.0 expresses that condition with two safe marker
traits:

- `StableSharedSecretStorage` permits scoped `&T` exposure;
- `StableMutableSecretStorage` permits scoped `&mut T` exposure and extends
  the shared contract.

These are conditional security contracts, not Rust memory-safety contracts.
An incorrect implementation does not by itself create undefined behavior, but
it can invalidate the crate's claim that released secret storage was cleared.

## Normative Contract

No safe operation reachable through `&self` or `&mut self` may release,
transfer, replace, or reallocate secret-bearing storage without clearing it
first. This includes:

- inherent and trait methods;
- mutation through `Cell`, `RefCell`, locks, atomics, or custom interior
  mutability;
- destructors and guard values returned by safe methods;
- callbacks initiated by those methods; and
- allocator operations or ownership transfers hidden behind safe APIs.

`StableSharedSecretStorage` requires this property for every safe operation
reachable through `&self`. `StableMutableSecretStorage` additionally requires
it for every safe operation reachable through `&mut self`.

The traits do not prevent an exposure closure from deliberately copying,
logging, exporting, or replacing secret data. They only establish what the
wrapped type itself promises while the closure has access.

## Built-In Implementations

The core crate implements the contracts for audited fixed-layout values and
secret containers whose safe operations preserve the contract. Dynamic
standard containers such as `Vec<T>` and `String` do not implement the marker
traits: safe growth can release an old allocation containing secret remnants.

Prefer purpose-built containers:

| Need | Type |
| --- | --- |
| Fixed bytes | `SecretBytes<N>` |
| Fixed heap allocation | `SecretBoxBytes` |
| Dynamic bytes with wipe-before-growth | `SecretVec` |
| Dynamic UTF-8 | `SecretString` |
| Bounded bytes or text | `BoundedSecretVec<MAX>`, `BoundedSecretString<MAX>` |
| Locked or guarded storage | mapped containers under the native features |
| Permanently bounded mapped storage | `BoundedLockedSecret*<MAX>`, `BoundedGuardedSecret*<MAX>` |

## Manual Implementation

Manual implementations should be rare and accompanied by a reviewable storage
argument:

```rust
use sanitization::{
    Secret, SecretBytes, SecureSanitize, StableMutableSecretStorage,
    StableSharedSecretStorage,
};

struct FixedCredentials {
    key: SecretBytes<32>,
    nonce: [u8; 12],
}

impl SecureSanitize for FixedCredentials {
    fn secure_sanitize(&mut self) {
        self.key.secure_sanitize();
        self.nonce.secure_sanitize();
    }
}

// STORAGE CONTRACT: all storage is inline and fixed-size. Shared methods do
// not mutate it, and mutable methods overwrite it in place.
impl StableSharedSecretStorage for FixedCredentials {}
impl StableMutableSecretStorage for FixedCredentials {}

let secret = Secret::new(FixedCredentials {
    key: SecretBytes::from_array([7; 32]),
    nonce: [9; 12],
});
assert_eq!(secret.with_secret(|value| value.nonce[0]), 9);
```

Before implementing either trait, review all safe methods, implemented traits,
interior-mutable fields, returned guards, callbacks, and destructor paths. In a
controlled high-assurance profile, allow-list reviewed implementations rather
than accepting arbitrary downstream attestations.

## Application Allow-Lists

`AllowlistedSecret<T, P>` adds a deployment-controlled gate on top of the
storage contracts. Define one private or crate-visible policy in a reviewed
module with `define_secret_storage_policy!`:

```rust
use sanitization::{
    define_secret_storage_policy, AllowlistedSecret, SecretBytes,
};

define_secret_storage_policy! {
    pub(crate) DeploymentStoragePolicy {
        SecretBytes<32> => "crate-audited fixed key storage",
        SecretBytes<16> => "crate-audited fixed nonce storage",
    }
}

let key = AllowlistedSecret::<SecretBytes<32>, DeploymentStoragePolicy>::new(
    SecretBytes::from_array([7; 32]),
);
assert_eq!(
    key.with_secret(|value| {
        value.export_byte("test observes reviewed key byte", 0)
    }),
    Some(7)
);
```

Every exact type requires a non-empty rationale that is not solely ASCII
whitespace. Those invalid literals are rejected at compile time. Construction
and exposure require `P: SecretStoragePolicy<T>`, and exposure independently
retains the shared or mutable stability bound. A newly introduced marker
implementation is therefore not accepted until the central policy adds that
exact type.

Keep the policy type private or `pub(crate)`. A public policy type can be named
by dependencies, and Rust's orphan rules may permit a dependency to implement
the policy for a storage type that dependency owns. A crate-private policy
keeps approval authority inside the application crate.

This mechanism centralizes review; it does not prove an attestation correct.
The application must still review each storage contract and each rationale.

### High-Assurance CI Enforcement

For closed production modules, make `AllowlistedSecret<T, P>` the only generic
secret owner and run the repository's dependency-free policy lint in
downstream CI:

```sh
python3 scripts/lint-storage-policies.py \
  --root crates/application/src/high_assurance \
  --root crates/application/src/approved_storage.rs \
  --policy-file crates/application/src/approved_storage.rs \
  --allow-marker-file crates/application/src/approved_storage_types.rs
```

The lint:

- rejects direct `Secret<T>`, `Secret::...`, and renamed `Secret` imports in
  scanned sensitive sources unless a file is explicitly exempted;
- rejects `StableSharedSecretStorage` and `StableMutableSecretStorage`
  implementations outside `--allow-marker-file` paths;
- rejects `mem::forget`, `Box::leak`, and `ManuallyDrop` in scanned sensitive
  roots because those primitives can bypass destructor-based cleanup;
- requires at least one `define_secret_storage_policy!` declaration in every
  `--policy-file`; and
- rejects policy visibility broader than private or `pub(crate)`.

The macro itself requires a written rationale that is neither empty nor
composed solely of ASCII whitespace for every exact approved type. Keep policy
and marker files small, require security
review for changes to either allow-list, and use code owners or equivalent
repository controls around them. `--allow-generic-secret-file` exists for a
reviewed migration boundary but should normally be absent in production.

The destructor-bypass rule is deliberately conservative and may reject a
non-secret use in the same sensitive root. Move that code outside the root or
review the root boundary; do not weaken the secret-owner rule with a broad
exemption.

This is a source-review gate, not a Rust parser or proof system. Macro indirection
or generated code can evade textual checks. Compile the policy, inspect the
expanded API when necessary, and retain human review of every marker contract.
The checked crate example is
`crates/sanitization/examples/high_assurance_policy.rs`; the lint's negative
fixtures are in `scripts/test-storage-policy-lint.py`.

## Why There Is No Storage Derive

A proc macro can inspect fields and add field bounds, but it cannot inspect
later inherent methods, implementations of foreign or local traits, interior
mutation hidden behind safe methods, returned guard destructors, callback
behavior, custom allocator activity, or deferred cleanup. A field-only derive
could therefore certify a struct whose `&self` method releases an uncleared
allocation.

For that reason, version 2 deliberately keeps storage attestations manual. Use
`SecureSanitize` derives for field-clearing coverage, write the storage-contract
argument explicitly, and use `AllowlistedSecret` to make deployment acceptance
central and compiler-enforced.

## Generic Bounds

Libraries that expose generic secret access should carry the appropriate bound
at their own API boundary:

```rust
use sanitization::{Secret, StableSharedSecretStorage};

fn inspect<T, R>(secret: &Secret<T>, f: impl FnOnce(&T) -> R) -> R
where
    T: StableSharedSecretStorage,
{
    secret.with_secret(f)
}
```

Do not add a marker implementation only to satisfy a compiler error. Choose a
container with controlled storage or document and review the actual invariant.

See `crates/sanitization/examples/storage_contracts.rs` and
`scripts/verify-secret-exposure-failures.sh` for positive and negative cases.
