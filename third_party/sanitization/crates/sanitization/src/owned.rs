#[cfg(feature = "alloc")]
use alloc::{boxed::Box, string::String, vec::Vec};
use core::{
    fmt,
    hint::black_box,
    marker::PhantomData,
    sync::atomic::{compiler_fence, Ordering},
};

use crate::{ct, wipe, wipe_backend};

/// Error returned when a caller provides a buffer with the wrong length.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LengthError {
    /// Number of bytes required by the operation.
    pub expected: usize,
    /// Number of bytes provided by the caller.
    pub actual: usize,
}

impl fmt::Display for LengthError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "length mismatch: expected {} bytes, got {} bytes",
            self.expected, self.actual
        )
    }
}

#[cfg(feature = "std")]
impl std::error::Error for LengthError {}

/// Clear the currently reachable sensitive contents owned by a value.
///
/// The crate implements this trait for common scalar types, arrays, slices,
/// `Option<T>`, `Result<T, E>`, and, with `alloc`, `Box<T>`, `Vec<T>`, and
/// `String`. Opaque third-party types cannot be implemented here without
/// taking dependencies on them; wrap those values in a local newtype and
/// implement this trait there.
///
/// # Implementer contract
///
/// An implementation must:
///
/// - be idempotent;
/// - avoid panicking where reasonably possible;
/// - allocate no new storage while sanitizing;
/// - leave the value valid for later sanitization and drop;
/// - clear every currently owned secret element and all reachable
///   secret-bearing allocation capacity;
/// - clear secret-bearing storage before releasing, replacing, or transferring
///   that storage; and
/// - when called from a destructor path, never trigger destruction of that
///   same value while its sanitization call is still active;
/// - document external allocations, shared storage, historical copies,
///   representation padding, allocator metadata, platform copies, or other
///   secret-bearing state that it cannot reach.
///
/// This contract covers the value and storage reachable when
/// [`SecureSanitize::secure_sanitize`] is called. It does not imply that the
/// type's other safe operations preserve storage, and it cannot recover
/// allocations or copies that were already released.
///
/// References, shared owners such as `Rc` and `Arc`, `NonZero*`,
/// `MaybeUninit<T>`, unions, and types whose all-zero representation is invalid
/// need type-specific review. The crate intentionally provides no blanket
/// implementation for those categories.
///
/// Raw pointers and arbitrary user-defined `Copy` types are not accepted by
/// the built-in representation wipe:
///
/// ```compile_fail
/// use sanitization::SecureSanitize;
///
/// let byte = 7_u8;
/// let mut pointer = &byte as *const u8;
/// pointer.secure_sanitize();
/// ```
///
/// ```compile_fail
/// use sanitization::SecureSanitize;
///
/// #[derive(Clone, Copy)]
/// struct Unreviewed(u32);
///
/// let mut value = Unreviewed(7);
/// value.secure_sanitize();
/// ```
pub trait SecureSanitize {
    /// Clear the sensitive bytes owned by this value.
    fn secure_sanitize(&mut self);
}

/// Security contract for calling [`SecureSanitize`] from the value's destructor.
///
/// Implementing this marker asserts that `secure_sanitize` preserves all
/// aggregate cleanup behavior when called from `Drop` and cannot destroy,
/// replace, or otherwise recursively enter destruction of the same value while
/// that call remains active. The implementation must remain valid when the
/// value is logically pinned; generated drop code separately requires
/// [`Unpin`](core::marker::Unpin) before obtaining `&mut Self`.
///
/// This is a normal trait because an incorrect implementation violates a
/// security and availability contract, but must not be relied on for Rust
/// memory safety. Manual implementations are an explicit review point and
/// should include a `DROP SANITIZE CONTRACT` comment covering external
/// storage, ordering requirements, and why the sanitizer cannot recursively
/// destroy `Self`.
///
/// `#[derive(SecureSanitize)]` and [`crate::secure_sanitize_struct!`] implement this
/// marker automatically for their generated field-wise sanitizers. Types with
/// reviewed manual aggregate sanitizers must implement it explicitly before
/// deriving `SecureSanitizeOnDrop`.
#[diagnostic::on_unimplemented(
    message = "`{Self}` is not approved for destructor-path sanitization",
    label = "`SecureSanitizeOnDrop` requires `DropSafeSanitize`",
    note = "derive `SecureSanitize` for a generated field-wise sanitizer, or explicitly implement `DropSafeSanitize` after reviewing a manual aggregate sanitizer"
)]
pub trait DropSafeSanitize: SecureSanitize {}

/// Security contract for secret storage exposed through shared references.
///
/// Implementing this marker asserts:
///
/// > No safe operation provided by the type and reachable through `&self`
/// > releases, transfers, replaces, or schedules later release of
/// > secret-bearing storage without clearing it first.
///
/// The assertion covers inherent and trait methods, interior mutation,
/// returned guards and destructors, callbacks invoked by those methods, and
/// deferred cleanup they schedule. The type must retain a valid later
/// [`SecureSanitize`] and drop path and document external, shared, deferred, or
/// historical storage it cannot reach.
///
/// This is a normal trait rather than an `unsafe trait`: an incorrect
/// implementation violates a security promise but must never be relied on for
/// Rust memory safety. Generic guarantees are conditional on downstream
/// implementations satisfying this contract.
///
/// High-assurance applications should not accept arbitrary third-party
/// implementations merely because they satisfy this public marker. Maintain an
/// application-level allow-list of reviewed concrete types, or expose only
/// constructors and APIs whose generic bounds are closed over that reviewed
/// set. The crate keeps this trait public so downstream fixed-storage types can
/// opt in without making their implementations part of this crate.
///
/// Deliberate copying, logging, `mem::replace`, or calls to external code by an
/// exposure closure remain caller responsibility. This marker describes the
/// operations supplied by the marked type; it does not make hostile closure
/// code safe.
///
/// # Manual implementations
///
/// Manual implementations should include a `STORAGE CONTRACT` comment that
/// identifies every safe shared operation and explains why none can release
/// uncleared secret storage:
///
/// ```
/// use sanitization::{SecureSanitize, StableSharedSecretStorage};
///
/// struct FixedRecord {
///     key: [u8; 32],
/// }
///
/// impl SecureSanitize for FixedRecord {
///     fn secure_sanitize(&mut self) {
///         self.key.secure_sanitize();
///     }
/// }
///
/// // STORAGE CONTRACT: shared methods only inspect the inline byte array.
/// impl StableSharedSecretStorage for FixedRecord {}
/// ```
///
/// Types with interior mutation are not stable merely because their
/// `SecureSanitize` implementation clears the current value:
///
/// ```compile_fail
/// use std::cell::RefCell;
/// use sanitization::{wipe, SecureSanitize, StableSharedSecretStorage};
///
/// struct Rotating {
///     bytes: RefCell<Vec<u8>>,
/// }
///
/// impl SecureSanitize for Rotating {
///     fn secure_sanitize(&mut self) {
///         let bytes = self.bytes.get_mut();
///         wipe::bytes(bytes.as_mut_slice());
///         bytes.clear();
///     }
/// }
///
/// fn require_shared_stability<T: StableSharedSecretStorage>() {}
///
/// // Rejected: `Rotating` can replace its allocation through `&self`.
/// require_shared_stability::<Rotating>();
/// ```
#[diagnostic::on_unimplemented(
    message = "`{Self}` does not guarantee stable shared secret storage",
    label = "generic shared secret exposure requires `StableSharedSecretStorage`",
    note = "use a dedicated secret container or implement and document the storage contract for a reviewed fixed-storage type"
)]
pub trait StableSharedSecretStorage: SecureSanitize {}

/// Security contract for secret storage exposed through mutable references.
///
/// This extends [`StableSharedSecretStorage`] and asserts that no safe operation
/// provided by the type and reachable through `&mut self` releases, transfers,
/// replaces, or schedules later release of secret-bearing storage without
/// clearing it first.
///
/// The same interior-mutation, guard, callback, destructor, deferred-cleanup,
/// documentation, and caller-responsibility rules described by
/// [`StableSharedSecretStorage`] apply. Manual implementations should include a
/// `STORAGE CONTRACT` comment covering both shared and mutable operations.
///
/// The crate intentionally does not implement this trait for `Vec<T>`,
/// `String`, `Box<T>`, references, shared owners, or arbitrary third-party
/// containers.
///
/// ```compile_fail
/// use sanitization::{wipe, SecureSanitize, StableMutableSecretStorage};
///
/// struct Reallocating(Vec<u8>);
///
/// impl Reallocating {
///     fn replace_without_clearing(&mut self, replacement: Vec<u8>) {
///         self.0 = replacement;
///     }
/// }
///
/// impl SecureSanitize for Reallocating {
///     fn secure_sanitize(&mut self) {
///         wipe::bytes(self.0.as_mut_slice());
///         self.0.clear();
///     }
/// }
///
/// fn require_mutable_stability<T: StableMutableSecretStorage>() {}
///
/// // Rejected: the old allocation can be released by a safe mutable method.
/// require_mutable_stability::<Reallocating>();
/// ```
#[diagnostic::on_unimplemented(
    message = "`{Self}` does not guarantee stable mutable secret storage",
    label = "generic mutable secret exposure requires `StableMutableSecretStorage`",
    note = "use a dedicated secret container or implement and document the storage contract for a reviewed fixed-storage type"
)]
pub trait StableMutableSecretStorage: StableSharedSecretStorage {}

/// Application-controlled allow-list for concrete secret storage types.
///
/// This policy is an additional gate, not a replacement for
/// [`StableSharedSecretStorage`] or [`StableMutableSecretStorage`]. A policy
/// implementation approves one exact `T` for one application-owned policy
/// type. [`AllowlistedSecret`] still requires the relevant storage-stability
/// contract before exposing `T`.
///
/// High-assurance applications should define one private or crate-visible
/// policy type in a reviewed module and implement this trait only for accepted
/// concrete storage types. Dependencies cannot name a non-public policy. A
/// public policy may be implementable by a dependency for a storage type that
/// dependency owns under Rust's orphan rules. Prefer
/// [`crate::define_secret_storage_policy!`] with no visibility or `pub(crate)` so
/// every approval stays local and carries a review rationale in one searchable
/// declaration.
///
/// This trait does not prove that `T` satisfies its storage contract. It makes
/// the deployment's concrete-type decision explicit and centrally auditable.
#[diagnostic::on_unimplemented(
    message = "`{Self}` does not allow-list `{T}` as secret storage",
    label = "this exact storage type is absent from the selected policy",
    note = "review the type and add it with `define_secret_storage_policy!`, or select an already approved type"
)]
pub trait SecretStoragePolicy<T: SecureSanitize> {
    /// Human-readable reason this exact type is accepted by the policy.
    const RATIONALE: &'static str;
}

/// Define an application-owned concrete-type allow-list for
/// [`AllowlistedSecret`].
///
/// Each entry requires a non-empty literal rationale that is not solely ASCII
/// whitespace. The generated policy is an uninhabited marker type and
/// implements [`SecretStoragePolicy<T>`] only for the listed exact types.
///
/// ```
/// use sanitization::{
///     define_secret_storage_policy, AllowlistedSecret, SecureSanitize,
///     StableMutableSecretStorage, StableSharedSecretStorage,
/// };
///
/// struct Credentials([u8; 32]);
///
/// impl SecureSanitize for Credentials {
///     fn secure_sanitize(&mut self) {
///         self.0.secure_sanitize();
///     }
/// }
///
/// // STORAGE CONTRACT: all safe operations retain the inline byte array.
/// impl StableSharedSecretStorage for Credentials {}
/// impl StableMutableSecretStorage for Credentials {}
///
/// define_secret_storage_policy! {
///     pub(crate) DeploymentStoragePolicy {
///         Credentials => "reviewed fixed inline storage with no interior mutation",
///     }
/// }
///
/// let mut secret =
///     AllowlistedSecret::<Credentials, DeploymentStoragePolicy>::new(
///         Credentials([7; 32]),
///     );
/// assert_eq!(secret.with_secret(|value| value.0[0]), 7);
/// secret.with_secret_mut(|value| value.0[0] = 9);
/// ```
#[macro_export]
macro_rules! define_secret_storage_policy {
    (
        $(#[$metadata:meta])*
        $visibility:vis $policy:ident {
            $($storage:ty => $reason:literal),+ $(,)?
        }
    ) => {
        $(#[$metadata])*
        $visibility enum $policy {}

        $(
            const _: () = {
                let reason: &str = $reason;
                let bytes = reason.as_bytes();
                let mut index = 0;
                let mut has_content = false;
                while index < bytes.len() {
                    let byte = bytes[index];
                    if byte != b' '
                        && byte != b'\t'
                        && byte != b'\n'
                        && byte != b'\r'
                        && byte != 0x0b
                        && byte != 0x0c
                    {
                        has_content = true;
                    }
                    index += 1;
                }
                assert!(
                    has_content,
                    "secret storage policy rationale must not be empty or ASCII-whitespace-only",
                );
            };

            impl $crate::SecretStoragePolicy<$storage> for $policy {
                const RATIONALE: &'static str = $reason;
            }
        )+
    };
}

/// Sanitize a value before replacing it.
///
/// This is the safe replacement pattern for values whose previous contents may
/// hold secrets, especially manually implemented enums that move from a
/// secret-bearing variant to a non-secret variant. Calling `secure_sanitize`
/// after assigning a unit or empty variant is too late; use `secure_replace` to
/// clear first. Derive macros reject enums because they cannot enforce this
/// transition discipline.
#[inline]
pub fn secure_replace<T: SecureSanitize>(slot: &mut T, replacement: T) {
    slot.secure_sanitize();
    *slot = replacement;
}

/// Sanitize one application-owned root value and then deliberately abort.
///
/// This helper is only for fatal paths that explicitly choose to abort. It
/// sanitizes `root` before invoking [`std::process::abort`]. Aggregate all
/// reachable secret owners into a struct or tuple when more than one value must
/// be cleared.
///
/// This does **not** install a panic, signal, or process-wide abort hook. It
/// cannot clear compiler temporaries, external copies, unrelated owners, or
/// secrets when another component aborts directly. Ordinary destructors still
/// do not run after process abort.
#[cfg(feature = "std")]
#[inline(never)]
pub fn sanitize_then_abort<T: SecureSanitize + ?Sized>(root: &mut T) -> ! {
    root.secure_sanitize();
    compiler_fence(Ordering::SeqCst);
    black_box(&mut *root);
    std::process::abort()
}

macro_rules! impl_secure_sanitize_scalar {
    ($($ty:ty),+ $(,)?) => {
        $(
            impl SecureSanitize for $ty {
                #[inline(never)]
                fn secure_sanitize(&mut self) {
                    wipe_backend::erase_plain_data(self);
                }
            }

            impl StableSharedSecretStorage for $ty {}
            impl StableMutableSecretStorage for $ty {}
        )+
    };
}

impl_secure_sanitize_scalar!(
    u8, u16, u32, u64, u128, usize, i8, i16, i32, i64, i128, isize, bool, char, f32, f64,
);

/// Declare a struct and generate [`SecureSanitize`] for all fields.
///
/// This is a dependency-free alternative to a derive macro. Each field type
/// must implement [`SecureSanitize`]. The macro does not implement [`Drop`], so
/// use this form when the type needs custom drop behavior or is wrapped in
/// [`Secret`].
///
/// This macro intentionally supports named-field structs without generics or
/// `where` clauses. For generic structs, implement [`SecureSanitize`] manually
/// so the impl generics and bounds stay explicit.
///
/// ```
/// use sanitization::{secure_sanitize_struct, SecretBytes, SecureSanitize};
///
/// secure_sanitize_struct! {
///     struct Credentials {
///         key: SecretBytes<32>,
///         nonce: SecretBytes<12>,
///     }
/// }
///
/// let mut credentials = Credentials {
///     key: SecretBytes::from_array([1; 32]),
///     nonce: SecretBytes::from_array([2; 12]),
/// };
///
/// credentials.secure_sanitize();
/// ```
#[macro_export]
macro_rules! secure_sanitize_struct {
    (
        $(#[$attr:meta])*
        $vis:vis struct $name:ident {
            $(
                $(#[$field_attr:meta])*
                $field_vis:vis $field:ident: $field_ty:ty
            ),* $(,)?
        }
    ) => {
        $(#[$attr])*
        $vis struct $name {
            $(
                $(#[$field_attr])*
                $field_vis $field: $field_ty,
            )*
        }

        impl $crate::SecureSanitize for $name {
            #[inline]
            fn secure_sanitize(&mut self) {
                $(
                    $crate::SecureSanitize::secure_sanitize(&mut self.$field);
                )*
            }
        }

        impl $crate::DropSafeSanitize for $name {}
    };
}

/// Declare a struct and generate [`SecureSanitize`] plus [`Drop`].
///
/// This macro owns the type's [`Drop`] implementation. Use
/// [`crate::secure_sanitize_struct!`] instead when custom drop behavior is required.
/// The generated destructor requires the declared struct to implement
/// [`DropSafeSanitize`] and [`Unpin`](core::marker::Unpin), then calls its
/// complete [`SecureSanitize`] implementation. The generated sanitizer is
/// field-wise, so the marker is provided automatically.
///
/// This macro intentionally supports named-field structs without generics or
/// `where` clauses. For generic structs, implement [`SecureSanitize`] and
/// [`Drop`] manually so the impl generics and bounds stay explicit.
///
/// ```
/// use sanitization::{secure_drop_struct, SecretBytes};
///
/// secure_drop_struct! {
///     struct Credentials {
///         key: SecretBytes<32>,
///         nonce: SecretBytes<12>,
///     }
/// }
/// ```
#[macro_export]
macro_rules! secure_drop_struct {
    (
        $(#[$attr:meta])*
        $vis:vis struct $name:ident {
            $(
                $(#[$field_attr:meta])*
                $field_vis:vis $field:ident: $field_ty:ty
            ),* $(,)?
        }
    ) => {
        $crate::secure_sanitize_struct! {
            $(#[$attr])*
            $vis struct $name {
                $(
                    $(#[$field_attr])*
                    $field_vis $field: $field_ty,
                )*
            }
        }

        impl Drop for $name {
            #[inline]
            fn drop(&mut self) {
                fn require_drop_contract<T: ?Sized + $crate::DropSafeSanitize + ::core::marker::Unpin>() {}
                require_drop_contract::<Self>();
                $crate::SecureSanitize::secure_sanitize(self);
            }
        }
    };
}

#[cfg(feature = "alloc")]
#[inline(never)]
pub(crate) fn sanitize_vec_capacity(bytes: &mut Vec<u8>) {
    wipe::vec(bytes);
}

#[cfg(all(feature = "alloc", feature = "multi-pass-clear"))]
#[inline(never)]
fn sanitize_vec_capacity_multi_pass(bytes: &mut Vec<u8>) {
    wipe::vec_multi_pass(bytes);
}

#[cfg(feature = "alloc")]
#[inline]
fn next_secret_capacity(current: usize, required: usize) -> usize {
    current.saturating_mul(2).max(required).max(8)
}

#[cfg(feature = "alloc")]
const MAX_UTF8_CHAR_BYTES: usize = 4;

impl<T: SecureSanitize> SecureSanitize for [T] {
    #[inline(never)]
    fn secure_sanitize(&mut self) {
        for item in self.iter_mut() {
            item.secure_sanitize();
        }
        compiler_fence(Ordering::SeqCst);
    }
}

impl<T: SecureSanitize, const N: usize> SecureSanitize for [T; N] {
    #[inline(never)]
    fn secure_sanitize(&mut self) {
        self.as_mut_slice().secure_sanitize();
    }
}

impl<T: StableSharedSecretStorage> StableSharedSecretStorage for [T] {}
impl<T: StableMutableSecretStorage> StableMutableSecretStorage for [T] {}

impl<T: StableSharedSecretStorage, const N: usize> StableSharedSecretStorage for [T; N] {}
impl<T: StableMutableSecretStorage, const N: usize> StableMutableSecretStorage for [T; N] {}

impl SecureSanitize for () {
    #[inline]
    fn secure_sanitize(&mut self) {}
}

impl StableSharedSecretStorage for () {}
impl StableMutableSecretStorage for () {}

macro_rules! impl_tuple_storage_contracts {
    ($(($($type:ident:$index:tt),+)),+ $(,)?) => {
        $(
            impl<$($type: SecureSanitize),+> SecureSanitize for ($($type,)+) {
                #[inline]
                fn secure_sanitize(&mut self) {
                    $(
                        self.$index.secure_sanitize();
                    )+
                    compiler_fence(Ordering::SeqCst);
                }
            }

            impl<$($type: StableSharedSecretStorage),+> StableSharedSecretStorage
                for ($($type,)+)
            {}

            impl<$($type: StableMutableSecretStorage),+> StableMutableSecretStorage
                for ($($type,)+)
            {}
        )+
    };
}

impl_tuple_storage_contracts!(
    (A:0),
    (A:0, B:1),
    (A:0, B:1, C:2),
    (A:0, B:1, C:2, D:3),
    (A:0, B:1, C:2, D:3, E:4),
    (A:0, B:1, C:2, D:3, E:4, F:5),
    (A:0, B:1, C:2, D:3, E:4, F:5, G:6),
    (A:0, B:1, C:2, D:3, E:4, F:5, G:6, H:7),
    (A:0, B:1, C:2, D:3, E:4, F:5, G:6, H:7, I:8),
    (A:0, B:1, C:2, D:3, E:4, F:5, G:6, H:7, I:8, J:9),
    (A:0, B:1, C:2, D:3, E:4, F:5, G:6, H:7, I:8, J:9, K:10),
    (A:0, B:1, C:2, D:3, E:4, F:5, G:6, H:7, I:8, J:9, K:10, L:11),
);

impl<T: SecureSanitize> SecureSanitize for Option<T> {
    #[inline]
    fn secure_sanitize(&mut self) {
        if let Some(value) = self.as_mut() {
            value.secure_sanitize();
        }
        *self = None;
        compiler_fence(Ordering::SeqCst);
    }
}

impl<T: SecureSanitize, E: SecureSanitize> SecureSanitize for Result<T, E> {
    #[inline]
    fn secure_sanitize(&mut self) {
        match self {
            Ok(value) => value.secure_sanitize(),
            Err(error) => error.secure_sanitize(),
        }
        compiler_fence(Ordering::SeqCst);
    }
}

impl<T> SecureSanitize for PhantomData<T> {
    #[inline]
    fn secure_sanitize(&mut self) {}
}

impl<T> StableSharedSecretStorage for PhantomData<T> {}
impl<T> StableMutableSecretStorage for PhantomData<T> {}

#[cfg(feature = "alloc")]
/// Field-wise sanitization for the currently boxed value.
///
/// This does not clear unknown representation padding and cannot recover a
/// different allocation previously released by caller-controlled replacement.
/// Byte workloads needing complete fixed-allocation wiping should use
/// [`SecretBoxBytes`].
impl<T: SecureSanitize + ?Sized> SecureSanitize for Box<T> {
    #[inline]
    fn secure_sanitize(&mut self) {
        self.as_mut().secure_sanitize();
    }
}

#[cfg(feature = "alloc")]
/// Sanitization for the vector's currently reachable allocation.
///
/// This sanitizes every live element, drops those elements, and then wipes the
/// current allocation capacity as bytes. It cannot recover allocations already
/// released by prior caller-controlled growth or replacement. Byte workloads
/// should prefer [`SecretVec`] for managed wipe-before-grow behavior or
/// [`SecretBoxBytes`] when the runtime length is fixed.
impl<T: SecureSanitize> SecureSanitize for Vec<T> {
    #[inline]
    fn secure_sanitize(&mut self) {
        for item in self.iter_mut() {
            item.secure_sanitize();
        }
        self.clear();
        wipe_backend::erase(
            self.as_mut_ptr().cast::<u8>(),
            self.capacity().saturating_mul(core::mem::size_of::<T>()),
        );
        compiler_fence(Ordering::SeqCst);
    }
}

#[cfg(feature = "alloc")]
impl SecureSanitize for String {
    #[inline(never)]
    fn secure_sanitize(&mut self) {
        wipe_backend::erase(self.as_mut_ptr(), self.capacity());
        self.clear();
    }
}

#[inline]
pub(crate) fn constant_time_eq_slices(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }

    constant_time_eq_equal_len(left, right)
}

#[inline]
pub(crate) fn constant_time_eq_equal_len(left: &[u8], right: &[u8]) -> bool {
    debug_assert_eq!(left.len(), right.len());

    #[cfg(all(
        feature = "asm-compare",
        any(target_arch = "x86_64", target_arch = "aarch64"),
        not(miri)
    ))]
    {
        crate::compare_asm::constant_time_eq_equal_len(left, right)
    }

    #[cfg(not(all(
        feature = "asm-compare",
        any(target_arch = "x86_64", target_arch = "aarch64"),
        not(miri)
    )))]
    {
        portable_constant_time_eq_equal_len(left, right)
    }
}

#[inline]
#[cfg_attr(
    all(
        feature = "asm-compare",
        any(target_arch = "x86_64", target_arch = "aarch64"),
        not(miri)
    ),
    allow(dead_code)
)]
pub(crate) fn portable_constant_time_eq_equal_len(left: &[u8], right: &[u8]) -> bool {
    debug_assert_eq!(left.len(), right.len());

    let mut diff = 0usize;
    let mut index = 0;
    while index < left.len() {
        diff = black_box(diff | usize::from(left[index] ^ right[index]));
        index += 1;
    }
    black_box(diff) == 0
}

#[cfg(kani)]
mod kani_verification {
    use super::*;
    use core::cmp::Ordering;

    fn assert_ct_ordering_matches(ordering: ct::CtOrdering, expected: Ordering) {
        match expected {
            Ordering::Less => {
                assert_eq!(
                    ordering
                        .is_less()
                        .declassify_u8("test or verification observes normalized choice"),
                    1
                );
                assert_eq!(
                    ordering
                        .is_equal()
                        .declassify_u8("test or verification observes normalized choice"),
                    0
                );
                assert_eq!(
                    ordering
                        .is_greater()
                        .declassify_u8("test or verification observes normalized choice"),
                    0
                );
            }
            Ordering::Equal => {
                assert_eq!(
                    ordering
                        .is_less()
                        .declassify_u8("test or verification observes normalized choice"),
                    0
                );
                assert_eq!(
                    ordering
                        .is_equal()
                        .declassify_u8("test or verification observes normalized choice"),
                    1
                );
                assert_eq!(
                    ordering
                        .is_greater()
                        .declassify_u8("test or verification observes normalized choice"),
                    0
                );
            }
            Ordering::Greater => {
                assert_eq!(
                    ordering
                        .is_less()
                        .declassify_u8("test or verification observes normalized choice"),
                    0
                );
                assert_eq!(
                    ordering
                        .is_equal()
                        .declassify_u8("test or verification observes normalized choice"),
                    0
                );
                assert_eq!(
                    ordering
                        .is_greater()
                        .declassify_u8("test or verification observes normalized choice"),
                    1
                );
            }
        }
    }

    fn lexicographic_cmp_4(left: &[u8; 4], right: &[u8; 4]) -> Ordering {
        let mut index = 0;
        while index < 4 {
            if left[index] < right[index] {
                return Ordering::Less;
            }
            if left[index] > right[index] {
                return Ordering::Greater;
            }
            index += 1;
        }
        Ordering::Equal
    }

    #[kani::proof]
    fn prove_wipe_bytes_clears_fixed_buffer() {
        let mut bytes: [u8; 4] = kani::any();

        wipe::bytes(&mut bytes);

        assert_eq!(bytes, [0; 4]);
    }

    #[kani::proof]
    fn prove_secret_bytes_clear_erases_visible_contents() {
        let source: [u8; 4] = kani::any();
        let mut secret = SecretBytes::<4>::from_array(source);
        let mut output = [0xA5; 4];

        secret.secure_clear();
        assert!(secret
            .export_to_slice("test exports bytes for verification output", &mut output)
            .is_ok());

        assert_eq!(output, [0; 4]);
    }

    #[kani::proof]
    fn prove_secret_bytes_constant_time_eq_matches_byte_equality() {
        let left: [u8; 4] = kani::any();
        let right: [u8; 4] = kani::any();
        let secret = SecretBytes::<4>::from_array(left);

        let mut expected = true;
        let mut index = 0;
        while index < 4 {
            expected &= left[index] == right[index];
            index += 1;
        }

        assert_eq!(secret.constant_time_eq(&right), expected);
    }

    #[kani::proof]
    fn prove_ct_choice_is_normalized() {
        let value: u8 = kani::any();
        let choice = ct::Choice::from_u8(value);
        let unwrapped = choice.declassify_u8("test or verification observes normalized choice");

        assert!(unwrapped == 0 || unwrapped == 1);
    }

    #[kani::proof]
    fn prove_ct_choice_boolean_algebra_matches_public_bits() {
        let left_byte: u8 = kani::any();
        let right_byte: u8 = kani::any();
        let left = ct::Choice::from_u8(left_byte);
        let right = ct::Choice::from_u8(right_byte);
        let left_bit = left.declassify_u8("test or verification observes normalized choice");
        let right_bit = right.declassify_u8("test or verification observes normalized choice");

        assert_eq!(
            (left & right).declassify_u8("test or verification observes normalized choice"),
            left_bit & right_bit
        );
        assert_eq!(
            (left | right).declassify_u8("test or verification observes normalized choice"),
            left_bit | right_bit
        );
        assert_eq!(
            (left ^ right).declassify_u8("test or verification observes normalized choice"),
            left_bit ^ right_bit
        );
        assert_eq!(
            (!left).declassify_u8("test or verification observes normalized choice"),
            left_bit ^ 1
        );
    }

    #[kani::proof]
    fn prove_ct_fixed_equality_matches_byte_equality() {
        let left: [u8; 4] = kani::any();
        let right: [u8; 4] = kani::any();

        let mut expected = true;
        let mut index = 0;
        while index < 4 {
            expected &= left[index] == right[index];
            index += 1;
        }

        assert_eq!(
            ct::eq_fixed(&left, &right)
                .declassify_u8("test or verification observes normalized choice")
                == 1,
            expected
        );
    }

    #[kani::proof]
    fn prove_ct_public_length_equality_rejects_mismatch() {
        let left: [u8; 4] = kani::any();
        let right: [u8; 3] = kani::any();

        assert_eq!(
            ct::eq_public_len(&left, &right)
                .declassify_u8("test or verification observes normalized choice"),
            0
        );
    }

    #[kani::proof]
    fn prove_ct_fixed_ordering_matches_lexicographic_ordering() {
        let left: [u8; 4] = kani::any();
        let right: [u8; 4] = kani::any();

        assert_ct_ordering_matches(
            ct::cmp_fixed(&left, &right),
            lexicographic_cmp_4(&left, &right),
        );
    }

    #[kani::proof]
    fn prove_ct_unsigned_ordering_matches_rust_ordering() {
        let left: u16 = kani::any();
        let right: u16 = kani::any();

        assert_ct_ordering_matches(
            <u16 as ct::ConstantTimeOrd>::ct_cmp(&left, &right),
            left.cmp(&right),
        );
    }

    #[kani::proof]
    fn prove_ct_signed_ordering_matches_rust_ordering() {
        let left: i16 = kani::any();
        let right: i16 = kani::any();

        assert_ct_ordering_matches(
            <i16 as ct::ConstantTimeOrd>::ct_cmp(&left, &right),
            left.cmp(&right),
        );
    }

    #[kani::proof]
    fn prove_ct_conditional_copy_matches_choice() {
        let initial: [u8; 4] = kani::any();
        let source: [u8; 4] = kani::any();
        let choice_byte: u8 = kani::any();
        let choice = ct::Choice::from_u8(choice_byte);
        let mut destination = initial;

        assert!(ct::conditional_copy(&mut destination, &source, choice).is_ok());

        if choice.declassify_u8("test or verification observes normalized choice") == 1 {
            assert_eq!(destination, source);
        } else {
            assert_eq!(destination, initial);
        }
    }

    #[kani::proof]
    fn prove_ct_conditional_swap_matches_choice() {
        let initial_left: [u8; 4] = kani::any();
        let initial_right: [u8; 4] = kani::any();
        let choice_byte: u8 = kani::any();
        let choice = ct::Choice::from_u8(choice_byte);
        let mut left = initial_left;
        let mut right = initial_right;

        assert!(ct::conditional_swap(&mut left, &mut right, choice).is_ok());

        if choice.declassify_u8("test or verification observes normalized choice") == 1 {
            assert_eq!(left, initial_right);
            assert_eq!(right, initial_left);
        } else {
            assert_eq!(left, initial_left);
            assert_eq!(right, initial_right);
        }
    }

    #[kani::proof]
    fn prove_ct_oblivious_lookup_matches_public_index() {
        let table: [u8; 4] = kani::any();
        let fallback: u8 = kani::any();
        let index: usize = kani::any();

        let selected = ct::oblivious_lookup(&table, ct::SecretIndex::new(index), &fallback);

        if index < 4 {
            assert_eq!(selected, table[index]);
        } else {
            assert_eq!(selected, fallback);
        }
    }

    #[kani::proof]
    fn prove_ct_select_slice_matches_choice() {
        let left: [u8; 4] = kani::any();
        let right: [u8; 4] = kani::any();
        let choice_byte: u8 = kani::any();
        let choice = ct::Choice::from_u8(choice_byte);
        let mut destination = [0u8; 4];

        assert!(ct::select_slice(&mut destination, &left, &right, choice).is_ok());

        if choice.declassify_u8("test or verification observes normalized choice") == 1 {
            assert_eq!(destination, right);
        } else {
            assert_eq!(destination, left);
        }
    }

    #[kani::proof]
    fn prove_ct_option_unwrap_or_matches_presence() {
        let value: u8 = kani::any();
        let fallback: u8 = kani::any();
        let presence_byte: u8 = kani::any();
        let presence = ct::Choice::from_u8(presence_byte);
        let option = ct::PublicCtOption::new(value, presence);

        let selected = option.unwrap_or(&fallback);

        if presence.declassify_u8("test or verification observes normalized choice") == 1 {
            assert_eq!(selected, value);
        } else {
            assert_eq!(selected, fallback);
        }
    }

    #[kani::proof]
    fn prove_ct_option_and_or_match_presence_bits() {
        let left_value: u8 = kani::any();
        let right_value: u8 = kani::any();
        let fallback: u8 = kani::any();
        let left_presence_byte: u8 = kani::any();
        let right_presence_byte: u8 = kani::any();
        let left_presence = ct::Choice::from_u8(left_presence_byte);
        let right_presence = ct::Choice::from_u8(right_presence_byte);
        let left = ct::PublicCtOption::new(left_value, left_presence);
        let right = ct::PublicCtOption::new(right_value, right_presence);

        let and_selected = left.and(right).unwrap_or(&fallback);
        let or_selected = left.or(right).unwrap_or(&fallback);

        if left_presence.declassify_u8("test or verification observes normalized choice") == 1
            && right_presence.declassify_u8("test or verification observes normalized choice") == 1
        {
            assert_eq!(and_selected, right_value);
        } else {
            assert_eq!(and_selected, fallback);
        }

        if left_presence.declassify_u8("test or verification observes normalized choice") == 1 {
            assert_eq!(or_selected, left_value);
        } else if right_presence.declassify_u8("test or verification observes normalized choice")
            == 1
        {
            assert_eq!(or_selected, right_value);
        } else {
            assert_eq!(or_selected, fallback);
        }
    }

    #[kani::proof]
    fn prove_ct_result_unwrap_or_and_maps_match_success_bit() {
        let value: u8 = kani::any();
        let error: u8 = kani::any();
        let fallback: u8 = kani::any();
        let success_byte: u8 = kani::any();
        let success = ct::Choice::from_u8(success_byte);
        let result = ct::PublicCtResult::new(value, error, success);

        let selected = result.unwrap_or(&fallback);
        let mapped = result.map(|inner| inner.wrapping_add(1));
        let mapped_error = result.map_err(|inner| inner.wrapping_add(1));

        if success.declassify_u8("test or verification observes normalized choice") == 1 {
            assert_eq!(selected, value);
            assert_eq!(
                mapped.declassify("Kani exposes mapped success bit"),
                Ok(value.wrapping_add(1))
            );
            assert_eq!(
                mapped_error.declassify("Kani exposes mapped success bit"),
                Ok(value)
            );
        } else {
            assert_eq!(selected, fallback);
            assert_eq!(
                mapped.declassify("Kani exposes mapped error bit"),
                Err(error)
            );
            assert_eq!(
                mapped_error.declassify("Kani exposes mapped error bit"),
                Err(error.wrapping_add(1))
            );
        }
    }

    #[kani::proof]
    fn prove_ct_option_and_result_conditional_select_match_choice() {
        let left_value: u8 = kani::any();
        let right_value: u8 = kani::any();
        let choice_byte: u8 = kani::any();
        let choice = ct::Choice::from_u8(choice_byte);
        let left_option = ct::PublicCtOption::some(left_value);
        let right_option = ct::PublicCtOption::some(right_value);
        let left_result = ct::PublicCtResult::new(left_value, 11u8, ct::Choice::TRUE);
        let right_result = ct::PublicCtResult::new(right_value, 22u8, ct::Choice::TRUE);

        let selected_option =
            <ct::PublicCtOption<u8> as ct::ConditionallySelectable>::conditional_select(
                &left_option,
                &right_option,
                choice,
            );
        let selected_result =
            <ct::PublicCtResult<u8, u8> as ct::ConditionallySelectable>::conditional_select(
                &left_result,
                &right_result,
                choice,
            );

        if choice.declassify_u8("test or verification observes normalized choice") == 1 {
            assert_eq!(selected_option.unwrap_or(&0), right_value);
            assert_eq!(selected_result.unwrap_or(&0), right_value);
        } else {
            assert_eq!(selected_option.unwrap_or(&0), left_value);
            assert_eq!(selected_result.unwrap_or(&0), left_value);
        }
    }

    #[kani::proof]
    fn prove_constant_time_eq_rejects_length_mismatch() {
        let left: [u8; 4] = kani::any();
        let right: [u8; 3] = kani::any();

        assert!(!constant_time_eq_slices(&left, &right));
    }

    #[kani::proof]
    fn prove_secret_bytes_replacement_commits_complete_new_value() {
        let initial: [u8; 4] = kani::any();
        let replacement: [u8; 4] = kani::any();
        let mut secret = SecretBytes::<4>::from_array(initial);
        let mut observed = [0_u8; 4];

        secret.copy_from_slice(&replacement).unwrap();
        secret
            .export_to_slice("test exports bytes for verification output", &mut observed)
            .unwrap();

        assert_eq!(observed, replacement);
    }

    #[kani::proof]
    #[cfg(feature = "alloc")]
    fn prove_next_secret_capacity_never_under_allocates() {
        let current: usize = kani::any();
        let required: usize = kani::any();

        let capacity = next_secret_capacity(current, required);

        assert!(capacity >= required);
        assert!(capacity >= 8);
    }
}

struct TemporaryBytes<'a, const N: usize> {
    bytes: &'a mut [u8; N],
}

impl<const N: usize> Drop for TemporaryBytes<'_, N> {
    #[inline]
    fn drop(&mut self) {
        wipe::bytes(self.bytes);
    }
}

pub(crate) fn expose_array_copy<const N: usize, R>(
    source: &[u8; N],
    inspect: impl FnOnce(&[u8; N]) -> R,
) -> R {
    let mut temporary = [0; N];
    temporary.copy_from_slice(source);
    compiler_fence(Ordering::SeqCst);
    let guard = TemporaryBytes {
        bytes: &mut temporary,
    };
    let result = inspect(guard.bytes);
    // Clear eagerly before returning. The guard repeats the clear on normal
    // return and clears during unwinding as defense in depth.
    wipe::bytes(guard.bytes);
    result
}

#[cfg(all(test, feature = "std"))]
mod temporary_bytes_tests {
    use super::TemporaryBytes;
    use std::panic::{catch_unwind, AssertUnwindSafe};

    #[test]
    fn temporary_bytes_clear_during_unwind() {
        let mut bytes = [7_u8; 32];

        let result = catch_unwind(AssertUnwindSafe(|| {
            let _guard = TemporaryBytes { bytes: &mut bytes };
            panic!("exercise temporary cleanup");
        }));

        assert!(result.is_err());
        assert_eq!(bytes, [0; 32]);
    }
}

/// Fixed-size secret byte storage with automatic sanitization on drop.
///
/// Bytes are stored in a plain `[u8; N]` and all clearing routes through the
/// crate's internal volatile wipe backend. This gives the same clearing behavior
/// on targets with and without native byte atomics.
///
/// # Platform Notes
///
/// This type is `Sync` because it contains only plain bytes. Mutating and
/// clearing operations require `&mut self` to prevent partially-cleared
/// multi-byte observations through shared references.
///
/// `SecretBytes<N>` stores `N` bytes inline. [`SecretBytes::expose_secret`]
/// borrows that storage directly and does not intentionally construct a
/// full-size temporary array. [`SecretBytes::export_secret_copy`] is the
/// explicit copy-based alternative.
///
/// The type deliberately does not implement `Clone`, `Copy`, `Deref`,
/// `AsRef<[u8]>`, `PartialEq`, or secret-printing `Debug`.
pub struct SecretBytes<const N: usize> {
    bytes: [u8; N],
}

impl<const N: usize> SecretBytes<N> {
    /// Create an all-zero secret buffer.
    #[must_use]
    #[inline]
    pub const fn zeroed() -> Self {
        Self { bytes: [0; N] }
    }

    /// Create a secret from an array, then volatile-clear the input array.
    ///
    /// For the strongest move hygiene, prefer [`SecretBytes::from_fn`] or
    /// [`SecretBytes::copy_from_slice`] so callers can avoid building a normal
    /// byte array first.
    #[must_use]
    #[inline]
    pub fn from_array(mut bytes: [u8; N]) -> Self {
        let mut secret = Self::zeroed();
        for (index, byte) in bytes.iter().copied().enumerate() {
            secret.store(index, byte);
        }
        secret.after_secret_write();
        wipe::bytes(&mut bytes);
        secret
    }

    /// Create a secret by producing each byte directly.
    ///
    /// This avoids requiring a full temporary `[u8; N]` at the call boundary.
    #[must_use]
    #[inline]
    pub fn from_fn(mut make_byte: impl FnMut(usize) -> u8) -> Self {
        let mut secret = Self::zeroed();
        let mut index = 0;
        while index < N {
            secret.store(index, make_byte(index));
            index += 1;
        }
        secret.after_secret_write();
        secret
    }

    /// Create a secret by producing each byte directly with a fallible
    /// generator.
    ///
    /// If `make_byte` returns an error, any bytes generated before the error
    /// are cleared before the error is returned.
    #[inline]
    pub fn try_from_fn<E>(mut make_byte: impl FnMut(usize) -> Result<u8, E>) -> Result<Self, E> {
        let mut secret = Self::zeroed();
        let mut index = 0;
        while index < N {
            let byte = make_byte(index)?;
            secret.store(index, byte);
            index += 1;
        }
        secret.after_secret_write();
        Ok(secret)
    }

    /// Number of bytes stored in this secret.
    #[must_use]
    #[inline]
    pub const fn len(&self) -> usize {
        N
    }

    /// Returns true when the secret has zero length.
    #[must_use]
    #[inline]
    pub const fn is_empty(&self) -> bool {
        N == 0
    }

    /// Replace all bytes from a same-length slice.
    #[inline]
    pub fn copy_from_slice(&mut self, source: &[u8]) -> Result<(), LengthError> {
        if source.len() != N {
            return Err(LengthError {
                expected: N,
                actual: source.len(),
            });
        }

        for (index, byte) in source.iter().copied().enumerate() {
            self.store(index, byte);
        }
        self.after_secret_write();
        Ok(())
    }

    /// Replace all bytes from an owned array, then volatile-clear that input
    /// array.
    ///
    /// Prefer this over [`SecretBytes::copy_from_slice`] when the caller has an
    /// owned `[u8; N]` that should be wiped after rotation.
    #[inline]
    pub fn replace_from_array(&mut self, mut bytes: [u8; N]) {
        for (index, byte) in bytes.iter().copied().enumerate() {
            self.store(index, byte);
        }
        self.after_secret_write();
        wipe::bytes(&mut bytes);
    }

    /// Replace all bytes with generated bytes.
    ///
    /// The new bytes are generated into a fresh clear-on-drop value before the
    /// old value is cleared and replaced. If `make_byte` panics, the old value
    /// remains unchanged and partial generated bytes are cleared during
    /// unwinding.
    #[inline]
    pub fn replace_from_fn(&mut self, make_byte: impl FnMut(usize) -> u8) {
        let mut replacement = Self::from_fn(make_byte);
        self.secure_clear();
        core::mem::swap(self, &mut replacement);
    }

    /// Replace all bytes with generated bytes from a fallible generator.
    ///
    /// The new bytes are generated into a fresh clear-on-drop value before the
    /// old value is cleared and replaced. If `make_byte` returns an error, the
    /// old value remains unchanged and partial generated bytes are cleared
    /// before the error is returned.
    #[inline]
    pub fn try_replace_from_fn<E>(
        &mut self,
        make_byte: impl FnMut(usize) -> Result<u8, E>,
    ) -> Result<(), E> {
        let mut replacement = Self::try_from_fn(make_byte)?;
        self.secure_clear();
        core::mem::swap(self, &mut replacement);
        Ok(())
    }

    /// Mutate the secret bytes in place.
    ///
    /// The closure receives direct mutable access to the fixed-size storage
    /// owned by this container. It can still intentionally copy bytes
    /// elsewhere, so keep this API at cryptographic transformation boundaries
    /// such as key derivation, masking, or protocol-specific normalization.
    #[inline]
    pub fn transform(&mut self, edit: impl FnOnce(&mut [u8; N])) {
        edit(&mut self.bytes);
        self.after_secret_write();
    }

    /// Fallible variant of [`SecretBytes::transform`].
    ///
    /// If the closure returns an error after partially mutating the value,
    /// those mutations remain in place. Use [`SecretBytes::try_replace_from_fn`]
    /// when the old value must remain unchanged on error.
    #[inline]
    pub fn try_transform<E>(
        &mut self,
        edit: impl FnOnce(&mut [u8; N]) -> Result<(), E>,
    ) -> Result<(), E> {
        edit(&mut self.bytes)?;
        self.after_secret_write();
        Ok(())
    }

    /// Derive a new fixed-size secret without exposing either buffer through a
    /// temporary stack copy.
    ///
    /// The closure receives read-only access to this secret's storage and
    /// mutable access to the new output secret's storage. This is intended for
    /// KDFs, key hierarchy expansion, and similar operations where the output
    /// should be written directly into a clear-on-drop container.
    #[must_use]
    #[inline]
    pub fn derive<const M: usize>(
        &self,
        derive: impl FnOnce(&[u8; N], &mut [u8; M]),
    ) -> SecretBytes<M> {
        let mut output = SecretBytes::<M>::zeroed();
        derive(&self.bytes, &mut output.bytes);
        output.after_secret_write();
        output
    }

    /// Fallible variant of [`SecretBytes::derive`].
    ///
    /// If derivation fails, the partially written output is dropped and
    /// volatile-cleared before the error is returned.
    #[inline]
    pub fn try_derive<const M: usize, E>(
        &self,
        derive: impl FnOnce(&[u8; N], &mut [u8; M]) -> Result<(), E>,
    ) -> Result<SecretBytes<M>, E> {
        let mut output = SecretBytes::<M>::zeroed();
        derive(&self.bytes, &mut output.bytes)?;
        output.after_secret_write();
        Ok(output)
    }

    /// Export a temporary copy into caller-owned storage.
    ///
    /// The destination is outside this container's clearing guarantee. The
    /// caller must clear it. `reason` is an audit label identifying why this
    /// copy is allowed to cross the secret-container boundary.
    #[inline]
    pub fn export_to_slice(
        &self,
        reason: &'static str,
        destination: &mut [u8],
    ) -> Result<(), LengthError> {
        black_box(reason);
        if destination.len() != N {
            return Err(LengthError {
                expected: N,
                actual: destination.len(),
            });
        }

        for (index, byte) in destination.iter_mut().enumerate() {
            *byte = self.load(index);
        }
        compiler_fence(Ordering::SeqCst);
        black_box(destination);
        Ok(())
    }

    /// Export one byte from the secret.
    ///
    /// The returned scalar is an unmanaged copy that may remain in registers or
    /// compiler temporaries. `reason` is an audit label identifying the public
    /// boundary that permits this extraction.
    #[must_use]
    #[inline]
    pub fn export_byte(&self, reason: &'static str, index: usize) -> Option<u8> {
        black_box(reason);
        if index < N {
            Some(self.load(index))
        } else {
            None
        }
    }

    /// Replace one byte.
    #[inline]
    pub fn write_byte(&mut self, index: usize, value: u8) -> Result<(), LengthError> {
        if index >= N {
            return Err(LengthError {
                expected: N,
                actual: index.saturating_add(1),
            });
        }

        self.store(index, value);
        self.after_secret_write();
        Ok(())
    }

    /// Call a closure with direct shared access to the owned fixed-size bytes.
    ///
    /// This method does not intentionally construct an additional `[u8; N]`
    /// temporary. The closure can still cause compiler spills or deliberately
    /// copy bytes elsewhere, so use it only at reviewed cryptographic or
    /// protocol boundaries.
    ///
    /// The returned value cannot borrow the secret:
    ///
    /// ```compile_fail
    /// use sanitization::SecretBytes;
    ///
    /// let secret = SecretBytes::<4>::from_array([1, 2, 3, 4]);
    /// let escaped = secret.expose_secret(|bytes| bytes);
    /// let _ = escaped;
    /// ```
    #[inline]
    pub fn expose_secret<R>(&self, inspect: impl FnOnce(&[u8; N]) -> R) -> R {
        inspect(&self.bytes)
    }

    /// Call a closure with a temporary array copy, then volatile-clear it.
    ///
    /// This explicitly creates an additional `N`-byte stack array. The copy is
    /// cleared eagerly on normal return and by an RAII guard during unwinding.
    /// It cannot be cleared if the process aborts, including under
    /// `panic = "abort"`.
    ///
    /// Prefer [`SecretBytes::expose_secret`] unless the callee must receive
    /// storage that is independent from the secret container.
    #[inline]
    pub fn export_secret_copy<R>(
        &self,
        reason: &'static str,
        inspect: impl FnOnce(&[u8; N]) -> R,
    ) -> R {
        black_box(reason);
        expose_array_copy(&self.bytes, inspect)
    }

    /// Compare against a slice without early exit for equal-length inputs.
    ///
    /// Length mismatch returns immediately because the provided slice length is
    /// treated as public metadata. Prefer fixed-size inputs where possible.
    ///
    /// The portable fallback is intended to avoid data-dependent early exit, but
    /// it is not a formal hardware-level constant-time guarantee. On x86_64,
    /// enable `asm-compare` for a stronger compiler boundary. Use a dedicated
    /// constant-time comparison crate if your protocol requires externally
    /// audited timing guarantees.
    #[must_use]
    #[inline]
    pub fn constant_time_eq(&self, other: &[u8]) -> bool {
        constant_time_eq_slices(self.bytes.as_slice(), other)
    }

    /// Compare against another secret without early exit.
    ///
    /// See [`SecretBytes::constant_time_eq`] for the portable fallback timing
    /// limits.
    #[must_use]
    #[inline]
    pub fn constant_time_eq_secret(&self, other: &Self) -> bool {
        constant_time_eq_equal_len(self.bytes.as_slice(), other.bytes.as_slice())
    }

    /// Clear all bytes now. This is also called from `Drop`.
    #[inline(never)]
    pub fn secure_clear(&mut self) {
        wipe_backend::erase(self.bytes.as_mut_ptr(), N);
    }

    /// Clear all bytes now with an explicit three-pass volatile pattern.
    ///
    /// Available with the `multi-pass-clear` feature. This is intended for
    /// policy or audit compatibility; for volatile RAM, the default
    /// [`SecretBytes::secure_clear`] remains the normal security boundary.
    #[cfg(feature = "multi-pass-clear")]
    #[inline(never)]
    pub fn secure_clear_multi_pass(&mut self) {
        wipe_backend::erase_multi_pass(self.bytes.as_mut_ptr(), N);
    }

    /// Consume this value after first clearing the fixed-size storage.
    ///
    /// Drop still runs after this method returns, so the storage is cleared a
    /// second time on the normal path.
    #[inline]
    pub fn into_cleared(mut self) {
        self.secure_clear();
    }

    /// Clear all bytes now with volatile writes, then flush the cache lines
    /// covering the fixed-size storage.
    #[cfg(feature = "cache-flush")]
    #[inline(never)]
    pub fn secure_clear_and_flush(
        &mut self,
    ) -> Result<crate::cache_flush::CacheFlushReport, crate::cache_flush::CacheFlushError> {
        crate::cache_flush::cache_flush_sanitize_bytes(self.bytes.as_mut_slice())
    }

    #[inline]
    fn load(&self, index: usize) -> u8 {
        self.bytes[index]
    }

    #[inline]
    pub(crate) fn store(&mut self, index: usize, value: u8) {
        self.bytes[index] = value;
    }

    #[inline]
    pub(crate) fn after_secret_write(&self) {
        compiler_fence(Ordering::SeqCst);
    }
}

impl<const N: usize> Default for SecretBytes<N> {
    #[inline]
    fn default() -> Self {
        Self::zeroed()
    }
}

impl<const N: usize> Drop for SecretBytes<N> {
    #[inline]
    fn drop(&mut self) {
        self.secure_clear();
    }
}

impl<const N: usize> SecureSanitize for SecretBytes<N> {
    #[inline]
    fn secure_sanitize(&mut self) {
        self.secure_clear();
    }
}

impl<const N: usize> StableSharedSecretStorage for SecretBytes<N> {}
impl<const N: usize> StableMutableSecretStorage for SecretBytes<N> {}

impl<const N: usize> fmt::Debug for SecretBytes<N> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretBytes")
            .field("len", &N)
            .field("contents", &"<redacted>")
            .finish()
    }
}

impl<const N: usize> ct::ConstantTimeEq for SecretBytes<N> {
    #[inline]
    fn ct_eq(&self, other: &Self) -> ct::Choice {
        ct::eq_fixed(&self.bytes, &other.bytes)
    }
}

impl<const N: usize> ct::ConstantTimeEq<[u8]> for SecretBytes<N> {
    #[inline]
    fn ct_eq(&self, other: &[u8]) -> ct::Choice {
        ct::eq_public_len(self.bytes.as_slice(), other)
    }
}

impl<const N: usize> ct::ConditionallySelectable for SecretBytes<N> {
    #[inline]
    fn conditional_select(left: &Self, right: &Self, choice: ct::Choice) -> Self {
        let mut output = Self::zeroed();
        let mut index = 0usize;
        while index < N {
            output.bytes[index] = <u8 as ct::ConditionallySelectable>::conditional_select(
                &left.bytes[index],
                &right.bytes[index],
                choice,
            );
            index += 1;
        }
        output.after_secret_write();
        output
    }
}

/// Error returned by split-secret construction.
#[cfg(feature = "split-secret")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SplitSecretError {
    /// XOR split storage requires at least two shares.
    TooFewShares,
    /// The generated mask shares were trivially constant.
    ///
    /// This usually means the caller passed a stub, deterministic test
    /// generator, all-zero generator, or otherwise unsuitable random source.
    TrivialMask,
}

#[cfg(feature = "split-secret")]
impl fmt::Display for SplitSecretError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooFewShares => formatter.write_str("split secrets require at least two shares"),
            Self::TrivialMask => formatter.write_str(
                "split-secret mask shares are trivially constant; use cryptographically random mask bytes",
            ),
        }
    }
}

#[cfg(all(feature = "split-secret", feature = "std"))]
impl std::error::Error for SplitSecretError {}

/// Fixed-size N-of-N XOR split secret storage.
///
/// This type is available with the `split-secret` feature. It stores a secret
/// as `SHARES` independent-looking fixed-size shares where XORing every share
/// reconstructs the original bytes. It is not threshold secret sharing: all
/// shares are required, and the caller must provide cryptographically random
/// bytes for every mask share through the generator closure.
///
/// # Security
///
/// The generator is trusted. Passing a deterministic, low-entropy, or reused
/// generator can make the split provide no confidentiality. Construction
/// rejects trivially constant mask shares and trivially constant combined mask
/// accumulators in all build profiles, but that cheap heuristic is not a
/// substitute for a CSPRNG.
#[cfg(feature = "split-secret")]
pub struct SplitSecretBytes<const N: usize, const SHARES: usize> {
    shares: [SecretBytes<N>; SHARES],
}

#[cfg(feature = "split-secret")]
impl<const N: usize, const SHARES: usize> SplitSecretBytes<N, SHARES> {
    /// Split an owned secret array into `SHARES` XOR shares, then clear the
    /// input array.
    ///
    /// `make_mask_byte(share_index, byte_index)` is called for shares
    /// `0..SHARES - 1`. It must return cryptographically random mask bytes for
    /// the split to provide meaningful protection.
    pub fn from_array_with_generator(
        mut secret: [u8; N],
        mut make_mask_byte: impl FnMut(usize, usize) -> u8,
    ) -> Result<Self, SplitSecretError> {
        let guard = TemporaryBytes { bytes: &mut secret };

        if SHARES < 2 {
            return Err(SplitSecretError::TooFewShares);
        }

        let split = Self::from_secret_bytes_with_generator(guard.bytes, &mut make_mask_byte)?;
        wipe::bytes(guard.bytes);
        Ok(split)
    }

    /// Split an existing [`SecretBytes`] value into `SHARES` XOR shares.
    ///
    /// The source secret is not cleared by this method. Use
    /// [`SecretBytes::secure_clear`] afterwards if ownership policy requires
    /// moving the secret exclusively into the split representation.
    pub fn from_secret_with_generator(
        secret: &SecretBytes<N>,
        mut make_mask_byte: impl FnMut(usize, usize) -> u8,
    ) -> Result<Self, SplitSecretError> {
        if SHARES < 2 {
            return Err(SplitSecretError::TooFewShares);
        }

        Self::from_secret_bytes_with_generator(&secret.bytes, &mut make_mask_byte)
    }

    /// Split an owned [`SecretBytes`] value into `SHARES` XOR shares, then clear
    /// the source secret before returning.
    pub fn from_secret_consuming_with_generator(
        mut secret: SecretBytes<N>,
        mut make_mask_byte: impl FnMut(usize, usize) -> u8,
    ) -> Result<Self, SplitSecretError> {
        let split = Self::from_secret_bytes_with_generator(&secret.bytes, &mut make_mask_byte)?;
        secret.secure_clear();
        Ok(split)
    }

    /// Reconstruct all shares into a new [`SecretBytes`] value.
    #[must_use]
    pub fn reconstruct(&self) -> SecretBytes<N> {
        let mut output = SecretBytes::<N>::zeroed();
        let mut byte_index = 0;
        while byte_index < N {
            let mut value = 0;
            let mut share_index = 0;
            while share_index < SHARES {
                value ^= self.shares[share_index].load(byte_index);
                share_index += 1;
            }
            output.store(byte_index, value);
            byte_index += 1;
        }
        output.after_secret_write();
        output
    }

    /// Reconstruct into a temporary clear-on-drop value and expose that copy.
    ///
    /// Split storage has no contiguous plaintext representation to borrow
    /// directly. This method is therefore explicitly copy-based: it creates a
    /// temporary [`SecretBytes<N>`], reconstructs every byte into it, and
    /// clears it on normal return or unwinding. The temporary cannot be cleared
    /// if the process aborts.
    #[inline]
    pub fn expose_secret_copy<R>(&self, inspect: impl FnOnce(&[u8; N]) -> R) -> R {
        let reconstructed = self.reconstruct();
        reconstructed.expose_secret(inspect)
    }

    /// Borrow all shares.
    #[must_use]
    #[inline]
    pub const fn shares(&self) -> &[SecretBytes<N>; SHARES] {
        &self.shares
    }

    /// Borrow one share by index.
    #[must_use]
    #[inline]
    pub fn share(&self, index: usize) -> Option<&SecretBytes<N>> {
        self.shares.get(index)
    }

    /// Consume the split storage and return the underlying shares.
    #[must_use]
    #[inline]
    pub fn into_shares(self) -> [SecretBytes<N>; SHARES] {
        self.shares
    }

    fn from_secret_bytes_with_generator(
        secret: &[u8; N],
        make_mask_byte: &mut impl FnMut(usize, usize) -> u8,
    ) -> Result<Self, SplitSecretError> {
        if SHARES < 2 {
            return Err(SplitSecretError::TooFewShares);
        }

        let mut shares = core::array::from_fn(|_| SecretBytes::<N>::zeroed());

        let mut byte_index = 0;
        while byte_index < N {
            let mut accumulator = 0;
            let mut share_index = 0;
            while share_index + 1 < SHARES {
                let mask = make_mask_byte(share_index, byte_index);
                shares[share_index].store(byte_index, mask);
                accumulator ^= mask;
                share_index += 1;
            }

            shares[SHARES - 1].store(byte_index, secret[byte_index] ^ accumulator);
            byte_index += 1;
        }

        let trivial_mask = u8::from(Self::mask_shares_are_trivially_constant(&shares))
            | u8::from(Self::mask_accumulator_is_trivial(&shares));
        if trivial_mask != 0 {
            shares.secure_sanitize();
            return Err(SplitSecretError::TrivialMask);
        }

        for share in shares.iter() {
            share.after_secret_write();
        }

        Ok(Self { shares })
    }

    #[inline]
    fn mask_shares_are_trivially_constant(shares: &[SecretBytes<N>; SHARES]) -> bool {
        if N < 2 {
            return false;
        }

        let mut any_trivial = false;
        let mut share_index = 0;
        while share_index + 1 < SHARES {
            let first = shares[share_index].load(0);
            let mut byte_index = 1;
            let mut all_same = true;
            while byte_index < N {
                let diff = shares[share_index].load(byte_index) ^ first;
                all_same &= diff == 0;
                byte_index += 1;
            }

            any_trivial |= all_same;
            share_index += 1;
        }

        any_trivial
    }

    #[inline]
    fn mask_accumulator_is_trivial(shares: &[SecretBytes<N>; SHARES]) -> bool {
        if N == 0 || SHARES < 2 {
            return false;
        }

        let mut first_accumulator = 0u8;
        let mut share_index = 0;
        while share_index + 1 < SHARES {
            first_accumulator ^= shares[share_index].load(0);
            share_index += 1;
        }

        let mut all_same = true;
        let mut byte_index = 1;
        while byte_index < N {
            let mut accumulator = 0u8;
            let mut share_index = 0;
            while share_index + 1 < SHARES {
                accumulator ^= shares[share_index].load(byte_index);
                share_index += 1;
            }

            all_same &= accumulator == first_accumulator;
            byte_index += 1;
        }

        if N == 1 {
            first_accumulator == 0
        } else {
            all_same
        }
    }
}

#[cfg(feature = "split-secret")]
impl<const N: usize, const SHARES: usize> SecureSanitize for SplitSecretBytes<N, SHARES> {
    #[inline]
    fn secure_sanitize(&mut self) {
        self.shares.secure_sanitize();
    }
}

#[cfg(feature = "split-secret")]
impl<const N: usize, const SHARES: usize> StableSharedSecretStorage
    for SplitSecretBytes<N, SHARES>
{
}

#[cfg(feature = "split-secret")]
impl<const N: usize, const SHARES: usize> StableMutableSecretStorage
    for SplitSecretBytes<N, SHARES>
{
}

#[cfg(feature = "split-secret")]
impl<const N: usize, const SHARES: usize> fmt::Debug for SplitSecretBytes<N, SHARES> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SplitSecretBytes")
            .field("len", &N)
            .field("shares", &SHARES)
            .field("contents", &"<redacted>")
            .finish()
    }
}

/// Error returned when an expiring secret has exceeded its configured lifetime.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SecretExpiredError;

impl fmt::Display for SecretExpiredError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("secret has expired")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for SecretExpiredError {}

/// Error returned by expiring secret operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExpiringSecretError {
    /// The secret has exceeded its configured lifetime.
    Expired(SecretExpiredError),
    /// The caller provided a buffer with the wrong length.
    Length(LengthError),
}

impl fmt::Display for ExpiringSecretError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Expired(error) => error.fmt(formatter),
            Self::Length(error) => error.fmt(formatter),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ExpiringSecretError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Expired(error) => Some(error),
            Self::Length(error) => Some(error),
        }
    }
}

impl From<SecretExpiredError> for ExpiringSecretError {
    #[inline]
    fn from(error: SecretExpiredError) -> Self {
        Self::Expired(error)
    }
}

impl From<LengthError> for ExpiringSecretError {
    #[inline]
    fn from(error: LengthError) -> Self {
        Self::Length(error)
    }
}

/// Caller-provided monotonic tick source for no-`std` expiring secrets.
///
/// The unit is intentionally application-defined: milliseconds, RTOS ticks,
/// counter increments, or another monotonic unit. Implementations must not move
/// backward for a given secret lifetime window.
pub trait MonotonicClock {
    /// Return the current monotonic tick value.
    fn now(&self) -> u64;
}

impl<C: MonotonicClock + ?Sized> MonotonicClock for &C {
    #[inline]
    fn now(&self) -> u64 {
        (**self).now()
    }
}

/// Fixed-size secret bytes with caller-provided monotonic lifetime enforcement.
///
/// This is the `no_std` counterpart to [`ExpiringSecretBytes`]. It wraps
/// [`SecretBytes<N>`], stores a caller-provided [`MonotonicClock`], and rejects
/// exposure after `max_age` ticks. On expiration, fallible
/// read/exposure/comparison methods clear the wrapped secret before returning
/// [`SecretExpiredError`].
///
/// `max_age` is measured in caller-defined ticks. A value of `0` means the
/// secret is immediately expired: access methods clear the value and return
/// [`SecretExpiredError`]. Use a large policy value, such as `u64::MAX`, when a
/// deployment needs an expiration window that should not be reached in normal
/// operation.
///
/// The clock must not move backward for a live value. If a caller-provided tick
/// counter wraps so that `now < created_at`, [`Self::age_ticks`] returns `0`
/// through saturating arithmetic and the secret appears freshly created.
/// Callers using short-period hardware counters must extend or normalize their
/// clock before passing it to this type.
///
/// There is no background task. Expiration is checked only when a method is
/// called.
pub struct MonotonicExpiringSecretBytes<const N: usize, C: MonotonicClock> {
    inner: SecretBytes<N>,
    clock: C,
    created_at: u64,
    max_age: u64,
}

impl<const N: usize, C: MonotonicClock> MonotonicExpiringSecretBytes<N, C> {
    /// Create an all-zero expiring secret.
    ///
    /// `max_age == 0` creates a secret that is expired immediately on first
    /// access. If the caller-provided clock wraps backward, age calculation
    /// saturates to `0`; wraparound must be handled by the clock
    /// implementation.
    #[must_use]
    #[inline]
    pub fn zeroed(clock: C, max_age: u64) -> Self {
        let created_at = clock.now();
        Self {
            inner: SecretBytes::zeroed(),
            clock,
            created_at,
            max_age,
        }
    }

    /// Create an expiring secret from an array, then volatile-clear the input
    /// array.
    #[must_use]
    #[inline]
    pub fn from_array(bytes: [u8; N], clock: C, max_age: u64) -> Self {
        let created_at = clock.now();
        Self {
            inner: SecretBytes::from_array(bytes),
            clock,
            created_at,
            max_age,
        }
    }

    /// Create an expiring secret by producing each byte directly.
    #[must_use]
    #[inline]
    pub fn from_fn(clock: C, max_age: u64, make_byte: impl FnMut(usize) -> u8) -> Self {
        let created_at = clock.now();
        Self {
            inner: SecretBytes::from_fn(make_byte),
            clock,
            created_at,
            max_age,
        }
    }

    /// Create an expiring secret by fallibly producing each byte directly.
    ///
    /// If `make_byte` returns an error, any bytes generated before the error
    /// are cleared before the error is returned.
    #[inline]
    pub fn try_from_fn<E>(
        clock: C,
        max_age: u64,
        make_byte: impl FnMut(usize) -> Result<u8, E>,
    ) -> Result<Self, E> {
        let created_at = clock.now();
        Ok(Self {
            inner: SecretBytes::try_from_fn(make_byte)?,
            clock,
            created_at,
            max_age,
        })
    }

    /// Wrap an existing [`SecretBytes<N>`] and start a new lifetime window.
    #[must_use]
    #[inline]
    pub fn from_secret(secret: SecretBytes<N>, clock: C, max_age: u64) -> Self {
        let created_at = clock.now();
        Self {
            inner: secret,
            clock,
            created_at,
            max_age,
        }
    }

    /// Number of bytes stored in this secret.
    #[must_use]
    #[inline]
    pub const fn len(&self) -> usize {
        N
    }

    /// Returns true when the secret has zero length.
    #[must_use]
    #[inline]
    pub const fn is_empty(&self) -> bool {
        N == 0
    }

    /// Configured maximum age in caller-defined clock ticks.
    ///
    /// A value of `0` means immediate expiry.
    #[must_use]
    #[inline]
    pub const fn max_age_ticks(&self) -> u64 {
        self.max_age
    }

    /// Elapsed lifetime in caller-defined clock ticks.
    ///
    /// If the caller-provided clock has moved backward or wrapped around, this
    /// returns `0` through saturating arithmetic.
    #[must_use]
    #[inline]
    pub fn age_ticks(&self) -> u64 {
        self.clock.now().saturating_sub(self.created_at)
    }

    /// Returns true when the current secret value has expired.
    #[must_use]
    #[inline]
    pub fn is_expired(&self) -> bool {
        self.age_ticks() >= self.max_age
    }

    /// Borrow the monotonic clock stored by this value.
    #[must_use]
    #[inline]
    pub const fn clock(&self) -> &C {
        &self.clock
    }

    /// Replace all bytes and restart the lifetime window.
    ///
    /// The replacement is validated and staged first. The old value is then
    /// volatile-cleared before the replacement is installed.
    #[inline]
    pub fn replace_from_slice(&mut self, source: &[u8]) -> Result<(), LengthError> {
        if source.len() != N {
            if self.is_expired() {
                self.inner.secure_clear();
            }
            return Err(LengthError {
                expected: N,
                actual: source.len(),
            });
        }

        let mut replacement = SecretBytes::<N>::zeroed();
        replacement.copy_from_slice(source)?;
        self.inner.secure_clear();
        self.inner = replacement;
        self.created_at = self.clock.now();
        Ok(())
    }

    /// Replace all bytes from an owned array, clear that input array, and
    /// restart the lifetime window.
    #[inline]
    pub fn replace_from_array(&mut self, bytes: [u8; N]) {
        let replacement = SecretBytes::from_array(bytes);
        self.inner.secure_clear();
        self.inner = replacement;
        self.created_at = self.clock.now();
    }

    /// Replace all bytes from a generator and restart the lifetime window.
    #[inline]
    pub fn replace_from_fn(&mut self, make_byte: impl FnMut(usize) -> u8) {
        let expired = self.is_expired();
        if expired {
            self.inner.secure_clear();
        }

        let replacement = SecretBytes::from_fn(make_byte);
        if !expired {
            self.inner.secure_clear();
        }
        self.inner = replacement;
        self.created_at = self.clock.now();
    }

    /// Replace all bytes from a fallible generator and restart the lifetime
    /// window.
    ///
    /// If the old value is still live and generation fails, the old value
    /// remains unchanged. If the old value has already expired, it is cleared
    /// before generation and remains cleared if generation fails.
    #[inline]
    pub fn try_replace_from_fn<E>(
        &mut self,
        make_byte: impl FnMut(usize) -> Result<u8, E>,
    ) -> Result<(), E> {
        let expired = self.is_expired();
        if expired {
            self.inner.secure_clear();
        }

        let replacement = SecretBytes::try_from_fn(make_byte)?;
        if !expired {
            self.inner.secure_clear();
        }
        self.inner = replacement;
        self.created_at = self.clock.now();
        Ok(())
    }

    /// Fill a caller-provided destination with a copy of the secret bytes if
    /// the secret has not expired.
    #[inline]
    pub fn try_export_to_slice(
        &mut self,
        reason: &'static str,
        destination: &mut [u8],
    ) -> Result<(), ExpiringSecretError> {
        self.enforce_live()?;
        self.inner
            .export_to_slice(reason, destination)
            .map_err(Into::into)
    }

    /// Run a closure with direct shared access if the secret has not expired.
    #[inline]
    pub fn try_expose_secret<R>(
        &mut self,
        inspect: impl FnOnce(&[u8; N]) -> R,
    ) -> Result<R, SecretExpiredError> {
        self.enforce_live()?;
        Ok(self.inner.expose_secret(inspect))
    }

    /// Run a closure with a temporary array copy if the secret has not expired.
    ///
    /// This is the monotonic-clock variant of
    /// [`SecretBytes::export_secret_copy`].
    #[inline]
    pub fn try_export_secret_copy<R>(
        &mut self,
        reason: &'static str,
        inspect: impl FnOnce(&[u8; N]) -> R,
    ) -> Result<R, SecretExpiredError> {
        self.enforce_live()?;
        Ok(self.inner.export_secret_copy(reason, inspect))
    }

    /// Compare against a slice if the secret has not expired.
    ///
    /// Length mismatch remains public metadata and returns `Ok(false)`.
    #[inline]
    pub fn try_constant_time_eq(&mut self, other: &[u8]) -> Result<bool, SecretExpiredError> {
        self.enforce_live()?;
        Ok(self.inner.constant_time_eq(other))
    }

    /// Clear the wrapped secret immediately.
    #[inline(never)]
    pub fn secure_clear(&mut self) {
        self.inner.secure_clear();
    }

    /// Consume this value after first clearing the wrapped secret.
    #[inline]
    pub fn into_cleared(mut self) {
        self.secure_clear();
    }

    #[inline]
    fn enforce_live(&mut self) -> Result<(), SecretExpiredError> {
        if self.is_expired() {
            self.inner.secure_clear();
            Err(SecretExpiredError)
        } else {
            Ok(())
        }
    }
}

impl<const N: usize, C: MonotonicClock> Drop for MonotonicExpiringSecretBytes<N, C> {
    #[inline]
    fn drop(&mut self) {
        self.secure_clear();
    }
}

impl<const N: usize, C: MonotonicClock> SecureSanitize for MonotonicExpiringSecretBytes<N, C> {
    #[inline]
    fn secure_sanitize(&mut self) {
        self.secure_clear();
    }
}

impl<const N: usize, C: MonotonicClock> fmt::Debug for MonotonicExpiringSecretBytes<N, C> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MonotonicExpiringSecretBytes")
            .field("len", &N)
            .field("age_ticks", &self.age_ticks())
            .field("max_age_ticks", &self.max_age)
            .field("contents", &"<redacted>")
            .finish()
    }
}

/// Fixed-size secret bytes with `std` lifetime enforcement.
///
/// This type is available with the `std` feature. It wraps [`SecretBytes<N>`],
/// tracks creation time with [`std::time::Instant`], and rejects exposure after
/// the configured maximum age. On expiration, fallible read/exposure/comparison
/// methods clear the wrapped secret before returning [`SecretExpiredError`].
///
/// There is no background task. Expiration is checked only when a method is
/// called.
#[cfg(feature = "std")]
pub struct ExpiringSecretBytes<const N: usize> {
    inner: SecretBytes<N>,
    created_at: std::time::Instant,
    max_age: std::time::Duration,
}

#[cfg(feature = "std")]
impl<const N: usize> ExpiringSecretBytes<N> {
    /// Create an all-zero expiring secret.
    #[must_use]
    #[inline]
    pub fn zeroed(max_age: std::time::Duration) -> Self {
        Self {
            inner: SecretBytes::zeroed(),
            created_at: std::time::Instant::now(),
            max_age,
        }
    }

    /// Create an expiring secret from an array, then volatile-clear the input
    /// array.
    #[must_use]
    #[inline]
    pub fn from_array(bytes: [u8; N], max_age: std::time::Duration) -> Self {
        Self {
            inner: SecretBytes::from_array(bytes),
            created_at: std::time::Instant::now(),
            max_age,
        }
    }

    /// Create an expiring secret by producing each byte directly.
    #[must_use]
    #[inline]
    pub fn from_fn(max_age: std::time::Duration, make_byte: impl FnMut(usize) -> u8) -> Self {
        Self {
            inner: SecretBytes::from_fn(make_byte),
            created_at: std::time::Instant::now(),
            max_age,
        }
    }

    /// Create an expiring secret by fallibly producing each byte directly.
    ///
    /// If `make_byte` returns an error, any bytes generated before the error
    /// are cleared before the error is returned.
    #[inline]
    pub fn try_from_fn<E>(
        max_age: std::time::Duration,
        make_byte: impl FnMut(usize) -> Result<u8, E>,
    ) -> Result<Self, E> {
        Ok(Self {
            inner: SecretBytes::try_from_fn(make_byte)?,
            created_at: std::time::Instant::now(),
            max_age,
        })
    }

    /// Wrap an existing [`SecretBytes<N>`] and start a new lifetime window.
    #[must_use]
    #[inline]
    pub fn from_secret(secret: SecretBytes<N>, max_age: std::time::Duration) -> Self {
        Self {
            inner: secret,
            created_at: std::time::Instant::now(),
            max_age,
        }
    }

    /// Number of bytes stored in this secret.
    #[must_use]
    #[inline]
    pub const fn len(&self) -> usize {
        N
    }

    /// Returns true when the secret has zero length.
    #[must_use]
    #[inline]
    pub const fn is_empty(&self) -> bool {
        N == 0
    }

    /// Configured maximum age for the current secret value.
    #[must_use]
    #[inline]
    pub const fn max_age(&self) -> std::time::Duration {
        self.max_age
    }

    /// Elapsed lifetime of the current secret value.
    #[must_use]
    #[inline]
    pub fn age(&self) -> std::time::Duration {
        self.created_at.elapsed()
    }

    /// Returns true when the current secret value has expired.
    #[must_use]
    #[inline]
    pub fn is_expired(&self) -> bool {
        self.age() >= self.max_age
    }

    /// Replace all bytes and restart the lifetime window.
    ///
    /// The replacement is validated and staged first. The old value is then
    /// volatile-cleared before the replacement is installed.
    #[inline]
    pub fn replace_from_slice(&mut self, source: &[u8]) -> Result<(), LengthError> {
        if source.len() != N {
            if self.is_expired() {
                self.inner.secure_clear();
            }
            return Err(LengthError {
                expected: N,
                actual: source.len(),
            });
        }

        let mut replacement = SecretBytes::<N>::zeroed();
        replacement.copy_from_slice(source)?;
        self.inner.secure_clear();
        self.inner = replacement;
        self.created_at = std::time::Instant::now();
        Ok(())
    }

    /// Replace all bytes from an owned array, clear that input array, and
    /// restart the lifetime window.
    ///
    /// The replacement is staged first. The old value is then volatile-cleared
    /// before the replacement is installed.
    #[inline]
    pub fn replace_from_array(&mut self, bytes: [u8; N]) {
        let replacement = SecretBytes::from_array(bytes);
        self.inner.secure_clear();
        self.inner = replacement;
        self.created_at = std::time::Instant::now();
    }

    /// Replace all bytes from a generator and restart the lifetime window.
    ///
    /// If the previous value has already expired, it is cleared before the new
    /// value is generated. If `make_byte` panics and the old value was still
    /// live, the old value remains unchanged.
    #[inline]
    pub fn replace_from_fn(&mut self, make_byte: impl FnMut(usize) -> u8) {
        let expired = self.is_expired();
        if expired {
            self.inner.secure_clear();
        }

        let replacement = SecretBytes::from_fn(make_byte);
        if !expired {
            self.inner.secure_clear();
        }
        self.inner = replacement;
        self.created_at = std::time::Instant::now();
    }

    /// Replace all bytes from a fallible generator and restart the lifetime
    /// window.
    ///
    /// If the old value is still live and generation fails, the old value
    /// remains unchanged. If the old value has already expired, it is cleared
    /// before generation and remains cleared if generation fails.
    #[inline]
    pub fn try_replace_from_fn<E>(
        &mut self,
        make_byte: impl FnMut(usize) -> Result<u8, E>,
    ) -> Result<(), E> {
        let expired = self.is_expired();
        if expired {
            self.inner.secure_clear();
        }

        let replacement = SecretBytes::try_from_fn(make_byte)?;
        if !expired {
            self.inner.secure_clear();
        }
        self.inner = replacement;
        self.created_at = std::time::Instant::now();
        Ok(())
    }

    /// Fill a caller-provided destination with a copy of the secret bytes if
    /// the secret has not expired.
    #[inline]
    pub fn try_export_to_slice(
        &mut self,
        reason: &'static str,
        destination: &mut [u8],
    ) -> Result<(), ExpiringSecretError> {
        self.enforce_live()?;
        self.inner
            .export_to_slice(reason, destination)
            .map_err(Into::into)
    }

    /// Run a closure with direct shared access if the secret has not expired.
    #[inline]
    pub fn try_expose_secret<R>(
        &mut self,
        inspect: impl FnOnce(&[u8; N]) -> R,
    ) -> Result<R, SecretExpiredError> {
        self.enforce_live()?;
        Ok(self.inner.expose_secret(inspect))
    }

    /// Run a closure with a temporary array copy if the secret has not expired.
    ///
    /// This is the expiring variant of [`SecretBytes::export_secret_copy`].
    #[inline]
    pub fn try_export_secret_copy<R>(
        &mut self,
        reason: &'static str,
        inspect: impl FnOnce(&[u8; N]) -> R,
    ) -> Result<R, SecretExpiredError> {
        self.enforce_live()?;
        Ok(self.inner.export_secret_copy(reason, inspect))
    }

    /// Compare against a slice if the secret has not expired.
    ///
    /// Length mismatch remains public metadata and returns `Ok(false)`.
    ///
    /// This delegates to [`SecretBytes::constant_time_eq`]; see that method for
    /// portable fallback timing limits.
    #[inline]
    pub fn try_constant_time_eq(&mut self, other: &[u8]) -> Result<bool, SecretExpiredError> {
        self.enforce_live()?;
        Ok(self.inner.constant_time_eq(other))
    }

    /// Clear the wrapped secret immediately.
    #[inline(never)]
    pub fn secure_clear(&mut self) {
        self.inner.secure_clear();
    }

    /// Consume this value after first clearing the wrapped secret.
    ///
    /// Drop still runs after this method returns, so the wrapped storage is
    /// cleared a second time on the normal path.
    #[inline]
    pub fn into_cleared(mut self) {
        self.secure_clear();
    }

    #[inline]
    fn enforce_live(&mut self) -> Result<(), SecretExpiredError> {
        if self.is_expired() {
            self.inner.secure_clear();
            Err(SecretExpiredError)
        } else {
            Ok(())
        }
    }
}

#[cfg(feature = "std")]
impl<const N: usize> Drop for ExpiringSecretBytes<N> {
    #[inline]
    fn drop(&mut self) {
        self.secure_clear();
    }
}

#[cfg(feature = "std")]
impl<const N: usize> SecureSanitize for ExpiringSecretBytes<N> {
    #[inline]
    fn secure_sanitize(&mut self) {
        self.secure_clear();
    }
}

#[cfg(feature = "std")]
impl<const N: usize> StableSharedSecretStorage for ExpiringSecretBytes<N> {}

#[cfg(feature = "std")]
impl<const N: usize> StableMutableSecretStorage for ExpiringSecretBytes<N> {}

#[cfg(feature = "std")]
impl<const N: usize> fmt::Debug for ExpiringSecretBytes<N> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExpiringSecretBytes")
            .field("len", &N)
            .field("max_age", &self.max_age)
            .field("contents", &"<redacted>")
            .finish()
    }
}

/// Fixed-allocation secret bytes with a runtime length.
///
/// This type is available with the `alloc` feature. Unlike [`SecretVec`], its
/// public API cannot grow or shrink the private backing allocation after
/// construction. Mutable exposure receives only `&mut [u8]`, so safe
/// operations cannot reallocate it. The private `Vec<u8>` representation exists
/// so bounded constructors can use fallible reservation; the safe API never
/// exposes vector growth or ownership extraction.
///
/// Replacement requires the same public length. A replacement value is fully
/// constructed in a separate clear-on-drop allocation before the old
/// allocation is cleared and exchanged. Use [`SecretVec`] when the secret
/// length must change over time.
///
/// Clearing covers the backing allocation's full capacity, including any
/// allocator-provided spare bytes.
///
/// The type deliberately does not implement `Clone`, `Copy`, `Deref`,
/// `AsRef<[u8]>`, `PartialEq`, or secret-printing `Debug`.
#[cfg(feature = "alloc")]
pub struct SecretBoxBytes {
    pub(crate) inner: Vec<u8>,
}

#[cfg(feature = "alloc")]
impl SecretBoxBytes {
    /// Allocate `len` zeroed secret bytes.
    ///
    /// `len` must already be validated as trusted public metadata. Like
    /// ordinary infallible Rust allocation APIs, allocation failure may abort
    /// the process. Use [`SecretBoxBytes::try_zeroed`] for untrusted lengths or
    /// availability-sensitive code.
    #[must_use]
    #[inline]
    pub fn zeroed(len: usize) -> Self {
        Self {
            inner: alloc::vec![0; len],
        }
    }

    /// Allocate a bounded fixed-length secret without aborting on reserve
    /// failure.
    ///
    /// The public maximum is checked before allocation. After
    /// `try_reserve_exact` succeeds, resizing to `len` cannot allocate.
    #[inline]
    pub fn try_zeroed(len: usize, maximum: usize) -> Result<Self, SecretBoxBytesBuildError> {
        if len > maximum {
            return Err(SecretBoxBytesBuildError::TooLong {
                maximum,
                actual: len,
            });
        }

        let mut inner = Vec::new();
        inner
            .try_reserve_exact(len)
            .map_err(SecretBoxBytesBuildError::Allocation)?;
        inner.resize(len, 0);
        Ok(Self { inner })
    }

    /// Take ownership of an existing boxed byte slice.
    ///
    /// The allocation is not copied. Its complete length is volatile-cleared
    /// when this value is cleared or dropped.
    #[must_use]
    #[inline]
    pub fn from_boxed_slice(inner: Box<[u8]>) -> Self {
        Self {
            inner: inner.into_vec(),
        }
    }

    /// Allocate fixed-length storage and copy bytes into it.
    ///
    /// The slice length must already be validated when it comes from untrusted
    /// metadata. Use [`SecretBoxBytes::try_from_slice`] to apply a public bound
    /// and return allocation failure.
    #[must_use]
    #[inline]
    pub fn from_slice(bytes: &[u8]) -> Self {
        Self {
            inner: Vec::from(bytes),
        }
    }

    /// Copy a bounded slice into fallibly allocated fixed-length storage.
    #[inline]
    pub fn try_from_slice(bytes: &[u8], maximum: usize) -> Result<Self, SecretBoxBytesBuildError> {
        let mut secret = Self::try_zeroed(bytes.len(), maximum)?;
        secret.inner.copy_from_slice(bytes);
        Ok(secret)
    }

    /// Generate each byte directly into fixed-length clear-on-drop storage.
    ///
    /// If the generator panics, the partially initialized value is cleared
    /// during unwinding. `len` must already be trusted and bounded; allocation
    /// failure may abort. Use [`SecretBoxBytes::try_from_fn_bounded`] for
    /// untrusted lengths.
    #[must_use]
    #[inline]
    pub fn from_fn(len: usize, mut make_byte: impl FnMut(usize) -> u8) -> Self {
        let mut secret = Self::zeroed(len);
        let mut index = 0;
        while index < len {
            secret.inner[index] = make_byte(index);
            index += 1;
        }
        secret
    }

    /// Generate each byte with a fallible generator.
    ///
    /// If generation fails, the partially initialized allocation is cleared
    /// before the error is returned. This method only reports generator errors;
    /// `len` must already be trusted and bounded, and allocation failure may
    /// abort. Use [`SecretBoxBytes::try_from_fn_bounded`] when allocation must
    /// also be fallible.
    #[inline]
    pub fn try_from_fn<E>(
        len: usize,
        mut make_byte: impl FnMut(usize) -> Result<u8, E>,
    ) -> Result<Self, E> {
        let mut secret = Self::zeroed(len);
        let mut index = 0;
        while index < len {
            secret.inner[index] = make_byte(index)?;
            index += 1;
        }
        Ok(secret)
    }

    /// Generate a bounded fixed-length secret with fallible allocation and
    /// fallible byte generation.
    #[inline]
    pub fn try_from_fn_bounded<E>(
        len: usize,
        maximum: usize,
        mut make_byte: impl FnMut(usize) -> Result<u8, E>,
    ) -> Result<Self, SecretBoxBytesGenerateError<E>> {
        let mut secret =
            Self::try_zeroed(len, maximum).map_err(SecretBoxBytesGenerateError::Build)?;
        let mut index = 0;
        while index < len {
            secret.inner[index] =
                make_byte(index).map_err(SecretBoxBytesGenerateError::Generate)?;
            index += 1;
        }
        Ok(secret)
    }

    /// Number of initialized bytes in the fixed allocation.
    #[must_use]
    #[inline]
    pub const fn len(&self) -> usize {
        self.inner.len()
    }

    /// Returns true when the fixed allocation has length zero.
    #[must_use]
    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Run a closure with direct shared access to the fixed allocation.
    ///
    /// The returned value cannot borrow the secret:
    ///
    /// ```compile_fail
    /// use sanitization::SecretBoxBytes;
    ///
    /// let secret = SecretBoxBytes::from_slice(b"token");
    /// let escaped = secret.with_secret(|bytes| bytes);
    /// let _ = escaped;
    /// ```
    #[inline]
    pub fn with_secret<R>(&self, inspect: impl FnOnce(&[u8]) -> R) -> R {
        inspect(self.inner.as_slice())
    }

    /// Run a closure with direct mutable access to the fixed allocation.
    ///
    /// A mutable slice cannot resize or replace the backing allocation.
    #[inline]
    pub fn with_secret_mut<R>(&mut self, edit: impl FnOnce(&mut [u8]) -> R) -> R {
        edit(self.inner.as_mut_slice())
    }

    /// Copy the secret into a caller-provided slice of the same public length.
    #[inline]
    pub fn copy_to_slice(&self, destination: &mut [u8]) -> Result<(), LengthError> {
        if destination.len() != self.len() {
            return Err(LengthError {
                expected: self.len(),
                actual: destination.len(),
            });
        }

        destination.copy_from_slice(self.inner.as_slice());
        Ok(())
    }

    /// Replace the secret from a same-length slice.
    ///
    /// The replacement allocation is constructed before the old allocation is
    /// cleared. A length mismatch leaves the existing secret unchanged.
    #[inline]
    pub fn replace_from_slice(&mut self, bytes: &[u8]) -> Result<(), LengthError> {
        self.ensure_replacement_len(bytes.len())?;
        let replacement = Self::from_slice(bytes);
        self.replace_staged(replacement);
        Ok(())
    }

    /// Replace the secret by taking ownership of a same-length boxed slice.
    ///
    /// On length mismatch, the rejected boxed bytes are cleared before this
    /// method returns the error.
    #[inline]
    pub fn replace_from_boxed_slice(&mut self, bytes: Box<[u8]>) -> Result<(), LengthError> {
        let replacement = Self::from_boxed_slice(bytes);
        self.ensure_replacement_len(replacement.len())?;
        self.replace_staged(replacement);
        Ok(())
    }

    /// Replace the secret with same-length generated bytes.
    ///
    /// The replacement is generated in a fresh clear-on-drop allocation. If
    /// generation panics, the old value remains unchanged.
    #[inline]
    pub fn replace_from_fn(&mut self, make_byte: impl FnMut(usize) -> u8) {
        let replacement = Self::from_fn(self.len(), make_byte);
        self.replace_staged(replacement);
    }

    /// Replace the secret with same-length fallibly generated bytes.
    ///
    /// If generation fails, the old value remains unchanged and the partial
    /// replacement is cleared before the error is returned.
    #[inline]
    pub fn try_replace_from_fn<E>(
        &mut self,
        make_byte: impl FnMut(usize) -> Result<u8, E>,
    ) -> Result<(), E> {
        let replacement = Self::try_from_fn(self.len(), make_byte)?;
        self.replace_staged(replacement);
        Ok(())
    }

    /// Clear every byte while retaining the fixed allocation and length.
    #[inline(never)]
    pub fn clear_secret(&mut self) {
        wipe_backend::erase(self.inner.as_mut_ptr(), self.inner.capacity());
    }

    /// Consume this value after clearing its complete allocation.
    #[inline]
    pub fn into_cleared(mut self) {
        self.clear_secret();
    }

    /// Compare against a slice without early exit for equal-length inputs.
    ///
    /// Length is treated as public metadata.
    #[must_use]
    #[inline]
    pub fn constant_time_eq(&self, other: &[u8]) -> bool {
        constant_time_eq_slices(self.inner.as_slice(), other)
    }

    #[inline]
    fn ensure_replacement_len(&self, actual: usize) -> Result<(), LengthError> {
        if actual == self.len() {
            Ok(())
        } else {
            Err(LengthError {
                expected: self.len(),
                actual,
            })
        }
    }

    #[inline]
    fn replace_staged(&mut self, mut replacement: Self) {
        self.clear_secret();
        core::mem::swap(&mut self.inner, &mut replacement.inner);
    }
}

#[cfg(feature = "alloc")]
impl Drop for SecretBoxBytes {
    #[inline]
    fn drop(&mut self) {
        self.clear_secret();
    }
}

#[cfg(feature = "alloc")]
impl Default for SecretBoxBytes {
    #[inline]
    fn default() -> Self {
        Self::zeroed(0)
    }
}

#[cfg(feature = "alloc")]
impl SecureSanitize for SecretBoxBytes {
    #[inline]
    fn secure_sanitize(&mut self) {
        self.clear_secret();
    }
}

#[cfg(feature = "alloc")]
impl StableSharedSecretStorage for SecretBoxBytes {}

#[cfg(feature = "alloc")]
impl StableMutableSecretStorage for SecretBoxBytes {}

#[cfg(feature = "alloc")]
impl fmt::Debug for SecretBoxBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretBoxBytes")
            .field("len", &self.len())
            .field("contents", &"<redacted>")
            .finish()
    }
}

#[cfg(feature = "alloc")]
impl ct::ConstantTimeEq for SecretBoxBytes {
    #[inline]
    fn ct_eq(&self, other: &Self) -> ct::Choice {
        ct::eq_public_len(self.inner.as_slice(), other.inner.as_slice())
    }
}

#[cfg(feature = "alloc")]
impl ct::ConstantTimeEq<[u8]> for SecretBoxBytes {
    #[inline]
    fn ct_eq(&self, other: &[u8]) -> ct::Choice {
        ct::eq_public_len(self.inner.as_slice(), other)
    }
}

/// Error returned when fallible dynamic secret allocation fails.
///
/// Public lengths and configured maxima are not treated as secret data.
#[cfg(feature = "alloc")]
#[derive(Debug)]
pub enum SecretAllocationError {
    /// The requested public length exceeded the caller's maximum.
    TooLong {
        /// Maximum accepted length.
        maximum: usize,
        /// Rejected requested length.
        actual: usize,
    },
    /// Arithmetic for the required allocation capacity overflowed.
    CapacityOverflow,
    /// The allocator could not reserve the requested storage.
    Allocation(alloc::collections::TryReserveError),
}

#[cfg(feature = "alloc")]
impl From<alloc::collections::TryReserveError> for SecretAllocationError {
    #[inline]
    fn from(error: alloc::collections::TryReserveError) -> Self {
        Self::Allocation(error)
    }
}

#[cfg(feature = "alloc")]
impl fmt::Display for SecretAllocationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLong { maximum, actual } => write!(
                formatter,
                "secret length exceeds limit: maximum {maximum} bytes, got {actual} bytes"
            ),
            Self::CapacityOverflow => formatter.write_str("secret capacity calculation overflowed"),
            Self::Allocation(error) => write!(formatter, "secret allocation failed: {error}"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for SecretAllocationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::TooLong { .. } | Self::CapacityOverflow => None,
            Self::Allocation(error) => Some(error),
        }
    }
}

/// Error returned by fallible dynamic secret generation.
///
/// Partially generated storage remains owned by a clear-on-drop value on every
/// error path.
#[cfg(feature = "alloc")]
#[derive(Debug)]
pub enum SecretGenerateError<E> {
    /// Allocation or public-length validation failed.
    Build(SecretAllocationError),
    /// The caller's generator failed.
    Generate(E),
}

#[cfg(feature = "alloc")]
impl<E> From<SecretAllocationError> for SecretGenerateError<E> {
    #[inline]
    fn from(error: SecretAllocationError) -> Self {
        Self::Build(error)
    }
}

#[cfg(feature = "alloc")]
impl<E: fmt::Display> fmt::Display for SecretGenerateError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Build(error) => error.fmt(formatter),
            Self::Generate(error) => write!(formatter, "secret generation failed: {error}"),
        }
    }
}

#[cfg(feature = "std")]
impl<E> std::error::Error for SecretGenerateError<E>
where
    E: std::error::Error + 'static,
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Build(error) => Some(error),
            Self::Generate(error) => Some(error),
        }
    }
}

/// Compatibility name for fixed-allocation build failures.
#[cfg(feature = "alloc")]
pub type SecretBoxBytesBuildError = SecretAllocationError;

/// Compatibility name for fixed-allocation generation failures.
#[cfg(feature = "alloc")]
pub type SecretBoxBytesGenerateError<E> = SecretGenerateError<E>;

/// Heap-allocated secret bytes with clear-on-drop behavior.
///
/// This type is available with the `alloc` feature. It is intended for
/// integration boundaries where the secret length is dynamic, such as decoded
/// tokens or PEM/DER material. Clearing uses volatile writes over the full
/// allocation capacity before the vector length is set to zero.
///
/// With the `serde` feature, deserialization rejects inputs larger than
/// [`DEFAULT_SECRET_VEC_SERDE_MAX_LEN`]. Use [`BoundedSecretVec<MAX>`] at
/// boundaries that require a different application-defined maximum.
#[cfg(feature = "alloc")]
pub struct SecretVec {
    pub(crate) inner: Vec<u8>,
}

/// Default maximum accepted by serde deserialization into [`SecretVec`].
///
/// The 1 MiB ceiling prevents accidental unbounded allocation while remaining
/// large enough for typical encoded keys, tokens, and certificate material.
/// Use [`BoundedSecretVec<MAX>`] when a protocol requires a different limit.
#[cfg(feature = "alloc")]
pub const DEFAULT_SECRET_VEC_SERDE_MAX_LEN: usize = 1024 * 1024;

#[cfg(feature = "alloc")]
impl SecretVec {
    /// Wrap a vector using volatile clearing on drop.
    #[must_use]
    #[inline]
    pub const fn new(inner: Vec<u8>) -> Self {
        Self { inner }
    }

    /// Wrap an existing vector using volatile clearing on drop.
    ///
    /// This is an explicit ownership-taking alias for [`SecretVec::new`]. The
    /// vector is not copied; its full capacity will be volatile-cleared when
    /// this `SecretVec` is cleared or dropped.
    #[must_use]
    #[inline]
    pub const fn from_vec(bytes: Vec<u8>) -> Self {
        Self::new(bytes)
    }

    /// Create an empty secret vector.
    #[must_use]
    #[inline]
    pub const fn empty() -> Self {
        Self::new(Vec::new())
    }

    /// Create an empty secret vector with at least the requested capacity.
    ///
    /// `capacity` must be trusted and bounded. Allocation failure may abort;
    /// use [`SecretVec::try_with_capacity`] when it must be reported.
    #[must_use]
    #[inline]
    pub fn with_capacity(capacity: usize) -> Self {
        Self::new(Vec::with_capacity(capacity))
    }

    /// Create an empty secret vector using fallible allocation.
    ///
    /// Unlike [`SecretVec::with_capacity`], this reports capacity overflow or
    /// allocation failure instead of panicking or invoking the allocation
    /// error handler.
    #[inline]
    pub fn try_with_capacity(capacity: usize) -> Result<Self, SecretAllocationError> {
        let mut inner = Vec::new();
        inner
            .try_reserve_exact(capacity)
            .map_err(SecretAllocationError::Allocation)?;
        Ok(Self::new(inner))
    }

    /// Create a secret vector by copying bytes from a slice.
    ///
    /// The public length must be trusted and bounded. Use
    /// [`SecretVec::try_from_slice_bounded`] at untrusted boundaries.
    #[must_use]
    #[inline]
    pub fn from_slice(bytes: &[u8]) -> Self {
        Self::new(Vec::from(bytes))
    }

    /// Copy a slice after enforcing a public byte-length ceiling and using
    /// fallible allocation.
    ///
    /// Length validation happens before allocation. The borrowed source is not
    /// cleared by this method.
    #[inline]
    pub fn try_from_slice_bounded(
        bytes: &[u8],
        maximum: usize,
    ) -> Result<Self, SecretAllocationError> {
        if bytes.len() > maximum {
            return Err(SecretAllocationError::TooLong {
                maximum,
                actual: bytes.len(),
            });
        }

        let mut secret = Self::try_with_capacity(bytes.len())?;
        secret.inner.extend_from_slice(bytes);
        Ok(secret)
    }

    /// Create a secret vector by generating each byte directly into a
    /// clear-on-drop allocation.
    ///
    /// If `make_byte` panics, any bytes generated before the panic are still
    /// owned by a `SecretVec` local and are cleared during unwinding.
    /// `len` must be trusted and bounded; allocation failure may abort.
    #[must_use]
    #[inline]
    pub fn from_fn(len: usize, mut make_byte: impl FnMut(usize) -> u8) -> Self {
        let mut secret = Self::with_capacity(len);
        let mut index = 0;
        while index < len {
            secret.inner.push(make_byte(index));
            index += 1;
        }
        secret
    }

    /// Create a secret vector by generating each byte with a fallible
    /// generator.
    ///
    /// If `make_byte` returns an error, any bytes generated before the error
    /// are cleared before the error is returned. This method reports both
    /// allocation failure through `SecretGenerateError::Build` and generator
    /// failure through `SecretGenerateError::Generate`. It does not enforce an
    /// application maximum; use [`SecretVec::try_from_fn_bounded`] when needed.
    #[inline]
    pub fn try_from_fn<E>(
        len: usize,
        mut make_byte: impl FnMut(usize) -> Result<u8, E>,
    ) -> Result<Self, SecretGenerateError<E>> {
        let mut secret = Self::try_with_capacity(len).map_err(SecretGenerateError::Build)?;
        let mut index = 0;
        while index < len {
            let byte = make_byte(index).map_err(SecretGenerateError::Generate)?;
            secret.inner.push(byte);
            index += 1;
        }
        Ok(secret)
    }

    /// Create a secret vector with a caller-enforced public length ceiling.
    ///
    /// Length validation happens before allocation and before the generator is
    /// called. Allocation and generator failures remain distinguishable.
    #[inline]
    pub fn try_from_fn_bounded<E>(
        len: usize,
        maximum: usize,
        make_byte: impl FnMut(usize) -> Result<u8, E>,
    ) -> Result<Self, SecretGenerateError<E>> {
        if len > maximum {
            return Err(SecretGenerateError::Build(SecretAllocationError::TooLong {
                maximum,
                actual: len,
            }));
        }
        Self::try_from_fn(len, make_byte)
    }

    /// Number of bytes currently held.
    #[must_use]
    #[inline]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Returns true when no bytes are held.
    #[must_use]
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Current allocation capacity in bytes.
    #[must_use]
    #[inline]
    pub fn capacity(&self) -> usize {
        self.inner.capacity()
    }

    /// Run a closure with read-only access to the secret bytes.
    #[inline]
    pub fn with_secret<R>(&self, inspect: impl FnOnce(&[u8]) -> R) -> R {
        inspect(self.inner.as_slice())
    }

    /// Run a closure with mutable access to the secret bytes.
    #[inline]
    pub fn with_secret_mut<R>(&mut self, edit: impl FnOnce(&mut [u8]) -> R) -> R {
        edit(self.inner.as_mut_slice())
    }

    /// Append bytes to the secret vector.
    ///
    /// If capacity must grow, the previous allocation is wiped before it is
    /// dropped. Prefer constructing with enough capacity in callers that append
    /// repeatedly.
    #[inline]
    pub fn extend_from_slice(&mut self, bytes: &[u8]) {
        self.grow_for(bytes.len());
        self.inner.extend_from_slice(bytes);
    }

    /// Replace all bytes with a new slice.
    ///
    /// If capacity must grow, the old allocation is wiped before it is dropped
    /// and the old secret bytes are not copied into the replacement allocation.
    #[inline]
    pub fn replace_from_slice(&mut self, bytes: &[u8]) {
        if bytes.len() > self.inner.capacity() {
            let new_capacity = next_secret_capacity(self.inner.capacity(), bytes.len());
            let mut replacement = Vec::with_capacity(new_capacity);
            replacement.extend_from_slice(bytes);
            self.clear_secret();
            self.inner = replacement;
            return;
        }

        self.clear_secret();
        self.inner.extend_from_slice(bytes);
    }

    /// Replace all bytes by taking ownership of an existing vector.
    ///
    /// The old allocation is cleared before the provided vector becomes the
    /// secret storage. The provided vector is not copied; its full capacity will
    /// be volatile-cleared when this `SecretVec` is later cleared or dropped.
    #[inline]
    pub fn replace_from_vec(&mut self, bytes: Vec<u8>) {
        self.clear_secret();
        self.inner = bytes;
    }

    /// Replace all bytes with generated bytes.
    ///
    /// The new bytes are generated into a fresh clear-on-drop allocation before
    /// the old value is cleared and replaced. If `make_byte` panics, the old
    /// value remains unchanged and partial generated bytes are cleared during
    /// unwinding.
    #[inline]
    pub fn replace_from_fn(&mut self, len: usize, make_byte: impl FnMut(usize) -> u8) {
        let mut replacement = Self::from_fn(len, make_byte);
        self.clear_secret();
        core::mem::swap(&mut self.inner, &mut replacement.inner);
    }

    /// Replace all bytes with generated bytes from a fallible generator.
    ///
    /// The new bytes are generated into a fresh clear-on-drop allocation before
    /// the old value is cleared and replaced. If `make_byte` returns an error,
    /// the old value remains unchanged and partial generated bytes are cleared
    /// before the error is returned.
    #[inline]
    pub fn try_replace_from_fn<E>(
        &mut self,
        len: usize,
        make_byte: impl FnMut(usize) -> Result<u8, E>,
    ) -> Result<(), SecretGenerateError<E>> {
        let mut replacement = Self::try_from_fn(len, make_byte)?;
        self.clear_secret();
        core::mem::swap(&mut self.inner, &mut replacement.inner);
        Ok(())
    }

    /// Clear this value immediately with volatile writes.
    #[inline(never)]
    pub fn clear_secret(&mut self) {
        sanitize_vec_capacity(&mut self.inner);
    }

    /// Clear this value immediately with an explicit three-pass volatile
    /// pattern over the full allocation capacity.
    ///
    /// Available with the `multi-pass-clear` feature. This is intended for
    /// policy or audit compatibility; for volatile RAM, the default
    /// [`SecretVec::clear_secret`] remains the normal security boundary.
    #[cfg(feature = "multi-pass-clear")]
    #[inline(never)]
    pub fn clear_secret_multi_pass(&mut self) {
        sanitize_vec_capacity_multi_pass(&mut self.inner);
    }

    /// Clear this value immediately with volatile writes, then flush the cache
    /// lines covering the heap allocation.
    #[cfg(feature = "cache-flush")]
    #[inline(never)]
    pub fn clear_secret_and_flush(
        &mut self,
    ) -> Result<crate::cache_flush::CacheFlushReport, crate::cache_flush::CacheFlushError> {
        crate::cache_flush::cache_flush_sanitize_vec(&mut self.inner)
    }

    /// Compare against a byte slice without early exit for equal-length inputs.
    ///
    /// Length mismatch returns immediately because the provided slice length is
    /// treated as public metadata.
    ///
    /// The portable fallback is intended to avoid data-dependent early exit, but
    /// it is not a formal hardware-level constant-time guarantee. On x86_64,
    /// enable `asm-compare` for a stronger compiler boundary. Use a dedicated
    /// constant-time comparison crate if your protocol requires externally
    /// audited timing guarantees.
    #[must_use]
    #[inline]
    pub fn constant_time_eq(&self, other: &[u8]) -> bool {
        constant_time_eq_slices(self.inner.as_slice(), other)
    }

    /// Consume the wrapper after first clearing the wrapped bytes.
    #[inline]
    pub fn into_cleared(mut self) {
        self.clear_secret();
    }

    /// Convert this byte container into secret UTF-8 text without reallocating.
    ///
    /// The existing heap allocation is transferred to [`SecretString`] after
    /// UTF-8 validation. If validation fails, the full allocation capacity is
    /// volatile-cleared before the error is returned.
    #[inline]
    pub fn try_into_secret_string(self) -> Result<SecretString, core::str::Utf8Error> {
        SecretString::from_secret_vec(self)
    }

    fn grow_for(&mut self, additional: usize) {
        let required = self.inner.len().saturating_add(additional);
        if required <= self.inner.capacity() {
            return;
        }

        let new_capacity = next_secret_capacity(self.inner.capacity(), required);
        let mut replacement = Vec::with_capacity(new_capacity);
        replacement.extend_from_slice(self.inner.as_slice());
        self.clear_secret();
        self.inner = replacement;
    }
}

#[cfg(feature = "alloc")]
impl Drop for SecretVec {
    #[inline]
    fn drop(&mut self) {
        self.clear_secret();
    }
}

#[cfg(feature = "alloc")]
impl Default for SecretVec {
    #[inline]
    fn default() -> Self {
        Self::empty()
    }
}

#[cfg(feature = "alloc")]
impl SecureSanitize for SecretVec {
    #[inline]
    fn secure_sanitize(&mut self) {
        self.clear_secret();
    }
}

#[cfg(feature = "alloc")]
impl fmt::Debug for SecretVec {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretVec")
            .field("len", &self.inner.len())
            .field("contents", &"<redacted>")
            .finish()
    }
}

#[cfg(feature = "alloc")]
impl ct::ConstantTimeEq for SecretVec {
    #[inline]
    fn ct_eq(&self, other: &Self) -> ct::Choice {
        ct::eq_public_len(self.inner.as_slice(), other.inner.as_slice())
    }
}

#[cfg(feature = "alloc")]
impl ct::ConstantTimeEq<[u8]> for SecretVec {
    #[inline]
    fn ct_eq(&self, other: &[u8]) -> ct::Choice {
        ct::eq_public_len(self.inner.as_slice(), other)
    }
}

/// Error returned when a dynamic secret exceeds its declared public limit.
#[cfg(feature = "alloc")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SecretVecLimitError {
    /// Maximum accepted secret length.
    pub maximum: usize,
    /// Length that was rejected.
    pub actual: usize,
}

#[cfg(feature = "alloc")]
impl fmt::Display for SecretVecLimitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "secret length exceeds limit: maximum {} bytes, got {} bytes",
            self.maximum, self.actual
        )
    }
}

#[cfg(feature = "std")]
impl std::error::Error for SecretVecLimitError {}

/// Heap-allocated secret bytes constrained to a public maximum length.
///
/// This additive wrapper is intended for protocol and configuration trust
/// boundaries where unbounded dynamic secret allocation is unacceptable. With
/// the `serde` feature, every deserialization input form rejects more than
/// `MAX` bytes. Rejected owned buffers and partially decoded values are cleared
/// before they are released.
#[cfg(feature = "alloc")]
pub struct BoundedSecretVec<const MAX: usize> {
    pub(crate) inner: SecretVec,
}

#[cfg(feature = "alloc")]
impl<const MAX: usize> BoundedSecretVec<MAX> {
    /// Create an empty bounded secret.
    #[must_use]
    #[inline]
    pub const fn empty() -> Self {
        Self {
            inner: SecretVec::empty(),
        }
    }

    /// Copy a slice into bounded secret storage.
    #[inline]
    pub fn from_slice(bytes: &[u8]) -> Result<Self, SecretVecLimitError> {
        Self::validate_len(bytes.len())?;
        Ok(Self {
            inner: SecretVec::from_slice(bytes),
        })
    }

    /// Take ownership of a vector after validating its length.
    ///
    /// An oversized input allocation is volatile-cleared before the error is
    /// returned.
    #[inline]
    pub fn from_vec(mut bytes: Vec<u8>) -> Result<Self, SecretVecLimitError> {
        if let Err(error) = Self::validate_len(bytes.len()) {
            sanitize_vec_capacity(&mut bytes);
            return Err(error);
        }
        Ok(Self {
            inner: SecretVec::from_vec(bytes),
        })
    }

    /// Convert an existing secret vector after validating its length.
    ///
    /// An oversized input is cleared before the error is returned.
    #[inline]
    pub fn from_secret_vec(mut secret: SecretVec) -> Result<Self, SecretVecLimitError> {
        if let Err(error) = Self::validate_len(secret.len()) {
            secret.clear_secret();
            return Err(error);
        }
        Ok(Self { inner: secret })
    }

    /// Maximum accepted length.
    #[must_use]
    #[inline]
    pub const fn max_len() -> usize {
        MAX
    }

    /// Number of initialized secret bytes.
    #[must_use]
    #[inline]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Returns true when no bytes are held.
    #[must_use]
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Run a closure with read-only access to the secret bytes.
    #[inline]
    pub fn with_secret<R>(&self, inspect: impl FnOnce(&[u8]) -> R) -> R {
        self.inner.with_secret(inspect)
    }

    /// Run a closure with mutable access to the initialized secret bytes.
    #[inline]
    pub fn with_secret_mut<R>(&mut self, edit: impl FnOnce(&mut [u8]) -> R) -> R {
        self.inner.with_secret_mut(edit)
    }

    /// Append bytes without permitting the configured limit to be exceeded.
    #[inline]
    pub fn extend_from_slice(&mut self, bytes: &[u8]) -> Result<(), SecretVecLimitError> {
        let actual = self.len().saturating_add(bytes.len());
        Self::validate_len(actual)?;
        self.inner.extend_from_slice(bytes);
        Ok(())
    }

    /// Replace the current value after validating the replacement length.
    #[inline]
    pub fn replace_from_slice(&mut self, bytes: &[u8]) -> Result<(), SecretVecLimitError> {
        Self::validate_len(bytes.len())?;
        self.inner.replace_from_slice(bytes);
        Ok(())
    }

    /// Clear this value immediately with volatile writes.
    #[inline(never)]
    pub fn clear_secret(&mut self) {
        self.inner.clear_secret();
    }

    /// Return the bounded value as an ordinary clear-on-drop secret vector.
    #[must_use]
    #[inline]
    pub fn into_secret_vec(self) -> SecretVec {
        self.inner
    }

    #[inline]
    fn validate_len(actual: usize) -> Result<(), SecretVecLimitError> {
        if actual > MAX {
            Err(SecretVecLimitError {
                maximum: MAX,
                actual,
            })
        } else {
            Ok(())
        }
    }
}

#[cfg(feature = "alloc")]
impl<const MAX: usize> Default for BoundedSecretVec<MAX> {
    #[inline]
    fn default() -> Self {
        Self::empty()
    }
}

#[cfg(feature = "alloc")]
impl<const MAX: usize> From<BoundedSecretVec<MAX>> for SecretVec {
    #[inline]
    fn from(secret: BoundedSecretVec<MAX>) -> Self {
        secret.into_secret_vec()
    }
}

#[cfg(feature = "alloc")]
impl<const MAX: usize> SecureSanitize for BoundedSecretVec<MAX> {
    #[inline]
    fn secure_sanitize(&mut self) {
        self.clear_secret();
    }
}

#[cfg(feature = "alloc")]
impl<const MAX: usize> fmt::Debug for BoundedSecretVec<MAX> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BoundedSecretVec")
            .field("len", &self.len())
            .field("max_len", &MAX)
            .field("contents", &"<redacted>")
            .finish()
    }
}

#[cfg(feature = "alloc")]
impl<const MAX: usize> ct::ConstantTimeEq for BoundedSecretVec<MAX> {
    #[inline]
    fn ct_eq(&self, other: &Self) -> ct::Choice {
        self.inner.ct_eq(&other.inner)
    }
}

/// Heap-allocated secret UTF-8 text with clear-on-drop behavior.
///
/// This type is available with the `alloc` feature. Use it for bearer tokens,
/// passphrases, and textual secrets that must cross APIs as UTF-8. Clearing
/// uses volatile writes over the full allocation capacity before the internal
/// byte vector length is set to zero.
#[cfg(feature = "alloc")]
pub struct SecretString {
    pub(crate) inner: Vec<u8>,
}

/// Default maximum accepted by serde deserialization into [`SecretString`].
///
/// The limit is measured in UTF-8 bytes, not Unicode scalar values. Use
/// [`BoundedSecretString<MAX>`] when a protocol requires a different maximum.
#[cfg(feature = "alloc")]
pub const DEFAULT_SECRET_STRING_SERDE_MAX_LEN: usize = 1024 * 1024;

#[cfg(feature = "alloc")]
impl SecretString {
    /// Wrap a string using volatile clearing on drop.
    #[must_use]
    #[inline]
    pub fn new(inner: String) -> Self {
        Self {
            inner: inner.into_bytes(),
        }
    }

    /// Wrap an existing string using volatile clearing on drop.
    ///
    /// This is an explicit ownership-taking alias for [`SecretString::new`].
    /// The string allocation is not copied; its full capacity will be
    /// volatile-cleared when this `SecretString` is cleared or dropped.
    #[must_use]
    #[inline]
    pub fn from_string(text: String) -> Self {
        Self::new(text)
    }

    /// Convert secret bytes into UTF-8 text without reallocating.
    ///
    /// UTF-8 is validated before the byte allocation is transferred. Invalid
    /// input is volatile-cleared before [`core::str::Utf8Error`] is returned; the rejected
    /// secret bytes are not returned to the caller.
    #[inline]
    pub fn from_secret_vec(mut secret: SecretVec) -> Result<Self, core::str::Utf8Error> {
        if let Err(error) = core::str::from_utf8(secret.inner.as_slice()) {
            secret.clear_secret();
            return Err(error);
        }

        Ok(Self {
            inner: core::mem::take(&mut secret.inner),
        })
    }

    /// Create an empty secret string.
    #[must_use]
    #[inline]
    pub const fn empty() -> Self {
        Self { inner: Vec::new() }
    }

    /// Create an empty secret string with at least the requested byte capacity.
    ///
    /// `capacity` must be trusted and bounded. Allocation failure may abort;
    /// use [`SecretString::try_with_capacity`] when it must be reported.
    #[must_use]
    #[inline]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            inner: Vec::with_capacity(capacity),
        }
    }

    /// Create an empty secret string using fallible byte allocation.
    ///
    /// Unlike [`SecretString::with_capacity`], this reports capacity overflow
    /// or allocation failure instead of panicking or invoking the allocation
    /// error handler.
    #[inline]
    pub fn try_with_capacity(capacity: usize) -> Result<Self, SecretAllocationError> {
        let mut inner = Vec::new();
        inner
            .try_reserve_exact(capacity)
            .map_err(SecretAllocationError::Allocation)?;
        Ok(Self { inner })
    }

    /// Create a secret string by copying from a string slice.
    ///
    /// The public byte length must be trusted and bounded. Use
    /// [`SecretString::try_from_secret_str_bounded`] at untrusted boundaries.
    #[must_use]
    #[inline]
    pub fn from_secret_str(text: &str) -> Self {
        Self {
            inner: Vec::from(text.as_bytes()),
        }
    }

    /// Copy UTF-8 text after enforcing a public byte-length ceiling and using
    /// fallible allocation.
    ///
    /// Length validation happens before allocation. The borrowed source is not
    /// cleared by this method.
    #[inline]
    pub fn try_from_secret_str_bounded(
        text: &str,
        maximum_bytes: usize,
    ) -> Result<Self, SecretAllocationError> {
        if text.len() > maximum_bytes {
            return Err(SecretAllocationError::TooLong {
                maximum: maximum_bytes,
                actual: text.len(),
            });
        }

        let mut secret = Self::try_with_capacity(text.len())?;
        secret.inner.extend_from_slice(text.as_bytes());
        Ok(secret)
    }

    /// Create a secret string by generating UTF-8 scalar values directly.
    ///
    /// `char_count` is the number of generated `char` values, not the final
    /// byte length. Each generated character is encoded into the secret heap
    /// allocation and the small stack encoding buffer is immediately cleared.
    /// `char_count` must be trusted and bounded; capacity overflow panics and
    /// allocation failure may abort.
    #[must_use]
    #[inline]
    pub fn from_chars(char_count: usize, mut make_char: impl FnMut(usize) -> char) -> Self {
        let capacity = char_count
            .checked_mul(MAX_UTF8_CHAR_BYTES)
            .expect("secret UTF-8 capacity calculation overflowed");
        let mut secret = Self::with_capacity(capacity);
        let mut index = 0;
        while index < char_count {
            secret.push_secret_char(make_char(index));
            index += 1;
        }
        secret
    }

    /// Create a secret string by fallibly generating UTF-8 scalar values
    /// directly.
    ///
    /// If `make_char` returns an error, any text generated before the error is
    /// cleared before the error is returned. This method reports both build
    /// failure through `SecretGenerateError::Build` and generator failure
    /// through `SecretGenerateError::Generate`. It does not enforce an
    /// application maximum; use [`SecretString::try_from_chars_bounded`] when
    /// needed.
    #[inline]
    pub fn try_from_chars<E>(
        char_count: usize,
        mut make_char: impl FnMut(usize) -> Result<char, E>,
    ) -> Result<Self, SecretGenerateError<E>> {
        let capacity =
            char_count
                .checked_mul(MAX_UTF8_CHAR_BYTES)
                .ok_or(SecretGenerateError::Build(
                    SecretAllocationError::CapacityOverflow,
                ))?;
        let mut secret = Self::try_with_capacity(capacity).map_err(SecretGenerateError::Build)?;
        let mut index = 0;
        while index < char_count {
            let character = make_char(index).map_err(SecretGenerateError::Generate)?;
            secret.push_secret_char(character);
            index += 1;
        }
        Ok(secret)
    }

    /// Create secret UTF-8 text with a caller-enforced byte-capacity ceiling.
    ///
    /// The worst-case UTF-8 byte capacity is calculated with checked arithmetic
    /// and compared with `maximum_bytes` before allocation or generator
    /// execution.
    #[inline]
    pub fn try_from_chars_bounded<E>(
        char_count: usize,
        maximum_bytes: usize,
        make_char: impl FnMut(usize) -> Result<char, E>,
    ) -> Result<Self, SecretGenerateError<E>> {
        let capacity =
            char_count
                .checked_mul(MAX_UTF8_CHAR_BYTES)
                .ok_or(SecretGenerateError::Build(
                    SecretAllocationError::CapacityOverflow,
                ))?;
        if capacity > maximum_bytes {
            return Err(SecretGenerateError::Build(SecretAllocationError::TooLong {
                maximum: maximum_bytes,
                actual: capacity,
            }));
        }
        Self::try_from_chars(char_count, make_char)
    }

    /// Number of bytes currently held.
    #[must_use]
    #[inline]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Returns true when no text is held.
    #[must_use]
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Current allocation capacity in bytes.
    #[must_use]
    #[inline]
    pub fn capacity(&self) -> usize {
        self.inner.capacity()
    }

    /// Run a closure with read-only access to the secret text.
    ///
    /// The result is fallible because the text is stored internally as bytes to
    /// keep clearing safe without `String::as_mut_vec`.
    #[inline]
    pub fn try_with_secret<R>(
        &self,
        inspect: impl FnOnce(&str) -> R,
    ) -> Result<R, core::str::Utf8Error> {
        core::str::from_utf8(self.inner.as_slice()).map(inspect)
    }

    /// Run a closure with mutable access to the secret text.
    ///
    /// The result is fallible because the text is stored internally as bytes to
    /// keep clearing safe without `String::as_mut_vec`. The closure receives
    /// `&mut str`, so safe Rust cannot invalidate UTF-8.
    #[inline]
    pub fn try_with_secret_mut<R>(
        &mut self,
        edit: impl FnOnce(&mut str) -> R,
    ) -> Result<R, core::str::Utf8Error> {
        core::str::from_utf8_mut(self.inner.as_mut_slice()).map(edit)
    }

    /// Run a closure with read-only access to the secret bytes.
    #[inline]
    pub fn with_secret_bytes<R>(&self, inspect: impl FnOnce(&[u8]) -> R) -> R {
        inspect(self.inner.as_slice())
    }

    /// Append text to the secret string.
    ///
    /// If capacity must grow, the previous allocation is wiped before it is
    /// dropped. Prefer constructing with enough capacity in callers that append
    /// repeatedly.
    #[inline]
    pub fn push_str(&mut self, text: &str) {
        self.grow_for(text.len());
        self.inner.extend_from_slice(text.as_bytes());
    }

    /// Replace all text with a new string slice.
    ///
    /// If capacity must grow, the old allocation is wiped before it is dropped
    /// and the old secret bytes are not copied into the replacement allocation.
    #[inline]
    pub fn replace_from_secret_str(&mut self, text: &str) {
        if text.len() > self.inner.capacity() {
            let new_capacity = next_secret_capacity(self.inner.capacity(), text.len());
            let mut replacement = Vec::with_capacity(new_capacity);
            replacement.extend_from_slice(text.as_bytes());
            self.clear_secret();
            self.inner = replacement;
            return;
        }

        self.clear_secret();
        self.inner.extend_from_slice(text.as_bytes());
    }

    /// Replace all text by taking ownership of an existing string.
    ///
    /// The old allocation is cleared before the provided string allocation
    /// becomes the secret storage. The provided string is not copied; its full
    /// capacity will be volatile-cleared when this `SecretString` is later
    /// cleared or dropped.
    #[inline]
    pub fn replace_from_string(&mut self, text: String) {
        let replacement = text.into_bytes();
        self.clear_secret();
        self.inner = replacement;
    }

    /// Replace all text with generated UTF-8 scalar values.
    ///
    /// The replacement text is generated into a fresh clear-on-drop allocation
    /// before the old value is cleared and replaced. If `make_char` panics, the
    /// old value remains unchanged and partial generated text is cleared during
    /// unwinding.
    #[inline]
    pub fn replace_from_chars(&mut self, char_count: usize, make_char: impl FnMut(usize) -> char) {
        let mut replacement = Self::from_chars(char_count, make_char);
        self.clear_secret();
        core::mem::swap(&mut self.inner, &mut replacement.inner);
    }

    /// Replace all text with fallibly generated UTF-8 scalar values.
    ///
    /// The replacement text is generated into a fresh clear-on-drop allocation
    /// before the old value is cleared and replaced. If `make_char` returns an
    /// error, the old value remains unchanged and partial generated text is
    /// cleared before the error is returned.
    #[inline]
    pub fn try_replace_from_chars<E>(
        &mut self,
        char_count: usize,
        make_char: impl FnMut(usize) -> Result<char, E>,
    ) -> Result<(), SecretGenerateError<E>> {
        let mut replacement = Self::try_from_chars(char_count, make_char)?;
        self.clear_secret();
        core::mem::swap(&mut self.inner, &mut replacement.inner);
        Ok(())
    }

    /// Clear this value immediately with volatile writes.
    #[inline(never)]
    pub fn clear_secret(&mut self) {
        sanitize_vec_capacity(&mut self.inner);
    }

    /// Clear this value immediately with an explicit three-pass volatile
    /// pattern over the full allocation capacity.
    ///
    /// Available with the `multi-pass-clear` feature. This is intended for
    /// policy or audit compatibility; for volatile RAM, the default
    /// [`SecretString::clear_secret`] remains the normal security boundary.
    #[cfg(feature = "multi-pass-clear")]
    #[inline(never)]
    pub fn clear_secret_multi_pass(&mut self) {
        sanitize_vec_capacity_multi_pass(&mut self.inner);
    }

    /// Clear this value immediately with volatile writes, then flush the cache
    /// lines covering the heap allocation.
    #[cfg(feature = "cache-flush")]
    #[inline(never)]
    pub fn clear_secret_and_flush(
        &mut self,
    ) -> Result<crate::cache_flush::CacheFlushReport, crate::cache_flush::CacheFlushError> {
        crate::cache_flush::cache_flush_sanitize_vec(&mut self.inner)
    }

    /// Compare against UTF-8 text without early exit for equal-length inputs.
    ///
    /// Length mismatch returns immediately because the provided string length
    /// is treated as public metadata.
    ///
    /// The portable fallback is intended to avoid data-dependent early exit, but
    /// it is not a formal hardware-level constant-time guarantee. On x86_64,
    /// enable `asm-compare` for a stronger compiler boundary. Use a dedicated
    /// constant-time comparison crate if your protocol requires externally
    /// audited timing guarantees.
    #[must_use]
    #[inline]
    pub fn constant_time_eq(&self, other: &str) -> bool {
        constant_time_eq_slices(self.inner.as_slice(), other.as_bytes())
    }

    /// Consume the wrapper after first clearing the wrapped string.
    #[inline]
    pub fn into_cleared(mut self) {
        self.clear_secret();
    }

    /// Convert this UTF-8 text into secret bytes without reallocating.
    #[must_use]
    #[inline]
    pub fn into_secret_vec(mut self) -> SecretVec {
        SecretVec::from_vec(core::mem::take(&mut self.inner))
    }

    fn grow_for(&mut self, additional: usize) {
        let required = self.inner.len().saturating_add(additional);
        if required <= self.inner.capacity() {
            return;
        }

        let new_capacity = next_secret_capacity(self.inner.capacity(), required);
        let mut replacement = Vec::with_capacity(new_capacity);
        replacement.extend_from_slice(self.inner.as_slice());
        self.clear_secret();
        self.inner = replacement;
    }

    fn push_secret_char(&mut self, character: char) {
        let mut encoded = [0; 4];
        let text = character.encode_utf8(&mut encoded);
        self.inner.extend_from_slice(text.as_bytes());
        wipe::bytes(&mut encoded);
    }
}

#[cfg(feature = "alloc")]
impl Drop for SecretString {
    #[inline]
    fn drop(&mut self) {
        self.clear_secret();
    }
}

#[cfg(feature = "alloc")]
impl Default for SecretString {
    #[inline]
    fn default() -> Self {
        Self::empty()
    }
}

#[cfg(feature = "alloc")]
impl SecureSanitize for SecretString {
    #[inline]
    fn secure_sanitize(&mut self) {
        self.clear_secret();
    }
}

#[cfg(feature = "alloc")]
impl fmt::Debug for SecretString {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretString")
            .field("len", &self.inner.len())
            .field("contents", &"<redacted>")
            .finish()
    }
}

#[cfg(feature = "alloc")]
impl ct::ConstantTimeEq for SecretString {
    #[inline]
    fn ct_eq(&self, other: &Self) -> ct::Choice {
        ct::eq_public_len(self.inner.as_slice(), other.inner.as_slice())
    }
}

#[cfg(feature = "alloc")]
impl ct::ConstantTimeEq<str> for SecretString {
    #[inline]
    fn ct_eq(&self, other: &str) -> ct::Choice {
        ct::eq_public_len(self.inner.as_slice(), other.as_bytes())
    }
}

#[cfg(feature = "alloc")]
impl TryFrom<SecretVec> for SecretString {
    type Error = core::str::Utf8Error;

    #[inline]
    fn try_from(secret: SecretVec) -> Result<Self, Self::Error> {
        Self::from_secret_vec(secret)
    }
}

#[cfg(feature = "alloc")]
impl From<SecretString> for SecretVec {
    #[inline]
    fn from(secret: SecretString) -> Self {
        secret.into_secret_vec()
    }
}

/// Error returned when secret UTF-8 text exceeds its declared public limit.
#[cfg(feature = "alloc")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SecretStringLimitError {
    /// Maximum accepted UTF-8 byte length.
    pub maximum: usize,
    /// UTF-8 byte length that was rejected.
    pub actual: usize,
}

#[cfg(feature = "alloc")]
impl fmt::Display for SecretStringLimitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "secret text length exceeds limit: maximum {} UTF-8 bytes, got {} bytes",
            self.maximum, self.actual
        )
    }
}

#[cfg(feature = "std")]
impl std::error::Error for SecretStringLimitError {}

/// Heap-allocated secret UTF-8 text constrained to a public byte limit.
///
/// The limit is measured after UTF-8 encoding. This type is intended for
/// configuration and protocol boundaries where unbounded textual secret
/// allocation is unacceptable. Rejected owned strings and secret containers
/// are volatile-cleared before the error is returned.
#[cfg(feature = "alloc")]
pub struct BoundedSecretString<const MAX: usize> {
    pub(crate) inner: SecretString,
}

#[cfg(feature = "alloc")]
impl<const MAX: usize> BoundedSecretString<MAX> {
    /// Create an empty bounded secret string.
    #[must_use]
    #[inline]
    pub const fn empty() -> Self {
        Self {
            inner: SecretString::empty(),
        }
    }

    /// Copy UTF-8 text into bounded secret storage.
    #[inline]
    pub fn from_secret_str(text: &str) -> Result<Self, SecretStringLimitError> {
        Self::validate_len(text.len())?;
        Ok(Self {
            inner: SecretString::from_secret_str(text),
        })
    }

    /// Take ownership of a string after validating its UTF-8 byte length.
    ///
    /// An oversized input allocation is volatile-cleared before the error is
    /// returned.
    #[inline]
    pub fn from_string(mut text: String) -> Result<Self, SecretStringLimitError> {
        if let Err(error) = Self::validate_len(text.len()) {
            text.secure_sanitize();
            return Err(error);
        }
        Ok(Self {
            inner: SecretString::from_string(text),
        })
    }

    /// Convert an existing secret string after validating its byte length.
    ///
    /// An oversized input is cleared before the error is returned.
    #[inline]
    pub fn from_secret_string(mut secret: SecretString) -> Result<Self, SecretStringLimitError> {
        if let Err(error) = Self::validate_len(secret.len()) {
            secret.clear_secret();
            return Err(error);
        }
        Ok(Self { inner: secret })
    }

    /// Convert secret bytes without reallocating after UTF-8 and length checks.
    ///
    /// Invalid UTF-8 is cleared by [`SecretString::from_secret_vec`]. Valid but
    /// oversized text is cleared before the limit error is returned.
    #[inline]
    pub fn from_secret_vec(secret: SecretVec) -> Result<Self, BoundedSecretStringError> {
        let text = SecretString::from_secret_vec(secret).map_err(BoundedSecretStringError::Utf8)?;
        Self::from_secret_string(text).map_err(BoundedSecretStringError::Limit)
    }

    /// Maximum accepted UTF-8 byte length.
    #[must_use]
    #[inline]
    pub const fn max_len() -> usize {
        MAX
    }

    /// Number of initialized UTF-8 bytes.
    #[must_use]
    #[inline]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Returns true when no text is held.
    #[must_use]
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Current allocation capacity in bytes.
    #[must_use]
    #[inline]
    pub fn capacity(&self) -> usize {
        self.inner.capacity()
    }

    /// Run a closure with read-only access to the secret text.
    #[inline]
    pub fn try_with_secret<R>(
        &self,
        inspect: impl FnOnce(&str) -> R,
    ) -> Result<R, core::str::Utf8Error> {
        self.inner.try_with_secret(inspect)
    }

    /// Run a closure with mutable access to the secret text.
    #[inline]
    pub fn try_with_secret_mut<R>(
        &mut self,
        edit: impl FnOnce(&mut str) -> R,
    ) -> Result<R, core::str::Utf8Error> {
        self.inner.try_with_secret_mut(edit)
    }

    /// Append text without permitting the configured byte limit to be exceeded.
    #[inline]
    pub fn push_str(&mut self, text: &str) -> Result<(), SecretStringLimitError> {
        Self::validate_len(self.len().saturating_add(text.len()))?;
        self.inner.push_str(text);
        Ok(())
    }

    /// Replace the current value after validating the replacement byte length.
    #[inline]
    pub fn replace_from_secret_str(&mut self, text: &str) -> Result<(), SecretStringLimitError> {
        Self::validate_len(text.len())?;
        self.inner.replace_from_secret_str(text);
        Ok(())
    }

    /// Replace the current value by taking ownership of a bounded string.
    ///
    /// Oversized input is cleared before the error is returned. On success the
    /// provided allocation becomes the secret storage without copying.
    #[inline]
    pub fn replace_from_string(&mut self, text: String) -> Result<(), SecretStringLimitError> {
        let mut replacement = Self::from_string(text)?;
        self.clear_secret();
        core::mem::swap(&mut self.inner, &mut replacement.inner);
        Ok(())
    }

    /// Clear this value immediately with volatile writes.
    #[inline(never)]
    pub fn clear_secret(&mut self) {
        self.inner.clear_secret();
    }

    /// Compare against UTF-8 text without early exit for equal-length inputs.
    #[must_use]
    #[inline]
    pub fn constant_time_eq(&self, other: &str) -> bool {
        self.inner.constant_time_eq(other)
    }

    /// Return the bounded value as an ordinary clear-on-drop secret string.
    #[must_use]
    #[inline]
    pub fn into_secret_string(self) -> SecretString {
        self.inner
    }

    /// Return the bounded value as secret bytes without reallocating.
    #[must_use]
    #[inline]
    pub fn into_secret_vec(self) -> SecretVec {
        self.inner.into_secret_vec()
    }

    #[inline]
    fn validate_len(actual: usize) -> Result<(), SecretStringLimitError> {
        if actual > MAX {
            Err(SecretStringLimitError {
                maximum: MAX,
                actual,
            })
        } else {
            Ok(())
        }
    }
}

/// Error returned while converting bounded secret bytes into UTF-8 text.
#[cfg(feature = "alloc")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BoundedSecretStringError {
    /// The secret bytes were not valid UTF-8.
    Utf8(core::str::Utf8Error),
    /// The valid UTF-8 text exceeded the declared public limit.
    Limit(SecretStringLimitError),
}

#[cfg(feature = "alloc")]
impl fmt::Display for BoundedSecretStringError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Utf8(error) => error.fmt(formatter),
            Self::Limit(error) => error.fmt(formatter),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for BoundedSecretStringError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Utf8(error) => Some(error),
            Self::Limit(error) => Some(error),
        }
    }
}

#[cfg(feature = "alloc")]
impl<const MAX: usize> Default for BoundedSecretString<MAX> {
    #[inline]
    fn default() -> Self {
        Self::empty()
    }
}

#[cfg(feature = "alloc")]
impl<const MAX: usize> SecureSanitize for BoundedSecretString<MAX> {
    #[inline]
    fn secure_sanitize(&mut self) {
        self.clear_secret();
    }
}

#[cfg(feature = "alloc")]
impl<const MAX: usize> fmt::Debug for BoundedSecretString<MAX> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BoundedSecretString")
            .field("len", &self.len())
            .field("max_len", &MAX)
            .field("contents", &"<redacted>")
            .finish()
    }
}

#[cfg(feature = "alloc")]
impl<const MAX: usize> ct::ConstantTimeEq for BoundedSecretString<MAX> {
    #[inline]
    fn ct_eq(&self, other: &Self) -> ct::Choice {
        self.inner.ct_eq(&other.inner)
    }
}

#[cfg(feature = "alloc")]
impl<const MAX: usize> ct::ConstantTimeEq<str> for BoundedSecretString<MAX> {
    #[inline]
    fn ct_eq(&self, other: &str) -> ct::Choice {
        self.inner.ct_eq(other)
    }
}

#[cfg(feature = "alloc")]
impl<const MAX: usize> From<BoundedSecretString<MAX>> for SecretString {
    #[inline]
    fn from(secret: BoundedSecretString<MAX>) -> Self {
        secret.into_secret_string()
    }
}

#[cfg(feature = "alloc")]
impl<const MAX: usize> TryFrom<SecretString> for BoundedSecretString<MAX> {
    type Error = SecretStringLimitError;

    #[inline]
    fn try_from(secret: SecretString) -> Result<Self, Self::Error> {
        Self::from_secret_string(secret)
    }
}

#[cfg(feature = "alloc")]
impl<const MAX: usize> TryFrom<SecretVec> for BoundedSecretString<MAX> {
    type Error = BoundedSecretStringError;

    #[inline]
    fn try_from(secret: SecretVec) -> Result<Self, Self::Error> {
        Self::from_secret_vec(secret)
    }
}

/// Clear-on-drop wrapper for non-byte secret types.
///
/// This is useful for structs that implement [`SecureSanitize`] by clearing
/// their sensitive fields. Like [`SecretBytes`], this wrapper intentionally does
/// not implement `Clone`, `Copy`, or secret-printing `Debug`.
///
/// # Clearing Strength
///
/// When `T = [u8; N]`, this wrapper clears through [`SecureSanitize`] for byte
/// arrays, which uses the same volatile byte clearing primitive as the rest of
/// the crate. For fixed-size byte secrets, still prefer [`SecretBytes<N>`],
/// which avoids implementing `Clone`, `Copy`, `Deref`, `AsRef<[u8]>`, or
/// secret-printing `Debug`.
///
/// Scalar values such as `u64`, arrays of sanitizable values, `Option<T>`, and
/// `Result<T, E>` implement [`SecureSanitize`] directly. With `alloc`, `Box<T>`,
/// `Vec<T>`, and `String` are supported as well. Construction, drop clearing,
/// and [`Secret::into_cleared`] remain available for all of them.
///
/// For byte vectors, prefer [`SecretVec`] over `Secret<Vec<u8>>`. `Vec<T>` is
/// supported for generic sanitizable containers and clears the raw allocation
/// capacity after dropping live elements, but generic exposure is intentionally
/// unavailable because `Vec<T>` does not implement the storage-stability
/// contracts. [`SecretVec`] provides reviewed scoped access and rotation that
/// clears old allocations before release.
pub struct Secret<T: SecureSanitize> {
    inner: T,
}

impl<T: SecureSanitize> Secret<T> {
    /// Wrap a sanitizable value.
    #[must_use]
    #[inline]
    pub const fn new(inner: T) -> Self {
        Self { inner }
    }

    /// Consume the wrapper after first clearing the wrapped value.
    #[inline]
    pub fn into_cleared(mut self) {
        self.inner.secure_sanitize();
    }
}

impl<T: StableSharedSecretStorage> Secret<T> {
    /// Run a closure with shared access to storage certified as shared-stable.
    ///
    /// This method is unavailable for types such as `Vec<T>`, `String`, and
    /// interior-mutable reallocating containers. Use a dedicated secret
    /// container or implement [`StableSharedSecretStorage`] after reviewing
    /// the type's complete safe shared API.
    ///
    /// The returned value cannot borrow the wrapped secret:
    ///
    /// ```compile_fail
    /// use sanitization::Secret;
    ///
    /// let secret = Secret::new([1_u8, 2, 3, 4]);
    /// let escaped = secret.with_secret(|bytes| bytes);
    /// let _ = escaped;
    /// ```
    #[inline]
    pub fn with_secret<R>(&self, inspect: impl FnOnce(&T) -> R) -> R {
        inspect(&self.inner)
    }
}

impl<T: StableMutableSecretStorage> Secret<T> {
    /// Run a closure with mutable access to storage certified as mutable-stable.
    ///
    /// This method is unavailable for generic growable or reallocating
    /// containers. Prefer [`SecretVec`], [`SecretString`], their bounded
    /// variants, or a reviewed fixed-storage type carrying
    /// [`StableMutableSecretStorage`].
    #[inline]
    pub fn with_secret_mut<R>(&mut self, edit: impl FnOnce(&mut T) -> R) -> R {
        edit(&mut self.inner)
    }
}

impl<T: SecureSanitize> SecureSanitize for Secret<T> {
    #[inline]
    fn secure_sanitize(&mut self) {
        self.inner.secure_sanitize();
    }
}

impl<T: StableSharedSecretStorage> StableSharedSecretStorage for Secret<T> {}
impl<T: StableMutableSecretStorage> StableMutableSecretStorage for Secret<T> {}

impl<T: SecureSanitize> Drop for Secret<T> {
    #[inline]
    fn drop(&mut self) {
        self.secure_sanitize();
    }
}

impl<T: SecureSanitize + Default> Default for Secret<T> {
    #[inline]
    fn default() -> Self {
        Self::new(T::default())
    }
}

impl<T: SecureSanitize> fmt::Debug for Secret<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Secret")
            .field("contents", &"<redacted>")
            .finish()
    }
}

/// Clear-on-drop secret gated by an application-controlled storage allow-list.
///
/// Unlike [`Secret<T>`], construction and exposure require a policy type that
/// implements [`SecretStoragePolicy<T>`] for the exact wrapped type. This lets
/// a high-assurance application centralize accepted storage types and prevents
/// a dependency's unrelated storage-marker implementation from automatically
/// entering that accepted set.
///
/// The policy is defense in depth. Shared and mutable access still require
/// [`StableSharedSecretStorage`] and [`StableMutableSecretStorage`]
/// respectively. An incorrect policy or storage-contract implementation can
/// invalidate the clearing guarantee, but cannot be relied on for Rust memory
/// safety.
///
/// There is intentionally no field-only derive for storage stability. A proc
/// macro cannot inspect later inherent methods, trait implementations,
/// interior mutation, returned guards, callbacks, or deferred cleanup.
///
/// An unapproved type cannot be constructed under a policy:
///
/// ```compile_fail
/// use sanitization::{
///     define_secret_storage_policy, AllowlistedSecret, SecretBytes,
/// };
///
/// define_secret_storage_policy! {
///     DeploymentStoragePolicy {
///         SecretBytes<32> => "reviewed fixed key storage",
///     }
/// }
///
/// let _ = AllowlistedSecret::<SecretBytes<16>, DeploymentStoragePolicy>::new(
///     SecretBytes::from_array([0; 16]),
/// );
/// ```
pub struct AllowlistedSecret<T: SecureSanitize, P> {
    inner: T,
    policy: PhantomData<fn() -> P>,
}

impl<T, P> AllowlistedSecret<T, P>
where
    T: SecureSanitize,
    P: SecretStoragePolicy<T>,
{
    /// Wrap a value approved by `P`.
    #[must_use]
    #[inline]
    pub const fn new(inner: T) -> Self {
        Self {
            inner,
            policy: PhantomData,
        }
    }

    /// Return the policy's review rationale for this exact storage type.
    #[must_use]
    #[inline]
    pub const fn policy_rationale() -> &'static str {
        P::RATIONALE
    }

    /// Consume the wrapper after first clearing the wrapped value.
    #[inline]
    pub fn into_cleared(mut self) {
        self.inner.secure_sanitize();
    }
}

impl<T, P> AllowlistedSecret<T, P>
where
    T: StableSharedSecretStorage,
    P: SecretStoragePolicy<T>,
{
    /// Run a closure with policy-approved shared-stable storage.
    #[inline]
    pub fn with_secret<R>(&self, inspect: impl FnOnce(&T) -> R) -> R {
        inspect(&self.inner)
    }
}

impl<T, P> AllowlistedSecret<T, P>
where
    T: StableMutableSecretStorage,
    P: SecretStoragePolicy<T>,
{
    /// Run a closure with policy-approved mutable-stable storage.
    #[inline]
    pub fn with_secret_mut<R>(&mut self, edit: impl FnOnce(&mut T) -> R) -> R {
        edit(&mut self.inner)
    }
}

impl<T: SecureSanitize, P> SecureSanitize for AllowlistedSecret<T, P> {
    #[inline]
    fn secure_sanitize(&mut self) {
        self.inner.secure_sanitize();
    }
}

impl<T, P> StableSharedSecretStorage for AllowlistedSecret<T, P>
where
    T: StableSharedSecretStorage,
    P: SecretStoragePolicy<T>,
{
}

impl<T, P> StableMutableSecretStorage for AllowlistedSecret<T, P>
where
    T: StableMutableSecretStorage,
    P: SecretStoragePolicy<T>,
{
}

impl<T: SecureSanitize, P> Drop for AllowlistedSecret<T, P> {
    #[inline]
    fn drop(&mut self) {
        self.secure_sanitize();
    }
}

impl<T, P> Default for AllowlistedSecret<T, P>
where
    T: SecureSanitize + Default,
    P: SecretStoragePolicy<T>,
{
    #[inline]
    fn default() -> Self {
        Self::new(T::default())
    }
}

impl<T: SecureSanitize, P> fmt::Debug for AllowlistedSecret<T, P> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AllowlistedSecret")
            .field("contents", &"<redacted>")
            .finish()
    }
}

#[allow(unsafe_code)]
mod consume_once {
    use super::{fmt, SecureSanitize, StableMutableSecretStorage, StableSharedSecretStorage};
    use core::{
        cell::UnsafeCell,
        sync::atomic::{AtomicBool, Ordering},
    };

    /// Error returned after a [`ConsumeOnceSecret`] has already been claimed.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct AlreadyConsumedError;

    impl fmt::Display for AlreadyConsumedError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("consume-once secret already claimed")
        }
    }

    #[cfg(feature = "std")]
    impl std::error::Error for AlreadyConsumedError {}

    /// Clear-on-drop wrapper that permits one scoped secret exposure.
    ///
    /// `ConsumeOnceSecret<T>` uses an atomic claim flag, so exactly one caller
    /// may enter [`ConsumeOnceSecret::consume`], including when multiple shared
    /// references race. The winning closure receives `&T`; ownership of `T` is
    /// not moved out through this API. A cleanup guard clears the wrapped value
    /// after that closure returns or unwinds, even when another owner keeps the
    /// wrapper alive. `Drop` clears a value that is never consumed.
    ///
    /// The successful closure can still deliberately copy or export data it
    /// reads. Rust moves and compiler-generated register copies remain outside
    /// the memory-sanitization guarantee.
    pub struct ConsumeOnceSecret<T: SecureSanitize> {
        inner: UnsafeCell<T>,
        claimed: AtomicBool,
    }

    struct ClearOnExit<'a, T: SecureSanitize> {
        owner: &'a ConsumeOnceSecret<T>,
    }

    impl<T: SecureSanitize> Drop for ClearOnExit<'_, T> {
        #[inline]
        fn drop(&mut self) {
            self.owner.clear_inner();
        }
    }

    // SAFETY: Moving the wrapper to another thread transfers ownership of the
    // inner value and atomic flag. Access to the inner value is still mediated
    // by the claim flag.
    unsafe impl<T: SecureSanitize + Send> Send for ConsumeOnceSecret<T> {}

    // SAFETY: Shared references may race to consume the value, but the atomic
    // swap permits exactly one successful accessor. That accessor has exclusive
    // logical access until its cleanup guard clears the inner value before
    // returning or while unwinding.
    unsafe impl<T: SecureSanitize + Send> Sync for ConsumeOnceSecret<T> {}

    impl<T: SecureSanitize> ConsumeOnceSecret<T> {
        /// Wrap a sanitizable value for one-time consumption.
        #[must_use]
        #[inline]
        pub const fn new(inner: T) -> Self {
            Self {
                inner: UnsafeCell::new(inner),
                claimed: AtomicBool::new(false),
            }
        }

        /// Consume the wrapper after first clearing the wrapped value.
        #[inline]
        pub fn into_cleared(mut self) {
            self.claimed.store(true, Ordering::Release);
            self.inner.get_mut().secure_sanitize();
        }

        /// Returns true after an accessor claims the value, after manual
        /// sanitization, or after [`ConsumeOnceSecret::into_cleared`].
        ///
        /// A `true` result means later access is rejected. It does not
        /// distinguish an accessor that is still running from one whose cleanup
        /// guard has already cleared the value.
        #[must_use]
        #[inline]
        pub fn is_claimed(&self) -> bool {
            self.claimed.load(Ordering::Acquire)
        }

        #[inline]
        fn claim(&self) -> Result<ClearOnExit<'_, T>, AlreadyConsumedError> {
            if self.claimed.swap(true, Ordering::AcqRel) {
                Err(AlreadyConsumedError)
            } else {
                Ok(ClearOnExit { owner: self })
            }
        }

        #[inline]
        fn clear_inner(&self) {
            // SAFETY: `clear_inner` is called only by the unique successful
            // claimant's cleanup guard. The closure frame and its inner borrow
            // have ended before the guard runs, including during unwinding.
            unsafe { (&mut *self.inner.get()).secure_sanitize() };
        }
    }

    impl<T: StableSharedSecretStorage> ConsumeOnceSecret<T> {
        /// Run a closure with shared access exactly once, then clear the
        /// wrapped value.
        ///
        /// The first caller atomically claims the value. Every later caller
        /// receives [`AlreadyConsumedError`]. The closure's return value may
        /// report success or failure; either way, a private cleanup guard clears
        /// the wrapped value before this method returns. The same guard runs
        /// during panic unwinding.
        ///
        /// Requiring [`StableSharedSecretStorage`] prevents safe methods reached
        /// through `&T` from silently releasing uncleared secret storage.
        /// Caller code can still deliberately copy, log, or export bytes.
        /// Process abort prevents the cleanup guard from running.
        ///
        /// ```compile_fail
        /// use sanitization::{ConsumeOnceSecret, SecureSanitize};
        ///
        /// struct Unreviewed(Vec<u8>);
        ///
        /// impl SecureSanitize for Unreviewed {
        ///     fn secure_sanitize(&mut self) {
        ///         self.0.secure_sanitize();
        ///     }
        /// }
        ///
        /// let secret = ConsumeOnceSecret::new(Unreviewed(vec![1, 2, 3]));
        /// // Rejected until `Unreviewed` explicitly satisfies the shared
        /// // storage-stability contract.
        /// let _ = secret.consume(|value| value.0.len());
        /// ```
        #[inline]
        pub fn consume<R>(&self, inspect: impl FnOnce(&T) -> R) -> Result<R, AlreadyConsumedError> {
            let clear_guard = self.claim()?;
            // SAFETY: `claim` permits exactly one successful accessor. No other
            // safe method can access `inner` after the claim flag is set.
            let result = inspect(unsafe { &*self.inner.get() });
            drop(clear_guard);
            Ok(result)
        }
    }

    impl<T: SecureSanitize> Drop for ConsumeOnceSecret<T> {
        #[inline]
        fn drop(&mut self) {
            self.inner.get_mut().secure_sanitize();
        }
    }

    impl<T: SecureSanitize + Default> Default for ConsumeOnceSecret<T> {
        #[inline]
        fn default() -> Self {
            Self::new(T::default())
        }
    }

    impl<T: SecureSanitize> SecureSanitize for ConsumeOnceSecret<T> {
        #[inline]
        fn secure_sanitize(&mut self) {
            self.claimed.store(true, Ordering::Release);
            self.inner.get_mut().secure_sanitize();
        }
    }

    impl<T: StableSharedSecretStorage> StableSharedSecretStorage for ConsumeOnceSecret<T> {}
    impl<T: StableMutableSecretStorage> StableMutableSecretStorage for ConsumeOnceSecret<T> {}

    impl<T: SecureSanitize> fmt::Debug for ConsumeOnceSecret<T> {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter
                .debug_struct("ConsumeOnceSecret")
                .field("contents", &"<redacted>")
                .finish()
        }
    }
}

pub use consume_once::{AlreadyConsumedError, ConsumeOnceSecret};
