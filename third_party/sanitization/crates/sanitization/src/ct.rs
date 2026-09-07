//! Data-oblivious primitives for secret-handling code.
//!
//! APIs here are designed to avoid secret-dependent control flow and
//! secret-dependent memory access under documented compiler, target, feature,
//! and release-profile conditions. This is not a claim of identical wall-clock
//! timing on every target.

use core::{cmp::Ordering, fmt, hint::black_box, marker::PhantomData, ops};

use crate::SecureSanitize;

/// Opaque normalized 0/1 value used by data-oblivious operations.
///
/// `Choice` is for secret-derived booleans that should remain branchless while
/// they are combined, selected on, or carried through public-backing
/// [`PublicCtOption`]/[`PublicCtResult`] and secret-backing
/// [`SecretCtOption`]/[`SecretCtResult`] state. Turning a `Choice` into a
/// normal `bool` is declassification and should happen only through
/// [`Choice::declassify`].
#[repr(transparent)]
#[derive(Clone, Copy, Default)]
pub struct Choice(u8);

impl Choice {
    /// Public false choice.
    pub const FALSE: Self = Self(0);

    /// Public true choice.
    pub const TRUE: Self = Self(1);

    /// Normalize any non-zero byte into `1` and zero into `0`.
    #[inline]
    pub const fn from_u8(value: u8) -> Self {
        Self(((value | value.wrapping_neg()) >> 7) & 1)
    }

    /// Convert a public boolean into a `Choice`.
    ///
    /// This is safe for public control values. Do not use normal `bool`
    /// values for secret-derived decisions before they have been explicitly
    /// declassified.
    #[inline]
    pub const fn from_public_bool(value: bool) -> Self {
        Self(value as u8)
    }

    /// Explicitly convert this choice into a public normalized byte.
    ///
    /// The `reason` string is intentionally required so security reviews can
    /// search for every raw-bit declassification boundary. Most callers
    /// should prefer [`Choice::declassify`].
    #[inline]
    pub fn declassify_u8(self, reason: &'static str) -> u8 {
        black_box(reason);
        self.bit()
    }

    /// Explicitly convert this choice into a public boolean.
    ///
    /// The `reason` string is intentionally required so security reviews
    /// can search for every declassification boundary and check that the
    /// branch result is meant to be public, such as an authentication
    /// accept/reject decision.
    #[inline]
    pub fn declassify(self, reason: &'static str) -> bool {
        black_box(reason);
        self.bit() == 1
    }

    /// Branchless logical AND.
    #[inline]
    pub fn and(self, other: Self) -> Self {
        Self((self.bit() & other.bit()) & 1)
    }

    /// Branchless logical OR.
    #[inline]
    pub fn or(self, other: Self) -> Self {
        Self((self.bit() | other.bit()) & 1)
    }

    /// Branchless logical XOR.
    #[inline]
    pub fn xor(self, other: Self) -> Self {
        Self((self.bit() ^ other.bit()) & 1)
    }

    /// Branchless logical NOT.
    #[inline]
    pub fn not_choice(self) -> Self {
        Self(self.bit() ^ 1)
    }

    #[inline]
    fn bit(self) -> u8 {
        black_box(self.0 & 1)
    }
}

impl fmt::Debug for Choice {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Choice(..)")
    }
}

impl From<u8> for Choice {
    #[inline]
    fn from(value: u8) -> Self {
        Self::from_u8(value)
    }
}

impl ops::BitAnd for Choice {
    type Output = Self;

    #[inline]
    fn bitand(self, rhs: Self) -> Self::Output {
        self.and(rhs)
    }
}

impl ops::BitOr for Choice {
    type Output = Self;

    #[inline]
    fn bitor(self, rhs: Self) -> Self::Output {
        self.or(rhs)
    }
}

impl ops::BitXor for Choice {
    type Output = Self;

    #[inline]
    fn bitxor(self, rhs: Self) -> Self::Output {
        self.xor(rhs)
    }
}

impl ops::Not for Choice {
    type Output = Self;

    #[inline]
    fn not(self) -> Self::Output {
        self.not_choice()
    }
}

impl ConditionallySelectable for Choice {
    #[inline]
    fn conditional_select(left: &Self, right: &Self, choice: Choice) -> Self {
        Self(u8::conditional_select(&left.0, &right.0, choice) & 1)
    }
}

/// Native data-oblivious equality trait.
///
/// For slices, length is public: length mismatch may return immediately,
/// while equal-length inputs must compare all elements.
pub trait ConstantTimeEq<Rhs: ?Sized = Self> {
    /// Compare without secret-dependent early exit.
    fn ct_eq(&self, other: &Rhs) -> Choice;

    /// Negated [`ConstantTimeEq::ct_eq`].
    #[inline]
    fn ct_ne(&self, other: &Rhs) -> Choice {
        !self.ct_eq(other)
    }
}

/// Branchless selection between two values.
pub trait ConditionallySelectable: Sized {
    /// Return `left` when `choice` is false and `right` when it is true.
    fn conditional_select(left: &Self, right: &Self, choice: Choice) -> Self;
}

/// Branchless assignment under a [`Choice`].
pub trait ConditionallyAssignable: ConditionallySelectable {
    /// Assign `other` to `self` when `choice` is true.
    #[inline]
    fn conditional_assign(&mut self, other: &Self, choice: Choice) {
        *self = Self::conditional_select(self, other, choice);
    }
}

impl<T: ConditionallySelectable> ConditionallyAssignable for T {}

/// Data-oblivious ordering result.
///
/// Exactly one of the three choices should be true. Converting the result
/// into [`Ordering`] is a public branch boundary and must go through
/// [`CtOrdering::declassify`].
#[derive(Clone, Copy)]
pub struct CtOrdering {
    less: Choice,
    equal: Choice,
    greater: Choice,
}

impl CtOrdering {
    /// Equal ordering.
    pub const EQUAL: Self = Self {
        less: Choice::FALSE,
        equal: Choice::TRUE,
        greater: Choice::FALSE,
    };

    /// Less-than ordering.
    pub const LESS: Self = Self {
        less: Choice::TRUE,
        equal: Choice::FALSE,
        greater: Choice::FALSE,
    };

    /// Greater-than ordering.
    pub const GREATER: Self = Self {
        less: Choice::FALSE,
        equal: Choice::FALSE,
        greater: Choice::TRUE,
    };

    /// Construct an ordering from hidden choice bits.
    ///
    /// If multiple bits are supplied, the value is normalized to one
    /// public ordering using `less`, then `greater`, then `equal`
    /// precedence. If no bit is supplied, the value normalizes to
    /// [`CtOrdering::EQUAL`].
    #[inline]
    pub const fn new(less: Choice, _equal: Choice, greater: Choice) -> Self {
        let less_bit = less.0 & 1;
        let greater_bit = (greater.0 & 1) & (less_bit ^ 1);
        let equal_bit = (less_bit | greater_bit) ^ 1;

        Self::from_normalized_bits(Choice(less_bit), Choice(equal_bit), Choice(greater_bit))
    }

    /// Construct an ordering from already-normalized internal bits.
    ///
    /// Callers must provide exactly one true bit. This preserves hidden
    /// accumulators from internal comparison routines without passing them
    /// through the public lossy normalizing constructor.
    #[inline]
    const fn from_normalized_bits(less: Choice, equal: Choice, greater: Choice) -> Self {
        debug_assert!(
            (less.0 & 1) + (equal.0 & 1) + (greater.0 & 1) == 1,
            "from_normalized_bits: caller must supply exactly one true bit"
        );
        Self {
            less,
            equal,
            greater,
        }
    }

    /// Return the hidden less-than bit.
    #[inline]
    pub const fn is_less(&self) -> Choice {
        self.less
    }

    /// Return the hidden equality bit.
    #[inline]
    pub const fn is_equal(&self) -> Choice {
        self.equal
    }

    /// Return the hidden greater-than bit.
    #[inline]
    pub const fn is_greater(&self) -> Choice {
        self.greater
    }

    /// Explicitly convert this ordering into a public [`Ordering`].
    ///
    /// The `reason` string is intentionally required so security reviews
    /// can search for every comparison declassification boundary.
    #[inline]
    pub fn declassify(self, reason: &'static str) -> Ordering {
        black_box(reason);
        // Fields are private and constructors normalize today. Keep this
        // as a future-refactor guard for any internal constructors.
        debug_assert_eq!(
            (self.less.0 & 1) + (self.equal.0 & 1) + (self.greater.0 & 1),
            1,
            "CtOrdering must have exactly one bit set"
        );
        if self.less.bit() == 1 {
            Ordering::Less
        } else if self.greater.bit() == 1 {
            Ordering::Greater
        } else {
            Ordering::Equal
        }
    }
}

impl fmt::Debug for CtOrdering {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CtOrdering(..)")
    }
}

/// Native data-oblivious ordering trait.
///
/// Implementations avoid secret-dependent early exit. For variable-length
/// inputs, length remains public metadata unless a specific API states
/// otherwise.
pub trait ConstantTimeOrd<Rhs: ?Sized = Self> {
    /// Compare without secret-dependent early exit.
    fn ct_cmp(&self, other: &Rhs) -> CtOrdering;

    /// Hidden less-than bit.
    #[inline]
    fn ct_lt(&self, other: &Rhs) -> Choice {
        self.ct_cmp(other).is_less()
    }

    /// Hidden less-than-or-equal bit.
    #[inline]
    fn ct_le(&self, other: &Rhs) -> Choice {
        let ordering = self.ct_cmp(other);
        ordering.is_less() | ordering.is_equal()
    }

    /// Hidden greater-than bit.
    #[inline]
    fn ct_gt(&self, other: &Rhs) -> Choice {
        self.ct_cmp(other).is_greater()
    }

    /// Hidden greater-than-or-equal bit.
    #[inline]
    fn ct_ge(&self, other: &Rhs) -> Choice {
        let ordering = self.ct_cmp(other);
        ordering.is_greater() | ordering.is_equal()
    }
}

/// All-zero/all-one mask value for branchless operations.
#[repr(transparent)]
#[derive(Clone, Copy)]
pub struct Mask<T> {
    value: T,
}

impl<T: Copy> Mask<T> {
    /// Explicitly convert this mask into a public raw value.
    ///
    /// The `reason` string is intentionally required so security reviews can
    /// search for every mask declassification boundary. Data-oblivious helpers
    /// inside this module use the private raw accessor instead.
    #[inline]
    pub fn declassify(self, reason: &'static str) -> T {
        black_box(reason);
        self.raw()
    }

    #[inline]
    const fn raw(self) -> T {
        self.value
    }
}

impl<T: fmt::Debug> fmt::Debug for Mask<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Mask(..)")
    }
}

/// Wrapper for values that are explicitly public by contract.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublicValue<T>(T);

impl<T> PublicValue<T> {
    /// Wrap a public value.
    #[inline]
    pub const fn new(value: T) -> Self {
        Self(value)
    }

    /// Unwrap a public value.
    #[inline]
    pub fn into_inner(self) -> T {
        self.0
    }

    /// Borrow the public value.
    #[inline]
    pub const fn expose(&self) -> &T {
        &self.0
    }
}

/// Secret-controlled table index with clear-on-drop storage.
///
/// The index cannot be copied, compared, printed, or borrowed through the
/// public API. Full-scan lookup helpers consume it directly. Explicitly
/// revealing the index requires a reason-bearing consuming declassification.
///
/// Clearing covers this wrapper's live storage. Rust moves, compiler-created
/// temporaries, registers, and caller-created copies remain outside that
/// guarantee.
pub struct SecretIndex {
    value: usize,
}

impl SecretIndex {
    /// Wrap a secret-controlled index.
    #[inline]
    pub const fn new(value: usize) -> Self {
        Self { value }
    }

    /// Explicitly reveal this index as public metadata.
    ///
    /// This consumes the wrapper and clears its remaining storage before
    /// returning the copied scalar.
    #[inline]
    pub fn declassify(mut self, reason: &'static str) -> usize {
        black_box(reason);
        let value = self.value;
        self.secure_sanitize();
        value
    }

    #[inline]
    const fn value(&self) -> usize {
        self.value
    }
}

impl SecureSanitize for SecretIndex {
    #[inline]
    fn secure_sanitize(&mut self) {
        self.value.secure_sanitize();
    }
}

impl Drop for SecretIndex {
    #[inline]
    fn drop(&mut self) {
        self.secure_sanitize();
    }
}

impl fmt::Debug for SecretIndex {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretIndex(..)")
    }
}

/// Owned secret-controlled scalar with clear-on-drop storage.
///
/// This type intentionally has no generic borrow or exposure closure. Reviewed
/// data-oblivious operations are provided through trait-bounded methods, while
/// conversion back to an ordinary value is a consuming, reason-bearing
/// declassification.
///
/// Clearing covers this wrapper's live storage. Rust moves, compiler-created
/// temporaries, registers, and caller-created copies remain outside that
/// guarantee.
pub struct SecretScalar<T: SecureSanitize> {
    value: Option<T>,
}

impl<T: SecureSanitize> SecretScalar<T> {
    /// Wrap a secret-controlled scalar.
    #[inline]
    pub const fn new(value: T) -> Self {
        Self { value: Some(value) }
    }

    /// Compare two wrapped scalars without declassifying the result.
    #[inline]
    pub fn ct_eq(&self, other: &Self) -> Choice
    where
        T: ConstantTimeEq,
    {
        self.value_ref().ct_eq(other.value_ref())
    }

    /// Order two wrapped scalars without declassifying the result.
    #[inline]
    pub fn ct_cmp(&self, other: &Self) -> CtOrdering
    where
        T: ConstantTimeOrd,
    {
        self.value_ref().ct_cmp(other.value_ref())
    }

    /// Select one wrapped scalar without consuming either source.
    ///
    /// The returned wrapper owns a third value. Both source wrappers remain
    /// live and retain their independent clear-on-drop obligations.
    #[inline]
    pub fn conditional_select(left: &Self, right: &Self, choice: Choice) -> Self
    where
        T: ConditionallySelectable,
    {
        Self::new(T::conditional_select(
            left.value_ref(),
            right.value_ref(),
            choice,
        ))
    }

    /// Explicitly reveal this scalar as a normal value.
    ///
    /// The caller assumes responsibility for sanitizing the returned value.
    /// The consumed wrapper is left empty so its destructor cannot clean the
    /// moved value a second time.
    #[inline]
    pub fn declassify(mut self, reason: &'static str) -> T {
        black_box(reason);
        self.value
            .take()
            .expect("SecretScalar value must exist before declassification")
    }

    #[inline]
    fn value_ref(&self) -> &T {
        self.value
            .as_ref()
            .expect("SecretScalar value must exist while borrowed")
    }
}

impl<T: SecureSanitize> SecureSanitize for SecretScalar<T> {
    #[inline]
    fn secure_sanitize(&mut self) {
        sanitize_owned_option(&mut self.value);
    }
}

impl<T: SecureSanitize> Drop for SecretScalar<T> {
    #[inline]
    fn drop(&mut self) {
        self.secure_sanitize();
    }
}

impl<T: SecureSanitize> fmt::Debug for SecretScalar<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretScalar(..)")
    }
}

/// Explicitly secret-classified backing value for secret CT containers.
///
/// The value is clear-on-drop and non-copying. Consuming declassification
/// transfers cleanup responsibility for the returned value to the caller.
pub struct SecretValue<T: SecureSanitize> {
    value: Option<T>,
}

impl<T: SecureSanitize> SecretValue<T> {
    /// Classify a backing value as secret.
    #[inline]
    pub const fn new(value: T) -> Self {
        Self { value: Some(value) }
    }

    /// Explicitly reveal the classified value.
    #[inline]
    pub fn declassify(mut self, reason: &'static str) -> T {
        black_box(reason);
        self.take_value()
    }

    #[inline]
    fn value_ref(&self) -> &T {
        self.value
            .as_ref()
            .expect("SecretValue must contain a value while borrowed")
    }

    #[inline]
    fn value_mut(&mut self) -> &mut T {
        self.value
            .as_mut()
            .expect("SecretValue must contain a value while borrowed")
    }

    #[inline]
    fn take_value(&mut self) -> T {
        self.value
            .take()
            .expect("SecretValue must contain a value before extraction")
    }
}

impl<T: SecureSanitize> SecureSanitize for SecretValue<T> {
    #[inline]
    fn secure_sanitize(&mut self) {
        sanitize_owned_option(&mut self.value);
    }
}

impl<T: SecureSanitize> Drop for SecretValue<T> {
    #[inline]
    fn drop(&mut self) {
        self.secure_sanitize();
    }
}

impl<T: SecureSanitize> fmt::Debug for SecretValue<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretValue(..)")
    }
}

#[inline]
fn sanitize_owned_option<T: SecureSanitize>(value: &mut Option<T>) {
    if let Some(value) = value.as_mut() {
        value.secure_sanitize();
    }
    *value = None;
}

/// Optional value with a hidden presence bit and explicitly public backing.
///
/// `PublicCtOption` stores a value regardless of whether it is logically present.
/// Callers should combine or select on the [`Choice`] returned by
/// [`PublicCtOption::is_some`] and declassify only at a public boundary.
///
/// # Warning
///
/// The `Public` prefix is a security classification, not merely a descriptive
/// name. This type is `Copy` when `T` is `Copy` and exposes unredacted `Debug`
/// output when `T` does. Do not instantiate it with secret-bearing storage.
/// Use [`SecretCtOption`] with [`SecretValue`] for non-`Copy`, redacted,
/// clear-on-drop backing values.
#[derive(Clone, Copy, Debug)]
pub struct PublicCtOption<T> {
    value: T,
    is_some: Choice,
}

impl<T> PublicCtOption<T> {
    /// Construct optional state whose backing value is classified as public.
    #[inline]
    pub const fn new(value: T, is_some: Choice) -> Self {
        Self { value, is_some }
    }

    /// Construct a logically present value.
    #[inline]
    pub const fn some(value: T) -> Self {
        Self {
            value,
            is_some: Choice::TRUE,
        }
    }

    /// Construct a logically absent value with a dummy backing value.
    #[inline]
    pub const fn none(dummy: T) -> Self {
        Self {
            value: dummy,
            is_some: Choice::FALSE,
        }
    }

    /// Return the hidden presence bit.
    #[inline]
    pub const fn is_some(&self) -> Choice {
        self.is_some
    }

    /// Return the hidden absence bit.
    #[inline]
    pub fn is_none(&self) -> Choice {
        !self.is_some
    }

    /// Borrow the backing value. Its logical validity is controlled by
    /// [`PublicCtOption::is_some`].
    #[inline]
    pub const fn value(&self) -> &T {
        &self.value
    }

    /// Select the backing value or `fallback` without branching on
    /// presence.
    #[inline]
    pub fn unwrap_or(&self, fallback: &T) -> T
    where
        T: ConditionallySelectable,
    {
        T::conditional_select(fallback, &self.value, self.is_some)
    }

    /// Transform the backing value without declassifying the presence bit.
    ///
    /// The closure is always called, even when this value is logically
    /// absent. If the backing value is secret-derived, the closure must
    /// avoid secret-dependent control flow and secret-dependent memory
    /// access.
    #[inline]
    pub fn map<U>(self, transform: impl FnOnce(T) -> U) -> PublicCtOption<U> {
        PublicCtOption {
            value: transform(self.value),
            is_some: self.is_some,
        }
    }

    /// Combine two optional values, keeping the result logically present
    /// only when both inputs are present.
    ///
    /// The backing value from `other` is retained regardless of presence.
    #[inline]
    pub fn and<U>(self, other: PublicCtOption<U>) -> PublicCtOption<U> {
        PublicCtOption {
            value: other.value,
            is_some: self.is_some & other.is_some,
        }
    }

    /// Select `self` when present and `other` otherwise without branching
    /// on the hidden presence bit.
    ///
    /// The result is present when either input is present.
    #[inline]
    pub fn or(self, other: Self) -> Self
    where
        T: ConditionallySelectable,
    {
        Self {
            value: T::conditional_select(&other.value, &self.value, self.is_some),
            is_some: self.is_some | other.is_some,
        }
    }

    /// Explicitly declassify the presence bit and convert into a normal
    /// [`Option`].
    ///
    /// This is a public branch boundary. The `reason` must explain why the
    /// caller is allowed to reveal the presence/absence decision.
    #[inline]
    pub fn declassify(self, reason: &'static str) -> Option<T> {
        if self.is_some.declassify(reason) {
            Some(self.value)
        } else {
            None
        }
    }
}

impl<T> ConditionallySelectable for PublicCtOption<T>
where
    T: ConditionallySelectable,
{
    #[inline]
    fn conditional_select(left: &Self, right: &Self, choice: Choice) -> Self {
        Self {
            value: T::conditional_select(&left.value, &right.value, choice),
            is_some: Choice::conditional_select(&left.is_some, &right.is_some, choice),
        }
    }
}

/// Result-like value with a hidden success bit and explicitly public backing.
///
/// # Warning
///
/// The `Public` prefix is a security classification. This type is `Copy` when
/// both backing types are `Copy` and exposes their normal `Debug` output. Do
/// not place secret-bearing values in either side. Use [`SecretCtResult`] when
/// a success or error backing value is secret and must be redacted and cleared
/// on drop.
#[derive(Clone, Copy, Debug)]
pub struct PublicCtResult<T, E> {
    value: T,
    error: E,
    is_ok: Choice,
}

impl<T, E> PublicCtResult<T, E> {
    /// Construct public result backing values and a hidden success bit.
    #[inline]
    pub const fn new(value: T, error: E, is_ok: Choice) -> Self {
        Self {
            value,
            error,
            is_ok,
        }
    }

    /// Return the hidden success bit.
    #[inline]
    pub const fn is_ok(&self) -> Choice {
        self.is_ok
    }

    /// Return the hidden error bit.
    #[inline]
    pub fn is_err(&self) -> Choice {
        !self.is_ok
    }

    /// Borrow the success backing value.
    #[inline]
    pub const fn value(&self) -> &T {
        &self.value
    }

    /// Borrow the error backing value.
    #[inline]
    pub const fn error(&self) -> &E {
        &self.error
    }

    /// Select the success backing value or `fallback` without branching on
    /// the success bit.
    #[inline]
    pub fn unwrap_or(&self, fallback: &T) -> T
    where
        T: ConditionallySelectable,
    {
        T::conditional_select(fallback, &self.value, self.is_ok)
    }

    /// Transform the success backing value without declassifying the
    /// success bit.
    ///
    /// The closure is always called, even when this value is logically an
    /// error. If the backing value is secret-derived, the closure must
    /// avoid secret-dependent control flow and secret-dependent memory
    /// access.
    #[inline]
    pub fn map<U>(self, transform: impl FnOnce(T) -> U) -> PublicCtResult<U, E> {
        PublicCtResult {
            value: transform(self.value),
            error: self.error,
            is_ok: self.is_ok,
        }
    }

    /// Transform the error backing value without declassifying the success
    /// bit.
    ///
    /// The closure is always called, even when this value is logically
    /// successful. If the backing error is secret-derived, the closure must
    /// avoid secret-dependent control flow and secret-dependent memory
    /// access.
    #[inline]
    pub fn map_err<F>(self, transform: impl FnOnce(E) -> F) -> PublicCtResult<T, F> {
        PublicCtResult {
            value: self.value,
            error: transform(self.error),
            is_ok: self.is_ok,
        }
    }

    /// Explicitly declassify the success bit and convert into a normal
    /// [`Result`].
    ///
    /// This is a public branch boundary. The `reason` must explain why the
    /// caller is allowed to reveal the success/error decision.
    #[inline]
    pub fn declassify(self, reason: &'static str) -> Result<T, E> {
        if self.is_ok.declassify(reason) {
            Ok(self.value)
        } else {
            Err(self.error)
        }
    }
}

impl<T, E> ConditionallySelectable for PublicCtResult<T, E>
where
    T: ConditionallySelectable,
    E: ConditionallySelectable,
{
    #[inline]
    fn conditional_select(left: &Self, right: &Self, choice: Choice) -> Self {
        Self {
            value: T::conditional_select(&left.value, &right.value, choice),
            error: E::conditional_select(&left.error, &right.error, choice),
            is_ok: Choice::conditional_select(&left.is_ok, &right.is_ok, choice),
        }
    }
}

/// Optional CT state whose backing value is explicitly classified as public
/// or secret.
///
/// Unlike [`PublicCtOption`], this container is non-copying, has redacted `Debug`,
/// exposes no raw backing getter, and can own a [`SecretValue`] that clears on
/// drop. The backing closure used by [`SecretCtOption::map_secret`] runs for
/// both present and absent states.
pub struct SecretCtOption<V> {
    value: Option<V>,
    is_some: Choice,
}

impl<V> SecretCtOption<V> {
    /// Return the hidden presence bit.
    #[inline]
    pub const fn is_some(&self) -> Choice {
        self.is_some
    }

    /// Return the hidden absence bit.
    #[inline]
    pub fn is_none(&self) -> Choice {
        !self.is_some
    }

    #[inline]
    fn classified(value: V, is_some: Choice) -> Self {
        Self {
            value: Some(value),
            is_some,
        }
    }

    #[inline]
    fn take_value(&mut self) -> V {
        self.value
            .take()
            .expect("SecretCtOption backing value must exist before extraction")
    }
}

impl<T> SecretCtOption<PublicValue<T>> {
    /// Construct optional state with explicitly public backing data.
    #[inline]
    pub fn public(value: T, is_some: Choice) -> Self {
        Self::classified(PublicValue::new(value), is_some)
    }

    /// Transform the public backing value without declassifying presence.
    ///
    /// The closure always runs, including for a logically absent value.
    #[inline]
    pub fn map_public<U>(
        mut self,
        transform: impl FnOnce(T) -> U,
    ) -> SecretCtOption<PublicValue<U>> {
        let is_some = self.is_some;
        let value = self.take_value().into_inner();
        SecretCtOption::classified(PublicValue::new(transform(value)), is_some)
    }

    /// Explicitly declassify presence and return public backing data.
    #[inline]
    pub fn declassify(mut self, reason: &'static str) -> Option<T> {
        let is_some = self.is_some.declassify(reason);
        let value = self.take_value().into_inner();
        is_some.then_some(value)
    }
}

impl<T: SecureSanitize> SecretCtOption<SecretValue<T>> {
    /// Construct optional state with clear-on-drop secret backing data.
    #[inline]
    pub fn secret(value: T, is_some: Choice) -> Self {
        Self::classified(SecretValue::new(value), is_some)
    }

    /// Transform secret backing data without moving it out of its owner.
    ///
    /// The closure always runs, including for a logically absent dummy value.
    /// If the closure panics, this container remains the owner and clears the
    /// original backing value during unwind.
    #[inline]
    pub fn map_secret<U: SecureSanitize>(
        mut self,
        transform: impl FnOnce(&mut T) -> U,
    ) -> SecretCtOption<SecretValue<U>> {
        let is_some = self.is_some;
        let mapped = transform(
            self.value
                .as_mut()
                .expect("SecretCtOption backing value must exist while mapped")
                .value_mut(),
        );
        SecretCtOption::classified(SecretValue::new(mapped), is_some)
    }

    /// Explicitly declassify presence and transfer a selected secret value.
    ///
    /// An absent dummy value is sanitized before this method returns `None`.
    /// For `Some`, cleanup responsibility for the returned value transfers to
    /// the caller.
    #[inline]
    pub fn declassify(mut self, reason: &'static str) -> Option<T> {
        if self.is_some.declassify(reason) {
            Some(self.take_value().declassify(reason))
        } else {
            drop(self.take_value());
            None
        }
    }
}

impl<T> ConditionallySelectable for SecretCtOption<PublicValue<T>>
where
    T: ConditionallySelectable,
{
    #[inline]
    fn conditional_select(left: &Self, right: &Self, choice: Choice) -> Self {
        let left_value = left
            .value
            .as_ref()
            .expect("left SecretCtOption must contain public backing data")
            .expose();
        let right_value = right
            .value
            .as_ref()
            .expect("right SecretCtOption must contain public backing data")
            .expose();
        Self::public(
            T::conditional_select(left_value, right_value, choice),
            Choice::conditional_select(&left.is_some, &right.is_some, choice),
        )
    }
}

impl<T> ConditionallySelectable for SecretCtOption<SecretValue<T>>
where
    T: SecureSanitize + ConditionallySelectable,
{
    #[inline]
    fn conditional_select(left: &Self, right: &Self, choice: Choice) -> Self {
        let left_value = left
            .value
            .as_ref()
            .expect("left SecretCtOption must contain secret backing data")
            .value_ref();
        let right_value = right
            .value
            .as_ref()
            .expect("right SecretCtOption must contain secret backing data")
            .value_ref();
        Self::secret(
            T::conditional_select(left_value, right_value, choice),
            Choice::conditional_select(&left.is_some, &right.is_some, choice),
        )
    }
}

impl<V> fmt::Debug for SecretCtOption<V> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretCtOption(..)")
    }
}

/// Result-like CT state with explicitly classified success and error backing
/// values.
///
/// Secret-classified selected values transfer to the caller only after
/// reason-bearing declassification. Every unselected [`SecretValue`] remains
/// owned by this container and is sanitized before the method returns.
pub struct SecretCtResult<V, E> {
    value: Option<V>,
    error: Option<E>,
    is_ok: Choice,
}

impl<V, E> SecretCtResult<V, E> {
    /// Return the hidden success bit.
    #[inline]
    pub const fn is_ok(&self) -> Choice {
        self.is_ok
    }

    /// Return the hidden error bit.
    #[inline]
    pub fn is_err(&self) -> Choice {
        !self.is_ok
    }

    #[inline]
    fn classified(value: V, error: E, is_ok: Choice) -> Self {
        Self {
            value: Some(value),
            error: Some(error),
            is_ok,
        }
    }

    #[inline]
    fn take_value(&mut self) -> V {
        self.value
            .take()
            .expect("SecretCtResult success backing value must exist before extraction")
    }

    #[inline]
    fn take_error(&mut self) -> E {
        self.error
            .take()
            .expect("SecretCtResult error backing value must exist before extraction")
    }
}

impl<T, E> SecretCtResult<PublicValue<T>, PublicValue<E>> {
    /// Construct result state with public success and error backing data.
    #[inline]
    pub fn public(value: T, error: E, is_ok: Choice) -> Self {
        Self::classified(PublicValue::new(value), PublicValue::new(error), is_ok)
    }

    /// Explicitly declassify the result.
    #[inline]
    pub fn declassify(mut self, reason: &'static str) -> Result<T, E> {
        let is_ok = self.is_ok.declassify(reason);
        let value = self.take_value().into_inner();
        let error = self.take_error().into_inner();
        if is_ok {
            Ok(value)
        } else {
            Err(error)
        }
    }
}

impl<T: SecureSanitize, E> SecretCtResult<SecretValue<T>, PublicValue<E>> {
    /// Construct result state with secret success data and public error data.
    #[inline]
    pub fn secret_success(value: T, error: E, is_ok: Choice) -> Self {
        Self::classified(SecretValue::new(value), PublicValue::new(error), is_ok)
    }

    /// Explicitly declassify the result.
    ///
    /// The secret success value transfers to the caller only on success. It is
    /// sanitized as an unselected backing value on error.
    #[inline]
    pub fn declassify(mut self, reason: &'static str) -> Result<T, E> {
        if self.is_ok.declassify(reason) {
            let value = self.take_value();
            drop(self.take_error());
            Ok(value.declassify(reason))
        } else {
            drop(self.take_value());
            Err(self.take_error().into_inner())
        }
    }
}

impl<T, E: SecureSanitize> SecretCtResult<PublicValue<T>, SecretValue<E>> {
    /// Construct result state with public success data and secret error data.
    #[inline]
    pub fn secret_error(value: T, error: E, is_ok: Choice) -> Self {
        Self::classified(PublicValue::new(value), SecretValue::new(error), is_ok)
    }

    /// Explicitly declassify the result.
    ///
    /// The secret error value transfers to the caller only on error. It is
    /// sanitized as an unselected backing value on success.
    #[inline]
    pub fn declassify(mut self, reason: &'static str) -> Result<T, E> {
        if self.is_ok.declassify(reason) {
            drop(self.take_error());
            Ok(self.take_value().into_inner())
        } else {
            drop(self.take_value());
            let error = self.take_error();
            Err(error.declassify(reason))
        }
    }
}

impl<T: SecureSanitize, E: SecureSanitize> SecretCtResult<SecretValue<T>, SecretValue<E>> {
    /// Construct result state with secret success and error backing data.
    #[inline]
    pub fn secret(value: T, error: E, is_ok: Choice) -> Self {
        Self::classified(SecretValue::new(value), SecretValue::new(error), is_ok)
    }

    /// Explicitly declassify the result.
    ///
    /// The selected value transfers to the caller. The unselected value is
    /// sanitized before this method returns.
    #[inline]
    pub fn declassify(mut self, reason: &'static str) -> Result<T, E> {
        if self.is_ok.declassify(reason) {
            let value = self.take_value();
            drop(self.take_error());
            Ok(value.declassify(reason))
        } else {
            drop(self.take_value());
            let error = self.take_error();
            Err(error.declassify(reason))
        }
    }
}

impl<T: SecureSanitize, E> SecretCtResult<SecretValue<T>, E> {
    /// Transform secret success backing data without moving it out of its
    /// clear-on-drop owner.
    ///
    /// The closure always runs, including for a logically failed result. If it
    /// panics, both original backing values remain owned and are dropped.
    #[inline]
    pub fn map_secret_success<U: SecureSanitize>(
        mut self,
        transform: impl FnOnce(&mut T) -> U,
    ) -> SecretCtResult<SecretValue<U>, E> {
        let is_ok = self.is_ok;
        let mapped = transform(
            self.value
                .as_mut()
                .expect("SecretCtResult success backing value must exist while mapped")
                .value_mut(),
        );
        let error = self.take_error();
        SecretCtResult::classified(SecretValue::new(mapped), error, is_ok)
    }
}

impl<T, E: SecureSanitize> SecretCtResult<T, SecretValue<E>> {
    /// Transform secret error backing data without moving it out of its
    /// clear-on-drop owner.
    ///
    /// The closure always runs, including for a logically successful result.
    /// If it panics, both original backing values remain owned and are dropped.
    #[inline]
    pub fn map_secret_error<F: SecureSanitize>(
        mut self,
        transform: impl FnOnce(&mut E) -> F,
    ) -> SecretCtResult<T, SecretValue<F>> {
        let is_ok = self.is_ok;
        let mapped = transform(
            self.error
                .as_mut()
                .expect("SecretCtResult error backing value must exist while mapped")
                .value_mut(),
        );
        let value = self.take_value();
        SecretCtResult::classified(value, SecretValue::new(mapped), is_ok)
    }
}

macro_rules! impl_secret_ct_result_select {
    (
        value = $value_wrapper:ident<$value:ident> $(where $value_bound:path)?,
        error = $error_wrapper:ident<$error:ident> $(where $error_bound:path)?,
        constructor = $constructor:ident
    ) => {
        impl<$value, $error> ConditionallySelectable
            for SecretCtResult<$value_wrapper<$value>, $error_wrapper<$error>>
        where
            $value: ConditionallySelectable $(+ $value_bound)?,
            $error: ConditionallySelectable $(+ $error_bound)?,
        {
            #[inline]
            fn conditional_select(left: &Self, right: &Self, choice: Choice) -> Self {
                let left_value = left
                    .value
                    .as_ref()
                    .expect("left SecretCtResult must contain success backing data");
                let right_value = right
                    .value
                    .as_ref()
                    .expect("right SecretCtResult must contain success backing data");
                let left_error = left
                    .error
                    .as_ref()
                    .expect("left SecretCtResult must contain error backing data");
                let right_error = right
                    .error
                    .as_ref()
                    .expect("right SecretCtResult must contain error backing data");

                SecretCtResult::$constructor(
                    $value::conditional_select(
                        impl_secret_ct_result_select!(@borrow left_value, $value_wrapper),
                        impl_secret_ct_result_select!(@borrow right_value, $value_wrapper),
                        choice,
                    ),
                    $error::conditional_select(
                        impl_secret_ct_result_select!(@borrow left_error, $error_wrapper),
                        impl_secret_ct_result_select!(@borrow right_error, $error_wrapper),
                        choice,
                    ),
                    Choice::conditional_select(&left.is_ok, &right.is_ok, choice),
                )
            }
        }
    };
    (@borrow $value:ident, PublicValue) => {
        $value.expose()
    };
    (@borrow $value:ident, SecretValue) => {
        $value.value_ref()
    };
}

impl_secret_ct_result_select!(
    value = PublicValue<T>,
    error = PublicValue<E>,
    constructor = public
);
impl_secret_ct_result_select!(
    value = SecretValue<T> where SecureSanitize,
    error = PublicValue<E>,
    constructor = secret_success
);
impl_secret_ct_result_select!(
    value = PublicValue<T>,
    error = SecretValue<E> where SecureSanitize,
    constructor = secret_error
);
impl_secret_ct_result_select!(
    value = SecretValue<T> where SecureSanitize,
    error = SecretValue<E> where SecureSanitize,
    constructor = secret
);

impl<V, E> fmt::Debug for SecretCtResult<V, E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretCtResult(..)")
    }
}

macro_rules! impl_unsigned_ct {
        ($($ty:ty),* $(,)?) => {
            $(
                impl Mask<$ty> {
                    /// Return an all-zero mask when `choice` is false and an
                    /// all-one mask when it is true.
                    #[inline]
                    pub fn from_choice(choice: Choice) -> Self {
                        Self {
                            value: (0 as $ty).wrapping_sub(choice.bit() as $ty),
                        }
                    }
                }

                impl ConstantTimeEq for $ty {
                    #[inline]
                    fn ct_eq(&self, other: &Self) -> Choice {
                        let diff = black_box(*self ^ *other);
                        let nonzero = ((diff | diff.wrapping_neg()) >> (<$ty>::BITS - 1)) as u8;
                        Choice::from_u8(nonzero ^ 1)
                    }
                }

                impl ConditionallySelectable for $ty {
                    #[inline]
                    fn conditional_select(left: &Self, right: &Self, choice: Choice) -> Self {
                        let mask = (0 as $ty).wrapping_sub(choice.bit() as $ty);
                        black_box((*left & !mask) | (*right & mask))
                    }
                }

                impl ConstantTimeOrd for $ty {
                    #[inline]
                    fn ct_cmp(&self, other: &Self) -> CtOrdering {
                        ct_cmp_be_bytes(&self.to_be_bytes(), &other.to_be_bytes())
                    }
                }
            )*
        };
    }

macro_rules! impl_signed_ct {
        ($(($signed:ty, $unsigned:ty)),* $(,)?) => {
            $(
                impl ConstantTimeEq for $signed {
                    #[inline]
                    fn ct_eq(&self, other: &Self) -> Choice {
                        (*self as $unsigned).ct_eq(&(*other as $unsigned))
                    }
                }

                impl ConditionallySelectable for $signed {
                    #[inline]
                    fn conditional_select(left: &Self, right: &Self, choice: Choice) -> Self {
                        <$unsigned as ConditionallySelectable>::conditional_select(
                            &(*left as $unsigned),
                            &(*right as $unsigned),
                            choice,
                        ) as $signed
                    }
                }

                impl ConstantTimeOrd for $signed {
                    #[inline]
                    fn ct_cmp(&self, other: &Self) -> CtOrdering {
                        let sign_bit = 1 as $unsigned << (<$unsigned>::BITS - 1);
                        let left = ((*self as $unsigned) ^ sign_bit).to_be_bytes();
                        let right = ((*other as $unsigned) ^ sign_bit).to_be_bytes();
                        ct_cmp_be_bytes(&left, &right)
                    }
                }
            )*
        };
    }

impl_unsigned_ct!(u8, u16, u32, u64, u128, usize);
impl_signed_ct!(
    (i8, u8),
    (i16, u16),
    (i32, u32),
    (i64, u64),
    (i128, u128),
    (isize, usize),
);

impl ConstantTimeEq for bool {
    #[inline]
    fn ct_eq(&self, other: &Self) -> Choice {
        (*self as u8).ct_eq(&(*other as u8))
    }
}

impl ConditionallySelectable for bool {
    #[inline]
    fn conditional_select(left: &Self, right: &Self, choice: Choice) -> Self {
        u8::conditional_select(&(*left as u8), &(*right as u8), choice) == 1
    }
}

/// Compare fixed-size byte arrays without leaking the first difference.
#[inline]
pub fn eq_fixed<const N: usize>(left: &[u8; N], right: &[u8; N]) -> Choice {
    bytes_eq_equal_len(left, right)
}

/// Compare fixed-size byte arrays and explicitly declassify the final equality
/// decision.
///
/// This is a convenience boundary for callers that do not need to compose the
/// returned [`Choice`]. The `reason` remains mandatory so the public decision
/// is searchable during review.
#[must_use]
#[inline]
pub fn declassified_eq_fixed<const N: usize>(
    left: &[u8; N],
    right: &[u8; N],
    reason: &'static str,
) -> bool {
    eq_fixed(left, right).declassify(reason)
}

/// Compare fixed-size byte arrays in lexicographic byte order without
/// leaking the first differing byte.
#[inline]
pub fn cmp_fixed<const N: usize>(left: &[u8; N], right: &[u8; N]) -> CtOrdering {
    ct_cmp_be_bytes(left, right)
}

/// Compare fixed-size byte arrays and explicitly declassify the final ordering.
///
/// Use [`cmp_fixed`] when the ordering must remain inside the data-oblivious
/// domain for further composition.
#[must_use]
#[inline]
pub fn declassified_cmp_fixed<const N: usize>(
    left: &[u8; N],
    right: &[u8; N],
    reason: &'static str,
) -> Ordering {
    cmp_fixed(left, right).declassify(reason)
}

/// Compare byte slices where length is explicitly public.
#[inline]
pub fn eq_public_len(left: &[u8], right: &[u8]) -> Choice {
    if left.len() != right.len() {
        return Choice::FALSE;
    }

    bytes_eq_equal_len(left, right)
}

/// Compare byte slices with explicitly public lengths and declassify the final
/// equality decision.
///
/// A length mismatch is public and may return before byte comparison. Use
/// [`declassified_eq_fixed`] when length must not influence control flow.
#[must_use]
#[inline]
pub fn declassified_eq_public_len(left: &[u8], right: &[u8], reason: &'static str) -> bool {
    eq_public_len(left, right).declassify(reason)
}

/// Look up one table entry by a secret index using a full-table scan.
///
/// The table length is public. Every table entry is visited exactly once
/// for the public length, and an out-of-range secret index returns
/// `fallback`.
///
/// The returned value is selected by a secret index. If the value remains
/// secret-controlled, prefer [`oblivious_lookup_secret`] so the type system
/// keeps that boundary visible to reviewers.
#[inline(never)]
pub fn oblivious_lookup<T>(table: &[T], secret_index: SecretIndex, fallback: &T) -> T
where
    T: ConditionallySelectable,
{
    // Initialize through the same selection trait required by the loop.
    // This avoids adding `Clone`/`Copy` bounds to `T` while making the
    // fallback behavior explicit.
    let mut output = T::conditional_select(fallback, fallback, Choice::FALSE);
    let wanted = black_box(secret_index.value());
    let mut index = 0usize;
    while index < table.len() {
        let selected = wanted.ct_eq(&index);
        output = T::conditional_select(&output, &table[index], selected);
        index += 1;
    }
    black_box(output)
}

/// Look up one table entry by a secret index and keep the selected value
/// wrapped as secret-controlled.
///
/// This is the audit-friendly variant of [`oblivious_lookup`] for call
/// sites where the selected value must not immediately drive ordinary
/// control flow or memory access.
#[inline(never)]
pub fn oblivious_lookup_secret<T>(
    table: &[T],
    secret_index: SecretIndex,
    fallback: &T,
) -> SecretScalar<T>
where
    T: ConditionallySelectable + SecureSanitize,
{
    SecretScalar::new(oblivious_lookup(table, secret_index, fallback))
}

/// Conditionally copy `source` into `destination`.
///
/// Lengths are public metadata. When `choice` is false, `destination` is
/// rewritten with its existing bytes; when true, it is rewritten with
/// `source`.
#[inline(never)]
pub fn conditional_copy(
    destination: &mut [u8],
    source: &[u8],
    choice: Choice,
) -> Result<(), crate::LengthError> {
    if destination.len() != source.len() {
        return Err(crate::LengthError {
            expected: destination.len(),
            actual: source.len(),
        });
    }

    let mut index = 0usize;
    while index < destination.len() {
        destination[index] = u8::conditional_select(&destination[index], &source[index], choice);
        index += 1;
    }
    Ok(())
}

/// Conditionally swap two equal-length byte slices.
///
/// Lengths are public metadata. Both slices are visited for the full public
/// length regardless of `choice`.
#[inline(never)]
pub fn conditional_swap(
    left: &mut [u8],
    right: &mut [u8],
    choice: Choice,
) -> Result<(), crate::LengthError> {
    if left.len() != right.len() {
        return Err(crate::LengthError {
            expected: left.len(),
            actual: right.len(),
        });
    }

    let mask = black_box(Mask::<u8>::from_choice(choice).raw());
    let mut index = 0usize;
    while index < left.len() {
        let swap = (left[index] ^ right[index]) & mask;
        left[index] ^= swap;
        right[index] ^= swap;
        index += 1;
    }
    Ok(())
}

/// Select between two equal-length source slices into `destination`.
///
/// Lengths are public metadata. All three slices must have the same public
/// length. Every byte is selected without branching on `choice`.
#[inline(never)]
pub fn select_slice(
    destination: &mut [u8],
    left: &[u8],
    right: &[u8],
    choice: Choice,
) -> Result<(), crate::LengthError> {
    if left.len() != right.len() {
        return Err(crate::LengthError {
            expected: left.len(),
            actual: right.len(),
        });
    }
    if destination.len() != left.len() {
        return Err(crate::LengthError {
            expected: left.len(),
            actual: destination.len(),
        });
    }

    let mut index = 0usize;
    while index < destination.len() {
        destination[index] = u8::conditional_select(&left[index], &right[index], choice);
        index += 1;
    }
    Ok(())
}

#[inline]
fn bytes_eq_equal_len(left: &[u8], right: &[u8]) -> Choice {
    debug_assert_eq!(left.len(), right.len());

    #[cfg(all(
        feature = "asm-compare",
        any(target_arch = "x86_64", target_arch = "aarch64"),
        not(miri)
    ))]
    {
        Choice::from_u8(crate::compare_asm::equal_len_choice_bit(left, right))
    }

    #[cfg(not(all(
        feature = "asm-compare",
        any(target_arch = "x86_64", target_arch = "aarch64"),
        not(miri)
    )))]
    {
        let mut diff = 0u8;
        let mut index = 0usize;
        while index < left.len() {
            diff = black_box(diff | (left[index] ^ right[index]));
            index += 1;
        }

        !Choice::from_u8(black_box(diff))
    }
}

#[inline]
fn byte_lt_bit(left: u8, right: u8) -> u8 {
    ((left as u16).wrapping_sub(right as u16) >> 8) as u8
}

#[inline]
fn byte_eq_bit(left: u8, right: u8) -> u8 {
    let diff = left ^ right;
    (((diff | diff.wrapping_neg()) >> 7) ^ 1) & 1
}

#[inline]
fn ct_cmp_be_bytes(left: &[u8], right: &[u8]) -> CtOrdering {
    debug_assert_eq!(left.len(), right.len());

    let mut less = 0u8;
    let mut greater = 0u8;
    let mut equal_so_far = 1u8;
    let mut index = 0usize;
    while index < left.len() {
        let left_byte = black_box(left[index]);
        let right_byte = black_box(right[index]);
        let left_less = byte_lt_bit(left_byte, right_byte);
        let right_less = byte_lt_bit(right_byte, left_byte);
        less = black_box(less | (equal_so_far & left_less));
        greater = black_box(greater | (equal_so_far & right_less));
        equal_so_far = black_box(equal_so_far & byte_eq_bit(left_byte, right_byte));
        index += 1;
    }

    CtOrdering::from_normalized_bits(
        Choice(black_box(less & 1)),
        Choice(black_box(equal_so_far & 1)),
        Choice(black_box(greater & 1)),
    )
}

impl<const N: usize> ConstantTimeEq for [u8; N] {
    #[inline]
    fn ct_eq(&self, other: &Self) -> Choice {
        eq_fixed(self, other)
    }
}

impl<const N: usize> ConstantTimeOrd for [u8; N] {
    #[inline]
    fn ct_cmp(&self, other: &Self) -> CtOrdering {
        cmp_fixed(self, other)
    }
}

impl ConstantTimeEq for [u8] {
    #[inline]
    fn ct_eq(&self, other: &Self) -> Choice {
        eq_public_len(self, other)
    }
}

impl<const N: usize> ConditionallySelectable for [u8; N] {
    #[inline]
    fn conditional_select(left: &Self, right: &Self, choice: Choice) -> Self {
        let mut output = [0u8; N];
        let mut index = 0usize;
        while index < N {
            output[index] = u8::conditional_select(&left[index], &right[index], choice);
            index += 1;
        }
        output
    }
}

impl<T> PublicValue<PhantomData<T>> {
    /// Construct a public marker value.
    #[inline]
    pub const fn marker() -> Self {
        Self(PhantomData)
    }
}
