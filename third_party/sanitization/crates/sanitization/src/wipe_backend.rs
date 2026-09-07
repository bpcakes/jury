#[cfg(target_arch = "wasm32")]
use core::hint::black_box;
use core::{
    ptr,
    sync::atomic::{compiler_fence, fence, Ordering},
};

mod sealed {
    pub trait Sealed {}
}

/// Internal marker for built-in plain-data representations that remain valid
/// after every byte is overwritten with zero.
///
/// # Safety
///
/// Implementations must be `Copy`, have no destructor, contain no references,
/// pointers, provenance, ownership, or interior mutability, and accept the
/// all-zero representation as a valid live value. This trait is intentionally
/// private and implemented only for the reviewed primitive scalar set.
pub(crate) unsafe trait ZeroValidPlainData: Copy {
    /// A valid value whose complete representation is zero.
    const ZERO: Self;
}

macro_rules! impl_zero_valid_plain_data {
    ($($ty:ty => $zero:expr),+ $(,)?) => {
        $(
            // SAFETY: this primitive is `Copy`, has no destructor, contains no
            // pointer or ownership state, and its all-zero bit pattern is a
            // valid value.
            unsafe impl ZeroValidPlainData for $ty {
                const ZERO: Self = $zero;
            }
        )+
    };
}

impl_zero_valid_plain_data!(
    u8 => 0,
    u16 => 0,
    u32 => 0,
    u64 => 0,
    u128 => 0,
    usize => 0,
    i8 => 0,
    i16 => 0,
    i32 => 0,
    i64 => 0,
    i128 => 0,
    isize => 0,
    bool => false,
    char => '\0',
    f32 => 0.0,
    f64 => 0.0,
);

pub(crate) trait ErasureBackend: sealed::Sealed {
    fn erase(ptr: *mut u8, len: usize);

    #[cfg(feature = "multi-pass-clear")]
    fn fill(ptr: *mut u8, len: usize, value: u8);
}

struct VolatileRam;

impl sealed::Sealed for VolatileRam {}

impl ErasureBackend for VolatileRam {
    #[inline(never)]
    fn erase(ptr: *mut u8, len: usize) {
        ordered_volatile_store(ptr, len, 0);
    }

    #[cfg(feature = "multi-pass-clear")]
    #[inline(never)]
    fn fill(ptr: *mut u8, len: usize, value: u8) {
        ordered_volatile_store(ptr, len, value);
    }
}

#[inline(never)]
pub(crate) fn erase(ptr: *mut u8, len: usize) {
    VolatileRam::erase(ptr, len);
}

#[inline(never)]
pub(crate) fn erase_plain_data<T: ZeroValidPlainData>(value: &mut T) {
    compiler_fence(Ordering::SeqCst);
    // SAFETY: `value` is exclusively borrowed and `T::ZERO` is a valid value
    // with an all-zero representation. A typed volatile write avoids
    // transient invalid representations for validity-constrained primitives
    // such as `char`.
    unsafe {
        ptr::write_volatile(value, T::ZERO);
    }
    compiler_fence(Ordering::SeqCst);
    fence(Ordering::SeqCst);
}

#[cfg(feature = "multi-pass-clear")]
#[inline(never)]
pub(crate) fn erase_multi_pass(ptr: *mut u8, len: usize) {
    VolatileRam::erase(ptr, len);
    VolatileRam::fill(ptr, len, 0xFF);
    VolatileRam::erase(ptr, len);
}

#[cfg(not(target_arch = "wasm32"))]
#[inline(never)]
fn ordered_volatile_store(ptr: *mut u8, len: usize, value: u8) {
    compiler_fence(Ordering::SeqCst);

    let mut offset = 0;
    while offset < len {
        // SAFETY: Callers pass a pointer and length from a live mutable byte
        // slice, a `MaybeUninit<T>` slice, or the full capacity of an owned
        // contiguous allocation. Each computed address is allocated and
        // writable for a single byte, including spare or uninitialized
        // capacity, and is never read through this pointer.
        unsafe {
            ptr::write_volatile(ptr.add(offset), value);
        }
        offset += 1;
    }

    compiler_fence(Ordering::SeqCst);
    // CP-10 retains the 1.x hardware-ordering boundary. Reducing this fence
    // requires target-specific codegen, native evidence, and external review.
    fence(Ordering::SeqCst);
}

#[cfg(target_arch = "wasm32")]
#[inline(never)]
fn ordered_volatile_store(ptr: *mut u8, len: usize, value: u8) {
    compiler_fence(Ordering::SeqCst);
    let store: fn(*mut u8, usize, u8) = wasm_volatile_store_impl;
    black_box(store)(ptr, len, value);
    compiler_fence(Ordering::SeqCst);
    fence(Ordering::SeqCst);
}

#[cfg(target_arch = "wasm32")]
#[inline(never)]
fn wasm_volatile_store_impl(ptr: *mut u8, len: usize, value: u8) {
    let mut offset = 0;
    while offset < len {
        // SAFETY: Same pointer validity contract as
        // `ordered_volatile_store`.
        unsafe {
            ptr::write_volatile(ptr.add(offset), value);
        }
        offset += 1;
    }
}
