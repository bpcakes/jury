use core::{
    fmt,
    ptr::NonNull,
    sync::atomic::{compiler_fence, AtomicBool, AtomicUsize, Ordering},
};

#[cfg(feature = "canary-check")]
use core::cell::Cell;

#[cfg(all(test, feature = "std", target_os = "linux"))]
unsafe extern "C" {
    fn fork() -> i32;
    fn waitpid(pid: i32, status: *mut i32, options: i32) -> i32;
    fn _exit(status: i32) -> !;
}

use super::{
    protection::replacement_request_preserving_established, CanaryCorruptedError, ForkPolicy,
    ForkProtectionRequest, ProtectedSecretFillError, ProtectionControl, ProtectionError,
    ProtectionFailure, ProtectionReport, ProtectionRequest, ProtectionState, Requirement,
    RollbackReport, RollbackState, SecretIntegrityError, SecretPoolReport, SecretPoolSlotId,
};

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
use core::arch::asm;
#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "android",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly",
))]
use core::ffi::c_int;
#[cfg(not(target_os = "linux"))]
use core::ffi::c_void;
#[cfg(target_os = "windows")]
use core::mem::MaybeUninit;

// Linux x86_64 has 4 KiB base pages for supported targets. Linux aarch64
// is detected at runtime from auxv and falls back to 64 KiB.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const LINUX_PAGE_GRANULE: usize = 4096;

#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "android",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly",
))]
const UNIX_FALLBACK_PAGE_GRANULE: usize = 4096;

#[cfg(target_os = "windows")]
const WINDOWS_FALLBACK_PAGE_GRANULE: usize = 4096;

#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "android",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly",
))]
const PROT_READ: usize = 0x1;
#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "android",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly",
))]
const PROT_WRITE: usize = 0x2;
#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "android",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly",
))]
const MAP_PRIVATE: usize = 0x02;
#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly",
))]
const MAP_ANONYMOUS: usize = 0x1000;
#[cfg(target_os = "android")]
const MAP_ANONYMOUS: usize = 0x20;
#[cfg(target_os = "freebsd")]
const MADV_NOCORE: i32 = 8;

#[cfg(target_os = "linux")]
const PROT_READ: usize = 0x1;
#[cfg(target_os = "linux")]
const PROT_WRITE: usize = 0x2;
#[cfg(target_os = "linux")]
const MAP_PRIVATE: usize = 0x02;
#[cfg(target_os = "linux")]
const MAP_ANONYMOUS: usize = 0x20;
#[cfg(target_os = "linux")]
const MAP_FD_ANONYMOUS: usize = (-1isize) as usize;
#[cfg(target_os = "linux")]
const MADV_DONTFORK: usize = 10;
#[cfg(target_os = "linux")]
const MADV_DONTDUMP: usize = 16;
#[cfg(target_os = "linux")]
const MADV_WIPEONFORK: usize = 18;

#[cfg(target_os = "windows")]
const MEM_COMMIT: u32 = 0x1000;
#[cfg(target_os = "windows")]
const MEM_RESERVE: u32 = 0x2000;
#[cfg(target_os = "windows")]
const MEM_RELEASE: u32 = 0x8000;
#[cfg(target_os = "windows")]
const PAGE_READWRITE: u32 = 0x04;

#[cfg(feature = "canary-check")]
const CANARY_SIZE: usize = 8;
#[cfg(all(feature = "canary-check", not(feature = "random-canary")))]
const CANARY_MASK: u64 = 0xDEAD_BEEF_CAFE_BABE;
#[cfg(all(feature = "canary-check", not(feature = "random-canary")))]
const CANARY_GENERATION_MIX: u64 = 0xD6E8_FEB8_6659_FD93;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const SYS_MMAP: usize = 9;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const SYS_MUNMAP: usize = 11;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const SYS_MADVISE: usize = 28;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const SYS_MLOCK: usize = 149;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const SYS_MUNLOCK: usize = 150;

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
const SYS_MMAP: usize = 222;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
const SYS_MUNMAP: usize = 215;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
const SYS_MADVISE: usize = 233;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
const SYS_MLOCK: usize = 228;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
const SYS_MUNLOCK: usize = 229;

#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "android",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly",
))]
unsafe extern "C" {
    fn getpagesize() -> i32;
    fn mmap(
        addr: *mut c_void,
        len: usize,
        prot: i32,
        flags: i32,
        fd: i32,
        offset: isize,
    ) -> *mut c_void;
    fn munmap(addr: *mut c_void, len: usize) -> i32;
    fn mlock(addr: *const c_void, len: usize) -> i32;
    fn munlock(addr: *const c_void, len: usize) -> i32;
    #[cfg(target_os = "freebsd")]
    fn madvise(addr: *mut c_void, len: usize, advice: i32) -> i32;

    #[cfg_attr(
        any(target_os = "macos", target_os = "ios", target_os = "freebsd"),
        link_name = "__error"
    )]
    #[cfg_attr(
        any(target_os = "android", target_os = "openbsd", target_os = "netbsd"),
        link_name = "__errno"
    )]
    #[cfg_attr(target_os = "dragonfly", link_name = "__errno_location")]
    fn errno_location() -> *mut c_int;
}

#[cfg(target_os = "windows")]
#[repr(C)]
struct SystemInfo {
    processor_architecture: u16,
    reserved: u16,
    page_size: u32,
    minimum_application_address: *mut c_void,
    maximum_application_address: *mut c_void,
    active_processor_mask: usize,
    number_of_processors: u32,
    processor_type: u32,
    allocation_granularity: u32,
    processor_level: u16,
    processor_revision: u16,
}

#[cfg(target_os = "windows")]
#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetLastError() -> u32;
    fn GetSystemInfo(system_info: *mut SystemInfo);
    fn VirtualAlloc(
        address: *mut c_void,
        size: usize,
        allocation_type: u32,
        protect: u32,
    ) -> *mut c_void;
    fn VirtualFree(address: *mut c_void, size: usize, free_type: u32) -> i32;
    fn VirtualLock(address: *mut c_void, size: usize) -> i32;
    fn VirtualUnlock(address: *mut c_void, size: usize) -> i32;
}

/// Platform memory-locking operation that failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemoryLockOperation {
    /// The requested mapping length overflowed.
    Length,
    /// Anonymous mapping creation failed.
    Map,
    /// Core-dump exclusion failed.
    DontDump,
    /// Fork inheritance exclusion failed.
    DontFork,
    /// Child-process wipe-on-fork policy failed.
    WipeOnFork,
    /// Page locking failed.
    Lock,
    /// Page unlocking failed.
    Unlock,
    /// Anonymous mapping release failed.
    Unmap,
    /// Operating-system random canary generation failed.
    Random,
}

/// Error returned by platform memory-locking operations.
///
/// If setup and the subsequent cleanup unmap both fail, the returned error
/// reports `Unmap`. A mapping that may still be live takes diagnostic
/// precedence over the original setup failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MemoryLockError {
    /// Operation that failed.
    pub operation: MemoryLockOperation,
    /// Positive errno or Windows `GetLastError` value when available.
    ///
    /// This is `0` for local arithmetic failures before a syscall.
    /// Negative values are crate-internal sentinel failures, such as an
    /// unsupported random-canary backend or a random backend that made no
    /// progress.
    pub errno: i32,
}

impl fmt::Display for MemoryLockError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "memory lock operation {:?} failed with errno {}",
            self.operation, self.errno
        )
    }
}

#[cfg(feature = "std")]
impl std::error::Error for MemoryLockError {}

impl From<MemoryLockError> for SecretIntegrityError<MemoryLockError> {
    #[inline]
    fn from(error: MemoryLockError) -> Self {
        Self::Operation(error)
    }
}

/// Error returned while initializing locked fixed-size secret storage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LockedSecretInitError {
    /// Mapping, memory policy, locking, or random-canary setup failed.
    Allocation(MemoryLockError),
    /// Canary verification failed before initialization completed.
    Integrity(CanaryCorruptedError),
}

impl fmt::Display for LockedSecretInitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Allocation(error) => error.fmt(formatter),
            Self::Integrity(error) => error.fmt(formatter),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for LockedSecretInitError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Allocation(error) => Some(error),
            Self::Integrity(error) => Some(error),
        }
    }
}

/// Error returned while initializing a locked pool slot from bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PoolInitError {
    /// The caller provided a slice with the wrong length.
    Length(crate::LengthError),
    /// Mapping, memory policy, or random-canary setup failed.
    Allocation(MemoryLockError),
    /// Canary verification failed and the affected slot was quarantined.
    Integrity(CanaryCorruptedError),
}

impl fmt::Display for PoolInitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Length(error) => error.fmt(formatter),
            Self::Allocation(error) => error.fmt(formatter),
            Self::Integrity(error) => error.fmt(formatter),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for PoolInitError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Length(error) => Some(error),
            Self::Allocation(error) => Some(error),
            Self::Integrity(error) => Some(error),
        }
    }
}

/// Error returned when initializing a pool slot with a fallible generator.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecretPoolGenerateError<E> {
    /// Mapping, memory policy, or random-canary setup failed.
    Allocation(MemoryLockError),
    /// Canary verification failed and the affected slot was quarantined.
    Integrity(CanaryCorruptedError),
    /// The caller-provided generator failed.
    Generate(E),
}

impl<E: fmt::Display> fmt::Display for SecretPoolGenerateError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Allocation(error) => error.fmt(formatter),
            Self::Integrity(error) => error.fmt(formatter),
            Self::Generate(error) => write!(formatter, "secret generation failed: {error}"),
        }
    }
}

#[cfg(feature = "std")]
impl<E> std::error::Error for SecretPoolGenerateError<E>
where
    E: std::error::Error + 'static,
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Allocation(error) => Some(error),
            Self::Integrity(error) => Some(error),
            Self::Generate(error) => Some(error),
        }
    }
}

/// Error returned when constructing [`LockedSecretBytes`] from a slice.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LockedSecretBytesError {
    /// The caller provided a slice with the wrong length.
    Length(crate::LengthError),
    /// Platform mapping, core-dump exclusion, locking, unlocking, or
    /// unmapping failed.
    Memory(MemoryLockError),
}

impl fmt::Display for LockedSecretBytesError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Length(error) => error.fmt(formatter),
            Self::Memory(error) => error.fmt(formatter),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for LockedSecretBytesError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Length(error) => Some(error),
            Self::Memory(error) => Some(error),
        }
    }
}

/// Error returned when fallible locked secret byte generation fails.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LockedSecretBytesGenerateError<E> {
    /// Platform mapping, core-dump exclusion, locking, unlocking, or
    /// unmapping failed before generation completed.
    Memory(MemoryLockError),
    /// The caller-provided byte generator failed.
    Generate(E),
}

impl<E: fmt::Display> fmt::Display for LockedSecretBytesGenerateError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Memory(error) => error.fmt(formatter),
            Self::Generate(error) => error.fmt(formatter),
        }
    }
}

#[cfg(feature = "std")]
impl<E> std::error::Error for LockedSecretBytesGenerateError<E>
where
    E: std::error::Error + 'static,
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Memory(error) => Some(error),
            Self::Generate(error) => Some(error),
        }
    }
}

/// Error returned while fallibly filling a new locked fixed-size mapping.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LockedSecretBytesFillError<E> {
    /// Platform mapping, memory-policy, locking, or random-canary setup failed.
    Memory(MemoryLockError),
    /// Canary verification failed before initialization completed.
    Integrity(CanaryCorruptedError),
    /// The caller-provided initializer failed.
    Generate(E),
}

impl<E: fmt::Display> fmt::Display for LockedSecretBytesFillError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Memory(error) => error.fmt(formatter),
            Self::Integrity(error) => error.fmt(formatter),
            Self::Generate(error) => write!(formatter, "secret initialization failed: {error}"),
        }
    }
}

#[cfg(feature = "std")]
impl<E> std::error::Error for LockedSecretBytesFillError<E>
where
    E: std::error::Error + 'static,
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Memory(error) => Some(error),
            Self::Integrity(error) => Some(error),
            Self::Generate(error) => Some(error),
        }
    }
}

/// Error returned while initializing an existing locked fixed-size mapping.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LockedSecretInitializeError<E> {
    /// Canary verification failed before or after the initializer ran.
    Integrity(CanaryCorruptedError),
    /// The caller-provided initializer failed.
    Generate(E),
}

impl<E: fmt::Display> fmt::Display for LockedSecretInitializeError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Integrity(error) => error.fmt(formatter),
            Self::Generate(error) => write!(formatter, "secret initialization failed: {error}"),
        }
    }
}

#[cfg(feature = "std")]
impl<E> std::error::Error for LockedSecretInitializeError<E>
where
    E: std::error::Error + 'static,
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Integrity(error) => Some(error),
            Self::Generate(error) => Some(error),
        }
    }
}

type LockedSecretBytesCheckedCopyError = SecretIntegrityError<crate::LengthError>;

impl From<crate::LengthError> for LockedSecretBytesError {
    #[inline]
    fn from(error: crate::LengthError) -> Self {
        Self::Length(error)
    }
}

impl From<MemoryLockError> for LockedSecretBytesError {
    #[inline]
    fn from(error: MemoryLockError) -> Self {
        Self::Memory(error)
    }
}

impl<E> From<MemoryLockError> for LockedSecretBytesGenerateError<E> {
    #[inline]
    fn from(error: MemoryLockError) -> Self {
        Self::Memory(error)
    }
}

/// Fixed-size secret bytes stored in a private locked platform mapping.
///
/// This type is available with the `memory-lock` feature on supported
/// Linux, Android, macOS, iOS, Windows, and BSD targets. Linux uses raw
/// syscalls with `mmap`, `MADV_DONTDUMP`, `MADV_DONTFORK`, and `mlock`.
/// Android, macOS, iOS, and BSD use system `mmap`/`mlock` entry points.
/// Windows uses `VirtualAlloc`/`VirtualLock`. Every backend volatile-clears
/// the full mapping before unlocking and releasing it.
///
/// With the `canary-check` feature enabled, non-empty locked mappings store
/// an 8-byte prefix canary and 8-byte suffix canary around the secret data.
/// Existing exposure APIs verify those canaries before use and fail closed
/// by clearing the mapping and panicking if corruption is detected. Checked
/// APIs return [`CanaryCorruptedError`] instead.
///
/// The secret bytes are not stored inline in the Rust value. Moving this
/// type only moves pointer metadata, so ordinary Rust moves do not copy the
/// secret byte array itself.
pub struct LockedSecretBytes<const N: usize> {
    ptr: NonNull<u8>,
    map_len: usize,
    locked: bool,
    request: ProtectionRequest,
    report: ProtectionReport,
    #[cfg(feature = "canary-check")]
    poisoned: Cell<bool>,
    #[cfg(feature = "random-canary")]
    canary: crate::canary::CanaryMaterial,
}

// SAFETY: The value exclusively owns a private mapping. Moving ownership to
// another thread does not invalidate the mapping, and mutation/clearing
// still requires `&mut self`. `Sync` is intentionally not implemented.
unsafe impl<const N: usize> Send for LockedSecretBytes<N> {}

impl<const N: usize> LockedSecretBytes<N> {
    /// Allocate locked zeroed storage for `N` bytes.
    #[inline]
    pub fn zeroed() -> Result<Self, MemoryLockError> {
        Self::zeroed_with_protection(ProtectionRequest::locked())
            .map_err(protection_error_as_memory_lock)
    }

    /// Allocate zeroed storage with the `profile-hardened-native` policy.
    ///
    /// Memory locking and canaries are required. Dump and fork exclusion are
    /// preferred, so inspect [`LockedSecretBytes::protection_report`] before
    /// relying on those controls.
    #[cfg(feature = "profile-hardened-native")]
    #[inline]
    pub fn zeroed_hardened_native() -> Result<Self, ProtectionError> {
        Self::zeroed_with_protection(ProtectionRequest::profile_hardened_native())
    }

    /// Allocate zeroed storage with the `profile-hardened-linux` policy.
    ///
    /// Memory locking, canaries, and Linux fork exclusion are required. Dump
    /// exclusion remains preferred and is reported at runtime.
    #[cfg(feature = "profile-hardened-linux")]
    #[inline]
    pub fn zeroed_hardened_linux() -> Result<Self, ProtectionError> {
        Self::zeroed_with_protection(ProtectionRequest::profile_hardened_linux())
    }

    /// Allocate zeroed storage under an explicit runtime protection policy.
    ///
    /// Preferred controls may fail while construction succeeds. Call
    /// [`LockedSecretBytes::protection_report`] before relying on them.
    #[inline]
    pub fn zeroed_with_protection(request: ProtectionRequest) -> Result<Self, ProtectionError> {
        if N == 0 {
            let report = empty_native_report(request, N, false)?;
            return Ok(Self {
                ptr: NonNull::dangling(),
                map_len: 0,
                locked: false,
                request,
                report,
                #[cfg(feature = "canary-check")]
                poisoned: Cell::new(false),
                #[cfg(feature = "random-canary")]
                canary: crate::canary::CanaryMaterial::zeroed(),
            });
        }

        #[cfg(feature = "random-canary")]
        let canary = random_canary_value().map_err(|error| {
            pre_mapping_error(request, N, ProtectionControl::Canary, error.errno, false)
        })?;

        let payload_len = Self::mapping_payload_len().map_err(|error| {
            pre_mapping_error(request, N, ProtectionControl::Mapping, error.errno, false)
        })?;
        let map_len = rounded_mapping_len(payload_len).map_err(|error| {
            pre_mapping_error(request, N, ProtectionControl::Mapping, error.errno, false)
        })?;
        let setup = setup_native_mapping(map_len, N, request, false)?;

        let mut secret = Self {
            ptr: setup.ptr,
            map_len,
            locked: setup.locked,
            request,
            report: setup.report,
            #[cfg(feature = "canary-check")]
            poisoned: Cell::new(false),
            #[cfg(feature = "random-canary")]
            canary,
        };
        secret.write_canaries();
        Ok(secret)
    }

    /// Actual runtime protections established for this allocation.
    #[must_use]
    #[inline]
    pub const fn protection_report(&self) -> &ProtectionReport {
        &self.report
    }

    /// Runtime protection policy requested for this allocation.
    #[must_use]
    #[inline]
    pub const fn protection_request(&self) -> ProtectionRequest {
        self.request
    }

    /// Returns true when the current mapping is locked against ordinary paging.
    #[must_use]
    #[inline]
    pub const fn is_memory_locked(&self) -> bool {
        self.locked
    }

    /// Allocate locked storage, copy an array into it, then clear this
    /// function's owned array parameter with the crate's volatile wipe backend.
    /// Other copies retained by the caller are outside this guarantee.
    #[inline]
    pub fn from_array(mut bytes: [u8; N]) -> Result<Self, LockedSecretInitError> {
        Self::from_array_buffer(&mut bytes)
    }

    #[inline]
    fn from_array_buffer(bytes: &mut [u8; N]) -> Result<Self, LockedSecretInitError> {
        let result = Self::zeroed()
            .map_err(LockedSecretInitError::Allocation)
            .and_then(|mut secret| {
                secret
                    .try_copy_from_array(bytes)
                    .map_err(LockedSecretInitError::Integrity)?;
                Ok(secret)
            });
        crate::wipe::bytes(bytes);
        result
    }

    #[cfg(all(
        test,
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64"),
        not(miri)
    ))]
    #[inline]
    pub(crate) fn from_array_buffer_for_test(
        bytes: &mut [u8; N],
    ) -> Result<Self, LockedSecretInitError> {
        Self::from_array_buffer(bytes)
    }

    /// Allocate locked storage and copy bytes from a same-length slice.
    ///
    /// This is the preferred constructor when the secret is already held in
    /// a runtime buffer. It creates the private mapping, applies
    /// OS-specific dump or fork-exclusion policies are applied where the
    /// backend supports them, and the mapping is locked before copying
    /// bytes into it. The source slice is borrowed and cannot be cleared by
    /// this function.
    #[inline]
    pub fn from_slice(source: &[u8]) -> Result<Self, LockedSecretBytesError> {
        if source.len() != N {
            return Err(crate::LengthError {
                expected: N,
                actual: source.len(),
            }
            .into());
        }

        let mut secret = Self::zeroed()?;
        secret.as_mut_slice().copy_from_slice(source);
        compiler_fence(Ordering::SeqCst);
        Ok(secret)
    }

    /// Allocate locked storage and produce each byte directly into it.
    ///
    /// This avoids requiring a full temporary `[u8; N]` or input slice at
    /// the call boundary. The private mapping is created, marked with
    /// locked before `make_byte` is called.
    #[inline]
    pub fn from_fn(mut make_byte: impl FnMut(usize) -> u8) -> Result<Self, MemoryLockError> {
        let mut secret = Self::zeroed()?;
        compiler_fence(Ordering::SeqCst);
        let mut index = 0;
        while index < N {
            secret.as_mut_slice()[index] = make_byte(index);
            index += 1;
        }
        compiler_fence(Ordering::SeqCst);
        Ok(secret)
    }

    /// Allocate locked storage and fallibly produce each byte directly into
    /// it.
    ///
    /// The private mapping is created, dump-excluded, fork-excluded, and
    /// locked before `make_byte` is called. If generation fails, partial
    /// bytes already written into the mapping are cleared before the error
    /// is returned.
    #[inline]
    pub fn try_from_fn<E>(
        mut make_byte: impl FnMut(usize) -> Result<u8, E>,
    ) -> Result<Self, LockedSecretBytesGenerateError<E>> {
        let mut secret = Self::zeroed()?;
        compiler_fence(Ordering::SeqCst);
        let mut index = 0;
        while index < N {
            match make_byte(index) {
                Ok(byte) => secret.as_mut_slice()[index] = byte,
                Err(error) => {
                    secret.secure_clear();
                    return Err(LockedSecretBytesGenerateError::Generate(error));
                }
            }
            index += 1;
        }
        compiler_fence(Ordering::SeqCst);
        Ok(secret)
    }

    /// Allocate locked storage and fill the full fixed-size payload in
    /// place.
    ///
    /// This is intended for decoder, KDF, RNG, or protocol APIs that can
    /// write into a caller-provided output buffer. The private mapping is
    /// created, dump-excluded, fork-excluded where supported, and locked
    /// before `fill` receives the mutable payload. No intermediate
    /// unlocked `Vec` or stack array is required by this API.
    #[inline]
    pub fn from_fill(fill: impl FnOnce(&mut [u8; N])) -> Result<Self, LockedSecretInitError> {
        let secret = Self::zeroed().map_err(LockedSecretInitError::Allocation)?;
        match secret.try_init_with(|output| {
            fill(output);
            Ok::<(), core::convert::Infallible>(())
        }) {
            Ok(secret) => Ok(secret),
            Err(LockedSecretInitializeError::Integrity(error)) => {
                Err(LockedSecretInitError::Integrity(error))
            }
            Err(LockedSecretInitializeError::Generate(error)) => match error {},
        }
    }

    /// Fallible variant of [`LockedSecretBytes::from_fill`].
    ///
    /// If `fill` returns an error, partial bytes already written into the
    /// locked mapping are volatile-cleared before the error is returned.
    #[inline]
    pub fn try_from_fill<E>(
        fill: impl FnOnce(&mut [u8; N]) -> Result<(), E>,
    ) -> Result<Self, LockedSecretBytesFillError<E>> {
        let secret = Self::zeroed().map_err(LockedSecretBytesFillError::Memory)?;
        secret.try_init_with(fill).map_err(|error| match error {
            LockedSecretInitializeError::Integrity(error) => {
                LockedSecretBytesFillError::Integrity(error)
            }
            LockedSecretInitializeError::Generate(error) => {
                LockedSecretBytesFillError::Generate(error)
            }
        })
    }

    /// Initialize an existing fixed-size locked mapping in place.
    ///
    /// This is useful after selecting a custom protection policy with
    /// [`LockedSecretBytes::zeroed_with_protection`]. The configured integrity
    /// check runs before and after `initialize`; with `canary-check`, both
    /// canary regions are verified. A generator error or integrity failure
    /// clears the mapping before it is dropped. Panic unwinding also reaches
    /// the value's clear-on-drop fallback.
    ///
    /// ```no_run
    /// use sanitization::{LockedSecretBytes, ProtectionRequest};
    ///
    /// let request = ProtectionRequest::locked();
    /// let secret = LockedSecretBytes::<32>::zeroed_with_protection(request)
    ///     .expect("required memory protection must be available")
    ///     .try_init_with(|output| {
    ///         output.fill(0x42);
    ///         Ok::<(), ()>(())
    ///     })
    ///     .expect("in-place initialization must succeed");
    ///
    /// assert_eq!(secret.try_constant_time_eq(&[0x42; 32]), Ok(true));
    /// ```
    pub fn try_init_with<E>(
        mut self,
        initialize: impl FnOnce(&mut [u8; N]) -> Result<(), E>,
    ) -> Result<Self, LockedSecretInitializeError<E>> {
        self.verify_integrity()
            .map_err(LockedSecretInitializeError::Integrity)?;
        compiler_fence(Ordering::SeqCst);
        if let Err(error) = initialize(self.as_mut_array()) {
            self.secure_clear();
            return Err(LockedSecretInitializeError::Generate(error));
        }
        compiler_fence(Ordering::SeqCst);
        self.verify_integrity()
            .map_err(LockedSecretInitializeError::Integrity)?;
        Ok(self)
    }

    /// Number of secret bytes stored in the locked mapping.
    #[must_use]
    #[inline]
    pub const fn len(&self) -> usize {
        N
    }

    /// Returns true when the locked secret has zero length.
    #[must_use]
    #[inline]
    pub const fn is_empty(&self) -> bool {
        N == 0
    }

    /// Replace all secret bytes from a same-length slice.
    #[inline]
    pub fn try_copy_from_slice(
        &mut self,
        source: &[u8],
    ) -> Result<(), SecretIntegrityError<crate::LengthError>> {
        if source.len() != N {
            return Err(SecretIntegrityError::Operation(crate::LengthError {
                expected: N,
                actual: source.len(),
            }));
        }

        self.verify_integrity()?;
        self.as_mut_slice().copy_from_slice(source);
        compiler_fence(Ordering::SeqCst);
        Ok(())
    }

    #[inline]
    fn try_copy_from_array(&mut self, source: &[u8; N]) -> Result<(), CanaryCorruptedError> {
        self.verify_integrity()?;
        self.as_mut_slice().copy_from_slice(source);
        compiler_fence(Ordering::SeqCst);
        Ok(())
    }

    /// Replace all secret bytes from a same-length slice.
    ///
    /// The replacement bytes are copied into a fresh locked mapping before
    /// the old mapping is cleared and swapped out. If mapping setup fails,
    /// the old locked value remains unchanged.
    #[inline]
    pub fn try_replace_from_slice(
        &mut self,
        source: &[u8],
    ) -> Result<(), SecretIntegrityError<LockedSecretBytesError>> {
        self.verify_integrity()?;
        if source.len() != N {
            return Err(SecretIntegrityError::Operation(
                crate::LengthError {
                    expected: N,
                    actual: source.len(),
                }
                .into(),
            ));
        }
        let mut replacement = self
            .replacement_zeroed()
            .map_err(LockedSecretBytesError::Memory)
            .map_err(SecretIntegrityError::Operation)?;
        replacement.as_mut_slice().copy_from_slice(source);
        compiler_fence(Ordering::SeqCst);
        self.secure_clear();
        core::mem::swap(self, &mut replacement);
        Ok(())
    }

    /// Replace all secret bytes from a same-length slice, panicking on any
    /// integrity, length, or mapping error.
    #[inline]
    pub fn replace_from_slice_or_panic(&mut self, source: &[u8]) {
        self.try_replace_from_slice(source)
            .unwrap_or_else(|_| panic!("locked secret replacement failed"));
    }

    /// Replace all secret bytes from an owned array, then volatile-clear
    /// that input array.
    ///
    /// The replacement bytes are copied into a fresh locked mapping before
    /// the old mapping is cleared and swapped out. If mapping setup fails,
    /// the owned input array is still cleared and the old locked value
    /// remains unchanged.
    #[inline]
    pub fn try_replace_from_array(
        &mut self,
        mut bytes: [u8; N],
    ) -> Result<(), SecretIntegrityError<MemoryLockError>> {
        if let Err(error) = self.verify_integrity() {
            crate::wipe::bytes(&mut bytes);
            return Err(error.into());
        }
        let mut replacement = match self.replacement_zeroed() {
            Ok(replacement) => replacement,
            Err(error) => {
                crate::wipe::bytes(&mut bytes);
                return Err(SecretIntegrityError::Operation(error));
            }
        };
        replacement.as_mut_slice().copy_from_slice(&bytes);
        crate::wipe::bytes(&mut bytes);
        self.secure_clear();
        core::mem::swap(self, &mut replacement);
        Ok(())
    }

    /// Replace all secret bytes with generated bytes.
    ///
    /// The replacement bytes are generated into a fresh locked mapping
    /// before the old mapping is cleared and swapped out. If `make_byte`
    /// panics, the old locked value remains unchanged and partial generated
    /// bytes are cleared during unwinding.
    #[inline]
    pub fn try_replace_from_fn(
        &mut self,
        make_byte: impl FnMut(usize) -> u8,
    ) -> Result<(), SecretIntegrityError<MemoryLockError>> {
        self.verify_integrity()?;
        let mut replacement = self
            .replacement_zeroed()
            .map_err(SecretIntegrityError::Operation)?;
        let mut make_byte = make_byte;
        let mut index = 0;
        while index < N {
            replacement.as_mut_slice()[index] = make_byte(index);
            index += 1;
        }
        compiler_fence(Ordering::SeqCst);
        self.secure_clear();
        core::mem::swap(self, &mut replacement);
        Ok(())
    }

    /// Replace all secret bytes with fallibly generated bytes.
    ///
    /// The replacement bytes are generated into a fresh locked mapping
    /// before the old mapping is cleared and swapped out. If mapping setup
    /// or generation fails, the old locked value remains unchanged and
    /// partial generated bytes are cleared before the error is returned.
    #[inline]
    pub fn try_replace_from_fallible_fn<E>(
        &mut self,
        make_byte: impl FnMut(usize) -> Result<u8, E>,
    ) -> Result<(), SecretIntegrityError<LockedSecretBytesGenerateError<E>>> {
        self.verify_integrity()?;
        let mut replacement = self
            .replacement_zeroed()
            .map_err(LockedSecretBytesGenerateError::Memory)
            .map_err(SecretIntegrityError::Operation)?;
        let mut make_byte = make_byte;
        let mut index = 0;
        while index < N {
            match make_byte(index) {
                Ok(byte) => replacement.as_mut_slice()[index] = byte,
                Err(error) => {
                    replacement.secure_clear();
                    return Err(SecretIntegrityError::Operation(
                        LockedSecretBytesGenerateError::Generate(error),
                    ));
                }
            }
            index += 1;
        }
        compiler_fence(Ordering::SeqCst);
        self.secure_clear();
        core::mem::swap(self, &mut replacement);
        Ok(())
    }

    /// Replace all secret bytes by filling a fresh locked mapping in
    /// place.
    #[inline]
    pub fn try_replace_from_fill(
        &mut self,
        fill: impl FnOnce(&mut [u8; N]),
    ) -> Result<(), SecretIntegrityError<MemoryLockError>> {
        self.verify_integrity()?;
        let mut replacement = self
            .replacement_zeroed()
            .map_err(SecretIntegrityError::Operation)?;
        compiler_fence(Ordering::SeqCst);
        fill(replacement.as_mut_array());
        compiler_fence(Ordering::SeqCst);
        replacement.verify_integrity()?;
        self.secure_clear();
        core::mem::swap(self, &mut replacement);
        Ok(())
    }

    /// Fallible variant of [`LockedSecretBytes::try_replace_from_fill`].
    #[inline]
    pub fn try_replace_from_fallible_fill<E>(
        &mut self,
        fill: impl FnOnce(&mut [u8; N]) -> Result<(), E>,
    ) -> Result<(), SecretIntegrityError<LockedSecretBytesGenerateError<E>>> {
        self.verify_integrity()?;
        let mut replacement = self
            .replacement_zeroed()
            .map_err(LockedSecretBytesGenerateError::Memory)
            .map_err(SecretIntegrityError::Operation)?;
        compiler_fence(Ordering::SeqCst);
        if let Err(error) = fill(replacement.as_mut_array()) {
            replacement.secure_clear();
            return Err(SecretIntegrityError::Operation(
                LockedSecretBytesGenerateError::Generate(error),
            ));
        }
        compiler_fence(Ordering::SeqCst);
        replacement.verify_integrity()?;
        self.secure_clear();
        core::mem::swap(self, &mut replacement);
        Ok(())
    }

    fn replacement_zeroed(&self) -> Result<Self, MemoryLockError> {
        let request = self.request;
        let replacement_request =
            replacement_request_preserving_established(request, &self.report, N);
        let mut replacement = Self::zeroed_with_protection(replacement_request)
            .map_err(protection_error_as_memory_lock)?;
        replacement.request = request;
        Ok(replacement)
    }

    /// Fill a caller-provided destination with a copy of the secret bytes.
    #[inline]
    pub fn try_copy_to_slice(
        &self,
        destination: &mut [u8],
    ) -> Result<(), LockedSecretBytesCheckedCopyError> {
        if destination.len() != N {
            return Err(SecretIntegrityError::Operation(crate::LengthError {
                expected: N,
                actual: destination.len(),
            }));
        }

        self.verify_integrity()?;
        destination.copy_from_slice(self.as_slice());
        compiler_fence(Ordering::SeqCst);
        core::hint::black_box(destination);
        Ok(())
    }

    /// Run a closure with read-only access to the locked secret bytes.
    ///
    /// The closure can still copy bytes elsewhere. Keep usage limited to
    /// cryptographic or protocol boundaries that genuinely need raw bytes.
    #[inline]
    pub fn try_expose_secret<R>(
        &self,
        inspect: impl FnOnce(&[u8; N]) -> R,
    ) -> Result<R, CanaryCorruptedError> {
        self.verify_integrity()?;
        let result = inspect(self.as_array());
        self.verify_integrity()?;
        Ok(result)
    }

    /// Verify integrity, copy into temporary stack storage, and expose the copy.
    ///
    /// The temporary is volatile-cleared on normal return and unwinding. It
    /// cannot be cleared if the process aborts.
    #[inline]
    pub fn try_expose_secret_copy<R>(
        &self,
        inspect: impl FnOnce(&[u8; N]) -> R,
    ) -> Result<R, CanaryCorruptedError> {
        self.verify_integrity()?;
        Ok(crate::owned::expose_array_copy(self.as_array(), inspect))
    }

    /// Verify locked mapping canaries.
    ///
    /// If corruption is detected, the full mapping is immediately
    /// volatile-cleared because the secret can no longer be trusted.
    #[inline]
    pub fn verify_integrity(&self) -> Result<(), CanaryCorruptedError> {
        #[cfg(not(feature = "canary-check"))]
        {
            return Ok(());
        }
        #[cfg(feature = "canary-check")]
        if !self.poisoned.get() && self.canaries_intact() {
            Ok(())
        } else {
            self.clear_after_canary_failure();
            Err(CanaryCorruptedError)
        }
    }

    /// Compare against a slice without early exit for equal-length inputs.
    ///
    /// Length mismatch returns immediately because the provided slice length
    /// is treated as public metadata.
    ///
    /// The portable fallback is intended to avoid data-dependent early
    /// exit, but it is not a formal hardware-level constant-time
    /// guarantee. On x86_64 or AArch64, enable `asm-compare` for a
    /// stronger compiler boundary.
    #[inline]
    pub fn try_constant_time_eq(&self, other: &[u8]) -> Result<bool, CanaryCorruptedError> {
        self.verify_integrity()?;
        Ok(crate::constant_time_eq_slices(self.as_slice(), other))
    }

    /// Run a closure with read-only access, panicking on canary corruption.
    #[inline]
    pub fn expose_secret_or_panic<R>(&self, inspect: impl FnOnce(&[u8; N]) -> R) -> R {
        self.try_expose_secret(inspect)
            .unwrap_or_else(|_| panic!("locked secret canary corrupted"))
    }

    /// Expose a temporary copy, panicking on canary corruption.
    #[inline]
    pub fn expose_secret_copy_or_panic<R>(&self, inspect: impl FnOnce(&[u8; N]) -> R) -> R {
        self.try_expose_secret_copy(inspect)
            .unwrap_or_else(|_| panic!("locked secret canary corrupted"))
    }

    /// Compare, panicking on canary corruption.
    #[must_use]
    #[inline]
    pub fn constant_time_eq_or_panic(&self, other: &[u8]) -> bool {
        self.try_constant_time_eq(other)
            .unwrap_or_else(|_| panic!("locked secret canary corrupted"))
    }

    /// Clear the full private mapping with volatile writes.
    #[inline(never)]
    pub fn secure_clear(&mut self) {
        if self.map_len != 0 {
            crate::wipe_backend::erase(self.ptr.as_ptr(), self.map_len);
        }
        self.write_canaries();
    }

    /// Consume this value after first clearing the full private mapping.
    ///
    /// Drop still runs after this method returns, so the mapping is
    /// unlocked and unmapped normally.
    #[inline]
    pub fn into_cleared(mut self) {
        self.secure_clear();
    }

    /// Clear the full private mapping with volatile writes, then flush the
    /// cache lines covering that mapping.
    #[cfg(feature = "cache-flush")]
    #[inline(never)]
    pub fn try_secure_clear_and_flush(
        &mut self,
    ) -> Result<crate::cache_flush::CacheFlushReport, crate::cache_flush::CacheFlushError> {
        self.secure_clear();
        crate::cache_flush::flush_cache_lines(self.as_mapping_slice())
    }

    #[inline]
    fn as_slice(&self) -> &[u8] {
        // SAFETY: `data_ptr` either points to `N` live secret bytes owned
        // by this value, or is dangling with `N == 0`.
        unsafe { core::slice::from_raw_parts(self.data_ptr(), N) }
    }

    #[cfg(feature = "cache-flush")]
    #[inline]
    fn as_mapping_slice(&self) -> &[u8] {
        // SAFETY: `ptr` either points to a live mapping of `map_len` bytes
        // owned by this value, or is dangling with `map_len == 0`.
        unsafe { core::slice::from_raw_parts(self.ptr.as_ptr(), self.map_len) }
    }

    #[inline]
    fn as_mut_slice(&mut self) -> &mut [u8] {
        // SAFETY: `&mut self` gives exclusive access to the live mapping,
        // and the mapping is at least `N` bytes long when `N > 0`.
        unsafe { core::slice::from_raw_parts_mut(self.data_ptr(), N) }
    }

    #[inline]
    fn as_mut_array(&mut self) -> &mut [u8; N] {
        // SAFETY: `data_ptr` is valid for exactly `N` payload bytes owned
        // by this value for the duration of `&mut self`.
        unsafe { &mut *(self.data_ptr() as *mut [u8; N]) }
    }

    #[inline]
    fn as_array(&self) -> &[u8; N] {
        // SAFETY: `as_slice` is exactly `N` bytes long, and the pointer is
        // valid for a `[u8; N]` reference for the duration of `&self`.
        unsafe { &*(self.data_ptr() as *const [u8; N]) }
    }

    #[cfg(all(feature = "canary-check", not(feature = "random-canary")))]
    #[inline]
    fn canary_value(&self) -> [u8; CANARY_SIZE] {
        ((self.ptr.as_ptr() as u64) ^ CANARY_MASK).to_ne_bytes()
    }

    #[cfg(feature = "random-canary")]
    #[inline]
    fn with_canary<R>(&self, use_canary: impl FnOnce(&[u8; CANARY_SIZE]) -> R) -> R {
        use_canary(self.canary.as_bytes())
    }

    #[cfg(all(feature = "canary-check", not(feature = "random-canary")))]
    #[inline]
    fn with_canary<R>(&self, use_canary: impl FnOnce(&[u8; CANARY_SIZE]) -> R) -> R {
        let canary = self.canary_value();
        use_canary(&canary)
    }

    #[cfg(feature = "canary-check")]
    #[inline]
    fn canaries_intact(&self) -> bool {
        if self.map_len == 0 {
            return true;
        }

        let Some(suffix_offset) = Self::suffix_offset() else {
            return false;
        };
        // SAFETY: With `map_len != 0`, construction allocated at least
        // `CANARY_SIZE + N + CANARY_SIZE` bytes before page rounding.
        let prefix = unsafe { core::slice::from_raw_parts(self.ptr.as_ptr(), CANARY_SIZE) };
        // SAFETY: `suffix_offset` was checked from the same payload layout,
        // so the suffix canary is inside the live mapping.
        let suffix = unsafe {
            core::slice::from_raw_parts(self.ptr.as_ptr().add(suffix_offset), CANARY_SIZE)
        };

        self.with_canary(|expected| {
            crate::constant_time_eq_slices(prefix, expected)
                & crate::constant_time_eq_slices(suffix, expected)
        })
    }

    #[cfg(feature = "canary-check")]
    #[inline]
    fn write_canaries(&mut self) {
        if self.map_len == 0 {
            return;
        }

        let Some(suffix_offset) = Self::suffix_offset() else {
            return;
        };
        self.with_canary(|canary| {
            // SAFETY: With `map_len != 0`, construction allocated at least
            // `CANARY_SIZE + N + CANARY_SIZE` bytes before page rounding.
            unsafe {
                core::ptr::copy_nonoverlapping(canary.as_ptr(), self.ptr.as_ptr(), CANARY_SIZE);
                core::ptr::copy_nonoverlapping(
                    canary.as_ptr(),
                    self.ptr.as_ptr().add(suffix_offset),
                    CANARY_SIZE,
                );
            }
        });
        compiler_fence(Ordering::SeqCst);
    }

    #[cfg(not(feature = "canary-check"))]
    #[inline]
    fn write_canaries(&mut self) {}

    #[cfg(feature = "canary-check")]
    #[inline]
    fn clear_after_canary_failure(&self) {
        self.poisoned.set(true);
        if self.map_len != 0 {
            // Fail-closed clearing intentionally mutates the owned mapping
            // through `&self`. `LockedSecretBytes` is `Send` but not
            // `Sync`, so safe code cannot run this concurrently through
            // shared references.
            crate::wipe_backend::erase(self.ptr.as_ptr(), self.map_len);
        }
    }

    #[inline]
    fn data_ptr(&self) -> *mut u8 {
        // SAFETY: `data_offset` is either zero or `CANARY_SIZE`; non-empty
        // canary-checked mappings are allocated with that prefix included.
        unsafe { self.ptr.as_ptr().add(Self::data_offset()) }
    }

    #[cfg(feature = "canary-check")]
    #[inline]
    const fn data_offset() -> usize {
        if N == 0 {
            0
        } else {
            CANARY_SIZE
        }
    }

    #[cfg(not(feature = "canary-check"))]
    #[inline]
    const fn data_offset() -> usize {
        0
    }

    #[cfg(feature = "canary-check")]
    #[inline]
    const fn suffix_offset() -> Option<usize> {
        match CANARY_SIZE.checked_add(N) {
            Some(offset) if N != 0 => Some(offset),
            _ => None,
        }
    }

    #[cfg(feature = "canary-check")]
    #[inline]
    fn mapping_payload_len() -> Result<usize, MemoryLockError> {
        if N == 0 {
            return Ok(0);
        }

        N.checked_add(CANARY_SIZE.saturating_mul(2))
            .ok_or(MemoryLockError {
                operation: MemoryLockOperation::Length,
                errno: 0,
            })
    }

    #[cfg(not(feature = "canary-check"))]
    #[inline]
    fn mapping_payload_len() -> Result<usize, MemoryLockError> {
        Ok(N)
    }

    #[cfg(all(test, feature = "canary-check"))]
    #[allow(dead_code)]
    #[inline]
    pub(crate) fn corrupt_prefix_canary_for_test(&mut self) {
        if self.map_len == 0 {
            return;
        }

        // SAFETY: `map_len != 0` means `ptr` points to the live mapping.
        unsafe {
            let byte = self.ptr.as_ptr();
            core::ptr::write(byte, core::ptr::read(byte) ^ 0xFF);
        }
    }

    #[cfg(all(test, feature = "std", target_os = "linux"))]
    pub(crate) fn child_observes_zero_payload_after_fork_for_test(&self) -> bool {
        // SAFETY: `fork`, `waitpid`, and `_exit` use the platform C ABI.
        // The child performs only fixed memory reads before `_exit`, avoiding
        // allocator, lock, and destructor activity after `fork`.
        let pid = unsafe { fork() };
        if pid < 0 {
            return false;
        }
        if pid == 0 {
            let mut difference = 0_u8;
            for byte in self.as_slice() {
                difference |= *byte;
            }
            unsafe { _exit(i32::from(difference != 0)) }
        }

        let mut status = 0_i32;
        // SAFETY: `status` is valid for one wait status and `pid` is the
        // child returned by `fork`.
        if unsafe { waitpid(pid, &mut status, 0) } != pid {
            return false;
        }

        status & 0x7f == 0 && ((status >> 8) & 0xff) == 0
    }
}

impl<const N: usize> Drop for LockedSecretBytes<N> {
    #[inline]
    fn drop(&mut self) {
        self.secure_clear();
        #[cfg(feature = "random-canary")]
        self.canary.clear();

        if self.map_len != 0 {
            crate::wipe_backend::erase(self.ptr.as_ptr(), self.map_len);
            if self.locked {
                let _ = backend_unlock_mapping(self.ptr, self.map_len);
            }
            let _ = backend_unmap_private(self.ptr, self.map_len);
        }
    }
}

impl<const N: usize> crate::SecureSanitize for LockedSecretBytes<N> {
    #[inline]
    fn secure_sanitize(&mut self) {
        self.secure_clear();
    }
}

impl<const N: usize> crate::StableSharedSecretStorage for LockedSecretBytes<N> {}
impl<const N: usize> crate::StableMutableSecretStorage for LockedSecretBytes<N> {}

impl<const N: usize> fmt::Debug for LockedSecretBytes<N> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LockedSecretBytes")
            .field("len", &N)
            .field("contents", &"<redacted>")
            .finish()
    }
}

/// Dynamic secret bytes stored in a private locked platform mapping.
///
/// Error returned when fallible locked dynamic byte generation fails.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LockedSecretVecGenerateError<E> {
    /// Platform mapping, core-dump exclusion, locking, unlocking, or
    /// unmapping failed before generation completed.
    Memory(MemoryLockError),
    /// The caller-provided byte generator failed.
    Generate(E),
}

impl<E: fmt::Display> fmt::Display for LockedSecretVecGenerateError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Memory(error) => error.fmt(formatter),
            Self::Generate(error) => error.fmt(formatter),
        }
    }
}

#[cfg(feature = "std")]
impl<E> std::error::Error for LockedSecretVecGenerateError<E>
where
    E: std::error::Error + 'static,
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Memory(error) => Some(error),
            Self::Generate(error) => Some(error),
        }
    }
}

impl<E> From<MemoryLockError> for LockedSecretVecGenerateError<E> {
    #[inline]
    fn from(error: MemoryLockError) -> Self {
        Self::Memory(error)
    }
}

/// Error returned when in-place locked dynamic byte filling fails.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LockedSecretVecFillError<E> {
    /// Platform memory-locking or mapping setup failed.
    Memory(MemoryLockError),
    /// The fill closure returned an error.
    Fill(E),
    /// The fill closure reported more initialized bytes than capacity.
    Length(crate::LengthError),
}

impl<E: fmt::Display> fmt::Display for LockedSecretVecFillError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Memory(error) => write!(formatter, "{error}"),
            Self::Fill(error) => {
                write!(formatter, "locked dynamic secret fill failed: {error}")
            }
            Self::Length(error) => write!(formatter, "{error}"),
        }
    }
}

#[cfg(feature = "std")]
impl<E> std::error::Error for LockedSecretVecFillError<E>
where
    E: std::error::Error + 'static,
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Memory(error) => Some(error),
            Self::Fill(error) => Some(error),
            Self::Length(error) => Some(error),
        }
    }
}

impl<E> From<MemoryLockError> for LockedSecretVecFillError<E> {
    #[inline]
    fn from(error: MemoryLockError) -> Self {
        Self::Memory(error)
    }
}

impl<E> From<crate::LengthError> for LockedSecretVecFillError<E> {
    #[inline]
    fn from(error: crate::LengthError) -> Self {
        Self::Length(error)
    }
}

/// `LockedSecretVec` fills the gap between [`crate::SecretVec`] and
/// [`crate::GuardedSecretVec`]. It supports runtime-length secret bytes in
/// platform-locked memory without adding guard pages, which keeps memory
/// overhead lower for large PEM/DER material, tokens, or generated secrets
/// where page-fence protection is not required.
pub struct LockedSecretVec {
    ptr: NonNull<u8>,
    map_len: usize,
    data_capacity: usize,
    len: usize,
    locked: bool,
    request: ProtectionRequest,
    report: ProtectionReport,
    #[cfg(feature = "canary-check")]
    poisoned: Cell<bool>,
    #[cfg(feature = "random-canary")]
    canary: crate::canary::CanaryMaterial,
}

// SAFETY: The value exclusively owns a private mapping. Moving ownership to
// another thread does not invalidate the mapping, and mutation/clearing
// still requires `&mut self`. `Sync` is intentionally not implemented.
unsafe impl Send for LockedSecretVec {}

impl LockedSecretVec {
    /// Allocate locked dynamic storage with at least `capacity` bytes.
    pub fn with_capacity(capacity: usize) -> Result<Self, MemoryLockError> {
        Self::with_capacity_with_protection(capacity, ProtectionRequest::locked())
            .map_err(protection_error_as_memory_lock)
    }

    /// Allocate dynamic storage with the `profile-hardened-native` policy.
    ///
    /// Preferred dump and fork exclusion outcomes remain visible through
    /// [`LockedSecretVec::protection_report`].
    #[cfg(feature = "profile-hardened-native")]
    #[inline]
    pub fn with_capacity_hardened_native(capacity: usize) -> Result<Self, ProtectionError> {
        Self::with_capacity_with_protection(capacity, ProtectionRequest::profile_hardened_native())
    }

    /// Allocate dynamic storage with the `profile-hardened-linux` policy.
    #[cfg(feature = "profile-hardened-linux")]
    #[inline]
    pub fn with_capacity_hardened_linux(capacity: usize) -> Result<Self, ProtectionError> {
        Self::with_capacity_with_protection(capacity, ProtectionRequest::profile_hardened_linux())
    }

    /// Allocate dynamic storage under an explicit runtime protection policy.
    pub fn with_capacity_with_protection(
        capacity: usize,
        request: ProtectionRequest,
    ) -> Result<Self, ProtectionError> {
        if capacity == 0 {
            let report = empty_native_report(request, capacity, false)?;
            return Ok(Self {
                ptr: NonNull::dangling(),
                map_len: 0,
                data_capacity: 0,
                len: 0,
                locked: false,
                request,
                report,
                #[cfg(feature = "canary-check")]
                poisoned: Cell::new(false),
                #[cfg(feature = "random-canary")]
                canary: crate::canary::CanaryMaterial::zeroed(),
            });
        }

        #[cfg(feature = "random-canary")]
        let canary = random_canary_value().map_err(|error| {
            pre_mapping_error(
                request,
                capacity,
                ProtectionControl::Canary,
                error.errno,
                false,
            )
        })?;

        let payload_len = Self::mapping_payload_len(capacity).map_err(|error| {
            pre_mapping_error(
                request,
                capacity,
                ProtectionControl::Mapping,
                error.errno,
                false,
            )
        })?;
        let map_len = rounded_mapping_len(payload_len).map_err(|error| {
            pre_mapping_error(
                request,
                capacity,
                ProtectionControl::Mapping,
                error.errno,
                false,
            )
        })?;
        let setup = setup_native_mapping(map_len, capacity, request, false)?;

        let mut secret = Self {
            ptr: setup.ptr,
            map_len,
            data_capacity: capacity,
            len: 0,
            locked: setup.locked,
            request,
            report: setup.report,
            #[cfg(feature = "canary-check")]
            poisoned: Cell::new(false),
            #[cfg(feature = "random-canary")]
            canary,
        };
        secret.write_canaries();
        Ok(secret)
    }

    /// Create protected dynamic storage by copying a slice only after all
    /// required controls have been established.
    ///
    /// Controls marked [`Requirement::Preferred`] may still be degraded; use
    /// [`Requirement::Required`] for every control that must precede secret
    /// materialization.
    pub fn from_slice_with_protection(
        bytes: &[u8],
        request: ProtectionRequest,
    ) -> Result<Self, ProtectedSecretFillError<core::convert::Infallible>> {
        Self::try_from_exact_len_with_protection(bytes.len(), request, |output| {
            output.copy_from_slice(bytes);
            Ok::<(), core::convert::Infallible>(())
        })
    }

    /// Generate bytes directly into protected dynamic storage after all
    /// required controls have been established.
    pub fn from_fn_with_protection(
        len: usize,
        request: ProtectionRequest,
        mut make_byte: impl FnMut(usize) -> u8,
    ) -> Result<Self, ProtectedSecretFillError<core::convert::Infallible>> {
        Self::try_from_exact_len_with_protection(len, request, |output| {
            let mut index = 0;
            while index < len {
                output[index] = make_byte(index);
                index += 1;
            }
            Ok::<(), core::convert::Infallible>(())
        })
    }

    /// Fallibly generate bytes directly into protected dynamic storage after
    /// all required controls have been established.
    pub fn try_from_fn_with_protection<E>(
        len: usize,
        request: ProtectionRequest,
        mut make_byte: impl FnMut(usize) -> Result<u8, E>,
    ) -> Result<Self, ProtectedSecretFillError<E>> {
        Self::try_from_exact_len_with_protection(len, request, |output| {
            let mut index = 0;
            while index < len {
                output[index] = make_byte(index)?;
                index += 1;
            }
            Ok(())
        })
    }

    /// Fill an exact-length payload only after all required controls have been
    /// established.
    ///
    /// If `fill` panics, clear-on-drop ownership remains active for the entire
    /// mapping during unwinding.
    pub fn from_exact_len_with_protection(
        len: usize,
        request: ProtectionRequest,
        fill: impl FnOnce(&mut [u8]),
    ) -> Result<Self, ProtectedSecretFillError<core::convert::Infallible>> {
        Self::try_from_exact_len_with_protection(len, request, |output| {
            fill(output);
            Ok::<(), core::convert::Infallible>(())
        })
    }

    /// Fallible variant of
    /// [`LockedSecretVec::from_exact_len_with_protection`].
    ///
    /// The fill closure is never invoked when a required control fails. A
    /// fill error clears the complete mapping before returning.
    pub fn try_from_exact_len_with_protection<E>(
        len: usize,
        request: ProtectionRequest,
        fill: impl FnOnce(&mut [u8]) -> Result<(), E>,
    ) -> Result<Self, ProtectedSecretFillError<E>> {
        Self::try_from_capacity_with_protection(len, request, |output| {
            fill(output)?;
            Ok(len)
        })
    }

    /// Fill protected dynamic storage and return the initialized byte length.
    ///
    /// This is the infallible-fill counterpart of
    /// [`LockedSecretVec::try_from_capacity_with_protection`].
    pub fn from_capacity_with_protection(
        capacity: usize,
        request: ProtectionRequest,
        fill: impl FnOnce(&mut [u8]) -> usize,
    ) -> Result<Self, ProtectedSecretFillError<core::convert::Infallible>> {
        Self::try_from_capacity_with_protection(capacity, request, |output| {
            Ok::<usize, core::convert::Infallible>(fill(output))
        })
    }

    /// Bounded variant of
    /// [`LockedSecretVec::try_from_capacity_with_protection`].
    ///
    /// Use this constructor whenever `capacity` originates from an untrusted
    /// protocol length, decoder hint, or message field. A capacity above
    /// `maximum` is rejected before mapping, locking, or invoking `fill`.
    pub fn try_from_capacity_bounded_with_protection<E>(
        capacity: usize,
        maximum: usize,
        request: ProtectionRequest,
        fill: impl FnOnce(&mut [u8]) -> Result<usize, E>,
    ) -> Result<Self, ProtectedSecretFillError<E>> {
        if capacity > maximum {
            return Err(ProtectedSecretFillError::CapacityLimit {
                maximum,
                actual: capacity,
            });
        }

        Self::try_from_capacity_with_protection(capacity, request, fill)
    }

    /// Fill protected dynamic storage only after all required controls have
    /// been established.
    ///
    /// This unbounded constructor is intended for trusted capacities that the
    /// application has already limited. Use
    /// [`LockedSecretVec::try_from_capacity_bounded_with_protection`] at
    /// untrusted protocol boundaries. The closure is not invoked when mapping
    /// setup or any
    /// [`Requirement::Required`] control fails. Controls marked
    /// [`Requirement::Preferred`] retain their normal degraded-success
    /// semantics and remain visible through [`LockedSecretVec::protection_report`].
    ///
    /// If `fill` fails or reports more than `capacity` initialized bytes, the
    /// complete mapping is cleared before the error is returned. Unused tail
    /// bytes are also cleared before successful construction completes.
    pub fn try_from_capacity_with_protection<E>(
        capacity: usize,
        request: ProtectionRequest,
        fill: impl FnOnce(&mut [u8]) -> Result<usize, E>,
    ) -> Result<Self, ProtectedSecretFillError<E>> {
        Self::try_from_capacity_with_protection_inner(capacity, request, fill, |_| {})
    }

    #[inline]
    fn try_from_capacity_with_protection_inner<E>(
        capacity: usize,
        request: ProtectionRequest,
        fill: impl FnOnce(&mut [u8]) -> Result<usize, E>,
        after_fill: impl FnOnce(&mut Self),
    ) -> Result<Self, ProtectedSecretFillError<E>> {
        let mut secret = Self::with_capacity_with_protection(capacity, request)
            .map_err(ProtectedSecretFillError::Protection)?;
        // `with_capacity_with_protection` initializes an empty value, so its
        // suffix canary initially occupies the first payload bytes. Erase the
        // caller-visible payload before relocating that canary; fill code must
        // never observe canary material or stale mapping contents.
        {
            let destination = secret.as_mut_capacity_slice();
            crate::wipe_backend::erase(destination.as_mut_ptr(), destination.len());
        }
        // During filling, place the suffix canary at the caller-visible
        // capacity boundary. This detects an unsafe decoder writing past the
        // provided output slice before the suffix is moved to the reported
        // initialized length.
        secret.len = capacity;
        secret.write_canaries();
        compiler_fence(Ordering::SeqCst);
        let fill_result = fill(&mut secret.as_mut_capacity_slice()[..capacity]);
        after_fill(&mut secret);
        secret
            .verify_integrity()
            .map_err(ProtectedSecretFillError::Integrity)?;
        let len = match fill_result {
            Ok(len) => len,
            Err(error) => {
                secret.clear_secret();
                return Err(ProtectedSecretFillError::Fill(error));
            }
        };
        if len > capacity {
            secret.clear_secret();
            return Err(ProtectedSecretFillError::Length(crate::LengthError {
                expected: capacity,
                actual: len,
            }));
        }

        if len < secret.data_capacity {
            let spare = &mut secret.as_mut_capacity_slice()[len..];
            crate::wipe_backend::erase(spare.as_mut_ptr(), spare.len());
        }
        secret.finish_initialization(len);
        Ok(secret)
    }

    #[cfg(all(test, feature = "canary-check", feature = "std"))]
    pub(crate) fn try_from_capacity_with_protection_and_corrupt_boundary_for_test<E>(
        capacity: usize,
        request: ProtectionRequest,
        fill: impl FnOnce(&mut [u8]) -> Result<usize, E>,
    ) -> Result<Self, ProtectedSecretFillError<E>> {
        Self::try_from_capacity_with_protection_inner(capacity, request, fill, |secret| {
            if secret.map_len == 0 {
                return;
            }

            // SAFETY: while filling, `len == capacity` and the suffix canary
            // immediately follows that payload within the live mapping. This
            // test hook derives its pointer from the full mapping owner, not
            // from the narrowed callback slice.
            unsafe {
                let byte = secret.payload_ptr().add(secret.len);
                core::ptr::write(byte, core::ptr::read(byte) ^ 0xFF);
            }
        })
    }

    #[cfg(test)]
    pub(crate) fn unreported_tail_is_clear_for_test(&self) -> bool {
        #[cfg(feature = "canary-check")]
        let tail_start = self.len.saturating_add(CANARY_SIZE).min(self.data_capacity);
        #[cfg(not(feature = "canary-check"))]
        let tail_start = self.len;
        let mut index = tail_start;
        while index < self.data_capacity {
            // SAFETY: `index < data_capacity`, and the mapping remains live for
            // the duration of `&self`. Volatile reads make this a direct check
            // of the mapped bytes rather than an optimizer-derived result.
            if unsafe { core::ptr::read_volatile(self.payload_ptr().add(index)) } != 0 {
                return false;
            }
            index += 1;
        }
        true
    }

    /// Create locked dynamic storage by copying bytes from a slice.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, MemoryLockError> {
        let mut secret = Self::with_capacity(bytes.len())?;
        secret.as_mut_capacity_slice()[..bytes.len()].copy_from_slice(bytes);
        secret.finish_initialization(bytes.len());
        Ok(secret)
    }

    /// Create locked dynamic storage by generating bytes directly into it.
    pub fn from_fn(
        len: usize,
        mut make_byte: impl FnMut(usize) -> u8,
    ) -> Result<Self, MemoryLockError> {
        let mut secret = Self::with_capacity(len)?;
        secret.fill_from_fn(len, &mut make_byte);
        Ok(secret)
    }

    /// Create locked dynamic storage with a fallible byte generator.
    pub fn try_from_fn<E>(
        len: usize,
        mut make_byte: impl FnMut(usize) -> Result<u8, E>,
    ) -> Result<Self, LockedSecretVecGenerateError<E>> {
        let mut secret = Self::with_capacity(len)?;
        secret
            .fill_from_try_fn(len, &mut make_byte)
            .map_err(LockedSecretVecGenerateError::Generate)?;
        Ok(secret)
    }

    /// Create locked dynamic storage and fill an exact-length payload in
    /// place.
    ///
    /// This is intended for decoders, KDFs, RNGs, and protocol APIs that
    /// can write into a caller-provided output buffer. The mapping is
    /// created, dump-excluded, fork-excluded where supported, and locked
    /// before `fill` receives the mutable payload. No intermediate
    /// unlocked `Vec` is required by this API.
    pub fn from_exact_len(
        len: usize,
        fill: impl FnOnce(&mut [u8]),
    ) -> Result<Self, MemoryLockError> {
        let mut secret = Self::with_capacity(len)?;
        compiler_fence(Ordering::SeqCst);
        fill(&mut secret.as_mut_capacity_slice()[..len]);
        secret.finish_initialization(len);
        Ok(secret)
    }

    /// Fallible variant of [`LockedSecretVec::from_exact_len`].
    ///
    /// If `fill` returns an error, partial bytes already written into the
    /// locked mapping are volatile-cleared before the error is returned.
    pub fn try_from_exact_len<E>(
        len: usize,
        fill: impl FnOnce(&mut [u8]) -> Result<(), E>,
    ) -> Result<Self, LockedSecretVecGenerateError<E>> {
        let mut secret = Self::with_capacity(len)?;
        compiler_fence(Ordering::SeqCst);
        if let Err(error) = fill(&mut secret.as_mut_capacity_slice()[..len]) {
            secret.clear_secret();
            return Err(LockedSecretVecGenerateError::Generate(error));
        }
        secret.finish_initialization(len);
        Ok(secret)
    }

    /// Create locked dynamic storage with `capacity` bytes and fill it in
    /// place, returning the number of initialized bytes.
    ///
    /// This is the preferred constructor for base64 or protocol decoders
    /// that can compute a maximum output size before decoding, but only
    /// learn the exact decoded length after writing. If `fill` reports a
    /// length greater than `capacity`, the mapping is cleared and
    /// [`LockedSecretVecFillError::Length`] is returned.
    pub fn from_capacity(
        capacity: usize,
        fill: impl FnOnce(&mut [u8]) -> usize,
    ) -> Result<Self, LockedSecretVecFillError<core::convert::Infallible>> {
        Self::try_from_capacity(capacity, |output| {
            Ok::<usize, core::convert::Infallible>(fill(output))
        })
    }

    /// Fallible variant of [`LockedSecretVec::from_capacity`].
    ///
    /// If `fill` returns an error or reports too many initialized bytes,
    /// partial bytes already written into the locked mapping are
    /// volatile-cleared before the error is returned.
    pub fn try_from_capacity<E>(
        capacity: usize,
        fill: impl FnOnce(&mut [u8]) -> Result<usize, E>,
    ) -> Result<Self, LockedSecretVecFillError<E>> {
        let mut secret = Self::with_capacity(capacity)?;
        compiler_fence(Ordering::SeqCst);
        let len = match fill(secret.as_mut_capacity_slice()) {
            Ok(len) => len,
            Err(error) => {
                secret.clear_secret();
                return Err(LockedSecretVecFillError::Fill(error));
            }
        };
        if len > capacity {
            // Explicit pre-return clear; Drop also wipes on return.
            secret.clear_secret();
            return Err(crate::LengthError {
                expected: capacity,
                actual: len,
            }
            .into());
        }

        if len < capacity {
            let spare = &mut secret.as_mut_capacity_slice()[len..capacity];
            crate::wipe_backend::erase(spare.as_mut_ptr(), spare.len());
        }
        secret.finish_initialization(len);
        Ok(secret)
    }

    /// Number of initialized secret bytes.
    #[must_use]
    #[inline]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Returns true when no bytes are held.
    #[must_use]
    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Dynamic payload capacity, excluding canary bytes.
    #[must_use]
    #[inline]
    pub const fn capacity(&self) -> usize {
        self.data_capacity
    }

    /// Length of the underlying locked mapping.
    #[must_use]
    #[inline]
    pub const fn locked_len(&self) -> usize {
        self.report.locked_bytes
    }

    /// Actual runtime protections established for the current mapping.
    #[must_use]
    #[inline]
    pub const fn protection_report(&self) -> &ProtectionReport {
        &self.report
    }

    /// Runtime protection policy requested for the current mapping.
    #[must_use]
    #[inline]
    pub const fn protection_request(&self) -> ProtectionRequest {
        self.request
    }

    #[cfg(all(test, target_os = "linux"))]
    pub(crate) fn mark_guard_pages_established_for_replacement_test(&mut self) {
        self.report.guard_pages = ProtectionState::Established;
    }

    /// Returns true when the pool mapping is locked against ordinary paging.
    #[must_use]
    #[inline]
    pub const fn is_memory_locked(&self) -> bool {
        self.locked
    }

    /// Run a closure with read-only access to initialized secret bytes.
    #[inline]
    pub fn try_with_secret<R>(
        &self,
        inspect: impl FnOnce(&[u8]) -> R,
    ) -> Result<R, CanaryCorruptedError> {
        self.verify_integrity()?;
        let result = inspect(self.as_slice());
        self.verify_integrity()?;
        Ok(result)
    }

    /// Run a closure with mutable access to initialized secret bytes.
    #[inline]
    pub fn try_with_secret_mut<R>(
        &mut self,
        edit: impl FnOnce(&mut [u8]) -> R,
    ) -> Result<R, CanaryCorruptedError> {
        self.verify_integrity()?;
        let result = edit(self.as_mut_slice());
        compiler_fence(Ordering::SeqCst);
        self.verify_integrity()?;
        Ok(result)
    }

    /// Append bytes, growing into a new locked mapping if needed.
    pub fn try_extend_from_slice(
        &mut self,
        bytes: &[u8],
    ) -> Result<(), SecretIntegrityError<MemoryLockError>> {
        self.verify_integrity()?;
        let required = self
            .len
            .checked_add(bytes.len())
            .ok_or(SecretIntegrityError::Operation(MemoryLockError {
                operation: MemoryLockOperation::Length,
                errno: 0,
            }))?;

        if required > self.data_capacity {
            self.grow_to(required)?;
        }

        let start = self.len;
        self.as_mut_capacity_slice()[start..required].copy_from_slice(bytes);
        self.finish_initialization(required);
        Ok(())
    }

    /// Replace all initialized bytes from a slice.
    pub fn try_replace_from_slice(
        &mut self,
        bytes: &[u8],
    ) -> Result<(), SecretIntegrityError<MemoryLockError>> {
        self.verify_integrity()?;

        if bytes.len() > self.data_capacity {
            let mut replacement = self
                .replacement_with_capacity(bytes.len())
                .map_err(SecretIntegrityError::Operation)?;
            replacement.as_mut_capacity_slice()[..bytes.len()].copy_from_slice(bytes);
            replacement.finish_initialization(bytes.len());
            self.clear_secret();
            core::mem::swap(self, &mut replacement);
            return Ok(());
        }

        self.clear_secret();
        self.as_mut_capacity_slice()[..bytes.len()].copy_from_slice(bytes);
        self.finish_initialization(bytes.len());
        Ok(())
    }

    /// Replace all initialized bytes with generated bytes.
    pub fn try_replace_from_fn(
        &mut self,
        len: usize,
        mut make_byte: impl FnMut(usize) -> u8,
    ) -> Result<(), SecretIntegrityError<MemoryLockError>> {
        self.verify_integrity()?;
        let mut replacement = self
            .replacement_with_capacity(len)
            .map_err(SecretIntegrityError::Operation)?;
        replacement.fill_from_fn(len, &mut make_byte);
        self.clear_secret();
        core::mem::swap(self, &mut replacement);
        Ok(())
    }

    /// Replace all initialized bytes with fallibly generated bytes.
    pub fn try_replace_from_fallible_fn<E>(
        &mut self,
        len: usize,
        mut make_byte: impl FnMut(usize) -> Result<u8, E>,
    ) -> Result<(), SecretIntegrityError<LockedSecretVecGenerateError<E>>> {
        self.verify_integrity()?;
        let mut replacement = self
            .replacement_with_capacity(len)
            .map_err(LockedSecretVecGenerateError::Memory)
            .map_err(SecretIntegrityError::Operation)?;
        replacement
            .fill_from_try_fn(len, &mut make_byte)
            .map_err(LockedSecretVecGenerateError::Generate)
            .map_err(SecretIntegrityError::Operation)?;
        self.clear_secret();
        core::mem::swap(self, &mut replacement);
        Ok(())
    }

    /// Replace all initialized bytes by filling an exact-length fresh
    /// locked mapping in place.
    ///
    /// The old locked value remains unchanged if mapping setup fails. If
    /// `fill` panics, the old value also remains unchanged and partial
    /// replacement bytes are cleared during unwinding.
    pub fn try_replace_from_exact_len(
        &mut self,
        len: usize,
        fill: impl FnOnce(&mut [u8]),
    ) -> Result<(), SecretIntegrityError<MemoryLockError>> {
        self.verify_integrity()?;
        let mut replacement = self
            .replacement_with_capacity(len)
            .map_err(SecretIntegrityError::Operation)?;
        compiler_fence(Ordering::SeqCst);
        fill(&mut replacement.as_mut_capacity_slice()[..len]);
        replacement.finish_initialization(len);
        self.clear_secret();
        core::mem::swap(self, &mut replacement);
        Ok(())
    }

    /// Fallible variant of [`LockedSecretVec::try_replace_from_exact_len`].
    ///
    /// The old locked value remains unchanged if mapping setup or `fill`
    /// fails. Partial replacement bytes are cleared before the error is
    /// returned.
    pub fn try_replace_from_fallible_exact_len<E>(
        &mut self,
        len: usize,
        fill: impl FnOnce(&mut [u8]) -> Result<(), E>,
    ) -> Result<(), SecretIntegrityError<LockedSecretVecGenerateError<E>>> {
        self.verify_integrity()?;
        let mut replacement = self
            .replacement_with_capacity(len)
            .map_err(LockedSecretVecGenerateError::Memory)
            .map_err(SecretIntegrityError::Operation)?;
        compiler_fence(Ordering::SeqCst);
        if let Err(error) = fill(&mut replacement.as_mut_capacity_slice()[..len]) {
            replacement.clear_secret();
            return Err(SecretIntegrityError::Operation(
                LockedSecretVecGenerateError::Generate(error),
            ));
        }
        replacement.finish_initialization(len);
        self.clear_secret();
        core::mem::swap(self, &mut replacement);
        Ok(())
    }

    /// Replace all initialized bytes by filling a fresh locked mapping
    /// with `capacity` bytes and returning the actual initialized length.
    ///
    /// The old locked value remains unchanged if mapping setup fails or if
    /// `fill` reports a length greater than `capacity`.
    pub fn try_replace_from_capacity(
        &mut self,
        capacity: usize,
        fill: impl FnOnce(&mut [u8]) -> usize,
    ) -> Result<(), SecretIntegrityError<LockedSecretVecFillError<core::convert::Infallible>>> {
        self.try_replace_from_fallible_capacity(capacity, |output| {
            Ok::<usize, core::convert::Infallible>(fill(output))
        })
    }

    /// Fallible variant of [`LockedSecretVec::try_replace_from_capacity`].
    ///
    /// The old locked value remains unchanged if mapping setup, filling, or
    /// length validation fails. Partial replacement bytes are cleared
    /// before the error is returned.
    pub fn try_replace_from_fallible_capacity<E>(
        &mut self,
        capacity: usize,
        fill: impl FnOnce(&mut [u8]) -> Result<usize, E>,
    ) -> Result<(), SecretIntegrityError<LockedSecretVecFillError<E>>> {
        self.verify_integrity()?;
        let mut replacement = self
            .replacement_with_capacity(capacity)
            .map_err(LockedSecretVecFillError::Memory)
            .map_err(SecretIntegrityError::Operation)?;
        compiler_fence(Ordering::SeqCst);
        let len = match fill(replacement.as_mut_capacity_slice()) {
            Ok(len) => len,
            Err(error) => {
                replacement.clear_secret();
                return Err(SecretIntegrityError::Operation(
                    LockedSecretVecFillError::Fill(error),
                ));
            }
        };
        if len > capacity {
            replacement.clear_secret();
            return Err(SecretIntegrityError::Operation(
                crate::LengthError {
                    expected: capacity,
                    actual: len,
                }
                .into(),
            ));
        }
        if len < capacity {
            let spare = &mut replacement.as_mut_capacity_slice()[len..capacity];
            crate::wipe_backend::erase(spare.as_mut_ptr(), spare.len());
        }
        replacement.finish_initialization(len);
        self.clear_secret();
        core::mem::swap(self, &mut replacement);
        Ok(())
    }

    /// Clear the full locked mapping and reset initialized length.
    #[inline(never)]
    pub fn clear_secret(&mut self) {
        if self.map_len != 0 {
            crate::wipe_backend::erase(self.ptr.as_ptr(), self.map_len);
        }
        self.len = 0;
        self.write_canaries();
    }

    /// Consume this value after first clearing the full locked mapping.
    #[inline]
    pub fn into_cleared(mut self) {
        self.clear_secret();
    }

    /// Clear the full locked mapping, then flush its cache lines.
    #[cfg(feature = "cache-flush")]
    #[inline(never)]
    pub fn try_clear_secret_and_flush(
        &mut self,
    ) -> Result<crate::cache_flush::CacheFlushReport, crate::cache_flush::CacheFlushError> {
        self.clear_secret();
        crate::cache_flush::flush_cache_lines(self.as_mapping_slice())
    }

    /// Compare against a byte slice without early exit for equal-length
    /// inputs.
    #[inline]
    pub fn try_constant_time_eq(&self, other: &[u8]) -> Result<bool, CanaryCorruptedError> {
        self.verify_integrity()?;
        Ok(crate::constant_time_eq_slices(self.as_slice(), other))
    }

    /// Verify locked dynamic mapping canaries.
    #[inline]
    pub fn verify_integrity(&self) -> Result<(), CanaryCorruptedError> {
        #[cfg(not(feature = "canary-check"))]
        {
            return Ok(());
        }
        #[cfg(feature = "canary-check")]
        if !self.poisoned.get() && self.canaries_intact() {
            Ok(())
        } else {
            self.clear_after_canary_failure();
            Err(CanaryCorruptedError)
        }
    }

    fn grow_to(&mut self, required: usize) -> Result<(), SecretIntegrityError<MemoryLockError>> {
        self.verify_integrity()?;
        let next_capacity = self.data_capacity.saturating_mul(2).max(required).max(1);
        let mut replacement = self
            .replacement_with_capacity(next_capacity)
            .map_err(SecretIntegrityError::Operation)?;
        replacement.as_mut_capacity_slice()[..self.len].copy_from_slice(self.as_slice());
        replacement.finish_initialization(self.len);
        self.clear_secret();
        core::mem::swap(self, &mut replacement);
        Ok(())
    }

    /// Run a closure with shared access, panicking on canary corruption.
    #[inline]
    pub fn with_secret_or_panic<R>(&self, inspect: impl FnOnce(&[u8]) -> R) -> R {
        self.try_with_secret(inspect)
            .unwrap_or_else(|_| panic!("locked dynamic secret canary corrupted"))
    }

    /// Run a closure with mutable access, panicking on canary corruption.
    #[inline]
    pub fn with_secret_mut_or_panic<R>(&mut self, edit: impl FnOnce(&mut [u8]) -> R) -> R {
        self.try_with_secret_mut(edit)
            .unwrap_or_else(|_| panic!("locked dynamic secret canary corrupted"))
    }

    /// Compare, panicking on canary corruption.
    #[must_use]
    #[inline]
    pub fn constant_time_eq_or_panic(&self, other: &[u8]) -> bool {
        self.try_constant_time_eq(other)
            .unwrap_or_else(|_| panic!("locked dynamic secret canary corrupted"))
    }

    fn replacement_with_capacity(&self, capacity: usize) -> Result<Self, MemoryLockError> {
        let request = self.request;
        let replacement_request =
            replacement_request_preserving_established(request, &self.report, capacity);
        let mut replacement = Self::with_capacity_with_protection(capacity, replacement_request)
            .map_err(protection_error_as_memory_lock)?;
        replacement.request = request;
        Ok(replacement)
    }

    fn fill_from_fn(&mut self, len: usize, make_byte: &mut impl FnMut(usize) -> u8) {
        assert!(
            len <= self.data_capacity,
            "locked dynamic secret length exceeds capacity"
        );
        compiler_fence(Ordering::SeqCst);
        let capacity = self.as_mut_capacity_slice();
        let mut index = 0;
        while index < len {
            capacity[index] = make_byte(index);
            index += 1;
        }
        self.finish_initialization(len);
    }

    /// Fill a fresh or throwaway dynamic mapping.
    ///
    /// On error, clears all bytes written so far and resets the mapping
    /// before returning. Callers that propagate the error may still run
    /// `Drop`, causing a harmless second clear of already-zeroed storage.
    fn fill_from_try_fn<E>(
        &mut self,
        len: usize,
        make_byte: &mut impl FnMut(usize) -> Result<u8, E>,
    ) -> Result<(), E> {
        assert!(
            len <= self.data_capacity,
            "locked dynamic secret length exceeds capacity"
        );
        compiler_fence(Ordering::SeqCst);
        let mut index = 0;
        while index < len {
            let byte = match make_byte(index) {
                Ok(byte) => byte,
                Err(error) => {
                    self.clear_secret();
                    return Err(error);
                }
            };
            self.as_mut_capacity_slice()[index] = byte;
            index += 1;
        }
        self.finish_initialization(len);
        Ok(())
    }

    #[inline]
    fn finish_initialization(&mut self, len: usize) {
        assert!(
            len <= self.data_capacity,
            "locked dynamic secret length exceeds capacity"
        );
        self.len = len;
        self.write_canaries();
        compiler_fence(Ordering::SeqCst);
    }

    #[inline]
    fn as_slice(&self) -> &[u8] {
        // SAFETY: `payload_ptr` points to `data_capacity` writable payload
        // bytes owned by this value, and `len <= data_capacity`.
        unsafe { core::slice::from_raw_parts(self.payload_ptr(), self.len) }
    }

    #[inline]
    fn as_mut_slice(&mut self) -> &mut [u8] {
        // SAFETY: `&mut self` gives exclusive access and `len <=
        // data_capacity`.
        unsafe { core::slice::from_raw_parts_mut(self.payload_ptr(), self.len) }
    }

    #[inline]
    fn as_mut_capacity_slice(&mut self) -> &mut [u8] {
        // SAFETY: `&mut self` gives exclusive access to the full payload
        // capacity inside the locked mapping.
        unsafe { core::slice::from_raw_parts_mut(self.payload_ptr(), self.data_capacity) }
    }

    #[cfg(feature = "cache-flush")]
    #[inline]
    fn as_mapping_slice(&self) -> &[u8] {
        // SAFETY: `ptr` points to this value's live mapping, or is
        // dangling with `map_len == 0`.
        unsafe { core::slice::from_raw_parts(self.ptr.as_ptr(), self.map_len) }
    }

    #[inline]
    fn payload_ptr(&self) -> *mut u8 {
        if self.map_len == 0 {
            return self.ptr.as_ptr();
        }

        // SAFETY: `payload_offset` is zero or the prefix canary size and
        // remains inside non-empty mappings.
        unsafe { self.ptr.as_ptr().add(Self::payload_offset()) }
    }

    #[cfg(feature = "canary-check")]
    #[inline]
    const fn payload_offset() -> usize {
        CANARY_SIZE
    }

    #[cfg(not(feature = "canary-check"))]
    #[inline]
    const fn payload_offset() -> usize {
        0
    }

    #[cfg(all(feature = "canary-check", not(feature = "random-canary")))]
    #[inline]
    fn canary_value(&self) -> [u8; CANARY_SIZE] {
        ((self.ptr.as_ptr() as u64) ^ CANARY_MASK).to_ne_bytes()
    }

    #[cfg(feature = "random-canary")]
    #[inline]
    fn with_canary<R>(&self, use_canary: impl FnOnce(&[u8; CANARY_SIZE]) -> R) -> R {
        use_canary(self.canary.as_bytes())
    }

    #[cfg(all(feature = "canary-check", not(feature = "random-canary")))]
    #[inline]
    fn with_canary<R>(&self, use_canary: impl FnOnce(&[u8; CANARY_SIZE]) -> R) -> R {
        let canary = self.canary_value();
        use_canary(&canary)
    }

    #[cfg(feature = "canary-check")]
    #[inline]
    fn canaries_intact(&self) -> bool {
        if self.map_len == 0 {
            return true;
        }

        // SAFETY: non-empty canary-checked dynamic mappings reserve prefix
        // and suffix canary regions around initialized bytes.
        let prefix = unsafe { core::slice::from_raw_parts(self.ptr.as_ptr(), CANARY_SIZE) };
        // SAFETY: `len <= data_capacity`, so the suffix at prefix + len is
        // inside the allocated payload plus suffix region.
        let suffix = unsafe {
            core::slice::from_raw_parts(self.ptr.as_ptr().add(CANARY_SIZE + self.len), CANARY_SIZE)
        };

        self.with_canary(|expected| {
            crate::constant_time_eq_slices(prefix, expected)
                & crate::constant_time_eq_slices(suffix, expected)
        })
    }

    #[cfg(feature = "canary-check")]
    #[inline]
    fn write_canaries(&mut self) {
        if self.map_len == 0 {
            return;
        }

        self.with_canary(|canary| {
            // SAFETY: non-empty canary-checked dynamic mappings reserve prefix
            // and suffix canary regions around initialized bytes.
            unsafe {
                core::ptr::copy_nonoverlapping(canary.as_ptr(), self.ptr.as_ptr(), CANARY_SIZE);
                core::ptr::copy_nonoverlapping(
                    canary.as_ptr(),
                    self.ptr.as_ptr().add(CANARY_SIZE + self.len),
                    CANARY_SIZE,
                );
            }
        });
        compiler_fence(Ordering::SeqCst);
    }

    #[cfg(not(feature = "canary-check"))]
    #[inline]
    fn write_canaries(&mut self) {}

    #[cfg(feature = "canary-check")]
    #[inline]
    fn clear_after_canary_failure(&self) {
        self.poisoned.set(true);
        if self.map_len != 0 {
            // Fail-closed clearing intentionally mutates the owned mapping
            // through `&self`. `LockedSecretVec` is `Send` but not `Sync`.
            crate::wipe_backend::erase(self.ptr.as_ptr(), self.map_len);
        }
    }

    #[cfg(feature = "canary-check")]
    #[inline]
    fn mapping_payload_len(capacity: usize) -> Result<usize, MemoryLockError> {
        capacity
            .checked_add(CANARY_SIZE.saturating_mul(2))
            .ok_or(MemoryLockError {
                operation: MemoryLockOperation::Length,
                errno: 0,
            })
    }

    #[cfg(not(feature = "canary-check"))]
    #[inline]
    fn mapping_payload_len(capacity: usize) -> Result<usize, MemoryLockError> {
        Ok(capacity)
    }

    #[cfg(all(test, feature = "canary-check", feature = "std"))]
    #[allow(dead_code)]
    #[inline]
    pub(crate) fn corrupt_prefix_canary_for_test(&mut self) {
        if self.map_len == 0 {
            return;
        }

        // SAFETY: `map_len != 0` means `ptr` points to the live mapping.
        unsafe {
            let byte = self.ptr.as_ptr();
            core::ptr::write(byte, core::ptr::read(byte) ^ 0xFF);
        }
    }
}

impl Drop for LockedSecretVec {
    #[inline]
    fn drop(&mut self) {
        self.clear_secret();
        #[cfg(feature = "random-canary")]
        self.canary.clear();
        if self.map_len != 0 {
            crate::wipe_backend::erase(self.ptr.as_ptr(), self.map_len);
            if self.locked {
                let _ = backend_unlock_mapping(self.ptr, self.map_len);
            }
            let _ = backend_unmap_private(self.ptr, self.map_len);
        }
    }
}

impl crate::SecureSanitize for LockedSecretVec {
    #[inline]
    fn secure_sanitize(&mut self) {
        self.clear_secret();
    }
}

impl fmt::Debug for LockedSecretVec {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LockedSecretVec")
            .field("len", &self.len)
            .field("capacity", &self.data_capacity)
            .field("locked_len", &self.map_len)
            .field("contents", &"<redacted>")
            .finish()
    }
}

/// Fixed-slot arena for many same-size secrets inside one locked mapping.
///
/// `SecretPool<N, SLOTS>` amortizes platform memory-locking overhead when
/// an application needs many fixed-size secrets at once. Instead of using
/// one locked page-backed mapping per secret, the pool creates one private
/// locked mapping large enough for `SLOTS` slots of `N` bytes and hands out
/// lifetime-bound [`SecretPoolSlot`] handles.
///
/// Slots borrow the pool, so Rust prevents the pool from being dropped
/// while a slot is still live. Dropping a slot volatile-clears exactly that
/// slot and returns it to the pool. Dropping the pool volatile-clears the
/// full mapping before unlocking and releasing it.
///
/// ```compile_fail
/// use sanitization::SecretPool;
///
/// let pool = SecretPool::<32, 4>::new().unwrap();
/// let slot = pool.try_allocate().unwrap().unwrap();
/// drop(pool); // rejected: `slot` still borrows the pool
/// drop(slot);
/// ```
pub struct SecretPool<const N: usize, const SLOTS: usize> {
    base: NonNull<u8>,
    map_len: usize,
    slot_stride: usize,
    locked: bool,
    request: ProtectionRequest,
    report: ProtectionReport,
    used: [AtomicBool; SLOTS],
    generations: [AtomicUsize; SLOTS],
    quarantined: [AtomicBool; SLOTS],
    #[cfg(all(test, feature = "canary-check"))]
    fail_next_initialization_integrity: AtomicBool,
}

/// A live fixed-size secret slot allocated from a [`SecretPool`].
///
/// The slot gives controlled access to one `N`-byte region inside the
/// parent pool. Moving the slot moves only pointer metadata; the secret
/// bytes stay inside the locked pool mapping.
pub struct SecretPoolSlot<'pool, const N: usize, const SLOTS: usize> {
    ptr: NonNull<u8>,
    slot_index: usize,
    pool: &'pool SecretPool<N, SLOTS>,
    generation: usize,
    #[cfg(feature = "canary-check")]
    canaries_initialized: bool,
    #[cfg(feature = "random-canary")]
    canary: crate::canary::CanaryMaterial,
}

// SAFETY: The pool owns one private mapping. Slot allocation state is
// coordinated with atomics, and mutable byte access is possible only
// through a uniquely-owned slot handle or `&mut self`.
unsafe impl<const N: usize, const SLOTS: usize> Send for SecretPool<N, SLOTS> {}
// SAFETY: Shared pool references may allocate different slots concurrently.
// The atomic bitmap prevents two live safe handles for the same slot.
unsafe impl<const N: usize, const SLOTS: usize> Sync for SecretPool<N, SLOTS> {}
// SAFETY: Moving a slot to another thread transfers the unique live handle
// for that slot. The borrowed pool remains live for the slot lifetime.
unsafe impl<'pool, const N: usize, const SLOTS: usize> Send for SecretPoolSlot<'pool, N, SLOTS> {}

impl<const N: usize, const SLOTS: usize> SecretPool<N, SLOTS> {
    /// Create a locked pool with `SLOTS` fixed-size slots of `N` bytes.
    ///
    /// This performs one platform mapping and one platform lock operation
    /// for the whole arena. The requested mapping length is rounded to the
    /// platform page granule, so the pool also clears padding bytes on
    /// drop.
    #[inline]
    pub fn new() -> Result<Self, MemoryLockError> {
        Self::new_with_protection(ProtectionRequest::locked())
            .map_err(protection_error_as_memory_lock)
    }

    /// Create a locked pool with the `profile-hardened-native` policy.
    ///
    /// Preferred dump and fork exclusion outcomes remain visible through
    /// [`SecretPool::protection_report`].
    #[cfg(feature = "profile-hardened-native")]
    #[inline]
    pub fn new_hardened_native() -> Result<Self, ProtectionError> {
        Self::new_with_protection(ProtectionRequest::profile_hardened_native())
    }

    /// Create a locked pool with the `profile-hardened-linux` policy.
    #[cfg(feature = "profile-hardened-linux")]
    #[inline]
    pub fn new_hardened_linux() -> Result<Self, ProtectionError> {
        Self::new_with_protection(ProtectionRequest::profile_hardened_linux())
    }

    /// Create a pool under an explicit runtime protection policy.
    #[inline]
    pub fn new_with_protection(request: ProtectionRequest) -> Result<Self, ProtectionError> {
        let used = core::array::from_fn(|_| AtomicBool::new(false));
        let generations = core::array::from_fn(|_| AtomicUsize::new(0));
        let quarantined = core::array::from_fn(|_| AtomicBool::new(false));
        let payload_bytes = N.checked_mul(SLOTS).ok_or_else(|| {
            pre_mapping_error(request, usize::MAX, ProtectionControl::Mapping, 0, false)
        })?;
        let slot_stride = Self::slot_stride().map_err(|error| {
            pre_mapping_error(
                request,
                payload_bytes,
                ProtectionControl::Mapping,
                error.errno,
                false,
            )
        })?;
        let total_bytes = slot_stride.checked_mul(SLOTS).ok_or_else(|| {
            pre_mapping_error(request, payload_bytes, ProtectionControl::Mapping, 0, false)
        })?;

        if total_bytes == 0 {
            let report = empty_native_report(request, payload_bytes, false)?;
            return Ok(Self {
                base: NonNull::dangling(),
                map_len: 0,
                slot_stride,
                locked: false,
                request,
                report,
                used,
                generations,
                quarantined,
                #[cfg(all(test, feature = "canary-check"))]
                fail_next_initialization_integrity: AtomicBool::new(false),
            });
        }

        let map_len = rounded_mapping_len(total_bytes).map_err(|error| {
            pre_mapping_error(
                request,
                total_bytes,
                ProtectionControl::Mapping,
                error.errno,
                false,
            )
        })?;
        let setup = setup_native_mapping(map_len, payload_bytes, request, false)?;

        Ok(Self {
            base: setup.ptr,
            map_len,
            slot_stride,
            locked: setup.locked,
            request,
            report: setup.report,
            used,
            generations,
            quarantined,
            #[cfg(all(test, feature = "canary-check"))]
            fail_next_initialization_integrity: AtomicBool::new(false),
        })
    }

    /// Number of bytes in each slot.
    #[must_use]
    #[inline]
    pub const fn slot_size(&self) -> usize {
        N
    }

    /// Number of slots in the pool.
    #[must_use]
    #[inline]
    pub const fn capacity_slots(&self) -> usize {
        SLOTS
    }

    /// Returns true when the pool cannot hold any secret bytes.
    #[must_use]
    #[inline]
    pub const fn is_empty(&self) -> bool {
        N == 0 || SLOTS == 0
    }

    /// Rounded platform mapping length locked by this pool.
    #[must_use]
    #[inline]
    pub const fn locked_len(&self) -> usize {
        self.report.locked_bytes
    }

    /// Actual runtime protections established for the pool mapping.
    #[must_use]
    #[inline]
    pub const fn protection_report(&self) -> &ProtectionReport {
        &self.report
    }

    /// Runtime protection policy requested for the pool mapping.
    #[must_use]
    #[inline]
    pub const fn protection_request(&self) -> ProtectionRequest {
        self.request
    }

    /// Returns true when the pool mapping is locked against ordinary paging.
    #[must_use]
    #[inline]
    pub const fn is_memory_locked(&self) -> bool {
        self.locked
    }

    /// Count slots that are currently available.
    ///
    /// This is a point-in-time observation. Other threads may allocate or
    /// release slots immediately after this method returns.
    #[must_use]
    #[inline]
    pub fn available_slots(&self) -> usize {
        self.used
            .iter()
            .enumerate()
            .filter(|(index, used)| {
                !used.load(Ordering::Acquire) && !self.quarantined[*index].load(Ordering::Acquire)
            })
            .count()
    }

    /// Count slots permanently withheld after an integrity failure.
    ///
    /// This is public operational metadata. It does not expose mapping
    /// addresses, canary values, or secret bytes.
    #[must_use]
    #[inline]
    pub fn quarantined_slots(&self) -> usize {
        self.quarantined
            .iter()
            .filter(|flag| flag.load(Ordering::Acquire))
            .count()
    }

    /// Capture fixed-arena capacity, utilization, and lock-overhead metadata.
    ///
    /// `live_slots` is a point-in-time observation. Other threads may allocate
    /// or release slots immediately after this method returns.
    #[must_use]
    pub fn arena_report(&self) -> SecretPoolReport {
        let live_slots = self
            .used
            .iter()
            .filter(|flag| flag.load(Ordering::Acquire))
            .count();
        let payload_capacity_bytes = N.saturating_mul(SLOTS);
        let reserved_bytes = self.slot_stride.saturating_mul(SLOTS);

        SecretPoolReport {
            slot_size: N,
            slot_stride: self.slot_stride,
            capacity_slots: SLOTS,
            live_slots,
            quarantined_slots: self.quarantined_slots(),
            payload_capacity_bytes,
            reserved_bytes,
            mapped_bytes: self.report.mapped_bytes,
            locked_bytes: self.report.locked_bytes,
            mapping_overhead_bytes: self.report.mapped_bytes.saturating_sub(reserved_bytes),
            locked_overhead_bytes: self
                .report
                .locked_bytes
                .saturating_sub(payload_capacity_bytes),
            page_granule: self.report.page_granule,
            lock_quota_likely: self.report.lock_quota_likely,
        }
    }

    /// Allocate one unused slot from the pool and report random-canary
    /// setup errors explicitly.
    ///
    /// `Ok(None)` means only that every non-quarantined slot is in use.
    /// Random-canary setup failures are returned as [`MemoryLockError`].
    #[inline]
    pub fn try_allocate(&self) -> Result<Option<SecretPoolSlot<'_, N, SLOTS>>, MemoryLockError> {
        for (slot_index, flag) in self.used.iter().enumerate() {
            if self.quarantined[slot_index].load(Ordering::Acquire) {
                continue;
            }
            if flag
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                let ptr = match self.slot_ptr(slot_index) {
                    Some(ptr) => ptr,
                    None => {
                        flag.store(false, Ordering::Release);
                        continue;
                    }
                };
                if self.quarantined[slot_index].load(Ordering::Acquire) {
                    flag.store(false, Ordering::Release);
                    continue;
                }
                let generation = advance_generation(&self.generations[slot_index]);
                let mut slot = SecretPoolSlot {
                    ptr,
                    slot_index,
                    pool: self,
                    generation,
                    #[cfg(feature = "canary-check")]
                    canaries_initialized: false,
                    #[cfg(feature = "random-canary")]
                    canary: crate::canary::CanaryMaterial::zeroed(),
                };
                if let Err(error) = slot.initialize_canaries() {
                    drop(slot);
                    return Err(error);
                }
                return Ok(Some(slot));
            }
        }

        Ok(None)
    }

    /// Allocate a slot and copy bytes from a same-length slice.
    ///
    /// Returns `Ok(None)` when the pool is full. A length mismatch returns
    /// an error without allocating a slot.
    #[inline]
    pub fn try_allocate_from_slice(
        &self,
        source: &[u8],
    ) -> Result<Option<SecretPoolSlot<'_, N, SLOTS>>, PoolInitError> {
        if source.len() != N {
            return Err(PoolInitError::Length(crate::LengthError {
                expected: N,
                actual: source.len(),
            }));
        }

        let Some(mut slot) = self.try_allocate().map_err(PoolInitError::Allocation)? else {
            return Ok(None);
        };

        #[cfg(feature = "canary-check")]
        self.inject_initialization_integrity_failure_for_test(&mut slot);

        slot.try_copy_from_slice(source)
            .map_err(|error| match error {
                SecretIntegrityError::Canary(error) => PoolInitError::Integrity(error),
                SecretIntegrityError::Operation(error) => PoolInitError::Length(error),
            })?;
        Ok(Some(slot))
    }

    /// Allocate a slot, copy an owned array into it, then clear this function's
    /// owned array parameter. Other caller-retained copies are unaffected.
    ///
    /// `Ok(None)` means only that the pool is exhausted. Platform setup and
    /// integrity failures remain distinct errors.
    #[inline]
    pub fn try_allocate_from_array(
        &self,
        mut bytes: [u8; N],
    ) -> Result<Option<SecretPoolSlot<'_, N, SLOTS>>, PoolInitError> {
        self.try_allocate_from_array_buffer(&mut bytes)
    }

    #[inline]
    fn try_allocate_from_array_buffer(
        &self,
        bytes: &mut [u8; N],
    ) -> Result<Option<SecretPoolSlot<'_, N, SLOTS>>, PoolInitError> {
        let result = match self.try_allocate().map_err(PoolInitError::Allocation) {
            Ok(Some(mut slot)) => {
                #[cfg(feature = "canary-check")]
                self.inject_initialization_integrity_failure_for_test(&mut slot);
                slot.try_copy_from_array(bytes)
                    .map_err(PoolInitError::Integrity)
                    .map(|()| Some(slot))
            }
            Ok(None) => Ok(None),
            Err(error) => Err(error),
        };

        crate::wipe::bytes(bytes);
        result
    }

    #[cfg(all(
        test,
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64"),
        not(miri)
    ))]
    #[inline]
    pub(crate) fn try_allocate_from_array_buffer_for_test(
        &self,
        bytes: &mut [u8; N],
    ) -> Result<Option<SecretPoolSlot<'_, N, SLOTS>>, PoolInitError> {
        self.try_allocate_from_array_buffer(bytes)
    }

    /// Allocate a slot and fallibly generate each byte directly inside it.
    ///
    /// If generation fails, the partially initialized slot is
    /// volatile-cleared and returned to the pool before the error is
    /// returned.
    #[inline]
    pub fn try_allocate_from_fn<E>(
        &self,
        make_byte: impl FnMut(usize) -> Result<u8, E>,
    ) -> Result<Option<SecretPoolSlot<'_, N, SLOTS>>, SecretPoolGenerateError<E>> {
        let Some(mut slot) = self
            .try_allocate()
            .map_err(SecretPoolGenerateError::Allocation)?
        else {
            return Ok(None);
        };

        #[cfg(feature = "canary-check")]
        self.inject_initialization_integrity_failure_for_test(&mut slot);

        slot.try_replace_from_fallible_fn(make_byte)
            .map_err(|error| match error {
                SecretIntegrityError::Canary(error) => SecretPoolGenerateError::Integrity(error),
                SecretIntegrityError::Operation(error) => SecretPoolGenerateError::Generate(error),
            })?;
        Ok(Some(slot))
    }

    /// Clear the full locked mapping and mark every slot available.
    ///
    /// This requires `&mut self`, so Rust prevents it while any live slot
    /// handle still borrows the pool.
    #[inline(never)]
    pub fn secure_clear(&mut self) {
        if self.map_len != 0 {
            crate::wipe_backend::erase(self.base.as_ptr(), self.map_len);
        }

        for flag in self.used.iter() {
            flag.store(false, Ordering::Release);
        }
        compiler_fence(Ordering::SeqCst);
    }

    #[cfg(feature = "cache-flush")]
    #[inline(never)]
    pub fn try_secure_clear_and_flush(
        &mut self,
    ) -> Result<crate::cache_flush::CacheFlushReport, crate::cache_flush::CacheFlushError> {
        self.secure_clear();
        crate::cache_flush::flush_cache_lines(self.as_mapping_slice())
    }

    #[inline]
    fn slot_ptr(&self, slot_index: usize) -> Option<NonNull<u8>> {
        if N == 0 {
            return Some(NonNull::dangling());
        }

        let offset = slot_index.checked_mul(self.slot_stride)?;
        // SAFETY: `slot_index < SLOTS`, construction checked the total
        // slot-stride size, and `map_len` is rounded up from that total.
        // Therefore `offset` is inside the live mapping for all allocated
        // non-zero slots.
        NonNull::new(unsafe { self.base.as_ptr().add(offset) })
    }

    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) fn quarantine_slot_for_test(&self, slot_index: usize, quarantined: bool) -> bool {
        let Some(flag) = self.quarantined.get(slot_index) else {
            return false;
        };
        if !quarantined {
            flag.store(false, Ordering::Release);
            return true;
        }

        flag.store(true, Ordering::Release);
        if self.used[slot_index].load(Ordering::Acquire) {
            flag.store(false, Ordering::Release);
            return false;
        }
        true
    }

    #[cfg(all(test, feature = "canary-check"))]
    #[inline]
    #[allow(dead_code)]
    pub(crate) fn fail_next_initialization_integrity_for_test(&self) {
        self.fail_next_initialization_integrity
            .store(true, Ordering::Release);
    }

    #[cfg(all(test, feature = "canary-check"))]
    #[inline]
    fn inject_initialization_integrity_failure_for_test(
        &self,
        slot: &mut SecretPoolSlot<'_, N, SLOTS>,
    ) {
        if self
            .fail_next_initialization_integrity
            .swap(false, Ordering::AcqRel)
        {
            slot.corrupt_prefix_canary_for_test();
        }
    }

    #[cfg(all(not(test), feature = "canary-check"))]
    #[inline]
    fn inject_initialization_integrity_failure_for_test(
        &self,
        _slot: &mut SecretPoolSlot<'_, N, SLOTS>,
    ) {
    }

    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) fn set_slot_generation_for_test(
        &self,
        slot_index: usize,
        generation: usize,
    ) -> bool {
        let Some(counter) = self.generations.get(slot_index) else {
            return false;
        };
        if !self.quarantined[slot_index].load(Ordering::Acquire)
            || self.used[slot_index].load(Ordering::Acquire)
        {
            return false;
        }
        counter.store(generation, Ordering::Release);
        true
    }

    #[cfg(feature = "canary-check")]
    #[inline]
    fn slot_stride() -> Result<usize, MemoryLockError> {
        if N == 0 {
            return Ok(0);
        }

        N.checked_add(CANARY_SIZE.saturating_mul(2))
            .ok_or(MemoryLockError {
                operation: MemoryLockOperation::Length,
                errno: 0,
            })
    }

    #[cfg(not(feature = "canary-check"))]
    #[inline]
    fn slot_stride() -> Result<usize, MemoryLockError> {
        Ok(N)
    }

    #[cfg(feature = "cache-flush")]
    #[inline]
    fn as_mapping_slice(&self) -> &[u8] {
        // SAFETY: `base` either points to a live mapping of `map_len` bytes
        // owned by this pool, or is dangling with `map_len == 0`.
        unsafe { core::slice::from_raw_parts(self.base.as_ptr(), self.map_len) }
    }
}

impl<'pool, const N: usize, const SLOTS: usize> SecretPoolSlot<'pool, N, SLOTS> {
    /// Number of secret bytes stored in this slot.
    #[must_use]
    #[inline]
    pub const fn len(&self) -> usize {
        N
    }

    /// Returns true when this slot stores zero bytes.
    #[must_use]
    #[inline]
    pub const fn is_empty(&self) -> bool {
        N == 0
    }

    /// Index of this slot inside the parent pool.
    #[must_use]
    #[inline]
    pub const fn slot_index(&self) -> usize {
        self.slot_index
    }

    /// Allocation generation assigned to this live slot handle.
    #[must_use]
    #[inline]
    pub const fn generation(&self) -> usize {
        self.generation
    }

    /// Stable diagnostic identity for this live slot allocation.
    ///
    /// Retaining this copy after the handle drops does not grant access. A
    /// later occupant of the same index receives a different generation.
    #[must_use]
    #[inline]
    pub const fn slot_id(&self) -> SecretPoolSlotId {
        SecretPoolSlotId {
            index: self.slot_index,
            generation: self.generation,
        }
    }

    /// Replace all slot bytes from a same-length slice.
    #[inline]
    pub fn try_copy_from_slice(
        &mut self,
        source: &[u8],
    ) -> Result<(), SecretIntegrityError<crate::LengthError>> {
        if source.len() != N {
            return Err(SecretIntegrityError::Operation(crate::LengthError {
                expected: N,
                actual: source.len(),
            }));
        }

        self.verify_integrity()?;
        self.as_mut_slice().copy_from_slice(source);
        compiler_fence(Ordering::SeqCst);
        Ok(())
    }

    /// Replacement-oriented alias for [`SecretPoolSlot::try_copy_from_slice`].
    #[inline]
    pub fn try_replace_from_slice(
        &mut self,
        source: &[u8],
    ) -> Result<(), SecretIntegrityError<crate::LengthError>> {
        self.try_copy_from_slice(source)
    }

    /// Replace all slot bytes from an owned array, then volatile-clear the
    /// input array.
    #[inline]
    pub fn try_replace_from_array(
        &mut self,
        mut bytes: [u8; N],
    ) -> Result<(), CanaryCorruptedError> {
        let result = self.try_copy_from_array(&bytes);
        crate::wipe::bytes(&mut bytes);
        result
    }

    #[inline]
    fn try_copy_from_array(&mut self, source: &[u8; N]) -> Result<(), CanaryCorruptedError> {
        self.verify_integrity()?;
        self.as_mut_slice().copy_from_slice(source);
        compiler_fence(Ordering::SeqCst);
        Ok(())
    }

    /// Replace all slot bytes with generated bytes.
    #[inline]
    pub fn try_replace_from_fn(
        &mut self,
        mut make_byte: impl FnMut(usize) -> u8,
    ) -> Result<(), CanaryCorruptedError> {
        self.verify_integrity()?;
        let mut index = 0;
        while index < N {
            self.as_mut_slice()[index] = make_byte(index);
            index += 1;
        }
        compiler_fence(Ordering::SeqCst);
        Ok(())
    }

    /// Replace all slot bytes with fallibly generated bytes.
    ///
    /// If generation fails, bytes already written by this call are cleared
    /// before the error is returned.
    #[inline]
    pub fn try_replace_from_fallible_fn<E>(
        &mut self,
        mut make_byte: impl FnMut(usize) -> Result<u8, E>,
    ) -> Result<(), SecretIntegrityError<E>> {
        self.verify_integrity()?;
        let mut index = 0;
        while index < N {
            match make_byte(index) {
                Ok(byte) => self.as_mut_slice()[index] = byte,
                Err(error) => {
                    self.secure_clear();
                    return Err(SecretIntegrityError::Operation(error));
                }
            }
            index += 1;
        }
        compiler_fence(Ordering::SeqCst);
        Ok(())
    }

    /// Fill a caller-provided destination with a copy of the slot bytes.
    #[inline]
    pub fn try_copy_to_slice(
        &self,
        destination: &mut [u8],
    ) -> Result<(), SecretIntegrityError<crate::LengthError>> {
        if destination.len() != N {
            return Err(SecretIntegrityError::Operation(crate::LengthError {
                expected: N,
                actual: destination.len(),
            }));
        }

        self.verify_integrity()?;
        destination.copy_from_slice(self.as_slice());
        compiler_fence(Ordering::SeqCst);
        core::hint::black_box(destination);
        Ok(())
    }

    /// Run a closure with read-only access to the slot bytes.
    ///
    /// The closure can copy the secret elsewhere. Keep usage limited to
    /// protocol or cryptographic boundaries that genuinely need raw bytes.
    #[inline]
    pub fn try_expose_secret<R>(
        &self,
        inspect: impl FnOnce(&[u8; N]) -> R,
    ) -> Result<R, CanaryCorruptedError> {
        self.verify_integrity()?;
        let result = inspect(self.as_array());
        self.verify_integrity()?;
        Ok(result)
    }

    /// Verify integrity, copy into temporary stack storage, and expose the copy.
    ///
    /// The temporary is volatile-cleared on normal return and unwinding. It
    /// cannot be cleared if the process aborts.
    #[inline]
    pub fn try_expose_secret_copy<R>(
        &self,
        inspect: impl FnOnce(&[u8; N]) -> R,
    ) -> Result<R, CanaryCorruptedError> {
        self.verify_integrity()?;
        Ok(crate::owned::expose_array_copy(self.as_array(), inspect))
    }

    /// Run a closure with mutable access to the slot bytes.
    #[inline]
    pub fn try_with_secret_mut<R>(
        &mut self,
        inspect: impl FnOnce(&mut [u8; N]) -> R,
    ) -> Result<R, CanaryCorruptedError> {
        self.verify_integrity()?;
        let result = inspect(self.as_array_mut());
        compiler_fence(Ordering::SeqCst);
        self.verify_integrity()?;
        Ok(result)
    }

    /// Verify this slot's canaries.
    #[inline]
    pub fn verify_integrity(&self) -> Result<(), CanaryCorruptedError> {
        #[cfg(not(feature = "canary-check"))]
        {
            return Ok(());
        }
        #[cfg(feature = "canary-check")]
        if !self.pool.quarantined[self.slot_index].load(Ordering::Acquire) && self.canaries_intact()
        {
            Ok(())
        } else {
            self.clear_after_canary_failure();
            Err(CanaryCorruptedError)
        }
    }

    /// Compare against a slice without early exit for equal-length inputs.
    ///
    /// Length mismatch returns immediately because the provided slice
    /// length is treated as public metadata.
    #[inline]
    pub fn try_constant_time_eq(&self, other: &[u8]) -> Result<bool, CanaryCorruptedError> {
        self.verify_integrity()?;
        Ok(crate::constant_time_eq_slices(self.as_slice(), other))
    }

    /// Clear only this slot with volatile writes.
    #[inline(never)]
    pub fn secure_clear(&mut self) {
        if N != 0 {
            crate::wipe_backend::erase(self.ptr.as_ptr(), self.slot_stride());
        }
        self.write_canaries();
    }

    /// Consume this slot after clearing it, then return it to the pool.
    #[inline]
    pub fn into_cleared(mut self) {
        self.secure_clear();
    }

    /// Clear this slot with volatile writes, then flush its cache lines.
    #[cfg(feature = "cache-flush")]
    #[inline(never)]
    pub fn try_secure_clear_and_flush(
        &mut self,
    ) -> Result<crate::cache_flush::CacheFlushReport, crate::cache_flush::CacheFlushError> {
        self.secure_clear();
        crate::cache_flush::flush_cache_lines(self.as_slot_slice())
    }

    /// Run a closure with shared access, panicking on canary corruption.
    #[inline]
    pub fn expose_secret_or_panic<R>(&self, inspect: impl FnOnce(&[u8; N]) -> R) -> R {
        self.try_expose_secret(inspect)
            .unwrap_or_else(|_| panic!("pooled secret slot canary corrupted"))
    }

    /// Expose a temporary copy, panicking on canary corruption.
    #[inline]
    pub fn expose_secret_copy_or_panic<R>(&self, inspect: impl FnOnce(&[u8; N]) -> R) -> R {
        self.try_expose_secret_copy(inspect)
            .unwrap_or_else(|_| panic!("pooled secret slot canary corrupted"))
    }

    /// Run a closure with mutable access, panicking on canary corruption.
    #[inline]
    pub fn with_secret_mut_or_panic<R>(&mut self, inspect: impl FnOnce(&mut [u8; N]) -> R) -> R {
        self.try_with_secret_mut(inspect)
            .unwrap_or_else(|_| panic!("pooled secret slot canary corrupted"))
    }

    /// Compare, panicking on canary corruption.
    #[must_use]
    #[inline]
    pub fn constant_time_eq_or_panic(&self, other: &[u8]) -> bool {
        self.try_constant_time_eq(other)
            .unwrap_or_else(|_| panic!("pooled secret slot canary corrupted"))
    }

    #[inline]
    fn as_slice(&self) -> &[u8] {
        // SAFETY: `data_ptr` points to this live slot's `N` bytes in the
        // parent pool mapping, or is dangling with `N == 0`.
        unsafe { core::slice::from_raw_parts(self.data_ptr(), N) }
    }

    #[inline]
    fn as_mut_slice(&mut self) -> &mut [u8] {
        // SAFETY: `&mut self` gives exclusive access to this live slot, and
        // the pool bitmap prevents another live safe handle for the same
        // slot until this value drops.
        unsafe { core::slice::from_raw_parts_mut(self.data_ptr(), N) }
    }

    #[inline]
    fn as_array(&self) -> &[u8; N] {
        // SAFETY: `as_slice` is exactly `N` bytes long, and the pointer is
        // valid for a `[u8; N]` reference for the duration of `&self`.
        unsafe { &*(self.data_ptr() as *const [u8; N]) }
    }

    #[inline]
    fn as_array_mut(&mut self) -> &mut [u8; N] {
        // SAFETY: `as_mut_slice` is exactly `N` bytes long, and `&mut self`
        // provides exclusive access to this slot for the returned borrow.
        unsafe { &mut *(self.data_ptr() as *mut [u8; N]) }
    }

    #[inline]
    fn data_ptr(&self) -> *mut u8 {
        // SAFETY: non-empty canary-checked slots reserve an 8-byte prefix.
        unsafe { self.ptr.as_ptr().add(Self::data_offset()) }
    }

    #[cfg(feature = "canary-check")]
    #[inline]
    const fn data_offset() -> usize {
        if N == 0 {
            0
        } else {
            CANARY_SIZE
        }
    }

    #[cfg(not(feature = "canary-check"))]
    #[inline]
    const fn data_offset() -> usize {
        0
    }

    #[inline]
    fn slot_stride(&self) -> usize {
        self.pool.slot_stride
    }

    #[cfg(feature = "cache-flush")]
    #[inline]
    fn as_slot_slice(&self) -> &[u8] {
        // SAFETY: `ptr` points to this live slot's full stride, or is
        // dangling with zero stride.
        unsafe { core::slice::from_raw_parts(self.ptr.as_ptr(), self.slot_stride()) }
    }

    #[cfg(all(feature = "canary-check", not(feature = "random-canary")))]
    #[inline]
    fn canary_value(&self) -> [u8; CANARY_SIZE] {
        let generation = (self.generation as u64).wrapping_mul(CANARY_GENERATION_MIX);
        ((self.ptr.as_ptr() as u64) ^ generation ^ CANARY_MASK).to_ne_bytes()
    }

    #[cfg(feature = "random-canary")]
    #[inline]
    fn with_canary<R>(&self, use_canary: impl FnOnce(&[u8; CANARY_SIZE]) -> R) -> R {
        use_canary(self.canary.as_bytes())
    }

    #[cfg(all(feature = "canary-check", not(feature = "random-canary")))]
    #[inline]
    fn with_canary<R>(&self, use_canary: impl FnOnce(&[u8; CANARY_SIZE]) -> R) -> R {
        let canary = self.canary_value();
        use_canary(&canary)
    }

    #[cfg(feature = "random-canary")]
    #[inline]
    fn initialize_canaries(&mut self) -> Result<(), MemoryLockError> {
        if N == 0 {
            self.canaries_initialized = true;
            return Ok(());
        }

        self.canary = random_canary_value()?;
        self.write_canaries();
        self.canaries_initialized = true;
        Ok(())
    }

    #[cfg(all(feature = "canary-check", not(feature = "random-canary")))]
    #[inline]
    fn initialize_canaries(&mut self) -> Result<(), MemoryLockError> {
        self.write_canaries();
        self.canaries_initialized = true;
        Ok(())
    }

    #[cfg(not(feature = "canary-check"))]
    #[inline]
    fn initialize_canaries(&mut self) -> Result<(), MemoryLockError> {
        Ok(())
    }

    #[cfg(feature = "canary-check")]
    #[inline]
    fn canaries_intact(&self) -> bool {
        if N == 0 {
            return true;
        }

        // SAFETY: non-empty canary-checked slots reserve prefix and suffix
        // canary regions inside the slot stride.
        let prefix = unsafe { core::slice::from_raw_parts(self.ptr.as_ptr(), CANARY_SIZE) };
        // SAFETY: the suffix follows exactly `CANARY_SIZE + N` bytes after
        // the slot base and remains inside the checked stride.
        let suffix = unsafe {
            core::slice::from_raw_parts(self.ptr.as_ptr().add(CANARY_SIZE + N), CANARY_SIZE)
        };

        self.with_canary(|expected| {
            crate::constant_time_eq_slices(prefix, expected)
                & crate::constant_time_eq_slices(suffix, expected)
        })
    }

    #[cfg(feature = "canary-check")]
    #[inline]
    fn write_canaries(&mut self) {
        if N == 0 {
            return;
        }

        self.with_canary(|canary| {
            // SAFETY: non-empty canary-checked slots reserve prefix and suffix
            // canary regions inside the slot stride.
            unsafe {
                core::ptr::copy_nonoverlapping(canary.as_ptr(), self.ptr.as_ptr(), CANARY_SIZE);
                core::ptr::copy_nonoverlapping(
                    canary.as_ptr(),
                    self.ptr.as_ptr().add(CANARY_SIZE + N),
                    CANARY_SIZE,
                );
            }
        });
        compiler_fence(Ordering::SeqCst);
    }

    #[cfg(not(feature = "canary-check"))]
    #[inline]
    fn write_canaries(&mut self) {}

    #[cfg(feature = "canary-check")]
    #[inline]
    fn clear_after_canary_failure(&self) {
        if N != 0 {
            // Fail-closed clearing intentionally mutates the uniquely owned
            // slot mapping through `&self`. Slot handles are `Send` but not
            // `Sync`, and the parent bitmap prevents a second safe handle
            // for this slot.
            crate::wipe_backend::erase(self.ptr.as_ptr(), self.slot_stride());
        }
        self.pool.quarantined[self.slot_index].store(true, Ordering::Release);
    }

    #[cfg(all(test, feature = "canary-check"))]
    #[allow(dead_code)]
    #[inline]
    pub(crate) fn corrupt_prefix_canary_for_test(&mut self) {
        if N == 0 {
            return;
        }

        // SAFETY: non-empty canary-checked slots start with a live prefix
        // canary byte.
        unsafe {
            let byte = self.ptr.as_ptr();
            core::ptr::write(byte, core::ptr::read(byte) ^ 0xFF);
        }
    }

    #[cfg(all(
        test,
        feature = "canary-check",
        not(feature = "random-canary"),
        feature = "std"
    ))]
    #[allow(dead_code)]
    #[inline]
    pub(crate) fn deterministic_canary_for_test(&self) -> [u8; CANARY_SIZE] {
        self.canary_value()
    }
}

impl<const N: usize, const SLOTS: usize> Drop for SecretPool<N, SLOTS> {
    #[inline]
    fn drop(&mut self) {
        self.secure_clear();

        if self.map_len != 0 {
            crate::wipe_backend::erase(self.base.as_ptr(), self.map_len);
            if self.locked {
                let _ = backend_unlock_mapping(self.base, self.map_len);
            }
            let _ = backend_unmap_private(self.base, self.map_len);
        }
    }
}

impl<'pool, const N: usize, const SLOTS: usize> Drop for SecretPoolSlot<'pool, N, SLOTS> {
    #[inline]
    fn drop(&mut self) {
        #[cfg(feature = "canary-check")]
        if self.canaries_initialized && !self.canaries_intact() {
            self.clear_after_canary_failure();
            #[cfg(feature = "random-canary")]
            self.canary.clear();
            self.pool.used[self.slot_index].store(false, Ordering::Release);
            return;
        }

        self.secure_clear();
        #[cfg(feature = "random-canary")]
        self.canary.clear();
        self.pool.used[self.slot_index].store(false, Ordering::Release);
    }
}

impl<const N: usize, const SLOTS: usize> crate::SecureSanitize for SecretPool<N, SLOTS> {
    #[inline]
    fn secure_sanitize(&mut self) {
        self.secure_clear();
    }
}

impl<const N: usize, const SLOTS: usize> crate::StableSharedSecretStorage for SecretPool<N, SLOTS> {}

impl<const N: usize, const SLOTS: usize> crate::StableMutableSecretStorage
    for SecretPool<N, SLOTS>
{
}

impl<'pool, const N: usize, const SLOTS: usize> crate::SecureSanitize
    for SecretPoolSlot<'pool, N, SLOTS>
{
    #[inline]
    fn secure_sanitize(&mut self) {
        self.secure_clear();
    }
}

impl<'pool, const N: usize, const SLOTS: usize> crate::StableSharedSecretStorage
    for SecretPoolSlot<'pool, N, SLOTS>
{
}

impl<'pool, const N: usize, const SLOTS: usize> crate::StableMutableSecretStorage
    for SecretPoolSlot<'pool, N, SLOTS>
{
}

impl<const N: usize, const SLOTS: usize> fmt::Debug for SecretPool<N, SLOTS> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretPool")
            .field("slot_size", &N)
            .field("capacity_slots", &SLOTS)
            .field("locked_len", &self.map_len)
            .field("contents", &"<redacted>")
            .finish()
    }
}

impl<'pool, const N: usize, const SLOTS: usize> fmt::Debug for SecretPoolSlot<'pool, N, SLOTS> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretPoolSlot")
            .field("len", &N)
            .field("slot_index", &self.slot_index)
            .field("generation", &self.generation)
            .field("contents", &"<redacted>")
            .finish()
    }
}

#[inline]
fn advance_generation(generation: &AtomicUsize) -> usize {
    let mut current = generation.load(Ordering::Relaxed);
    loop {
        let mut next = current.wrapping_add(1);
        if next == 0 {
            next = 1;
        }
        match generation.compare_exchange_weak(current, next, Ordering::AcqRel, Ordering::Relaxed) {
            Ok(_) => return next,
            Err(observed) => current = observed,
        }
    }
}

struct NativeMappingSetup {
    ptr: NonNull<u8>,
    locked: bool,
    report: ProtectionReport,
}

fn empty_native_report(
    request: ProtectionRequest,
    requested_bytes: usize,
    guard_pages: bool,
) -> Result<ProtectionReport, ProtectionError> {
    let mut report = ProtectionReport::pending(request, requested_bytes, backend_page_granule());
    report.mapping = ProtectionState::NotApplicable;
    report.memory_lock = resolve_empty_control(request.memory_lock);
    report.dump_exclusion = resolve_empty_control(request.dump_exclusion);
    report.fork.state = resolve_empty_fork(request.fork);
    report.guard_pages = if guard_pages {
        ProtectionState::NotApplicable
    } else {
        resolve_unavailable(request.guard_pages, ProtectionControl::GuardPages, &report)?
    };
    report.canary = resolve_empty_control(request.canary);
    report.cache_policy = resolve_unavailable(
        request.cache_policy,
        ProtectionControl::CachePolicy,
        &report,
    )?;
    Ok(report)
}

fn setup_native_mapping(
    map_len: usize,
    requested_bytes: usize,
    request: ProtectionRequest,
    guard_pages: bool,
) -> Result<NativeMappingSetup, ProtectionError> {
    let mut report = ProtectionReport::pending(request, requested_bytes, backend_page_granule());
    report.guard_pages = if guard_pages {
        ProtectionState::Established
    } else {
        resolve_unavailable(request.guard_pages, ProtectionControl::GuardPages, &report)?
    };
    report.canary = resolve_canary(request.canary, &report)?;
    report.cache_policy = resolve_unavailable(
        request.cache_policy,
        ProtectionControl::CachePolicy,
        &report,
    )?;

    let ptr = match backend_map_private(map_len) {
        Ok(ptr) => ptr,
        Err(error) => {
            report.mapping = ProtectionState::Failed { code: error.errno };
            return Err(ProtectionError {
                failure: ProtectionFailure {
                    control: ProtectionControl::Mapping,
                    code: error.errno,
                },
                partial_report: report,
                rollback: RollbackReport::not_needed(),
            });
        }
    };
    report.mapping = ProtectionState::Established;
    report.mapped_bytes = map_len;

    report.dump_exclusion = apply_native_control(
        request.dump_exclusion,
        dump_exclusion_supported(),
        ProtectionControl::DumpExclusion,
        &mut report,
        ptr,
        map_len,
        backend_mark_dontdump,
    )?;
    report.fork.state = apply_native_fork_policy(request.fork, &mut report, ptr, map_len)?;
    report.memory_lock = apply_native_control(
        request.memory_lock,
        true,
        ProtectionControl::MemoryLock,
        &mut report,
        ptr,
        map_len,
        backend_lock_mapping,
    )?;
    let locked = report.memory_lock == ProtectionState::Established;
    if locked {
        report.locked_bytes = map_len;
    }

    Ok(NativeMappingSetup {
        ptr,
        locked,
        report,
    })
}

fn apply_native_fork_policy(
    request: ForkProtectionRequest,
    report: &mut ProtectionReport,
    ptr: NonNull<u8>,
    len: usize,
) -> Result<ProtectionState, ProtectionError> {
    match request.policy {
        ForkPolicy::Inherit => Ok(ProtectionState::Established),
        ForkPolicy::Exclude => apply_native_control(
            request.requirement,
            fork_exclusion_supported(),
            ProtectionControl::ForkPolicy,
            report,
            ptr,
            len,
            backend_mark_dontfork,
        ),
        ForkPolicy::WipeChild => apply_native_control(
            request.requirement,
            wipe_child_supported(),
            ProtectionControl::ForkPolicy,
            report,
            ptr,
            len,
            backend_mark_wipeonfork,
        ),
    }
}

fn apply_native_control(
    requirement: Requirement,
    supported: bool,
    control: ProtectionControl,
    report: &mut ProtectionReport,
    ptr: NonNull<u8>,
    len: usize,
    apply: fn(NonNull<u8>, usize) -> Result<(), MemoryLockError>,
) -> Result<ProtectionState, ProtectionError> {
    if requirement == Requirement::NotRequested {
        return Ok(ProtectionState::NotRequested);
    }
    if !supported {
        if requirement == Requirement::Preferred {
            return Ok(ProtectionState::Unsupported);
        }
        set_failed_state(report, control, 0);
        return Err(ProtectionError {
            failure: ProtectionFailure { control, code: 0 },
            partial_report: *report,
            rollback: rollback_native_mapping(ptr, len, false),
        });
    }

    #[cfg(all(
        test,
        feature = "std",
        feature = "profile-guarded-native",
        any(target_os = "macos", target_os = "linux"),
        not(miri)
    ))]
    let apply = |ptr, len| {
        if super::native_tests::fail(control) {
            Err(MemoryLockError {
                operation: MemoryLockOperation::DontFork,
                errno: 0,
            })
        } else {
            apply(ptr, len)
        }
    };
    match apply(ptr, len) {
        Ok(()) => Ok(ProtectionState::Established),
        Err(error) => {
            if control == ProtectionControl::MemoryLock {
                report.lock_quota_likely = lock_quota_likely(error.errno);
            }
            if requirement == Requirement::Preferred {
                return Ok(ProtectionState::Failed { code: error.errno });
            }

            set_failed_state(report, control, error.errno);
            Err(ProtectionError {
                failure: ProtectionFailure {
                    control,
                    code: error.errno,
                },
                partial_report: *report,
                rollback: rollback_native_mapping(ptr, len, false),
            })
        }
    }
}

fn resolve_unavailable(
    requirement: Requirement,
    control: ProtectionControl,
    report: &ProtectionReport,
) -> Result<ProtectionState, ProtectionError> {
    match super::protection::unavailable_state(requirement) {
        Ok(state) => Ok(state),
        Err(()) => Err(ProtectionError {
            failure: ProtectionFailure { control, code: 0 },
            partial_report: *report,
            rollback: RollbackReport::not_needed(),
        }),
    }
}

fn resolve_canary(
    requirement: Requirement,
    report: &ProtectionReport,
) -> Result<ProtectionState, ProtectionError> {
    #[cfg(feature = "canary-check")]
    {
        let _ = requirement;
        let _ = report;
        Ok(ProtectionState::Established)
    }
    #[cfg(not(feature = "canary-check"))]
    {
        resolve_unavailable(requirement, ProtectionControl::Canary, report)
    }
}

const fn resolve_empty_control(requirement: Requirement) -> ProtectionState {
    match requirement {
        Requirement::NotRequested => ProtectionState::NotRequested,
        Requirement::Required | Requirement::Preferred => ProtectionState::NotApplicable,
    }
}

const fn resolve_empty_fork(request: ForkProtectionRequest) -> ProtectionState {
    match request.policy {
        ForkPolicy::Inherit => ProtectionState::Established,
        ForkPolicy::Exclude | ForkPolicy::WipeChild => resolve_empty_control(request.requirement),
    }
}

fn pre_mapping_error(
    request: ProtectionRequest,
    requested_bytes: usize,
    control: ProtectionControl,
    code: i32,
    guard_pages: bool,
) -> ProtectionError {
    let mut report = ProtectionReport::pending(request, requested_bytes, backend_page_granule());
    if guard_pages {
        report.guard_pages = ProtectionState::Failed { code };
    }
    set_failed_state(&mut report, control, code);
    ProtectionError {
        failure: ProtectionFailure { control, code },
        partial_report: report,
        rollback: RollbackReport::not_needed(),
    }
}

fn set_failed_state(report: &mut ProtectionReport, control: ProtectionControl, code: i32) {
    let state = ProtectionState::Failed { code };
    match control {
        ProtectionControl::Mapping => report.mapping = state,
        ProtectionControl::MemoryLock => report.memory_lock = state,
        ProtectionControl::DumpExclusion => report.dump_exclusion = state,
        ProtectionControl::ForkPolicy => report.fork.state = state,
        ProtectionControl::GuardPages => report.guard_pages = state,
        ProtectionControl::Canary => report.canary = state,
        ProtectionControl::CachePolicy => report.cache_policy = state,
    }
}

fn rollback_native_mapping(ptr: NonNull<u8>, len: usize, locked: bool) -> RollbackReport {
    let unlock = if locked {
        match backend_unlock_mapping(ptr, len) {
            Ok(()) => RollbackState::Completed,
            Err(error) => RollbackState::Failed(ProtectionFailure {
                control: ProtectionControl::MemoryLock,
                code: error.errno,
            }),
        }
    } else {
        RollbackState::NotNeeded
    };
    let unmap = match backend_unmap_private(ptr, len) {
        Ok(()) => RollbackState::Completed,
        Err(error) => RollbackState::Failed(ProtectionFailure {
            control: ProtectionControl::Mapping,
            code: error.errno,
        }),
    };
    RollbackReport { unlock, unmap }
}

fn protection_error_as_memory_lock(error: ProtectionError) -> MemoryLockError {
    if let RollbackState::Failed(failure) = error.rollback.unmap {
        return MemoryLockError {
            operation: MemoryLockOperation::Unmap,
            errno: failure.code,
        };
    }
    if let RollbackState::Failed(failure) = error.rollback.unlock {
        return MemoryLockError {
            operation: MemoryLockOperation::Unlock,
            errno: failure.code,
        };
    }

    MemoryLockError {
        operation: match error.failure.control {
            ProtectionControl::Mapping => MemoryLockOperation::Map,
            ProtectionControl::MemoryLock => MemoryLockOperation::Lock,
            ProtectionControl::DumpExclusion => MemoryLockOperation::DontDump,
            ProtectionControl::ForkPolicy => match error.partial_report.fork.policy {
                ForkPolicy::WipeChild => MemoryLockOperation::WipeOnFork,
                ForkPolicy::Inherit | ForkPolicy::Exclude => MemoryLockOperation::DontFork,
            },
            ProtectionControl::GuardPages | ProtectionControl::CachePolicy => {
                MemoryLockOperation::Map
            }
            ProtectionControl::Canary => MemoryLockOperation::Random,
        },
        errno: error.failure.code,
    }
}

#[inline]
const fn lock_quota_likely(code: i32) -> bool {
    matches!(code, 11 | 12 | 1453)
}

#[inline]
const fn dump_exclusion_supported() -> bool {
    cfg!(any(target_os = "linux", target_os = "freebsd"))
}

#[inline]
const fn fork_exclusion_supported() -> bool {
    cfg!(any(target_os = "linux", target_os = "macos"))
}

#[inline]
const fn wipe_child_supported() -> bool {
    cfg!(target_os = "linux")
}

#[cfg(feature = "random-canary")]
fn random_canary_value() -> Result<crate::canary::CanaryMaterial, MemoryLockError> {
    #[cfg(all(
        test,
        feature = "std",
        feature = "profile-guarded-native",
        any(target_os = "macos", target_os = "linux"),
        not(miri)
    ))]
    if super::native_tests::fail(ProtectionControl::Canary) {
        return Err(MemoryLockError {
            operation: MemoryLockOperation::Random,
            errno: 0,
        });
    }
    crate::canary::CanaryMaterial::random().map_err(|errno| MemoryLockError {
        operation: MemoryLockOperation::Random,
        errno,
    })
}

fn rounded_mapping_len(len: usize) -> Result<usize, MemoryLockError> {
    let page_granule = backend_page_granule();
    len.checked_add(page_granule - 1)
        .map(|value| value & !(page_granule - 1))
        .ok_or(MemoryLockError {
            operation: MemoryLockOperation::Length,
            errno: 0,
        })
}

#[cfg(not(all(miri, test)))]
#[inline]
fn backend_page_granule() -> usize {
    platform_page_granule()
}

#[cfg(all(miri, test))]
#[inline]
const fn backend_page_granule() -> usize {
    // This is an allocator alignment for the Miri model, not an observed OS
    // page size and not evidence that page-granule controls were established.
    4096
}

#[cfg(not(all(miri, test)))]
#[inline]
fn backend_map_private(len: usize) -> Result<NonNull<u8>, MemoryLockError> {
    #[cfg(all(
        test,
        feature = "std",
        feature = "profile-guarded-native",
        any(target_os = "macos", target_os = "linux"),
        not(miri)
    ))]
    if super::native_tests::fail(ProtectionControl::Mapping) {
        return Err(MemoryLockError {
            operation: MemoryLockOperation::Map,
            errno: 0,
        });
    }
    let ptr = map_private(len)?;
    #[cfg(all(
        test,
        feature = "std",
        feature = "profile-guarded-native",
        any(target_os = "macos", target_os = "linux"),
        not(miri)
    ))]
    {
        super::native_tests::mapped(ptr.as_ptr(), len);
        super::native_tests::writable(ptr.as_ptr(), len);
    }
    Ok(ptr)
}

#[cfg(all(miri, test))]
fn backend_map_private(len: usize) -> Result<NonNull<u8>, MemoryLockError> {
    use std::alloc::{alloc_zeroed, Layout};

    let layout =
        Layout::from_size_align(len, backend_page_granule()).map_err(|_| MemoryLockError {
            operation: MemoryLockOperation::Length,
            errno: 0,
        })?;
    // SAFETY: `layout` has non-zero size and valid power-of-two alignment.
    // The returned allocation is owned by the mapped container until the
    // matching Miri-only `backend_unmap_private` call.
    let ptr = unsafe { alloc_zeroed(layout) };
    NonNull::new(ptr).ok_or(MemoryLockError {
        operation: MemoryLockOperation::Map,
        errno: 0,
    })
}

#[cfg(not(all(miri, test)))]
#[inline]
fn backend_lock_mapping(ptr: NonNull<u8>, len: usize) -> Result<(), MemoryLockError> {
    lock_mapping(ptr, len)
}

#[cfg(all(miri, test))]
#[inline]
fn backend_lock_mapping(_ptr: NonNull<u8>, _len: usize) -> Result<(), MemoryLockError> {
    // Modeled success permits state-transition testing. No OS memory lock is
    // attempted or claimed under Miri.
    Ok(())
}

#[cfg(not(all(miri, test)))]
#[inline]
fn backend_mark_dontdump(ptr: NonNull<u8>, len: usize) -> Result<(), MemoryLockError> {
    mark_dontdump(ptr, len)
}

#[cfg(all(miri, test))]
#[inline]
fn backend_mark_dontdump(_ptr: NonNull<u8>, _len: usize) -> Result<(), MemoryLockError> {
    Ok(())
}

#[cfg(not(all(miri, test)))]
#[inline]
fn backend_mark_dontfork(ptr: NonNull<u8>, len: usize) -> Result<(), MemoryLockError> {
    mark_dontfork(ptr, len)
}

#[cfg(all(miri, test))]
#[inline]
fn backend_mark_dontfork(_ptr: NonNull<u8>, _len: usize) -> Result<(), MemoryLockError> {
    Ok(())
}

#[cfg(not(all(miri, test)))]
#[inline]
fn backend_mark_wipeonfork(ptr: NonNull<u8>, len: usize) -> Result<(), MemoryLockError> {
    mark_wipeonfork(ptr, len)
}

#[cfg(all(miri, test))]
#[inline]
fn backend_mark_wipeonfork(_ptr: NonNull<u8>, _len: usize) -> Result<(), MemoryLockError> {
    Ok(())
}

#[cfg(not(all(miri, test)))]
#[inline]
fn backend_unlock_mapping(ptr: NonNull<u8>, len: usize) -> Result<(), MemoryLockError> {
    unlock_mapping(ptr, len)
}

#[cfg(all(miri, test))]
#[inline]
fn backend_unlock_mapping(_ptr: NonNull<u8>, _len: usize) -> Result<(), MemoryLockError> {
    Ok(())
}

#[cfg(not(all(miri, test)))]
#[inline]
fn backend_unmap_private(ptr: NonNull<u8>, len: usize) -> Result<(), MemoryLockError> {
    #[cfg(all(
        test,
        feature = "std",
        feature = "profile-guarded-native",
        any(target_os = "macos", target_os = "linux"),
        not(miri)
    ))]
    super::native_tests::before_unmap(ptr.as_ptr());
    let result = unmap_private(ptr, len);
    #[cfg(all(
        test,
        feature = "std",
        feature = "profile-guarded-native",
        any(target_os = "macos", target_os = "linux"),
        not(miri)
    ))]
    super::native_tests::unmapped(ptr.as_ptr(), result.is_ok());
    result
}

#[cfg(all(miri, test))]
fn backend_unmap_private(ptr: NonNull<u8>, len: usize) -> Result<(), MemoryLockError> {
    use std::alloc::{dealloc, Layout};

    // SAFETY: `ptr` and `len` identify the live allocation created by
    // `backend_map_private`. Reading it before release is valid and turns
    // clear-before-release into an executable Miri invariant.
    let mapping = unsafe { core::slice::from_raw_parts(ptr.as_ptr(), len) };
    assert!(
        mapping.iter().all(|byte| *byte == 0),
        "Miri mapping released before its complete byte range was cleared"
    );
    let layout =
        Layout::from_size_align(len, backend_page_granule()).map_err(|_| MemoryLockError {
            operation: MemoryLockOperation::Length,
            errno: 0,
        })?;
    // SAFETY: the allocation was created with the same layout and has not
    // previously been released.
    unsafe { dealloc(ptr.as_ptr(), layout) };
    Ok(())
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[inline]
const fn platform_page_granule() -> usize {
    LINUX_PAGE_GRANULE
}

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
#[inline]
fn platform_page_granule() -> usize {
    crate::platform::linux_aarch64_page_size::detect_page_granule()
}

#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "android",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly",
))]
#[inline]
fn platform_page_granule() -> usize {
    // SAFETY: `getpagesize` takes no arguments and returns the process page
    // size according to the platform C ABI.
    let page_size = unsafe { getpagesize() };
    if page_size > 0 && (page_size as usize).is_power_of_two() {
        page_size as usize
    } else {
        UNIX_FALLBACK_PAGE_GRANULE
    }
}

#[cfg(target_os = "windows")]
#[inline]
fn platform_page_granule() -> usize {
    let mut info = MaybeUninit::<SystemInfo>::zeroed();
    // SAFETY: `GetSystemInfo` initializes the provided `SYSTEM_INFO`
    // structure according to the Windows ABI.
    unsafe {
        GetSystemInfo(info.as_mut_ptr());
        let page_size = info.assume_init().page_size as usize;
        if page_size != 0 && page_size.is_power_of_two() {
            page_size
        } else {
            WINDOWS_FALLBACK_PAGE_GRANULE
        }
    }
}

#[cfg(target_os = "linux")]
fn syscall_failed(ret: isize) -> bool {
    (-4095..=-1).contains(&ret)
}

#[cfg(target_os = "linux")]
fn syscall_error(operation: MemoryLockOperation, ret: isize) -> MemoryLockError {
    MemoryLockError {
        operation,
        errno: (-ret) as i32,
    }
}

#[cfg(target_os = "windows")]
fn windows_error(operation: MemoryLockOperation) -> MemoryLockError {
    // SAFETY: `GetLastError` takes no arguments and returns the calling
    // thread's last-error code.
    let errno = unsafe { GetLastError() } as i32;
    MemoryLockError { operation, errno }
}

#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "android",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly",
))]
fn unix_error(operation: MemoryLockOperation) -> MemoryLockError {
    MemoryLockError {
        operation,
        errno: unix_errno(),
    }
}

#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "android",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly",
))]
fn unix_errno() -> i32 {
    // SAFETY: `errno_location` returns a pointer to the calling thread's
    // errno according to the target C ABI.
    unsafe { *errno_location() as i32 }
}

#[cfg(target_os = "linux")]
fn map_private(len: usize) -> Result<NonNull<u8>, MemoryLockError> {
    let ret = raw_syscall6(
        SYS_MMAP,
        0,
        len,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        MAP_FD_ANONYMOUS,
        0,
    );

    if syscall_failed(ret) {
        return Err(syscall_error(MemoryLockOperation::Map, ret));
    }

    NonNull::new(ret as *mut u8).ok_or(MemoryLockError {
        operation: MemoryLockOperation::Map,
        errno: 0,
    })
}

#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "android",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly",
))]
fn map_private(len: usize) -> Result<NonNull<u8>, MemoryLockError> {
    // SAFETY: Arguments request a new private anonymous read/write mapping.
    let ptr = unsafe {
        mmap(
            core::ptr::null_mut(),
            len,
            (PROT_READ | PROT_WRITE) as i32,
            (MAP_PRIVATE | MAP_ANONYMOUS) as i32,
            -1,
            0,
        )
    };

    if ptr as isize == -1 {
        return Err(unix_error(MemoryLockOperation::Map));
    }

    NonNull::new(ptr.cast::<u8>()).ok_or(MemoryLockError {
        operation: MemoryLockOperation::Map,
        errno: 0,
    })
}

#[cfg(target_os = "windows")]
fn map_private(len: usize) -> Result<NonNull<u8>, MemoryLockError> {
    // SAFETY: Arguments request a new private committed/reserved read/write
    // region owned by this process.
    let ptr = unsafe {
        VirtualAlloc(
            core::ptr::null_mut(),
            len,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        )
    };

    NonNull::new(ptr.cast::<u8>()).ok_or_else(|| windows_error(MemoryLockOperation::Map))
}

#[cfg(target_os = "linux")]
fn lock_mapping(ptr: NonNull<u8>, len: usize) -> Result<(), MemoryLockError> {
    let ret = raw_syscall2(SYS_MLOCK, ptr.as_ptr() as usize, len);
    if syscall_failed(ret) {
        Err(syscall_error(MemoryLockOperation::Lock, ret))
    } else {
        Ok(())
    }
}

#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "android",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly",
))]
fn lock_mapping(ptr: NonNull<u8>, len: usize) -> Result<(), MemoryLockError> {
    // SAFETY: `ptr` and `len` describe a live mapping owned by this value.
    let ret = unsafe { mlock(ptr.as_ptr().cast::<c_void>(), len) };
    if ret != 0 {
        Err(unix_error(MemoryLockOperation::Lock))
    } else {
        Ok(())
    }
}

#[cfg(target_os = "windows")]
fn lock_mapping(ptr: NonNull<u8>, len: usize) -> Result<(), MemoryLockError> {
    // SAFETY: `ptr` and `len` describe a live region owned by this value.
    let ret = unsafe { VirtualLock(ptr.as_ptr().cast::<c_void>(), len) };
    if ret == 0 {
        Err(windows_error(MemoryLockOperation::Lock))
    } else {
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn mark_dontdump(ptr: NonNull<u8>, len: usize) -> Result<(), MemoryLockError> {
    let ret = raw_syscall3(SYS_MADVISE, ptr.as_ptr() as usize, len, MADV_DONTDUMP);
    if syscall_failed(ret) {
        Err(syscall_error(MemoryLockOperation::DontDump, ret))
    } else {
        Ok(())
    }
}

#[cfg(all(not(target_os = "linux"), not(target_os = "freebsd")))]
#[inline]
fn mark_dontdump(_ptr: NonNull<u8>, _len: usize) -> Result<(), MemoryLockError> {
    Ok(())
}

#[cfg(target_os = "freebsd")]
fn mark_dontdump(ptr: NonNull<u8>, len: usize) -> Result<(), MemoryLockError> {
    // SAFETY: `ptr` and `len` describe a live private mapping owned by this
    // value, and `MADV_NOCORE` requests core-dump exclusion for it.
    let ret = unsafe { madvise(ptr.as_ptr().cast::<c_void>(), len, MADV_NOCORE) };
    if ret != 0 {
        Err(unix_error(MemoryLockOperation::DontDump))
    } else {
        Ok(())
    }
}

// SDK: sys/mman.h declares int minherit(void *, size_t, int).
// mach/vm_inherit.h defines VM_INHERIT_NONE as 2 (absent from child).
#[cfg(target_os = "macos")]
unsafe extern "C" {
    fn minherit(addr: *mut c_void, len: usize, inherit: c_int) -> c_int;
}

#[cfg(target_os = "macos")]
fn mark_dontfork(ptr: NonNull<u8>, len: usize) -> Result<(), MemoryLockError> {
    const VM_INHERIT_NONE: c_int = 2;
    // SAFETY: the owning constructor supplies the entire live, page-aligned
    // writable region, before any caller initializer can run. The SDK ABI
    // takes size_t (usize), not a truncated 32-bit length.
    if unsafe { minherit(ptr.as_ptr().cast::<c_void>(), len, VM_INHERIT_NONE) } != 0 {
        Err(unix_error(MemoryLockOperation::DontFork))
    } else {
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn mark_dontfork(ptr: NonNull<u8>, len: usize) -> Result<(), MemoryLockError> {
    let ret = raw_syscall3(SYS_MADVISE, ptr.as_ptr() as usize, len, MADV_DONTFORK);
    if syscall_failed(ret) {
        Err(syscall_error(MemoryLockOperation::DontFork, ret))
    } else {
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn mark_wipeonfork(ptr: NonNull<u8>, len: usize) -> Result<(), MemoryLockError> {
    let ret = raw_syscall3(SYS_MADVISE, ptr.as_ptr() as usize, len, MADV_WIPEONFORK);
    if syscall_failed(ret) {
        Err(syscall_error(MemoryLockOperation::WipeOnFork, ret))
    } else {
        Ok(())
    }
}

#[cfg(not(target_os = "linux"))]
#[inline]
fn mark_wipeonfork(_ptr: NonNull<u8>, _len: usize) -> Result<(), MemoryLockError> {
    Err(MemoryLockError {
        operation: MemoryLockOperation::WipeOnFork,
        errno: 0,
    })
}

#[cfg(all(
    not(any(target_os = "linux", target_os = "macos")),
    not(feature = "require-fork-exclusion")
))]
#[inline]
fn mark_dontfork(_ptr: NonNull<u8>, _len: usize) -> Result<(), MemoryLockError> {
    Ok(())
}

#[cfg(all(
    not(any(target_os = "linux", target_os = "macos")),
    feature = "require-fork-exclusion"
))]
#[inline]
fn mark_dontfork(_ptr: NonNull<u8>, _len: usize) -> Result<(), MemoryLockError> {
    Err(MemoryLockError {
        operation: MemoryLockOperation::DontFork,
        errno: 0,
    })
}

#[cfg(target_os = "linux")]
fn unlock_mapping(ptr: NonNull<u8>, len: usize) -> Result<(), MemoryLockError> {
    let ret = raw_syscall2(SYS_MUNLOCK, ptr.as_ptr() as usize, len);
    if syscall_failed(ret) {
        Err(syscall_error(MemoryLockOperation::Unlock, ret))
    } else {
        Ok(())
    }
}

#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "android",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly",
))]
fn unlock_mapping(ptr: NonNull<u8>, len: usize) -> Result<(), MemoryLockError> {
    // SAFETY: `ptr` and `len` describe a live mapping owned by this value.
    let ret = unsafe { munlock(ptr.as_ptr().cast::<c_void>(), len) };
    if ret != 0 {
        Err(unix_error(MemoryLockOperation::Unlock))
    } else {
        Ok(())
    }
}

#[cfg(target_os = "windows")]
fn unlock_mapping(ptr: NonNull<u8>, len: usize) -> Result<(), MemoryLockError> {
    // SAFETY: `ptr` and `len` describe a live region owned by this value.
    let ret = unsafe { VirtualUnlock(ptr.as_ptr().cast::<c_void>(), len) };
    if ret == 0 {
        Err(windows_error(MemoryLockOperation::Unlock))
    } else {
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn unmap_private(ptr: NonNull<u8>, len: usize) -> Result<(), MemoryLockError> {
    let ret = raw_syscall2(SYS_MUNMAP, ptr.as_ptr() as usize, len);
    if syscall_failed(ret) {
        Err(syscall_error(MemoryLockOperation::Unmap, ret))
    } else {
        Ok(())
    }
}

#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "android",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly",
))]
fn unmap_private(ptr: NonNull<u8>, len: usize) -> Result<(), MemoryLockError> {
    // SAFETY: `ptr` and `len` describe a live mapping owned by this value.
    let ret = unsafe { munmap(ptr.as_ptr().cast::<c_void>(), len) };
    if ret != 0 {
        Err(unix_error(MemoryLockOperation::Unmap))
    } else {
        Ok(())
    }
}

#[cfg(target_os = "windows")]
fn unmap_private(ptr: NonNull<u8>, _len: usize) -> Result<(), MemoryLockError> {
    // SAFETY: `ptr` points to a region allocated by `VirtualAlloc`.
    let ret = unsafe { VirtualFree(ptr.as_ptr().cast::<c_void>(), 0, MEM_RELEASE) };
    if ret == 0 {
        Err(windows_error(MemoryLockOperation::Unmap))
    } else {
        Ok(())
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn raw_syscall2(number: usize, arg1: usize, arg2: usize) -> isize {
    raw_syscall6(number, arg1, arg2, 0, 0, 0, 0)
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn raw_syscall3(number: usize, arg1: usize, arg2: usize, arg3: usize) -> isize {
    raw_syscall6(number, arg1, arg2, arg3, 0, 0, 0)
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn raw_syscall6(
    number: usize,
    arg1: usize,
    arg2: usize,
    arg3: usize,
    arg4: usize,
    arg5: usize,
    arg6: usize,
) -> isize {
    let ret: isize;

    // SAFETY: Registers follow the Linux x86_64 syscall ABI. The syscall
    // number and arguments are fixed by the caller wrappers above.
    unsafe {
        asm!(
            "syscall",
            inlateout("rax") number as isize => ret,
            in("rdi") arg1,
            in("rsi") arg2,
            in("rdx") arg3,
            in("r10") arg4,
            in("r8") arg5,
            in("r9") arg6,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack)
        );
    }

    ret
}

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
fn raw_syscall2(number: usize, arg1: usize, arg2: usize) -> isize {
    raw_syscall6(number, arg1, arg2, 0, 0, 0, 0)
}

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
fn raw_syscall3(number: usize, arg1: usize, arg2: usize, arg3: usize) -> isize {
    raw_syscall6(number, arg1, arg2, arg3, 0, 0, 0)
}

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
fn raw_syscall6(
    number: usize,
    arg1: usize,
    arg2: usize,
    arg3: usize,
    arg4: usize,
    arg5: usize,
    arg6: usize,
) -> isize {
    let ret: isize;

    // SAFETY: Registers follow the Linux aarch64 syscall ABI. The syscall
    // number and arguments are fixed by the caller wrappers above.
    unsafe {
        asm!(
            "svc 0",
            inlateout("x0") arg1 as isize => ret,
            in("x1") arg2,
            in("x2") arg3,
            in("x3") arg4,
            in("x4") arg5,
            in("x5") arg6,
            in("x8") number,
            options(nostack)
        );
    }

    ret
}

#[cfg(all(
    test,
    feature = "std",
    feature = "profile-guarded-native",
    any(target_os = "macos", target_os = "linux"),
    not(miri)
))]
#[test]
fn native_locked_fork_excludes_entire_writable_region() {
    let mut owner = LockedSecretVec::with_capacity_with_protection(
        backend_page_granule() + 1,
        super::native_tests::request(false),
    )
    .expect("native locked setup");
    owner.as_mut_capacity_slice().fill(0xa5);
    assert!(super::native_tests::range_absent_after_fork(
        owner.ptr.as_ptr(),
        owner.map_len
    ));
    assert!(owner
        .as_mut_capacity_slice()
        .iter()
        .all(|byte| *byte == 0xa5));
}
