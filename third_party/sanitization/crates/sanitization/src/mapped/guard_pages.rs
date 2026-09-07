#[cfg(feature = "page-seal")]
use core::mem::ManuallyDrop;
use core::{
    fmt,
    ptr::NonNull,
    sync::atomic::{compiler_fence, Ordering},
};

#[cfg(feature = "canary-check")]
use core::cell::Cell;

use super::{
    protection::replacement_request_preserving_established, CanaryCorruptedError, ForkPolicy,
    ForkProtectionRequest, ProtectedSecretFillError, ProtectionControl, ProtectionError,
    ProtectionFailure, ProtectionReport, ProtectionRequest, ProtectionState, Requirement,
    RollbackReport, RollbackState, SecretIntegrityError,
};

#[cfg(all(
    test,
    feature = "page-seal",
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64"),
    not(all(miri, test))
))]
unsafe extern "C" {
    fn fork() -> i32;
    fn waitpid(pid: i32, status: *mut i32, options: i32) -> i32;
    fn _exit(status: i32) -> !;
}

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

// Guard layout must place the writable region on a kernel page boundary.
// Linux x86_64 uses 4 KiB. Linux aarch64 is detected at runtime from auxv
// and falls back to 64 KiB if detection fails.
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
const PROT_NONE: usize = 0x0;
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
#[cfg(all(feature = "memory-lock", target_os = "freebsd"))]
const MADV_NOCORE: i32 = 8;

#[cfg(target_os = "linux")]
const PROT_NONE: usize = 0x0;
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
#[cfg(feature = "memory-lock")]
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
const PAGE_NOACCESS: u32 = 0x01;
#[cfg(target_os = "windows")]
const PAGE_READWRITE: u32 = 0x04;

#[cfg(feature = "canary-check")]
const CANARY_SIZE: usize = 8;
#[cfg(all(feature = "canary-check", not(feature = "random-canary")))]
const CANARY_MASK: u64 = 0xA11C_E5AF_EC0D_EC0D;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const SYS_MMAP: usize = 9;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const SYS_MPROTECT: usize = 10;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const SYS_MUNMAP: usize = 11;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const SYS_MADVISE: usize = 28;
#[cfg(all(feature = "memory-lock", target_os = "linux", target_arch = "x86_64"))]
const SYS_MLOCK: usize = 149;
#[cfg(all(feature = "memory-lock", target_os = "linux", target_arch = "x86_64"))]
const SYS_MUNLOCK: usize = 150;

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
const SYS_MMAP: usize = 222;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
const SYS_MPROTECT: usize = 226;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
const SYS_MUNMAP: usize = 215;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
const SYS_MADVISE: usize = 233;
#[cfg(all(feature = "memory-lock", target_os = "linux", target_arch = "aarch64"))]
const SYS_MLOCK: usize = 228;
#[cfg(all(feature = "memory-lock", target_os = "linux", target_arch = "aarch64"))]
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
    fn mprotect(addr: *mut c_void, len: usize, prot: i32) -> i32;
    fn munmap(addr: *mut c_void, len: usize) -> i32;
    #[cfg(all(feature = "memory-lock", target_os = "freebsd"))]
    fn madvise(addr: *mut c_void, len: usize, advice: i32) -> i32;
    #[cfg(feature = "memory-lock")]
    fn mlock(addr: *const c_void, len: usize) -> i32;
    #[cfg(feature = "memory-lock")]
    fn munlock(addr: *const c_void, len: usize) -> i32;

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
    fn VirtualProtect(
        address: *mut c_void,
        size: usize,
        new_protect: u32,
        old_protect: *mut u32,
    ) -> i32;
    #[cfg(feature = "memory-lock")]
    fn VirtualLock(address: *mut c_void, size: usize) -> i32;
    #[cfg(feature = "memory-lock")]
    fn VirtualUnlock(address: *mut c_void, size: usize) -> i32;
}

/// Platform guard-page operation that failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GuardPageOperation {
    /// Requested length arithmetic overflowed.
    Length,
    /// Anonymous mapping creation failed.
    Map,
    /// Data-page protection update failed.
    Protect,
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

/// Error returned by guarded secret allocation operations.
///
/// If setup and the subsequent cleanup unmap both fail, the returned error
/// reports `Unmap`. A mapping that may still be live takes diagnostic
/// precedence over the original setup failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GuardPageError {
    /// Operation that failed.
    pub operation: GuardPageOperation,
    /// Positive errno or Windows `GetLastError` value when available.
    ///
    /// This is `0` for local arithmetic failures before a syscall.
    /// Negative values are crate-internal sentinel failures, such as an
    /// unsupported random-canary backend or a random backend that made no
    /// progress.
    pub errno: i32,
}

impl fmt::Display for GuardPageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "guard page operation {:?} failed with errno {}",
            self.operation, self.errno
        )
    }
}

#[cfg(feature = "std")]
impl std::error::Error for GuardPageError {}

/// Outcome of one explicit page-sealed cleanup operation.
#[cfg(feature = "page-seal")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CleanupState {
    /// The operation did not apply to this mapping.
    NotNeeded,
    /// The operation completed successfully.
    Completed,
    /// The operation failed. The error contains only the public operation and
    /// platform error code.
    Failed(GuardPageError),
}

#[cfg(feature = "page-seal")]
impl CleanupState {
    /// Return the public operation failure, when one occurred.
    #[must_use]
    #[inline]
    pub const fn failure(self) -> Option<GuardPageError> {
        match self {
            Self::Failed(error) => Some(error),
            Self::NotNeeded | Self::Completed => None,
        }
    }
}

/// Observable result of explicit page-sealed mapping cleanup.
///
/// This report contains no secret bytes, mapping addresses, or canary values.
#[cfg(feature = "page-seal")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CleanupReport {
    /// Outcome of normalizing every data page to writable protection before
    /// clearing.
    pub normalization: CleanupState,
    /// Outcome of releasing the operating-system memory lock.
    pub unlock: CleanupState,
    /// Outcome of releasing the guarded mapping.
    pub unmap: CleanupState,
}

#[cfg(feature = "page-seal")]
impl CleanupReport {
    /// Return true when every required cleanup operation completed.
    #[must_use]
    #[inline]
    pub const fn completed(self) -> bool {
        !self.normalization_failed() && !self.unlock_failed() && !self.unmap_failed()
    }

    /// Return true when page-protection normalization failed.
    #[must_use]
    #[inline]
    pub const fn normalization_failed(self) -> bool {
        matches!(self.normalization, CleanupState::Failed(_))
    }

    /// Return true when memory unlocking failed.
    #[must_use]
    #[inline]
    pub const fn unlock_failed(self) -> bool {
        matches!(self.unlock, CleanupState::Failed(_))
    }

    /// Return true when mapping release failed.
    #[must_use]
    #[inline]
    pub const fn unmap_failed(self) -> bool {
        matches!(self.unmap, CleanupState::Failed(_))
    }

    /// Return the first failed operation in normalization, unlock, unmap
    /// order.
    #[must_use]
    #[inline]
    pub const fn first_failure(self) -> Option<GuardPageError> {
        if let Some(error) = self.normalization.failure() {
            return Some(error);
        }
        if let Some(error) = self.unlock.failure() {
            return Some(error);
        }
        self.unmap.failure()
    }
}

/// Error returned when explicit page-sealed cleanup is incomplete.
#[cfg(feature = "page-seal")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CleanupError {
    failure: GuardPageError,
    report: CleanupReport,
}

#[cfg(feature = "page-seal")]
impl CleanupError {
    fn from_report(report: CleanupReport) -> Option<Self> {
        report
            .first_failure()
            .map(|failure| Self { failure, report })
    }

    /// Outcomes of every cleanup operation that was attempted.
    #[must_use]
    #[inline]
    pub const fn report(self) -> CleanupReport {
        self.report
    }

    /// Operation associated with the first cleanup failure.
    #[must_use]
    #[inline]
    pub const fn operation(self) -> GuardPageOperation {
        self.failure.operation
    }

    /// Platform error code associated with the first cleanup failure.
    #[must_use]
    #[inline]
    pub const fn errno(self) -> i32 {
        self.failure.errno
    }
}

#[cfg(feature = "page-seal")]
impl fmt::Display for CleanupError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "page-sealed cleanup failed: {}", self.failure)
    }
}

#[cfg(all(feature = "page-seal", feature = "std"))]
impl std::error::Error for CleanupError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.failure)
    }
}

impl From<GuardPageError> for SecretIntegrityError<GuardPageError> {
    #[inline]
    fn from(error: GuardPageError) -> Self {
        Self::Operation(error)
    }
}

/// Error returned when fallible guarded byte generation fails.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GuardedSecretVecGenerateError<E> {
    /// Guarded mapping setup, protection, locking, unlocking, or unmapping
    /// failed before generation completed.
    Guard(GuardPageError),
    /// The caller-provided byte generator failed.
    Generate(E),
}

impl<E: fmt::Display> fmt::Display for GuardedSecretVecGenerateError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Guard(error) => error.fmt(formatter),
            Self::Generate(error) => error.fmt(formatter),
        }
    }
}

#[cfg(feature = "std")]
impl<E> std::error::Error for GuardedSecretVecGenerateError<E>
where
    E: std::error::Error + 'static,
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Guard(error) => Some(error),
            Self::Generate(error) => Some(error),
        }
    }
}

impl<E> From<GuardPageError> for GuardedSecretVecGenerateError<E> {
    #[inline]
    fn from(error: GuardPageError) -> Self {
        Self::Guard(error)
    }
}

/// Dynamic secret bytes stored between inaccessible platform guard pages.
///
/// This type is available with the `guard-pages` feature on supported
/// Linux, Android, macOS, iOS, Windows, and BSD targets. Secret bytes live
/// in private platform mappings. The pages immediately before and after
/// the writable data region remain inaccessible, so linear overreads or
/// overwrites past the mapped data region fault instead of reaching
/// unrelated memory.
///
/// The secret bytes are not allocated with the Rust global allocator.
pub struct GuardedSecretVec {
    base: NonNull<u8>,
    data: NonNull<u8>,
    map_len: usize,
    writable_len: usize,
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

// SAFETY: The value exclusively owns a private guarded mapping. Moving
// ownership to another thread does not invalidate the mapping, and
// mutation/clearing still requires `&mut self`. `Sync` is intentionally not
// implemented.
unsafe impl Send for GuardedSecretVec {}

impl GuardedSecretVec {
    /// Create an empty guarded secret buffer with at least `capacity` bytes
    /// of writable data space.
    pub fn with_capacity(capacity: usize) -> Result<Self, GuardPageError> {
        Self::with_capacity_with_protection(capacity, ProtectionRequest::guarded())
            .map_err(protection_error_as_guard_page)
    }

    /// Create guarded storage with the `profile-guarded-native` policy.
    ///
    /// Guard pages, memory locking, and canaries are required. Preferred dump
    /// and fork exclusion outcomes remain visible through
    /// [`GuardedSecretVec::protection_report`].
    #[cfg(feature = "profile-guarded-native")]
    #[inline]
    pub fn with_capacity_guarded_native(capacity: usize) -> Result<Self, ProtectionError> {
        Self::with_capacity_with_protection(capacity, ProtectionRequest::profile_guarded_native())
    }

    /// Create an empty guarded secret buffer and lock its writable data
    /// pages with the platform memory-locking backend.
    ///
    /// This constructor is available when both `guard-pages` and
    /// `memory-lock` are enabled. Locking can fail due to operating-system
    /// resource limits or policy. Core-dump and fork-inheritance exclusion
    /// can fail if the kernel rejects the requested `madvise` policies. On
    /// failure, the mapping is unmapped before the error is returned. Guard
    /// pages are not locked because they never contain secret bytes.
    #[cfg(feature = "memory-lock")]
    pub fn locked_with_capacity(capacity: usize) -> Result<Self, GuardPageError> {
        Self::with_capacity_with_protection(capacity, ProtectionRequest::locked_guarded())
            .map_err(protection_error_as_guard_page)
    }

    /// Create guarded storage under an explicit runtime protection policy.
    ///
    /// Guard pages are intrinsic to this type and are always required.
    /// Preferred lock, dump, or fork controls may fail while construction
    /// succeeds with an explicit reduced-protection report.
    pub fn with_capacity_with_protection(
        capacity: usize,
        request: ProtectionRequest,
    ) -> Result<Self, ProtectionError> {
        #[cfg(feature = "random-canary")]
        let canary = random_canary_value().map_err(|error| {
            guard_pre_mapping_error(request, capacity, ProtectionControl::Canary, error.errno)
        })?;

        let page_granule = platform_page_granule();
        let mut report = ProtectionReport::pending(request, capacity, page_granule);
        report.canary = resolve_guard_canary(request.canary, &report)?;
        report.cache_policy = resolve_guard_unavailable(
            request.cache_policy,
            ProtectionControl::CachePolicy,
            &report,
        )?;

        let data_capacity = guarded_payload_capacity(capacity).map_err(|error| {
            guard_pre_mapping_error(request, capacity, ProtectionControl::Mapping, error.errno)
        })?;
        let writable_len = guarded_writable_len(data_capacity).map_err(|error| {
            guard_pre_mapping_error(request, capacity, ProtectionControl::Mapping, error.errno)
        })?;
        let total_len = writable_len
            .checked_add(page_granule)
            .and_then(|value| value.checked_add(page_granule))
            .ok_or_else(|| {
                guard_pre_mapping_error(request, capacity, ProtectionControl::Mapping, 0)
            })?;

        let base = match allocate_guarded(total_len) {
            Ok(base) => base,
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
        report.mapped_bytes = total_len;
        let data_addr = match (base.as_ptr() as usize).checked_add(page_granule) {
            Some(address) => address,
            None => {
                report.guard_pages = ProtectionState::Failed { code: 0 };
                return Err(guard_required_error(
                    base,
                    total_len,
                    ProtectionControl::GuardPages,
                    0,
                    report,
                ));
            }
        };
        let data = match NonNull::new(data_addr as *mut u8) {
            Some(data) => data,
            None => {
                report.guard_pages = ProtectionState::Failed { code: 0 };
                return Err(guard_required_error(
                    base,
                    total_len,
                    ProtectionControl::GuardPages,
                    0,
                    report,
                ));
            }
        };

        if let Err(error) = establish_guard_data(data, writable_len) {
            report.guard_pages = ProtectionState::Failed { code: error.errno };
            return Err(guard_required_error(
                base,
                total_len,
                ProtectionControl::GuardPages,
                error.errno,
                report,
            ));
        }
        report.guard_pages = ProtectionState::Established;
        #[cfg(all(
            test,
            feature = "std",
            feature = "profile-guarded-native",
            any(target_os = "macos", target_os = "linux"),
            not(miri)
        ))]
        super::native_tests::writable(data.as_ptr(), writable_len);

        report.dump_exclusion = apply_guard_control(
            request.dump_exclusion,
            dump_exclusion_supported(),
            ProtectionControl::DumpExclusion,
            &mut report,
            base,
            total_len,
            data,
            writable_len,
            guard_mark_dontdump,
        )?;
        report.fork.state = apply_guard_fork_policy(
            request.fork,
            &mut report,
            base,
            total_len,
            data,
            writable_len,
        )?;
        report.memory_lock = apply_guard_control(
            request.memory_lock,
            cfg!(feature = "memory-lock"),
            ProtectionControl::MemoryLock,
            &mut report,
            base,
            total_len,
            data,
            writable_len,
            guard_lock_mapping,
        )?;
        let locked = report.memory_lock == ProtectionState::Established;
        if locked {
            report.locked_bytes = writable_len;
        }

        let mut secret = Self {
            base,
            data,
            map_len: total_len,
            writable_len,
            data_capacity,
            len: 0,
            locked,
            request,
            report,
            #[cfg(feature = "canary-check")]
            poisoned: Cell::new(false),
            #[cfg(feature = "random-canary")]
            canary,
        };
        secret.write_canaries();
        Ok(secret)
    }

    /// Create guarded dynamic storage by copying a slice only after all
    /// required controls have been established.
    ///
    /// Guard pages are intrinsic and required. Mark memory locking, dump
    /// exclusion, fork policy, canaries, or other controls
    /// [`Requirement::Required`] when they must also precede secret
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

    /// Generate bytes directly into guarded dynamic storage after all
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

    /// Fallibly generate bytes directly into guarded dynamic storage after
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

    /// Fill an exact-length guarded payload only after all required controls
    /// have been established.
    ///
    /// If `fill` panics, clear-on-drop ownership remains active for the entire
    /// writable mapping during unwinding.
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
    /// [`GuardedSecretVec::from_exact_len_with_protection`].
    ///
    /// The fill closure is never invoked when a required control fails. A
    /// fill error clears the complete writable mapping before returning.
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

    /// Fill guarded dynamic storage and return the initialized byte length.
    ///
    /// This is the infallible-fill counterpart of
    /// [`GuardedSecretVec::try_from_capacity_with_protection`].
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
    /// [`GuardedSecretVec::try_from_capacity_with_protection`].
    ///
    /// Use this constructor whenever `capacity` originates from an untrusted
    /// protocol length, decoder hint, or message field. A capacity above
    /// `maximum` is rejected before mapping, protection setup, or invoking
    /// `fill`.
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

    /// Fill guarded dynamic storage only after all required controls have
    /// been established.
    ///
    /// This unbounded constructor supports trusted capacities that the
    /// application has already limited. Use
    /// [`GuardedSecretVec::try_from_capacity_bounded_with_protection`] at
    /// untrusted protocol boundaries. No plaintext is materialized before
    /// mandatory guard, lock, dump, fork, or canary controls succeed. The
    /// closure is not invoked when any
    /// [`Requirement::Required`] control fails. Controls marked
    /// [`Requirement::Preferred`] retain their normal degraded-success
    /// semantics and remain visible through [`GuardedSecretVec::protection_report`].
    ///
    /// If `fill` fails or reports more than `capacity` initialized bytes, the
    /// complete writable mapping is cleared before the error is returned.
    /// Unused tail bytes are also cleared before successful construction.
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
        // Empty construction places the suffix canary at payload offset zero.
        // Clear the complete writable payload before moving it so fill code
        // cannot observe canary material or stale page contents.
        {
            let destination = secret.as_mut_capacity_slice();
            crate::wipe_backend::erase(destination.as_mut_ptr(), destination.len());
        }
        // During filling, place the suffix canary at the caller-visible
        // capacity boundary rather than at the page-rounded payload end.
        // This detects an unsafe decoder writing beyond the advertised
        // output slice before the canary is moved to the initialized length.
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
            secret.corrupt_suffix_canary_for_test();
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
            // SAFETY: `index < data_capacity`, and the guarded writable region
            // remains mapped for the duration of `&self`.
            if unsafe { core::ptr::read_volatile(self.payload_ptr().add(index)) } != 0 {
                return false;
            }
            index += 1;
        }
        true
    }

    /// Create a guarded secret buffer by copying bytes from a slice.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, GuardPageError> {
        let mut secret = Self::with_capacity(bytes.len())?;
        secret.as_mut_capacity_slice()[..bytes.len()].copy_from_slice(bytes);
        secret.finish_initialization(bytes.len());
        Ok(secret)
    }

    /// Create a guarded secret buffer by writing generated bytes directly
    /// into the guarded mapping.
    ///
    /// This avoids staging dynamically generated secret bytes in an
    /// ordinary intermediate allocation before they enter guarded storage.
    pub fn from_fn(
        len: usize,
        mut make_byte: impl FnMut(usize) -> u8,
    ) -> Result<Self, GuardPageError> {
        let mut secret = Self::with_capacity(len)?;
        secret.fill_from_fn(len, &mut make_byte);
        Ok(secret)
    }

    /// Create a guarded secret buffer by fallibly writing generated bytes
    /// directly into the guarded mapping.
    ///
    /// If generation fails, any bytes already written into the guarded
    /// mapping are cleared before the error is returned.
    pub fn try_from_fn<E>(
        len: usize,
        mut make_byte: impl FnMut(usize) -> Result<u8, E>,
    ) -> Result<Self, GuardedSecretVecGenerateError<E>> {
        let mut secret = Self::with_capacity(len)?;
        secret
            .fill_from_try_fn(len, &mut make_byte)
            .map_err(GuardedSecretVecGenerateError::Generate)?;
        Ok(secret)
    }

    /// Create a guarded and memory-locked secret buffer by copying bytes
    /// from a slice.
    ///
    /// The writable data pages are locked before bytes are copied into
    /// them. OS-specific dump or fork-exclusion policies are applied where
    /// the backend supports them.
    #[cfg(feature = "memory-lock")]
    pub fn locked_from_slice(bytes: &[u8]) -> Result<Self, GuardPageError> {
        let mut secret = Self::locked_with_capacity(bytes.len())?;
        secret.as_mut_capacity_slice()[..bytes.len()].copy_from_slice(bytes);
        secret.finish_initialization(bytes.len());
        Ok(secret)
    }

    /// Create a guarded and memory-locked secret buffer by writing
    /// generated bytes directly into the locked guarded mapping.
    ///
    /// The writable data pages are locked before bytes are generated into
    /// them. OS-specific dump or fork-exclusion policies are applied where
    /// the backend supports them.
    #[cfg(feature = "memory-lock")]
    pub fn locked_from_fn(
        len: usize,
        mut make_byte: impl FnMut(usize) -> u8,
    ) -> Result<Self, GuardPageError> {
        let mut secret = Self::locked_with_capacity(len)?;
        secret.fill_from_fn(len, &mut make_byte);
        Ok(secret)
    }

    /// Create a guarded and memory-locked secret buffer by fallibly writing
    /// generated bytes directly into the locked guarded mapping.
    ///
    /// OS-specific dump or fork-exclusion policies are applied where the
    /// backend supports them. If generation fails, partial bytes are
    /// cleared before the error is returned.
    #[cfg(feature = "memory-lock")]
    pub fn locked_try_from_fn<E>(
        len: usize,
        mut make_byte: impl FnMut(usize) -> Result<u8, E>,
    ) -> Result<Self, GuardedSecretVecGenerateError<E>> {
        let mut secret = Self::locked_with_capacity(len)?;
        secret
            .fill_from_try_fn(len, &mut make_byte)
            .map_err(GuardedSecretVecGenerateError::Generate)?;
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

    /// Writable data capacity between the guard pages.
    #[must_use]
    #[inline]
    pub const fn capacity(&self) -> usize {
        self.data_capacity
    }

    /// Returns true when this guarded mapping was locked with `mlock`.
    #[must_use]
    #[inline]
    pub const fn is_memory_locked(&self) -> bool {
        self.locked
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

    #[cfg(all(test, target_os = "linux", not(feature = "memory-lock")))]
    pub(crate) fn mark_memory_lock_established_for_replacement_test(&mut self) {
        self.report.memory_lock = ProtectionState::Established;
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

    /// Append bytes, growing into a new guarded mapping if needed.
    pub fn try_extend_from_slice(
        &mut self,
        bytes: &[u8],
    ) -> Result<(), SecretIntegrityError<GuardPageError>> {
        self.verify_integrity()?;
        let required = self
            .len
            .checked_add(bytes.len())
            .ok_or(SecretIntegrityError::Operation(GuardPageError {
                operation: GuardPageOperation::Length,
                errno: 0,
            }))?;

        if required > self.data_capacity {
            self.grow_to(required)?;
        }

        let start = self.len;
        let end = required;
        self.as_mut_capacity_slice()[start..end].copy_from_slice(bytes);
        self.finish_initialization(required);
        Ok(())
    }

    /// Replace all initialized secret bytes with a new slice.
    ///
    /// If the current guarded mapping is large enough, the old writable
    /// region is cleared before the new bytes are copied in. If the new
    /// value requires a larger mapping, a replacement mapping is allocated
    /// without permitting an established preferred control to downgrade,
    /// populated with the new bytes, and then the old mapping is cleared
    /// before it is unmapped.
    pub fn try_replace_from_slice(
        &mut self,
        bytes: &[u8],
    ) -> Result<(), SecretIntegrityError<GuardPageError>> {
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

    /// Replace all initialized secret bytes with generated bytes.
    ///
    /// A replacement mapping is allocated without permitting an established
    /// preferred control to downgrade, then populated before the old mapping
    /// is cleared and swapped out.
    pub fn try_replace_from_fn(
        &mut self,
        len: usize,
        mut make_byte: impl FnMut(usize) -> u8,
    ) -> Result<(), SecretIntegrityError<GuardPageError>> {
        self.verify_integrity()?;
        let mut replacement = self
            .replacement_with_capacity(len)
            .map_err(SecretIntegrityError::Operation)?;
        replacement.fill_from_fn(len, &mut make_byte);

        self.clear_secret();
        core::mem::swap(self, &mut replacement);
        Ok(())
    }

    /// Replace all initialized secret bytes with fallibly generated bytes.
    ///
    /// The old guarded value remains unchanged if mapping setup or
    /// generation fails. Any partial generated bytes are cleared when the
    /// replacement mapping is dropped.
    pub fn try_replace_from_fallible_fn<E>(
        &mut self,
        len: usize,
        mut make_byte: impl FnMut(usize) -> Result<u8, E>,
    ) -> Result<(), SecretIntegrityError<GuardedSecretVecGenerateError<E>>> {
        self.verify_integrity()?;
        let mut replacement = self
            .replacement_with_capacity(len)
            .map_err(GuardedSecretVecGenerateError::Guard)
            .map_err(SecretIntegrityError::Operation)?;
        replacement
            .fill_from_try_fn(len, &mut make_byte)
            .map_err(GuardedSecretVecGenerateError::Generate)
            .map_err(SecretIntegrityError::Operation)?;

        self.clear_secret();
        core::mem::swap(self, &mut replacement);
        Ok(())
    }

    /// Clear the full writable data region and reset initialized length.
    #[inline(never)]
    pub fn clear_secret(&mut self) {
        crate::wipe_backend::erase(self.data.as_ptr(), self.writable_len);
        self.len = 0;
        self.write_canaries();
    }

    /// Consume this value after first clearing the full writable data
    /// region.
    ///
    /// Drop still runs after this method returns, so locked mappings are
    /// unlocked and the guarded mapping is unmapped normally.
    #[inline]
    pub fn into_cleared(mut self) {
        self.clear_secret();
    }

    /// Clear the full writable data region with volatile writes, flush the
    /// cache lines covering that region, and reset initialized length.
    #[cfg(feature = "cache-flush")]
    #[inline(never)]
    pub fn try_clear_secret_and_flush(
        &mut self,
    ) -> Result<crate::cache_flush::CacheFlushReport, crate::cache_flush::CacheFlushError> {
        self.clear_secret();
        crate::cache_flush::flush_cache_lines(self.as_capacity_slice())
    }

    /// Compare against a byte slice without early exit for equal-length
    /// inputs.
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

    /// Verify guarded mapping canaries.
    #[inline]
    pub fn verify_integrity(&self) -> Result<(), CanaryCorruptedError> {
        #[cfg(not(feature = "canary-check"))]
        {
            Ok(())
        }
        #[cfg(feature = "canary-check")]
        {
            if !self.poisoned.get() && self.canaries_intact() {
                Ok(())
            } else {
                self.clear_after_canary_failure();
                Err(CanaryCorruptedError)
            }
        }
    }

    fn grow_to(&mut self, required: usize) -> Result<(), SecretIntegrityError<GuardPageError>> {
        self.verify_integrity()?;
        let page_granule = platform_page_granule();
        let next_capacity = self
            .data_capacity
            .saturating_mul(2)
            .max(required)
            .max(page_granule);
        let mut replacement = self
            .replacement_with_capacity(next_capacity)
            .map_err(SecretIntegrityError::Operation)?;
        replacement.as_mut_capacity_slice()[..self.len].copy_from_slice(self.as_slice());
        replacement.finish_initialization(self.len);

        self.clear_secret();
        core::mem::swap(self, &mut replacement);
        Ok(())
    }

    fn replacement_with_capacity(&self, capacity: usize) -> Result<Self, GuardPageError> {
        let request = self.request;
        let replacement_request =
            replacement_request_preserving_established(request, &self.report, capacity);
        let mut replacement = Self::with_capacity_with_protection(capacity, replacement_request)
            .map_err(protection_error_as_guard_page)?;
        replacement.request = request;
        Ok(replacement)
    }

    /// Run a closure with shared access, panicking on canary corruption.
    #[inline]
    pub fn with_secret_or_panic<R>(&self, inspect: impl FnOnce(&[u8]) -> R) -> R {
        self.try_with_secret(inspect)
            .unwrap_or_else(|_| panic!("guarded secret canary corrupted"))
    }

    /// Run a closure with mutable access, panicking on canary corruption.
    #[inline]
    pub fn with_secret_mut_or_panic<R>(&mut self, edit: impl FnOnce(&mut [u8]) -> R) -> R {
        self.try_with_secret_mut(edit)
            .unwrap_or_else(|_| panic!("guarded secret canary corrupted"))
    }

    /// Compare, panicking on canary corruption.
    #[must_use]
    #[inline]
    pub fn constant_time_eq_or_panic(&self, other: &[u8]) -> bool {
        self.try_constant_time_eq(other)
            .unwrap_or_else(|_| panic!("guarded secret canary corrupted"))
    }

    fn fill_from_fn(&mut self, len: usize, make_byte: &mut impl FnMut(usize) -> u8) {
        assert!(
            len <= self.data_capacity,
            "guarded secret length exceeds capacity"
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

    /// Fill a fresh or throwaway guarded mapping.
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
            "guarded secret length exceeds capacity"
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
            "guarded secret length exceeds capacity"
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
        // capacity inside the writable region between guard pages.
        unsafe { core::slice::from_raw_parts_mut(self.payload_ptr(), self.data_capacity) }
    }

    #[cfg(feature = "cache-flush")]
    #[inline]
    fn as_capacity_slice(&self) -> &[u8] {
        // SAFETY: `data` points to the live writable data region between
        // guard pages for the duration of `&self`.
        unsafe { core::slice::from_raw_parts(self.data.as_ptr(), self.writable_len) }
    }

    #[inline]
    fn payload_ptr(&self) -> *mut u8 {
        // SAFETY: canary-checked guarded mappings reserve an 8-byte prefix.
        unsafe { self.data.as_ptr().add(Self::payload_offset()) }
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
        ((self.data.as_ptr() as u64) ^ CANARY_MASK).to_ne_bytes()
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
        // SAFETY: canary-checked guarded mappings reserve prefix and suffix
        // canary regions inside the writable data area.
        let prefix = unsafe { core::slice::from_raw_parts(self.data.as_ptr(), CANARY_SIZE) };
        // SAFETY: `len <= data_capacity`, so suffix at prefix + len stays
        // inside the writable data area.
        let suffix = unsafe {
            core::slice::from_raw_parts(self.data.as_ptr().add(CANARY_SIZE + self.len), CANARY_SIZE)
        };

        self.with_canary(|expected| {
            crate::constant_time_eq_slices(prefix, expected)
                & crate::constant_time_eq_slices(suffix, expected)
        })
    }

    #[cfg(feature = "canary-check")]
    #[inline]
    fn write_canaries(&mut self) {
        self.with_canary(|canary| {
            // SAFETY: canary-checked guarded mappings reserve prefix and suffix
            // canary regions inside the writable data area.
            unsafe {
                core::ptr::copy_nonoverlapping(canary.as_ptr(), self.data.as_ptr(), CANARY_SIZE);
                core::ptr::copy_nonoverlapping(
                    canary.as_ptr(),
                    self.data.as_ptr().add(CANARY_SIZE + self.len),
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
        // Fail-closed clearing intentionally mutates the owned guarded
        // mapping through `&self`. `GuardedSecretVec` is `Send` but not
        // `Sync`, so safe code cannot run this concurrently through shared
        // references.
        crate::wipe_backend::erase(self.data.as_ptr(), self.writable_len);
    }

    #[cfg(feature = "random-canary")]
    #[inline]
    fn clear_canary_material(&mut self) {
        self.canary.clear();
    }

    #[cfg(feature = "page-seal")]
    #[inline]
    fn mark_memory_unlocked(&mut self) {
        self.locked = false;
        self.report.memory_lock = ProtectionState::NotApplicable;
        self.report.locked_bytes = 0;
    }

    #[cfg(feature = "page-seal")]
    #[inline]
    fn mark_mapping_released(&mut self) {
        self.mark_memory_unlocked();
        self.report.mapping = ProtectionState::NotApplicable;
        self.report.dump_exclusion = ProtectionState::NotApplicable;
        self.report.fork.state = ProtectionState::NotApplicable;
        self.report.guard_pages = ProtectionState::NotApplicable;
        self.report.canary = ProtectionState::NotApplicable;
        self.report.cache_policy = ProtectionState::NotApplicable;
        self.report.mapped_bytes = 0;
    }

    #[cfg(all(test, feature = "canary-check", feature = "std"))]
    #[allow(dead_code)]
    #[inline]
    pub(crate) fn corrupt_suffix_canary_for_test(&mut self) {
        // SAFETY: canary-checked guarded mappings reserve a suffix canary
        // immediately after the initialized payload.
        unsafe {
            let byte = self.data.as_ptr().add(CANARY_SIZE + self.len);
            core::ptr::write(byte, core::ptr::read(byte) ^ 0xFF);
        }
    }
}

impl Drop for GuardedSecretVec {
    #[inline]
    fn drop(&mut self) {
        self.clear_secret();
        #[cfg(feature = "random-canary")]
        self.clear_canary_material();
        // clear_secret resets live-owner canaries. Erase those too before release.
        crate::wipe_backend::erase(self.data.as_ptr(), self.writable_len);
        #[cfg(feature = "memory-lock")]
        if self.locked {
            let _ = unlock_mapping(self.data, self.writable_len);
        }
        let _ = unmap_guarded(self.base, self.map_len);
    }
}

#[cfg(feature = "cache-flush")]
impl crate::cache_flush::CacheFlushSanitize for GuardedSecretVec {
    #[inline(never)]
    fn cache_flush_sanitize(
        &mut self,
    ) -> Result<crate::cache_flush::CacheFlushReport, crate::cache_flush::CacheFlushError> {
        self.try_clear_secret_and_flush()
    }
}

impl crate::SecureSanitize for GuardedSecretVec {
    #[inline]
    fn secure_sanitize(&mut self) {
        self.clear_secret();
    }
}

impl fmt::Debug for GuardedSecretVec {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GuardedSecretVec")
            .field("len", &self.len)
            .field("capacity", &self.data_capacity)
            .field("writable_len", &self.writable_len)
            .field("memory_locked", &self.locked)
            .field("contents", &"<redacted>")
            .finish()
    }
}

/// Error returned by scoped page-sealed secret access.
#[cfg(feature = "page-seal")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SealedSecretAccessError {
    /// A platform page-protection transition failed.
    Guard(GuardPageError),
    /// Integrity canaries were corrupted while the page was inaccessible.
    Canary(CanaryCorruptedError),
    /// Access was attempted while another access window was active.
    AccessInProgress,
    /// A prior protection-transition failure retired and released the mapping.
    Retired,
    /// A protection transition failed and the mapping could not be released.
    ///
    /// The mapping's page protections are uncertain. No later operation will
    /// dereference it. Cleanup retries mapping release and retains an
    /// established memory lock until the payload is confirmed erased.
    Poisoned,
}

#[cfg(feature = "page-seal")]
impl fmt::Display for SealedSecretAccessError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Guard(error) => error.fmt(formatter),
            Self::Canary(error) => error.fmt(formatter),
            Self::AccessInProgress => {
                formatter.write_str("page-sealed secret access is already in progress")
            }
            Self::Retired => formatter.write_str("page-sealed secret mapping is retired"),
            Self::Poisoned => formatter.write_str("page-sealed secret mapping is poisoned"),
        }
    }
}

#[cfg(all(feature = "page-seal", feature = "std"))]
impl std::error::Error for SealedSecretAccessError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Guard(error) => Some(error),
            Self::Canary(error) => Some(error),
            Self::AccessInProgress | Self::Retired | Self::Poisoned => None,
        }
    }
}

#[cfg(feature = "page-seal")]
impl From<GuardPageError> for SealedSecretAccessError {
    #[inline]
    fn from(error: GuardPageError) -> Self {
        Self::Guard(error)
    }
}

#[cfg(feature = "page-seal")]
impl From<CanaryCorruptedError> for SealedSecretAccessError {
    #[inline]
    fn from(error: CanaryCorruptedError) -> Self {
        Self::Canary(error)
    }
}

#[cfg(feature = "page-seal")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SealedState {
    Sealed,
    Exposed,
    Poisoned,
    Retired,
}

/// Fixed-size secret bytes kept on an inaccessible page between accesses.
///
/// Every access requires `&mut self`, temporarily changes the data page to
/// read/write, verifies integrity, invokes the closure, and restores no-access
/// protection before returning. An unwind guard performs the same reseal
/// attempt if the closure panics.
///
/// This opt-in type is deliberately not `Sync`. Signal handlers, process
/// abort, privileged remapping, DMA, and copies made by the closure remain
/// outside the guarantee.
///
/// Default construction requires Linux wipe-on-fork. Windows process creation
/// does not clone the current address space. Other fork-capable targets must
/// use an explicit [`ProtectionRequest`] after reviewing the inheritance risk.
///
/// ```compile_fail
/// use sanitization::SealedSecretBytes;
///
/// fn assert_sync<T: Sync>() {}
/// assert_sync::<SealedSecretBytes<32>>();
/// ```
#[cfg(feature = "page-seal")]
pub struct SealedSecretBytes<const N: usize> {
    inner: ManuallyDrop<GuardedSecretVec>,
    state: SealedState,
    #[cfg(test)]
    fail_next_seal: bool,
    #[cfg(test)]
    fail_next_unseal: bool,
    #[cfg(test)]
    fail_normalization_page: Option<usize>,
    #[cfg(test)]
    fail_cleanup_reseal_page: Option<usize>,
    #[cfg(test)]
    cleanup_reseal_failed_page: Option<usize>,
    #[cfg(test)]
    fail_next_unmap: bool,
}

// SAFETY: The value exclusively owns its mapping. Moving ownership to another
// thread preserves the mapping and all access still requires `&mut self`.
// `Sync` is intentionally not implemented.
#[cfg(feature = "page-seal")]
unsafe impl<const N: usize> Send for SealedSecretBytes<N> {}

#[cfg(feature = "page-seal")]
impl<const N: usize> SealedSecretBytes<N> {
    /// Allocate a zero-filled page-sealed secret.
    pub fn zeroed() -> Result<Self, GuardPageError> {
        Self::zeroed_with_protection(ProtectionRequest::page_sealed())
            .map_err(protection_error_as_guard_page)
    }

    /// Allocate a zero-filled page-sealed secret under explicit protection
    /// policy.
    pub fn zeroed_with_protection(request: ProtectionRequest) -> Result<Self, ProtectionError> {
        let mut inner = GuardedSecretVec::with_capacity_with_protection(N, request)?;
        inner.finish_initialization(N);
        if let Err(error) = seal_data(inner.data, inner.writable_len) {
            let mut report = *inner.protection_report();
            report.guard_pages = ProtectionState::Failed { code: error.errno };
            let rollback = rollback_sealed_transition_failure(inner);
            return Err(ProtectionError {
                failure: ProtectionFailure {
                    control: ProtectionControl::GuardPages,
                    code: error.errno,
                },
                partial_report: report,
                rollback,
            });
        }

        Ok(Self {
            inner: ManuallyDrop::new(inner),
            state: SealedState::Sealed,
            #[cfg(test)]
            fail_next_seal: false,
            #[cfg(test)]
            fail_next_unseal: false,
            #[cfg(test)]
            fail_normalization_page: None,
            #[cfg(test)]
            fail_cleanup_reseal_page: None,
            #[cfg(test)]
            cleanup_reseal_failed_page: None,
            #[cfg(test)]
            fail_next_unmap: false,
        })
    }

    /// Allocate page-sealed storage and copy an owned array into it.
    pub fn from_array(mut bytes: [u8; N]) -> Result<Self, SealedSecretAccessError> {
        let result = Self::zeroed()
            .map_err(SealedSecretAccessError::Guard)
            .and_then(|mut secret| {
                secret.try_with_secret_mut(|target| target.copy_from_slice(&bytes))?;
                Ok(secret)
            });
        crate::wipe::bytes(&mut bytes);
        result
    }

    /// Number of secret bytes stored in the sealed mapping.
    #[must_use]
    #[inline]
    pub const fn len(&self) -> usize {
        N
    }

    /// Returns true when this fixed secret has zero length.
    #[must_use]
    #[inline]
    pub const fn is_empty(&self) -> bool {
        N == 0
    }

    /// Returns true when the data page is currently inaccessible.
    #[must_use]
    #[inline]
    pub const fn is_sealed(&self) -> bool {
        matches!(self.state, SealedState::Sealed)
    }

    /// Returns true after a failed reseal retired the mapping.
    #[must_use]
    #[inline]
    pub const fn is_retired(&self) -> bool {
        matches!(self.state, SealedState::Retired)
    }

    /// Returns true when a failed transition left uncertain page protections
    /// and releasing the mapping also failed.
    #[must_use]
    #[inline]
    pub const fn is_poisoned(&self) -> bool {
        matches!(self.state, SealedState::Poisoned)
    }

    /// Actual protections established for the underlying guarded mapping.
    #[must_use]
    #[inline]
    pub fn protection_report(&self) -> &ProtectionReport {
        self.inner.protection_report()
    }

    /// Runtime policy requested for the underlying guarded mapping.
    #[must_use]
    #[inline]
    pub fn protection_request(&self) -> ProtectionRequest {
        self.inner.protection_request()
    }

    /// Run a closure with scoped shared access to the secret bytes.
    pub fn try_with_secret<R>(
        &mut self,
        inspect: impl FnOnce(&[u8; N]) -> R,
    ) -> Result<R, SealedSecretAccessError> {
        self.begin_access()?;
        let guard = SealedAccessGuard::new(self);
        if let Err(error) = guard.secret.inner.verify_integrity() {
            guard.secret.reset_zeroed_payload();
            guard.finish()?;
            return Err(error.into());
        }

        // SAFETY: the page is read/write for this access window, the guarded
        // mapping owns at least N payload bytes, and the guard reseals before
        // this method returns or unwinds.
        let bytes = unsafe { &*(guard.secret.inner.payload_ptr() as *const [u8; N]) };
        let result = inspect(bytes);
        guard.finish()?;
        Ok(result)
    }

    /// Run a closure with scoped mutable access to the secret bytes.
    pub fn try_with_secret_mut<R>(
        &mut self,
        edit: impl FnOnce(&mut [u8; N]) -> R,
    ) -> Result<R, SealedSecretAccessError> {
        self.begin_access()?;
        let guard = SealedAccessGuard::new(self);
        if let Err(error) = guard.secret.inner.verify_integrity() {
            guard.secret.reset_zeroed_payload();
            guard.finish()?;
            return Err(error.into());
        }

        // SAFETY: `&mut self` provides exclusive access, the page is
        // read/write for this window, and the guard reseals on every exit.
        let bytes = unsafe { &mut *(guard.secret.inner.payload_ptr() as *mut [u8; N]) };
        let result = edit(bytes);
        compiler_fence(Ordering::SeqCst);
        guard.finish()?;
        Ok(result)
    }

    /// Compare with a fixed byte array while the page is temporarily exposed.
    pub fn try_constant_time_eq(
        &mut self,
        other: &[u8; N],
    ) -> Result<bool, SealedSecretAccessError> {
        self.try_with_secret(|bytes| crate::constant_time_eq_slices(bytes, other))
    }

    /// Run a closure with shared access, panicking on a sealed-access failure.
    #[inline]
    pub fn with_secret_or_panic<R>(&mut self, inspect: impl FnOnce(&[u8; N]) -> R) -> R {
        self.try_with_secret(inspect)
            .unwrap_or_else(|_| panic!("sealed secret access failed"))
    }

    /// Run a closure with mutable access, panicking on a sealed-access failure.
    #[inline]
    pub fn with_secret_mut_or_panic<R>(&mut self, edit: impl FnOnce(&mut [u8; N]) -> R) -> R {
        self.try_with_secret_mut(edit)
            .unwrap_or_else(|_| panic!("sealed secret mutation failed"))
    }

    /// Compare, panicking on a sealed-access failure.
    #[must_use]
    #[inline]
    pub fn constant_time_eq_or_panic(&mut self, other: &[u8; N]) -> bool {
        self.try_constant_time_eq(other)
            .unwrap_or_else(|_| panic!("sealed secret comparison failed"))
    }

    /// Clear the payload and restore no-access protection.
    pub fn try_clear_secret(&mut self) -> Result<(), SealedSecretAccessError> {
        self.begin_access()?;
        let guard = SealedAccessGuard::new(self);
        guard.secret.reset_zeroed_payload();
        guard.finish()
    }

    /// Clear the payload, panicking if the mapping cannot be accessed or resealed.
    #[inline]
    pub fn clear_secret_or_panic(&mut self) {
        self.try_clear_secret()
            .unwrap_or_else(|_| panic!("sealed secret clear failed"));
    }

    /// Attempt to sanitize the payload and restore no-access protection.
    ///
    /// This operation is fallible because an operating-system protection
    /// failure can prevent the sealed page from becoming writable. The type
    /// therefore does not implement the infallible [`crate::SecureSanitize`]
    /// contract.
    #[inline]
    pub fn try_secure_sanitize(&mut self) -> Result<(), SealedSecretAccessError> {
        self.try_clear_secret()
    }

    /// Clear and release the page-sealed mapping with observable cleanup
    /// results.
    ///
    /// The value rejects all later secret access as soon as cleanup begins.
    /// When mapping release fails, the value remains poisoned and this method
    /// may be retried. Successful mapping release retires the value even if an
    /// earlier normalization or unlock operation reported failure, because no
    /// live mapping remains to retry. [`Drop`] invokes the same cleanup path as
    /// a final best-effort fallback.
    ///
    /// Returned diagnostics contain only operation names and platform error
    /// codes. Applications must not add secret bytes, mapping addresses, or
    /// canary values to cleanup telemetry.
    pub fn try_close(&mut self) -> Result<(), CleanupError> {
        if self.state == SealedState::Retired {
            return Ok(());
        }

        let report = self.cleanup_mapping();
        if report.completed() {
            Ok(())
        } else {
            match CleanupError::from_report(report) {
                Some(error) => Err(error),
                None => Ok(()),
            }
        }
    }

    fn begin_access(&mut self) -> Result<(), SealedSecretAccessError> {
        match self.state {
            SealedState::Sealed => {}
            SealedState::Exposed => return Err(SealedSecretAccessError::AccessInProgress),
            SealedState::Poisoned => return Err(SealedSecretAccessError::Poisoned),
            SealedState::Retired => return Err(SealedSecretAccessError::Retired),
        }

        #[cfg(test)]
        if core::mem::take(&mut self.fail_next_unseal) {
            let error = match simulate_partial_transition(
                self.inner.data,
                self.inner.writable_len,
                PageProtection::ReadWrite,
            ) {
                Ok(()) => GuardPageError {
                    operation: GuardPageOperation::Protect,
                    errno: 0,
                },
                Err(error) => error,
            };
            self.retire_after_transition_failure();
            return Err(error.into());
        }

        if let Err(error) = protect_data(self.inner.data, self.inner.writable_len) {
            self.retire_after_transition_failure();
            return Err(error.into());
        }
        self.state = SealedState::Exposed;
        Ok(())
    }

    fn finish_access(&mut self) -> Result<(), SealedSecretAccessError> {
        if self.state != SealedState::Exposed {
            return match self.state {
                SealedState::Sealed | SealedState::Exposed => {
                    Err(SealedSecretAccessError::AccessInProgress)
                }
                SealedState::Poisoned => Err(SealedSecretAccessError::Poisoned),
                SealedState::Retired => Err(SealedSecretAccessError::Retired),
            };
        }

        let integrity_result = self.inner.verify_integrity().map_err(Into::into);

        #[cfg(test)]
        let seal_result = if core::mem::take(&mut self.fail_next_seal) {
            match simulate_partial_transition(
                self.inner.data,
                self.inner.writable_len,
                PageProtection::NoAccess,
            ) {
                Ok(()) => Err(GuardPageError {
                    operation: GuardPageOperation::Protect,
                    errno: 0,
                }),
                Err(error) => Err(error),
            }
        } else {
            seal_data(self.inner.data, self.inner.writable_len)
        };
        #[cfg(not(test))]
        let seal_result = seal_data(self.inner.data, self.inner.writable_len);

        match seal_result {
            Ok(()) => {
                self.state = SealedState::Sealed;
                integrity_result
            }
            Err(error) => {
                self.retire_after_transition_failure();
                Err(error.into())
            }
        }
    }

    fn reset_zeroed_payload(&mut self) {
        crate::wipe_backend::erase(self.inner.data.as_ptr(), self.inner.writable_len);
        self.inner.len = N;
        self.inner.write_canaries();
    }

    fn retire_after_transition_failure(&mut self) {
        let _ = self.cleanup_mapping();
    }

    fn cleanup_mapping(&mut self) -> CleanupReport {
        if self.state == SealedState::Retired {
            return CleanupReport {
                normalization: CleanupState::NotNeeded,
                unlock: CleanupState::NotNeeded,
                unmap: CleanupState::NotNeeded,
            };
        }

        self.state = SealedState::Poisoned;
        #[cfg(test)]
        let normalization = {
            let failed_write_page = self.fail_normalization_page.take();
            let failed_reseal_page = self.fail_cleanup_reseal_page.take();
            self.cleanup_reseal_failed_page = None;
            let (result, observed_reseal_failure) = match (failed_write_page, failed_reseal_page) {
                (None, None) => (
                    erase_and_reseal_data_pages(self.inner.data, self.inner.writable_len),
                    None,
                ),
                (failed_write_page, failed_reseal_page) => {
                    erase_and_reseal_data_pages_with_failures(
                        self.inner.data,
                        self.inner.writable_len,
                        failed_write_page,
                        failed_reseal_page,
                    )
                }
            };
            if result.is_err() {
                self.cleanup_reseal_failed_page = observed_reseal_failure;
            }
            result
        };
        #[cfg(not(test))]
        let normalization = erase_and_reseal_data_pages(self.inner.data, self.inner.writable_len);

        let normalization = match normalization {
            Ok(()) => CleanupState::Completed,
            Err(error) => {
                // The page protections are uncertain, so neither dereference
                // nor release the mapping. Preserve any established lock and
                // leave the poisoned value available for checked cleanup retry.
                return CleanupReport {
                    normalization: CleanupState::Failed(error),
                    unlock: CleanupState::NotNeeded,
                    unmap: CleanupState::NotNeeded,
                };
            }
        };

        #[cfg(feature = "random-canary")]
        self.inner.clear_canary_material();

        #[cfg(test)]
        let unmap = if core::mem::take(&mut self.fail_next_unmap) {
            Err(GuardPageError {
                operation: GuardPageOperation::Unmap,
                errno: 0,
            })
        } else {
            unmap_guarded(self.inner.base, self.inner.map_len)
        };
        #[cfg(not(test))]
        let unmap = unmap_guarded(self.inner.base, self.inner.map_len);

        // Releasing a mapping also disposes of its page lock. At this point the
        // payload is erased, so a failed release may be followed by unlock.
        #[cfg(feature = "memory-lock")]
        let unlock = if unmap.is_ok() || !self.inner.locked {
            CleanupState::NotNeeded
        } else {
            match unlock_mapping(self.inner.data, self.inner.writable_len) {
                Ok(()) => {
                    self.inner.mark_memory_unlocked();
                    CleanupState::Completed
                }
                Err(error) => CleanupState::Failed(error),
            }
        };
        #[cfg(not(feature = "memory-lock"))]
        let unlock = CleanupState::NotNeeded;

        if unmap.is_ok() {
            self.state = SealedState::Retired;
            self.inner.mark_mapping_released();
        }

        CleanupReport {
            normalization,
            unlock,
            unmap: match unmap {
                Ok(()) => CleanupState::Completed,
                Err(error) => CleanupState::Failed(error),
            },
        }
    }

    #[cfg(all(
        test,
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64"),
        not(miri)
    ))]
    pub(crate) fn fail_next_seal_for_test(&mut self) {
        self.fail_next_seal = true;
    }

    #[cfg(all(
        test,
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64"),
        not(miri)
    ))]
    pub(crate) fn fail_next_unseal_for_test(&mut self) {
        self.fail_next_unseal = true;
    }

    #[cfg(all(
        test,
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64"),
        not(miri)
    ))]
    pub(crate) fn fail_normalization_page_for_test(&mut self, page_index: usize) {
        self.fail_normalization_page = Some(page_index);
    }

    #[cfg(all(
        test,
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64"),
        not(miri)
    ))]
    pub(crate) fn fail_cleanup_reseal_page_for_test(&mut self, page_index: usize) {
        self.fail_cleanup_reseal_page = Some(page_index);
    }

    #[cfg(all(
        test,
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64"),
        not(miri)
    ))]
    pub(crate) fn fail_next_unmap_for_test(&mut self) {
        self.fail_next_unmap = true;
    }

    #[cfg(all(
        test,
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64"),
        not(miri)
    ))]
    pub(crate) fn erased_page_is_zero_for_test(
        &mut self,
        page_index: usize,
    ) -> Result<bool, GuardPageError> {
        let page_granule = platform_page_granule();
        let offset = page_index
            .checked_mul(page_granule)
            .filter(|offset| *offset < self.inner.writable_len)
            .ok_or(GuardPageError {
                operation: GuardPageOperation::Length,
                errno: 0,
            })?;
        // SAFETY: the checked page offset is inside the live, page-rounded
        // writable region owned by this test value.
        let page = unsafe { NonNull::new_unchecked(self.inner.data.as_ptr().add(offset)) };
        protect_data(page, page_granule)?;
        // SAFETY: the page was made readable and spans exactly one live page.
        let erased = unsafe { core::slice::from_raw_parts(page.as_ptr(), page_granule) }
            .iter()
            .all(|byte| *byte == 0);
        seal_data(page, page_granule)?;
        if self.cleanup_reseal_failed_page == Some(page_index) {
            self.cleanup_reseal_failed_page = None;
        }
        Ok(erased)
    }

    #[cfg(all(
        test,
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64"),
        not(miri)
    ))]
    /// Observes a page left readable by an injected cleanup-reseal failure.
    ///
    /// # Safety
    ///
    /// The recorded page must not have been resealed outside the helpers that
    /// maintain `cleanup_reseal_failed_page` since the injected failure.
    pub(crate) unsafe fn writable_failed_reseal_page_is_zero_for_test(
        &self,
        page_index: usize,
    ) -> Result<bool, GuardPageError> {
        if self.state != SealedState::Poisoned
            || self.cleanup_reseal_failed_page != Some(page_index)
        {
            return Err(GuardPageError {
                operation: GuardPageOperation::Protect,
                errno: 0,
            });
        }

        let page_granule = platform_page_granule();
        let offset = page_index
            .checked_mul(page_granule)
            .filter(|offset| *offset < self.inner.writable_len)
            .ok_or(GuardPageError {
                operation: GuardPageOperation::Length,
                errno: 0,
            })?;
        // SAFETY: the test-only cleanup injection leaves exactly the recorded
        // page readable after erasing it. Poisoned state prevents safe mapped
        // exposure, and this helper neither changes protection nor returns a
        // reference to the page.
        let page = unsafe { self.inner.data.as_ptr().add(offset) };
        // SAFETY: the recorded injected page is live, readable, and spans one
        // complete page granule inside the mapping.
        Ok(unsafe { core::slice::from_raw_parts(page, page_granule) }
            .iter()
            .all(|byte| *byte == 0))
    }

    #[cfg(all(
        test,
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64"),
        not(miri)
    ))]
    pub(crate) fn mark_access_in_progress_for_test(&mut self) -> Result<(), GuardPageError> {
        protect_data(self.inner.data, self.inner.writable_len)?;
        self.state = SealedState::Exposed;
        Ok(())
    }

    #[cfg(all(
        test,
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64"),
        not(miri)
    ))]
    pub(crate) fn child_observes_zero_during_exposed_fork_for_test(
        &mut self,
    ) -> Result<bool, SealedSecretAccessError> {
        self.begin_access()?;
        let guard = SealedAccessGuard::new(self);

        // SAFETY: the child performs only direct reads followed by `_exit`.
        // `MADV_WIPEONFORK` applies before the child resumes after `fork`.
        let pid = unsafe { fork() };
        if pid == 0 {
            // SAFETY: the parent successfully opened the data page before
            // forking. The child inherits the mapping with zeroed contents.
            let bytes = unsafe {
                core::slice::from_raw_parts(guard.secret.inner.payload_ptr() as *const u8, N)
            };
            let all_zero = bytes.iter().all(|byte| *byte == 0);
            // SAFETY: `_exit` terminates the post-fork child without running
            // Rust destructors or allocator code.
            unsafe { _exit(if all_zero { 0 } else { 1 }) };
        }

        let mut status = -1;
        // SAFETY: a positive `pid` identifies the child created above and
        // `status` points to writable parent memory.
        let waited = if pid > 0 {
            unsafe { waitpid(pid, &mut status, 0) }
        } else {
            -1
        };
        guard.finish()?;
        Ok(waited == pid && status == 0)
    }

    #[cfg(all(
        test,
        feature = "canary-check",
        feature = "std",
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64"),
        not(miri)
    ))]
    pub(crate) fn corrupt_canary_for_test(&mut self) -> Result<(), SealedSecretAccessError> {
        self.begin_access()?;
        let guard = SealedAccessGuard::new(self);
        guard.secret.inner.corrupt_suffix_canary_for_test();
        guard.finish()
    }
}

#[cfg(feature = "page-seal")]
struct SealedAccessGuard<'a, const N: usize> {
    secret: &'a mut SealedSecretBytes<N>,
    active: bool,
}

#[cfg(feature = "page-seal")]
impl<'a, const N: usize> SealedAccessGuard<'a, N> {
    fn new(secret: &'a mut SealedSecretBytes<N>) -> Self {
        Self {
            secret,
            active: true,
        }
    }

    fn finish(mut self) -> Result<(), SealedSecretAccessError> {
        let result = self.secret.finish_access();
        self.active = false;
        result
    }
}

#[cfg(feature = "page-seal")]
impl<const N: usize> Drop for SealedAccessGuard<'_, N> {
    fn drop(&mut self) {
        if self.active {
            let _ = self.secret.finish_access();
        }
    }
}

#[cfg(feature = "page-seal")]
impl<const N: usize> Drop for SealedSecretBytes<N> {
    fn drop(&mut self) {
        let _ = self.cleanup_mapping();
    }
}

#[cfg(feature = "page-seal")]
impl<const N: usize> fmt::Debug for SealedSecretBytes<N> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SealedSecretBytes")
            .field("len", &N)
            .field("sealed", &self.is_sealed())
            .field("poisoned", &self.is_poisoned())
            .field("retired", &self.is_retired())
            .field("contents", &"<redacted>")
            .finish()
    }
}

#[cfg(feature = "page-seal")]
fn rollback_sealed_transition_failure(mut inner: GuardedSecretVec) -> RollbackReport {
    if normalize_data_pages(inner.data, inner.writable_len, PageProtection::ReadWrite).is_ok() {
        inner.clear_secret();
    }
    #[cfg(feature = "random-canary")]
    inner.clear_canary_material();
    let inner = ManuallyDrop::new(inner);

    #[cfg(feature = "memory-lock")]
    let unlock = if inner.locked {
        match unlock_mapping(inner.data, inner.writable_len) {
            Ok(()) => RollbackState::Completed,
            Err(error) => RollbackState::Failed(ProtectionFailure {
                control: ProtectionControl::MemoryLock,
                code: error.errno,
            }),
        }
    } else {
        RollbackState::NotNeeded
    };
    #[cfg(not(feature = "memory-lock"))]
    let unlock = RollbackState::NotNeeded;

    let unmap = match unmap_guarded(inner.base, inner.map_len) {
        Ok(()) => RollbackState::Completed,
        Err(error) => RollbackState::Failed(ProtectionFailure {
            control: ProtectionControl::Mapping,
            code: error.errno,
        }),
    };

    RollbackReport { unlock, unmap }
}

fn resolve_guard_unavailable(
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

fn resolve_guard_canary(
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
        resolve_guard_unavailable(requirement, ProtectionControl::Canary, report)
    }
}

fn guard_pre_mapping_error(
    request: ProtectionRequest,
    requested_bytes: usize,
    control: ProtectionControl,
    code: i32,
) -> ProtectionError {
    let mut report = ProtectionReport::pending(request, requested_bytes, platform_page_granule());
    set_guard_failed_state(&mut report, control, code);
    ProtectionError {
        failure: ProtectionFailure { control, code },
        partial_report: report,
        rollback: RollbackReport::not_needed(),
    }
}

#[allow(clippy::too_many_arguments)]
fn apply_guard_fork_policy(
    request: ForkProtectionRequest,
    report: &mut ProtectionReport,
    base: NonNull<u8>,
    total_len: usize,
    data: NonNull<u8>,
    writable_len: usize,
) -> Result<ProtectionState, ProtectionError> {
    match request.policy {
        ForkPolicy::Inherit => Ok(ProtectionState::Established),
        ForkPolicy::Exclude => apply_guard_control(
            request.requirement,
            fork_exclusion_supported(),
            ProtectionControl::ForkPolicy,
            report,
            base,
            total_len,
            data,
            writable_len,
            guard_mark_dontfork,
        ),
        ForkPolicy::WipeChild => apply_guard_control(
            request.requirement,
            wipe_child_supported(),
            ProtectionControl::ForkPolicy,
            report,
            base,
            total_len,
            data,
            writable_len,
            guard_mark_wipeonfork,
        ),
    }
}

#[allow(clippy::too_many_arguments)]
fn apply_guard_control(
    requirement: Requirement,
    supported: bool,
    control: ProtectionControl,
    report: &mut ProtectionReport,
    base: NonNull<u8>,
    total_len: usize,
    data: NonNull<u8>,
    writable_len: usize,
    apply: fn(NonNull<u8>, usize) -> Result<(), GuardPageError>,
) -> Result<ProtectionState, ProtectionError> {
    if requirement == Requirement::NotRequested {
        return Ok(ProtectionState::NotRequested);
    }
    if !supported {
        if requirement == Requirement::Preferred {
            return Ok(ProtectionState::Unsupported);
        }
        set_guard_failed_state(report, control, 0);
        return Err(guard_required_error(base, total_len, control, 0, *report));
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
            Err(GuardPageError {
                operation: GuardPageOperation::DontFork,
                errno: 0,
            })
        } else {
            apply(ptr, len)
        }
    };
    match apply(data, writable_len) {
        Ok(()) => Ok(ProtectionState::Established),
        Err(error) => {
            if control == ProtectionControl::MemoryLock {
                report.lock_quota_likely = lock_quota_likely(error.errno);
            }
            if requirement == Requirement::Preferred {
                return Ok(ProtectionState::Failed { code: error.errno });
            }
            set_guard_failed_state(report, control, error.errno);
            Err(guard_required_error(
                base,
                total_len,
                control,
                error.errno,
                *report,
            ))
        }
    }
}

fn guard_required_error(
    base: NonNull<u8>,
    total_len: usize,
    control: ProtectionControl,
    code: i32,
    report: ProtectionReport,
) -> ProtectionError {
    ProtectionError {
        failure: ProtectionFailure { control, code },
        partial_report: report,
        rollback: rollback_guarded_mapping(base, total_len),
    }
}

fn rollback_guarded_mapping(base: NonNull<u8>, total_len: usize) -> RollbackReport {
    // Locking is deliberately the final setup operation, so no later setup
    // step can fail after a successful lock.
    let unlock = RollbackState::NotNeeded;
    let unmap = match unmap_guarded(base, total_len) {
        Ok(()) => RollbackState::Completed,
        Err(error) => RollbackState::Failed(ProtectionFailure {
            control: ProtectionControl::Mapping,
            code: error.errno,
        }),
    };
    RollbackReport { unlock, unmap }
}

fn set_guard_failed_state(report: &mut ProtectionReport, control: ProtectionControl, code: i32) {
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

fn protection_error_as_guard_page(error: ProtectionError) -> GuardPageError {
    if let RollbackState::Failed(failure) = error.rollback.unmap {
        return GuardPageError {
            operation: GuardPageOperation::Unmap,
            errno: failure.code,
        };
    }
    if let RollbackState::Failed(failure) = error.rollback.unlock {
        return GuardPageError {
            operation: GuardPageOperation::Unlock,
            errno: failure.code,
        };
    }

    GuardPageError {
        operation: match error.failure.control {
            ProtectionControl::Mapping => GuardPageOperation::Map,
            ProtectionControl::MemoryLock => GuardPageOperation::Lock,
            ProtectionControl::DumpExclusion => GuardPageOperation::DontDump,
            ProtectionControl::ForkPolicy => match error.partial_report.fork.policy {
                ForkPolicy::WipeChild => GuardPageOperation::WipeOnFork,
                ForkPolicy::Inherit | ForkPolicy::Exclude => GuardPageOperation::DontFork,
            },
            ProtectionControl::GuardPages => GuardPageOperation::Protect,
            ProtectionControl::Canary => GuardPageOperation::Random,
            ProtectionControl::CachePolicy => GuardPageOperation::Protect,
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
    cfg!(all(
        feature = "memory-lock",
        any(target_os = "linux", target_os = "freebsd")
    ))
}

#[inline]
const fn fork_exclusion_supported() -> bool {
    cfg!(any(target_os = "linux", target_os = "macos"))
}

#[inline]
const fn wipe_child_supported() -> bool {
    cfg!(target_os = "linux")
}

#[cfg(feature = "memory-lock")]
fn guard_lock_mapping(ptr: NonNull<u8>, len: usize) -> Result<(), GuardPageError> {
    lock_mapping(ptr, len)
}

#[cfg(not(feature = "memory-lock"))]
fn guard_lock_mapping(_ptr: NonNull<u8>, _len: usize) -> Result<(), GuardPageError> {
    Err(GuardPageError {
        operation: GuardPageOperation::Lock,
        errno: 0,
    })
}

#[cfg(feature = "memory-lock")]
fn guard_mark_dontdump(ptr: NonNull<u8>, len: usize) -> Result<(), GuardPageError> {
    mark_dontdump(ptr, len)
}

#[cfg(not(feature = "memory-lock"))]
fn guard_mark_dontdump(_ptr: NonNull<u8>, _len: usize) -> Result<(), GuardPageError> {
    Err(GuardPageError {
        operation: GuardPageOperation::DontDump,
        errno: 0,
    })
}

fn guard_mark_dontfork(ptr: NonNull<u8>, len: usize) -> Result<(), GuardPageError> {
    mark_dontfork(ptr, len)
}

fn guard_mark_wipeonfork(ptr: NonNull<u8>, len: usize) -> Result<(), GuardPageError> {
    mark_wipeonfork(ptr, len)
}

#[cfg(feature = "random-canary")]
fn random_canary_value() -> Result<crate::canary::CanaryMaterial, GuardPageError> {
    #[cfg(all(
        test,
        feature = "std",
        feature = "profile-guarded-native",
        any(target_os = "macos", target_os = "linux"),
        not(miri)
    ))]
    if super::native_tests::fail(ProtectionControl::Canary) {
        return Err(GuardPageError {
            operation: GuardPageOperation::Random,
            errno: 0,
        });
    }
    crate::canary::CanaryMaterial::random().map_err(|errno| GuardPageError {
        operation: GuardPageOperation::Random,
        errno,
    })
}

fn rounded_data_len(len: usize) -> Result<usize, GuardPageError> {
    let page_granule = platform_page_granule();
    len.max(1)
        .checked_add(page_granule - 1)
        .map(|value| value & !(page_granule - 1))
        .ok_or(GuardPageError {
            operation: GuardPageOperation::Length,
            errno: 0,
        })
}

#[cfg(feature = "canary-check")]
fn guarded_payload_capacity(requested: usize) -> Result<usize, GuardPageError> {
    let requested_with_canaries =
        requested
            .checked_add(guarded_extra_len())
            .ok_or(GuardPageError {
                operation: GuardPageOperation::Length,
                errno: 0,
            })?;
    rounded_data_len(requested_with_canaries).map(|writable_len| {
        writable_len
            .saturating_sub(guarded_extra_len())
            .max(requested)
    })
}

#[cfg(not(feature = "canary-check"))]
fn guarded_payload_capacity(requested: usize) -> Result<usize, GuardPageError> {
    rounded_data_len(requested)
}

#[cfg(feature = "canary-check")]
fn guarded_writable_len(payload_capacity: usize) -> Result<usize, GuardPageError> {
    payload_capacity
        .checked_add(guarded_extra_len())
        .ok_or(GuardPageError {
            operation: GuardPageOperation::Length,
            errno: 0,
        })
}

#[cfg(not(feature = "canary-check"))]
fn guarded_writable_len(payload_capacity: usize) -> Result<usize, GuardPageError> {
    Ok(payload_capacity)
}

#[cfg(feature = "canary-check")]
#[inline]
const fn guarded_extra_len() -> usize {
    CANARY_SIZE * 2
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
fn syscall_error(operation: GuardPageOperation, ret: isize) -> GuardPageError {
    GuardPageError {
        operation,
        errno: (-ret) as i32,
    }
}

#[cfg(target_os = "windows")]
fn windows_error(operation: GuardPageOperation) -> GuardPageError {
    // SAFETY: `GetLastError` takes no arguments and returns the calling
    // thread's last-error code.
    let errno = unsafe { GetLastError() } as i32;
    GuardPageError { operation, errno }
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
fn unix_error(operation: GuardPageOperation) -> GuardPageError {
    GuardPageError {
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
fn map_guarded(len: usize) -> Result<NonNull<u8>, GuardPageError> {
    let ret = raw_syscall6(
        SYS_MMAP,
        0,
        len,
        PROT_NONE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        MAP_FD_ANONYMOUS,
        0,
    );

    if syscall_failed(ret) {
        return Err(syscall_error(GuardPageOperation::Map, ret));
    }

    NonNull::new(ret as *mut u8).ok_or(GuardPageError {
        operation: GuardPageOperation::Map,
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
fn map_guarded(len: usize) -> Result<NonNull<u8>, GuardPageError> {
    // SAFETY: Arguments request a new private anonymous no-access mapping.
    let ptr = unsafe {
        mmap(
            core::ptr::null_mut(),
            len,
            PROT_NONE as i32,
            (MAP_PRIVATE | MAP_ANONYMOUS) as i32,
            -1,
            0,
        )
    };

    if ptr as isize == -1 {
        return Err(unix_error(GuardPageOperation::Map));
    }

    NonNull::new(ptr.cast::<u8>()).ok_or(GuardPageError {
        operation: GuardPageOperation::Map,
        errno: 0,
    })
}

#[cfg(target_os = "windows")]
fn map_guarded(len: usize) -> Result<NonNull<u8>, GuardPageError> {
    // SAFETY: Arguments request a new private committed/reserved no-access
    // region owned by this process.
    let ptr = unsafe {
        VirtualAlloc(
            core::ptr::null_mut(),
            len,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_NOACCESS,
        )
    };

    NonNull::new(ptr.cast::<u8>()).ok_or_else(|| windows_error(GuardPageOperation::Map))
}

#[cfg(target_os = "linux")]
fn protect_data(ptr: NonNull<u8>, len: usize) -> Result<(), GuardPageError> {
    let ret = raw_syscall3(
        SYS_MPROTECT,
        ptr.as_ptr() as usize,
        len,
        PROT_READ | PROT_WRITE,
    );
    if syscall_failed(ret) {
        Err(syscall_error(GuardPageOperation::Protect, ret))
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
fn protect_data(ptr: NonNull<u8>, len: usize) -> Result<(), GuardPageError> {
    // SAFETY: `ptr` and `len` describe the data region inside a live
    // no-access mapping owned by this value.
    let ret = unsafe {
        mprotect(
            ptr.as_ptr().cast::<c_void>(),
            len,
            (PROT_READ | PROT_WRITE) as i32,
        )
    };
    if ret != 0 {
        Err(unix_error(GuardPageOperation::Protect))
    } else {
        Ok(())
    }
}

#[cfg(target_os = "windows")]
fn protect_data(ptr: NonNull<u8>, len: usize) -> Result<(), GuardPageError> {
    let mut old_protect = 0_u32;
    // SAFETY: `ptr` and `len` describe the data region inside a live
    // no-access mapping owned by this value.
    let ret = unsafe {
        VirtualProtect(
            ptr.as_ptr().cast::<c_void>(),
            len,
            PAGE_READWRITE,
            &mut old_protect,
        )
    };
    if ret == 0 {
        Err(windows_error(GuardPageOperation::Protect))
    } else {
        Ok(())
    }
}

#[cfg(all(feature = "page-seal", target_os = "linux"))]
fn seal_data(ptr: NonNull<u8>, len: usize) -> Result<(), GuardPageError> {
    let ret = raw_syscall3(SYS_MPROTECT, ptr.as_ptr() as usize, len, PROT_NONE);
    if syscall_failed(ret) {
        Err(syscall_error(GuardPageOperation::Protect, ret))
    } else {
        Ok(())
    }
}

#[cfg(any(
    all(feature = "page-seal", target_os = "macos"),
    all(feature = "page-seal", target_os = "ios"),
    all(feature = "page-seal", target_os = "android"),
    all(feature = "page-seal", target_os = "freebsd"),
    all(feature = "page-seal", target_os = "openbsd"),
    all(feature = "page-seal", target_os = "netbsd"),
    all(feature = "page-seal", target_os = "dragonfly"),
))]
fn seal_data(ptr: NonNull<u8>, len: usize) -> Result<(), GuardPageError> {
    // SAFETY: `ptr` and `len` describe the live data region owned by the
    // page-sealed value.
    let ret = unsafe { mprotect(ptr.as_ptr().cast::<c_void>(), len, PROT_NONE as i32) };
    if ret != 0 {
        Err(unix_error(GuardPageOperation::Protect))
    } else {
        Ok(())
    }
}

#[cfg(all(feature = "page-seal", target_os = "windows"))]
fn seal_data(ptr: NonNull<u8>, len: usize) -> Result<(), GuardPageError> {
    let mut old_protect = 0_u32;
    // SAFETY: `ptr` and `len` describe the live data region owned by the
    // page-sealed value.
    let ret = unsafe {
        VirtualProtect(
            ptr.as_ptr().cast::<c_void>(),
            len,
            PAGE_NOACCESS,
            &mut old_protect,
        )
    };
    if ret == 0 {
        Err(windows_error(GuardPageOperation::Protect))
    } else {
        Ok(())
    }
}

#[cfg(feature = "page-seal")]
#[derive(Clone, Copy)]
enum PageProtection {
    ReadWrite,
    #[cfg(test)]
    NoAccess,
}

#[cfg(feature = "page-seal")]
fn apply_page_protection(
    ptr: NonNull<u8>,
    len: usize,
    protection: PageProtection,
) -> Result<(), GuardPageError> {
    match protection {
        PageProtection::ReadWrite => protect_data(ptr, len),
        #[cfg(test)]
        PageProtection::NoAccess => seal_data(ptr, len),
    }
}

/// Re-establish a known protection for every page in the data region.
///
/// A failed range-wide `mprotect`/`VirtualProtect` transition may have changed
/// only part of the range. Cleanup must not dereference the mapping until every
/// page has independently been confirmed writable.
#[cfg(feature = "page-seal")]
fn normalize_data_pages(
    ptr: NonNull<u8>,
    len: usize,
    protection: PageProtection,
) -> Result<(), GuardPageError> {
    let page_granule = platform_page_granule();
    let mut first_error = None;

    for offset in (0..len).step_by(page_granule) {
        // SAFETY: guarded writable regions are page-aligned, page-rounded,
        // and live for `len` bytes. `offset` is strictly inside that range.
        let page = unsafe { NonNull::new_unchecked(ptr.as_ptr().add(offset)) };

        if let Err(error) = apply_page_protection(page, page_granule, protection) {
            if first_error.is_none() {
                first_error = Some(error);
            }
        }
    }

    match first_error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

/// Make each page writable, erase it immediately, and restore no-access.
///
/// Processing continues after a page failure so every independently writable
/// page is erased even when another page cannot be normalized. The caller must
/// retain the mapping when any page reports an error because that failed page's
/// protection and contents remain uncertain.
#[cfg(feature = "page-seal")]
fn erase_and_reseal_data_pages(ptr: NonNull<u8>, len: usize) -> Result<(), GuardPageError> {
    let mut observed_reseal_failure = None;
    erase_and_reseal_data_pages_inner(ptr, len, None, None, &mut observed_reseal_failure)
}

#[cfg(all(feature = "page-seal", test))]
fn erase_and_reseal_data_pages_with_failures(
    ptr: NonNull<u8>,
    len: usize,
    failed_write_page: Option<usize>,
    failed_reseal_page: Option<usize>,
) -> (Result<(), GuardPageError>, Option<usize>) {
    let mut observed_reseal_failure = None;
    let result = erase_and_reseal_data_pages_inner(
        ptr,
        len,
        failed_write_page,
        failed_reseal_page,
        &mut observed_reseal_failure,
    );
    (result, observed_reseal_failure)
}

#[cfg(feature = "page-seal")]
fn erase_and_reseal_data_pages_inner(
    ptr: NonNull<u8>,
    len: usize,
    _failed_write_page: Option<usize>,
    _failed_reseal_page: Option<usize>,
    _observed_reseal_failure: &mut Option<usize>,
) -> Result<(), GuardPageError> {
    let page_granule = platform_page_granule();
    let mut first_error = None;

    for offset in (0..len).step_by(page_granule) {
        // SAFETY: guarded writable regions are page-aligned, page-rounded,
        // and live for `len` bytes. `offset` is strictly inside that range.
        let page = unsafe { NonNull::new_unchecked(ptr.as_ptr().add(offset)) };

        #[cfg(test)]
        if _failed_write_page == Some(offset / page_granule) {
            // Keep the injected page inaccessible while other pages continue
            // through immediate erase-and-reseal cleanup.
            let _ = seal_data(page, page_granule);
            if first_error.is_none() {
                first_error = Some(GuardPageError {
                    operation: GuardPageOperation::Protect,
                    errno: 0,
                });
            }
            continue;
        }

        if let Err(error) = protect_data(page, page_granule) {
            if first_error.is_none() {
                first_error = Some(error);
            }
            continue;
        }

        crate::wipe_backend::erase(page.as_ptr(), page_granule);

        #[cfg(test)]
        if _failed_reseal_page == Some(offset / page_granule) {
            // Leave the injected page writable after erasure to model a
            // failed cleanup reseal. The mapping must remain poisoned and
            // retained, while cleanup continues across later pages.
            *_observed_reseal_failure = Some(offset / page_granule);
            if first_error.is_none() {
                first_error = Some(GuardPageError {
                    operation: GuardPageOperation::Protect,
                    errno: 0,
                });
            }
            continue;
        }

        if let Err(error) = seal_data(page, page_granule) {
            if first_error.is_none() {
                first_error = Some(error);
            }
        }
    }

    match first_error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

#[cfg(all(feature = "page-seal", test))]
fn simulate_partial_transition(
    ptr: NonNull<u8>,
    len: usize,
    protection: PageProtection,
) -> Result<(), GuardPageError> {
    if len != 0 {
        apply_page_protection(ptr, platform_page_granule(), protection)?;
    }
    Ok(())
}

#[cfg(all(feature = "memory-lock", target_os = "linux"))]
fn lock_mapping(ptr: NonNull<u8>, len: usize) -> Result<(), GuardPageError> {
    let ret = raw_syscall2(SYS_MLOCK, ptr.as_ptr() as usize, len);
    if syscall_failed(ret) {
        Err(syscall_error(GuardPageOperation::Lock, ret))
    } else {
        Ok(())
    }
}

#[cfg(all(
    feature = "memory-lock",
    any(
        target_os = "macos",
        target_os = "ios",
        target_os = "android",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
    )
))]
fn lock_mapping(ptr: NonNull<u8>, len: usize) -> Result<(), GuardPageError> {
    // SAFETY: `ptr` and `len` describe a live mapping owned by this value.
    let ret = unsafe { mlock(ptr.as_ptr().cast::<c_void>(), len) };
    if ret != 0 {
        Err(unix_error(GuardPageOperation::Lock))
    } else {
        Ok(())
    }
}

#[cfg(all(feature = "memory-lock", target_os = "windows"))]
fn lock_mapping(ptr: NonNull<u8>, len: usize) -> Result<(), GuardPageError> {
    // SAFETY: `ptr` and `len` describe a live region owned by this value.
    let ret = unsafe { VirtualLock(ptr.as_ptr().cast::<c_void>(), len) };
    if ret == 0 {
        Err(windows_error(GuardPageOperation::Lock))
    } else {
        Ok(())
    }
}

#[cfg(all(feature = "memory-lock", target_os = "linux"))]
fn mark_dontdump(ptr: NonNull<u8>, len: usize) -> Result<(), GuardPageError> {
    let ret = raw_syscall3(SYS_MADVISE, ptr.as_ptr() as usize, len, MADV_DONTDUMP);
    if syscall_failed(ret) {
        Err(syscall_error(GuardPageOperation::DontDump, ret))
    } else {
        Ok(())
    }
}

#[cfg(all(
    feature = "memory-lock",
    not(target_os = "linux"),
    not(target_os = "freebsd")
))]
#[inline]
fn mark_dontdump(_ptr: NonNull<u8>, _len: usize) -> Result<(), GuardPageError> {
    Err(GuardPageError {
        operation: GuardPageOperation::DontDump,
        errno: 0,
    })
}

#[cfg(all(feature = "memory-lock", target_os = "freebsd"))]
fn mark_dontdump(ptr: NonNull<u8>, len: usize) -> Result<(), GuardPageError> {
    // SAFETY: `ptr` and `len` describe the live writable data region owned
    // by this value, and `MADV_NOCORE` requests core-dump exclusion for it.
    let ret = unsafe { madvise(ptr.as_ptr().cast::<c_void>(), len, MADV_NOCORE) };
    if ret != 0 {
        Err(unix_error(GuardPageOperation::DontDump))
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
fn mark_dontfork(ptr: NonNull<u8>, len: usize) -> Result<(), GuardPageError> {
    const VM_INHERIT_NONE: c_int = 2;
    // SAFETY: the owning constructor supplies the entire live, page-aligned
    // writable region, before any caller initializer can run. The SDK ABI
    // takes size_t (usize), not a truncated 32-bit length.
    if unsafe { minherit(ptr.as_ptr().cast::<c_void>(), len, VM_INHERIT_NONE) } != 0 {
        Err(unix_error(GuardPageOperation::DontFork))
    } else {
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn mark_dontfork(ptr: NonNull<u8>, len: usize) -> Result<(), GuardPageError> {
    let ret = raw_syscall3(SYS_MADVISE, ptr.as_ptr() as usize, len, MADV_DONTFORK);
    if syscall_failed(ret) {
        Err(syscall_error(GuardPageOperation::DontFork, ret))
    } else {
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn mark_wipeonfork(ptr: NonNull<u8>, len: usize) -> Result<(), GuardPageError> {
    let ret = raw_syscall3(SYS_MADVISE, ptr.as_ptr() as usize, len, MADV_WIPEONFORK);
    if syscall_failed(ret) {
        Err(syscall_error(GuardPageOperation::WipeOnFork, ret))
    } else {
        Ok(())
    }
}

#[cfg(not(target_os = "linux"))]
#[inline]
fn mark_wipeonfork(_ptr: NonNull<u8>, _len: usize) -> Result<(), GuardPageError> {
    Err(GuardPageError {
        operation: GuardPageOperation::WipeOnFork,
        errno: 0,
    })
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
#[inline]
fn mark_dontfork(_ptr: NonNull<u8>, _len: usize) -> Result<(), GuardPageError> {
    Err(GuardPageError {
        operation: GuardPageOperation::DontFork,
        errno: 0,
    })
}

#[cfg(all(feature = "memory-lock", target_os = "linux"))]
fn unlock_mapping(ptr: NonNull<u8>, len: usize) -> Result<(), GuardPageError> {
    let ret = raw_syscall2(SYS_MUNLOCK, ptr.as_ptr() as usize, len);
    if syscall_failed(ret) {
        Err(syscall_error(GuardPageOperation::Unlock, ret))
    } else {
        Ok(())
    }
}

#[cfg(all(
    feature = "memory-lock",
    any(
        target_os = "macos",
        target_os = "ios",
        target_os = "android",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
    )
))]
fn unlock_mapping(ptr: NonNull<u8>, len: usize) -> Result<(), GuardPageError> {
    // SAFETY: `ptr` and `len` describe a live mapping owned by this value.
    let ret = unsafe { munlock(ptr.as_ptr().cast::<c_void>(), len) };
    if ret != 0 {
        Err(unix_error(GuardPageOperation::Unlock))
    } else {
        Ok(())
    }
}

#[cfg(all(feature = "memory-lock", target_os = "windows"))]
fn unlock_mapping(ptr: NonNull<u8>, len: usize) -> Result<(), GuardPageError> {
    // SAFETY: `ptr` and `len` describe a live region owned by this value.
    let ret = unsafe { VirtualUnlock(ptr.as_ptr().cast::<c_void>(), len) };
    if ret == 0 {
        Err(windows_error(GuardPageOperation::Unlock))
    } else {
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn platform_unmap_guarded(ptr: NonNull<u8>, len: usize) -> Result<(), GuardPageError> {
    let ret = raw_syscall2(SYS_MUNMAP, ptr.as_ptr() as usize, len);
    if syscall_failed(ret) {
        Err(syscall_error(GuardPageOperation::Unmap, ret))
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
fn platform_unmap_guarded(ptr: NonNull<u8>, len: usize) -> Result<(), GuardPageError> {
    // SAFETY: `ptr` and `len` describe a live mapping owned by this value.
    let ret = unsafe { munmap(ptr.as_ptr().cast::<c_void>(), len) };
    if ret != 0 {
        Err(unix_error(GuardPageOperation::Unmap))
    } else {
        Ok(())
    }
}

#[cfg(target_os = "windows")]
fn platform_unmap_guarded(ptr: NonNull<u8>, _len: usize) -> Result<(), GuardPageError> {
    // SAFETY: `ptr` points to a region allocated by `VirtualAlloc`.
    let ret = unsafe { VirtualFree(ptr.as_ptr().cast::<c_void>(), 0, MEM_RELEASE) };
    if ret == 0 {
        Err(windows_error(GuardPageOperation::Unmap))
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

fn allocate_guarded(len: usize) -> Result<NonNull<u8>, GuardPageError> {
    #[cfg(all(
        test,
        feature = "std",
        feature = "profile-guarded-native",
        any(target_os = "macos", target_os = "linux"),
        not(miri)
    ))]
    if super::native_tests::fail(ProtectionControl::Mapping) {
        return Err(GuardPageError {
            operation: GuardPageOperation::Map,
            errno: 0,
        });
    }
    let ptr = map_guarded(len)?;
    #[cfg(all(
        test,
        feature = "std",
        feature = "profile-guarded-native",
        any(target_os = "macos", target_os = "linux"),
        not(miri)
    ))]
    super::native_tests::mapped(ptr.as_ptr(), len);
    Ok(ptr)
}

fn establish_guard_data(ptr: NonNull<u8>, len: usize) -> Result<(), GuardPageError> {
    #[cfg(all(
        test,
        feature = "std",
        feature = "profile-guarded-native",
        any(target_os = "macos", target_os = "linux"),
        not(miri)
    ))]
    if super::native_tests::fail(ProtectionControl::GuardPages) {
        return Err(GuardPageError {
            operation: GuardPageOperation::Protect,
            errno: 0,
        });
    }
    protect_data(ptr, len)
}

fn unmap_guarded(ptr: NonNull<u8>, len: usize) -> Result<(), GuardPageError> {
    #[cfg(all(
        test,
        feature = "std",
        feature = "profile-guarded-native",
        any(target_os = "macos", target_os = "linux"),
        not(miri)
    ))]
    super::native_tests::before_unmap(ptr.as_ptr());
    let result = platform_unmap_guarded(ptr, len);
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

#[cfg(all(
    test,
    feature = "std",
    feature = "profile-guarded-native",
    any(target_os = "macos", target_os = "linux"),
    not(miri)
))]
#[test]
fn native_guarded_fork_excludes_entire_writable_region() {
    let mut owner = GuardedSecretVec::with_capacity_with_protection(
        platform_page_granule() + 1,
        super::native_tests::request(true),
    )
    .expect("native guarded setup");
    owner.as_mut_capacity_slice().fill(0xa5);
    assert!(super::native_tests::range_absent_after_fork(
        owner.data.as_ptr(),
        owner.writable_len
    ));
    assert!(owner
        .as_mut_capacity_slice()
        .iter()
        .all(|byte| *byte == 0xa5));
}
