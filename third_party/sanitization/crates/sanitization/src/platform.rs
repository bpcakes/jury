#[cfg(all(
    target_os = "linux",
    target_arch = "aarch64",
    not(all(miri, test)),
    any(feature = "memory-lock", feature = "guard-pages")
))]
#[allow(unsafe_code)]
pub(crate) mod linux_aarch64_page_size {
    use core::{
        arch::asm,
        sync::atomic::{AtomicUsize, Ordering},
    };

    const AT_NULL: usize = 0;
    const AT_PAGESZ: usize = 6;
    const AUXV_ENTRY_SIZE: usize = core::mem::size_of::<usize>() * 2;
    const CONSERVATIVE_PAGE_GRANULE: usize = 65_536;
    const MIN_PAGE_GRANULE: usize = 4096;

    const AT_FDCWD: usize = usize::MAX - 99;
    const O_RDONLY: usize = 0;
    const SYS_OPENAT: usize = 56;
    const SYS_CLOSE: usize = 57;
    const SYS_READ: usize = 63;
    const EINTR_RET: isize = -4;
    const MAX_AUXV_READ_RETRIES: usize = 16;

    static DETECTED_PAGE_GRANULE: AtomicUsize = AtomicUsize::new(0);

    pub(crate) fn detect_page_granule() -> usize {
        let cached = DETECTED_PAGE_GRANULE.load(Ordering::Acquire);
        if cached != 0 {
            return cached;
        }

        let detected = read_auxv_page_size().unwrap_or(CONSERVATIVE_PAGE_GRANULE);
        DETECTED_PAGE_GRANULE.store(detected, Ordering::Release);
        detected
    }

    fn read_auxv_page_size() -> Option<usize> {
        let path = b"/proc/self/auxv\0";
        let fd = raw_syscall4(SYS_OPENAT, AT_FDCWD, path.as_ptr() as usize, O_RDONLY, 0);
        if syscall_failed(fd) {
            return None;
        }

        let fd = fd as usize;
        let mut pending = [0_u8; AUXV_ENTRY_SIZE];
        let mut pending_len = 0;
        let mut buffer = [0_u8; 256];
        let mut interrupted_reads = 0;

        loop {
            let read = raw_syscall3(SYS_READ, fd, buffer.as_mut_ptr() as usize, buffer.len());
            if read == EINTR_RET {
                if interrupted_reads == MAX_AUXV_READ_RETRIES {
                    let _ = raw_syscall1(SYS_CLOSE, fd);
                    return None;
                }
                interrupted_reads += 1;
                continue;
            }

            if syscall_failed(read) || read == 0 {
                let _ = raw_syscall1(SYS_CLOSE, fd);
                return None;
            }

            for byte in buffer[..read as usize].iter().copied() {
                pending[pending_len] = byte;
                pending_len += 1;

                if pending_len == AUXV_ENTRY_SIZE {
                    let (key, value) = parse_auxv_entry(&pending);
                    pending_len = 0;

                    if key == AT_PAGESZ {
                        let _ = raw_syscall1(SYS_CLOSE, fd);
                        return valid_page_granule(value).then_some(value);
                    }

                    if key == AT_NULL {
                        let _ = raw_syscall1(SYS_CLOSE, fd);
                        return None;
                    }
                }
            }
        }
    }

    fn parse_auxv_entry(entry: &[u8; AUXV_ENTRY_SIZE]) -> (usize, usize) {
        let mut key = [0_u8; core::mem::size_of::<usize>()];
        let mut value = [0_u8; core::mem::size_of::<usize>()];
        key.copy_from_slice(&entry[..core::mem::size_of::<usize>()]);
        value.copy_from_slice(&entry[core::mem::size_of::<usize>()..]);
        (usize::from_ne_bytes(key), usize::from_ne_bytes(value))
    }

    fn valid_page_granule(value: usize) -> bool {
        (MIN_PAGE_GRANULE..=CONSERVATIVE_PAGE_GRANULE).contains(&value) && value.is_power_of_two()
    }

    fn syscall_failed(ret: isize) -> bool {
        (-4095..=-1).contains(&ret)
    }

    fn raw_syscall1(number: usize, arg1: usize) -> isize {
        raw_syscall6(number, arg1, 0, 0, 0, 0, 0)
    }

    fn raw_syscall3(number: usize, arg1: usize, arg2: usize, arg3: usize) -> isize {
        raw_syscall6(number, arg1, arg2, arg3, 0, 0, 0)
    }

    fn raw_syscall4(number: usize, arg1: usize, arg2: usize, arg3: usize, arg4: usize) -> isize {
        raw_syscall6(number, arg1, arg2, arg3, arg4, 0, 0)
    }

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
        // number and arguments are fixed by the wrappers above.
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
}

#[cfg(all(
    feature = "asm-compare",
    any(target_arch = "x86_64", target_arch = "aarch64"),
    not(miri)
))]
#[allow(unsafe_code)]
pub(crate) mod compare_asm {
    use core::arch::asm;

    #[inline(never)]
    pub(crate) fn constant_time_eq_equal_len(left: &[u8], right: &[u8]) -> bool {
        equal_len_choice_bit(left, right) == 1
    }

    #[inline(never)]
    pub(crate) fn equal_len_choice_bit(left: &[u8], right: &[u8]) -> u8 {
        #[cfg(target_arch = "x86_64")]
        {
            equal_len_choice_bit_x86_64(left, right)
        }

        #[cfg(target_arch = "aarch64")]
        {
            equal_len_choice_bit_aarch64(left, right)
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[inline(never)]
    fn equal_len_choice_bit_x86_64(left: &[u8], right: &[u8]) -> u8 {
        debug_assert_eq!(left.len(), right.len());

        let mut left_ptr = left.as_ptr();
        let mut right_ptr = right.as_ptr();
        let mut remaining = left.len();
        let diff: usize;
        let tmp: usize;

        // SAFETY: The public caller checks that both slices have the same
        // length. The loop reads exactly `remaining` bytes from each valid
        // slice, never writes memory, and does not expose the raw pointers.
        unsafe {
            asm!(
                "xor {diff:e}, {diff:e}",
                "xor {tmp:e}, {tmp:e}",
                "test {remaining}, {remaining}",
                "je 3f",
                "2:",
                "movzx {tmp:e}, byte ptr [{left_ptr}]",
                "xor {tmp:l}, byte ptr [{right_ptr}]",
                "or {diff:l}, {tmp:l}",
                "inc {left_ptr}",
                "inc {right_ptr}",
                "dec {remaining}",
                "jne 2b",
                "3:",
                left_ptr = inout(reg) left_ptr,
                right_ptr = inout(reg) right_ptr,
                remaining = inout(reg) remaining,
                diff = lateout(reg) diff,
                tmp = lateout(reg) tmp,
                options(nostack, readonly)
            );
        }

        let _ = (left_ptr, right_ptr, remaining, tmp);
        // The assembly loop ORs byte differences into the low accumulator byte.
        // Mask explicitly so the observable Rust contract does not depend on
        // readers inferring that the full register was zeroed before the loop.
        let diff = core::hint::black_box((diff & 0xFF) as u8);
        ((diff | diff.wrapping_neg()) >> 7) ^ 1
    }

    #[cfg(target_arch = "aarch64")]
    #[inline(never)]
    fn equal_len_choice_bit_aarch64(left: &[u8], right: &[u8]) -> u8 {
        debug_assert_eq!(left.len(), right.len());

        let mut left_ptr = left.as_ptr();
        let mut right_ptr = right.as_ptr();
        let mut remaining = left.len();
        let mut diff: u32 = 0;
        let tmp_left: u32;
        let tmp_right: u32;

        // SAFETY: The public caller checks that both slices have the same
        // length. The loop reads exactly `remaining` bytes from each valid
        // slice, never writes memory, and does not expose the raw pointers.
        unsafe {
            asm!(
                "cbz {remaining}, 3f",
                "2:",
                "ldrb {tmp_left:w}, [{left_ptr}], #1",
                "ldrb {tmp_right:w}, [{right_ptr}], #1",
                "eor {tmp_left:w}, {tmp_left:w}, {tmp_right:w}",
                "orr {diff:w}, {diff:w}, {tmp_left:w}",
                "subs {remaining}, {remaining}, #1",
                "b.ne 2b",
                "3:",
                left_ptr = inout(reg) left_ptr,
                right_ptr = inout(reg) right_ptr,
                remaining = inout(reg) remaining,
                diff = inout(reg) diff,
                tmp_left = lateout(reg) tmp_left,
                tmp_right = lateout(reg) tmp_right,
                options(nostack, readonly)
            );
        }

        let _ = (left_ptr, right_ptr, remaining, tmp_left, tmp_right);
        let diff = core::hint::black_box((diff & 0xFF) as u8);
        ((diff | diff.wrapping_neg()) >> 7) ^ 1
    }
}

#[cfg(feature = "cache-flush")]
#[allow(unsafe_code)]
pub mod cache_flush {
    #[cfg(feature = "alloc")]
    use alloc::{string::String, vec::Vec};
    use core::fmt;
    #[cfg(all(target_arch = "x86_64", not(all(miri, test))))]
    use core::sync::atomic::{compiler_fence, Ordering};

    #[cfg(any(all(target_arch = "x86_64", not(all(miri, test))), test))]
    const MIN_CACHE_LINE_SIZE: usize = 8;
    #[cfg(any(all(target_arch = "x86_64", not(all(miri, test))), test))]
    const MAX_CACHE_LINE_SIZE: usize = 4096;

    /// Runtime capability required for x86 cache-line eviction.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct CacheFlushCapability {
        cache_line_size: usize,
    }

    impl CacheFlushCapability {
        /// Cache-line size reported by CPUID for `clflush`, in bytes.
        #[must_use]
        #[inline]
        pub const fn cache_line_size(self) -> usize {
            self.cache_line_size
        }
    }

    /// Successful cache-eviction outcome.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct CacheFlushReport {
        bytes_covered: usize,
        cache_line_size: usize,
        cache_lines_flushed: usize,
    }

    impl CacheFlushReport {
        /// Number of bytes in the caller-provided range.
        #[must_use]
        #[inline]
        pub const fn bytes_covered(self) -> usize {
            self.bytes_covered
        }

        /// Cache-line size used for range alignment and stepping.
        #[must_use]
        #[inline]
        pub const fn cache_line_size(self) -> usize {
            self.cache_line_size
        }

        /// Number of cache lines on which `clflush` executed.
        #[must_use]
        #[inline]
        pub const fn cache_lines_flushed(self) -> usize {
            self.cache_lines_flushed
        }
    }

    /// Why cache-line eviction could not be completed.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum CacheFlushError {
        /// The current architecture has no backend in this crate.
        UnsupportedArchitecture,
        /// Miri cannot execute or validate the native cache instruction.
        UnavailableUnderMiri,
        /// CPUID reports that `clflush` is unavailable.
        InstructionUnavailable,
        /// CPUID reported a zero, non-power-of-two, or unreasonable line size.
        InvalidReportedLineSize {
            /// Raw CPUID line size in bytes.
            reported: usize,
        },
        /// The provided pointer range could not be represented without overflow.
        AddressRangeOverflow,
    }

    impl fmt::Display for CacheFlushError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::UnsupportedArchitecture => {
                    formatter.write_str("cache-line eviction is unsupported on this architecture")
                }
                Self::UnavailableUnderMiri => {
                    formatter.write_str("cache-line eviction is unavailable under Miri")
                }
                Self::InstructionUnavailable => {
                    formatter.write_str("CPUID reports that clflush is unavailable")
                }
                Self::InvalidReportedLineSize { reported } => {
                    write!(
                        formatter,
                        "CPUID reported invalid clflush line size {reported}"
                    )
                }
                Self::AddressRangeOverflow => {
                    formatter.write_str("cache-flush address range overflowed")
                }
            }
        }
    }

    #[cfg(feature = "std")]
    impl std::error::Error for CacheFlushError {}

    /// Trait for values that should be cleared with volatile byte writes and
    /// then evicted from x86_64 cache lines when supported.
    pub trait CacheFlushSanitize {
        /// Clear this value, then try to flush the cache lines covering its
        /// storage.
        ///
        /// Implementations must clear before returning any error.
        fn cache_flush_sanitize(&mut self) -> Result<CacheFlushReport, CacheFlushError>;
    }

    /// Query the runtime cache-flush capability.
    ///
    /// The x86_64 backend checks the CPUID `CLFSH` bit and validates the
    /// reported line size before any `clflush` instruction can execute.
    #[inline]
    pub fn cache_flush_capability() -> Result<CacheFlushCapability, CacheFlushError> {
        detect_capability()
    }

    /// Flush the cache lines covering a byte slice.
    ///
    /// This does not clear memory by itself. Prefer
    /// [`cache_flush_sanitize_bytes`] for secret clearing.
    ///
    /// # Errors
    ///
    /// Returns a structured error when the backend is unsupported, unavailable,
    /// or cannot safely represent the address range.
    #[inline(never)]
    pub fn flush_cache_lines(bytes: &[u8]) -> Result<CacheFlushReport, CacheFlushError> {
        flush_raw(bytes.as_ptr(), bytes.len())
    }

    /// Clear a mutable byte slice with volatile writes, then flush its cache
    /// lines.
    ///
    /// The volatile clear always occurs, including when cache eviction returns
    /// an error.
    #[inline(never)]
    pub fn cache_flush_sanitize_bytes(
        bytes: &mut [u8],
    ) -> Result<CacheFlushReport, CacheFlushError> {
        crate::wipe::bytes(bytes);
        flush_raw(bytes.as_ptr(), bytes.len())
    }

    /// Clear a fixed-size byte array with volatile writes, then flush its cache
    /// lines.
    #[inline(never)]
    pub fn cache_flush_sanitize_array<const N: usize>(
        bytes: &mut [u8; N],
    ) -> Result<CacheFlushReport, CacheFlushError> {
        cache_flush_sanitize_bytes(bytes)
    }

    /// Clear a `Vec<u8>` allocation capacity with volatile writes, then flush
    /// the cache lines covering the allocation.
    #[cfg(feature = "alloc")]
    #[inline(never)]
    pub fn cache_flush_sanitize_vec(
        bytes: &mut Vec<u8>,
    ) -> Result<CacheFlushReport, CacheFlushError> {
        let ptr = bytes.as_ptr();
        let len = bytes.capacity();
        crate::wipe::vec(bytes);
        flush_raw(ptr, len)
    }

    /// Clear a `String` allocation capacity with volatile writes, then flush
    /// the cache lines covering the allocation.
    #[cfg(feature = "alloc")]
    #[inline(never)]
    pub fn cache_flush_sanitize_string(
        text: &mut String,
    ) -> Result<CacheFlushReport, CacheFlushError> {
        let ptr = text.as_ptr();
        let len = text.capacity();
        crate::wipe::string(text);
        flush_raw(ptr, len)
    }

    impl CacheFlushSanitize for [u8] {
        #[inline(never)]
        fn cache_flush_sanitize(&mut self) -> Result<CacheFlushReport, CacheFlushError> {
            cache_flush_sanitize_bytes(self)
        }
    }

    impl<const N: usize> CacheFlushSanitize for [u8; N] {
        #[inline(never)]
        fn cache_flush_sanitize(&mut self) -> Result<CacheFlushReport, CacheFlushError> {
            cache_flush_sanitize_array(self)
        }
    }

    #[cfg(feature = "alloc")]
    impl CacheFlushSanitize for Vec<u8> {
        #[inline(never)]
        fn cache_flush_sanitize(&mut self) -> Result<CacheFlushReport, CacheFlushError> {
            cache_flush_sanitize_vec(self)
        }
    }

    #[cfg(feature = "alloc")]
    impl CacheFlushSanitize for String {
        #[inline(never)]
        fn cache_flush_sanitize(&mut self) -> Result<CacheFlushReport, CacheFlushError> {
            cache_flush_sanitize_string(self)
        }
    }

    /// Clear-on-drop wrapper using volatile writes followed by checked x86_64
    /// cache-line eviction.
    ///
    /// `Drop` cannot return an error, so it always clears and treats eviction
    /// as best effort. Use [`CacheFlushOnDrop::into_cleared`] when the caller
    /// must observe the eviction result.
    pub struct CacheFlushOnDrop<T: CacheFlushSanitize> {
        inner: T,
    }

    impl<T: CacheFlushSanitize> CacheFlushOnDrop<T> {
        /// Wrap a value that implements [`CacheFlushSanitize`].
        #[must_use]
        #[inline]
        pub const fn new(inner: T) -> Self {
            Self { inner }
        }

        /// Run a closure with read-only access to the wrapped value.
        #[inline]
        pub fn with_secret<R>(&self, inspect: impl FnOnce(&T) -> R) -> R {
            inspect(&self.inner)
        }

        /// Run a closure with mutable access to the wrapped value.
        #[inline]
        pub fn with_secret_mut<R>(&mut self, edit: impl FnOnce(&mut T) -> R) -> R {
            edit(&mut self.inner)
        }

        /// Consume the wrapper after first clearing the wrapped value and
        /// attempting cache eviction.
        ///
        /// # Errors
        ///
        /// The wrapped value has already been cleared when an error is
        /// returned.
        #[inline]
        pub fn into_cleared(mut self) -> Result<CacheFlushReport, CacheFlushError> {
            self.inner.cache_flush_sanitize()
        }
    }

    impl<T: CacheFlushSanitize> Drop for CacheFlushOnDrop<T> {
        #[inline]
        fn drop(&mut self) {
            let _ = self.inner.cache_flush_sanitize();
        }
    }

    impl<T: CacheFlushSanitize> core::fmt::Debug for CacheFlushOnDrop<T> {
        fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            formatter
                .debug_struct("CacheFlushOnDrop")
                .field("contents", &"<redacted>")
                .finish()
        }
    }

    #[inline(never)]
    fn flush_raw(ptr: *const u8, len: usize) -> Result<CacheFlushReport, CacheFlushError> {
        let capability = detect_capability()?;

        #[cfg(all(target_arch = "x86_64", not(all(miri, test))))]
        {
            let cache_line_size = capability.cache_line_size;
            let Some((first_line, end_line, expected_lines)) =
                cache_line_range(ptr as usize, len, cache_line_size)?
            else {
                return Ok(CacheFlushReport {
                    bytes_covered: 0,
                    cache_line_size,
                    cache_lines_flushed: 0,
                });
            };
            let mut current = first_line;
            let mut cache_lines_flushed = 0usize;

            compiler_fence(Ordering::SeqCst);

            loop {
                // SAFETY: capability detection verified `clflush` support.
                // Callers provide a range derived from a live slice or owned
                // allocation. `clflush` identifies a cache line by virtual
                // address and does not dereference it through a Rust pointer.
                unsafe {
                    core::arch::asm!(
                        "clflush [{address}]",
                        address = in(reg) current as *const u8,
                        options(nostack, preserves_flags)
                    );
                }
                cache_lines_flushed += 1;

                if current == end_line {
                    break;
                }
                current = current
                    .checked_add(cache_line_size)
                    .ok_or(CacheFlushError::AddressRangeOverflow)?;
            }

            // SAFETY: `mfence` orders prior cache flushes before later memory
            // operations and does not access memory itself.
            unsafe {
                core::arch::asm!("mfence", options(nostack, preserves_flags));
            }

            compiler_fence(Ordering::SeqCst);
            debug_assert_eq!(cache_lines_flushed, expected_lines);
            Ok(CacheFlushReport {
                bytes_covered: len,
                cache_line_size,
                cache_lines_flushed,
            })
        }

        #[cfg(any(not(target_arch = "x86_64"), all(miri, test)))]
        {
            let _ = (ptr, len, capability);
            unreachable!("unsupported cache-flush targets cannot yield a capability")
        }
    }

    #[cfg(all(target_arch = "x86_64", not(all(miri, test))))]
    #[allow(unused_unsafe)]
    #[inline]
    fn detect_capability() -> Result<CacheFlushCapability, CacheFlushError> {
        const CPUID_1_EDX_CLFSH: u32 = 1 << 19;

        // SAFETY: CPUID leaf 1 is available on x86_64 and only reads CPU
        // feature metadata. Newer compilers expose this intrinsic as safe,
        // while the MSRV still requires an unsafe call.
        let cpuid = unsafe { core::arch::x86_64::__cpuid_count(1, 0) };
        if cpuid.edx & CPUID_1_EDX_CLFSH == 0 {
            return Err(CacheFlushError::InstructionUnavailable);
        }

        let cache_line_size = (((cpuid.ebx >> 8) & 0xFF) as usize) * 8;
        if !valid_cache_line_size(cache_line_size) {
            return Err(CacheFlushError::InvalidReportedLineSize {
                reported: cache_line_size,
            });
        }

        Ok(CacheFlushCapability { cache_line_size })
    }

    #[cfg(all(miri, test))]
    #[inline]
    const fn detect_capability() -> Result<CacheFlushCapability, CacheFlushError> {
        Err(CacheFlushError::UnavailableUnderMiri)
    }

    #[cfg(all(not(target_arch = "x86_64"), not(all(miri, test))))]
    #[inline]
    const fn detect_capability() -> Result<CacheFlushCapability, CacheFlushError> {
        Err(CacheFlushError::UnsupportedArchitecture)
    }

    #[cfg(any(all(target_arch = "x86_64", not(all(miri, test))), test))]
    #[inline]
    const fn valid_cache_line_size(cache_line_size: usize) -> bool {
        cache_line_size >= MIN_CACHE_LINE_SIZE
            && cache_line_size <= MAX_CACHE_LINE_SIZE
            && cache_line_size.is_power_of_two()
    }

    #[cfg(any(all(target_arch = "x86_64", not(all(miri, test))), test))]
    #[inline]
    fn cache_line_range(
        start: usize,
        len: usize,
        cache_line_size: usize,
    ) -> Result<Option<(usize, usize, usize)>, CacheFlushError> {
        if len == 0 {
            return Ok(None);
        }

        let end = start
            .checked_add(len - 1)
            .ok_or(CacheFlushError::AddressRangeOverflow)?;
        let first_line = start & !(cache_line_size - 1);
        let end_line = end & !(cache_line_size - 1);
        let lines = ((end_line - first_line) / cache_line_size) + 1;
        Ok(Some((first_line, end_line, lines)))
    }

    #[cfg(test)]
    mod tests {
        use super::{cache_line_range, valid_cache_line_size, CacheFlushError};

        #[test]
        fn cache_line_size_validation_rejects_unusable_values() {
            assert!(valid_cache_line_size(64));
            assert!(valid_cache_line_size(128));
            assert!(!valid_cache_line_size(0));
            assert!(!valid_cache_line_size(24));
            assert!(!valid_cache_line_size(8192));
        }

        #[test]
        fn cache_line_range_handles_alignment_and_overflow() {
            assert_eq!(cache_line_range(64, 0, 64), Ok(None));
            assert_eq!(cache_line_range(64, 64, 64), Ok(Some((64, 64, 1))));
            assert_eq!(cache_line_range(63, 2, 64), Ok(Some((0, 64, 2))));
            assert_eq!(
                cache_line_range(usize::MAX - 3, 8, 64),
                Err(CacheFlushError::AddressRangeOverflow)
            );
        }
    }
}

/// Architecture-specific register scrubbing helpers.
///
/// This module is available with the `register-scrub` feature. It is an
/// explicit best-effort boundary for code that wants to clear caller-saved SIMD
/// registers after cryptographic routines. It does not and cannot clear
/// registers saved by the compiler, callee-saved vector state,
/// kernel context-switch buffers, or registers owned by other threads.
#[cfg(feature = "register-scrub")]
#[allow(unsafe_code)]
pub mod register_scrub {
    #[cfg(all(target_arch = "x86_64", not(all(miri, test))))]
    use core::sync::atomic::AtomicU8;
    use core::sync::atomic::{compiler_fence, Ordering};

    #[cfg(all(target_arch = "x86_64", not(all(miri, test))))]
    const AVX_UNKNOWN: u8 = 0;
    #[cfg(all(target_arch = "x86_64", not(all(miri, test))))]
    const AVX_SUPPORTED: u8 = 1;
    #[cfg(all(target_arch = "x86_64", not(all(miri, test))))]
    const AVX_NOT_SUPPORTED: u8 = 2;

    #[cfg(all(target_arch = "x86_64", not(all(miri, test))))]
    static AVX_STATE: AtomicU8 = AtomicU8::new(AVX_UNKNOWN);

    /// Architectural register subset scrubbed by one call.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum RegisterScrubReport {
        /// x86_64 XMM0-XMM5 were cleared.
        X86CallerSavedXmm,
        /// Non-Windows x86_64 YMM0-YMM15 were cleared with `vzeroall`.
        X86AvxYmm0To15,
        /// Windows x64 XMM0-XMM5 and all YMM upper halves were cleared.
        X86WindowsCallerSavedXmmAndYmmUpper,
        /// AArch64 V0-V7 and V16-V31 were cleared.
        Aarch64CallerSavedVector,
        /// The architecture has no register-scrub backend in this crate.
        UnsupportedArchitecture,
        /// Miri cannot execute or validate the architecture instructions.
        UnavailableUnderMiri,
    }

    impl RegisterScrubReport {
        /// Whether architecture-specific register-zeroing instructions ran.
        #[must_use]
        #[inline]
        pub const fn instructions_executed(self) -> bool {
            !matches!(
                self,
                Self::UnsupportedArchitecture | Self::UnavailableUnderMiri
            )
        }
    }

    /// Best-effort scrub of architecture SIMD/vector registers supported by
    /// this crate.
    ///
    /// On unsupported architectures this returns an explicit unsupported
    /// report after a compiler fence. On x86_64 it
    /// clears caller-saved XMM0-XMM5 and, when AVX OS support is detected,
    /// clears AVX upper register state. Non-Windows x86_64 targets use
    /// `vzeroall` when AVX is available; Windows x64 uses `vzeroupper` to avoid
    /// clobbering ABI-preserved XMM6-XMM15 lower halves. On AArch64 it clears
    /// caller-saved V0-V7 and V16-V31. Call this immediately after a
    /// cryptographic routine that may have left key material in vector
    /// registers.
    ///
    /// This is not complete register-file erasure. AVX-512 opmask registers
    /// and ZMM16-ZMM31 are not scrubbed, and AArch64 V8-V15 upper halves are
    /// intentionally not modified because Rust inline assembly cannot express
    /// that partial-register clobber safely.
    #[must_use]
    #[inline(never)]
    pub fn scrub_simd_registers() -> RegisterScrubReport {
        compiler_fence(Ordering::SeqCst);

        #[cfg(all(target_arch = "x86_64", not(all(miri, test))))]
        let report = scrub_x86_64_simd_registers();

        #[cfg(all(target_arch = "aarch64", not(all(miri, test))))]
        let report = scrub_aarch64_neon_registers();

        #[cfg(all(miri, test))]
        let report = RegisterScrubReport::UnavailableUnderMiri;

        #[cfg(all(
            not(all(miri, test)),
            not(any(target_arch = "x86_64", target_arch = "aarch64"))
        ))]
        let report = RegisterScrubReport::UnsupportedArchitecture;

        compiler_fence(Ordering::SeqCst);
        report
    }

    /// Clear x86_64 XMM registers with zeroing instructions.
    #[cfg(all(target_arch = "x86_64", not(all(miri, test))))]
    #[must_use]
    #[inline(never)]
    pub fn scrub_x86_64_simd_registers() -> RegisterScrubReport {
        if avx_os_supported() {
            scrub_x86_64_avx_registers()
        } else {
            scrub_x86_64_sse_registers();
            RegisterScrubReport::X86CallerSavedXmm
        }
    }

    #[cfg(all(target_arch = "x86_64", not(all(miri, test))))]
    #[inline(never)]
    fn scrub_x86_64_sse_registers() {
        // SAFETY: These instructions write only caller-saved architectural
        // SIMD registers in the current thread. They do not read or write
        // memory.
        unsafe {
            core::arch::asm!(
                "pxor xmm0, xmm0",
                "pxor xmm1, xmm1",
                "pxor xmm2, xmm2",
                "pxor xmm3, xmm3",
                "pxor xmm4, xmm4",
                "pxor xmm5, xmm5",
                out("xmm0") _,
                out("xmm1") _,
                out("xmm2") _,
                out("xmm3") _,
                out("xmm4") _,
                out("xmm5") _,
                options(nostack, nomem, preserves_flags)
            );
        }
    }

    #[cfg(all(
        target_arch = "x86_64",
        not(target_os = "windows"),
        not(all(miri, test))
    ))]
    #[inline(never)]
    fn scrub_x86_64_avx_registers() -> RegisterScrubReport {
        // SAFETY: `avx_os_supported` verified AVX and XMM/YMM OS save support.
        // On non-Windows x86_64 ABIs, XMM/YMM registers are caller-saved. The
        // instruction does not read or write memory.
        unsafe {
            core::arch::asm!(
                "vzeroall",
                out("xmm0") _,
                out("xmm1") _,
                out("xmm2") _,
                out("xmm3") _,
                out("xmm4") _,
                out("xmm5") _,
                out("xmm6") _,
                out("xmm7") _,
                out("xmm8") _,
                out("xmm9") _,
                out("xmm10") _,
                out("xmm11") _,
                out("xmm12") _,
                out("xmm13") _,
                out("xmm14") _,
                out("xmm15") _,
                options(nostack, nomem, preserves_flags)
            );
        }
        RegisterScrubReport::X86AvxYmm0To15
    }

    #[cfg(all(target_arch = "x86_64", target_os = "windows", not(all(miri, test))))]
    #[inline(never)]
    fn scrub_x86_64_avx_registers() -> RegisterScrubReport {
        scrub_x86_64_sse_registers();
        // SAFETY: `avx_os_supported` verified AVX and XMM/YMM OS save support.
        // `vzeroupper` clears the upper vector state without clobbering the
        // ABI-preserved lower halves of XMM6-XMM15 on Windows x64.
        unsafe {
            core::arch::asm!("vzeroupper", options(nostack, nomem, preserves_flags));
        }
        RegisterScrubReport::X86WindowsCallerSavedXmmAndYmmUpper
    }

    #[cfg(all(target_arch = "x86_64", not(all(miri, test))))]
    #[inline]
    fn avx_os_supported() -> bool {
        let cached = AVX_STATE.load(Ordering::Relaxed);
        if cached != AVX_UNKNOWN {
            return cached == AVX_SUPPORTED;
        }

        // Benign init race: `detect_avx_os_support` is pure and idempotent.
        // Concurrent first callers may repeat CPUID/XGETBV detection, but all
        // writers store the same value and no other state depends on ordering.
        let detected = detect_avx_os_support();
        AVX_STATE.store(
            if detected {
                AVX_SUPPORTED
            } else {
                AVX_NOT_SUPPORTED
            },
            Ordering::Relaxed,
        );
        detected
    }

    #[cfg(all(target_arch = "x86_64", not(all(miri, test))))]
    #[inline]
    fn detect_avx_os_support() -> bool {
        const CPUID_1_ECX_OSXSAVE: u32 = 1 << 27;
        const CPUID_1_ECX_AVX: u32 = 1 << 28;
        const XCR0_XMM: u64 = 1 << 1;
        const XCR0_YMM: u64 = 1 << 2;

        // SAFETY: `cpuid` and `xgetbv` query CPU/OS feature state and do not
        // access memory. `_xgetbv(0)` is executed only when CPUID reports
        // OSXSAVE support.
        unsafe {
            let cpuid = core::arch::x86_64::__cpuid_count(1, 0);
            if (cpuid.ecx & (CPUID_1_ECX_OSXSAVE | CPUID_1_ECX_AVX))
                != (CPUID_1_ECX_OSXSAVE | CPUID_1_ECX_AVX)
            {
                return false;
            }

            let xcr0 = core::arch::x86_64::_xgetbv(0);
            (xcr0 & (XCR0_XMM | XCR0_YMM)) == (XCR0_XMM | XCR0_YMM)
        }
    }

    /// Clear AArch64 NEON vector registers with zeroing instructions.
    #[cfg(all(target_arch = "aarch64", not(all(miri, test))))]
    #[must_use]
    #[inline(never)]
    pub fn scrub_aarch64_neon_registers() -> RegisterScrubReport {
        // SAFETY: These instructions write only architectural vector registers
        // in the current thread. They do not read or write memory.
        unsafe {
            core::arch::asm!(
                "eor v0.16b, v0.16b, v0.16b",
                "eor v1.16b, v1.16b, v1.16b",
                "eor v2.16b, v2.16b, v2.16b",
                "eor v3.16b, v3.16b, v3.16b",
                "eor v4.16b, v4.16b, v4.16b",
                "eor v5.16b, v5.16b, v5.16b",
                "eor v6.16b, v6.16b, v6.16b",
                "eor v7.16b, v7.16b, v7.16b",
                "eor v16.16b, v16.16b, v16.16b",
                "eor v17.16b, v17.16b, v17.16b",
                "eor v18.16b, v18.16b, v18.16b",
                "eor v19.16b, v19.16b, v19.16b",
                "eor v20.16b, v20.16b, v20.16b",
                "eor v21.16b, v21.16b, v21.16b",
                "eor v22.16b, v22.16b, v22.16b",
                "eor v23.16b, v23.16b, v23.16b",
                "eor v24.16b, v24.16b, v24.16b",
                "eor v25.16b, v25.16b, v25.16b",
                "eor v26.16b, v26.16b, v26.16b",
                "eor v27.16b, v27.16b, v27.16b",
                "eor v28.16b, v28.16b, v28.16b",
                "eor v29.16b, v29.16b, v29.16b",
                "eor v30.16b, v30.16b, v30.16b",
                "eor v31.16b, v31.16b, v31.16b",
                out("v0") _,
                out("v1") _,
                out("v2") _,
                out("v3") _,
                out("v4") _,
                out("v5") _,
                out("v6") _,
                out("v7") _,
                out("v16") _,
                out("v17") _,
                out("v18") _,
                out("v19") _,
                out("v20") _,
                out("v21") _,
                out("v22") _,
                out("v23") _,
                out("v24") _,
                out("v25") _,
                out("v26") _,
                out("v27") _,
                out("v28") _,
                out("v29") _,
                out("v30") _,
                out("v31") _,
                options(nostack, nomem)
            );
        }
        RegisterScrubReport::Aarch64CallerSavedVector
    }
}

/// Traits for integrating external hardware-backed secret providers.
///
/// This module is available with the `hardware-secrets` feature. It deliberately
/// defines only trait surfaces and small error types; it does not claim built-in
/// SGX, Nitro, TPM, HSM, or enclave support. Backend crates can implement these
/// traits while keeping vendor SDKs and platform dependencies out of the main
/// crate.
#[cfg(feature = "hardware-secrets")]
pub mod hardware {
    use core::fmt;

    /// Broad class of hardware-backed provider failure.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum HardwareSecretErrorKind {
        /// The backend is unavailable on this host.
        Unavailable,
        /// The backend denied access to the requested secret.
        AccessDenied,
        /// The caller provided an invalid or stale handle.
        InvalidHandle,
        /// The caller-provided output buffer is too small.
        OutputTooSmall,
        /// Backend-specific failure.
        Backend,
    }

    /// Small dependency-free error type for hardware-backed secret providers.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct HardwareSecretError {
        /// Failure class.
        pub kind: HardwareSecretErrorKind,
        /// Optional platform or backend error code. `0` means unavailable.
        pub code: i32,
    }

    impl fmt::Display for HardwareSecretError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                formatter,
                "hardware secret operation {:?} failed with code {}",
                self.kind, self.code
            )
        }
    }

    #[cfg(feature = "std")]
    impl std::error::Error for HardwareSecretError {}

    /// Marker trait for opaque handles owned by a hardware-backed provider.
    pub trait HardwareSecretHandle {}

    /// Provider interface for secrets that live outside ordinary process
    /// memory until deliberately exposed through a closure.
    pub trait HardwareSecretProvider {
        /// Opaque backend-owned handle type.
        type Handle: HardwareSecretHandle;
        /// Backend-specific error type.
        type Error;

        /// Seal or import a byte slice into the backend and return a handle.
        fn seal_from_slice(&self, secret: &[u8]) -> Result<Self::Handle, Self::Error>;

        /// Expose a backend secret for the duration of a closure.
        fn expose_secret<R, F: FnOnce(&[u8]) -> R>(
            &self,
            handle: &Self::Handle,
            inspect: F,
        ) -> Result<R, Self::Error>;

        /// Replace the value behind an existing backend handle.
        fn rotate_from_slice(
            &self,
            handle: &mut Self::Handle,
            secret: &[u8],
        ) -> Result<(), Self::Error>;

        /// Destroy a backend handle if the provider has an explicit deletion
        /// operation. Providers without one may make this a no-op.
        fn destroy(&self, handle: Self::Handle) -> Result<(), Self::Error>;
    }
}
