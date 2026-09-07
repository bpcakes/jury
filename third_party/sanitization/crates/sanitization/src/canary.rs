#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly",
    target_os = "windows",
))]
use core::ffi::c_void;

#[cfg(any(target_os = "linux", target_os = "android"))]
use core::arch::asm;

#[cfg(all(
    any(target_os = "linux", target_os = "android"),
    target_arch = "x86_64"
))]
const SYS_GETRANDOM: usize = 318;
#[cfg(all(
    any(target_os = "linux", target_os = "android"),
    target_arch = "aarch64"
))]
const SYS_GETRANDOM: usize = 278;

#[cfg(target_os = "windows")]
const BCRYPT_USE_SYSTEM_PREFERRED_RNG: u32 = 0x0000_0002;
#[cfg(all(
    any(target_os = "linux", target_os = "android"),
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
const ERRNO_NO_PROGRESS: i32 = -2;
#[cfg(all(
    any(target_os = "linux", target_os = "android"),
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
const EINTR: i32 = 4;
#[cfg(all(
    any(target_os = "linux", target_os = "android"),
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
const EAGAIN: i32 = 11;
#[cfg(all(
    any(target_os = "linux", target_os = "android"),
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
const MAX_GETRANDOM_RETRIES: usize = 16;

#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly",
))]
unsafe extern "C" {
    fn arc4random_buf(buf: *mut c_void, nbytes: usize);
}

#[cfg(target_os = "windows")]
#[link(name = "bcrypt")]
unsafe extern "system" {
    fn BCryptGenRandom(algorithm: *mut c_void, buffer: *mut u8, buffer_len: u32, flags: u32)
        -> i32;
}

#[cfg(all(target_os = "wasi", target_env = "p1"))]
#[link(wasm_import_module = "wasi_snapshot_preview1")]
unsafe extern "C" {
    #[link_name = "random_get"]
    fn wasi_random_get(buf: *mut u8, buf_len: usize) -> u16;
}

#[cfg(all(
    test,
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64"),
    not(miri)
))]
std::thread_local! {
    static FAIL_NEXT_FILL: core::cell::Cell<bool> = const { core::cell::Cell::new(false) };
}

#[cfg(all(
    test,
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64"),
    not(miri)
))]
pub(crate) fn fail_next_fill_for_test() {
    FAIL_NEXT_FILL.with(|fail| fail.set(true));
}

pub(crate) const CANARY_SIZE: usize = 8;

/// Non-copying owner for random canary material held outside a mapping.
pub(crate) struct CanaryMaterial([u8; CANARY_SIZE]);

impl CanaryMaterial {
    #[inline]
    pub(crate) const fn zeroed() -> Self {
        Self([0; CANARY_SIZE])
    }

    #[inline]
    pub(crate) fn random() -> Result<Self, i32> {
        let mut material = Self::zeroed();
        fill(&mut material.0)?;
        Ok(material)
    }

    #[inline]
    pub(crate) const fn as_bytes(&self) -> &[u8; CANARY_SIZE] {
        &self.0
    }

    #[inline]
    pub(crate) fn clear(&mut self) {
        crate::wipe_backend::erase(self.0.as_mut_ptr(), self.0.len());
    }
}

impl Drop for CanaryMaterial {
    #[inline]
    fn drop(&mut self) {
        self.clear();
    }
}

pub(crate) fn fill(bytes: &mut [u8]) -> Result<(), i32> {
    if bytes.is_empty() {
        return Ok(());
    }

    #[cfg(all(
        test,
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64"),
        not(miri)
    ))]
    if FAIL_NEXT_FILL.with(|fail| fail.replace(false)) {
        const ERRNO_INJECTED_FAILURE: i32 = -3;
        return Err(ERRNO_INJECTED_FAILURE);
    }

    #[cfg(all(miri, test))]
    {
        fill_for_miri(bytes);
        Ok(())
    }

    #[cfg(not(all(miri, test)))]
    fill_inner(bytes)
}

/// Miri cannot execute the native CSPRNG syscall/FFI boundary. This generator
/// exists only in this crate's unit-test build to exercise canary ownership and
/// failure handling; it makes no randomness or deployment-security claim.
#[cfg(all(miri, test))]
fn fill_for_miri(bytes: &mut [u8]) {
    use core::sync::atomic::{AtomicUsize, Ordering};

    static GENERATION: AtomicUsize = AtomicUsize::new(1);
    let generation = GENERATION.fetch_add(1, Ordering::Relaxed);
    let mut state = (generation as u64)
        .wrapping_mul(0x9E37_79B9_7F4A_7C15)
        .wrapping_add(0xD1B5_4A32_D192_ED03);

    for byte in bytes {
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        state = state.wrapping_mul(0x2545_F491_4F6C_DD1D);
        *byte = state as u8;
    }
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
fn fill_inner(bytes: &mut [u8]) -> Result<(), i32> {
    fill_with_getrandom_syscall(bytes)
}

#[cfg(all(
    target_os = "android",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
fn fill_inner(bytes: &mut [u8]) -> Result<(), i32> {
    fill_with_getrandom_syscall(bytes)
}

#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly",
))]
fn fill_inner(bytes: &mut [u8]) -> Result<(), i32> {
    // SAFETY: `bytes` is a live mutable byte slice, and `arc4random_buf`
    // fills exactly the provided byte range without additional
    // initialization requirements.
    unsafe { arc4random_buf(bytes.as_mut_ptr().cast::<c_void>(), bytes.len()) };
    Ok(())
}

#[cfg(target_os = "windows")]
fn fill_inner(bytes: &mut [u8]) -> Result<(), i32> {
    for chunk in bytes.chunks_mut(u32::MAX as usize) {
        // SAFETY: `chunk` is a live mutable byte slice. A null algorithm
        // handle with `BCRYPT_USE_SYSTEM_PREFERRED_RNG` requests the
        // system-preferred CSPRNG.
        let status = unsafe {
            BCryptGenRandom(
                core::ptr::null_mut(),
                chunk.as_mut_ptr(),
                chunk.len() as u32,
                BCRYPT_USE_SYSTEM_PREFERRED_RNG,
            )
        };
        if status != 0 {
            return Err(status);
        }
    }
    Ok(())
}

#[cfg(all(target_os = "wasi", target_env = "p1"))]
fn fill_inner(bytes: &mut [u8]) -> Result<(), i32> {
    // SAFETY: `bytes` is a live mutable byte slice. WASI preview1
    // `random_get` writes exactly the requested byte range or returns an
    // errno without retaining the pointer.
    let errno = unsafe { wasi_random_get(bytes.as_mut_ptr(), bytes.len()) };
    if errno == 0 {
        Ok(())
    } else {
        Err(errno as i32)
    }
}

#[cfg(not(any(
    all(
        any(target_os = "linux", target_os = "android"),
        target_arch = "x86_64"
    ),
    all(
        any(target_os = "linux", target_os = "android"),
        target_arch = "aarch64"
    ),
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly",
    target_os = "windows",
    all(target_os = "wasi", target_env = "p1"),
)))]
fn fill_inner(_bytes: &mut [u8]) -> Result<(), i32> {
    const ERRNO_UNSUPPORTED_PLATFORM: i32 = -1;
    Err(ERRNO_UNSUPPORTED_PLATFORM)
}

#[cfg(all(
    any(target_os = "linux", target_os = "android"),
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
fn fill_with_getrandom_syscall(bytes: &mut [u8]) -> Result<(), i32> {
    let mut filled = 0;
    let mut retries = 0;
    while filled < bytes.len() {
        let ptr = bytes[filled..].as_mut_ptr() as usize;
        let len = bytes.len() - filled;
        let ret = raw_syscall3(SYS_GETRANDOM, ptr, len, 0);
        if syscall_failed(ret) {
            let errno = (-ret) as i32;
            if errno == EINTR || errno == EAGAIN {
                retries += 1;
                if retries > MAX_GETRANDOM_RETRIES {
                    return Err(errno);
                }
                continue;
            }

            return Err(errno);
        }

        if ret == 0 {
            return Err(ERRNO_NO_PROGRESS);
        }

        filled += ret as usize;
    }

    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn syscall_failed(ret: isize) -> bool {
    (-4095..=-1).contains(&ret)
}

#[cfg(all(
    any(target_os = "linux", target_os = "android"),
    target_arch = "x86_64"
))]
fn raw_syscall3(number: usize, arg1: usize, arg2: usize, arg3: usize) -> isize {
    let ret: isize;

    // SAFETY: Registers follow the Linux x86_64 syscall ABI. The caller
    // supplies the `getrandom` syscall number and pointer/length args.
    unsafe {
        asm!(
            "syscall",
            inlateout("rax") number as isize => ret,
            in("rdi") arg1,
            in("rsi") arg2,
            in("rdx") arg3,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack)
        );
    }

    ret
}

#[cfg(all(
    any(target_os = "linux", target_os = "android"),
    target_arch = "aarch64"
))]
fn raw_syscall3(number: usize, arg1: usize, arg2: usize, arg3: usize) -> isize {
    let ret: isize;

    // SAFETY: Registers follow the Linux aarch64 syscall ABI. The caller
    // supplies the `getrandom` syscall number and pointer/length args.
    unsafe {
        asm!(
            "svc 0",
            inlateout("x0") arg1 as isize => ret,
            in("x1") arg2,
            in("x2") arg3,
            in("x8") number,
            options(nostack)
        );
    }

    ret
}

#[cfg(test)]
mod material_tests {
    use super::{CanaryMaterial, CANARY_SIZE};

    #[test]
    fn canary_material_explicit_clear_wipes_owned_bytes() {
        let mut material = CanaryMaterial([0xA5; CANARY_SIZE]);
        material.clear();
        assert_eq!(material.as_bytes(), &[0; CANARY_SIZE]);
    }
}
