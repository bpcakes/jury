//! Owned metadata for the vnode backing a Darwin process memory region.

#![cfg(target_os = "macos")]
#![deny(unsafe_op_in_unsafe_fn)]

#[allow(warnings)]
mod bindings {
    include!(concat!(env!("OUT_DIR"), "/osx_libproc_bindings.rs"));
}

use std::convert::TryFrom;
use std::ffi::OsString;
use std::io;
use std::mem::{MaybeUninit, size_of};
use std::os::unix::ffi::OsStringExt;
use std::path::PathBuf;

use bindings::{PROC_PIDREGIONPATHINFO, proc_pidinfo, proc_regionwithpathinfo};

/// Kernel snapshot of a file-backed memory region. The path may be renamed
/// immediately after the query; the metadata belongs to the mapped vnode.
#[derive(Debug)]
pub struct RegionInfo {
    /// Region start address.
    pub address: u64,
    /// Region size in bytes.
    pub size: u64,
    /// Current Mach VM protection flags (execute is bit 2).
    pub protection: u32,
    /// Kernel pathname of the backing vnode, without UTF-8 conversion.
    pub path: PathBuf,
    /// Backing vnode device identifier, widened like Darwin MetadataExt::dev.
    pub device: u64,
    /// Backing vnode inode number.
    pub inode: u64,
    /// Backing vnode mode, including file type.
    pub mode: u32,
    /// Backing vnode file length in bytes.
    pub length: u64,
}

/// Query the vnode backing the current process's main executable header.
///
/// Darwin supplies the main header independently of image ordering or where
/// this provider is linked. Its address is never dereferenced. The header need
/// not occupy executable memory; the loader identifies it as the main image.
///
/// # Errors
/// Returns an error for a missing header, an invalid region response, or a
/// region that does not contain the main header.
pub fn main_image_region() -> io::Result<RegionInfo> {
    // SAFETY: this Darwin accessor takes no arguments and returns the main
    // executable header. We only use its address as a kernel query key.
    let header = unsafe { bindings::_NSGetMachExecuteHeader() };
    if header.is_null() {
        return Err(invalid_response());
    }
    let address = header as u64;
    let region = self_region_info(address)?;
    if address < region.address || address - region.address >= region.size {
        return Err(invalid_response());
    }
    Ok(region)
}

/// Query the region containing or following `address` in the current process.
///
/// The address is an integer query key, never dereferenced. Callers requiring
/// the containing region must check its returned address and size. The kernel
/// retains the mapped vnode while filling metadata; no pathname is reopened.
///
/// # Errors
/// Returns an error for a failed/short query, absent backing file, negative
/// file length, or empty/non-terminated path. Kernel access restrictions apply.
fn self_region_info(address: u64) -> io::Result<RegionInfo> {
    let pid = i32::try_from(std::process::id()).map_err(|_| invalid_response())?;
    let mut raw = MaybeUninit::<proc_regionwithpathinfo>::zeroed();
    let size =
        i32::try_from(size_of::<proc_regionwithpathinfo>()).map_err(|_| invalid_response())?;
    // SAFETY: raw is writable, correctly aligned storage of the SDK-generated
    // ABI type, with its exact size. The address is passed as a scalar and is
    // not dereferenced by this function. No pointers escape the syscall.
    let count = unsafe {
        proc_pidinfo(
            pid,
            PROC_PIDREGIONPATHINFO as i32,
            address,
            raw.as_mut_ptr().cast(),
            size,
        )
    };
    check_response_size(count, size)?;
    // SAFETY: the successful exact-size response initialized this C struct,
    // which contains only integer fields and fixed arrays of integers.
    decode_region(unsafe { raw.assume_init() })
}

fn check_response_size(count: i32, size: i32) -> io::Result<()> {
    // proc_pidinfo maps syscall -1 to zero while preserving errno. This
    // particular flavor returns exactly the structure size on success.
    if count <= 0 {
        return Err(io::Error::last_os_error());
    }
    if count != size {
        return Err(invalid_response());
    }
    Ok(())
}

fn decode_region(raw: proc_regionwithpathinfo) -> io::Result<RegionInfo> {
    let stat = raw.prp_vip.vip_vi.vi_stat;
    let bytes: Vec<u8> = raw
        .prp_vip
        .vip_path
        .iter()
        .map(|byte| *byte as u8)
        .collect();
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .ok_or_else(invalid_response)?;
    if end == 0 || stat.vst_ino == 0 {
        return Err(invalid_response());
    }
    let path = PathBuf::from(OsString::from_vec(bytes[..end].to_vec()));
    if !path.is_absolute() {
        return Err(invalid_response());
    }
    Ok(RegionInfo {
        address: raw.prp_prinfo.pri_address,
        size: raw.prp_prinfo.pri_size,
        protection: raw.prp_prinfo.pri_protection,
        path,
        // Darwin stat uses signed dev_t; match Rust MetadataExt::dev exactly.
        device: stat.vst_dev as i32 as u64,
        inode: stat.vst_ino,
        mode: u32::from(stat.vst_mode),
        length: u64::try_from(stat.vst_size).map_err(|_| invalid_response())?,
    })
}

fn invalid_response() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid region-vnode response")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;

    #[test]
    fn executing_code_has_native_vnode_metadata() -> io::Result<()> {
        let address = executing_code_has_native_vnode_metadata as *const () as u64;
        let region = self_region_info(address)?;
        assert!(region.address <= address && address - region.address < region.size);
        assert_ne!(region.protection & 4, 0);
        let metadata = std::fs::metadata(&region.path)?;
        assert_eq!(region.device, metadata.dev());
        assert_eq!(region.inode, metadata.ino());
        assert_eq!(region.mode, metadata.mode());
        assert_eq!(region.length, metadata.len());
        Ok(())
    }

    #[test]
    fn main_image_has_executable_vnode_metadata() -> io::Result<()> {
        let region = main_image_region()?;
        let metadata = std::fs::metadata(std::env::current_exe()?)?;
        assert_eq!(region.device, metadata.dev());
        assert_eq!(region.inode, metadata.ino());
        assert_eq!(region.mode, metadata.mode());
        assert_eq!(region.length, metadata.len());
        Ok(())
    }

    #[test]
    fn unmapped_address_is_an_error() {
        let error = self_region_info(u64::MAX).expect_err("unmapped query succeeded");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn rejects_incomplete_and_oversized_responses() {
        let size = size_of::<proc_regionwithpathinfo>() as i32;
        for count in [-1, 0, size - 1, size + 1] {
            assert!(check_response_size(count, size).is_err());
        }
        assert!(check_response_size(size, size).is_ok());
    }

    #[test]
    fn high_bit_device_matches_darwin_stat_widening() {
        // Synthetic ABI input, not a claim to have mounted such a device.
        // SAFETY: the ABI struct consists solely of integers and arrays.
        let mut raw: proc_regionwithpathinfo = unsafe { MaybeUninit::zeroed().assume_init() };
        raw.prp_vip.vip_path[0] = b'/' as _;
        raw.prp_vip.vip_vi.vi_stat.vst_ino = 1;
        raw.prp_vip.vip_vi.vi_stat.vst_dev = 0x8000_0001;
        assert_eq!(decode_region(raw).unwrap().device, 0xffff_ffff_8000_0001);
    }

    #[test]
    fn rejects_malformed_region_metadata() {
        // Synthetic decoder cases, separate from the live vnode test above.
        let sample = || {
            // SAFETY: this ABI struct consists solely of integers and arrays.
            let mut raw: proc_regionwithpathinfo = unsafe { MaybeUninit::zeroed().assume_init() };
            raw.prp_vip.vip_path[0] = b'/' as _;
            raw.prp_vip.vip_vi.vi_stat.vst_ino = 1;
            raw
        };
        assert!(decode_region(sample()).is_ok());
        let mut raw = sample();
        raw.prp_vip.vip_path[0] = b'.' as _;
        assert!(decode_region(raw).is_err());
        let mut raw = sample();
        raw.prp_vip.vip_path.fill(1);
        assert!(decode_region(raw).is_err());
        let mut raw = sample();
        raw.prp_vip.vip_path[0] = 0;
        assert!(decode_region(raw).is_err());
        let mut raw = sample();
        raw.prp_vip.vip_vi.vi_stat.vst_ino = 0;
        assert!(decode_region(raw).is_err());
        let mut raw = sample();
        raw.prp_vip.vip_vi.vi_stat.vst_size = -1;
        assert!(decode_region(raw).is_err());
    }
}
