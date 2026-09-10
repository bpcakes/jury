//! Identity evidence tied to the current executable's backing file.

use std::io;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

/// Kernel-backed snapshot of the running executable's file identity.
/// A pathname alone cannot construct this value.
///
/// This does not attest immutable file contents, dynamic dependencies, or
/// authority to launch code. The normalized path names the captured file at
/// verification time and may subsequently be renamed or replaced.
pub struct RunningImage {
    path: PathBuf,
    identity: FileIdentity,
}

#[derive(PartialEq, Eq)]
struct FileIdentity {
    device: u64,
    inode: u64,
    mode: u32,
    length: u64,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl From<std::fs::Metadata> for FileIdentity {
    fn from(metadata: std::fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            mode: metadata.mode(),
            length: metadata.len(),
        }
    }
}

impl RunningImage {
    /// Capture the running executable, refusing if the discovered pathname
    /// refers to another file. Path discovery is never identity evidence.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub fn capture() -> io::Result<Self> {
        #[cfg(target_os = "linux")]
        let (candidate, identity) = {
            // O_PATH permits identity capture for execute-only files, too.
            let image = std::fs::File::from(rustix::fs::open(
                "/proc/self/exe",
                rustix::fs::OFlags::PATH | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            )?);
            let identity = FileIdentity::from(image.metadata()?);
            (std::fs::read_link("/proc/self/exe")?, identity)
        };
        #[cfg(target_os = "macos")]
        let (candidate, identity) = {
            // Darwin identifies the main executable header; the kernel query
            // supplies its backing vnode identity and current name.
            let region = libproc_region::main_image_region()?;
            let identity = FileIdentity {
                device: region.device,
                inode: region.inode,
                mode: region.mode,
                length: region.length,
            };
            (region.path, identity)
        };
        let path = std::fs::canonicalize(candidate)?;
        // This only verifies the descriptive path. The independent kernel
        // identity above supplies the evidence even if this name is replaced
        // again. Nothing opens or executes this pathname after capture.
        let metadata = std::fs::metadata(&path)?;
        if !metadata.is_file() || FileIdentity::from(metadata) != identity {
            return Err(invalid_image());
        }
        Ok(Self { path, identity })
    }

    /// Refuse identity capture on unsupported platforms.
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    pub fn capture() -> io::Result<Self> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "running image identity is unsupported",
        ))
    }

    /// Normalized name verified against the captured image.
    pub fn path(&self) -> &Path {
        &self.path
    }
    /// Backing file's device identifier.
    pub fn device(&self) -> u64 {
        self.identity.device
    }
    /// Backing file's inode number.
    pub fn inode(&self) -> u64 {
        self.identity.inode
    }
    /// Backing file's Unix mode, including file type.
    pub fn mode(&self) -> u32 {
        self.identity.mode
    }
    /// Backing file's byte length at capture time.
    pub fn length(&self) -> u64 {
        self.identity.length
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn invalid_image() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "running image identity is unavailable",
    )
}
