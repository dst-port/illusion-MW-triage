#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "windows")]
pub mod windows;

#[cfg(target_os = "linux")]
pub use linux::*;

#[cfg(target_os = "windows")]
pub use windows::*;

// Allow the re-exports to exist even if unused on some platforms.
#[allow(unused_imports)]

/// Platform-agnostic dump function signature.
use std::path::Path;
use std::io;
use std::path::PathBuf;

pub fn dump_process_platform(pid: u32, out_dir: &Path) -> io::Result<(PathBuf, String)> {
    // delegated to platform-specific module
    platform_dump_process(pid, out_dir)
}

// platform-specific implementations must provide this function.
#[allow(unused_variables)]
fn platform_dump_process(pid: u32, out_dir: &Path) -> io::Result<(PathBuf, String)> {
    Err(io::Error::new(io::ErrorKind::Other, "platform dump not implemented"))
}
