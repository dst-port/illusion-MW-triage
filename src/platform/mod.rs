#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "windows")]
pub mod windows;

#[cfg(target_os = "linux")]
#[allow(unused_imports)]
pub use linux::*;

#[cfg(target_os = "windows")]
#[allow(unused_imports)]
pub use windows::*;

use std::io;
#[allow(unused_imports)]
use std::path::Path;
use std::path::PathBuf;

pub fn dump_process_platform(pid: u32, out_dir: &Path) -> io::Result<(PathBuf, String)> {
    platform_dump_process(pid, out_dir)
}

#[allow(unused_variables)]
fn platform_dump_process(pid: u32, out_dir: &Path) -> io::Result<(PathBuf, String)> {
    Err(io::Error::other("platform dump not implemented"))
}
