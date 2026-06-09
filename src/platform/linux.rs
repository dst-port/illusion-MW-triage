use std::path::Path;
use std::io;
use std::path::PathBuf;

use crate::dumper::{dump_process};

pub fn platform_dump_process(pid: u32, out_dir: &Path) -> io::Result<(PathBuf, String)> {
    // reuse existing dumper
    match dump_process(pid, out_dir) {
        Ok(dm) => Ok((dm.path, dm.method)),
        Err(e) => Err(e),
    }
}
