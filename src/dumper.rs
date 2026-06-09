use std::path::{Path, PathBuf};
use std::process::Command;
use std::io::{self, Read, Write, Seek, SeekFrom};
use std::fs::File;
use std::os::unix::io::AsRawFd;
use std::io::BufWriter;
use sha2::{Sha256, Digest};
use std::fs;

use nix::sys::ptrace;
use nix::unistd::Pid;
use nix::sys::wait::{waitpid, WaitStatus};

#[derive(Debug)]
pub struct DumpMetadata {
    pub path: PathBuf,
    pub method: String,
}

pub fn dump_process(pid: u32, out_dir: &Path) -> io::Result<DumpMetadata> {
    // On Windows, delegate to platform-specific dumper when compiled there.
    #[cfg(target_os = "windows")]
    {
        match crate::platform::dump_process_platform(pid, out_dir) {
            Ok((p, m)) => return Ok(DumpMetadata { path: p, method: m }),
            Err(e) => return Err(e),
        }
    }
    // try gcore
    let out_base = out_dir.join(format!("core.{}", pid));
    let gcore_out = out_base.with_extension("core");
    if Command::new("gcore")
        .arg("-o")
        .arg(&out_base)
        .arg(pid.to_string())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
    {
        return Ok(DumpMetadata { path: gcore_out, method: "gcore".to_string() });
    }

    // try gdb
    let gdb_out = out_base.with_extension("core.gdb");
    if Command::new("gdb")
        .arg("--batch")
        .arg("--pid")
        .arg(pid.to_string())
        .arg("-ex")
        .arg(format!("gcore {}", gdb_out.display()))
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
    {
        return Ok(DumpMetadata { path: gdb_out, method: "gdb".to_string() });
    }

    // attempt ptrace-based dump
    match ptrace_dump(pid, &out_base) {
        Ok(p) => Ok(DumpMetadata { path: p, method: "ptrace".to_string() }),
        Err(e) => {
            // fallback: create a placeholder file to indicate that ptrace path failed
            let ptrace_out = out_base.with_extension("core.ptrace");
            let _f = File::create(&ptrace_out)?;
            Ok(DumpMetadata { path: ptrace_out, method: format!("ptrace-fallback: {}", e) })
        }
    }
}

#[derive(Debug)]
pub struct MemoryDiskComparison {
    pub exe_path: Option<PathBuf>,
    pub on_disk_hash: Option<String>,
    pub in_memory_hash: Option<String>,
    pub mismatch: bool,
    pub notes: Vec<String>,
}

/// Compare the SHA256 of the on-disk executable (if accessible) with the
/// SHA256 computed from the process's mapped executable regions in memory.
/// Returns `MemoryDiskComparison` with details and notes about failures.
pub fn compare_memory_vs_disk(pid: u32) -> io::Result<MemoryDiskComparison> {
    let mut notes: Vec<String> = Vec::new();
    // resolve /proc/<pid>/exe
    let exe_link = format!("/proc/{}/exe", pid);
    let exe_path = match fs::read_link(&exe_link) {
        Ok(p) => Some(p),
        Err(e) => {
            notes.push(format!("unable to read exe symlink: {}", e));
            None
        }
    };

    // compute on-disk hash if we have a path
    let on_disk_hash = if let Some(ref p) = exe_path {
        match compute_file_sha256(p) {
            Ok(h) => Some(h),
            Err(e) => {
                notes.push(format!("unable to hash on-disk exe: {}", e));
                None
            }
        }
    } else { None };

    // compute in-memory hash for regions that appear to belong to the exe
    let in_memory_hash = match compute_memory_sha256_for_exe(pid, exe_path.as_ref()) {
        Ok(h) => h,
        Err(e) => {
            notes.push(format!("unable to hash in-memory regions: {}", e));
            None
        }
    };

    let mismatch = match (&on_disk_hash, &in_memory_hash) {
        (Some(d), Some(m)) => d != m,
        _ => false,
    };

    Ok(MemoryDiskComparison { exe_path, on_disk_hash, in_memory_hash, mismatch, notes })
}

fn compute_file_sha256(path: &Path) -> io::Result<String> {
    let mut f = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 { break; }
        hasher.update(&buf[..n]);
    }
    let digest = hasher.finalize();
    Ok(digest.iter().map(|b| format!("{:02x}", b)).collect())
}

fn compute_memory_sha256_for_exe(pid: u32, exe_path_opt: Option<&PathBuf>) -> io::Result<Option<String>> {
    // open maps and mem
    let maps_path = format!("/proc/{}/maps", pid);
    let maps = fs::read_to_string(&maps_path)?;
    let mem_path = format!("/proc/{}/mem", pid);
    let mut mem_file = File::open(&mem_path)?;

    let exe_basename = exe_path_opt.and_then(|p| p.file_name().map(|s| s.to_string_lossy().to_string()));

    let mut hasher = Sha256::new();
    let mut found_any = false;

    for line in maps.lines() {
        // tokens: range perms offset dev inode [pathname]
        let tokens: Vec<&str> = line.split_whitespace().collect();
        if tokens.len() < 2 { continue; }
        let range = tokens[0];
        let perms = tokens[1];
        if !perms.starts_with('r') { continue; }

        let pathname_opt = tokens.get(5).map(|s| s.to_string());
        let mut pathname_clean: Option<String> = None;
        if let Some(p) = pathname_opt {
            // strip " (deleted)" suffix which appears in some /proc maps
            let p = p.trim_end_matches(" (deleted)");
            pathname_clean = Some(p.to_string());
        }

        let is_exe_region = match (&exe_path_opt, &pathname_clean, &exe_basename) {
            (Some(exe_path), Some(map_p), Some(bn)) => {
                // exact path match, or basename match
                let map_path = Path::new(map_p);
                if map_path == exe_path.as_path() { true }
                else if map_p.ends_with(bn) { true }
                else { false }
            }
            // if we don't have an exe_path, fall back to matching basename only
            (None, Some(map_p), Some(bn)) => map_p.ends_with(bn),
            _ => false,
        };

        if !is_exe_region {
            continue;
        }

        // parse range
        let mut se = range.split('-');
        let start = u64::from_str_radix(se.next().unwrap_or("0"), 16).unwrap_or(0);
        let end = u64::from_str_radix(se.next().unwrap_or("0"), 16).unwrap_or(0);
        if end <= start { continue; }

        let mut remaining = end - start;
        let mut offset = start;
        let mut buf = vec![0u8; 64 * 1024];
        while remaining > 0 {
            let to_read = std::cmp::min(buf.len() as u64, remaining) as usize;
            if mem_file.seek(SeekFrom::Start(offset)).is_err() {
                break;
            }
            let n = match mem_file.read(&mut buf[..to_read]) {
                Ok(0) => break,
                Ok(n) => n,
                Err(_) => break,
            };
            hasher.update(&buf[..n]);
            remaining -= n as u64;
            offset += n as u64;
            found_any = true;
        }
    }

    if !found_any {
        return Ok(None);
    }
    let digest = hasher.finalize();
    Ok(Some(digest.iter().map(|b| format!("{:02x}", b)).collect()))
}

fn ptrace_dump(pid: u32, out_base: &Path) -> io::Result<PathBuf> {
    // conservative limit to avoid blowing disk
    const MAX_DUMP_BYTES: u64 = 100 * 1024 * 1024; // 100 MiB

    let out_path = out_base.with_extension("core.ptrace");
    let mut out = BufWriter::new(File::create(&out_path)?);

    let target = Pid::from_raw(pid as i32);
    let mut attached = false;

    // Try to attach; if we can't, we'll still attempt to read /proc/<pid>/mem
    if ptrace::attach(target).is_ok() {
        attached = true;
        // Wait for the tracee to stop
        match waitpid(target, None) {
            Ok(WaitStatus::Stopped(_, _)) | Ok(WaitStatus::PtraceEvent(_, _, _)) | Ok(WaitStatus::PtraceSyscall(_)) => {}
            _ => {}
        }
    }

    // Read /proc/<pid>/maps to find readable regions
    let maps_path = format!("/proc/{}/maps", pid);
    let maps = std::fs::read_to_string(&maps_path)?;
    let mem_path = format!("/proc/{}/mem", pid);
    let mut mem_file = File::open(&mem_path)?;
    let _mem_fd = mem_file.as_raw_fd();

    let mut total_read: u64 = 0;
    for line in maps.lines() {
        if total_read >= MAX_DUMP_BYTES {
            break;
        }
        // Format: address perms offset dev inode pathname
        let mut parts = line.split_whitespace();
        let range = match parts.next() {
            Some(r) => r,
            None => continue,
        };
        let perms = parts.next().unwrap_or("");
        if !perms.starts_with('r') {
            continue;
        }
        let mut se = range.split('-');
        let start = u64::from_str_radix(se.next().unwrap_or("0"), 16).unwrap_or(0);
        let end = u64::from_str_radix(se.next().unwrap_or("0"), 16).unwrap_or(0);
        if end <= start {
            continue;
        }
        let mut region_size = end - start;
        if region_size == 0 {
            continue;
        }
        if region_size > (MAX_DUMP_BYTES - total_read) {
            region_size = MAX_DUMP_BYTES - total_read;
        }

        // write a simple header for this region
        writeln!(out, "REGION {:#x}-{:#x} {}", start, start + region_size, perms)?;

        // read region in chunks using seek+read on /proc/<pid>/mem
        let mut remaining = region_size;
        let mut offset = start;
        let mut buf = vec![0u8; 64 * 1024];
        while remaining > 0 {
            let to_read = std::cmp::min(buf.len() as u64, remaining) as usize;
            if mem_file.seek(SeekFrom::Start(offset)).is_err() {
                break;
            }
            let n = match mem_file.read(&mut buf[..to_read]) {
                Ok(0) => break,
                Ok(n) => n,
                Err(_) => break,
            };
            out.write_all(&buf[..n])?;
            remaining -= n as u64;
            total_read += n as u64;
            offset += n as u64;
            if total_read >= MAX_DUMP_BYTES {
                break;
            }
        }
        out.flush()?;
    }

    // Detach if we attached
    if attached {
        let _ = ptrace::detach(target, None);
    }

    Ok(out_path)
}
