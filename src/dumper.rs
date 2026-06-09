use sha2::{Digest, Sha256};
use std::fs;
use std::fs::File;
use std::io::BufRead;
use std::io::BufReader;
use std::io::BufWriter;
use std::io::{self, Read, Seek, SeekFrom, Write};
#[cfg(unix)]
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::process::Command;

#[cfg(unix)]
use nix::sys::ptrace;
#[cfg(unix)]
use nix::sys::wait::{waitpid, WaitStatus};
#[cfg(unix)]
use nix::unistd::Pid;

#[derive(Debug)]
pub struct DumpMetadata {
    pub path: PathBuf,
    pub method: String,
}

pub fn dump_process(pid: u32, out_dir: &Path) -> io::Result<DumpMetadata> {
    #[cfg(target_os = "windows")]
    {
        match crate::platform::dump_process_platform(pid, out_dir) {
            Ok((p, m)) => return Ok(DumpMetadata { path: p, method: m }),
            Err(e) => return Err(e),
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
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
            return Ok(DumpMetadata {
                path: gcore_out,
                method: "gcore".to_string(),
            });
        }

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
            return Ok(DumpMetadata {
                path: gdb_out,
                method: "gdb".to_string(),
            });
        }

        match ptrace_dump(pid, &out_base) {
            Ok(p) => {
                // Attempt to normalize ptrace-style dumps into a canonical JSON
                // with per-region sha256. If normalization succeeds, return the
                // normalized path; otherwise return the raw ptrace dump.
                match normalize_ptrace_core(&p) {
                    Ok(norm) => Ok(DumpMetadata {
                        path: norm,
                        method: "ptrace-normalized".to_string(),
                    }),
                    Err(_) => Ok(DumpMetadata {
                        path: p,
                        method: "ptrace".to_string(),
                    }),
                }
            }
            Err(e) => {
                let ptrace_out = out_base.with_extension("core.ptrace");
                let _f = File::create(&ptrace_out)?;
                Ok(DumpMetadata {
                    path: ptrace_out,
                    method: format!("ptrace-fallback: {}", e),
                })
            }
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

pub fn compare_memory_vs_disk(pid: u32) -> io::Result<MemoryDiskComparison> {
    let mut notes: Vec<String> = Vec::new();
    let exe_link = format!("/proc/{}/exe", pid);
    let exe_path = match fs::read_link(&exe_link) {
        Ok(p) => Some(p),
        Err(e) => {
            notes.push(format!("unable to read exe symlink: {}", e));
            None
        }
    };

    let on_disk_hash = if let Some(ref p) = exe_path {
        match compute_file_sha256(p) {
            Ok(h) => Some(h),
            Err(e) => {
                notes.push(format!("unable to hash on-disk exe: {}", e));
                None
            }
        }
    } else {
        None
    };

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

    Ok(MemoryDiskComparison {
        exe_path,
        on_disk_hash,
        in_memory_hash,
        mismatch,
        notes,
    })
}

fn compute_file_sha256(path: &Path) -> io::Result<String> {
    let mut f = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let digest = hasher.finalize();
    Ok(digest.iter().map(|b| format!("{:02x}", b)).collect())
}

#[cfg(unix)]
fn compute_memory_sha256_for_exe(
    pid: u32,
    exe_path_opt: Option<&PathBuf>,
) -> io::Result<Option<String>> {
    let maps_path = format!("/proc/{}/maps", pid);
    let maps = fs::read_to_string(&maps_path)?;
    let mem_path = format!("/proc/{}/mem", pid);
    let mut mem_file = File::open(&mem_path)?;

    let exe_basename =
        exe_path_opt.and_then(|p| p.file_name().map(|s| s.to_string_lossy().to_string()));

    let mut hasher = Sha256::new();
    let mut found_any = false;

    for line in maps.lines() {
        let tokens: Vec<&str> = line.split_whitespace().collect();
        if tokens.len() < 2 {
            continue;
        }
        let range = tokens[0];
        let perms = tokens[1];
        if !perms.starts_with('r') {
            continue;
        }

        let pathname_opt = tokens.get(5).map(|s| s.to_string());
        let mut pathname_clean: Option<String> = None;
        if let Some(p) = pathname_opt {
            let p = p.trim_end_matches(" (deleted)");
            pathname_clean = Some(p.to_string());
        }

        let is_exe_region = match (&exe_path_opt, &pathname_clean, &exe_basename) {
            (Some(exe_path), Some(map_p), Some(bn)) => {
                let map_path = Path::new(map_p);
                map_path == exe_path.as_path() || map_p.ends_with(bn)
            }
            (None, Some(map_p), Some(bn)) => map_p.ends_with(bn),
            _ => false,
        };

        if !is_exe_region {
            continue;
        }

        let mut se = range.split('-');
        let start = u64::from_str_radix(se.next().unwrap_or("0"), 16).unwrap_or(0);
        let end = u64::from_str_radix(se.next().unwrap_or("0"), 16).unwrap_or(0);
        if end <= start {
            continue;
        }

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

#[cfg(target_os = "windows")]
fn compute_memory_sha256_for_exe(
    pid: u32,
    exe_path_opt: Option<&PathBuf>,
) -> io::Result<Option<String>> {
    use std::ffi::c_void;
    use std::mem::zeroed;
    use std::ptr::null_mut;
    use std::os::windows::ffi::OsStringExt;
    use std::ffi::OsString;

    #[repr(C)]
    struct MODULEENTRY32W {
        dwSize: u32,
        th32ModuleID: u32,
        th32ProcessID: u32,
        GlblcntUsage: u32,
        ProccntUsage: u32,
        modBaseAddr: *mut c_void,
        modBaseSize: u32,
        hModule: *mut c_void,
        szModule: [u16; 256],
        szExePath: [u16; 260],
    }

    extern "system" {
        fn CreateToolhelp32Snapshot(dwFlags: u32, th32ProcessID: u32) -> *mut c_void;
        fn Module32FirstW(hSnapshot: *mut c_void, lpme: *mut MODULEENTRY32W) -> i32;
        fn Module32NextW(hSnapshot: *mut c_void, lpme: *mut MODULEENTRY32W) -> i32;
        fn CloseHandle(hObject: *mut c_void) -> i32;
        fn OpenProcess(dwDesiredAccess: u32, bInheritHandle: i32, dwProcessId: u32) -> *mut c_void;
        fn ReadProcessMemory(hProcess: *mut c_void, lpBaseAddress: *const c_void, lpBuffer: *mut c_void, nSize: usize, lpNumberOfBytesRead: *mut usize) -> i32;
    }

    const TH32CS_SNAPMODULE: u32 = 0x00000008;
    const TH32CS_SNAPMODULE32: u32 = 0x00000010;
    const PROCESS_QUERY_INFORMATION: u32 = 0x0400;
    const PROCESS_VM_READ: u32 = 0x0010;

    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
        if snapshot.is_null() {
            return Ok(None);
        }
        let mut me: MODULEENTRY32W = zeroed();
        me.dwSize = std::mem::size_of::<MODULEENTRY32W>() as u32;
        if Module32FirstW(snapshot, &mut me) == 0 {
            CloseHandle(snapshot);
            return Ok(None);
        }

        let mut target_base: usize = 0;
        let mut target_size: usize = 0;

        loop {
            let len = me.szExePath.iter().position(|&c| c == 0).unwrap_or(me.szExePath.len());
            let os = OsString::from_wide(&me.szExePath[..len]);
            let path = PathBuf::from(os);
            let matches = if let Some(exe_path) = exe_path_opt {
                let bn = exe_path.file_name().and_then(|s| s.to_str()).unwrap_or("");
                path.file_name().and_then(|s| s.to_str()).map(|n| n == bn).unwrap_or(false)
            } else {
                // If no exe path given, assume the first module is the main exe
                true
            };

            if matches {
                target_base = me.modBaseAddr as usize;
                target_size = me.modBaseSize as usize;
                break;
            }

            if Module32NextW(snapshot, &mut me) == 0 {
                break;
            }
        }

        CloseHandle(snapshot);
        if target_base == 0 || target_size == 0 {
            return Ok(None);
        }

        let hproc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, pid);
        if hproc.is_null() {
            return Ok(None);
        }

        let mut hasher = Sha256::new();
        let mut total_read: usize = 0;
        let mut buf = vec![0u8; 64 * 1024];
        while total_read < target_size {
            let to_read = std::cmp::min(buf.len(), target_size - total_read);
            let mut bytes_read: usize = 0;
            let ok = ReadProcessMemory(hproc, (target_base + total_read) as *const c_void, buf.as_mut_ptr() as *mut c_void, to_read, &mut bytes_read as *mut usize);
            if ok == 0 || bytes_read == 0 {
                break;
            }
            hasher.update(&buf[..bytes_read]);
            total_read += bytes_read;
        }

        CloseHandle(hproc);
        if total_read == 0 {
            return Ok(None);
        }
        let digest = hasher.finalize();
        Ok(Some(digest.iter().map(|b| format!("{:02x}", b)).collect()))
    }
}

#[cfg(unix)]
fn ptrace_dump(pid: u32, out_base: &Path) -> io::Result<PathBuf> {
    const MAX_DUMP_BYTES: u64 = 100 * 1024 * 1024;

    let out_path = out_base.with_extension("core.ptrace");
    let mut out = BufWriter::new(File::create(&out_path)?);

    let target = Pid::from_raw(pid as i32);
    let mut attached = false;

    if ptrace::attach(target).is_ok() {
        attached = true;
        match waitpid(target, None) {
            Ok(WaitStatus::Stopped(_, _))
            | Ok(WaitStatus::PtraceEvent(_, _, _))
            | Ok(WaitStatus::PtraceSyscall(_)) => {}
            _ => {}
        }
    }

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

        writeln!(
            out,
            "REGION {:#x}-{:#x} {}",
            start,
            start + region_size,
            perms
        )?;

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

    if attached {
        let _ = ptrace::detach(target, None);
    }

    Ok(out_path)
}

#[cfg(not(unix))]
fn ptrace_dump(_pid: u32, _out_base: &Path) -> io::Result<PathBuf> {
    Err(io::Error::new(
        io::ErrorKind::Other,
        "ptrace dump not supported on this platform",
    ))
}

pub fn normalize_ptrace_core(core_path: &Path) -> io::Result<PathBuf> {
    use serde::Serialize;
    use std::fs::OpenOptions;

    #[derive(Serialize)]
    struct RegionInfo {
        start: u64,
        end: u64,
        perms: String,
        sha256: String,
    }

    let f = OpenOptions::new().read(true).open(core_path)?;
    let mut reader = BufReader::new(f);
    let mut regions: Vec<RegionInfo> = Vec::new();

    loop {
        let mut header = String::new();
        let n = reader.read_line(&mut header)?;
        if n == 0 {
            break;
        }
        let header = header.trim_end();
        if header.is_empty() {
            continue;
        }
        if !header.starts_with("REGION ") {
            // Unexpected line; skip
            continue;
        }
        let parts: Vec<&str> = header.split_whitespace().collect();
        if parts.len() < 3 {
            continue;
        }
        let range = parts[1];
        let perms = parts[2].to_string();
        let mut se = range.split('-');
        let start_s = se.next().unwrap_or("0");
        let end_s = se.next().unwrap_or("0");
        let start = if let Some(stripped) = start_s.strip_prefix("0x") {
            u64::from_str_radix(stripped, 16).unwrap_or(0)
        } else {
            u64::from_str_radix(start_s, 16).unwrap_or(0)
        };
        let end = if let Some(stripped) = end_s.strip_prefix("0x") {
            u64::from_str_radix(stripped, 16).unwrap_or(0)
        } else {
            u64::from_str_radix(end_s, 16).unwrap_or(0)
        };
        if end <= start {
            continue;
        }
        let mut remaining = end - start;
        let mut hasher = Sha256::new();
        let mut buf = [0u8; 64 * 1024];
        while remaining > 0 {
            let to_read = std::cmp::min(buf.len() as u64, remaining) as usize;
            let read_n = reader.read(&mut buf[..to_read])?;
            if read_n == 0 {
                break;
            }
            hasher.update(&buf[..read_n]);
            remaining -= read_n as u64;
        }
        let digest = hasher.finalize();
        let sha = digest.iter().map(|b| format!("{:02x}", b)).collect();
        regions.push(RegionInfo {
            start,
            end,
            perms,
            sha256: sha,
        });
    }

    // Write normalized JSON next to the core file
    let out_path = core_path.with_extension("core.normalized.json");
    let j = serde_json::to_string_pretty(&regions)?;
    std::fs::write(&out_path, j.as_bytes())?;
    Ok(out_path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::tempdir;

    #[test]
    fn test_normalize_ptrace_core() {
        let td = tempdir().unwrap();
        let core_path = td.path().join("core.test.ptrace");
        let mut f = File::create(&core_path).unwrap();
        // write a single region header and 16 bytes of data
        writeln!(f, "REGION 0x1000-0x1010 rw- ").unwrap();
        let data: Vec<u8> = (0u8..16u8).collect();
        f.write_all(&data).unwrap();
        f.flush().unwrap();

        let norm = normalize_ptrace_core(&core_path).unwrap();
        let s = std::fs::read_to_string(&norm).unwrap();
        assert!(s.contains("start"));
        assert!(s.contains("sha256"));
    }
}
