use std::io;
use std::path::Path;
use std::path::PathBuf;
#[cfg(not(target_os = "windows"))]
pub fn platform_dump_process(_pid: u32, _out_dir: &Path) -> io::Result<(PathBuf, String)> {
    Err(io::Error::new(
        io::ErrorKind::Other,
        "Windows backend not implemented on this platform",
    ))
}

#[cfg(target_os = "windows")]
pub fn platform_dump_process(pid: u32, out_dir: &Path) -> io::Result<(PathBuf, String)> {
    use std::ffi::c_void;
    use std::io::Error;
    use std::mem::{size_of, zeroed};
    use std::ptr::null_mut;

    use std::os::windows::ffi::OsStrExt;

    use std::fs::File;
    use std::io::{BufWriter, Write};

    const PROCESS_QUERY_INFORMATION: u32 = 0x0400;
    const PROCESS_VM_READ: u32 = 0x0010;
    const GENERIC_WRITE: u32 = 0x4000_0000;
    const CREATE_ALWAYS: u32 = 2;
    const FILE_SHARE_READ: u32 = 0x0000_0001;
    const FILE_SHARE_WRITE: u32 = 0x0000_0002;
    const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
    const MINIDUMP_TYPE_NORMAL: u32 = 0x0000_0000;

    const MEM_COMMIT: u32 = 0x1000;
    const PAGE_NOACCESS: u32 = 0x01;
    const PAGE_READONLY: u32 = 0x02;
    const PAGE_READWRITE: u32 = 0x04;
    const PAGE_WRITECOPY: u32 = 0x08;
    const PAGE_EXECUTE: u32 = 0x10;
    const PAGE_EXECUTE_READ: u32 = 0x20;
    const PAGE_EXECUTE_READWRITE: u32 = 0x40;

    extern "system" {
        fn OpenProcess(dwDesiredAccess: u32, bInheritHandle: i32, dwProcessId: u32) -> *mut c_void;
        fn CloseHandle(hObject: *mut c_void) -> i32;
        fn CreateFileW(
            lpFileName: *const u16,
            dwDesiredAccess: u32,
            dwShareMode: u32,
            lpSecurityAttributes: *mut c_void,
            dwCreationDisposition: u32,
            dwFlagsAndAttributes: u32,
            hTemplateFile: *mut c_void,
        ) -> *mut c_void;
        fn MiniDumpWriteDump(
            hProcess: *mut c_void,
            ProcessId: u32,
            hFile: *mut c_void,
            DumpType: u32,
            ExceptionParam: *mut c_void,
            UserStreamParam: *mut c_void,
            CallbackParam: *mut c_void,
        ) -> i32;

        fn VirtualQueryEx(
            hProcess: *mut c_void,
            lpAddress: *const c_void,
            lpBuffer: *mut MEMORY_BASIC_INFORMATION,
            dwLength: usize,
        ) -> usize;

        fn ReadProcessMemory(
            hProcess: *mut c_void,
            lpBaseAddress: *const c_void,
            lpBuffer: *mut c_void,
            nSize: usize,
            lpNumberOfBytesRead: *mut usize,
        ) -> i32;
    }

    #[repr(C)]
    struct MEMORY_BASIC_INFORMATION {
        BaseAddress: *mut c_void,
        AllocationBase: *mut c_void,
        AllocationProtect: u32,
        RegionSize: usize,
        State: u32,
        Protect: u32,
        Type: u32,
    }

    // First try a normal minidump (closest to gcore behaviour)
    let out_minidump = out_dir.join(format!("proc-{}.dmp", pid));
    let wide: Vec<u16> = out_minidump
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect();

    let hfile = unsafe {
        CreateFileW(
            wide.as_ptr(),
            GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            null_mut(),
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            null_mut(),
        )
    };
    if !hfile.is_null() {
        let hproc = unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, pid) };
        if !hproc.is_null() {
            let ok = unsafe {
                MiniDumpWriteDump(
                    hproc,
                    pid,
                    hfile,
                    MINIDUMP_TYPE_NORMAL,
                    null_mut(),
                    null_mut(),
                    null_mut(),
                )
            };
            unsafe {
                CloseHandle(hproc);
            }
            unsafe {
                CloseHandle(hfile);
            }
            if ok != 0 {
                return Ok((out_minidump, "minidump".to_string()));
            }
        } else {
            unsafe {
                CloseHandle(hfile);
            }
        }
    }

    // Fall back to a Linux-style memory-region dump using VirtualQueryEx + ReadProcessMemory
    let out_base = out_dir.join(format!("core.{}", pid));
    let out_path = out_base.with_extension("core.ptrace");
    let f = File::create(&out_path)?;
    let mut out = BufWriter::new(f);

    let hproc = unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, pid) };
    if hproc.is_null() {
        return Err(Error::last_os_error());
    }

    const MAX_DUMP_BYTES: usize = 100 * 1024 * 1024;
    let mut total_read: usize = 0;

    let mut addr: usize = 0;
    let max_addr: usize = if cfg!(target_pointer_width = "64") {
        0x7fff_ffff_ffffusize
    } else {
        0xffff_ffffusize
    };

    while addr < max_addr && total_read < MAX_DUMP_BYTES {
        let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { zeroed() };
        let res = unsafe {
            VirtualQueryEx(
                hproc,
                addr as *const c_void,
                &mut mbi,
                size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        };
        if res == 0 {
            break;
        }
        let start = mbi.BaseAddress as usize;
        let region_size = mbi.RegionSize as usize;
        if region_size == 0 {
            addr = addr.saturating_add(0x1000);
            continue;
        }

        // Determine a simple perms string (rwx-like)
        let mut perms = String::new();
        let prot = mbi.Protect;
        let readable = (prot & PAGE_READONLY != 0)
            || (prot & PAGE_READWRITE != 0)
            || (prot & PAGE_WRITECOPY != 0)
            || (prot & PAGE_EXECUTE_READ != 0)
            || (prot & PAGE_EXECUTE_READWRITE != 0);
        let writable = (prot & PAGE_READWRITE != 0)
            || (prot & PAGE_WRITECOPY != 0)
            || (prot & PAGE_EXECUTE_READWRITE != 0);
        let exec = (prot & PAGE_EXECUTE != 0)
            || (prot & PAGE_EXECUTE_READ != 0)
            || (prot & PAGE_EXECUTE_READWRITE != 0);
        perms.push(if readable { 'r' } else { '-' });
        perms.push(if writable { 'w' } else { '-' });
        perms.push(if exec { 'x' } else { '-' });

        if readable {
            let mut remaining = region_size;
            let mut offset = start;
            writeln!(
                out,
                "REGION {:#x}-{:#x} {}",
                start,
                start + region_size,
                perms
            )?;
            let mut buf = vec![0u8; 64 * 1024];
            while remaining > 0 && total_read < MAX_DUMP_BYTES {
                let to_read = std::cmp::min(buf.len(), remaining);
                let mut bytes_read: usize = 0;
                let ok = unsafe {
                    ReadProcessMemory(
                        hproc,
                        offset as *const c_void,
                        buf.as_mut_ptr() as *mut c_void,
                        to_read,
                        &mut bytes_read as *mut usize,
                    )
                };
                if ok == 0 || bytes_read == 0 {
                    break;
                }
                out.write_all(&buf[..bytes_read])?;
                remaining -= bytes_read;
                total_read += bytes_read;
                offset += bytes_read;
            }
            out.flush()?;
        }

        addr = start.saturating_add(region_size);
    }

    unsafe {
        CloseHandle(hproc);
    }

    Ok((out_path, "ptrace".to_string()))
}
