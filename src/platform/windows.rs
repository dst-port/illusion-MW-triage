use std::path::Path;
use std::io;
use std::path::PathBuf;

// Windows backend: attempt to create a minidump using MiniDumpWriteDump when built
// for Windows. On non-Windows targets this returns an error.

#[cfg(not(target_os = "windows"))]
pub fn platform_dump_process(_pid: u32, _out_dir: &Path) -> io::Result<(PathBuf, String)> {
    Err(io::Error::new(io::ErrorKind::Other, "Windows backend not implemented on this platform"))
}

#[cfg(target_os = "windows")]
pub fn platform_dump_process(pid: u32, out_dir: &Path) -> io::Result<(PathBuf, String)> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use std::ptr::null_mut;
    use std::io::Error;
    use std::ffi::c_void;

    const PROCESS_QUERY_INFORMATION: u32 = 0x0400;
    const PROCESS_VM_READ: u32 = 0x0010;
    const GENERIC_WRITE: u32 = 0x4000_0000;
    const CREATE_ALWAYS: u32 = 2;
    const FILE_SHARE_READ: u32 = 0x0000_0001;
    const FILE_SHARE_WRITE: u32 = 0x0000_0002;
    const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
    const MINIDUMP_TYPE_NORMAL: u32 = 0x0000_0000; // MiniDumpNormal

    extern "system" {
        fn OpenProcess(dwDesiredAccess: u32, bInheritHandle: i32, dwProcessId: u32) -> *mut c_void;
        fn CloseHandle(hObject: *mut c_void) -> i32;
        fn CreateFileW(lpFileName: *const u16, dwDesiredAccess: u32, dwShareMode: u32, lpSecurityAttributes: *mut c_void, dwCreationDisposition: u32, dwFlagsAndAttributes: u32, hTemplateFile: *mut c_void) -> *mut c_void;
        fn MiniDumpWriteDump(hProcess: *mut c_void, ProcessId: u32, hFile: *mut c_void, DumpType: u32, ExceptionParam: *mut c_void, UserStreamParam: *mut c_void, CallbackParam: *mut c_void) -> i32;
    }

    // Build output filename
    let out_file = out_dir.join(format!("proc-{}.dmp", pid));
    let wide: Vec<u16> = out_file.as_os_str().encode_wide().chain(Some(0)).collect();

    // Create output file handle
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
    if hfile.is_null() {
        return Err(Error::last_os_error());
    }

    // Open the target process
    let hproc = unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, pid) };
    if hproc.is_null() {
        // Close file handle before returning
        unsafe { CloseHandle(hfile); }
        return Err(Error::last_os_error());
    }

    // Attempt writing the minidump
    let ok = unsafe { MiniDumpWriteDump(hproc, pid, hfile, MINIDUMP_TYPE_NORMAL, null_mut(), null_mut(), null_mut()) };

    // Close handles
    unsafe { CloseHandle(hproc); }
    unsafe { CloseHandle(hfile); }

    if ok == 0 {
        Err(Error::last_os_error())
    } else {
        Ok((out_file, "minidump".to_string()))
    }
}
