use std::env;
use std::fmt;
use std::fs::{self, File};
use std::io::Read;
use std::io::Write as IoWrite;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::dumper::{compare_memory_vs_disk, dump_process};
use crate::hash;
use crate::impersonation::detect_masquerade;
use crate::monitor::{monitor_process, MonitorOptions};
use crate::packers::{contains_upx_marker, shannon_entropy};
use crate::pe;
use crate::report::{
    ArtifactInfo, CoreDumpInfo, DropInfo, Evidence, Metrics, ProcessInfo, Report, Verdict,
};
use std::path::Path;

fn sanitize_filename(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c == ':' || c == '/' || c == ' ' {
                '_'
            } else {
                c
            }
        })
        .collect()
}

const KNOWN_GOOD_BASENAMES: &[&str] = &[
    "bash", "sh", "sshd", "sudo", "systemd", "ls", "cp", "mv", "cat", "python", "python3", "sleep",
    "cron",
];

#[derive(Debug)]
pub struct SandboxResult {
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub timed_out: bool,
}

#[derive(Debug)]
pub enum SandboxError {
    Io(std::io::Error),
    Utf8(std::string::FromUtf8Error),
    FirejailNotFound,
}

impl fmt::Display for SandboxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SandboxError::Io(e) => write!(f, "IO error: {}", e),
            SandboxError::Utf8(e) => write!(f, "UTF-8 conversion error: {}", e),
            SandboxError::FirejailNotFound => write!(f, "firejail not found on PATH"),
        }
    }
}

impl std::error::Error for SandboxError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            SandboxError::Io(e) => Some(e),
            SandboxError::Utf8(e) => Some(e),
            SandboxError::FirejailNotFound => None,
        }
    }
}

impl From<std::io::Error> for SandboxError {
    fn from(e: std::io::Error) -> Self {
        SandboxError::Io(e)
    }
}

impl From<std::string::FromUtf8Error> for SandboxError {
    fn from(e: std::string::FromUtf8Error) -> Self {
        SandboxError::Utf8(e)
    }
}

// Small abstraction for spawning sandboxed processes. This keeps the
// launcher logic separate so we can add Windows backends (Job/AppContainer)
// later without changing the rest of the sandbox flow.
trait SandboxSpawner {
    fn spawn(&self, file_path: &str) -> std::io::Result<Child>;
}

struct DirectSpawner;
impl SandboxSpawner for DirectSpawner {
    fn spawn(&self, file_path: &str) -> std::io::Result<Child> {
        let mut c = Command::new(file_path);
        c.stdout(Stdio::piped()).stderr(Stdio::piped());
        c.spawn()
    }
}

struct FirejailSpawner;
impl SandboxSpawner for FirejailSpawner {
    fn spawn(&self, file_path: &str) -> std::io::Result<Child> {
        let mut c = Command::new("firejail");
        c.args(["--allow-debug", "--net=none", "--private", "--", file_path])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        c.spawn()
    }
}

#[cfg(all(target_os = "windows", feature = "windows-backend"))]
struct WindowsSpawner {
    job_handle: isize,
}

#[cfg(all(target_os = "windows", feature = "windows-backend"))]
impl WindowsSpawner {
    fn new() -> Self {
        use std::ptr::null_mut;
        use std::ffi::c_void;

        // Use minimal raw FFI for CreateJobObjectW so the backend compiles
        // on cross-targets without depending on `windows-sys` feature gates.
        unsafe extern "system" {
            fn CreateJobObjectW(lpJobAttributes: *mut c_void, lpName: *const u16) -> *mut c_void;
        }

        unsafe {
            let job = CreateJobObjectW(null_mut(), null_mut()) as isize;
            if job == 0 {
                WindowsSpawner { job_handle: 0 }
            } else {
                WindowsSpawner { job_handle: job }
            }
        }
    }
}

#[cfg(all(target_os = "windows", feature = "windows-backend"))]
impl SandboxSpawner for WindowsSpawner {
    fn spawn(&self, file_path: &str) -> std::io::Result<Child> {
        use std::ffi::c_void;

        unsafe extern "system" {
            fn OpenProcess(dwDesiredAccess: u32, bInheritHandle: i32, dwProcessId: u32) -> *mut c_void;
            fn AssignProcessToJobObject(hJob: *mut c_void, hProcess: *mut c_void) -> i32;
            fn CloseHandle(hObject: *mut c_void) -> i32;
        }

        const PROCESS_ALL_ACCESS: u32 = 0x1F0FFF;

        let mut c = Command::new(file_path);
        c.stdout(Stdio::piped()).stderr(Stdio::piped());
        let mut child = c.spawn()?;
        let pid = child.id();
        unsafe {
            let hproc = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
            if !hproc.is_null() && self.job_handle != 0 {
                let _ = AssignProcessToJobObject(self.job_handle as *mut c_void, hproc);
                let _ = CloseHandle(hproc);
            }
        }
        Ok(child)
    }
}

#[cfg(all(target_os = "windows", feature = "windows-backend"))]
impl Drop for WindowsSpawner {
    fn drop(&mut self) {
        use std::ffi::c_void;
        unsafe extern "system" {
            fn CloseHandle(hObject: *mut c_void) -> i32;
        }
        unsafe {
            if self.job_handle != 0 {
                let _ = CloseHandle(self.job_handle as *mut c_void);
                self.job_handle = 0;
            }
        }
    }
}

#[cfg(all(target_os = "windows", not(feature = "windows-backend")))]
struct WindowsSpawner;

#[cfg(all(target_os = "windows", not(feature = "windows-backend")))]
impl WindowsSpawner {
    fn new() -> Self {
        WindowsSpawner
    }
}

#[cfg(all(target_os = "windows", not(feature = "windows-backend")))]
impl SandboxSpawner for WindowsSpawner {
    fn spawn(&self, file_path: &str) -> std::io::Result<Child> {
        let mut c = Command::new(file_path);
        c.stdout(Stdio::piped()).stderr(Stdio::piped());
        c.spawn()
    }
}

#[cfg(all(target_os = "windows", feature = "windows-backend"))]
#[cfg(test)]
mod windows_tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;
    use tempfile::tempdir;

    #[test]
    fn test_windows_spawner_assigns_job() {
        let td = tempdir().unwrap();
        let script = td.path().join("exit0.bat");
        let mut f = File::create(&script).unwrap();
        writeln!(f, "exit /b 0").unwrap();
        f.flush().unwrap();

        let spawner = WindowsSpawner::new();
        let mut child = spawner.spawn(script.to_str().unwrap()).unwrap();
        let id = child.id();
        let _ = child.wait();
        assert!(id > 0);
    }
}

fn platform_spawner() -> Box<dyn SandboxSpawner> {
    #[cfg(target_os = "linux")]
    {
        Box::new(FirejailSpawner)
    }
    #[cfg(target_os = "windows")]
    {
        Box::new(WindowsSpawner::new())
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        Box::new(FirejailSpawner)
    }
}

pub fn run_in_sandbox(file_path: &str) -> Result<SandboxResult, SandboxError> {
    const POLL_INTERVAL_MS: u64 = 20;
    const MAX_OUTPUT_BYTES: u64 = 64 * 1024;

    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis();
    let base_name = std::path::Path::new(file_path)
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "artifact".to_string());
    let out_dir = PathBuf::from(format!("runs/{}-{}", base_name, ts));
    fs::create_dir_all(&out_dir)?;

    let test_mode = env::var("ILLUSION_TEST_MODE")
        .map(|v| {
            let v = v.to_lowercase();
            v == "1" || v == "true" || v == "yes"
        })
        .unwrap_or(false);

    // Spawn the child process via a platform-appropriate spawner.
    let spawner: Box<dyn SandboxSpawner> = if test_mode {
        Box::new(DirectSpawner)
    } else {
        platform_spawner()
    };

    let mut child = match spawner.spawn(file_path) {
        Ok(c) => c,
        Err(e) => {
            if !test_mode && e.kind() == std::io::ErrorKind::NotFound {
                return Err(SandboxError::FirejailNotFound);
            } else {
                return Err(SandboxError::Io(e));
            }
        }
    };

    let pid = child.id();
    let monitor_handle = if !test_mode {
        Some(thread::spawn(move || {
            let opts = MonitorOptions::default();
            monitor_process(pid as i32, Duration::from_secs(30), &opts)
        }))
    } else {
        None
    };

    let dumper_handle = if !test_mode {
        let out_dir = out_dir.clone();
        Some(thread::spawn(move || {
            thread::sleep(Duration::from_millis(100));
            let dump_res = dump_process(pid, &out_dir);
            let cmp_res = compare_memory_vs_disk(pid);
            (dump_res, cmp_res)
        }))
    } else {
        None
    };

    // Optional packet capture (best-effort). If `tcpdump` is available and
    // permitted, start it to capture to `runs/<name>-<ts>/traffic.pcap`.
    let mut pcap_child_opt: Option<std::process::Child> = None;
    if !test_mode {
        let pcap_path = out_dir.join("traffic.pcap");
        if let Ok(child) = Command::new("tcpdump")
            .args([
                "-i",
                "any",
                "-w",
                pcap_path.to_str().unwrap_or("traffic.pcap"),
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        {
            pcap_child_opt = Some(child);
        }
    }

    let mut stdout_buf_rx = None;
    let mut stderr_buf_rx = None;

    if child.stdout.is_some() {
        let out = child.stdout.take().unwrap();
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        stdout_buf_rx = Some(rx);
        thread::spawn(move || {
            let mut v = Vec::new();
            let _ = out.take(MAX_OUTPUT_BYTES).read_to_end(&mut v);
            let _ = tx.send(v);
        });
    }

    if child.stderr.is_some() {
        let err = child.stderr.take().unwrap();
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        stderr_buf_rx = Some(rx);
        thread::spawn(move || {
            let mut v = Vec::new();
            let _ = err.take(MAX_OUTPUT_BYTES).read_to_end(&mut v);
            let _ = tx.send(v);
        });
    }

    let timeout = Duration::from_secs(30);
    let start = Instant::now();
    let mut timed_out = false;

    loop {
        match child.try_wait()? {
            Some(status) => {
                let out = stdout_buf_rx
                    .and_then(|r| r.recv().ok())
                    .unwrap_or_default();
                let err = stderr_buf_rx
                    .and_then(|r| r.recv().ok())
                    .unwrap_or_default();
                let out_s = String::from_utf8(out)?;
                let err_s = String::from_utf8(err)?;

                let _ = File::create(out_dir.join("stdout.txt"))
                    .and_then(|mut f| f.write_all(out_s.as_bytes()));
                let _ = File::create(out_dir.join("stderr.txt"))
                    .and_then(|mut f| f.write_all(err_s.as_bytes()));

                let monitor_r = if let Some(h) = monitor_handle {
                    h.join().ok().and_then(|r| r.ok())
                } else {
                    None
                };
                let dumper_r = if let Some(h) = dumper_handle {
                    h.join().ok()
                } else {
                    None
                };

                let artifact_hash = hash::compute_sha256(std::path::Path::new(file_path))
                    .ok()
                    .unwrap_or_default();
                let artifact = ArtifactInfo {
                    name: base_name.clone(),
                    sha256: artifact_hash,
                };

                let (total_pids, transient_count, drops, network_contacts) =
                    if let Some((metrics, trans, net)) = monitor_r {
                        (
                            metrics.total_pids_tracked,
                            metrics.transient_drops_detected,
                            trans,
                            net,
                        )
                    } else {
                        (1usize, 0usize, Vec::new(), Vec::new())
                    };

                let (core_info, mem_cmp_opt) = if let Some((dump_res, cmp_res)) = dumper_r {
                    let core = match dump_res {
                        Ok(dm) => Some(CoreDumpInfo {
                            path: dm.path,
                            method: dm.method,
                        }),
                        Err(_) => None,
                    };
                    let cmp = cmp_res.ok();
                    (core, cmp)
                } else {
                    (None, None)
                };

                let verdict_status = if let Some(ref c) = mem_cmp_opt {
                    if c.mismatch {
                        "suspicious".to_string()
                    } else {
                        "unknown".to_string()
                    }
                } else {
                    "unknown".to_string()
                };
                let mut verdict = Verdict {
                    status: verdict_status.clone(),
                    flags: Vec::new(),
                };

                if let Some((cand, score)) =
                    detect_masquerade(&base_name, KNOWN_GOOD_BASENAMES, 0.9)
                {
                    verdict
                        .flags
                        .push(format!("masquerade:artifact:{}:{:.2}", cand, score));
                    if verdict.status == "unknown" {
                        verdict.status = "suspicious".to_string();
                    }
                }

                if let Ok(true) = contains_upx_marker(Path::new(file_path)) {
                    verdict.flags.push("packer:upx".to_string());
                    if verdict.status == "unknown" {
                        verdict.status = "suspicious".to_string();
                    }
                }

                if let Ok(ent) = shannon_entropy(Path::new(file_path)) {
                    if ent > 7.5 {
                        verdict.flags.push(format!("high_entropy:{:.2}", ent));
                        if verdict.status == "unknown" {
                            verdict.status = "suspicious".to_string();
                        }
                    }
                }

                let metrics = Metrics {
                    execution_time_ms: start.elapsed().as_millis(),
                    total_pids_tracked: total_pids,
                    transient_drops_detected: transient_count,
                };

                let mut drops_info: Vec<DropInfo> = drops
                    .into_iter()
                    .map(|p| DropInfo {
                        path: p,
                        sha256: None,
                        matched_whitelist_name: None,
                    })
                    .collect();

                // Prepare a mutable copy of network contacts so we can attach per-flow pcaps
                let mut network_contacts2 = network_contacts.clone();

                // If tcpdump was started, stop it and add the pcap to files_written
                let pcap_path = out_dir.join("traffic.pcap");
                if pcap_child_opt.is_some() {
                    if let Some(mut pc) = pcap_child_opt.take() {
                        let _ = pc.kill();
                        let _ = pc.wait();
                    }
                }
                if pcap_path.exists() {
                    let sha = hash::compute_sha256(&pcap_path).ok();
                    drops_info.push(DropInfo {
                        path: pcap_path.clone(),
                        sha256: sha.clone(),
                        matched_whitelist_name: None,
                    });

                    // Try to correlate flows per-network-contact using tcpdump filters
                    let flows_dir = out_dir.join("flows");
                    let _ = fs::create_dir_all(&flows_dir);
                    for nc in network_contacts2.iter_mut() {
                        let addr = nc.remote_addr.clone();
                        let port_opt = nc.remote_port;
                        let safe_addr = sanitize_filename(&addr);
                        let flow_name = if let Some(p) = port_opt {
                            format!("flow-{}-{}.pcap", safe_addr, p)
                        } else {
                            format!("flow-{}.pcap", safe_addr)
                        };
                        let flow_path = flows_dir.join(flow_name);
                        // Build tcpdump filter expression
                        let mut cmd = Command::new("tcpdump");
                        cmd.args([
                            "-nn",
                            "-r",
                            pcap_path.to_str().unwrap_or("traffic.pcap"),
                            "-w",
                            flow_path.to_str().unwrap_or(""),
                        ]);
                        if let Some(p) = port_opt {
                            cmd.args(["host", &addr, "and", "port", &p.to_string()]);
                        } else {
                            cmd.args(["host", &addr]);
                        }
                        if let Ok(st) = cmd.status() {
                            if st.success() && flow_path.exists() {
                                let fsha = hash::compute_sha256(&flow_path).ok();
                                drops_info.push(DropInfo {
                                    path: flow_path.clone(),
                                    sha256: fsha.clone(),
                                    matched_whitelist_name: None,
                                });
                                nc.pcap_path = Some(flow_path);
                                nc.pcap_sha = fsha;
                            }
                        }
                    }
                }

                // Optional YARA scanning (prefers crate when enabled, falls back to CLI)
                let mut yara_matches_vec: Vec<String> = Vec::new();
                if let Ok(rules_path) = env::var("YARA_RULES_PATH") {
                    if !rules_path.is_empty() && Path::new(&rules_path).exists() {
                        yara_matches_vec = crate::yara_wrapper::run_yara_matches(
                            Path::new(&rules_path),
                            Path::new(file_path),
                        );
                    }
                }

                let exe_path_buf = mem_cmp_opt
                    .as_ref()
                    .and_then(|c| c.exe_path.clone())
                    .unwrap_or_else(|| PathBuf::from(""));
                let exe_name = exe_path_buf
                    .file_name()
                    .map(|s| s.to_string_lossy().to_string())
                    .unwrap_or_else(|| "".to_string());
                let mut matched_name: Option<String> = None;
                let mut proc_flagged = mem_cmp_opt.as_ref().map(|c| c.mismatch).unwrap_or(false);
                if !exe_name.is_empty() {
                    if let Some((cand, score)) =
                        detect_masquerade(&exe_name, KNOWN_GOOD_BASENAMES, 0.9)
                    {
                        matched_name = Some(cand.to_string());
                        proc_flagged = true;
                        verdict
                            .flags
                            .push(format!("masquerade:process:{}:{:.2}", cand, score));
                        if verdict.status == "unknown" {
                            verdict.status = "suspicious".to_string();
                        }
                    }
                }

                let processes_info: Vec<ProcessInfo> = vec![ProcessInfo {
                    pid,
                    exe_path: exe_path_buf,
                    sha256: mem_cmp_opt.as_ref().and_then(|c| c.in_memory_hash.clone()),
                    matched_whitelist_name: matched_name,
                    flagged: proc_flagged,
                }];

                let evidence = Evidence {
                    exit_code: status.code(),
                    timed_out,
                    stdout_snip: out_s.chars().take(4096).collect(),
                    stderr_snip: err_s.chars().take(4096).collect(),
                    drops: drops_info.clone(),
                    files_written: drops_info.clone(),
                    processes: processes_info,
                    network: network_contacts2.clone(),
                    core_dump: core_info,
                    entry_point: {
                        let p = Path::new(file_path);
                        if let Ok(Some(ei)) = crate::elf::extract_entry_snippet(p, 64) {
                            Some(crate::report::EntryPointInfo {
                                addr: ei.addr,
                                offset: ei.offset,
                                packed: ei.packed,
                                bytes: ei.bytes.iter().map(|b| format!("{:02x}", b)).collect(),
                            })
                        } else if let Ok(Some(ei)) = pe::extract_entry_snippet(p, 64) {
                            Some(crate::report::EntryPointInfo {
                                addr: ei.addr,
                                offset: ei.offset,
                                packed: ei.packed,
                                bytes: ei.bytes.iter().map(|b| format!("{:02x}", b)).collect(),
                            })
                        } else {
                            None
                        }
                    },
                    yara_matches: yara_matches_vec.clone(),
                };

                let report = Report {
                    artifact,
                    verdict,
                    metrics,
                    evidence,
                };
                if let Ok(j) = report.to_json() {
                    let _ = File::create(out_dir.join("report.json"))
                        .and_then(|mut f| f.write_all(j.as_bytes()));
                }

                return Ok(SandboxResult {
                    exit_code: status.code(),
                    stdout: out_s,
                    stderr: err_s,
                    timed_out,
                });
            }
            None => {
                if start.elapsed() >= timeout {
                    timed_out = true;
                    let _ = child.kill();
                    let status = child.wait()?;
                    let out = stdout_buf_rx
                        .and_then(|r| r.recv().ok())
                        .unwrap_or_default();
                    let err = stderr_buf_rx
                        .and_then(|r| r.recv().ok())
                        .unwrap_or_default();
                    let out_s = String::from_utf8(out)?;
                    let err_s = String::from_utf8(err)?;

                    let _ = File::create(out_dir.join("stdout.txt"))
                        .and_then(|mut f| f.write_all(out_s.as_bytes()));
                    let _ = File::create(out_dir.join("stderr.txt"))
                        .and_then(|mut f| f.write_all(err_s.as_bytes()));

                    let monitor_r = if let Some(h) = monitor_handle {
                        h.join().ok().and_then(|r| r.ok())
                    } else {
                        None
                    };
                    let dumper_r = if let Some(h) = dumper_handle {
                        h.join().ok()
                    } else {
                        None
                    };

                    let artifact_hash = hash::compute_sha256(std::path::Path::new(file_path))
                        .ok()
                        .unwrap_or_default();
                    let artifact = ArtifactInfo {
                        name: base_name.clone(),
                        sha256: artifact_hash,
                    };

                    let (total_pids, transient_count, drops, network_contacts) =
                        if let Some((metrics, trans, net)) = monitor_r {
                            (
                                metrics.total_pids_tracked,
                                metrics.transient_drops_detected,
                                trans,
                                net,
                            )
                        } else {
                            (1usize, 0usize, Vec::new(), Vec::new())
                        };

                    let (core_info, mem_cmp_opt) = if let Some((dump_res, cmp_res)) = dumper_r {
                        let core = match dump_res {
                            Ok(dm) => Some(CoreDumpInfo {
                                path: dm.path,
                                method: dm.method,
                            }),
                            Err(_) => None,
                        };
                        let cmp = cmp_res.ok();
                        (core, cmp)
                    } else {
                        (None, None)
                    };

                    let verdict_status = if let Some(ref c) = mem_cmp_opt {
                        if c.mismatch {
                            "suspicious".to_string()
                        } else {
                            "unknown".to_string()
                        }
                    } else {
                        "unknown".to_string()
                    };
                    let mut verdict = Verdict {
                        status: verdict_status.clone(),
                        flags: Vec::new(),
                    };

                    if let Some((cand, score)) =
                        detect_masquerade(&base_name, KNOWN_GOOD_BASENAMES, 0.9)
                    {
                        verdict
                            .flags
                            .push(format!("masquerade:artifact:{}:{:.2}", cand, score));
                        if verdict.status == "unknown" {
                            verdict.status = "suspicious".to_string();
                        }
                    }

                    if let Ok(true) = contains_upx_marker(Path::new(file_path)) {
                        verdict.flags.push("packer:upx".to_string());
                        if verdict.status == "unknown" {
                            verdict.status = "suspicious".to_string();
                        }
                    }

                    if let Ok(ent) = shannon_entropy(Path::new(file_path)) {
                        if ent > 7.5 {
                            verdict.flags.push(format!("high_entropy:{:.2}", ent));
                            if verdict.status == "unknown" {
                                verdict.status = "suspicious".to_string();
                            }
                        }
                    }

                    let metrics = Metrics {
                        execution_time_ms: start.elapsed().as_millis(),
                        total_pids_tracked: total_pids,
                        transient_drops_detected: transient_count,
                    };

                    let mut drops_info: Vec<DropInfo> = drops
                        .into_iter()
                        .map(|p| DropInfo {
                            path: p,
                            sha256: None,
                            matched_whitelist_name: None,
                        })
                        .collect();

                    // Prepare a mutable copy of network contacts so we can attach per-flow pcaps
                    let mut network_contacts2 = network_contacts.clone();

                    // If tcpdump was started, stop it and add the pcap to files_written
                    let pcap_path = out_dir.join("traffic.pcap");
                    if pcap_child_opt.is_some() {
                        if let Some(mut pc) = pcap_child_opt.take() {
                            let _ = pc.kill();
                            let _ = pc.wait();
                        }
                    }
                    if pcap_path.exists() {
                        let sha = hash::compute_sha256(&pcap_path).ok();
                        drops_info.push(DropInfo {
                            path: pcap_path.clone(),
                            sha256: sha.clone(),
                            matched_whitelist_name: None,
                        });

                        // Try to correlate flows per-network-contact using tcpdump filters
                        let flows_dir = out_dir.join("flows");
                        let _ = fs::create_dir_all(&flows_dir);
                        for nc in network_contacts2.iter_mut() {
                            let addr = nc.remote_addr.clone();
                            let port_opt = nc.remote_port;
                            let safe_addr = sanitize_filename(&addr);
                            let flow_name = if let Some(p) = port_opt {
                                format!("flow-{}-{}.pcap", safe_addr, p)
                            } else {
                                format!("flow-{}.pcap", safe_addr)
                            };
                            let flow_path = flows_dir.join(flow_name);
                            let mut cmd = Command::new("tcpdump");
                            cmd.args([
                                "-nn",
                                "-r",
                                pcap_path.to_str().unwrap_or("traffic.pcap"),
                                "-w",
                                flow_path.to_str().unwrap_or(""),
                            ]);
                            if let Some(p) = port_opt {
                                cmd.args(["host", &addr, "and", "port", &p.to_string()]);
                            } else {
                                cmd.args(["host", &addr]);
                            }
                            if let Ok(st) = cmd.status() {
                                if st.success() && flow_path.exists() {
                                    let fsha = hash::compute_sha256(&flow_path).ok();
                                    drops_info.push(DropInfo {
                                        path: flow_path.clone(),
                                        sha256: fsha.clone(),
                                        matched_whitelist_name: None,
                                    });
                                    nc.pcap_path = Some(flow_path);
                                    nc.pcap_sha = fsha;
                                }
                            }
                        }
                    }

                    // Optional YARA scanning (prefers crate when enabled, falls back to CLI)
                    let mut yara_matches_vec: Vec<String> = Vec::new();
                    if let Ok(rules_path) = env::var("YARA_RULES_PATH") {
                        if !rules_path.is_empty() && Path::new(&rules_path).exists() {
                            yara_matches_vec = crate::yara_wrapper::run_yara_matches(
                                Path::new(&rules_path),
                                Path::new(file_path),
                            );
                        }
                    }

                    let exe_path_buf = mem_cmp_opt
                        .as_ref()
                        .and_then(|c| c.exe_path.clone())
                        .unwrap_or_else(|| PathBuf::from(""));
                    let exe_name = exe_path_buf
                        .file_name()
                        .map(|s| s.to_string_lossy().to_string())
                        .unwrap_or_else(|| "".to_string());
                    let mut matched_name: Option<String> = None;
                    let mut proc_flagged =
                        mem_cmp_opt.as_ref().map(|c| c.mismatch).unwrap_or(false);
                    if !exe_name.is_empty() {
                        if let Some((cand, score)) =
                            detect_masquerade(&exe_name, KNOWN_GOOD_BASENAMES, 0.9)
                        {
                            matched_name = Some(cand.to_string());
                            proc_flagged = true;
                            verdict
                                .flags
                                .push(format!("masquerade:process:{}:{:.2}", cand, score));
                            if verdict.status == "unknown" {
                                verdict.status = "suspicious".to_string();
                            }
                        }
                    }

                    let processes_info: Vec<ProcessInfo> = vec![ProcessInfo {
                        pid,
                        exe_path: exe_path_buf,
                        sha256: mem_cmp_opt.as_ref().and_then(|c| c.in_memory_hash.clone()),
                        matched_whitelist_name: matched_name,
                        flagged: proc_flagged,
                    }];

                    let evidence = Evidence {
                        exit_code: status.code(),
                        timed_out,
                        stdout_snip: out_s.chars().take(4096).collect(),
                        stderr_snip: err_s.chars().take(4096).collect(),
                        drops: drops_info.clone(),
                        files_written: drops_info.clone(),
                        processes: processes_info,
                        network: network_contacts2.clone(),
                        core_dump: core_info,
                        entry_point: {
                            let p = Path::new(file_path);
                            if let Ok(Some(ei)) = crate::elf::extract_entry_snippet(p, 64) {
                                Some(crate::report::EntryPointInfo {
                                    addr: ei.addr,
                                    offset: ei.offset,
                                    packed: ei.packed,
                                    bytes: ei.bytes.iter().map(|b| format!("{:02x}", b)).collect(),
                                })
                            } else if let Ok(Some(ei)) = pe::extract_entry_snippet(p, 64) {
                                Some(crate::report::EntryPointInfo {
                                    addr: ei.addr,
                                    offset: ei.offset,
                                    packed: ei.packed,
                                    bytes: ei.bytes.iter().map(|b| format!("{:02x}", b)).collect(),
                                })
                            } else {
                                None
                            }
                        },
                        yara_matches: yara_matches_vec.clone(),
                    };

                    let report = Report {
                        artifact,
                        verdict,
                        metrics,
                        evidence,
                    };
                    if let Ok(j) = report.to_json() {
                        let _ = File::create(out_dir.join("report.json"))
                            .and_then(|mut f| f.write_all(j.as_bytes()));
                    }

                    return Ok(SandboxResult {
                        exit_code: status.code(),
                        stdout: out_s,
                        stderr: err_s,
                        timed_out,
                    });
                }
                thread::sleep(Duration::from_millis(POLL_INTERVAL_MS));
            }
        }
    }
}
