use std::env;
use std::fmt;
use std::fs::{self, File};
use std::io::Read;
use std::io::Write as IoWrite;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::dumper::{compare_memory_vs_disk, dump_process};
use crate::hash;
use crate::impersonation::detect_masquerade;
use crate::monitor::{monitor_process, MonitorOptions};
use crate::packers::{contains_upx_marker, shannon_entropy};
use crate::report::{
    ArtifactInfo, CoreDumpInfo, DropInfo, Evidence, Metrics, ProcessInfo, Report, Verdict,
};
use std::path::Path;

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

    let mut cmd = if test_mode {
        let mut c = Command::new(file_path);
        c.stdout(Stdio::piped()).stderr(Stdio::piped());
        c
    } else {
        let mut c = Command::new("firejail");
        c.args(["--allow-debug", "--net=none", "--private", "--", file_path])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        c
    };

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(SandboxError::FirejailNotFound)
        }
        Err(e) => return Err(SandboxError::Io(e)),
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

                let (total_pids, transient_count, drops) = if let Some((metrics, trans)) = monitor_r
                {
                    (
                        metrics.total_pids_tracked,
                        metrics.transient_drops_detected,
                        trans,
                    )
                } else {
                    (1usize, 0usize, Vec::new())
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

                let drops_info: Vec<DropInfo> = drops
                    .into_iter()
                    .map(|p| DropInfo {
                        path: p,
                        sha256: None,
                        matched_whitelist_name: None,
                    })
                    .collect();

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
                    drops: drops_info,
                    processes: processes_info,
                    core_dump: core_info,
                    entry_point: None,
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

                    let (total_pids, transient_count, drops) =
                        if let Some((metrics, trans)) = monitor_r {
                            (
                                metrics.total_pids_tracked,
                                metrics.transient_drops_detected,
                                trans,
                            )
                        } else {
                            (1usize, 0usize, Vec::new())
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

                    let drops_info: Vec<DropInfo> = drops
                        .into_iter()
                        .map(|p| DropInfo {
                            path: p,
                            sha256: None,
                            matched_whitelist_name: None,
                        })
                        .collect();

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
                        drops: drops_info,
                        processes: processes_info,
                        core_dump: core_info,
                        entry_point: None,
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
