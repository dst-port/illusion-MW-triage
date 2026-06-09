use std::collections::HashSet;
#[cfg(target_os = "windows")]
use std::env;
use std::fs;
use std::io;
use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub struct MonitorOptions {
    pub poll_interval_ms: u64,
    pub drop_dirs: Vec<PathBuf>,
}

pub struct MonitorMetrics {
    pub total_pids_tracked: usize,
    pub transient_drops_detected: usize,
}

impl Default for MonitorOptions {
    fn default() -> Self {
        #[cfg(target_os = "linux")]
        {
            MonitorOptions {
                poll_interval_ms: 20,
                drop_dirs: vec![PathBuf::from("/tmp"), PathBuf::from("/dev/shm")],
            }
        }

        #[cfg(target_os = "windows")]
        {
            MonitorOptions {
                poll_interval_ms: 20,
                drop_dirs: vec![env::temp_dir()],
            }
        }

        #[cfg(not(any(target_os = "linux", target_os = "windows")))]
        {
            MonitorOptions {
                poll_interval_ms: 20,
                drop_dirs: vec![PathBuf::from("/tmp")],
            }
        }
    }
}

/// Monitoring backend abstraction. Implement platform-specific logic here.
trait MonitorBackend {
    fn monitor(
        &self,
        pid: i32,
        duration: Duration,
        opts: &MonitorOptions,
    ) -> io::Result<(
        MonitorMetrics,
        Vec<PathBuf>,
        Vec<crate::report::NetworkContact>,
    )>;
}

#[cfg(target_os = "linux")]
struct LinuxMonitor;

#[cfg(target_os = "linux")]
impl MonitorBackend for LinuxMonitor {
    fn monitor(
        &self,
        pid: i32,
        duration: Duration,
        opts: &MonitorOptions,
    ) -> io::Result<(
        MonitorMetrics,
        Vec<PathBuf>,
        Vec<crate::report::NetworkContact>,
    )> {
        let start = Instant::now();
        let mut seen: HashSet<i32> = HashSet::new();
        seen.insert(pid);
        let mut transient: Vec<PathBuf> = Vec::new();
        let mut metrics = MonitorMetrics {
            total_pids_tracked: 1,
            transient_drops_detected: 0,
        };

        let mut net_contacts: Vec<crate::report::NetworkContact> = Vec::new();
        let mut seen_net_keys: HashSet<String> = HashSet::new();

        while start.elapsed() < duration {
            let proc_entries = fs::read_dir("/proc")?;
            for entry in proc_entries.flatten() {
                let file_name = entry.file_name();
                if let Ok(pid_val) = file_name.to_string_lossy().parse::<i32>() {
                    if seen.contains(&pid_val) {
                        continue;
                    }
                    let stat_path = format!("/proc/{}/stat", pid_val);
                    if let Ok(s) = fs::read_to_string(&stat_path) {
                        if let Some(rest) = s.split(')').nth(1) {
                            let parts: Vec<&str> = rest.split_whitespace().collect();
                            if parts.len() > 1 {
                                if let Ok(ppid) = parts[1].parse::<i32>() {
                                    if seen.contains(&ppid) {
                                        seen.insert(pid_val);
                                        metrics.total_pids_tracked = seen.len();
                                        let fd_dir = format!("/proc/{}/fd", pid_val);
                                        if let Ok(fds) = fs::read_dir(&fd_dir) {
                                            for fd in fds.flatten() {
                                                if let Ok(target) = fd.path().read_link() {
                                                    for d in &opts.drop_dirs {
                                                        if target.starts_with(d) {
                                                            transient.push(target.clone());
                                                            metrics.transient_drops_detected += 1;
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // capture network via `ss -tnp`, correlate to seen PIDs
            if let Ok(out) = Command::new("ss").args(["-tnp"]).output() {
                if out.status.success() {
                    if let Ok(s) = String::from_utf8(out.stdout) {
                        for line in s.lines() {
                            if line.starts_with("State") || line.trim().is_empty() {
                                continue;
                            }
                            if let Some(users_idx) = line.find("users:(") {
                                let users_part = &line[users_idx..];
                                if let Some(pid_val) = parse_pid_from_users(users_part) {
                                    if pid_val == pid || seen.contains(&pid_val) {
                                        let prefix = &line[..users_idx];
                                        let toks: Vec<&str> = prefix.split_whitespace().collect();
                                        if !toks.is_empty() {
                                            let peer = toks.last().unwrap();
                                            if let Some((addr, port)) = parse_addr_port(peer) {
                                                let key =
                                                    format!("{}|{}|{:?}", pid_val, addr, port);
                                                if !seen_net_keys.contains(&key) {
                                                    seen_net_keys.insert(key.clone());
                                                    let ts = SystemTime::now()
                                                        .duration_since(UNIX_EPOCH)
                                                        .map(|d| d.as_millis())
                                                        .ok();
                                                    net_contacts.push(
                                                        crate::report::NetworkContact {
                                                            protocol: "tcp".to_string(),
                                                            remote_addr: addr.to_string(),
                                                            remote_port: port,
                                                            hostname: None,
                                                            timestamp_ms: ts,
                                                            pcap_path: None,
                                                            pcap_sha: None,
                                                        },
                                                    );
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            std::thread::sleep(Duration::from_millis(opts.poll_interval_ms));
        }

        Ok((metrics, transient, net_contacts))
    }
}

#[cfg(not(target_os = "linux"))]
struct DummyMonitor;

#[cfg(not(target_os = "linux"))]
impl MonitorBackend for DummyMonitor {
    fn monitor(
        &self,
        _pid: i32,
        duration: Duration,
        opts: &MonitorOptions,
    ) -> io::Result<(
        MonitorMetrics,
        Vec<PathBuf>,
        Vec<crate::report::NetworkContact>,
    )> {
        // Best-effort fallback for non-Linux platforms: sleep for duration and
        // report minimal metrics. Windows-specific implementation will replace this.
        let start = Instant::now();
        while start.elapsed() < duration {
            std::thread::sleep(Duration::from_millis(opts.poll_interval_ms));
        }
        Ok((
            MonitorMetrics {
                total_pids_tracked: 1,
                transient_drops_detected: 0,
            },
            Vec::new(),
            Vec::new(),
        ))
    }
}

// helpers for parsing `ss`/`netstat` output
fn parse_pid_from_users(s: &str) -> Option<i32> {
    if let Some(idx) = s.find("pid=") {
        let mut i = idx + 4;
        let bytes = s.as_bytes();
        let mut num = 0i64;
        let mut found = false;
        while i < s.len() && (bytes[i] as char).is_ascii_digit() {
            found = true;
            num = num * 10 + ((bytes[i] - b'0') as i64);
            i += 1;
        }
        if found {
            return Some(num as i32);
        }
    }
    // fallback: pick the largest digit-sequence in the users string
    let mut max_seq = String::new();
    let mut cur = String::new();
    for c in s.chars() {
        if c.is_ascii_digit() {
            cur.push(c);
        } else {
            if cur.len() > max_seq.len() {
                max_seq = cur.clone();
            }
            cur.clear();
        }
    }
    if cur.len() > max_seq.len() {
        max_seq = cur;
    }
    if !max_seq.is_empty() {
        if let Ok(v) = max_seq.parse::<i32>() {
            return Some(v);
        }
    }
    None
}

fn parse_addr_port(tok: &str) -> Option<(String, Option<u16>)> {
    if tok == "*" || tok.ends_with(":*") {
        return None;
    }
    if tok.starts_with('[') {
        if let Some(pos) = tok.rfind(':') {
            let end_br = tok.find(']').unwrap_or(tok.len() - 1);
            let addr = &tok[1..end_br];
            let port = tok[pos + 1..].parse::<u16>().ok();
            return Some((addr.to_string(), port));
        }
    }
    if let Some(pos) = tok.rfind(':') {
        let addr = &tok[..pos];
        let port = tok[pos + 1..].parse::<u16>().ok();
        return Some((addr.to_string(), port));
    }
    None
}

#[cfg(target_os = "windows")]
struct WindowsMonitor;

#[cfg(target_os = "windows")]
impl MonitorBackend for WindowsMonitor {
    fn monitor(
        &self,
        pid: i32,
        duration: Duration,
        opts: &MonitorOptions,
    ) -> io::Result<(
        MonitorMetrics,
        Vec<PathBuf>,
        Vec<crate::report::NetworkContact>,
    )> {
        // Basic Windows monitor: watch configured drop directories for new files
        // and capture simple network connections via netstat for the target PID.
        let start = Instant::now();
        let mut metrics = MonitorMetrics {
            total_pids_tracked: 1,
            transient_drops_detected: 0,
        };

        let mut seen_files: HashSet<PathBuf> = HashSet::new();
        for d in &opts.drop_dirs {
            if let Ok(entries) = fs::read_dir(d) {
                for e in entries.flatten() {
                    seen_files.insert(e.path());
                }
            }
        }

        let mut transient: Vec<PathBuf> = Vec::new();
        let mut net_contacts: Vec<crate::report::NetworkContact> = Vec::new();
        let mut seen_net_keys: HashSet<String> = HashSet::new();

        while start.elapsed() < duration {
            for d in &opts.drop_dirs {
                if let Ok(entries) = fs::read_dir(d) {
                    for e in entries.flatten() {
                        let p = e.path();
                        if !seen_files.contains(&p) {
                            seen_files.insert(p.clone());
                            transient.push(p.clone());
                            metrics.transient_drops_detected += 1;
                        }
                    }
                }
            }

            if let Ok(out) = Command::new("netstat").args(["-n", "-o"]).output() {
                if out.status.success() {
                    if let Ok(s) = String::from_utf8(out.stdout) {
                        for line in s.lines() {
                            let line = line.trim();
                            if line.is_empty() || line.starts_with("Proto") {
                                continue;
                            }
                            let toks: Vec<&str> = line.split_whitespace().collect();
                            if toks.len() < 4 {
                                continue;
                            }
                            if let Ok(pid_val) = toks.last().unwrap().parse::<i32>() {
                                if pid_val == pid {
                                    let foreign = if toks.len() >= 3 { toks[2] } else { continue };
                                    if let Some((addr, port)) = parse_addr_port(foreign) {
                                        let key = format!("{}|{}|{:?}", pid_val, addr, port);
                                        if !seen_net_keys.contains(&key) {
                                            seen_net_keys.insert(key.clone());
                                            let ts = SystemTime::now()
                                                .duration_since(UNIX_EPOCH)
                                                .map(|d| d.as_millis())
                                                .ok();
                                            net_contacts.push(crate::report::NetworkContact {
                                                protocol: toks[0].to_string(),
                                                remote_addr: addr.to_string(),
                                                remote_port: port,
                                                hostname: None,
                                                timestamp_ms: ts,
                                                pcap_path: None,
                                                pcap_sha: None,
                                            });
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            std::thread::sleep(Duration::from_millis(opts.poll_interval_ms));
        }

        Ok((metrics, transient, net_contacts))
    }
}

pub fn monitor_process(
    pid: i32,
    duration: Duration,
    opts: &MonitorOptions,
) -> io::Result<(
    MonitorMetrics,
    Vec<PathBuf>,
    Vec<crate::report::NetworkContact>,
)> {
    #[cfg(target_os = "linux")]
    let backend: Box<dyn MonitorBackend> = Box::new(LinuxMonitor);

    #[cfg(target_os = "windows")]
    let backend: Box<dyn MonitorBackend> = Box::new(WindowsMonitor);

    #[cfg(all(not(target_os = "linux"), not(target_os = "windows")))]
    let backend: Box<dyn MonitorBackend> = Box::new(DummyMonitor);

    backend.monitor(pid, duration, opts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;
    use std::time::Duration;

    #[test]
    fn test_monitor_no_crash() {
        let mut child = Command::new("sleep").arg("1").spawn().expect("spawn");
        let pid = child.id() as i32;
        let opts = MonitorOptions::default();
        let (metrics, _transient, _network) =
            monitor_process(pid, Duration::from_millis(200), &opts).expect("monitor");
        assert!(metrics.total_pids_tracked >= 1);
        let _ = child.kill();
        let _ = child.wait();
    }
}
