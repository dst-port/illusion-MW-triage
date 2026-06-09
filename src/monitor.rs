use std::collections::HashSet;
use std::fs;
use std::io;
use std::path::PathBuf;
use std::time::{Duration, Instant};

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
        MonitorOptions {
            poll_interval_ms: 20,
            drop_dirs: vec![PathBuf::from("/tmp"), PathBuf::from("/dev/shm")],
        }
    }
}

pub fn monitor_process(
    pid: i32,
    duration: Duration,
    opts: &MonitorOptions,
) -> io::Result<(MonitorMetrics, Vec<PathBuf>)> {
    let start = Instant::now();
    let mut seen: HashSet<i32> = HashSet::new();
    seen.insert(pid);
    let mut transient: Vec<PathBuf> = Vec::new();
    let mut metrics = MonitorMetrics {
        total_pids_tracked: 1,
        transient_drops_detected: 0,
    };

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

        std::thread::sleep(Duration::from_millis(opts.poll_interval_ms));
    }

    Ok((metrics, transient))
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
        let (metrics, _transient) =
            monitor_process(pid, Duration::from_millis(200), &opts).expect("monitor");
        assert!(metrics.total_pids_tracked >= 1);
        let _ = child.kill();
        let _ = child.wait();
    }
}
