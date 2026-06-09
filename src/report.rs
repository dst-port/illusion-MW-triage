use serde::Serialize;
use std::path::PathBuf;

#[derive(Serialize)]
pub struct ArtifactInfo {
    pub name: String,
    pub sha256: String,
}

#[derive(Serialize)]
pub struct Verdict {
    pub status: String,
    pub flags: Vec<String>,
}

#[derive(Serialize, Default)]
pub struct Metrics {
    pub execution_time_ms: u128,
    pub total_pids_tracked: usize,
    pub transient_drops_detected: usize,
}

#[derive(Serialize, Clone)]
pub struct DropInfo {
    pub path: PathBuf,
    pub sha256: Option<String>,
    pub matched_whitelist_name: Option<String>,
}

#[derive(Serialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub exe_path: PathBuf,
    pub sha256: Option<String>,
    pub matched_whitelist_name: Option<String>,
    pub flagged: bool,
}

#[derive(Serialize)]
pub struct CoreDumpInfo {
    pub path: PathBuf,
    pub method: String,
}

#[derive(Serialize)]
pub struct EntryPointInfo {
    pub addr: u64,
    pub offset: u64,
    pub packed: Option<String>,
    pub bytes: String,
}

#[derive(Serialize, Clone)]
pub struct NetworkContact {
    pub protocol: String,
    pub remote_addr: String,
    pub remote_port: Option<u16>,
    pub hostname: Option<String>,
    pub timestamp_ms: Option<u128>,
    pub pcap_path: Option<PathBuf>,
    pub pcap_sha: Option<String>,
}

#[derive(Serialize)]
pub struct Report {
    pub artifact: ArtifactInfo,
    pub verdict: Verdict,
    pub metrics: Metrics,
    pub evidence: Evidence,
}

#[derive(Serialize)]
pub struct Evidence {
    pub exit_code: Option<i32>,
    pub timed_out: bool,
    pub stdout_snip: String,
    pub stderr_snip: String,
    pub drops: Vec<DropInfo>,
    pub files_written: Vec<DropInfo>,
    pub processes: Vec<ProcessInfo>,
    pub network: Vec<NetworkContact>,
    pub core_dump: Option<CoreDumpInfo>,
    pub entry_point: Option<EntryPointInfo>,
    pub yara_matches: Vec<String>,
}

impl Report {
    pub fn to_json(&self) -> serde_json::Result<String> {
        serde_json::to_string_pretty(self)
    }
}
