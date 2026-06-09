use serde::Serialize;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::detection::analyze_path;
use crate::quarantine::quarantine_file;
use crate::whitelist::Whitelist;

#[derive(Serialize, Debug)]
pub struct HuntFinding {
    pub path: PathBuf,
    pub flags: Vec<String>,
    pub sha256: Option<String>,
    pub quarantined: Option<PathBuf>,
}

pub fn hunt_paths(
    paths: &[PathBuf],
    quarantine: bool,
    whitelist_path: Option<&Path>,
) -> io::Result<Vec<HuntFinding>> {
    let mut findings = Vec::new();
    let whitelist = if let Some(p) = whitelist_path {
        Whitelist::load(p).ok()
    } else {
        None
    };
    for p in paths {
        if p.is_dir() {
            for entry in walk_dir(p)? {
                let res = analyze_path(&entry, whitelist.as_ref());
                if let Ok(dr) = res {
                    if dr.suspicious {
                        let mut quarantined = None;
                        if quarantine {
                            if let Ok(dest) = quarantine_file(&entry) {
                                quarantined = Some(dest);
                            }
                        }
                        findings.push(HuntFinding {
                            path: entry,
                            flags: dr.flags,
                            sha256: dr.sha256,
                            quarantined,
                        });
                    }
                }
            }
        } else if p.is_file() {
            if let Ok(dr) = analyze_path(p, whitelist.as_ref()) {
                if dr.suspicious {
                    let mut quarantined = None;
                    if quarantine {
                        if let Ok(dest) = quarantine_file(p) {
                            quarantined = Some(dest);
                        }
                    }
                    findings.push(HuntFinding {
                        path: p.clone(),
                        flags: dr.flags,
                        sha256: dr.sha256,
                        quarantined,
                    });
                }
            }
        }
    }

    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis();
    let out_dir = PathBuf::from(format!("hunt_reports/{}", ts));
    fs::create_dir_all(&out_dir)?;
    let report_path = out_dir.join("hunt_report.json");
    let _ = fs::write(
        &report_path,
        serde_json::to_string_pretty(&findings).unwrap(),
    );

    Ok(findings)
}

fn walk_dir(dir: &Path) -> io::Result<Vec<PathBuf>> {
    let mut res = Vec::new();
    for entry in fs::read_dir(dir)? {
        let e = entry?;
        let p = e.path();
        if p.is_dir() {
            res.extend(walk_dir(&p)?);
        } else if p.is_file() {
            res.push(p);
        }
    }
    Ok(res)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::tempdir;

    #[test]
    fn test_hunt_quarantine() {
        let td = tempdir().unwrap();
        let p = td.path().join("suspect");
        let mut f = fs::File::create(&p).unwrap();
        f.write_all(b"\x00UPX0\x00").unwrap();
        let findings = hunt_paths(&[td.path().to_path_buf()], true, None).unwrap();
        assert!(!findings.is_empty());
        assert!(findings[0].quarantined.is_some());
    }
}
