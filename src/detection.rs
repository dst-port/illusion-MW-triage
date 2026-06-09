use std::path::Path;
use std::io;

use crate::packers::{contains_upx_marker, contains_packer_marker, shannon_entropy};
use crate::impersonation::detect_masquerade;
use crate::whitelist::Whitelist;
use crate::hash;

#[derive(Debug, Clone)]
pub struct DetectionResult {
    pub suspicious: bool,
    pub flags: Vec<String>,
    pub sha256: Option<String>,
}

/// Analyze a path using simple heuristics: whitelist, packer markers, entropy, masquerade.
pub fn analyze_path(path: &Path, whitelist: Option<&Whitelist>) -> io::Result<DetectionResult> {
    let mut flags = Vec::new();
    let mut suspicious = false;
    let sha = hash::compute_sha256(path).ok();
    if let Some(ref s) = sha {
        if let Some(wl) = whitelist {
            if wl.is_whitelisted(&path.file_name().and_then(|s| s.to_str()).unwrap_or_default().to_string(), s) {
                flags.push("whitelisted".to_string());
                return Ok(DetectionResult { suspicious: false, flags, sha256: Some(s.clone()) });
            }
        }
    }

    // packer marker (broad scan)
    match contains_packer_marker(path) {
        Ok(Some(name)) => {
            flags.push(format!("packer:{}", name.to_lowercase()));
            suspicious = true;
        }
        Ok(None) => {
            // fallback: check explicit UPX quick-check
            if let Ok(true) = contains_upx_marker(path) {
                flags.push("packer:upx".to_string());
                suspicious = true;
            }
        }
        Err(_) => {}
    }

    // entropy
    if let Ok(ent) = shannon_entropy(path) {
        if ent > 7.5 {
            flags.push(format!("high_entropy:{:.2}", ent));
            suspicious = true;
        }
    }

    // masquerade detection against a small common list
    let name = path.file_name().and_then(|s| s.to_str()).unwrap_or_default();
    if let Some((cand, score)) = detect_masquerade(name, &["bash","sh","sshd","sudo","systemd","python","python3"], 0.9) {
        flags.push(format!("masquerade:{}:{:.2}", cand, score));
        suspicious = true;
    }

    // optional YARA scan (feature-gated); returns rule name or None
    if let Ok(Some(rule)) = run_yara_scan(path) {
        flags.push(format!("yara:{}", rule));
        suspicious = true;
    }

    Ok(DetectionResult { suspicious, flags, sha256: sha })
}

// YARA integration: feature-gated. When the `yara` feature is enabled and
// `libyara` is available, this will run the rules and return a matching rule
// identifier. Without the feature this is a no-op returning Ok(None).
#[cfg(feature = "yara")]
fn run_yara_scan(path: &Path) -> io::Result<Option<String>> {
    use std::process::Command;
    // look for common rule filenames in the repo
    let candidates = ["yara_rules.yar", "rules.yar", "yara/rules.yar"];
    for c in candidates.iter() {
        let p = std::path::Path::new(c);
        if p.exists() {
            if let Ok(out) = Command::new("yara").arg("-r").arg(p).arg(path).output() {
                if out.status.success() {
                    let s = String::from_utf8_lossy(&out.stdout).to_string();
                    for line in s.lines() {
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        if parts.len() > 0 {
                            return Ok(Some(parts[0].to_string()));
                        }
                    }
                }
            }
        }
    }
    Ok(None)
}

#[cfg(not(feature = "yara"))]
fn run_yara_scan(_path: &Path) -> io::Result<Option<String>> { Ok(None) }

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;
    use std::io::Write;

    #[test]
    fn test_detection_whitelist() {
        let mut wl = Whitelist::default();
        wl.add_entry("goodbin".to_string(), "abcd1234".to_string());

        let mut f = NamedTempFile::new().unwrap();
        f.write_all(b"dummy").unwrap();
        let res = analyze_path(f.path(), Some(&wl)).unwrap();
        // not whitelisted because name doesn't match
        assert!(res.suspicious == false || res.suspicious == false);
    }

    #[test]
    fn test_detection_packer_marker_detected() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        use std::io::Write;
        f.write_all(b"xxMPRESSyy").unwrap();
        let res = analyze_path(f.path(), None).unwrap();
        assert!(res.suspicious);
        assert!(res.flags.iter().any(|s| s.starts_with("packer:")));
    }
}
