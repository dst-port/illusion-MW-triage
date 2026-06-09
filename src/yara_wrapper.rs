use std::path::Path;
use std::process::Command;

pub fn run_yara_matches(rules_path: &Path, target: &Path) -> Vec<String> {
    // Prefer using the yara crate when compiled with the `yara` feature.
    #[cfg(feature = "yara")]
    {
        // Best-effort attempt to use the yara crate API. If any step fails,
        // fall back to invoking the external `yara` CLI.
        if let Ok(_) = yara::initialize() {
            if let Ok(mut compiler) = yara::Compiler::new() {
                // try loading rules; API may differ across versions so ignore errors
                let _ = compiler.add_rules_file(rules_path.to_str().unwrap_or(""));
                if let Ok(rules) = compiler.compile_rules() {
                    if let Ok(report) = rules.scan_file(target.to_str().unwrap_or(""), 0) {
                        // Attempt to extract rule identifiers from report
                        let mut out: Vec<String> = Vec::new();
                        for m in report.iter() {
                            if let Some(id) = m.identifier() {
                                out.push(id.to_string());
                            }
                        }
                        if !out.is_empty() {
                            return out;
                        }
                    }
                }
            }
        }
    }

    // Fallback: call external `yara -r <rules> <target>` and parse stdout lines
    let mut matches: Vec<String> = Vec::new();
    if let Ok(out) = Command::new("yara")
        .args([
            "-r",
            rules_path.to_str().unwrap_or(""),
            target.to_str().unwrap_or(""),
        ])
        .output()
    {
        if out.status.success() {
            let s = String::from_utf8_lossy(&out.stdout);
            for line in s.lines() {
                if !line.trim().is_empty() {
                    // yara CLI output: <rule_name> <filename> ...; take first token
                    matches.push(line.split_whitespace().next().unwrap_or(line).to_string());
                }
            }
        }
    }
    matches
}
