use std::fs;
use std::os::unix::fs::PermissionsExt;

#[test]
fn test_masquerade_report_flag() {
    std::env::set_var("ILLUSION_TEST_MODE", "1");

    let tmpdir = tempfile::tempdir().expect("tmpdir");
    let fname = "b\u{0251}sh".to_string();
    let path = tmpdir.path().join(&fname);
    fs::write(&path, "#!/bin/sh\necho OK\n").expect("write");
    let mut perms = fs::metadata(&path).expect("meta").permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&path, perms).expect("chmod");

    let res = illusion_sandbox::run_in_sandbox(path.to_str().unwrap()).expect("run");
    assert!(res.stdout.contains("OK"));

    let base_name = fname;
    let mut found = None;
    if let Ok(entries) = fs::read_dir("runs") {
        for e in entries.flatten() {
            let n = e.file_name().into_string().unwrap_or_default();
            if n.starts_with(&base_name) {
                found = Some(e.path());
                break;
            }
        }
    }
    assert!(found.is_some());
    let run_dir = found.unwrap();
    let report = fs::read_to_string(run_dir.join("report.json")).expect("report");
    assert!(
        report.contains("masquerade:artifact"),
        "expected masquerade flag in report.json"
    );

    let _ = fs::remove_dir_all(run_dir);
    std::env::remove_var("ILLUSION_TEST_MODE");
}
