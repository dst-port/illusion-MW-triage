use std::fs;
use std::os::unix::fs::PermissionsExt;

#[test]
fn test_run_in_sandbox_test_mode_basic() {
    // enable test mode so we don't require firejail/gcore/ptrace
    std::env::set_var("ILLUSION_TEST_MODE", "1");

    // create a small shell script that writes to stdout and stderr
    let tmpdir = tempfile::tempdir().expect("tmpdir");
    let path = tmpdir.path().join("script.sh");
    fs::write(&path, "#!/bin/sh\nprintf \"STDOUT_OK\\n\"\nprintf \"STDERR_OK\\n\" 1>&2\nexit 0\n").expect("write script");
    let mut perms = fs::metadata(&path).expect("meta").permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&path, perms).expect("chmod");

    // run inside sandbox (test mode)
    let res = illusion_sandbox::run_in_sandbox(path.to_str().unwrap()).expect("run_in_sandbox");
    assert_eq!(res.exit_code, Some(0));
    assert!(res.stdout.contains("STDOUT_OK"));
    assert!(res.stderr.contains("STDERR_OK"));

    // locate the created run artifacts directory
    let base_name = path.file_name().unwrap().to_string_lossy().to_string();
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
    assert!(found.is_some(), "expected run artifacts directory for {}", base_name);
    let run_dir = found.unwrap();
    assert!(run_dir.join("report.json").exists(), "report.json missing");
    assert!(run_dir.join("stdout.txt").exists(), "stdout.txt missing");
    assert!(run_dir.join("stderr.txt").exists(), "stderr.txt missing");

    // cleanup
    let _ = fs::remove_dir_all(run_dir);
    std::env::remove_var("ILLUSION_TEST_MODE");
}
