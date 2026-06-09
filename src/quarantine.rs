use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub fn quarantine_file(path: &Path) -> io::Result<PathBuf> {
    let base = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("artifact");
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis();
    let qdir = PathBuf::from(format!("quarantine/{}-{}", base, ts));
    fs::create_dir_all(&qdir)?;
    let dest = qdir.join(base);
    match fs::rename(path, &dest) {
        Ok(_) => {}
        Err(_) => {
            fs::copy(path, &dest)?;
            fs::remove_file(path)?;
        }
    }
    let mut perms = fs::metadata(&dest)?.permissions();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        perms.set_mode(0o600);
        fs::set_permissions(&dest, perms)?;
    }
    Ok(dest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_quarantine_move() {
        let mut f = NamedTempFile::new().unwrap();
        let p = f.path().to_path_buf();
        write!(f, "hello").unwrap();
        let dest = quarantine_file(&p).unwrap();
        assert!(dest.exists());
    }
}
