use std::path::Path;
use std::io::{self, Read};
use std::fs::File;
use sha2::{Sha256, Digest};

pub fn compute_sha256(path: &Path) -> io::Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 { break; }
        hasher.update(&buf[..n]);
    }
    let result = hasher.finalize();
    let bytes = result.as_slice();
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;
    use std::io::Write;

    #[test]
    fn test_compute_sha256() {
        let mut f = NamedTempFile::new().expect("create temp file");
        write!(f, "hello").expect("write");
        let path = f.path();
        let h = compute_sha256(path).expect("hash");
        // SHA256("hello")
        assert_eq!(h, "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
    }
}
