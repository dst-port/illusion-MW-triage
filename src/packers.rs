use std::path::Path;
use std::fs::File;
use std::io::{self, Read};

/// Check for simple UPX markers in the binary.
pub fn contains_upx_marker(path: &Path) -> io::Result<bool> {
    let mut f = File::open(path)?;
    let mut buf = Vec::new();
    // read up to 2MiB for scanning
    let _ = f.by_ref().take(2 * 1024 * 1024).read_to_end(&mut buf)?;
    let s = &buf;
    Ok(s.windows(4).any(|w| w == b"UPX0" || w == b"UPX1")
        || s.windows(3).any(|w| w.eq_ignore_ascii_case(b"UPX")))
}

/// Scan for a small set of common packer markers (UPX, MPRESS, ASPACK, THEMIDA, etc.)
/// Returns the matched marker name if found.
pub fn contains_packer_marker(path: &Path) -> io::Result<Option<String>> {
    let mut f = File::open(path)?;
    let mut buf = Vec::new();
    let _ = f.by_ref().take(2 * 1024 * 1024).read_to_end(&mut buf)?;
    let hay = &buf;
    // common ASCII markers (strings), case-insensitive where appropriate
    let patterns = [
        "UPX", "UPX0", "UPX1", "MPRESS", "ASPACK", "PEPACK", "THEMIDA", "KPACK", "MEW", "PACK",
    ];
    for p in patterns.iter() {
        let pb = p.as_bytes();
        if hay.windows(pb.len()).any(|w| w.eq_ignore_ascii_case(pb)) {
            return Ok(Some(p.to_string()));
        }
    }
    Ok(None)
}

/// Compute Shannon entropy over the file bytes (sampled up to 4MiB).
pub fn shannon_entropy(path: &Path) -> io::Result<f64> {
    let mut f = File::open(path)?;
    let mut buf = Vec::new();
    let _ = f.by_ref().take(4 * 1024 * 1024).read_to_end(&mut buf)?;
    if buf.is_empty() {
        return Ok(0.0);
    }
    let mut counts = [0usize; 256];
    for &b in &buf {
        counts[b as usize] += 1;
    }
    let len = buf.len() as f64;
    let mut entropy = 0.0f64;
    for &c in &counts {
        if c == 0 { continue; }
        let p = (c as f64) / len;
        entropy -= p * p.log2();
    }
    Ok(entropy)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;
    use std::io::Write;

    #[test]
    fn test_entropy_low() {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(&vec![0u8; 1024]).unwrap();
        let e = shannon_entropy(f.path()).unwrap();
        assert!(e < 0.01);
    }

    #[test]
    fn test_upx_marker() {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(b"\x00UPX0\x00").unwrap();
        let found = contains_upx_marker(f.path()).unwrap();
        assert!(found);
    }

    #[test]
    fn test_packer_marker_generic() {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(b"helloMPRESSworld").unwrap();
        let found = contains_packer_marker(f.path()).unwrap();
        assert_eq!(found.unwrap().to_uppercase(), "MPRESS");
    }
}
