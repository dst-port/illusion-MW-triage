use std::path::Path;
use std::io;
use goblin::Object;
use goblin::elf::program_header::PT_LOAD;

#[derive(Debug, Clone)]
pub struct EntryInfo {
    pub addr: u64,
    pub offset: u64,
    pub bytes: Vec<u8>,
    pub packed: Option<String>,
}

pub fn extract_entry_snippet(path: &Path, window: usize) -> io::Result<Option<EntryInfo>> {
    let buf = std::fs::read(path)?;
    match Object::parse(&buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))? {
        Object::Elf(elf) => {
            let entry = elf.header.e_entry;
            for ph in &elf.program_headers {
                if ph.p_type == PT_LOAD && entry >= ph.p_vaddr && entry < ph.p_vaddr + ph.p_memsz {
                    let offset = (entry - ph.p_vaddr) + ph.p_offset;
                    let start = if offset > window as u64 { offset - window as u64 } else { 0 };
                    let end = std::cmp::min(offset + window as u64, buf.len() as u64);
                    let bytes = buf[start as usize..end as usize].to_vec();
                    let packed = detect_upx(&buf);
                    return Ok(Some(EntryInfo { addr: entry, offset, bytes, packed }));
                }
            }
            Ok(None)
        }
        _ => Ok(None),
    }
}

fn detect_upx(buf: &[u8]) -> Option<String> {
    if buf.windows(4).any(|w| w == b"UPX!") {
        Some("UPX suspected".to_string())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;
    use std::io::Write;

    #[test]
    fn test_non_elf_returns_none() {
        let mut f = NamedTempFile::new().expect("tempfile");
        write!(f, "this is not an elf").expect("write");
        let r = extract_entry_snippet(f.path(), 16).expect("call");
        assert!(r.is_none());
    }
}
