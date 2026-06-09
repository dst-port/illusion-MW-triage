use goblin::Object;
use std::io;
use std::path::Path;

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
        Object::PE(pe) => {
            let entry = pe.entry as u64;
            // Find section that contains the entry and compute file offset
            for sec in &pe.sections {
                let va = sec.virtual_address as u64;
                let vsz = sec.virtual_size as u64;
                if entry >= va && entry < va + vsz {
                    let offset = (entry - va) + sec.pointer_to_raw_data as u64;
                    let start = offset.saturating_sub(window as u64);
                    let end = std::cmp::min(offset + window as u64, buf.len() as u64);
                    let bytes = buf[start as usize..end as usize].to_vec();
                    let packed = detect_simple_packer(&buf);
                    return Ok(Some(EntryInfo {
                        addr: entry,
                        offset,
                        bytes,
                        packed,
                    }));
                }
            }
            Ok(None)
        }
        _ => Ok(None),
    }
}

fn detect_simple_packer(buf: &[u8]) -> Option<String> {
    if buf.windows(4).any(|w| w == b"UPX!") {
        Some("UPX suspected".to_string())
    } else {
        None
    }
}
