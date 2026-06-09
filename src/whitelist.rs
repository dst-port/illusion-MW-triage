use serde::{Deserialize, Serialize};
use std::fs;
use std::io;
use std::path::Path;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub name: String,
    pub sha256: String,
    pub notes: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct Whitelist {
    pub entries: Vec<Entry>,
}

impl Whitelist {
    pub fn load(path: &Path) -> io::Result<Self> {
        let s = fs::read_to_string(path)?;
        let wl: Whitelist =
            toml::from_str(&s).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        Ok(wl)
    }

    pub fn save(&self, path: &Path) -> io::Result<()> {
        let s =
            toml::to_string(&self).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        fs::write(path, s)
    }

    pub fn add_entry(&mut self, name: String, sha256: String) {
        self.entries.push(Entry {
            name,
            sha256,
            notes: None,
        });
    }

    pub fn is_whitelisted(&self, name: &str, sha256: &str) -> bool {
        self.entries
            .iter()
            .any(|e| e.name == name && e.sha256 == sha256)
    }

    pub fn lookup_by_name(&self, name: &str) -> Option<String> {
        self.entries
            .iter()
            .find(|e| e.name == name)
            .map(|e| e.sha256.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_whitelist_roundtrip() {
        let mut wl = Whitelist::default();
        wl.add_entry("goodbin".to_string(), "abcd1234".to_string());

        let f = NamedTempFile::new().expect("tempfile");
        wl.save(f.path()).expect("save");

        let loaded = Whitelist::load(f.path()).expect("load");
        assert_eq!(loaded.entries.len(), 1);
        assert_eq!(loaded.entries[0].name, "goodbin");
        assert_eq!(loaded.entries[0].sha256, "abcd1234");
    }
}
