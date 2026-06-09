use std::env;
use std::fs;
use std::path::Path;

fn main() {
    // Generate a small helper file that can be replaced by a fuller CLDR-based
    // confusables generator. If a user places a custom mapping in the repo
    // and modifies this script, it will be embedded at build time.
    let manifest = env::var("CARGO_MANIFEST_DIR").unwrap();
    let out_path = Path::new(&manifest).join("src/impersonation_confusables_gen.rs");
    let contents = r#"// Generated placeholder for confusable mappings.
// Replace by a richer generator that parses CLDR confusables and emits
// a mapping from confusable char -> ASCII approximation.
pub fn generated_confusable(_c: char) -> Option<char> {
    None
}
"#;
    let _ = fs::write(out_path, contents);
}
