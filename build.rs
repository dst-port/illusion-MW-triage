use std::env;
use std::fs;
use std::path::Path;

fn main() {
    let manifest = env::var("CARGO_MANIFEST_DIR").unwrap();
    let out_path = Path::new(&manifest).join("src/impersonation_confusables_gen.rs");
    let contents = r#"// Generated placeholder for confusable mappings.
pub fn generated_confusable(_c: char) -> Option<char> {
    None
}
"#;
    let _ = fs::write(out_path, contents);
}
