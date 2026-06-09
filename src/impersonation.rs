use strsim::jaro_winkler;
use unicode_normalization::UnicodeNormalization;
use std::char;

// Include build-generated confusable helper (may be a no-op placeholder)
include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/impersonation_confusables_gen.rs"));

/// Return a similarity score in [0.0, 1.0] between two strings using Jaro-Winkler.
pub fn similarity_score(a: &str, b: &str) -> f64 {
    jaro_winkler(a, b)
}

/// Simple heuristic: returns true if the string contains non-ASCII characters.
/// This is a lightweight proxy for potential homoglyph/confusable characters.
pub fn has_non_ascii(s: &str) -> bool {
    s.chars().any(|c| c as u32 > 0x7F)
}

/// Normalize to NFKC and lower-case for comparison convenience.
pub fn normalize_name(s: &str) -> String {
    s.nfkc().collect::<String>().to_lowercase()
}

/// Fold common homoglyphs/confusables into ASCII equivalents.
/// This is intentionally small and conservative — expand as needed.
pub fn fold_confusables(s: &str) -> String {
    s.chars()
        .map(|ch| {
            // allow build-generated mapping first
            if let Some(m) = generated_confusable(ch) {
                return m;
            }

            match ch {
                '\u{0251}' => 'a', // latin small letter alpha (looks like 'a')

                // Cyrillic -> Latin (preserve case where applicable)
                '\u{0410}' | '\u{0430}' => 'a', // А а
                '\u{0412}' | '\u{0432}' => 'b', // В в -> looks like B/b
                '\u{0415}' | '\u{0435}' => 'e', // Е е
                '\u{041E}' | '\u{043E}' => 'o', // О о
                '\u{0420}' | '\u{0440}' => 'p', // Р р
                '\u{0421}' | '\u{0441}' => 'c', // С с
                '\u{0422}' | '\u{0442}' => 't', // Т т
                '\u{041C}' | '\u{043C}' => 'm', // М м
                '\u{0418}' | '\u{0438}' => 'i', // И и
                '\u{0423}' | '\u{0443}' => 'y', // У у -> Y/y (approx)
                '\u{0425}' | '\u{0445}' => 'x', // Х х -> X/x
                '\u{041D}' | '\u{043D}' => 'h', // Н н -> H/h
                '\u{041A}' | '\u{043A}' => 'k', // К к

                // Greek -> Latin approximations
                '\u{0391}' | '\u{03B1}' => 'a', // Alpha
                '\u{0392}' | '\u{03B2}' => 'b', // Beta
                '\u{0395}' | '\u{03B5}' => 'e', // Epsilon
                '\u{039F}' | '\u{03BF}' => 'o', // Omicron
                '\u{03A1}' | '\u{03C1}' => 'p', // Rho -> p (lowercase)

                // Latin fullwidth range -> ASCII
                v if ('\u{FF01}'..='\u{FF5E}').contains(&v) => {
                    // convert fullwidth ASCII variants back to ASCII
                    let code = (v as u32).saturating_sub(0xFEE0);
                    char::from_u32(code).unwrap_or(v)
                }

                // Dotless i and other common lookalikes
                '\u{0131}' => 'i', // dotless i

                _ => ch,
            }
        })
        .collect()
}

/// Normalize, fold confusables, and lower-case for comparison.
pub fn normalize_confusable_name(s: &str) -> String {
    let nfkc = s.nfkc().collect::<String>();
    fold_confusables(&nfkc).to_lowercase()
}

/// Detect potential masquerade against a list of known-good basenames.
/// Returns the best match and its similarity score if above `threshold`.
pub fn detect_masquerade<'a>(name: &str, candidates: &'a[&str], threshold: f64) -> Option<(&'a str, f64)> {
    let n = normalize_confusable_name(name);
    let mut best: Option<(&str, f64)> = None;
    for &c in candidates {
        let cnorm = normalize_confusable_name(c);
        let score = similarity_score(&n, &cnorm);
        if score >= threshold {
            if let Some((_, s)) = best {
                if score > s { best = Some((c, score)); }
            } else {
                best = Some((c, score));
            }
        }
    }
    best
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_similarity() {
        let a = "bash";
        let b = "bash";
        assert!(similarity_score(a, b) > 0.99);
        let c = "b\u{0251}sh"; // uses U+0251 latin small letter alpha (looks like 'a')
        assert!(has_non_ascii(&c));
        assert_eq!(fold_confusables(&c), "bash");
        assert_eq!(normalize_confusable_name(&c), "bash");
    }

    #[test]
    fn test_detect_masquerade() {
        let candidates = ["bash", "sshd", "sudo"];
        // exact match
        let res = detect_masquerade("bash", &candidates, 0.9);
        assert!(res.is_some());
        assert_eq!(res.unwrap().0, "bash");

        // confusable match (uses U+0251 for 'a')
        let res2 = detect_masquerade("b\u{0251}sh", &candidates, 0.9);
        assert!(res2.is_some());
        assert_eq!(res2.unwrap().0, "bash");

        // near match should not match if threshold high
        let res3 = detect_masquerade("b4sh", &candidates, 0.9);
        assert!(res3.is_none());
    }
}
