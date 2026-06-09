use std::char;
use strsim::jaro_winkler;
use unicode_normalization::UnicodeNormalization;

include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/src/impersonation_confusables_gen.rs"
));

pub fn similarity_score(a: &str, b: &str) -> f64 {
    jaro_winkler(a, b)
}

pub fn has_non_ascii(s: &str) -> bool {
    s.chars().any(|c| c as u32 > 0x7F)
}

pub fn normalize_name(s: &str) -> String {
    s.nfkc().collect::<String>().to_lowercase()
}

pub fn fold_confusables(s: &str) -> String {
    s.chars()
        .map(|ch| {
            if let Some(m) = generated_confusable(ch) {
                return m;
            }

            match ch {
                '\u{0251}' => 'a',

                '\u{0410}' | '\u{0430}' => 'a',
                '\u{0412}' | '\u{0432}' => 'b',
                '\u{0415}' | '\u{0435}' => 'e',
                '\u{041E}' | '\u{043E}' => 'o',
                '\u{0420}' | '\u{0440}' => 'p',
                '\u{0421}' | '\u{0441}' => 'c',
                '\u{0422}' | '\u{0442}' => 't',
                '\u{041C}' | '\u{043C}' => 'm',
                '\u{0418}' | '\u{0438}' => 'i',
                '\u{0423}' | '\u{0443}' => 'y',
                '\u{0425}' | '\u{0445}' => 'x',
                '\u{041D}' | '\u{043D}' => 'h',
                '\u{041A}' | '\u{043A}' => 'k',

                '\u{0391}' | '\u{03B1}' => 'a',
                '\u{0392}' | '\u{03B2}' => 'b',
                '\u{0395}' | '\u{03B5}' => 'e',
                '\u{039F}' | '\u{03BF}' => 'o',
                '\u{03A1}' | '\u{03C1}' => 'p',

                v if ('\u{FF01}'..='\u{FF5E}').contains(&v) => {
                    let code = (v as u32).saturating_sub(0xFEE0);
                    char::from_u32(code).unwrap_or(v)
                }

                '\u{0131}' => 'i',

                _ => ch,
            }
        })
        .collect()
}

pub fn normalize_confusable_name(s: &str) -> String {
    let nfkc = s.nfkc().collect::<String>();
    fold_confusables(&nfkc).to_lowercase()
}

pub fn detect_masquerade<'a>(
    name: &str,
    candidates: &'a [&str],
    threshold: f64,
) -> Option<(&'a str, f64)> {
    let n = normalize_confusable_name(name);
    let mut best: Option<(&str, f64)> = None;
    for &c in candidates {
        let cnorm = normalize_confusable_name(c);
        let score = similarity_score(&n, &cnorm);
        if score >= threshold {
            if let Some((_, s)) = best {
                if score > s {
                    best = Some((c, score));
                }
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
        let c = "b\u{0251}sh";
        assert!(has_non_ascii(c));
        assert_eq!(fold_confusables(c), "bash");
        assert_eq!(normalize_confusable_name(c), "bash");
    }

    #[test]
    fn test_detect_masquerade() {
        let candidates = ["bash", "sshd", "sudo"];
        let res = detect_masquerade("bash", &candidates, 0.9);
        assert!(res.is_some());
        assert_eq!(res.unwrap().0, "bash");

        let res2 = detect_masquerade("b\u{0251}sh", &candidates, 0.9);
        assert!(res2.is_some());
        assert_eq!(res2.unwrap().0, "bash");

        let res3 = detect_masquerade("b4sh", &candidates, 0.9);
        assert!(res3.is_none());
    }
}
