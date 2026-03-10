//! Entropy-based detection for secrets
//!
//! Uses Shannon entropy to detect random tokens that don't match known patterns.

use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::HashMap;

static HIGH_ENTROPY_TOKEN_PATTERN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"[A-Za-z0-9+/=_-]{20,}").expect("Invalid high entropy token regex"));

static HIGH_ENTROPY_BASE64_PATTERN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"[A-Za-z0-9+/=_-]{40,}").expect("Invalid high entropy base64 regex"));

static HIGH_ENTROPY_HEX_PATTERN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"[a-f0-9]{32,}").expect("Invalid high entropy hex regex"));

/// Calculates Shannon entropy of a string (measure of randomness)
/// Returns value between 0 and 8 (bits per character for base64/hex)
pub fn calculate_entropy(text: &str) -> f64 {
    if text.is_empty() {
        return 0.0;
    }

    let mut char_counts: HashMap<char, usize> = HashMap::with_capacity(text.len().min(256));
    let len = text.len() as f64;

    for c in text.chars() {
        *char_counts.entry(c).or_insert(0) += 1;
    }

    let mut entropy = 0.0;
    for count in char_counts.values() {
        let probability = *count as f64 / len;
        if probability > 0.0 {
            entropy -= probability * probability.log2();
        }
    }

    entropy
}

/// Checks if a string has high entropy (indicative of secret/token)
/// threshold: minimum entropy value (default: 4.5 for base64, 3.5 for hex)
pub fn has_high_entropy(text: &str, threshold: f64) -> bool {
    calculate_entropy(text) >= threshold
}

/// Detects generic secrets based on high entropy
/// Useful for detecting tokens that don't follow known patterns
pub fn detect_high_entropy_tokens(
    content: &str,
    min_length: usize,
    entropy_threshold: f64,
) -> Vec<(String, f64)> {
    let mut findings = Vec::new();

    for mat in HIGH_ENTROPY_TOKEN_PATTERN.find_iter(content) {
        let token = mat.as_str();

        if looks_like_placeholder(token) {
            continue;
        }

        if token.len() >= min_length {
            let entropy = calculate_entropy(token);
            if entropy >= entropy_threshold {
                findings.push((token.to_string(), entropy));
            }
        }
    }

    findings
}

/// Detects high entropy base64 strings (possible tokens)
pub fn detect_high_entropy_base64(content: &str, min_length: usize) -> Vec<(String, f64)> {
    let mut findings = Vec::new();

    for mat in HIGH_ENTROPY_BASE64_PATTERN.find_iter(content) {
        let token = mat.as_str();

        if token.len() < min_length {
            continue;
        }

        if looks_like_placeholder(token) {
            continue;
        }

        let entropy = calculate_entropy(token);
        if entropy >= 5.0 {
            findings.push((token.to_string(), entropy));
        }
    }

    findings
}

/// Detects high entropy hex strings (possible hashes/secrets)
pub fn detect_high_entropy_hex(content: &str, min_length: usize) -> Vec<(String, f64)> {
    let mut findings = Vec::new();

    for mat in HIGH_ENTROPY_HEX_PATTERN.find_iter(content) {
        let token = mat.as_str();

        if token.len() < min_length {
            continue;
        }

        if looks_like_placeholder(token) || is_repetitive(token) {
            continue;
        }

        let entropy = calculate_entropy(token);
        if entropy >= 3.8 {
            findings.push((token.to_string(), entropy));
        }
    }

    findings
}

/// Checks if text looks like a placeholder/fake value
fn looks_like_placeholder(text: &str) -> bool {
    let placeholder_patterns = [
        "EXAMPLE",
        "example",
        "TEST",
        "test",
        "DUMMY",
        "dummy",
        "FAKE",
        "fake",
        "PLACEHOLDER",
        "placeholder",
        "SAMPLE",
        "sample",
        "XXXXXX",
        "xxxxxx",
        "000000",
        "111111",
        "YOUR_KEY_HERE",
        "REPLACE_ME",
        "replace_me",
        "INSERT_KEY",
        "API_KEY_HERE",
        "example.com",
        "test.com",
        "localhost",
        "127.0.0.1",
    ];

    let upper = text.to_uppercase();
    placeholder_patterns.iter().any(|p| upper.contains(p))
}

/// Checks if a string is repetitive (low actual entropy)
fn is_repetitive(text: &str) -> bool {
    if text.len() < 4 {
        return false;
    }

    let unique_chars: std::collections::HashSet<char> = text.chars().collect();
    let unique_ratio = unique_chars.len() as f64 / text.len() as f64;

    unique_ratio < 0.2
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_entropy_low() {
        let low = calculate_entropy("aaaaaaaaaa");
        assert!(
            low < 1.0,
            "Constant strings should have low entropy: {}",
            low
        );
    }

    #[test]
    fn test_calculate_entropy_high() {
        let high = calculate_entropy("aBc9xK2mPqRsTuVw");
        assert!(
            high > 3.5,
            "Random strings should have high entropy: {}",
            high
        );
    }

    #[test]
    fn test_calculate_entropy_hex() {
        let hex = calculate_entropy("1a2b3c4d5e6f7890");
        assert!(hex > 3.0, "Hex should have moderate entropy: {}", hex);
    }

    #[test]
    fn test_has_high_entropy() {
        assert!(has_high_entropy(
            "FAKE_KEY_abcdefghijklmnopqrstuvwxyz123456",
            4.0
        ));
        assert!(!has_high_entropy("test_test_test_test_test", 4.0));
        assert!(has_high_entropy("1a2b3c4d5e6f7890", 3.0));
    }

    #[test]
    fn test_detect_high_entropy_tokens() {
        let content = r#"
            const API_KEY = "rnd_Xk9mP2qL8nR4vJ6wT1yB5cF3hD7eG0iA";
            const safe = "this_is_a_test_value";
            const token = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
        "#;

        let findings = detect_high_entropy_tokens(content, 20, 4.0);
        assert!(!findings.is_empty(), "Should detect high entropy tokens");

        for (token, entropy) in &findings {
            assert!(
                *entropy >= 4.0,
                "Token {} should have entropy >= 4.0: {}",
                token,
                entropy
            );
        }
    }

    #[test]
    fn test_detect_high_entropy_base64() {
        let content = r#"key: aBc9xK2mPqRsTuVwXyZ1AbC3dEfGh5IjKlMnOpQr7StUvWxYz9aBcDeFgHiJk"#;
        let findings = detect_high_entropy_base64(content, 40);
        assert!(
            !findings.is_empty(),
            "Should detect high entropy base64: {:?}",
            findings
        );

        for (token, entropy) in &findings {
            assert!(
                *entropy >= 5.0,
                "Token {} should have entropy >= 5.0: {}",
                token,
                entropy
            );
        }
    }

    #[test]
    fn test_detect_high_entropy_hex() {
        let content = r#"
            const hash = "1a2b3c4d5e6f7890a1b2c3d4e5f6789a";
            const low_entropy = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        "#;

        let findings = detect_high_entropy_hex(content, 32);
        assert!(!findings.is_empty(), "Should detect high entropy hex");

        for (token, entropy) in &findings {
            assert!(
                *entropy >= 3.8,
                "Token {} should have entropy >= 3.8: {}",
                token,
                entropy
            );
        }
    }

    #[test]
    fn test_is_repetitive() {
        assert!(is_repetitive("aaaaaaaaaaaa"));
        assert!(is_repetitive("abababababab"));
        assert!(is_repetitive("000000000000"));
        assert!(!is_repetitive("1a2b3c4d5e6f7890"));
        assert!(!is_repetitive("FAKE_KEY_abcdefghijklmnopqrstuvwxyz"));
    }
}
