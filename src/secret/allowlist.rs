//! Allowlist system for reducing false positives
//!
//! Provides patterns and functions to identify and filter out
//! placeholder values, test credentials, and known safe patterns.

use once_cell::sync::Lazy;
use regex::Regex;

/// Global allowlist patterns for known safe values
static GLOBAL_ALLOWLIST: Lazy<Vec<Regex>> = Lazy::new(|| {
    let patterns = [
        r"^example$",
        r"^test$",
        r"^dummy$",
        r"^fake$",
        r"^placeholder$",
        r"^your_\w+_here$",
        r"^insert_\w+_here$",
        r"^\*+$",
        r"^x+$",
        r"^X+$",
        r"^0+$",
        r"^[aA]+$",
        r"example\.com",
        r"test\.com",
        r"localhost",
        r"127\.0\.0\.1",
    ];

    patterns.iter().filter_map(|p| Regex::new(p).ok()).collect()
});

/// Path patterns to ignore during scanning
static IGNORE_PATH_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    let patterns = [
        r"vendor/",
        r"node_modules/",
        r"\.git/",
        r"__pycache__/",
        r"\.pytest_cache/",
        r"target/debug/",
        r"target/release/",
        r"dist/",
        r"build/",
        r"\.next/",
        r"\.venv/",
        r"venv/",
        r"\.idea/",
        r"\.vscode/",
        r"\.lock$",
        r"package-lock\.json$",
        r"yarn\.lock$",
        r"Cargo\.lock$",
        r"poetry\.lock$",
        r"\.min\.js$",
        r"\.min\.css$",
        r"_test\.",
        r"\.test\.",
        r"_spec\.",
        r"\.spec\.",
        r"/tests?/",
        r"/__tests__/",
        r"CHANGELOG",
        r"LICENSE",
        r"README",
        r"\.md$",
    ];

    patterns.iter().filter_map(|p| Regex::new(p).ok()).collect()
});

/// Checks if a match is in the allowlist
pub fn is_allowlisted(text: &str, allowlist: &[Regex]) -> bool {
    allowlist.iter().any(|re| re.is_match(text))
}

/// Checks if text looks like a placeholder/fake value
pub fn looks_like_placeholder(text: &str) -> bool {
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
pub fn is_repetitive(text: &str) -> bool {
    if text.len() < 4 {
        return false;
    }

    let unique_chars: std::collections::HashSet<char> = text.chars().collect();
    let unique_ratio = unique_chars.len() as f64 / text.len() as f64;

    unique_ratio < 0.2
}

/// Returns the global allowlist patterns
pub fn get_global_allowlist() -> &'static Vec<Regex> {
    &GLOBAL_ALLOWLIST
}

/// Returns the ignore path patterns
pub fn get_ignore_path_patterns() -> &'static Vec<Regex> {
    &IGNORE_PATH_PATTERNS
}

/// Checks if the path contains path traversal attempt (..)
pub fn contains_path_traversal(path: &str) -> bool {
    let normalized = path.replace('\\', "/");

    if normalized.starts_with('/') {
        return true;
    }

    if normalized.len() >= 2
        && normalized.chars().nth(1) == Some(':')
        && normalized
            .chars()
            .next()
            .map(|c| c.is_ascii_alphabetic())
            .unwrap_or(false)
    {
        return true;
    }

    normalized.split('/').any(|component| component == "..")
}

/// Checks if a path should be ignored based on custom patterns
pub fn should_ignore_path(path: &str, ignore_patterns: &[String]) -> bool {
    ignore_patterns.iter().any(|pattern| {
        if let Ok(re) = Regex::new(pattern) {
            re.is_match(path)
        } else {
            path.contains(pattern)
        }
    })
}

/// Checks if a path should be ignored based on global patterns
pub fn is_global_ignored_path(path: &str) -> bool {
    IGNORE_PATH_PATTERNS.iter().any(|re| re.is_match(path))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_looks_like_placeholder() {
        assert!(looks_like_placeholder("EXAMPLE_KEY"));
        assert!(looks_like_placeholder("test_token"));
        assert!(looks_like_placeholder("DUMMY_SECRET"));
        assert!(looks_like_placeholder("PLACEHOLDER_VALUE"));
        assert!(looks_like_placeholder("YOUR_KEY_HERE"));
        assert!(!looks_like_placeholder("AKIAIOSFODNN7REAL12"));
    }

    #[test]
    fn test_is_repetitive() {
        assert!(is_repetitive("aaaaaaaaaaaa"));
        assert!(is_repetitive("abababababab"));
        assert!(is_repetitive("000000000000"));
        assert!(!is_repetitive("1a2b3c4d5e6f7890"));
        assert!(!is_repetitive("FAKE_KEY_abcdefghijklmnopqrstuvwxyz"));
    }

    #[test]
    fn test_contains_path_traversal() {
        assert!(contains_path_traversal("../etc/passwd"));
        assert!(contains_path_traversal("foo/../../bar"));
        assert!(contains_path_traversal("/absolute/path"));
        assert!(contains_path_traversal("C:\\Windows\\System32"));
        assert!(!contains_path_traversal("src/main.rs"));
        assert!(!contains_path_traversal("lib/module/file.rs"));
    }

    #[test]
    fn test_should_ignore_path() {
        let patterns = vec!["node_modules/".to_string(), r"\.test\.".to_string()];
        assert!(should_ignore_path("node_modules/foo/bar.js", &patterns));
        assert!(should_ignore_path("src/utils.test.js", &patterns));
        assert!(!should_ignore_path("src/utils.js", &patterns));
    }

    #[test]
    fn test_is_global_ignored_path() {
        assert!(is_global_ignored_path("vendor/lib/foo.php"));
        assert!(is_global_ignored_path("node_modules/react/index.js"));
        assert!(is_global_ignored_path("dist/bundle.min.js"));
        assert!(is_global_ignored_path("target/release/binary"));
        assert!(!is_global_ignored_path("src/main.rs"));
    }
}
