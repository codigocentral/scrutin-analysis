//! Secret masking utilities
//!
//! Provides functions to mask sensitive values for safe display.

/// Finds the byte index of the n-th char from the start.
/// Returns `len` if the string has fewer than `n` chars.
fn char_start(s: &str, n: usize) -> usize {
    s.char_indices()
        .nth(n)
        .map(|(i, _)| i)
        .unwrap_or(s.len())
}

/// Finds the byte index where the last `n` chars begin.
/// Returns 0 if the string has fewer than `n` chars.
fn char_end(s: &str, n: usize) -> usize {
    let total = s.chars().count();
    if n >= total {
        return 0;
    }
    char_start(s, total - n)
}

/// Masks a secret for safe display
/// Shows: first 4 chars + `****` + last 4 chars (if >12 chars)
/// Or: first 2 chars + `****` (if <=12 chars)
pub fn mask_secret(secret: &str) -> String {
    let char_count = secret.chars().count();

    if char_count <= 8 {
        let prefix_end = char_start(secret, 2.min(char_count));
        format!("{}****", &secret[..prefix_end])
    } else if char_count <= 12 {
        let prefix_end = char_start(secret, 2);
        let suffix_start = char_end(secret, 2);
        format!("{}****{}", &secret[..prefix_end], &secret[suffix_start..])
    } else {
        let prefix_end = char_start(secret, 4);
        let suffix_start = char_end(secret, 4);
        format!("{}****{}", &secret[..prefix_end], &secret[suffix_start..])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mask_secret_short() {
        assert_eq!(mask_secret("abc"), "ab****");
        assert_eq!(mask_secret("abcdefgh"), "ab****");
    }

    #[test]
    fn test_mask_secret_medium() {
        assert_eq!(mask_secret("abcdefghijkl"), "ab****kl");
    }

    #[test]
    fn test_mask_secret_long() {
        assert_eq!(mask_secret("AKIAIOSFODNN7EXAMPLE"), "AKIA****MPLE");
        assert_eq!(
            mask_secret("ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"),
            "ghp_****xxxx"
        );
    }

    #[test]
    fn test_mask_secret_unicode() {
        // Should not panic on multi-byte UTF-8 characters
        assert_eq!(mask_secret("¿Olvidaste tu contraseña?"), "¿Olv****eña?");
        assert_eq!(mask_secret("パスワード忘れました"), "パス****した"); // 10 chars → medium branch (first 2 + last 2)
        assert_eq!(mask_secret("café"), "ca****");
        assert_eq!(mask_secret("🔑secret🔒key"), "🔑s****ey"); // 11 chars → medium branch (first 2 + last 2)
    }

    #[test]
    fn test_mask_secret_empty() {
        assert_eq!(mask_secret(""), "****");
        assert_eq!(mask_secret("a"), "a****");
    }
}
