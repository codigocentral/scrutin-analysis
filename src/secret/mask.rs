//! Secret masking utilities
//!
//! Provides functions to mask sensitive values for safe display.

/// Masks a secret for safe display
/// Shows: first 4 chars + `****` + last 4 chars (if >12 chars)
/// Or: first 2 chars + `****` (if <=12 chars)
pub fn mask_secret(secret: &str) -> String {
    let len = secret.len();

    if len <= 8 {
        format!("{}****", &secret[..2.min(len)])
    } else if len <= 12 {
        format!("{}****{}", &secret[..2], &secret[len - 2..])
    } else {
        format!("{}****{}", &secret[..4], &secret[len - 4..])
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
}
