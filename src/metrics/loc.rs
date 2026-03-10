//! Lines of Code (LOC) counting utilities

use crate::metrics::models::LocMetrics;

pub struct LocCounter;

impl LocCounter {
    pub fn count(content: &str) -> LocMetrics {
        let lines: Vec<&str> = content.lines().collect();
        let total_lines = lines.len();

        let mut code_lines = 0;
        let mut comment_lines = 0;
        let mut blank_lines = 0;

        let mut in_block_comment = false;

        for line in &lines {
            let trimmed = line.trim();

            if trimmed.is_empty() {
                blank_lines += 1;
                continue;
            }

            if in_block_comment {
                comment_lines += 1;
                if trimmed.contains("*/") {
                    in_block_comment = false;
                }
                continue;
            }

            if trimmed.starts_with("//") || trimmed.starts_with('#') {
                comment_lines += 1;
                continue;
            }

            if trimmed.starts_with("/*") {
                comment_lines += 1;
                if !trimmed.contains("*/") {
                    in_block_comment = true;
                }
                continue;
            }

            if trimmed.starts_with("<!--") {
                comment_lines += 1;
                if !trimmed.contains("-->") {
                    in_block_comment = true;
                }
                continue;
            }

            if trimmed.starts_with("=begin") {
                comment_lines += 1;
                in_block_comment = true;
                continue;
            }

            if trimmed.starts_with("=end") {
                comment_lines += 1;
                in_block_comment = false;
                continue;
            }

            if trimmed.starts_with("'''") || trimmed.starts_with("\"\"\"") {
                comment_lines += 1;
                in_block_comment = !in_block_comment;
                continue;
            }

            let code_part = remove_inline_comment(trimmed);
            if !code_part.trim().is_empty() {
                code_lines += 1;
            } else if trimmed.contains("//") || trimmed.contains('#') {
                comment_lines += 1;
            }
        }

        LocMetrics {
            total_lines,
            code_lines,
            comment_lines,
            blank_lines,
        }
    }

    pub fn count_code_lines(content: &str) -> usize {
        Self::count(content).code_lines
    }

    pub fn count_total_lines(content: &str) -> usize {
        content.lines().count()
    }
}

fn remove_inline_comment(line: &str) -> &str {
    let mut in_string = false;
    let mut string_char = ' ';
    let mut escaped = false;

    for (i, c) in line.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }

        if c == '\\' && in_string {
            escaped = true;
            continue;
        }

        if (c == '"' || c == '\'' || c == '`') && !in_string {
            in_string = true;
            string_char = c;
            continue;
        }

        if in_string && c == string_char {
            in_string = false;
            continue;
        }

        if !in_string && (c == '/' && i + 1 < line.len() && line.chars().nth(i + 1) == Some('/')) {
            return &line[..i];
        }

        if !in_string && c == '#' {
            return &line[..i];
        }
    }

    line
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_count_simple_code() {
        let code = r#"fn main() {
    println!("Hello");
}
"#;
        let metrics = LocCounter::count(code);
        assert_eq!(metrics.total_lines, 3);
        assert_eq!(metrics.code_lines, 3);
        assert_eq!(metrics.comment_lines, 0);
        assert_eq!(metrics.blank_lines, 0);
    }

    #[test]
    fn test_count_with_blank_lines() {
        let code = r#"fn main() {

    println!("Hello");

}
"#;
        let metrics = LocCounter::count(code);
        assert_eq!(metrics.total_lines, 5);
        assert_eq!(metrics.code_lines, 3);
        assert_eq!(metrics.blank_lines, 2);
    }

    #[test]
    fn test_count_with_comments() {
        let code = r#"// This is a comment
fn main() {
    // Another comment
    println!("Hello"); // inline comment
}
"#;
        let metrics = LocCounter::count(code);
        assert_eq!(metrics.code_lines, 3);
        assert!(metrics.comment_lines >= 2);
    }

    #[test]
    fn test_count_block_comment() {
        let code = r#"fn main() {
    /* This is a
       multi-line
       comment */
    println!("Hello");
}
"#;
        let metrics = LocCounter::count(code);
        assert_eq!(metrics.total_lines, 6);
        assert!(metrics.comment_lines >= 3);
    }

    #[test]
    fn test_count_python_comments() {
        let code = r#"# Python comment
def main():
    # Another comment
    print("Hello")
"#;
        let metrics = LocCounter::count(code);
        assert!(metrics.comment_lines >= 2);
    }

    #[test]
    fn test_inline_comment_in_string() {
        let line = r#"let s = "not a // comment";"#;
        let result = remove_inline_comment(line);
        assert_eq!(result, line);
    }

    #[test]
    fn test_real_inline_comment() {
        let line = r#"let x = 1; // real comment"#;
        let result = remove_inline_comment(line);
        assert_eq!(result, "let x = 1; ");
    }
}
