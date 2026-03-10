//! Rust function parser

use once_cell::sync::Lazy;
use regex::Regex;

use crate::detect::Language;
use crate::metrics::languages::FunctionParser;
use crate::metrics::models::FunctionSpan;

static FUNCTION_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?:pub\s+)?(?:async\s+)?(?:const\s+)?fn\s+(\w+)\s*(?:<[^>]*>)?\s*\(([^)]*)\)")
        .unwrap()
});

#[allow(dead_code)]
static METHOD_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"fn\s+(\w+)\s*\((?:&(?:mut\s+)?self|mut\s+self|self)\s*(?:,\s*([^)]*))?\)").unwrap()
});

#[allow(dead_code)]
static TRAIT_METHOD_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"fn\s+(\w+)\s*\(([^)]*)\)\s*(?::\s*[^;{]+)?\s*[;{]").unwrap());

pub struct RustParser;

impl FunctionParser for RustParser {
    fn language(&self) -> Language {
        Language::Rust
    }

    fn detect_functions(&self, content: &str) -> Vec<FunctionSpan> {
        let lines: Vec<&str> = content.lines().collect();
        let mut functions = Vec::new();
        let mut processed_ranges: Vec<(usize, usize)> = Vec::new();

        for (i, line) in lines.iter().enumerate() {
            let already_processed = processed_ranges
                .iter()
                .any(|(start, end)| i >= *start && i < *end);

            if already_processed {
                continue;
            }

            let trimmed = line.trim();

            if trimmed.starts_with("//") || trimmed.starts_with("/*") || trimmed.starts_with("///")
            {
                continue;
            }

            if let Some(result) = try_parse_function(line, i, &lines) {
                processed_ranges.push((i, result.end_line));
                functions.push(result);
            }
        }

        functions
    }
}

fn try_parse_function(line: &str, line_idx: usize, lines: &[&str]) -> Option<FunctionSpan> {
    if let Some(captures) = FUNCTION_REGEX.captures(line) {
        let name = captures.get(1).map(|m| m.as_str()).unwrap_or("unknown");
        let params_str = captures.get(2).map(|m| m.as_str()).unwrap_or("");
        let parameters = parse_rust_parameters(params_str);

        let is_trait_declaration = is_trait_method(line, lines, line_idx);

        let end_line = if is_trait_declaration {
            find_trait_method_end(lines, line_idx)
        } else {
            find_brace_end(lines, line_idx)
        };

        let body = extract_body(lines, line_idx, end_line);

        return Some(FunctionSpan {
            name: name.to_string(),
            start_line: line_idx + 1,
            end_line,
            body,
            parameters,
        });
    }

    None
}

fn is_trait_method(line: &str, lines: &[&str], line_idx: usize) -> bool {
    let has_semicolon = line.trim().ends_with(';');

    if has_semicolon {
        for i in (0..line_idx).rev() {
            let prev_line = lines[i].trim();
            if prev_line.starts_with("//") || prev_line.is_empty() {
                continue;
            }
            if prev_line.contains("trait ") {
                return true;
            }
            if prev_line.contains("impl ") {
                return false;
            }
            break;
        }
    }

    false
}

fn parse_rust_parameters(params_str: &str) -> Vec<String> {
    if params_str.trim().is_empty() {
        return Vec::new();
    }

    let mut params = Vec::new();
    let mut depth = 0;
    let mut current = String::new();

    for c in params_str.chars() {
        match c {
            '<' | '(' | '[' | '{' => {
                depth += 1;
                current.push(c);
            }
            '>' | ')' | ']' | '}' => {
                depth -= 1;
                current.push(c);
            }
            ',' if depth == 0 => {
                let param = current.trim();
                if !param.is_empty() && !is_self_param(param) {
                    if let Some(name) = extract_rust_param_name(param) {
                        params.push(name);
                    }
                }
                current.clear();
            }
            _ => {
                current.push(c);
            }
        }
    }

    let param = current.trim();
    if !param.is_empty() && !is_self_param(param) {
        if let Some(name) = extract_rust_param_name(param) {
            params.push(name);
        }
    }

    params
}

fn is_self_param(param: &str) -> bool {
    let param = param.trim();
    param == "self" || param == "&self" || param == "&mut self" || param == "mut self"
}

fn extract_rust_param_name(param: &str) -> Option<String> {
    let param = param.trim();

    if param.starts_with("mut ") {
        let rest = &param[4..].trim();
        return extract_rust_param_name(rest);
    }

    let parts: Vec<&str> = param.split(':').collect();
    if parts.is_empty() {
        return None;
    }

    let name = parts[0].trim();
    let name = name.trim_start_matches('&').trim();
    let name = name.trim_start_matches("mut ").trim();

    if name.is_empty() || name.starts_with('_') && name.len() == 1 {
        return None;
    }

    Some(name.to_string())
}

fn find_brace_end(lines: &[&str], start_idx: usize) -> usize {
    let mut brace_count = 0i32;
    let mut found_open = false;

    for i in start_idx..lines.len() {
        let line = lines[i];
        let mut in_string = false;
        let mut in_char = false;
        let mut in_block_comment = false;
        let mut prev_char = ' ';

        for c in line.chars() {
            if in_block_comment {
                if prev_char == '*' && c == '/' {
                    in_block_comment = false;
                }
                prev_char = c;
                continue;
            }

            match c {
                '"' if prev_char != '\\' && !in_char => {
                    in_string = !in_string;
                }
                '\'' if prev_char != '\\' && !in_string => {
                    in_char = !in_char;
                }
                '/' if prev_char == '/' && !in_string && !in_char => {
                    break;
                }
                '*' if prev_char == '/' && !in_string && !in_char => {
                    in_block_comment = true;
                }
                '{' if !in_string && !in_char => {
                    brace_count += 1;
                    found_open = true;
                }
                '}' if !in_string && !in_char => {
                    brace_count -= 1;
                    if found_open && brace_count == 0 {
                        return i + 1;
                    }
                }
                _ => {}
            }
            prev_char = c;
        }
    }

    lines.len()
}

fn find_trait_method_end(lines: &[&str], start_idx: usize) -> usize {
    let line = lines[start_idx];
    if line.trim().ends_with(';') {
        return start_idx + 1;
    }
    find_brace_end(lines, start_idx)
}

fn extract_body(lines: &[&str], start_idx: usize, end_idx: usize) -> String {
    lines[start_idx..end_idx.min(lines.len())].join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_simple_function() {
        let code = r#"
fn hello() {
    println!("Hello");
}
"#;
        let parser = RustParser;
        let functions = parser.detect_functions(code);
        assert_eq!(functions.len(), 1);
        assert_eq!(functions[0].name, "hello");
    }

    #[test]
    fn test_detect_function_with_params() {
        let code = r#"
fn add(a: i32, b: i32) -> i32 {
    a + b
}
"#;
        let parser = RustParser;
        let functions = parser.detect_functions(code);
        assert_eq!(functions.len(), 1);
        assert_eq!(functions[0].name, "add");
        assert_eq!(functions[0].parameters.len(), 2);
    }

    #[test]
    fn test_detect_pub_function() {
        let code = r#"
pub fn public_function() {
    // code
}
"#;
        let parser = RustParser;
        let functions = parser.detect_functions(code);
        assert_eq!(functions.len(), 1);
        assert_eq!(functions[0].name, "public_function");
    }

    #[test]
    fn test_detect_async_function() {
        let code = r#"
async fn fetch_data() -> Result<String, Error> {
    // async code
}
"#;
        let parser = RustParser;
        let functions = parser.detect_functions(code);
        assert_eq!(functions.len(), 1);
        assert_eq!(functions[0].name, "fetch_data");
    }

    #[test]
    fn test_detect_generic_function() {
        let code = r#"
fn identity<T>(value: T) -> T {
    value
}
"#;
        let parser = RustParser;
        let functions = parser.detect_functions(code);
        assert_eq!(functions.len(), 1);
        assert_eq!(functions[0].name, "identity");
    }

    #[test]
    fn test_detect_impl_method() {
        let code = r#"
impl Calculator {
    fn add(&self, a: i32, b: i32) -> i32 {
        a + b
    }
}
"#;
        let parser = RustParser;
        let functions = parser.detect_functions(code);
        assert_eq!(functions.len(), 1);
        assert_eq!(functions[0].name, "add");
        assert_eq!(functions[0].parameters.len(), 2);
    }

    #[test]
    fn test_detect_multiple_functions() {
        let code = r#"
fn foo() {}
fn bar() {}
fn baz() {}
"#;
        let parser = RustParser;
        let functions = parser.detect_functions(code);
        assert_eq!(functions.len(), 3);
    }
}
