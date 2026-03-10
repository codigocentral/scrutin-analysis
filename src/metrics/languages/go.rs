//! Go function parser

use once_cell::sync::Lazy;
use regex::Regex;

use crate::detect::Language;
use crate::metrics::languages::FunctionParser;
use crate::metrics::models::FunctionSpan;

static FUNCTION_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"func\s+(?:\(([^)]+)\)\s+)?(\w+)\s*\(([^)]*)\)").unwrap());

static METHOD_RECEIVER_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"func\s+\((\w+)\s+(?:\*?)(\w+)\)\s+(\w+)\s*\(([^)]*)\)").unwrap());

pub struct GoParser;

impl FunctionParser for GoParser {
    fn language(&self) -> Language {
        Language::Go
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

            if trimmed.starts_with("//") {
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
    if let Some(captures) = METHOD_RECEIVER_REGEX.captures(line) {
        let _receiver_name = captures.get(1).map(|m| m.as_str()).unwrap_or("");
        let receiver_type = captures.get(2).map(|m| m.as_str()).unwrap_or("");
        let method_name = captures.get(3).map(|m| m.as_str()).unwrap_or("unknown");
        let params_str = captures.get(4).map(|m| m.as_str()).unwrap_or("");
        let parameters = parse_go_parameters(params_str);

        let full_name = format!("{}.{}", receiver_type, method_name);
        let end_line = find_brace_end(lines, line_idx);
        let body = extract_body(lines, line_idx, end_line);

        return Some(FunctionSpan {
            name: full_name,
            start_line: line_idx + 1,
            end_line,
            body,
            parameters,
        });
    }

    if let Some(captures) = FUNCTION_REGEX.captures(line) {
        let name = captures.get(2).map(|m| m.as_str()).unwrap_or("unknown");
        let params_str = captures.get(3).map(|m| m.as_str()).unwrap_or("");
        let parameters = parse_go_parameters(params_str);

        let end_line = find_brace_end(lines, line_idx);
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

fn parse_go_parameters(params_str: &str) -> Vec<String> {
    if params_str.trim().is_empty() {
        return Vec::new();
    }

    let mut params = Vec::new();
    // Go allows: "a, b int" (multiple names share type) or "a int, b string"
    // First split by comma to get parameter groups
    let groups: Vec<&str> = params_str.split(',').collect();

    let mut pending_names: Vec<String> = Vec::new();

    for group in groups {
        let group = group.trim();
        if group.is_empty() {
            continue;
        }

        // Check if this group has a type
        let parts: Vec<&str> = group.split_whitespace().collect();

        if parts.len() >= 2 {
            // This group has a type (e.g., "b int" or "x y int")
            // First, add any pending names (they share this type)
            for pending in &pending_names {
                params.push(pending.clone());
            }
            pending_names.clear();

            // Last part is the type
            // All parts except last are parameter names
            for i in 0..parts.len() - 1 {
                let name = parts[i].trim();
                if !name.is_empty() && !is_go_type(name) {
                    params.push(name.to_string());
                }
            }
        } else if parts.len() == 1 {
            // This might be just a name (part of "a, b int")
            let name = parts[0].trim();
            if !name.is_empty() && !is_go_type(name) {
                pending_names.push(name.to_string());
            }
        }
    }

    // Add any remaining pending names (shouldn't happen in valid Go)
    for name in pending_names {
        params.push(name);
    }

    params
}

#[allow(dead_code)]
fn split_go_params(params_str: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut depth = 0;

    for c in params_str.chars() {
        match c {
            '[' | '(' | '{' | '<' => {
                depth += 1;
                current.push(c);
            }
            ']' | ')' | '}' | '>' => {
                depth -= 1;
                current.push(c);
            }
            ',' if depth == 0 => {
                parts.push(current.trim().to_string());
                current.clear();
            }
            _ => {
                current.push(c);
            }
        }
    }

    if !current.trim().is_empty() {
        parts.push(current.trim().to_string());
    }

    parts
}

fn is_go_type(s: &str) -> bool {
    let types = [
        "string",
        "int",
        "int8",
        "int16",
        "int32",
        "int64",
        "uint",
        "uint8",
        "uint16",
        "uint32",
        "uint64",
        "float32",
        "float64",
        "bool",
        "rune",
        "byte",
        "complex64",
        "complex128",
        "error",
        "any",
    ];
    types.contains(&s) || s.chars().next().map(|c| c.is_uppercase()).unwrap_or(false)
}

fn find_brace_end(lines: &[&str], start_idx: usize) -> usize {
    let mut brace_count = 0i32;
    let mut found_open = false;

    for i in start_idx..lines.len() {
        for c in lines[i].chars() {
            match c {
                '{' => {
                    brace_count += 1;
                    found_open = true;
                }
                '}' => {
                    brace_count -= 1;
                    if found_open && brace_count == 0 {
                        return i + 1;
                    }
                }
                _ => {}
            }
        }
    }

    lines.len()
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
func hello() {
    fmt.Println("Hello")
}
"#;
        let parser = GoParser;
        let functions = parser.detect_functions(code);
        assert_eq!(functions.len(), 1);
        assert_eq!(functions[0].name, "hello");
    }

    #[test]
    fn test_detect_function_with_params() {
        let code = r#"
func add(a int, b int) int {
    return a + b
}
"#;
        let parser = GoParser;
        let functions = parser.detect_functions(code);
        assert_eq!(functions.len(), 1);
        assert_eq!(functions[0].name, "add");
        assert_eq!(functions[0].parameters.len(), 2);
    }

    #[test]
    fn test_detect_function_with_shared_type() {
        let code = r#"
func multiply(a, b int) int {
    return a * b
}
"#;
        let parser = GoParser;
        let functions = parser.detect_functions(code);
        assert_eq!(functions.len(), 1);
        assert_eq!(functions[0].name, "multiply");
        assert_eq!(functions[0].parameters.len(), 2);
    }

    #[test]
    fn test_detect_method() {
        let code = r#"
func (c *Calculator) Add(a, b int) int {
    return a + b
}
"#;
        let parser = GoParser;
        let functions = parser.detect_functions(code);
        assert_eq!(functions.len(), 1);
        assert!(functions[0].name.contains("Add"));
    }

    #[test]
    fn test_detect_multiple_functions() {
        let code = r#"
func foo() {}
func bar() {}
func baz() {}
"#;
        let parser = GoParser;
        let functions = parser.detect_functions(code);
        assert_eq!(functions.len(), 3);
    }
}
