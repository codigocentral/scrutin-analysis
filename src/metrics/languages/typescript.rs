//! TypeScript function parser
//!
//! Extends JavaScript parser with TypeScript-specific features

use once_cell::sync::Lazy;
use regex::Regex;

use crate::detect::Language;
use crate::metrics::languages::javascript::JavaScriptParser;
use crate::metrics::languages::FunctionParser;
use crate::metrics::models::FunctionSpan;

static TS_FUNCTION_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?:export\s+)?(?:async\s+)?function\s+(\w+)\s*<[^>]*>?\s*\(([^)]*)\)").unwrap()
});

static TS_ARROW_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?:export\s+)?(?:const|let|var)\s+(\w+)\s*(?::\s*[^=]+)?\s*=\s*(?:async\s*)?\(([^)]*)\)\s*(?::\s*[^=]+)?\s*=>",
    )
    .unwrap()
});

static TS_CLASS_METHOD_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?:public|private|protected|readonly|static|async)\s+(\w+)\s*\(([^)]*)\)(?:\s*:\s*[^{]+)?\s*\{",
    )
    .unwrap()
});

#[allow(dead_code)]
static TS_INTERFACE_METHOD_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^\s*(\w+)\s*\(([^)]*)\)\s*(?::\s*[^;]+)?\s*;").unwrap());

pub struct TypeScriptParser;

impl FunctionParser for TypeScriptParser {
    fn language(&self) -> Language {
        Language::TypeScript
    }

    fn detect_functions(&self, content: &str) -> Vec<FunctionSpan> {
        let mut functions = Vec::new();
        let lines: Vec<&str> = content.lines().collect();
        let mut processed_ranges: Vec<(usize, usize)> = Vec::new();

        for (i, line) in lines.iter().enumerate() {
            let already_processed = processed_ranges
                .iter()
                .any(|(start, end)| i >= *start && i < *end);

            if already_processed {
                continue;
            }

            if let Some(result) = try_parse_ts_function(line, i, &lines) {
                processed_ranges.push((i, result.end_line));
                functions.push(result);
                continue;
            }

            if let Some(result) = try_parse_ts_arrow(line, i, &lines) {
                processed_ranges.push((i, result.end_line));
                functions.push(result);
                continue;
            }

            if let Some(result) = try_parse_ts_method(line, i, &lines) {
                processed_ranges.push((i, result.end_line));
                functions.push(result);
            }
        }

        if functions.is_empty() {
            return JavaScriptParser.detect_functions(content);
        }

        functions
    }
}

fn try_parse_ts_function(line: &str, line_idx: usize, lines: &[&str]) -> Option<FunctionSpan> {
    if let Some(captures) = TS_FUNCTION_REGEX.captures(line) {
        let name = captures.get(1).map(|m| m.as_str()).unwrap_or("anonymous");
        let params_str = captures.get(2).map(|m| m.as_str()).unwrap_or("");
        let parameters = parse_ts_parameters(params_str);

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

fn try_parse_ts_arrow(line: &str, line_idx: usize, lines: &[&str]) -> Option<FunctionSpan> {
    if let Some(captures) = TS_ARROW_REGEX.captures(line) {
        let name = captures.get(1).map(|m| m.as_str()).unwrap_or("anonymous");
        let params_str = captures.get(2).map(|m| m.as_str()).unwrap_or("");
        let parameters = parse_ts_parameters(params_str);

        let has_brace = line
            .find("=>")
            .map(|i| &line[i..])
            .unwrap_or("")
            .contains('{');

        let (end_line, body) = if has_brace {
            let end = find_brace_end(lines, line_idx);
            (end, extract_body(lines, line_idx, end))
        } else {
            let end = find_statement_end(lines, line_idx);
            (end, extract_body(lines, line_idx, end))
        };

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

fn try_parse_ts_method(line: &str, line_idx: usize, lines: &[&str]) -> Option<FunctionSpan> {
    let trimmed = line.trim();

    if trimmed.starts_with("//") || trimmed.starts_with("*") || trimmed.starts_with("/*") {
        return None;
    }

    if trimmed.starts_with("if ")
        || trimmed.starts_with("if(")
        || trimmed.starts_with("while ")
        || trimmed.starts_with("while(")
        || trimmed.starts_with("for ")
        || trimmed.starts_with("for(")
        || trimmed.starts_with("switch ")
        || trimmed.starts_with("switch(")
        || trimmed.starts_with("catch ")
        || trimmed.starts_with("catch(")
    {
        return None;
    }

    if let Some(captures) = TS_CLASS_METHOD_REGEX.captures(line) {
        let name = captures.get(1).map(|m| m.as_str()).unwrap_or("anonymous");

        if name == "if" || name == "while" || name == "for" || name == "switch" || name == "catch" {
            return None;
        }

        let params_str = captures.get(2).map(|m| m.as_str()).unwrap_or("");
        let parameters = parse_ts_parameters(params_str);

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

fn parse_ts_parameters(params_str: &str) -> Vec<String> {
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
                if !param.is_empty() {
                    if let Some(name) = extract_param_name(param) {
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
    if !param.is_empty() {
        if let Some(name) = extract_param_name(param) {
            params.push(name);
        }
    }

    params
}

fn extract_param_name(param: &str) -> Option<String> {
    let param = param.trim();
    if param.is_empty() || param.starts_with('*') {
        return None;
    }

    let name = param.split(':').next().unwrap_or(param).trim();
    let name = name.split('=').next().unwrap_or(name).trim();
    let name = name.trim_start_matches("...").trim();
    let name = name.trim_start_matches("private ").trim();
    let name = name.trim_start_matches("public ").trim();
    let name = name.trim_start_matches("protected ").trim();
    let name = name.trim_start_matches("readonly ").trim();

    if name.is_empty() {
        None
    } else {
        Some(name.to_string())
    }
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

fn find_statement_end(lines: &[&str], start_idx: usize) -> usize {
    for i in start_idx..lines.len() {
        if lines[i].trim_end().ends_with(';') {
            return i + 1;
        }
    }
    (start_idx + 1).min(lines.len())
}

fn extract_body(lines: &[&str], start_idx: usize, end_idx: usize) -> String {
    lines[start_idx..end_idx.min(lines.len())].join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_ts_function_with_generics() {
        let code = r#"
function identity<T>(arg: T): T {
    return arg;
}
"#;
        let parser = TypeScriptParser;
        let functions = parser.detect_functions(code);
        assert_eq!(functions.len(), 1);
        assert_eq!(functions[0].name, "identity");
    }

    #[test]
    fn test_detect_ts_arrow_with_types() {
        let code = r#"
const add = (a: number, b: number): number => a + b;
"#;
        let parser = TypeScriptParser;
        let functions = parser.detect_functions(code);
        assert_eq!(functions.len(), 1);
        assert_eq!(functions[0].name, "add");
    }

    #[test]
    fn test_detect_ts_class_method() {
        let code = r#"class Calculator {
    public add(a: number, b: number): number {
        return a + b;
    }
}
"#;
        let parser = TypeScriptParser;
        let functions = parser.detect_functions(code);
        assert!(functions.iter().any(|f| f.name == "add"));
    }

    #[test]
    fn test_detect_export_function() {
        let code = r#"
export function hello(): void {
    console.log("Hello");
}
"#;
        let parser = TypeScriptParser;
        let functions = parser.detect_functions(code);
        assert_eq!(functions.len(), 1);
        assert_eq!(functions[0].name, "hello");
    }

    #[test]
    fn test_fallback_to_js_parser() {
        let code = r#"
function simple() {
    return 1;
}
"#;
        let parser = TypeScriptParser;
        let functions = parser.detect_functions(code);
        assert_eq!(functions.len(), 1);
        assert_eq!(functions[0].name, "simple");
    }
}
