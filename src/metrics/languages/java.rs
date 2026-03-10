//! Java function parser

use once_cell::sync::Lazy;
use regex::Regex;

use crate::detect::Language;
use crate::metrics::languages::FunctionParser;
use crate::metrics::models::FunctionSpan;

static METHOD_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?:public|private|protected|static|final|synchronized|abstract|native|\s)+(\w+)\s*\(([^)]*)\)\s*(?:throws\s+[\w,\s]+)?\s*\{",
    )
    .unwrap()
});

static CONSTRUCTOR_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?:public|private|protected)\s+(\w+)\s*\(([^)]*)\)\s*\{").unwrap());

pub struct JavaParser;

impl FunctionParser for JavaParser {
    fn language(&self) -> Language {
        Language::Java
    }

    fn detect_functions(&self, content: &str) -> Vec<FunctionSpan> {
        let lines: Vec<&str> = content.lines().collect();
        let mut functions = Vec::new();
        let mut processed_ranges: Vec<(usize, usize)> = Vec::new();
        let class_name = find_class_name(&lines);

        for (i, line) in lines.iter().enumerate() {
            let already_processed = processed_ranges
                .iter()
                .any(|(start, end)| i >= *start && i < *end);

            if already_processed {
                continue;
            }

            let trimmed = line.trim();

            if trimmed.starts_with("//") || trimmed.starts_with("/*") || trimmed.starts_with("*") {
                continue;
            }

            if let Some(result) = try_parse_method(line, i, &lines, &class_name) {
                processed_ranges.push((i, result.end_line));
                functions.push(result);
            }
        }

        functions
    }
}

fn find_class_name(lines: &[&str]) -> Option<String> {
    for line in lines {
        if let Some(caps) = CLASS_NAME_REGEX.captures(line) {
            return caps.get(1).map(|m| m.as_str().to_string());
        }
    }
    None
}

static CLASS_NAME_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?:public|private|protected)?\s*class\s+(\w+)").unwrap());

fn try_parse_method(
    line: &str,
    line_idx: usize,
    lines: &[&str],
    class_name: &Option<String>,
) -> Option<FunctionSpan> {
    // Try constructor first (before method regex to avoid constructor being filtered out)
    if let Some(captures) = CONSTRUCTOR_REGEX.captures(line) {
        let name = captures.get(1).map(|m| m.as_str()).unwrap_or("unknown");

        if let Some(ref class) = class_name {
            if name == class {
                let params_str = captures.get(2).map(|m| m.as_str()).unwrap_or("");
                let parameters = parse_java_parameters(params_str);

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
        }
    }

    // Try regular method
    if let Some(captures) = METHOD_REGEX.captures(line) {
        let name = captures.get(1).map(|m| m.as_str()).unwrap_or("unknown");

        if is_control_keyword(name) {
            return None;
        }

        // Skip constructors (already handled above)
        if let Some(ref class) = class_name {
            if name == class {
                return None;
            }
        }

        let params_str = captures.get(2).map(|m| m.as_str()).unwrap_or("");
        let parameters = parse_java_parameters(params_str);

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

fn is_control_keyword(word: &str) -> bool {
    matches!(
        word,
        "if" | "while" | "for" | "switch" | "catch" | "class" | "interface" | "enum" | "try"
    )
}

fn parse_java_parameters(params_str: &str) -> Vec<String> {
    if params_str.trim().is_empty() {
        return Vec::new();
    }

    let mut params = Vec::new();
    let mut depth = 0;
    let mut current = String::new();

    for c in params_str.chars() {
        match c {
            '<' | '(' | '[' => {
                depth += 1;
                current.push(c);
            }
            '>' | ')' | ']' => {
                depth -= 1;
                current.push(c);
            }
            ',' if depth == 0 => {
                let param = current.trim();
                if !param.is_empty() {
                    if let Some(name) = extract_java_param_name(param) {
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
        if let Some(name) = extract_java_param_name(param) {
            params.push(name);
        }
    }

    params
}

fn extract_java_param_name(param: &str) -> Option<String> {
    let parts: Vec<&str> = param.split_whitespace().collect();
    if parts.is_empty() {
        return None;
    }

    let last = parts.last()?;
    let name = last.trim_end_matches(',');

    if name.contains('<') || name.contains('>') || name.is_empty() {
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

fn extract_body(lines: &[&str], start_idx: usize, end_idx: usize) -> String {
    lines[start_idx..end_idx.min(lines.len())].join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_simple_method() {
        let code = r#"
public class Test {
    public void hello() {
        System.out.println("Hello");
    }
}
"#;
        let parser = JavaParser;
        let functions = parser.detect_functions(code);
        assert_eq!(functions.len(), 1);
        assert_eq!(functions[0].name, "hello");
    }

    #[test]
    fn test_detect_method_with_params() {
        let code = r#"
public class Calculator {
    public int add(int a, int b) {
        return a + b;
    }
}
"#;
        let parser = JavaParser;
        let functions = parser.detect_functions(code);
        assert_eq!(functions.len(), 1);
        assert_eq!(functions[0].name, "add");
        assert_eq!(functions[0].parameters.len(), 2);
    }

    #[test]
    fn test_detect_private_method() {
        let code = r#"
public class Test {
    private void helper() {
        // helper code
    }
}
"#;
        let parser = JavaParser;
        let functions = parser.detect_functions(code);
        assert_eq!(functions.len(), 1);
        assert_eq!(functions[0].name, "helper");
    }

    #[test]
    fn test_detect_static_method() {
        let code = r#"
public class Utils {
    public static String format(String input) {
        return input.trim();
    }
}
"#;
        let parser = JavaParser;
        let functions = parser.detect_functions(code);
        assert_eq!(functions.len(), 1);
        assert_eq!(functions[0].name, "format");
    }

    #[test]
    fn test_detect_constructor() {
        let code = r#"
public class Person {
    private String name;
    
    public Person(String name) {
        this.name = name;
    }
}
"#;
        let parser = JavaParser;
        let functions = parser.detect_functions(code);
        assert!(functions.iter().any(|f| f.name == "Person"));
    }

    #[test]
    fn test_ignore_control_structures() {
        let code = r#"
public class Test {
    public void method() {
        if (true) {
            // code
        }
    }
}
"#;
        let parser = JavaParser;
        let functions = parser.detect_functions(code);
        assert_eq!(functions.len(), 1);
        assert_eq!(functions[0].name, "method");
    }
}
