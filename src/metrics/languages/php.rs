//! PHP function parser

use once_cell::sync::Lazy;
use regex::Regex;

use crate::detect::Language;
use crate::metrics::languages::FunctionParser;
use crate::metrics::models::FunctionSpan;

/// Matches PHP function declarations
/// - function name()
/// - public function name()
/// - private function name()
/// - protected function name()
/// - static function name()
/// - abstract function name()
static FUNCTION_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^\s*(?:(?:public|private|protected|static|abstract|final)\s+)*(?:async\s+)?function\s+(\w+)\s*\(([^)]*)").unwrap()
});

/// Matches PHP class declarations
#[allow(dead_code)]
static CLASS_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^\s*(?:abstract\s+)?class\s+(\w+)").unwrap());

/// Matches PHP trait declarations
#[allow(dead_code)]
static TRAIT_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(r"^\s*trait\s+(\w+)").unwrap());

/// Matches PHP interface declarations
#[allow(dead_code)]
static INTERFACE_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(r"^\s*interface\s+(\w+)").unwrap());

pub struct PhpParser;

impl FunctionParser for PhpParser {
    fn language(&self) -> Language {
        Language::Php
    }

    fn detect_functions(&self, content: &str) -> Vec<FunctionSpan> {
        let lines: Vec<&str> = content.lines().collect();
        let mut functions = Vec::new();
        let mut i = 0;

        while i < lines.len() {
            let line = lines[i];

            if let Some(captures) = FUNCTION_REGEX.captures(line) {
                let name = captures.get(1).map(|m| m.as_str()).unwrap_or("unknown");
                let params_str = captures.get(2).map(|m| m.as_str()).unwrap_or("");
                let parameters = parse_php_parameters(params_str);

                let start_line = i + 1;
                let end_line = find_brace_end(&lines, i);
                let body = extract_body(&lines, i, end_line);

                functions.push(FunctionSpan {
                    name: name.to_string(),
                    start_line,
                    end_line,
                    body,
                    parameters,
                });

                i = end_line;
                continue;
            }

            i += 1;
        }

        functions
    }
}

fn parse_php_parameters(params_str: &str) -> Vec<String> {
    if params_str.trim().is_empty() {
        return Vec::new();
    }

    let mut params = Vec::new();
    let mut depth = 0;
    let mut current = String::new();

    for c in params_str.chars() {
        match c {
            '(' | '[' | '{' => {
                depth += 1;
                current.push(c);
            }
            ')' | ']' | '}' => {
                depth -= 1;
                current.push(c);
            }
            ',' if depth == 0 => {
                if let Some(param) = extract_param_name(&current) {
                    params.push(param);
                }
                current.clear();
            }
            _ => {
                current.push(c);
            }
        }
    }

    // Handle last parameter
    if !current.trim().is_empty() {
        if let Some(param) = extract_param_name(&current) {
            params.push(param);
        }
    }

    params
}

fn extract_param_name(param_str: &str) -> Option<String> {
    let trimmed = param_str.trim();
    if trimmed.is_empty() {
        return None;
    }

    // PHP params can be:
    // $name
    // string $name
    // string $name = 'default'
    // ?Type $name
    // array $name
    // callable $name

    let parts: Vec<&str> = trimmed.split_whitespace().collect();

    // Find the part that starts with $
    for part in &parts {
        if part.starts_with('$') {
            // Remove $ and any trailing characters like = or ,
            let name = part.trim_start_matches('$');
            let name = name.split('=').next().unwrap_or(name).trim();
            if !name.is_empty() {
                return Some(name.to_string());
            }
        }
    }

    None
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
        let code = r#"<?php
function hello() {
    echo "Hello";
}
"#;
        let parser = PhpParser;
        let functions = parser.detect_functions(code);
        assert_eq!(functions.len(), 1);
        assert_eq!(functions[0].name, "hello");
    }

    #[test]
    fn test_detect_class_method() {
        let code = r#"<?php
class User {
    public function getName() {
        return $this->name;
    }
}
"#;
        let parser = PhpParser;
        let functions = parser.detect_functions(code);
        assert_eq!(functions.len(), 1);
        assert_eq!(functions[0].name, "getName");
    }

    #[test]
    fn test_detect_private_method() {
        let code = r#"<?php
class User {
    private function validate() {
        return true;
    }
}
"#;
        let parser = PhpParser;
        let functions = parser.detect_functions(code);
        assert_eq!(functions.len(), 1);
        assert_eq!(functions[0].name, "validate");
    }

    #[test]
    fn test_detect_static_method() {
        let code = r#"<?php
class Utils {
    public static function helper() {
        return "help";
    }
}
"#;
        let parser = PhpParser;
        let functions = parser.detect_functions(code);
        assert_eq!(functions.len(), 1);
        assert_eq!(functions[0].name, "helper");
    }

    #[test]
    fn test_detect_function_with_params() {
        let code = r#"<?php
function greet($name, $age) {
    return "Hello $name";
}
"#;
        let parser = PhpParser;
        let functions = parser.detect_functions(code);
        assert_eq!(functions.len(), 1);
        assert_eq!(functions[0].name, "greet");
        assert_eq!(functions[0].parameters.len(), 2);
        assert_eq!(functions[0].parameters[0], "name");
        assert_eq!(functions[0].parameters[1], "age");
    }

    #[test]
    fn test_detect_function_with_typed_params() {
        let code = r#"<?php
function greet(string $name, int $age = 18): string {
    return "Hello $name";
}
"#;
        let parser = PhpParser;
        let functions = parser.detect_functions(code);
        assert_eq!(functions.len(), 1);
        assert_eq!(functions[0].name, "greet");
        assert_eq!(functions[0].parameters.len(), 2);
        assert_eq!(functions[0].parameters[0], "name");
        assert_eq!(functions[0].parameters[1], "age");
    }

    #[test]
    fn test_detect_multiple_functions() {
        let code = r#"<?php
function foo() {
    return 1;
}

function bar() {
    return 2;
}

function baz() {
    return 3;
}
"#;
        let parser = PhpParser;
        let functions = parser.detect_functions(code);
        assert_eq!(functions.len(), 3);
    }

    #[test]
    fn test_detect_abstract_method() {
        let code = r#"<?php
abstract class Base {
    abstract protected function render();
}
"#;
        let parser = PhpParser;
        let functions = parser.detect_functions(code);
        assert_eq!(functions.len(), 1);
        assert_eq!(functions[0].name, "render");
    }
}
