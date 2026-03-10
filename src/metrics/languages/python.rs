//! Python function parser

use once_cell::sync::Lazy;
use regex::Regex;

use crate::detect::Language;
use crate::metrics::languages::FunctionParser;
use crate::metrics::models::FunctionSpan;

static FUNCTION_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^\s*(?:async\s+)?def\s+(\w+)\s*\(([^)]*)\)").unwrap());

static CLASS_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(r"^\s*class\s+(\w+)").unwrap());

static DECORATOR_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(r"^\s*@([\w.]+)").unwrap());

pub struct PythonParser;

impl FunctionParser for PythonParser {
    fn language(&self) -> Language {
        Language::Python
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
                let parameters = parse_parameters(params_str);

                let start_line = i + 1;
                let base_indent = get_indent_level(line);

                let mut decorator_lines = 0;
                let mut j = i;
                while j > 0 {
                    if let Some(_) = DECORATOR_REGEX.captures(lines[j - 1]) {
                        decorator_lines += 1;
                        j -= 1;
                    } else {
                        break;
                    }
                }

                let end_line = find_python_function_end(&lines, i, base_indent);
                let actual_start = start_line - decorator_lines;

                let body_lines: Vec<&str> = lines[actual_start - 1..end_line].to_vec();
                let body = body_lines.join("\n");

                functions.push(FunctionSpan {
                    name: name.to_string(),
                    start_line: actual_start,
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

fn parse_parameters(params_str: &str) -> Vec<String> {
    if params_str.trim().is_empty() {
        return Vec::new();
    }

    params_str
        .split(',')
        .filter_map(|p| {
            let p = p.trim();
            if p.is_empty() || p.starts_with('*') || p.starts_with('/') {
                None
            } else {
                let name = p.split(':').next().unwrap_or(p).trim();
                let name = name.split('=').next().unwrap_or(name).trim();
                if name.is_empty() {
                    None
                } else {
                    Some(name.to_string())
                }
            }
        })
        .collect()
}

fn get_indent_level(line: &str) -> usize {
    line.len() - line.trim_start().len()
}

fn find_python_function_end(lines: &[&str], start_idx: usize, base_indent: usize) -> usize {
    let mut end_line = start_idx + 1;

    for i in (start_idx + 1)..lines.len() {
        let line = lines[i];

        if line.trim().is_empty() {
            continue;
        }

        let current_indent = get_indent_level(line);

        if current_indent <= base_indent {
            if CLASS_REGEX.is_match(line) || FUNCTION_REGEX.is_match(line) {
                break;
            }
            let trimmed = line.trim();
            if !trimmed.starts_with('#')
                && !trimmed.starts_with('@')
                && !trimmed.starts_with("pass")
            {
                break;
            }
        }

        end_line = i + 1;
    }

    end_line.max(start_idx + 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_simple_function() {
        let code = r#"
def hello():
    print("Hello")
"#;
        let parser = PythonParser;
        let functions = parser.detect_functions(code);
        assert_eq!(functions.len(), 1);
        assert_eq!(functions[0].name, "hello");
    }

    #[test]
    fn test_detect_function_with_params() {
        let code = r#"
def greet(name: str, age: int = 18):
    print(f"Hello {name}")
"#;
        let parser = PythonParser;
        let functions = parser.detect_functions(code);
        assert_eq!(functions.len(), 1);
        assert_eq!(functions[0].name, "greet");
        assert_eq!(functions[0].parameters.len(), 2);
    }

    #[test]
    fn test_detect_async_function() {
        let code = r#"
async def fetch_data():
    return await something()
"#;
        let parser = PythonParser;
        let functions = parser.detect_functions(code);
        assert_eq!(functions.len(), 1);
        assert_eq!(functions[0].name, "fetch_data");
    }

    #[test]
    fn test_detect_decorated_function() {
        let code = r#"@app.route("/")
@login_required
def index():
    return "Hello"
"#;
        let parser = PythonParser;
        let functions = parser.detect_functions(code);
        assert_eq!(functions.len(), 1);
        assert_eq!(functions[0].name, "index");
        assert_eq!(functions[0].start_line, 1);
    }

    #[test]
    fn test_detect_multiple_functions() {
        let code = r#"
def foo():
    pass

def bar():
    pass

def baz():
    pass
"#;
        let parser = PythonParser;
        let functions = parser.detect_functions(code);
        assert_eq!(functions.len(), 3);
    }
}
