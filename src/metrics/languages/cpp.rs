//! C/C++ function parser

use once_cell::sync::Lazy;
use regex::Regex;

use crate::detect::Language;
use crate::metrics::languages::FunctionParser;
use crate::metrics::models::FunctionSpan;

static FUNCTION_NAME_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"((?:~?[A-Za-z_]\w*)(?:::(?:~?[A-Za-z_]\w*))*)\s*\(").unwrap());

pub struct CppParser;

impl FunctionParser for CppParser {
    fn language(&self) -> Language {
        Language::Cpp
    }

    fn detect_functions(&self, content: &str) -> Vec<FunctionSpan> {
        let lines: Vec<&str> = content.lines().collect();
        let mut functions = Vec::new();
        let mut processed_ranges: Vec<(usize, usize)> = Vec::new();

        for (i, _) in lines.iter().enumerate() {
            let already_processed = processed_ranges
                .iter()
                .any(|(start, end)| i >= *start && i < *end);

            if already_processed {
                continue;
            }

            if let Some(result) = try_parse_function(i, &lines) {
                processed_ranges.push((i, result.end_line));
                functions.push(result);
            }
        }

        functions
    }
}

fn try_parse_function(line_idx: usize, lines: &[&str]) -> Option<FunctionSpan> {
    let signature_end = find_signature_end(line_idx, lines)?;
    let signature = lines[line_idx..=signature_end]
        .iter()
        .map(|line| line.trim())
        .collect::<Vec<_>>()
        .join(" ");

    if should_skip_signature(&signature) {
        return None;
    }

    let captures = FUNCTION_NAME_REGEX.captures(&signature)?;
    let name = captures.get(1)?.as_str();

    if is_control_keyword(name) {
        return None;
    }

    let params = extract_parameters(&signature);
    let end_line = find_brace_end(lines, line_idx);
    let body = lines[line_idx..end_line].join("\n");

    Some(FunctionSpan {
        name: name.to_string(),
        start_line: line_idx + 1,
        end_line,
        body,
        parameters: params,
    })
}

fn find_signature_end(start_idx: usize, lines: &[&str]) -> Option<usize> {
    let mut collected = String::new();

    for i in start_idx..lines.len() {
        let trimmed = lines[i].trim();
        if trimmed.is_empty() || trimmed.starts_with("//") || trimmed.starts_with('#') {
            if i == start_idx {
                return None;
            }
            continue;
        }

        collected.push_str(trimmed);
        collected.push(' ');

        if trimmed.contains(';') && !trimmed.contains('{') {
            return None;
        }

        if trimmed.contains('{') {
            return Some(i);
        }

        if trimmed.ends_with(')') && i + 1 < lines.len() && lines[i + 1].trim().starts_with('{') {
            return Some(i + 1);
        }
    }

    None
}

fn should_skip_signature(signature: &str) -> bool {
    let normalized = signature.trim();
    normalized.is_empty()
        || normalized.contains('=')
        || normalized.starts_with("if ")
        || normalized.starts_with("for ")
        || normalized.starts_with("while ")
        || normalized.starts_with("switch ")
        || normalized.starts_with("catch ")
        || normalized.starts_with("class ")
        || normalized.starts_with("struct ")
        || normalized.starts_with("enum ")
        || normalized.starts_with("namespace ")
        || normalized.starts_with("typedef ")
        || normalized.starts_with("using ")
}

fn is_control_keyword(name: &str) -> bool {
    matches!(
        name,
        "if" | "for" | "while" | "switch" | "catch" | "return" | "sizeof" | "delete"
    )
}

fn extract_parameters(signature: &str) -> Vec<String> {
    let start = signature.find('(');
    let end = signature.rfind(')');
    let (Some(start), Some(end)) = (start, end) else {
        return Vec::new();
    };

    let params_str = &signature[start + 1..end];
    if params_str.trim().is_empty() || params_str.trim() == "void" {
        return Vec::new();
    }

    split_params(params_str)
        .into_iter()
        .filter_map(|param| {
            let candidate = param
                .split('=')
                .next()
                .unwrap_or("")
                .split_whitespace()
                .last()
                .unwrap_or("")
                .trim_matches('&')
                .trim_matches('*')
                .trim();

            if candidate.is_empty() || candidate == "const" {
                None
            } else {
                Some(candidate.to_string())
            }
        })
        .collect()
}

fn split_params(params: &str) -> Vec<String> {
    let mut items = Vec::new();
    let mut current = String::new();
    let mut depth = 0;

    for ch in params.chars() {
        match ch {
            '<' | '(' | '[' | '{' => {
                depth += 1;
                current.push(ch);
            }
            '>' | ')' | ']' | '}' => {
                depth -= 1;
                current.push(ch);
            }
            ',' if depth == 0 => {
                let value = current.trim();
                if !value.is_empty() {
                    items.push(value.to_string());
                }
                current.clear();
            }
            _ => current.push(ch),
        }
    }

    let value = current.trim();
    if !value.is_empty() {
        items.push(value.to_string());
    }

    items
}

fn find_brace_end(lines: &[&str], start_idx: usize) -> usize {
    let mut brace_count = 0i32;
    let mut found_open = false;

    for i in start_idx..lines.len() {
        for ch in lines[i].chars() {
            match ch {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_cpp_functions_and_methods() {
        let parser = CppParser;
        let content = r#"
int sum(int a, int b) {
    return a + b;
}

Foo::~Foo() {
}
"#;

        let functions = parser.detect_functions(content);

        assert_eq!(functions.len(), 2);
        assert_eq!(functions[0].name, "sum");
        assert_eq!(
            functions[0].parameters,
            vec!["a".to_string(), "b".to_string()]
        );
        assert_eq!(functions[1].name, "Foo::~Foo");
    }
}
