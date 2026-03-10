//! JavaScript function parser

use once_cell::sync::Lazy;
use regex::Regex;

use crate::detect::Language;
use crate::metrics::languages::FunctionParser;
use crate::metrics::models::FunctionSpan;

static FUNCTION_DECL_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?:async\s+)?function\s+(\w+)\s*\(([^)]*)\)").unwrap());

static ARROW_FUNCTION_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s*)?\(([^)]*)\)\s*=>").unwrap()
});

static METHOD_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^\s*(?:async\s+)?(\w+)\s*\(([^)]*)\)\s*\{").unwrap());

#[allow(dead_code)]
static CLASS_METHOD_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?:public|private|protected|static|async|\s)+(\w+)\s*\(([^)]*)\)\s*\{").unwrap()
});

pub struct JavaScriptParser;

impl FunctionParser for JavaScriptParser {
    fn language(&self) -> Language {
        Language::TypeScript
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

            if let Some(result) = try_parse_function_declaration(line, i, &lines) {
                processed_ranges.push((i, result.end_line));
                functions.push(result);
                continue;
            }

            if let Some(result) = try_parse_arrow_function(line, i, &lines) {
                processed_ranges.push((i, result.end_line));
                functions.push(result);
                continue;
            }

            if let Some(result) = try_parse_method(line, i, &lines) {
                processed_ranges.push((i, result.end_line));
                functions.push(result);
            }
        }

        functions
    }
}

fn try_parse_function_declaration(
    line: &str,
    line_idx: usize,
    lines: &[&str],
) -> Option<FunctionSpan> {
    if let Some(captures) = FUNCTION_DECL_REGEX.captures(line) {
        let name = captures.get(1).map(|m| m.as_str()).unwrap_or("anonymous");
        let params_str = captures.get(2).map(|m| m.as_str()).unwrap_or("");
        let parameters = parse_js_parameters(params_str);

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

fn try_parse_arrow_function(line: &str, line_idx: usize, lines: &[&str]) -> Option<FunctionSpan> {
    if let Some(captures) = ARROW_FUNCTION_REGEX.captures(line) {
        let name = captures.get(1).map(|m| m.as_str()).unwrap_or("anonymous");
        let params_str = captures.get(2).map(|m| m.as_str()).unwrap_or("");
        let parameters = parse_js_parameters(params_str);

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

fn try_parse_method(line: &str, line_idx: usize, lines: &[&str]) -> Option<FunctionSpan> {
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

    if let Some(captures) = METHOD_REGEX.captures(line) {
        let name = captures.get(1).map(|m| m.as_str()).unwrap_or("anonymous");

        if name == "if" || name == "while" || name == "for" || name == "switch" || name == "catch" {
            return None;
        }

        let params_str = captures.get(2).map(|m| m.as_str()).unwrap_or("");
        let parameters = parse_js_parameters(params_str);

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

fn parse_js_parameters(params_str: &str) -> Vec<String> {
    if params_str.trim().is_empty() {
        return Vec::new();
    }

    params_str
        .split(',')
        .filter_map(|p| {
            let p = p.trim();
            if p.is_empty() {
                None
            } else {
                let name = p.split(':').next().unwrap_or(p).trim();
                let name = name.split('=').next().unwrap_or(name).trim();
                let name = name.trim_start_matches("...").trim();
                if name.is_empty() {
                    None
                } else {
                    Some(name.to_string())
                }
            }
        })
        .collect()
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
    fn test_detect_function_declaration() {
        let code = r#"
function hello() {
    console.log("Hello");
}
"#;
        let parser = JavaScriptParser;
        let functions = parser.detect_functions(code);
        assert_eq!(functions.len(), 1);
        assert_eq!(functions[0].name, "hello");
    }

    #[test]
    fn test_detect_arrow_function() {
        let code = r#"
const add = (a, b) => a + b;
"#;
        let parser = JavaScriptParser;
        let functions = parser.detect_functions(code);
        assert_eq!(functions.len(), 1);
        assert_eq!(functions[0].name, "add");
    }

    #[test]
    fn test_detect_arrow_function_block() {
        let code = r#"
const greet = (name) => {
    return `Hello ${name}`;
};
"#;
        let parser = JavaScriptParser;
        let functions = parser.detect_functions(code);
        assert_eq!(functions.len(), 1);
        assert_eq!(functions[0].name, "greet");
    }

    #[test]
    fn test_detect_async_function() {
        let code = r#"
async function fetchData() {
    return await fetch(url);
}
"#;
        let parser = JavaScriptParser;
        let functions = parser.detect_functions(code);
        assert_eq!(functions.len(), 1);
        assert_eq!(functions[0].name, "fetchData");
    }

    #[test]
    fn test_detect_object_method() {
        let code = r#"
const obj = {
    getName() {
        return this.name;
    }
};
"#;
        let parser = JavaScriptParser;
        let functions = parser.detect_functions(code);
        assert!(functions.iter().any(|f| f.name == "getName"));
    }
}
