//! Ruby function parser

use once_cell::sync::Lazy;
use regex::Regex;

use crate::detect::Language;
use crate::metrics::languages::FunctionParser;
use crate::metrics::models::FunctionSpan;

/// Matches Ruby method definitions
/// - def method_name
/// - def self.method_name (class method)
/// - def method_name(param1, param2)
/// - def method_name(param1 = default)
/// - def method_name(*args)
/// - def method_name(&block)
/// - def method_name(**kwargs)
static METHOD_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^\s*def\s+(?:self\.)?(\w+[?!]?)(?:\s*\(([^)]*)\)|\s+|$)").unwrap());

/// Matches Ruby class definitions
#[allow(dead_code)]
static CLASS_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(r"^\s*class\s+(\w+(?:::\w+)*)").unwrap());

/// Matches Ruby module definitions
#[allow(dead_code)]
static MODULE_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^\s*module\s+(\w+(?:::\w+)*)").unwrap());

/// Matches Ruby singleton class (class << self)
#[allow(dead_code)]
static SINGLETON_CLASS_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^\s*class\s+<<\s+\w+").unwrap());

pub struct RubyParser;

impl FunctionParser for RubyParser {
    fn language(&self) -> Language {
        Language::Ruby
    }

    fn detect_functions(&self, content: &str) -> Vec<FunctionSpan> {
        let lines: Vec<&str> = content.lines().collect();
        let mut functions = Vec::new();
        let mut i = 0;

        while i < lines.len() {
            let line = lines[i];

            if let Some(captures) = METHOD_REGEX.captures(line) {
                let name = captures.get(1).map(|m| m.as_str()).unwrap_or("unknown");
                let params_str = captures.get(2).map(|m| m.as_str()).unwrap_or("");
                let parameters = parse_ruby_parameters(params_str);

                let start_line = i + 1;
                let base_indent = get_indent_level(line);
                let end_line = find_ruby_method_end(&lines, i, base_indent);
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

fn parse_ruby_parameters(params_str: &str) -> Vec<String> {
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
                if let Some(param) = extract_ruby_param_name(&current) {
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
        if let Some(param) = extract_ruby_param_name(&current) {
            params.push(param);
        }
    }

    params
}

fn extract_ruby_param_name(param_str: &str) -> Option<String> {
    let trimmed = param_str.trim();
    if trimmed.is_empty() {
        return None;
    }

    // Ruby params can be:
    // name
    // name = default
    // *args (splat)
    // **kwargs (double splat)
    // &block
    // key: value (keyword arg with default)
    // key: (required keyword arg)

    let param = if trimmed.starts_with("**") {
        // Keyword arguments hash
        trimmed[2..]
            .trim()
            .split(':')
            .next()
            .unwrap_or("")
            .trim()
            .to_string()
    } else if trimmed.starts_with('*') {
        // Splat argument
        trimmed[1..]
            .trim()
            .split('=')
            .next()
            .unwrap_or("")
            .trim()
            .to_string()
    } else if trimmed.starts_with('&') {
        // Block argument
        trimmed[1..].trim().to_string()
    } else if trimmed.contains(':') && !trimmed.contains("::") {
        // Keyword argument (key: or key: value)
        trimmed.split(':').next().unwrap_or("").trim().to_string()
    } else {
        // Regular parameter with optional default
        trimmed
            .split('=')
            .next()
            .unwrap_or(trimmed)
            .trim()
            .to_string()
    };

    if param.is_empty() {
        None
    } else {
        Some(param)
    }
}

fn get_indent_level(line: &str) -> usize {
    line.len() - line.trim_start().len()
}

fn find_ruby_method_end(lines: &[&str], start_idx: usize, base_indent: usize) -> usize {
    let mut end_line = start_idx + 1;

    for i in (start_idx + 1)..lines.len() {
        let line = lines[i];

        if line.trim().is_empty() {
            end_line = i + 1;
            continue;
        }

        let current_indent = get_indent_level(line);

        // In Ruby, methods end when we reach a line with same or lower indentation
        // that's not part of the method body (like another method def, class, module, etc.)
        if current_indent <= base_indent {
            let trimmed = line.trim();
            // Check if this line starts a new definition
            if trimmed.starts_with("def ")
                || trimmed.starts_with("class ")
                || trimmed.starts_with("module ")
                || trimmed.starts_with("end")
            {
                break;
            }
        }

        end_line = i + 1;
    }

    end_line.max(start_idx + 1)
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
def hello
  puts "Hello"
end
"#;
        let parser = RubyParser;
        let functions = parser.detect_functions(code);
        assert_eq!(functions.len(), 1);
        assert_eq!(functions[0].name, "hello");
    }

    #[test]
    fn test_detect_method_with_params() {
        let code = r#"
def greet(name, age)
  puts "Hello #{name}"
end
"#;
        let parser = RubyParser;
        let functions = parser.detect_functions(code);
        assert_eq!(functions.len(), 1);
        assert_eq!(functions[0].name, "greet");
        assert_eq!(functions[0].parameters.len(), 2);
        assert_eq!(functions[0].parameters[0], "name");
        assert_eq!(functions[0].parameters[1], "age");
    }

    #[test]
    fn test_detect_class_method() {
        let code = r#"
class User
  def self.create
    new
  end
end
"#;
        let parser = RubyParser;
        let functions = parser.detect_functions(code);
        assert_eq!(functions.len(), 1);
        assert_eq!(functions[0].name, "create");
    }

    #[test]
    fn test_detect_method_with_defaults() {
        let code = r#"
def greet(name = "World")
  puts "Hello #{name}"
end
"#;
        let parser = RubyParser;
        let functions = parser.detect_functions(code);
        assert_eq!(functions.len(), 1);
        assert_eq!(functions[0].name, "greet");
        assert_eq!(functions[0].parameters.len(), 1);
        assert_eq!(functions[0].parameters[0], "name");
    }

    #[test]
    fn test_detect_method_with_splat() {
        let code = r#"
def sum(*args)
  args.reduce(0, :+)
end
"#;
        let parser = RubyParser;
        let functions = parser.detect_functions(code);
        assert_eq!(functions.len(), 1);
        assert_eq!(functions[0].name, "sum");
        assert_eq!(functions[0].parameters.len(), 1);
        assert_eq!(functions[0].parameters[0], "args");
    }

    #[test]
    fn test_detect_method_with_block() {
        let code = r#"
def with_logging(&block)
  puts "Before"
  block.call
  puts "After"
end
"#;
        let parser = RubyParser;
        let functions = parser.detect_functions(code);
        assert_eq!(functions.len(), 1);
        assert_eq!(functions[0].name, "with_logging");
        assert_eq!(functions[0].parameters.len(), 1);
        assert_eq!(functions[0].parameters[0], "block");
    }

    #[test]
    fn test_detect_method_with_keyword_args() {
        let code = r#"
def create_user(name:, email:, age: nil)
  User.new(name: name, email: email, age: age)
end
"#;
        let parser = RubyParser;
        let functions = parser.detect_functions(code);
        assert_eq!(functions.len(), 1);
        assert_eq!(functions[0].name, "create_user");
        assert_eq!(functions[0].parameters.len(), 3);
    }

    #[test]
    fn test_detect_bang_method() {
        let code = r#"
def save!
  save || raise("Failed to save")
end
"#;
        let parser = RubyParser;
        let functions = parser.detect_functions(code);
        assert_eq!(functions.len(), 1);
        assert_eq!(functions[0].name, "save!");
    }

    #[test]
    fn test_detect_predicate_method() {
        let code = r#"
def valid?
  errors.empty?
end
"#;
        let parser = RubyParser;
        let functions = parser.detect_functions(code);
        assert_eq!(functions.len(), 1);
        assert_eq!(functions[0].name, "valid?");
    }

    #[test]
    fn test_detect_multiple_methods() {
        let code = r#"
def foo
  1
end

def bar
  2
end

def baz
  3
end
"#;
        let parser = RubyParser;
        let functions = parser.detect_functions(code);
        assert_eq!(functions.len(), 3);
    }

    #[test]
    fn test_detect_method_in_class() {
        let code = r#"
class User
  attr_reader :name

  def initialize(name)
    @name = name
  end

  def greet
    "Hello #{name}"
  end
end
"#;
        let parser = RubyParser;
        let functions = parser.detect_functions(code);
        assert_eq!(functions.len(), 2);
        assert_eq!(functions[0].name, "initialize");
        assert_eq!(functions[1].name, "greet");
    }
}
