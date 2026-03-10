//! Kotlin function parser

use once_cell::sync::Lazy;
use regex::Regex;

use crate::detect::Language;
use crate::metrics::languages::FunctionParser;
use crate::metrics::models::FunctionSpan;

/// Matches Kotlin function declarations
/// - fun functionName()
/// - fun functionName(param: Type)
/// - fun functionName(): ReturnType
/// - suspend fun functionName()
/// - private fun functionName()
/// - inline fun functionName()
/// - fun Class.methodName() (extension function)
/// - fun (Type).methodName() (extension function on type)
static FUNCTION_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^\s*(?:(?:public|private|protected|internal|open|abstract|final|override|suspend|inline|crossinline|noinline)\s+)*fun\s+(?:(?:<[^>]+>\s+)?(?:[\w\s<>,?.()]+\.)?)?(\w+)\s*\(([^)]*)\)").unwrap()
});

/// Matches Kotlin class declarations
#[allow(dead_code)]
static CLASS_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^\s*(?:(?:public|private|protected|internal|open|abstract|sealed|data|inline|value)\s+)*class\s+(\w+)").unwrap()
});

/// Matches Kotlin object declarations (singleton)
#[allow(dead_code)]
static OBJECT_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^\s*(?:(?:public|private|protected|internal)\s+)*object\s+(\w+)").unwrap()
});

/// Matches Kotlin interface declarations
#[allow(dead_code)]
static INTERFACE_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^\s*(?:(?:public|private|protected|internal|sealed)\s+)*interface\s+(\w+)")
        .unwrap()
});

/// Matches Kotlin companion object
#[allow(dead_code)]
static COMPANION_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(r"^\s*companion\s+object").unwrap());

pub struct KotlinParser;

impl FunctionParser for KotlinParser {
    fn language(&self) -> Language {
        Language::Kotlin
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
                let parameters = parse_kotlin_parameters(params_str);

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

fn parse_kotlin_parameters(params_str: &str) -> Vec<String> {
    if params_str.trim().is_empty() {
        return Vec::new();
    }

    let mut params = Vec::new();
    let mut depth = 0;
    let mut current = String::new();

    for c in params_str.chars() {
        match c {
            '(' | '[' | '{' | '<' => {
                depth += 1;
                current.push(c);
            }
            ')' | ']' | '}' | '>' => {
                depth -= 1;
                current.push(c);
            }
            ',' if depth == 0 => {
                if let Some(param) = extract_kotlin_param_name(&current) {
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
        if let Some(param) = extract_kotlin_param_name(&current) {
            params.push(param);
        }
    }

    params
}

fn extract_kotlin_param_name(param_str: &str) -> Option<String> {
    let trimmed = param_str.trim();
    if trimmed.is_empty() {
        return None;
    }

    // Kotlin params can be:
    // name: Type
    // name: Type = default
    // vararg name: Type
    // namer: (Param) -> Return (function type)
    // name: Type.() -> Unit (receiver function type)

    // Remove 'vararg' keyword if present
    let without_vararg = if trimmed.starts_with("vararg ") {
        &trimmed[7..]
    } else {
        trimmed
    };

    // Get the parameter name (first part before :)
    let name = without_vararg.split(':').next().unwrap_or("").trim();

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

fn extract_body(lines: &[&str], start_idx: usize, end_idx: usize) -> String {
    lines[start_idx..end_idx.min(lines.len())].join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_simple_function() {
        let code = r#"
fun hello() {
    println("Hello")
}
"#;
        let parser = KotlinParser;
        let functions = parser.detect_functions(code);
        assert_eq!(functions.len(), 1);
        assert_eq!(functions[0].name, "hello");
    }

    #[test]
    fn test_detect_function_with_params() {
        let code = r#"
fun greet(name: String, age: Int) {
    println("Hello $name")
}
"#;
        let parser = KotlinParser;
        let functions = parser.detect_functions(code);
        assert_eq!(functions.len(), 1);
        assert_eq!(functions[0].name, "greet");
        assert_eq!(functions[0].parameters.len(), 2);
        assert_eq!(functions[0].parameters[0], "name");
        assert_eq!(functions[0].parameters[1], "age");
    }

    #[test]
    fn test_detect_function_with_return_type() {
        let code = r#"
fun add(a: Int, b: Int): Int {
    return a + b
}
"#;
        let parser = KotlinParser;
        let functions = parser.detect_functions(code);
        assert_eq!(functions.len(), 1);
        assert_eq!(functions[0].name, "add");
        assert_eq!(functions[0].parameters.len(), 2);
    }

    #[test]
    fn test_detect_suspending_function() {
        let code = r#"
suspend fun fetchData(): String {
    delay(1000)
    return "data"
}
"#;
        let parser = KotlinParser;
        let functions = parser.detect_functions(code);
        assert_eq!(functions.len(), 1);
        assert_eq!(functions[0].name, "fetchData");
    }

    #[test]
    fn test_detect_private_function() {
        let code = r#"
class User {
    private fun validate(): Boolean {
        return true
    }
}
"#;
        let parser = KotlinParser;
        let functions = parser.detect_functions(code);
        assert_eq!(functions.len(), 1);
        assert_eq!(functions[0].name, "validate");
    }

    #[test]
    fn test_detect_extension_function() {
        let code = r#"
fun String.addExclamation(): String {
    return this + "!"
}
"#;
        let parser = KotlinParser;
        let functions = parser.detect_functions(code);
        assert_eq!(functions.len(), 1);
        assert_eq!(functions[0].name, "addExclamation");
    }

    #[test]
    fn test_detect_generic_function() {
        let code = r#"
fun <T> identity(value: T): T {
    return value
}
"#;
        let parser = KotlinParser;
        let functions = parser.detect_functions(code);
        assert_eq!(functions.len(), 1);
        assert_eq!(functions[0].name, "identity");
    }

    #[test]
    fn test_detect_function_with_default_value() {
        let code = r#"
fun greet(name: String = "World") {
    println("Hello $name")
}
"#;
        let parser = KotlinParser;
        let functions = parser.detect_functions(code);
        assert_eq!(functions.len(), 1);
        assert_eq!(functions[0].name, "greet");
        assert_eq!(functions[0].parameters.len(), 1);
        assert_eq!(functions[0].parameters[0], "name");
    }

    #[test]
    fn test_detect_function_with_vararg() {
        let code = r#"
fun sum(vararg numbers: Int): Int {
    return numbers.sum()
}
"#;
        let parser = KotlinParser;
        let functions = parser.detect_functions(code);
        assert_eq!(functions.len(), 1);
        assert_eq!(functions[0].name, "sum");
        assert_eq!(functions[0].parameters.len(), 1);
        assert_eq!(functions[0].parameters[0], "numbers");
    }

    #[test]
    fn test_detect_multiple_functions() {
        let code = r#"
fun foo() {
    println("foo")
}

fun bar() {
    println("bar")
}

fun baz() {
    println("baz")
}
"#;
        let parser = KotlinParser;
        let functions = parser.detect_functions(code);
        assert_eq!(functions.len(), 3);
    }

    #[test]
    fn test_detect_inline_function() {
        let code = r#"
inline fun measureTime(block: () -> Unit): Long {
    val start = System.currentTimeMillis()
    block()
    return System.currentTimeMillis() - start
}
"#;
        let parser = KotlinParser;
        let functions = parser.detect_functions(code);
        assert_eq!(functions.len(), 1);
        assert_eq!(functions[0].name, "measureTime");
    }

    #[test]
    fn test_detect_override_function() {
        let code = r#"
class MyClass : BaseClass() {
    override fun toString(): String {
        return "MyClass"
    }
}
"#;
        let parser = KotlinParser;
        let functions = parser.detect_functions(code);
        assert_eq!(functions.len(), 1);
        assert_eq!(functions[0].name, "toString");
    }

    #[test]
    fn test_detect_abstract_function() {
        let code = r#"
abstract class Base {
    abstract fun render(): String
}
"#;
        let parser = KotlinParser;
        let functions = parser.detect_functions(code);
        assert_eq!(functions.len(), 1);
        assert_eq!(functions[0].name, "render");
    }

    #[test]
    fn test_detect_function_with_lambda_param() {
        let code = r#"
fun withLogging(block: () -> Unit) {
    println("Before")
    block()
    println("After")
}
"#;
        let parser = KotlinParser;
        let functions = parser.detect_functions(code);
        assert_eq!(functions.len(), 1);
        assert_eq!(functions[0].name, "withLogging");
        assert_eq!(functions[0].parameters.len(), 1);
        assert_eq!(functions[0].parameters[0], "block");
    }

    #[test]
    fn test_detect_single_expression_function() {
        let code = r#"
fun add(a: Int, b: Int) = a + b
"#;
        let parser = KotlinParser;
        let functions = parser.detect_functions(code);
        assert_eq!(functions.len(), 1);
        assert_eq!(functions[0].name, "add");
    }
}
