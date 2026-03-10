//! Halstead complexity metrics calculator
//!
//! Implements Halstead metrics based on operator and operand counting.

use std::collections::HashSet;

use crate::detect::Language;
use crate::metrics::models::HalsteadMetrics;

pub struct HalsteadCalculator;

impl HalsteadCalculator {
    pub fn calculate(content: &str, language: Language) -> HalsteadMetrics {
        let (operators, operands, unique_operators, unique_operands) =
            count_operators_and_operands(content, language);

        HalsteadMetrics::new(operators, operands, unique_operators, unique_operands)
    }
}

fn count_operators_and_operands(content: &str, language: Language) -> (usize, usize, usize, usize) {
    let cleaned = remove_comments_and_strings(content);

    let mut operators: Vec<String> = Vec::new();
    let mut operands: Vec<String> = Vec::new();

    let operator_symbols = get_operator_symbols(language);
    let operator_keywords = get_operator_keywords(language);

    let mut remaining = cleaned.as_str();

    while !remaining.is_empty() {
        let trimmed = remaining.trim_start();
        if trimmed.is_empty() {
            break;
        }

        let mut found = false;

        for keyword in &operator_keywords {
            if trimmed.starts_with(keyword) {
                let after_keyword = &trimmed[keyword.len()..];
                if after_keyword.is_empty()
                    || !after_keyword
                        .chars()
                        .next()
                        .map(|c| c.is_alphanumeric() || c == '_')
                        .unwrap_or(false)
                {
                    operators.push(keyword.to_string());
                    remaining = after_keyword;
                    found = true;
                    break;
                }
            }
        }

        if found {
            continue;
        }

        for symbol in &operator_symbols {
            if trimmed.starts_with(symbol) {
                operators.push(symbol.to_string());
                remaining = &trimmed[symbol.len()..];
                found = true;
                break;
            }
        }

        if found {
            continue;
        }

        if let Some(ident) = extract_identifier(trimmed) {
            if is_keyword(&ident, language) {
                operators.push(ident.clone());
            } else {
                operands.push(ident.clone());
            }
            remaining = &trimmed[ident.len()..];
            continue;
        }

        if let Some(literal) = extract_literal(trimmed) {
            operands.push(literal.clone());
            remaining = &trimmed[literal.len()..];
            continue;
        }

        remaining = &trimmed[1..];
    }

    let unique_operators: HashSet<String> = operators.iter().cloned().collect();
    let unique_operands: HashSet<String> = operands.iter().cloned().collect();

    (
        operators.len(),
        operands.len(),
        unique_operators.len(),
        unique_operands.len(),
    )
}

fn get_operator_symbols(language: Language) -> Vec<&'static str> {
    let common = vec![
        "+", "-", "*", "/", "%", "=", "==", "!=", "<", ">", "<=", ">=", "&&", "||", "!", "&", "|",
        "^", "~", "<<", ">>", "++", "--", "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "<<=",
        ">>=", "=>", "->", "::", ".", ",", ";", ":", "?", "??", "?.", "?:",
    ];

    match language {
        Language::Rust => vec![
            "+", "-", "*", "/", "%", "=", "==", "!=", "<", ">", "<=", ">=", "&&", "||", "!", "&",
            "|", "^", "~", "<<", ">>", "++", "--", "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=",
            "<<=", ">>=", "=>", "->", "::", ".", ",", ";", ":", "?", "..", "..=", "|>",
        ],
        Language::Go => vec![
            "+", "-", "*", "/", "%", "=", "==", "!=", "<", ">", "<=", ">=", "&&", "||", "!", "&",
            "|", "^", "<<", ">>", "&^", "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "<<=",
            ">>=", "&^=", "<-", ":=", ".", ",", ";", ":",
        ],
        _ => common,
    }
}

fn get_operator_keywords(language: Language) -> Vec<&'static str> {
    match language {
        Language::Rust => vec![
            "fn", "let", "mut", "const", "static", "pub", "mod", "use", "crate", "self", "super",
            "impl", "trait", "type", "struct", "enum", "match", "if", "else", "for", "while",
            "loop", "break", "continue", "return", "async", "await", "move", "ref", "as", "in",
            "where", "unsafe", "extern", "dyn", "box",
        ],
        Language::Python => vec![
            "def", "class", "lambda", "if", "elif", "else", "for", "while", "break", "continue",
            "return", "yield", "import", "from", "as", "with", "try", "except", "finally", "raise",
            "assert", "pass", "del", "global", "nonlocal", "async", "await", "and", "or", "not",
            "in", "is",
        ],
        Language::TypeScript | Language::Java => vec![
            "function",
            "var",
            "let",
            "const",
            "class",
            "interface",
            "type",
            "enum",
            "if",
            "else",
            "for",
            "while",
            "do",
            "switch",
            "case",
            "default",
            "break",
            "continue",
            "return",
            "throw",
            "try",
            "catch",
            "finally",
            "new",
            "delete",
            "typeof",
            "instanceof",
            "in",
            "async",
            "await",
            "import",
            "export",
            "from",
            "as",
            "extends",
            "implements",
            "public",
            "private",
            "protected",
            "static",
            "abstract",
            "final",
            "readonly",
        ],
        Language::Dotnet => vec![
            "class",
            "interface",
            "struct",
            "enum",
            "record",
            "delegate",
            "if",
            "else",
            "for",
            "foreach",
            "while",
            "do",
            "switch",
            "case",
            "default",
            "break",
            "continue",
            "return",
            "throw",
            "try",
            "catch",
            "finally",
            "new",
            "typeof",
            "sizeof",
            "nameof",
            "is",
            "as",
            "async",
            "await",
            "using",
            "lock",
            "fixed",
            "unsafe",
            "checked",
            "unchecked",
            "public",
            "private",
            "protected",
            "internal",
            "static",
            "readonly",
            "const",
            "sealed",
            "abstract",
            "virtual",
            "override",
            "new",
            "extern",
            "volatile",
        ],
        Language::Go => vec![
            "func",
            "var",
            "const",
            "type",
            "struct",
            "interface",
            "map",
            "chan",
            "if",
            "else",
            "for",
            "range",
            "switch",
            "case",
            "default",
            "break",
            "continue",
            "return",
            "goto",
            "fallthrough",
            "defer",
            "go",
            "select",
            "package",
            "import",
        ],
        _ => vec![
            "function", "class", "if", "else", "for", "while", "switch", "case", "default",
            "break", "continue", "return", "try", "catch", "finally", "throw", "new",
        ],
    }
}

fn is_keyword(s: &str, language: Language) -> bool {
    let keywords = get_operator_keywords(language);
    let types = get_type_keywords(language);

    keywords.contains(&s) || types.contains(&s)
}

fn get_type_keywords(language: Language) -> Vec<&'static str> {
    match language {
        Language::Rust => vec![
            "i8", "i16", "i32", "i64", "i128", "isize", "u8", "u16", "u32", "u64", "u128", "usize",
            "f32", "f64", "bool", "char", "str", "String", "Vec", "Option", "Result", "Box", "Rc",
            "Arc", "Cell", "RefCell", "Some", "None", "Ok", "Err", "true", "false",
        ],
        Language::Python => vec![
            "int", "float", "bool", "str", "list", "dict", "set", "tuple", "None", "True", "False",
        ],
        Language::TypeScript | Language::Java => vec![
            "number",
            "string",
            "boolean",
            "void",
            "null",
            "undefined",
            "any",
            "never",
            "object",
            "symbol",
            "bigint",
            "true",
            "false",
            "int",
            "long",
            "short",
            "byte",
            "float",
            "double",
            "char",
        ],
        Language::Dotnet => vec![
            "int", "long", "short", "byte", "float", "double", "decimal", "bool", "char", "string",
            "object", "void", "null", "true", "false", "var", "dynamic", "nint", "nuint",
        ],
        Language::Go => vec![
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
            "complex64",
            "complex128",
            "bool",
            "string",
            "rune",
            "byte",
            "uintptr",
            "true",
            "false",
            "nil",
            "any",
            "error",
        ],
        _ => vec!["int", "float", "bool", "string", "true", "false", "null"],
    }
}

fn extract_identifier(s: &str) -> Option<String> {
    let mut chars = s.chars().peekable();

    if let Some(&first) = chars.peek() {
        if first.is_alphabetic() || first == '_' {
            let mut ident = String::new();
            while let Some(&c) = chars.peek() {
                if c.is_alphanumeric() || c == '_' {
                    ident.push(c);
                    chars.next();
                } else {
                    break;
                }
            }
            if !ident.is_empty() {
                return Some(ident);
            }
        }
    }
    None
}

fn extract_literal(s: &str) -> Option<String> {
    let mut chars = s.chars().peekable();

    if let Some(&first) = chars.peek() {
        if first.is_ascii_digit() {
            let mut lit = String::new();
            while let Some(&c) = chars.peek() {
                if c.is_ascii_digit()
                    || c == '.'
                    || c == 'x'
                    || c == 'X'
                    || c == 'e'
                    || c == 'E'
                    || c == '+'
                    || c == '-'
                    || c == 'b'
                    || c == 'o'
                {
                    lit.push(c);
                    chars.next();
                } else if c == '_' {
                    chars.next();
                } else {
                    break;
                }
            }
            return Some(lit);
        }

        if first == '"' || first == '\'' || first == '`' {
            let quote = first;
            let mut lit = String::new();
            lit.push(chars.next()?);

            let mut escaped = false;
            while let Some(&c) = chars.peek() {
                lit.push(c);
                chars.next();

                if escaped {
                    escaped = false;
                    continue;
                }

                if c == '\\' {
                    escaped = true;
                    continue;
                }

                if c == quote {
                    break;
                }
            }
            return Some(lit);
        }
    }
    None
}

fn remove_comments_and_strings(content: &str) -> String {
    use once_cell::sync::Lazy;
    use regex::Regex;

    static COMMENT_REGEX: Lazy<Regex> =
        Lazy::new(|| Regex::new(r#"//.*$|/\*[\s\S]*?\*/|#[^\n]*"#).unwrap());

    COMMENT_REGEX.replace_all(content, "").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_function_halstead() {
        let code = r#"
fn add(a: i32, b: i32) -> i32 {
    a + b
}
"#;
        let metrics = HalsteadCalculator::calculate(code, Language::Rust);

        assert!(metrics.operators > 0);
        assert!(metrics.operands > 0);
        assert!(metrics.volume > 0.0);
    }

    #[test]
    fn test_halstead_volume() {
        let code = r#"
fn complex(x: i32, y: i32, z: i32) -> i32 {
    let result = x + y;
    let result2 = result * z;
    if result2 > 100 {
        return result2;
    }
    0
}
"#;
        let metrics = HalsteadCalculator::calculate(code, Language::Rust);

        assert!(metrics.volume > 0.0);
        assert!(metrics.effort >= metrics.volume);
    }

    #[test]
    fn test_halstead_difficulty() {
        let code = r#"
fn unique_ops(a: i32) -> i32 {
    a + 1
}
"#;
        let metrics = HalsteadCalculator::calculate(code, Language::Rust);

        assert!(metrics.difficulty >= 0.0);
    }

    #[test]
    fn test_halstead_time_estimate() {
        let code = r#"
fn test() -> i32 {
    let a = 1;
    let b = 2;
    let c = a + b;
    c
}
"#;
        let metrics = HalsteadCalculator::calculate(code, Language::Rust);

        assert!(metrics.time_minutes >= 0.0);
        assert!(metrics.bugs_estimate >= 0.0);
    }

    #[test]
    fn test_python_halstead() {
        let code = r#"
def add(a, b):
    return a + b
"#;
        let metrics = HalsteadCalculator::calculate(code, Language::Python);

        assert!(metrics.operators > 0);
        assert!(metrics.operands > 0);
    }
}
