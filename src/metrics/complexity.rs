//! Complexity calculations for code analysis
//!
//! Implements Cyclomatic Complexity and Cognitive Complexity
//! following industry standards (McCabe, SonarQube).

use once_cell::sync::Lazy;
use regex::Regex;

use crate::detect::Language;

#[derive(Debug, Clone)]
pub struct ComplexityResult {
    pub cyclomatic: u32,
    pub cognitive: u32,
    pub max_nesting: u32,
}

#[derive(Debug, Clone)]
pub struct ComplexityKeywords {
    pub decision_keywords: Vec<&'static str>,
    pub loop_keywords: Vec<&'static str>,
    pub switch_keywords: Vec<&'static str>,
    pub try_catch_keywords: Vec<&'static str>,
    pub boolean_operators: Vec<&'static str>,
}

static COMMENT_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"//.*$|/\*[\s\S]*?\*/|#[^\n]*"#).unwrap());

static STRING_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#""(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|`(?:[^`\\]|\\.)*`"#).unwrap());

pub fn calculate_complexity(content: &str, language: Language) -> ComplexityResult {
    let cleaned = remove_comments_and_strings(content);
    let keywords = get_keywords(language);

    let cyclomatic = calculate_cyclomatic(&cleaned, &keywords);
    let (cognitive, max_nesting) = calculate_cognitive(&cleaned, &keywords, language);

    ComplexityResult {
        cyclomatic,
        cognitive,
        max_nesting,
    }
}

pub fn calculate_cyclomatic_complexity(content: &str, language: Language) -> u32 {
    let cleaned = remove_comments_and_strings(content);
    let keywords = get_keywords(language);
    calculate_cyclomatic(&cleaned, &keywords)
}

pub fn calculate_cognitive_complexity(content: &str, language: Language) -> (u32, u32) {
    let cleaned = remove_comments_and_strings(content);
    let keywords = get_keywords(language);
    calculate_cognitive(&cleaned, &keywords, language)
}

fn calculate_cyclomatic(content: &str, keywords: &ComplexityKeywords) -> u32 {
    let mut complexity = 1u32;

    let lines: Vec<&str> = content.lines().collect();
    for (idx, line) in lines.iter().enumerate() {
        let line_lower = line.to_lowercase();
        let trimmed = line.trim();

        for keyword in &keywords.decision_keywords {
            if line_lower.contains(keyword) {
                complexity += count_keyword_occurrences(&line_lower, keyword);
            }
        }

        for keyword in &keywords.loop_keywords {
            if line_lower.contains(keyword) {
                complexity += count_keyword_occurrences(&line_lower, keyword);
            }
        }

        for keyword in &keywords.switch_keywords {
            if line_lower.contains(keyword) {
                // For Rust match statements, count arms instead of keyword
                if keyword == &"match" {
                    if let Some(arm_count) = count_match_arms(&lines, idx, Language::Rust) {
                        complexity += arm_count;
                    }
                } else {
                    complexity += count_keyword_occurrences(&line_lower, keyword);
                }
            }
        }

        for keyword in &keywords.try_catch_keywords {
            if line_lower.contains(keyword) {
                complexity += count_keyword_occurrences(&line_lower, keyword);
            }
        }

        for op in &keywords.boolean_operators {
            complexity += count_operator_occurrences(trimmed, op) as u32;
        }
    }

    complexity
}

fn calculate_cognitive(
    content: &str,
    keywords: &ComplexityKeywords,
    language: Language,
) -> (u32, u32) {
    let mut total_cognitive = 0u32;
    let mut max_nesting = 0u32;
    let mut nesting_stack: Vec<u32> = Vec::new();

    let lines: Vec<&str> = content.lines().collect();
    let mut i = 0;

    while i < lines.len() {
        let line = lines[i];
        let line_lower = line.to_lowercase();
        let trimmed = line.trim();

        let is_nesting_start = is_nesting_keyword(&line_lower, keywords);
        let is_nesting_end = is_nesting_end(trimmed, language);

        if is_nesting_start && !is_nesting_end {
            let nesting_level = nesting_stack.len() as u32;

            let increment = if nesting_level > 0 { nesting_level } else { 1 };
            total_cognitive += increment;

            max_nesting = max_nesting.max(nesting_level + 1);
            nesting_stack.push(increment);

            if let Some(count) = count_switch_cases(&lines, i, language) {
                total_cognitive += count;
            }

            if let Some(count) = count_match_arms(&lines, i, language) {
                total_cognitive += count.saturating_sub(1);
            }
        }

        if is_nesting_end && !nesting_stack.is_empty() {
            nesting_stack.pop();
        }

        for op in &keywords.boolean_operators {
            let count = count_operator_occurrences(trimmed, op) as u32;
            if count > 0 && nesting_stack.is_empty() {
                total_cognitive += count;
            }
        }

        i += 1;
    }

    (total_cognitive, max_nesting)
}

fn is_nesting_keyword(line: &str, keywords: &ComplexityKeywords) -> bool {
    let trimmed = line.trim();

    for keyword in &keywords.decision_keywords {
        if trimmed.starts_with(keyword) || trimmed.contains(&format!("{} ", keyword)) {
            return true;
        }
    }

    for keyword in &keywords.loop_keywords {
        if trimmed.starts_with(keyword) || trimmed.contains(&format!("{} ", keyword)) {
            return true;
        }
    }

    for keyword in &keywords.switch_keywords {
        if trimmed.starts_with(keyword) || trimmed.contains(&format!("{} ", keyword)) {
            return true;
        }
    }

    false
}

fn is_nesting_end(line: &str, language: Language) -> bool {
    match language {
        Language::Python | Language::Ruby => false,
        _ => {
            let open_count = line.matches('{').count();
            let close_count = line.matches('}').count();
            close_count > open_count
        }
    }
}

fn count_switch_cases(lines: &[&str], start_idx: usize, language: Language) -> Option<u32> {
    let switch_keyword = match language {
        Language::Dotnet | Language::Java | Language::TypeScript | Language::Php => "case",
        Language::Go => "case",
        _ => return None,
    };

    let mut case_count = 0u32;
    let mut brace_count = 0i32;
    let mut found_switch = false;

    for i in start_idx..lines.len() {
        let line_lower = lines[i].to_lowercase();

        if line_lower.contains("switch") || line_lower.contains("select ") {
            found_switch = true;
        }

        if found_switch {
            brace_count += lines[i].matches('{').count() as i32;
            brace_count -= lines[i].matches('}').count() as i32;

            if line_lower.trim().starts_with(switch_keyword)
                || line_lower.contains(&format!("{} ", switch_keyword))
            {
                case_count += 1;
            }

            if brace_count <= 0 && lines[i].contains('}') {
                break;
            }
        }
    }

    if case_count > 0 {
        Some(case_count)
    } else {
        None
    }
}

fn count_match_arms(lines: &[&str], start_idx: usize, language: Language) -> Option<u32> {
    if language != Language::Rust {
        return None;
    }

    let mut arm_count = 0u32;
    let mut brace_count = 0i32;
    let mut in_match = false;

    for i in start_idx..lines.len() {
        let line = lines[i];

        if line.contains("match ") {
            in_match = true;
        }

        if in_match {
            brace_count += line.matches('{').count() as i32;
            brace_count -= line.matches('}').count() as i32;

            if line.contains("=>") && !line.trim().starts_with("//") {
                arm_count += 1;
            }

            if brace_count <= 0 && line.contains('}') {
                break;
            }
        }
    }

    if arm_count > 0 {
        Some(arm_count)
    } else {
        None
    }
}

fn count_keyword_occurrences(line: &str, keyword: &str) -> u32 {
    let mut count = 0u32;
    let mut pos = 0;

    while let Some(idx) = line[pos..].find(keyword) {
        let actual_pos = pos + idx;
        let before_ok = actual_pos == 0
            || !line
                .as_bytes()
                .get(actual_pos - 1)
                .map(|&b| b.is_ascii_alphabetic())
                .unwrap_or(false);
        let after_ok = actual_pos + keyword.len() >= line.len()
            || !line
                .as_bytes()
                .get(actual_pos + keyword.len())
                .map(|&b| b.is_ascii_alphabetic())
                .unwrap_or(false);

        if before_ok && after_ok {
            count += 1;
        }
        pos = actual_pos + keyword.len();
    }

    count
}

fn count_operator_occurrences(line: &str, op: &str) -> usize {
    line.matches(op).count()
}

fn get_keywords(language: Language) -> ComplexityKeywords {
    match language {
        Language::Dotnet => ComplexityKeywords {
            decision_keywords: vec!["if", "else if", "elif"],
            loop_keywords: vec!["for", "foreach", "while", "do"],
            switch_keywords: vec!["case", "default"],
            try_catch_keywords: vec!["catch", "when"],
            boolean_operators: vec!["&&", "||", "?", "??"],
        },
        Language::TypeScript | Language::Java => ComplexityKeywords {
            decision_keywords: vec!["if", "else if"],
            loop_keywords: vec!["for", "while", "do"],
            switch_keywords: vec!["case", "default"],
            try_catch_keywords: vec!["catch"],
            boolean_operators: vec!["&&", "||", "?", "??", "?."],
        },
        Language::Python => ComplexityKeywords {
            decision_keywords: vec!["if", "elif"],
            loop_keywords: vec!["for", "while"],
            switch_keywords: vec![],
            try_catch_keywords: vec!["except", "finally"],
            boolean_operators: vec!["and", "or"],
        },
        Language::Go => ComplexityKeywords {
            decision_keywords: vec!["if", "else if"],
            loop_keywords: vec!["for"],
            switch_keywords: vec!["case", "default"],
            try_catch_keywords: vec![],
            boolean_operators: vec!["&&", "||"],
        },
        Language::Rust => ComplexityKeywords {
            decision_keywords: vec!["if", "else if"],
            loop_keywords: vec!["for", "while", "loop"],
            switch_keywords: vec!["match"],
            try_catch_keywords: vec![],
            boolean_operators: vec!["&&", "||", "?"],
        },
        Language::Php => ComplexityKeywords {
            decision_keywords: vec!["if", "elseif"],
            loop_keywords: vec!["for", "foreach", "while", "do"],
            switch_keywords: vec!["case", "default"],
            try_catch_keywords: vec!["catch"],
            boolean_operators: vec!["&&", "||", "?", "??"],
        },
        Language::Ruby => ComplexityKeywords {
            decision_keywords: vec!["if", "elsif", "unless"],
            loop_keywords: vec!["for", "while", "until"],
            switch_keywords: vec!["when"],
            try_catch_keywords: vec!["rescue"],
            boolean_operators: vec!["&&", "||"],
        },
        _ => ComplexityKeywords {
            decision_keywords: vec!["if", "else"],
            loop_keywords: vec!["for", "while"],
            switch_keywords: vec!["case"],
            try_catch_keywords: vec!["catch"],
            boolean_operators: vec!["&&", "||"],
        },
    }
}

fn remove_comments_and_strings(content: &str) -> String {
    let mut result = content.to_string();
    result = STRING_REGEX.replace_all(&result, "\"\"").to_string();
    result = COMMENT_REGEX.replace_all(&result, "").to_string();
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_function_complexity() {
        let code = r#"
fn simple() {
    println!("Hello");
}
"#;
        let result = calculate_complexity(code, Language::Rust);
        assert_eq!(result.cyclomatic, 1);
        assert_eq!(result.cognitive, 0);
    }

    #[test]
    fn test_if_complexity() {
        let code = r#"
fn check(x: i32) {
    if x > 0 {
        println!("Positive");
    }
}
"#;
        let result = calculate_complexity(code, Language::Rust);
        assert!(result.cyclomatic >= 2);
        assert!(result.cognitive >= 1);
    }

    #[test]
    fn test_nested_if_complexity() {
        let code = r#"
fn nested(x: i32, y: i32) {
    if x > 0 {
        if y > 0 {
            println!("Both positive");
        }
    }
}
"#;
        let result = calculate_complexity(code, Language::Rust);
        assert!(result.cyclomatic >= 3);
        assert!(result.max_nesting >= 2);
    }

    #[test]
    fn test_boolean_operators() {
        let code = r#"
fn check(x: i32, y: i32) {
    if x > 0 && y > 0 || x < 0 {
        println!("Condition");
    }
}
"#;
        let result = calculate_complexity(code, Language::Rust);
        assert!(result.cyclomatic >= 4);
    }

    #[test]
    fn test_loop_complexity() {
        let code = r#"
fn loops() {
    for i in 0..10 {
        while i < 5 {
            println!("{}", i);
        }
    }
}
"#;
        let result = calculate_complexity(code, Language::Rust);
        assert!(result.cyclomatic >= 3);
    }

    #[test]
    fn test_python_complexity() {
        let code = r#"
def check(x, y):
    if x > 0 and y > 0:
        for i in range(10):
            print(i)
"#;
        let result = calculate_complexity(code, Language::Python);
        assert!(result.cyclomatic >= 3);
    }

    #[test]
    fn test_match_complexity() {
        let code = r#"
fn match_example(x: i32) {
    match x {
        1 => println!("One"),
        2 => println!("Two"),
        3 => println!("Three"),
        _ => println!("Other"),
    }
}
"#;
        let result = calculate_complexity(code, Language::Rust);
        assert!(result.cyclomatic >= 5);
    }
}
