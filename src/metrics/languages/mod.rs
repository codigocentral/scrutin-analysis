//! Function parsers for different programming languages
//!
//! This module provides a trait-based system for detecting functions
//! in various programming languages.

mod cpp;
mod csharp;
mod go;
mod java;
mod javascript;
mod kotlin;
mod php;
mod python;
mod ruby;
mod rust_parser;
mod typescript;

use std::collections::HashMap;
use std::sync::OnceLock;

use crate::detect::Language;
use crate::metrics::models::FunctionSpan;

pub use cpp::CppParser;
pub use csharp::CSharpParser;
pub use go::GoParser;
pub use java::JavaParser;
pub use javascript::JavaScriptParser;
pub use kotlin::KotlinParser;
pub use php::PhpParser;
pub use python::PythonParser;
pub use ruby::RubyParser;
pub use rust_parser::RustParser;
pub use typescript::TypeScriptParser;

static PARSERS: OnceLock<HashMap<Language, Box<dyn FunctionParser>>> = OnceLock::new();

/// Trait for language-specific function detection
pub trait FunctionParser: Send + Sync {
    fn language(&self) -> Language;

    fn detect_functions(&self, content: &str) -> Vec<FunctionSpan>;

    fn detect_functions_in_range(
        &self,
        content: &str,
        start_line: usize,
        end_line: usize,
    ) -> Vec<FunctionSpan> {
        let all_functions = self.detect_functions(content);
        all_functions
            .into_iter()
            .filter(|f| f.start_line >= start_line && f.end_line <= end_line)
            .collect()
    }
}

pub fn get_parser(language: Language) -> &'static dyn FunctionParser {
    let parsers = PARSERS.get_or_init(|| {
        let mut map: HashMap<Language, Box<dyn FunctionParser>> = HashMap::new();
        map.insert(Language::Python, Box::new(PythonParser));
        map.insert(Language::TypeScript, Box::new(TypeScriptParser));
        map.insert(Language::Dotnet, Box::new(CSharpParser));
        map.insert(Language::Java, Box::new(JavaParser));
        map.insert(Language::Go, Box::new(GoParser));
        map.insert(Language::Cpp, Box::new(CppParser));
        map.insert(Language::Rust, Box::new(RustParser));
        map.insert(Language::Php, Box::new(PhpParser));
        map.insert(Language::Ruby, Box::new(RubyParser));
        map.insert(Language::Kotlin, Box::new(KotlinParser));
        map
    });

    parsers
        .get(&language)
        .map(|b| b.as_ref())
        .unwrap_or_else(|| parsers.get(&Language::TypeScript).unwrap().as_ref())
}

pub fn detect_language_from_path(path: &str) -> Language {
    let lower = path.to_lowercase();

    if lower.ends_with(".cs") {
        Language::Dotnet
    } else if lower.ends_with(".ts") || lower.ends_with(".tsx") {
        Language::TypeScript
    } else if lower.ends_with(".js") || lower.ends_with(".jsx") {
        Language::TypeScript
    } else if lower.ends_with(".py") {
        Language::Python
    } else if lower.ends_with(".go") {
        Language::Go
    } else if lower.ends_with(".rs") {
        Language::Rust
    } else if lower.ends_with(".java") {
        Language::Java
    } else if lower.ends_with(".cpp") || lower.ends_with(".cc") || lower.ends_with(".c") {
        Language::Cpp
    } else if lower.ends_with(".php") {
        Language::Php
    } else if lower.ends_with(".rb") {
        Language::Ruby
    } else if lower.ends_with(".kt") || lower.ends_with(".kts") {
        Language::Kotlin
    } else {
        Language::Unknown
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_parser_python() {
        let parser = get_parser(Language::Python);
        assert_eq!(parser.language(), Language::Python);
    }

    #[test]
    fn test_get_parser_rust() {
        let parser = get_parser(Language::Rust);
        assert_eq!(parser.language(), Language::Rust);
    }

    #[test]
    fn test_detect_language_from_path() {
        assert_eq!(detect_language_from_path("test.cs"), Language::Dotnet);
        assert_eq!(detect_language_from_path("test.ts"), Language::TypeScript);
        assert_eq!(detect_language_from_path("test.py"), Language::Python);
        assert_eq!(detect_language_from_path("test.go"), Language::Go);
        assert_eq!(detect_language_from_path("test.rs"), Language::Rust);
        assert_eq!(detect_language_from_path("test.java"), Language::Java);
        assert_eq!(detect_language_from_path("test.cpp"), Language::Cpp);
        assert_eq!(detect_language_from_path("test.php"), Language::Php);
        assert_eq!(detect_language_from_path("test.rb"), Language::Ruby);
        assert_eq!(detect_language_from_path("test.kt"), Language::Kotlin);
    }
}
