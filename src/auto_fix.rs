use std::cmp::Ordering;
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use regex::Regex;

use crate::rules::RulesService;
use crate::models::{AnalysisIssue, AutoFixSuggestion};

static REGEX_CACHE: OnceLock<Mutex<HashMap<String, Result<Regex, String>>>> = OnceLock::new();

pub fn generate_auto_fixes(
    rules: &RulesService,
    issues: &[AnalysisIssue],
    max_auto_fixes: Option<usize>,
) -> Vec<AutoFixSuggestion> {
    let mut suggestions = Vec::new();

    for issue in issues {
        let Some(rule_id) = issue.rule_id.as_deref() else {
            continue;
        };
        let Some(code_snippet) = issue.code_snippet.as_deref() else {
            continue;
        };
        let Some(language) = rules.detect_language(&issue.file_path) else {
            continue;
        };

        for pattern in rules.get_auto_fix_patterns(&language, rule_id) {
            let Some(replacement) = pattern.replace_template.as_deref() else {
                continue;
            };
            let Some(re) = get_cached_regex(&pattern.find_pattern, rule_id) else {
                continue;
            };
            if !re.is_match(code_snippet) {
                continue;
            }

            let fixed_code = re.replace(code_snippet, replacement).to_string();
            if fixed_code == code_snippet {
                continue;
            }

            suggestions.push(AutoFixSuggestion {
                issue_key: issue_key(issue),
                rule_id: rule_id.to_string(),
                original_code: code_snippet.to_string(),
                fixed_code,
                fix_description: pattern.description.clone(),
                confidence: pattern.confidence,
                is_safe: is_safe_to_auto_apply(
                    pattern.is_safe,
                    pattern.confidence,
                    pattern.breaking_changes.as_ref(),
                    issue.category.as_str(),
                ),
                breaking_changes: pattern.breaking_changes.unwrap_or_default(),
            });
        }
    }

    suggestions.sort_by(compare_confidence_desc);
    if let Some(max) = max_auto_fixes {
        suggestions.truncate(max);
    }
    dedup_suggestions(&mut suggestions);
    suggestions
}

fn get_cached_regex(pattern: &str, rule_id: &str) -> Option<Regex> {
    let cache = REGEX_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let mut cache = cache.lock().unwrap_or_else(|poisoned| {
        tracing::warn!("Regex cache lock poisoned, recovering cache state");
        poisoned.into_inner()
    });

    if let Some(cached) = cache.get(pattern) {
        return cached.clone().ok();
    }

    match Regex::new(pattern) {
        Ok(regex) => {
            cache.insert(pattern.to_string(), Ok(regex));
            cache.get(pattern).and_then(|r| r.as_ref().ok().cloned())
        }
        Err(e) => {
            tracing::warn!("Invalid regex pattern in auto-fix rule {}: {}", rule_id, e);
            cache.insert(pattern.to_string(), Err(e.to_string()));
            None
        }
    }
}

fn compare_confidence_desc(a: &AutoFixSuggestion, b: &AutoFixSuggestion) -> Ordering {
    match (a.confidence.is_nan(), b.confidence.is_nan()) {
        (true, true) => Ordering::Equal,
        (true, false) => Ordering::Greater,
        (false, true) => Ordering::Less,
        (false, false) => b.confidence.total_cmp(&a.confidence),
    }
}

pub fn is_safe_to_auto_apply(
    pattern_safe: bool,
    confidence: f64,
    breaking_changes: Option<&Vec<String>>,
    issue_category: &str,
) -> bool {
    pattern_safe
        && confidence >= 0.9
        && breaking_changes.map(|v| v.is_empty()).unwrap_or(true)
        && issue_category != "security"
}

fn issue_key(issue: &AnalysisIssue) -> String {
    format!(
        "{}:{}:{}",
        issue.file_path,
        issue.line_start,
        issue.rule_id.as_deref().unwrap_or("unknown")
    )
}

fn dedup_suggestions(items: &mut Vec<AutoFixSuggestion>) {
    use std::collections::HashSet;
    // PERFORMANCE: Usar tupla de referências em vez de alocar String
    // Primeiro, identificar duplicados
    let mut seen: HashSet<(&str, &str, &str)> = HashSet::new();
    let len = items.len();
    let mut to_remove = vec![false; len];

    for (i, item) in items.iter().enumerate() {
        let key = (
            item.issue_key.as_str(),
            item.rule_id.as_str(),
            item.fixed_code.as_str(),
        );
        if !seen.insert(key) {
            to_remove[i] = true;
        }
    }

    // Compactar o vec removendo os duplicados
    let mut i = 0;
    items.retain(|_| {
        let keep = !to_remove[i];
        i += 1;
        keep
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::RulesService;

    #[test]
    fn test_is_safe_to_auto_apply_rules() {
        assert!(is_safe_to_auto_apply(
            true,
            0.95,
            Some(&vec![]),
            "maintainability"
        ));
        assert!(!is_safe_to_auto_apply(
            false,
            0.95,
            Some(&vec![]),
            "maintainability"
        ));
        assert!(!is_safe_to_auto_apply(
            true,
            0.75,
            Some(&vec![]),
            "maintainability"
        ));
        assert!(!is_safe_to_auto_apply(
            true,
            0.95,
            Some(&vec!["break".to_string()]),
            "maintainability"
        ));
        assert!(!is_safe_to_auto_apply(
            true,
            0.95,
            Some(&vec![]),
            "security"
        ));
    }

    #[test]
    fn test_generate_auto_fixes_returns_ordered() {
        let rules = RulesService::load().unwrap();
        let issues = vec![AnalysisIssue {
            rule_id: Some("S3168".to_string()),
            file_path: "src/TestRepository.cs".to_string(),
            line_start: 10,
            line_end: Some(10),
            severity: "high".to_string(),
            category: "maintainability".to_string(),
            title: "Async void".to_string(),
            description: "desc".to_string(),
            suggestion: None,
            code_snippet: Some("public async void ProcessData()".to_string()),
            confidence: 0.95,
            source: "static".to_string(),
        }];

        let suggestions = generate_auto_fixes(&rules, &issues, Some(10));
        assert!(!suggestions.is_empty());
        assert!(suggestions
            .windows(2)
            .all(|w| w[0].confidence >= w[1].confidence));
    }

    #[test]
    fn test_sort_keeps_nan_at_end() {
        let mut suggestions = vec![
            AutoFixSuggestion {
                issue_key: "1".to_string(),
                rule_id: "R1".to_string(),
                original_code: "a".to_string(),
                fixed_code: "b".to_string(),
                fix_description: "x".to_string(),
                confidence: 0.8,
                is_safe: true,
                breaking_changes: Vec::new(),
            },
            AutoFixSuggestion {
                issue_key: "2".to_string(),
                rule_id: "R2".to_string(),
                original_code: "a".to_string(),
                fixed_code: "b".to_string(),
                fix_description: "x".to_string(),
                confidence: f64::NAN,
                is_safe: true,
                breaking_changes: Vec::new(),
            },
            AutoFixSuggestion {
                issue_key: "3".to_string(),
                rule_id: "R3".to_string(),
                original_code: "a".to_string(),
                fixed_code: "b".to_string(),
                fix_description: "x".to_string(),
                confidence: 0.95,
                is_safe: true,
                breaking_changes: Vec::new(),
            },
        ];

        suggestions.sort_by(compare_confidence_desc);

        assert_eq!(suggestions[0].confidence, 0.95);
        assert_eq!(suggestions[1].confidence, 0.8);
        assert!(suggestions[2].confidence.is_nan());
    }
}
