//! Core data types shared across the analysis engine.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AnalysisIssue {
    #[serde(default)]
    pub rule_id: Option<String>,
    pub file_path: String,
    pub line_start: u32,
    pub line_end: Option<u32>,
    pub severity: String,
    pub category: String,
    pub title: String,
    pub description: String,
    pub suggestion: Option<String>,
    pub code_snippet: Option<String>,
    pub confidence: f64,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AutoFixSuggestion {
    pub issue_key: String,
    pub rule_id: String,
    pub original_code: String,
    pub fixed_code: String,
    pub fix_description: String,
    pub confidence: f64,
    pub is_safe: bool,
    #[serde(default)]
    pub breaking_changes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct JobConfig {
    #[serde(default)]
    pub ai_enabled: bool,
    pub model: Option<String>,
    #[serde(default)]
    pub max_issues: Option<usize>,
    #[serde(default)]
    pub ignore_paths: Vec<String>,
    #[serde(default)]
    pub minimum_severity: Option<String>,
    #[serde(default)]
    pub include_rules: Vec<String>,
    #[serde(default)]
    pub exclude_rules: Vec<String>,
    #[serde(default = "default_true")]
    pub only_new_code: bool,
    #[serde(default)]
    pub auto_fix_enabled: bool,
    #[serde(default)]
    pub max_auto_fixes: Option<usize>,
    #[serde(default = "default_true")]
    pub secret_detection_enabled: bool,
    #[serde(default = "default_true")]
    pub iac_detection_enabled: bool,
}

fn default_true() -> bool { true }
