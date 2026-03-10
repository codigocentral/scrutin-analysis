//! Gitleaks configuration parser
//!
//! Supports loading secret detection rules from Gitleaks TOML and JSON config files.
//! Reference: https://github.com/gitleaks/gitleaks

use crate::error::{AnalysisError, Result};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::path::Path;

use super::patterns::SecretRule;

/// Gitleaks configuration structure (TOML format)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitleaksConfig {
    pub title: Option<String>,
    pub extend: Option<GitleaksExtend>,
    #[serde(default)]
    pub rules: Vec<GitleaksRule>,
    #[serde(default)]
    pub allowlist: Option<GitleaksAllowlist>,
}

/// Extension configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitleaksExtend {
    pub path: String,
    #[serde(default)]
    pub url: Option<String>,
}

/// Gitleaks rule definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitleaksRule {
    pub id: String,
    pub description: String,
    pub regex: Option<String>,
    pub keywords: Option<Vec<String>>,
    pub path: Option<String>,
    pub entropy: Option<f64>,
    #[serde(default)]
    pub secret_group: Option<i32>,
    #[serde(rename = "matchCondition")]
    pub match_condition: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub allowlist: Option<GitleaksAllowlist>,
}

/// Gitleaks allowlist configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitleaksAllowlist {
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub regexes: Vec<String>,
    #[serde(default)]
    pub paths: Vec<String>,
    #[serde(default)]
    pub commits: Vec<String>,
    #[serde(default)]
    pub stop_words: Vec<String>,
}

/// Parser for Gitleaks configuration files
pub struct GitleaksParser;

impl GitleaksParser {
    /// Parses a Gitleaks TOML configuration file
    pub fn parse_toml(content: &str) -> Result<GitleaksConfig> {
        toml::from_str(content)
            .map_err(|e| AnalysisError::message(format!("Failed to parse Gitleaks TOML: {}", e)))
    }

    /// Parses a Gitleaks JSON configuration file
    pub fn parse_json(content: &str) -> Result<GitleaksConfig> {
        serde_json::from_str(content)
            .map_err(|e| AnalysisError::message(format!("Failed to parse Gitleaks JSON: {}", e)))
    }

    /// Loads a Gitleaks configuration from a file
    pub fn load_from_file(path: &Path) -> Result<GitleaksConfig> {
        let content = std::fs::read_to_string(path)?;
        let extension = path.extension().and_then(|e| e.to_str()).unwrap_or("");

        match extension.to_lowercase().as_str() {
            "toml" => Self::parse_toml(&content),
            "json" => Self::parse_json(&content),
            _ => {
                // Try both formats
                if let Ok(config) = Self::parse_toml(&content) {
                    return Ok(config);
                }
                Self::parse_json(&content)
            }
        }
    }

    /// Converts a GitleaksConfig to our internal SecretRule format
    pub fn to_secret_rules(config: &GitleaksConfig) -> Result<Vec<SecretRule>> {
        let mut rules = Vec::with_capacity(config.rules.len());

        for gitleaks_rule in &config.rules {
            let patterns = if let Some(regex) = &gitleaks_rule.regex {
                vec![regex.clone()]
            } else if let Some(path) = &gitleaks_rule.path {
                vec![path.clone()]
            } else {
                continue; // Skip rules without regex or path
            };

            let allowlist_patterns = gitleaks_rule
                .allowlist
                .as_ref()
                .map(|a| a.regexes.as_slice())
                .unwrap_or(&[])
                .to_vec();

            let provider = gitleaks_rule
                .tags
                .first()
                .cloned()
                .unwrap_or_else(|| "generic".to_string());

            let rule = SecretRule {
                rule_id: format!(
                    "SEC-GL-{}",
                    gitleaks_rule.id.replace('-', "-").to_uppercase()
                ),
                external_id: format!("gitleaks/{}", gitleaks_rule.id),
                title: gitleaks_rule.description.clone(),
                message: format!("A {} was detected.", gitleaks_rule.description),
                severity: Self::determine_severity(&gitleaks_rule.id),
                patterns,
                provider,
                keywords: gitleaks_rule.keywords.clone().unwrap_or_default(),
                suggestion: Some(Self::generate_suggestion(&gitleaks_rule.id)),
                allowlist_patterns,
                entropy: gitleaks_rule.entropy,
            };

            rules.push(rule);
        }

        Ok(rules)
    }

    /// Determines severity based on rule ID patterns
    pub fn determine_severity(rule_id: &str) -> String {
        let critical_keywords = [
            "aws",
            "github",
            "gitlab",
            "stripe",
            "slack",
            "private",
            "secret",
            "password",
            "token",
            "api-key",
            "credential",
            "auth",
        ];

        let id_lower = rule_id.to_lowercase();
        if critical_keywords.iter().any(|k| id_lower.contains(k)) {
            "critical".to_string()
        } else if id_lower.contains("test") || id_lower.contains("example") {
            "low".to_string()
        } else {
            "high".to_string()
        }
    }

    /// Generates a suggestion based on the rule type
    fn generate_suggestion(rule_id: &str) -> String {
        let id_lower = rule_id.to_lowercase();

        if id_lower.contains("aws") {
            "Remove the key from code and rotate it immediately. Use AWS Secrets Manager or environment variables.".to_string()
        } else if id_lower.contains("github") {
            "Revoke this token immediately in GitHub Settings > Developer settings.".to_string()
        } else if id_lower.contains("gitlab") {
            "Revoke this token in GitLab User Settings > Access Tokens.".to_string()
        } else if id_lower.contains("private") || id_lower.contains("key") {
            "Remove this private key immediately and generate a new key pair.".to_string()
        } else if id_lower.contains("password") || id_lower.contains("secret") {
            "Never hardcode passwords or secrets. Use environment variables.".to_string()
        } else {
            "Remove this secret from the code and rotate it immediately. Use environment variables or a secrets manager.".to_string()
        }
    }

    /// Merges Gitleaks rules with embedded rules
    pub fn merge_with_embedded(gitleaks_rules: Vec<SecretRule>) -> Vec<SecretRule> {
        let mut embedded = super::patterns::load_embedded_rules();

        // Create a set of existing rule IDs to avoid duplicates
        let existing_ids: std::collections::HashSet<_> =
            embedded.iter().map(|r| r.external_id.clone()).collect();

        // Add only new rules from Gitleaks
        for rule in gitleaks_rules {
            if !existing_ids.contains(&rule.external_id) {
                embedded.push(rule);
            }
        }

        embedded
    }

    /// Validates a Gitleaks rule's regex patterns
    pub fn validate_rule(rule: &GitleaksRule) -> Result<()> {
        if let Some(regex) = &rule.regex {
            Regex::new(regex).map_err(|e| AnalysisError::Regex(e))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_toml_config() {
        let toml_content = r#"
title = "Custom Gitleaks Config"

[[rules]]
id = "custom-api-key"
description = "Custom API Key"
regex = '''(?i)api[_-]?key\s*[=:]\s*['"][a-z0-9]{32}['"]'''
keywords = ["api_key", "apikey"]
tags = ["api", "custom"]

[[rules]]
id = "custom-token"
description = "Custom Token"
regex = '''token_[a-z0-9]{40}'''
keywords = ["token"]
"#;

        let config = GitleaksParser::parse_toml(toml_content).unwrap();
        assert_eq!(config.rules.len(), 2);
        assert_eq!(config.rules[0].id, "custom-api-key");
    }

    #[test]
    fn test_parse_json_config() {
        let json_content = r#"{
            "title": "Custom Gitleaks Config",
            "rules": [
                {
                    "id": "json-api-key",
                    "description": "JSON API Key",
                    "regex": "api_key_[a-z0-9]{32}",
                    "keywords": ["api_key"]
                }
            ]
        }"#;

        let config = GitleaksParser::parse_json(json_content).unwrap();
        assert_eq!(config.rules.len(), 1);
        assert_eq!(config.rules[0].id, "json-api-key");
    }

    #[test]
    fn test_to_secret_rules() {
        let config = GitleaksConfig {
            title: Some("Test".to_string()),
            extend: None,
            rules: vec![GitleaksRule {
                id: "test-rule".to_string(),
                description: "Test Rule".to_string(),
                regex: Some(r"test_[a-z0-9]{32}".to_string()),
                keywords: Some(vec!["test".to_string()]),
                path: None,
                entropy: Some(4.5),
                secret_group: None,
                match_condition: None,
                tags: vec!["testing".to_string()],
                allowlist: None,
            }],
            allowlist: None,
        };

        let rules = GitleaksParser::to_secret_rules(&config).unwrap();
        assert_eq!(rules.len(), 1);
        assert!(rules[0].rule_id.contains("TEST-RULE"));
    }

    #[test]
    fn test_determine_severity() {
        assert_eq!(
            GitleaksParser::determine_severity("aws-access-key"),
            "critical"
        );
        assert_eq!(
            GitleaksParser::determine_severity("github-token"),
            "critical"
        );
        assert_eq!(GitleaksParser::determine_severity("test-example"), "low");
        assert_eq!(GitleaksParser::determine_severity("custom-rule"), "high");
    }

    #[test]
    fn test_merge_with_embedded() {
        let custom_rule = SecretRule {
            rule_id: "SEC-CUSTOM-001".into(),
            external_id: "custom/my-rule".into(),
            title: "Custom Rule".into(),
            message: "Custom message".into(),
            severity: "high".into(),
            patterns: vec![r"custom_[a-z0-9]+".into()],
            provider: "custom".into(),
            keywords: vec!["custom".into()],
            suggestion: Some("Fix it".into()),
            allowlist_patterns: vec![],
            entropy: None,
        };

        let merged = GitleaksParser::merge_with_embedded(vec![custom_rule]);
        assert!(merged.len() > 180);
    }

    #[test]
    fn test_validate_rule() {
        let valid_rule = GitleaksRule {
            id: "test".to_string(),
            description: "Test".to_string(),
            regex: Some(r"[a-z]+".to_string()),
            keywords: None,
            path: None,
            entropy: None,
            secret_group: None,
            match_condition: None,
            tags: vec![],
            allowlist: None,
        };
        assert!(GitleaksParser::validate_rule(&valid_rule).is_ok());

        let invalid_rule = GitleaksRule {
            id: "test".to_string(),
            description: "Test".to_string(),
            regex: Some(r"[a-z".to_string()), // Invalid regex
            keywords: None,
            path: None,
            entropy: None,
            secret_group: None,
            match_condition: None,
            tags: vec![],
            allowlist: None,
        };
        assert!(GitleaksParser::validate_rule(&invalid_rule).is_err());
    }
}
