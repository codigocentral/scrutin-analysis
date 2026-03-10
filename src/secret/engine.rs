//! Secret Detection Engine
//!
//! Core engine for detecting secrets, API keys, tokens, and credentials in source code.

use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

use crate::diff_parser::{DiffFile, DiffLine};
use crate::error::Result;
use crate::models::AnalysisIssue;

use super::allowlist::{
    contains_path_traversal, get_global_allowlist, get_ignore_path_patterns, is_allowlisted,
    is_global_ignored_path, is_repetitive, looks_like_placeholder, should_ignore_path,
};
use super::mask::mask_secret;
use super::parser::GitleaksParser;
use super::patterns::{load_embedded_rules, SecretRule};

/// Severity levels for secrets
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SecretSeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for SecretSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SecretSeverity::Low => write!(f, "low"),
            SecretSeverity::Medium => write!(f, "medium"),
            SecretSeverity::High => write!(f, "high"),
            SecretSeverity::Critical => write!(f, "critical"),
        }
    }
}

impl From<&str> for SecretSeverity {
    fn from(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "critical" => SecretSeverity::Critical,
            "high" => SecretSeverity::High,
            "medium" => SecretSeverity::Medium,
            "low" => SecretSeverity::Low,
            _ => SecretSeverity::High,
        }
    }
}

/// Represents a secret found in the code
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretFinding {
    pub rule_id: String,
    pub file_path: String,
    pub line_number: u32,
    pub matched_text: String,
    pub masked_text: String,
    pub severity: SecretSeverity,
    pub title: String,
    pub message: String,
    pub suggestion: String,
    pub provider: String,
    pub confidence: f64,
}

impl SecretFinding {
    pub fn to_analysis_issue(&self) -> AnalysisIssue {
        AnalysisIssue {
            rule_id: Some(self.rule_id.clone()),
            file_path: self.file_path.clone(),
            line_start: self.line_number,
            line_end: Some(self.line_number),
            severity: self.severity.to_string(),
            category: "secret".to_string(),
            title: self.title.clone(),
            description: format!("{} (detected: {})", self.message, self.masked_text),
            suggestion: Some(self.suggestion.clone()),
            code_snippet: Some(self.matched_text.clone()),
            confidence: self.confidence,
            source: "secret-detection".to_string(),
        }
    }
}

/// Compiled rule with pre-compiled regex patterns
#[derive(Clone)]
struct CompiledSecretRule {
    rule: SecretRule,
    patterns: Vec<Regex>,
    allowlist: Vec<Regex>,
    keywords_lower: Vec<String>,
}

/// Scan options for secret detection
#[derive(Debug, Clone)]
pub struct SecretScanOptions {
    pub ignore_paths: Vec<String>,
    pub max_findings: Option<usize>,
    pub minimum_severity: SecretSeverity,
    pub include_rules: Vec<String>,
    pub exclude_rules: Vec<String>,
}

impl Default for SecretScanOptions {
    fn default() -> Self {
        Self {
            ignore_paths: Vec::new(),
            max_findings: None,
            minimum_severity: SecretSeverity::Low,
            include_rules: Vec::new(),
            exclude_rules: Vec::new(),
        }
    }
}

/// Configuration for loading rules
#[derive(Debug, Clone)]
pub struct SecretEngineConfig {
    pub api_endpoint: Option<String>,
    pub api_token: Option<String>,
    pub cache_file: Option<std::path::PathBuf>,
    pub use_embedded_fallback: bool,
    pub gitleaks_config_path: Option<std::path::PathBuf>,
}

impl Default for SecretEngineConfig {
    fn default() -> Self {
        Self {
            api_endpoint: std::env::var("SCRUTIN_API_URL").ok(),
            api_token: std::env::var("SCRUTIN_API_TOKEN").ok(),
            cache_file: dirs::home_dir()
                .map(|d| d.join(".scrutin").join("secret_rules_cache.json")),
            use_embedded_fallback: true,
            gitleaks_config_path: None,
        }
    }
}

/// Statistics about the engine
#[derive(Debug, Clone)]
pub struct SecretEngineStats {
    pub total_rules: usize,
    pub by_provider: HashMap<String, usize>,
    pub by_severity: HashMap<String, usize>,
}

/// Secret Detection Engine
pub struct SecretEngine {
    rules: Vec<CompiledSecretRule>,
    global_allowlist: Vec<Regex>,
    _ignore_paths: Vec<Regex>,
}

impl SecretEngine {
    /// Loads engine with embedded rules (~200+ rules)
    pub fn load() -> Result<Self> {
        let rules = load_embedded_rules();
        Self::from_rules(&rules)
    }

    /// Loads engine with configuration
    pub fn load_with_config(config: &SecretEngineConfig) -> Result<Self> {
        // Try loading Gitleaks config if provided
        if let Some(gitleaks_path) = &config.gitleaks_config_path {
            if gitleaks_path.exists() {
                match GitleaksParser::load_from_file(gitleaks_path) {
                    Ok(gitleaks_config) => {
                        let gitleaks_rules = GitleaksParser::to_secret_rules(&gitleaks_config)?;
                        let merged = GitleaksParser::merge_with_embedded(gitleaks_rules);
                        tracing::info!("Loaded {} rules from Gitleaks config", merged.len());
                        return Self::from_rules(&merged);
                    }
                    Err(e) => {
                        tracing::warn!("Failed to load Gitleaks config: {}", e);
                    }
                }
            }
        }

        // Try cache
        if let Some(cache) = &config.cache_file {
            if cache.exists() {
                match Self::load_from_file(cache) {
                    Ok(engine) => {
                        tracing::info!("Loaded secret rules from cache: {:?}", cache);
                        return Ok(engine);
                    }
                    Err(e) => {
                        tracing::warn!("Failed to load from cache: {}", e);
                    }
                }
            }
        }

        // Fallback to embedded
        if config.use_embedded_fallback {
            tracing::info!("Using embedded secret detection rules");
            Self::load()
        } else {
            Err(crate::error::AnalysisError::message(
                "No secret rules available and fallback disabled",
            ))
        }
    }

    /// Loads rules from a JSON file
    pub fn load_from_file(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let rules: Vec<SecretRule> = serde_json::from_str(&content)?;
        Self::from_rules(&rules)
    }

    /// Saves current rules to a JSON file
    pub fn save_to_file(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let rules: Vec<&SecretRule> = self.rules.iter().map(|c| &c.rule).collect();
        let json = serde_json::to_string_pretty(&rules)?;
        std::fs::write(path, json)?;

        Ok(())
    }

    /// Creates engine from a list of rules
    pub fn from_rules(rules: &[SecretRule]) -> Result<Self> {
        let mut compiled = Vec::with_capacity(rules.len());

        for rule in rules {
            let compiled_patterns = compile_patterns(&rule.patterns)?;
            let allowlist = compile_patterns(&rule.allowlist_patterns).unwrap_or_default();
            let keywords_lower: Vec<String> =
                rule.keywords.iter().map(|kw| kw.to_lowercase()).collect();

            compiled.push(CompiledSecretRule {
                rule: rule.clone(),
                patterns: compiled_patterns,
                allowlist,
                keywords_lower,
            });
        }

        Ok(Self {
            rules: compiled,
            global_allowlist: get_global_allowlist().clone(),
            _ignore_paths: get_ignore_path_patterns().clone(),
        })
    }

    /// Scans diff files
    pub fn scan_diff(&self, files: &[DiffFile], options: &SecretScanOptions) -> Vec<SecretFinding> {
        let estimated_capacity = files
            .iter()
            .map(|f| f.added_lines.len())
            .sum::<usize>()
            .min(1000);
        let mut findings = Vec::with_capacity(estimated_capacity);

        for file in files {
            if contains_path_traversal(&file.path) {
                tracing::warn!("Path traversal detected and rejected: {}", file.path);
                continue;
            }

            if should_ignore_path(&file.path, &options.ignore_paths) {
                continue;
            }

            if is_global_ignored_path(&file.path) {
                continue;
            }

            for line in &file.added_lines {
                if let Some(finding) = self.scan_line(&file.path, line) {
                    if finding.severity < options.minimum_severity {
                        continue;
                    }

                    if !options.include_rules.is_empty()
                        && !options.include_rules.contains(&finding.rule_id)
                    {
                        continue;
                    }
                    if options.exclude_rules.contains(&finding.rule_id) {
                        continue;
                    }

                    findings.push(finding);
                }
            }

            if let Some(max) = options.max_findings {
                if findings.len() >= max {
                    findings.truncate(max);
                    break;
                }
            }
        }

        findings.sort_by(|a, b| {
            b.severity
                .cmp(&a.severity)
                .then_with(|| a.file_path.cmp(&b.file_path))
                .then_with(|| a.line_number.cmp(&b.line_number))
        });

        findings
    }

    /// Scans a single line
    fn scan_line(&self, file_path: &str, line: &DiffLine) -> Option<SecretFinding> {
        let content = &line.content;
        let content_lower = content.to_lowercase();

        for compiled in &self.rules {
            if !compiled.keywords_lower.is_empty() {
                let has_keyword = compiled
                    .keywords_lower
                    .iter()
                    .any(|kw| content_lower.contains(kw));
                if !has_keyword {
                    continue;
                }
            }

            for pattern in &compiled.patterns {
                if let Some(mat) = pattern.find(content) {
                    let matched_text = mat.as_str().to_string();

                    if is_allowlisted(&matched_text, &compiled.allowlist) {
                        continue;
                    }

                    if is_allowlisted(&matched_text, &self.global_allowlist) {
                        continue;
                    }

                    if looks_like_placeholder(&matched_text) {
                        continue;
                    }

                    if is_repetitive(&matched_text) {
                        continue;
                    }

                    let masked = mask_secret(&matched_text);
                    let severity = SecretSeverity::from(compiled.rule.severity.as_str());

                    return Some(SecretFinding {
                        rule_id: compiled.rule.rule_id.clone(),
                        file_path: file_path.to_string(),
                        line_number: line.line_number as u32,
                        matched_text: matched_text.clone(),
                        masked_text: masked,
                        severity,
                        title: compiled.rule.title.clone(),
                        message: compiled.rule.message.clone(),
                        suggestion: compiled
                            .rule
                            .suggestion
                            .clone()
                            .unwrap_or_else(|| {
                                "Remove this secret from the code and rotate it immediately. Use environment variables or a secrets manager.".to_string()
                            }),
                        provider: compiled.rule.provider.clone(),
                        confidence: calculate_confidence(&matched_text, compiled.rule.entropy),
                    });
                }
            }
        }

        None
    }

    /// Scans a single file
    pub fn scan_file(&self, file_path: &Path, options: &SecretScanOptions) -> Vec<SecretFinding> {
        let path_str = file_path.to_string_lossy();
        if should_ignore_path(&path_str, &options.ignore_paths) || is_global_ignored_path(&path_str)
        {
            return Vec::new();
        }

        let content = match std::fs::read_to_string(file_path) {
            Ok(c) => c,
            Err(_) => return Vec::new(),
        };

        self.scan_content(&path_str, &content, options)
    }

    /// Scans content string
    pub fn scan_content(
        &self,
        file_path: &str,
        content: &str,
        options: &SecretScanOptions,
    ) -> Vec<SecretFinding> {
        let lines: Vec<&str> = content.lines().collect();
        let estimated = lines.len() / 100;
        let mut findings = Vec::with_capacity(estimated.min(100));

        for (line_num, line_content) in lines.iter().enumerate() {
            let line = DiffLine {
                line_number: line_num + 1,
                content: line_content.to_string(),
            };

            if let Some(finding) = self.scan_line(file_path, &line) {
                if finding.severity < options.minimum_severity {
                    continue;
                }

                if !options.include_rules.is_empty()
                    && !options.include_rules.contains(&finding.rule_id)
                {
                    continue;
                }
                if options.exclude_rules.contains(&finding.rule_id) {
                    continue;
                }

                findings.push(finding);
            }

            if let Some(max) = options.max_findings {
                if findings.len() >= max {
                    findings.truncate(max);
                    break;
                }
            }
        }

        findings.sort_by(|a, b| {
            b.severity
                .cmp(&a.severity)
                .then_with(|| a.file_path.cmp(&b.file_path))
                .then_with(|| a.line_number.cmp(&b.line_number))
        });

        findings
    }

    /// Scans a directory recursively
    pub fn scan_directory(
        &self,
        dir_path: &Path,
        options: &SecretScanOptions,
        max_files: Option<usize>,
    ) -> Vec<SecretFinding> {
        let mut findings = Vec::with_capacity(64);
        let mut files_scanned = 0;

        for entry in walkdir::WalkDir::new(dir_path)
            .follow_links(false)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            if entry.file_type().is_file() {
                let path = entry.path();
                let file_findings = self.scan_file(path, options);
                findings.extend(file_findings);

                files_scanned += 1;
                if let Some(max) = max_files {
                    if files_scanned >= max {
                        break;
                    }
                }

                if let Some(max) = options.max_findings {
                    if findings.len() >= max {
                        findings.truncate(max);
                        break;
                    }
                }
            }
        }

        findings
    }

    /// Returns engine statistics
    pub fn stats(&self) -> SecretEngineStats {
        let mut by_provider: HashMap<&str, usize> = HashMap::with_capacity(20);
        let mut by_severity: HashMap<&str, usize> = HashMap::with_capacity(5);

        for compiled in &self.rules {
            *by_provider
                .entry(compiled.rule.provider.as_str())
                .or_insert(0) += 1;
            *by_severity
                .entry(compiled.rule.severity.as_str())
                .or_insert(0) += 1;
        }

        SecretEngineStats {
            total_rules: self.rules.len(),
            by_provider: by_provider
                .into_iter()
                .map(|(k, v)| (k.to_string(), v))
                .collect(),
            by_severity: by_severity
                .into_iter()
                .map(|(k, v)| (k.to_string(), v))
                .collect(),
        }
    }

}

/// Compiles regex patterns
fn compile_patterns(patterns: &[String]) -> Result<Vec<Regex>> {
    patterns
        .iter()
        .map(|p| Regex::new(p).map_err(crate::error::AnalysisError::Regex))
        .collect()
}

/// Calculates confidence score
fn calculate_confidence(text: &str, entropy: Option<f64>) -> f64 {
    let base_confidence = 0.85;
    let length_boost = (text.len() as f64 / 40.0).min(0.1);
    let entropy_factor = entropy.map(|e| (e / 10.0).min(0.05)).unwrap_or(0.0);

    (base_confidence + length_boost + entropy_factor).min(0.99)
}

/// Rotation information for a provider
#[derive(Debug, Clone)]
pub struct SecretRotationInfo {
    pub provider: String,
    pub documentation_url: String,
    pub rotation_steps: Vec<String>,
    pub revoke_url: Option<String>,
    pub severity: String,
}

/// Helper for secret rotation information
pub struct SecretRotationHelper;

impl SecretRotationHelper {
    pub fn get_rotation_info(provider: &str) -> Option<SecretRotationInfo> {
        match provider.to_lowercase().as_str() {
            "aws" => Some(SecretRotationInfo {
                provider: "AWS".to_string(),
                documentation_url: "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html".to_string(),
                rotation_steps: vec![
                    "1. Access AWS Console IAM".to_string(),
                    "2. Navigate to 'Users' or 'Access keys'".to_string(),
                    "3. Find the compromised key".to_string(),
                    "4. Click 'Delete' to revoke immediately".to_string(),
                    "5. Create a new access key".to_string(),
                    "6. Update your applications with the new key".to_string(),
                ],
                revoke_url: Some("https://console.aws.amazon.com/iam/".to_string()),
                severity: "critical".to_string(),
            }),
            "github" => Some(SecretRotationInfo {
                provider: "GitHub".to_string(),
                documentation_url: "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/reviewing-your-security-log".to_string(),
                rotation_steps: vec![
                    "1. Access GitHub Settings".to_string(),
                    "2. Go to 'Developer settings' > 'Personal access tokens'".to_string(),
                    "3. Find the compromised token".to_string(),
                    "4. Click 'Delete'".to_string(),
                    "5. Generate a new token with the same scopes".to_string(),
                ],
                revoke_url: Some("https://github.com/settings/tokens".to_string()),
                severity: "critical".to_string(),
            }),
            "stripe" => Some(SecretRotationInfo {
                provider: "Stripe".to_string(),
                documentation_url: "https://stripe.com/docs/keys".to_string(),
                rotation_steps: vec![
                    "1. Access Stripe Dashboard".to_string(),
                    "2. Go to 'Developers' > 'API keys'".to_string(),
                    "3. Click 'Roll key' to revoke and create new".to_string(),
                    "4. Update your code with the new key".to_string(),
                ],
                revoke_url: Some("https://dashboard.stripe.com/apikeys".to_string()),
                severity: "critical".to_string(),
            }),
            "slack" => Some(SecretRotationInfo {
                provider: "Slack".to_string(),
                documentation_url: "https://api.slack.com/authentication/token-types".to_string(),
                rotation_steps: vec![
                    "1. Access api.slack.com/apps".to_string(),
                    "2. Select your app".to_string(),
                    "3. Go to 'OAuth & Permissions'".to_string(),
                    "4. Revoke the compromised token".to_string(),
                    "5. Reinstall the app to generate new token".to_string(),
                ],
                revoke_url: Some("https://api.slack.com/apps".to_string()),
                severity: "critical".to_string(),
            }),
            "openai" => Some(SecretRotationInfo {
                provider: "OpenAI".to_string(),
                documentation_url: "https://platform.openai.com/account/api-keys".to_string(),
                rotation_steps: vec![
                    "1. Access platform.openai.com/account/api-keys".to_string(),
                    "2. Find the compromised key".to_string(),
                    "3. Click on the key and then 'Revoke key'".to_string(),
                    "4. Create a new API key".to_string(),
                    "5. Update your application".to_string(),
                ],
                revoke_url: Some("https://platform.openai.com/account/api-keys".to_string()),
                severity: "critical".to_string(),
            }),
            "gcp" | "google" => Some(SecretRotationInfo {
                provider: "Google Cloud".to_string(),
                documentation_url: "https://cloud.google.com/iam/docs/creating-managing-service-account-keys".to_string(),
                rotation_steps: vec![
                    "1. Access GCP Console".to_string(),
                    "2. Go to 'IAM & Admin' > 'Service Accounts'".to_string(),
                    "3. Select the service account".to_string(),
                    "4. Delete the compromised key".to_string(),
                    "5. Create a new key".to_string(),
                ],
                revoke_url: Some("https://console.cloud.google.com/iam-admin/serviceaccounts".to_string()),
                severity: "critical".to_string(),
            }),
            "gitlab" => Some(SecretRotationInfo {
                provider: "GitLab".to_string(),
                documentation_url: "https://docs.gitlab.com/ee/user/profile/personal_access_tokens.html".to_string(),
                rotation_steps: vec![
                    "1. Access GitLab User Settings".to_string(),
                    "2. Go to 'Access Tokens'".to_string(),
                    "3. Revoke the compromised token".to_string(),
                    "4. Create a new token".to_string(),
                ],
                revoke_url: Some("https://gitlab.com/-/profile/personal_access_tokens".to_string()),
                severity: "critical".to_string(),
            }),
            "vercel" => Some(SecretRotationInfo {
                provider: "Vercel".to_string(),
                documentation_url: "https://vercel.com/account/tokens".to_string(),
                rotation_steps: vec![
                    "1. Access vercel.com/account/tokens".to_string(),
                    "2. Find the compromised token".to_string(),
                    "3. Click 'Delete'".to_string(),
                    "4. Create a new token".to_string(),
                ],
                revoke_url: Some("https://vercel.com/account/tokens".to_string()),
                severity: "critical".to_string(),
            }),
            "azure" => Some(SecretRotationInfo {
                provider: "Azure".to_string(),
                documentation_url: "https://docs.microsoft.com/en-us/azure/active-directory/develop/howto-create-service-principal-portal".to_string(),
                rotation_steps: vec![
                    "1. Access Azure Portal".to_string(),
                    "2. Go to 'Azure Active Directory'".to_string(),
                    "3. 'App registrations' > Your app".to_string(),
                    "4. 'Certificates & secrets'".to_string(),
                    "5. Delete the compromised secret".to_string(),
                    "6. Add a new secret".to_string(),
                ],
                revoke_url: Some("https://portal.azure.com".to_string()),
                severity: "critical".to_string(),
            }),
            "datadog" => Some(SecretRotationInfo {
                provider: "Datadog".to_string(),
                documentation_url: "https://docs.datadoghq.com/account_management/api-app-keys/".to_string(),
                rotation_steps: vec![
                    "1. Access Datadog Organization Settings".to_string(),
                    "2. Go to 'API Keys'".to_string(),
                    "3. Revoke the compromised key".to_string(),
                    "4. Generate a new key".to_string(),
                ],
                revoke_url: Some("https://app.datadoghq.com/organization-settings/api-keys".to_string()),
                severity: "critical".to_string(),
            }),
            _ => Some(SecretRotationInfo {
                provider: "Generic".to_string(),
                documentation_url: "https://docs.github.com/en/code-security/secret-scanning/about-secret-scanning".to_string(),
                rotation_steps: vec![
                    "1. Identify the service related to the secret".to_string(),
                    "2. Access the service's console/administration".to_string(),
                    "3. Revoke the compromised token/key".to_string(),
                    "4. Generate a new token/key".to_string(),
                    "5. Update all applications".to_string(),
                ],
                revoke_url: None,
                severity: "high".to_string(),
            }),
        }
    }

    pub fn supported_providers() -> Vec<&'static str> {
        vec![
            "aws",
            "github",
            "gitlab",
            "stripe",
            "slack",
            "openai",
            "gcp",
            "google",
            "vercel",
            "npm",
            "docker",
            "azure",
            "datadog",
            "generic",
            "anthropic",
            "huggingface",
            "twilio",
            "sendgrid",
            "telegram",
            "discord",
            "shopify",
            "firebase",
            "mongodb",
            "postgres",
            "mysql",
            "redis",
            "jwt",
            "crypto",
        ]
    }

    pub fn generate_rotation_report(finding: &SecretFinding) -> String {
        let mut report = String::new();

        report.push_str("🔐 SECRET ROTATION REPORT\n");
        report.push_str("========================\n\n");
        report.push_str(&format!("Rule: {}\n", finding.rule_id));
        report.push_str(&format!("Provider: {}\n", finding.provider));
        report.push_str(&format!("Severity: {}\n", finding.severity));
        report.push_str(&format!(
            "File: {}:{}\n\n",
            finding.file_path, finding.line_number
        ));

        report.push_str(&format!("Masked Secret: {}\n", finding.masked_text));
        report.push_str(&format!("Description: {}\n\n", finding.message));

        if let Some(info) = Self::get_rotation_info(&finding.provider) {
            report.push_str("🔄 ROTATION STEPS\n");
            report.push_str("-----------------\n");
            for step in &info.rotation_steps {
                report.push_str(&format!("{}\n", step));
            }
            report.push('\n');

            report.push_str(&format!("📚 Documentation: {}\n", info.documentation_url));
            if let Some(url) = info.revoke_url {
                report.push_str(&format!("🔗 Revoke URL: {}\n", url));
            }
        } else {
            report.push_str(&format!(
                "⚠️  No specific rotation info available for provider: {}\n",
                finding.provider
            ));
            report.push_str(
                "Please refer to the provider's documentation for key rotation procedures.\n",
            );
        }

        report.push_str(&format!("\n💡 Suggestion: {}\n", finding.suggestion));

        report
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secret_engine_loads() {
        let engine = SecretEngine::load().unwrap();
        let stats = engine.stats();
        assert!(stats.total_rules >= 180);
        assert!(stats.by_provider.contains_key("aws"));
        assert!(stats.by_provider.contains_key("github"));
    }

    #[test]
    fn test_secret_finding_to_analysis_issue() {
        let finding = SecretFinding {
            rule_id: "SEC-AWS-001".to_string(),
            file_path: "config.py".to_string(),
            line_number: 42,
            matched_text: "AKIAIOSFODNN7REAL123".to_string(),
            masked_text: "AKIA****L123".to_string(),
            severity: SecretSeverity::Critical,
            title: "AWS Access Key".to_string(),
            message: "Found AWS key".to_string(),
            suggestion: "Remove it".to_string(),
            provider: "aws".to_string(),
            confidence: 0.95,
        };

        let issue = finding.to_analysis_issue();
        assert_eq!(issue.rule_id, Some("SEC-AWS-001".to_string()));
        assert_eq!(issue.category, "secret");
        assert_eq!(issue.severity, "critical");
        assert_eq!(issue.line_start, 42);
    }

    #[test]
    fn test_severity_ordering() {
        assert!(SecretSeverity::Critical > SecretSeverity::High);
        assert!(SecretSeverity::High > SecretSeverity::Medium);
        assert!(SecretSeverity::Medium > SecretSeverity::Low);
    }

    #[test]
    fn test_secret_rotation_helper() {
        let aws_info = SecretRotationHelper::get_rotation_info("aws");
        assert!(aws_info.is_some());
        let aws = aws_info.unwrap();
        assert_eq!(aws.provider, "AWS");
        assert!(!aws.rotation_steps.is_empty());

        let github_info = SecretRotationHelper::get_rotation_info("github");
        assert!(github_info.is_some());

        let stripe_info = SecretRotationHelper::get_rotation_info("stripe");
        assert!(stripe_info.is_some());
    }

    #[test]
    fn test_generate_rotation_report() {
        let finding = SecretFinding {
            rule_id: "SEC-AWS-001".to_string(),
            file_path: "config.py".to_string(),
            line_number: 42,
            matched_text: "AKIAIOSFODNN7REAL123".to_string(),
            masked_text: "AKIA****L123".to_string(),
            severity: SecretSeverity::Critical,
            title: "AWS Access Key ID Detected".to_string(),
            message: "An AWS Access Key ID was found.".to_string(),
            suggestion: "Remove the key from code and rotate it immediately.".to_string(),
            provider: "aws".to_string(),
            confidence: 0.95,
        };

        let report = SecretRotationHelper::generate_rotation_report(&finding);

        assert!(report.contains("SEC-AWS-001"));
        assert!(report.contains("AWS"));
        assert!(report.contains("critical"));
        assert!(report.contains("AKIA****L123"));
        assert!(report.contains("ROTATION STEPS"));
    }

    #[test]
    fn test_scan_content() {
        let engine = SecretEngine::load().unwrap();

        let content = r#"
            const config = {
                apiKey: "AKIAIOSFODNN7REAL123",
                secret: "super_secret_value_here"
            };
        "#;

        let options = SecretScanOptions::default();
        let findings = engine.scan_content("test.js", content, &options);

        assert!(!findings.is_empty(), "Should detect secrets in content");
    }
}
