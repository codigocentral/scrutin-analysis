use std::collections::HashMap;
use std::path::PathBuf;

use serde::Deserialize;

use crate::engine::IssueSeverity;
use crate::error::Result;

pub const RULE_FILES: &[&str] = &[
    "AllRules.json",
    "DetectionPatterns.json",
    "CodeAnalysisRules.json",
    "LanguagePrompts.json",
    "AutoFixPatterns.json",
];

#[derive(Debug, Clone)]
pub struct RulesService {
    pub rules_version: String,
    rules_dir: Option<PathBuf>,
    rule_meta: HashMap<String, RuleMeta>,
    detection_patterns: HashMap<String, Vec<PatternRule>>,
    auto_fix_patterns: HashMap<String, Vec<AutoFixPattern>>,
    language_extensions: HashMap<String, Vec<String>>,
    language_file_names: HashMap<String, Vec<String>>,
    _analysis_rules: serde_json::Value,
}

#[derive(Debug, Clone)]
pub struct RuleMeta {
    pub name: String,
    pub severity: String,
    pub cwe: Vec<String>,
    pub owasp_top10: Vec<String>,
    pub owasp_asvs: Vec<String>,
    pub compliance_standards: Vec<String>,
    pub canonical_category: Option<String>,
    pub canonical_subcategory: Option<String>,
}

#[derive(Debug, Clone)]
pub struct PatternRule {
    pub rule_id: String,
    pub category: PatternCategory,
    pub patterns: Vec<String>,
    pub message: String,
    pub suggestion: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PatternCategory {
    Vulnerability,
    SecurityHotspot,
    Bug,
    CodeSmell,
    React,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AutoFixPattern {
    pub rule_id: String,
    pub name: Option<String>,
    pub description: String,
    pub find_pattern: String,
    pub replace_template: Option<String>,
    #[serde(default)]
    pub is_safe: bool,
    #[serde(default)]
    pub confidence: f64,
    #[serde(default)]
    pub breaking_changes: Option<Vec<String>>,
}

impl RulesService {
    pub fn load() -> Result<Self> {
        Self::load_from_dir(resolve_rules_dir())
    }

    pub fn load_from_dir(rules_dir: Option<PathBuf>) -> Result<Self> {
        let all_rules: serde_json::Value = load_json(
            "AllRules.json",
            include_str!("../rules/AllRules.json"),
            rules_dir.as_ref(),
        )?;
        let detection: serde_json::Value = load_json(
            "DetectionPatterns.json",
            include_str!("../rules/DetectionPatterns.json"),
            rules_dir.as_ref(),
        )?;
        let analysis_rules: serde_json::Value = load_json(
            "CodeAnalysisRules.json",
            include_str!("../rules/CodeAnalysisRules.json"),
            rules_dir.as_ref(),
        )?;
        let prompts: LanguagePromptsFile = load_json(
            "LanguagePrompts.json",
            include_str!("../rules/LanguagePrompts.json"),
            rules_dir.as_ref(),
        )?;
        let auto_fix_patterns: serde_json::Value = load_json(
            "AutoFixPatterns.json",
            include_str!("../rules/AutoFixPatterns.json"),
            rules_dir.as_ref(),
        )?;

        // SEGURANÇA #6: Não silenciar erro de versão ausente
        let version = all_rules
            .get("version")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                crate::error::AnalysisError::message("Rules file missing 'version' field".to_string())
            })?
            .to_string();

        Ok(Self {
            rules_version: version,
            rules_dir,
            rule_meta: extract_rule_meta(&all_rules),
            detection_patterns: extract_patterns(&detection),
            auto_fix_patterns: extract_auto_fix_patterns(&auto_fix_patterns),
            language_extensions: collect_language_extensions(&prompts),
            language_file_names: collect_language_file_names(&prompts),
            _analysis_rules: analysis_rules,
        })
    }

    // PERFORMANCE #7: Retorna referência em vez de clonar
    pub fn rules_dir(&self) -> Option<&PathBuf> {
        self.rules_dir.as_ref()
    }

    pub fn detect_language(&self, file_path: &str) -> Option<String> {
        let lower_path = file_path.to_lowercase();
        let file_name = std::path::Path::new(file_path)
            .file_name()
            .and_then(|name| name.to_str())
            .map(|name| name.to_lowercase());

        if let Some(file_name) = file_name.as_ref() {
            if let Some((lang, _)) = self.language_file_names.iter().find(|(_, names)| {
                names.iter().any(|candidate| {
                    let normalized = candidate.to_lowercase();
                    file_name == &normalized || lower_path.ends_with(&normalized)
                })
            }) {
                return Some(lang.clone());
            }
        }

        let ext = file_path
            .rsplit('.')
            .next()
            .map(|e| format!(".{}", e.to_lowercase()))?;

        self.language_extensions.iter().find_map(|(lang, exts)| {
            if exts.iter().any(|e| e.eq_ignore_ascii_case(&ext)) {
                Some(lang.clone())
            } else {
                None
            }
        })
    }

    // PERFORMANCE #8: Retorna referência em vez de clonar Vec inteiro
    pub fn patterns_for_language(&self, language: &str) -> &[PatternRule] {
        match language.to_lowercase().as_str() {
            "javascript" | "js" => self
                .detection_patterns
                .get("typescript")
                .map(|v| v.as_slice())
                .unwrap_or(&[]),
            "typescript" | "ts" => self
                .detection_patterns
                .get("typescript")
                .map(|v| v.as_slice())
                .unwrap_or(&[]),
            "csharp" | "c#" => self
                .detection_patterns
                .get("csharp")
                .map(|v| v.as_slice())
                .unwrap_or(&[]),
            "python" | "py" => self
                .detection_patterns
                .get("python")
                .map(|v| v.as_slice())
                .unwrap_or(&[]),
            "go" | "golang" => self
                .detection_patterns
                .get("go")
                .map(|v| v.as_slice())
                .unwrap_or(&[]),
            "java" => self
                .detection_patterns
                .get("java")
                .map(|v| v.as_slice())
                .unwrap_or(&[]),
            "rust" | "rs" => self
                .detection_patterns
                .get("rust")
                .map(|v| v.as_slice())
                .unwrap_or(&[]),
            "php" => self
                .detection_patterns
                .get("php")
                .map(|v| v.as_slice())
                .unwrap_or(&[]),
            "kotlin" | "kt" => self
                .detection_patterns
                .get("kotlin")
                .map(|v| v.as_slice())
                .unwrap_or(&[]),
            "ruby" | "rb" => self
                .detection_patterns
                .get("ruby")
                .map(|v| v.as_slice())
                .unwrap_or(&[]),
            other => self
                .detection_patterns
                .get(other)
                .map(|v| v.as_slice())
                .unwrap_or(&[]),
        }
    }

    pub fn pattern_languages(&self) -> Vec<&str> {
        let mut languages = self
            .detection_patterns
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>();
        languages.sort_unstable();
        languages
    }

    pub fn find_rule(&self, rule_id: &str) -> Option<&RuleMeta> {
        self.rule_meta.get(rule_id)
    }

    pub fn map_severity(&self, sonar_severity: Option<&str>) -> IssueSeverity {
        match sonar_severity.unwrap_or("MAJOR").to_uppercase().as_str() {
            "BLOCKER" | "CRITICAL" => IssueSeverity::Critical,
            "MAJOR" => IssueSeverity::High,
            "MINOR" => IssueSeverity::Medium,
            "INFO" => IssueSeverity::Info,
            _ => IssueSeverity::Medium,
        }
    }

    pub fn get_auto_fix_patterns(&self, language: &str, rule_id: &str) -> Vec<AutoFixPattern> {
        let key = normalize_language_key(language);
        self.auto_fix_patterns
            .get(&key)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .filter(|pattern| pattern.rule_id == rule_id)
            .collect()
    }
}

fn resolve_rules_dir() -> Option<PathBuf> {
    if let Ok(custom_rules_dir) = std::env::var("SCRUTIN_RULES_DIR") {
        let trimmed = custom_rules_dir.trim();
        if !trimmed.is_empty() {
            return Some(PathBuf::from(trimmed));
        }
    }

    if let Some(home_dir) = dirs::home_dir() {
        return Some(home_dir.join(".scrutin").join("rules"));
    }

    if let Ok(current_dir) = std::env::current_dir() {
        return Some(current_dir.join(".scrutin").join("rules"));
    }

    // Sem diretório seguro disponível: usar apenas regras embedded.
    None
}

fn load_json<T: serde::de::DeserializeOwned>(
    filename: &str,
    embedded: &str,
    rules_dir: Option<&PathBuf>,
) -> Result<T> {
    if let Some(dir) = rules_dir {
        let local = dir.join(filename);
        if local.exists() {
            let content = std::fs::read_to_string(local)?;
            return Ok(serde_json::from_str(&content)?);
        }

        let cache = dir.join("cache").join(filename);
        if cache.exists() {
            let content = std::fs::read_to_string(cache)?;
            return Ok(serde_json::from_str(&content)?);
        }
    }

    Ok(serde_json::from_str(embedded)?)
}

fn extract_rule_meta(root: &serde_json::Value) -> HashMap<String, RuleMeta> {
    let mut map = HashMap::new();
    let categories = [
        "vulnerabilities",
        "security_hotspots",
        "bugs",
        "code_smells",
        "react",
    ];

    if let Some(obj) = root.as_object() {
        for (_, value) in obj {
            if let Some(lang_obj) = value.as_object() {
                for category in categories {
                    if let Some(entries) = lang_obj.get(category).and_then(|v| v.as_array()) {
                        for entry in entries {
                            let Some(id) = entry.get("id").and_then(|v| v.as_str()) else {
                                continue;
                            };
                            let id = id.to_string();
                            let name = entry
                                .get("name")
                                .and_then(|v| v.as_str())
                                .unwrap_or(&id)
                                .to_string();
                            let severity = entry
                                .get("severity")
                                .and_then(|v| v.as_str())
                                .unwrap_or("MAJOR")
                                .to_string();
                            let cwe = entry
                                .get("cwe")
                                .and_then(|v| v.as_array())
                                .map(|list| {
                                    list.iter()
                                        .filter_map(|v| v.as_str().map(ToString::to_string))
                                        .collect::<Vec<_>>()
                                })
                                .unwrap_or_default();
                            let owasp_top10 = entry
                                .get("owaspTop10")
                                .and_then(|v| v.as_array())
                                .map(|list| {
                                    list.iter()
                                        .filter_map(|v| v.as_str().map(ToString::to_string))
                                        .collect::<Vec<_>>()
                                })
                                .unwrap_or_default();
                            let owasp_asvs = entry
                                .get("owaspAsvs")
                                .and_then(|v| v.as_array())
                                .map(|list| {
                                    list.iter()
                                        .filter_map(|v| v.as_str().map(ToString::to_string))
                                        .collect::<Vec<_>>()
                                })
                                .unwrap_or_default();
                            let compliance_standards = entry
                                .get("complianceStandards")
                                .and_then(|v| v.as_array())
                                .map(|list| {
                                    list.iter()
                                        .filter_map(|v| v.as_str().map(ToString::to_string))
                                        .collect::<Vec<_>>()
                                })
                                .unwrap_or_default();
                            map.entry(id.clone()).or_insert(RuleMeta {
                                name,
                                severity,
                                cwe,
                                owasp_top10,
                                owasp_asvs,
                                compliance_standards,
                                canonical_category: entry
                                    .get("canonicalCategory")
                                    .and_then(|v| v.as_str())
                                    .map(ToString::to_string),
                                canonical_subcategory: entry
                                    .get("canonicalSubcategory")
                                    .and_then(|v| v.as_str())
                                    .map(ToString::to_string),
                            });
                        }
                    }
                }
            }
        }
    }

    map
}

fn extract_patterns(root: &serde_json::Value) -> HashMap<String, Vec<PatternRule>> {
    let mut map = HashMap::new();

    let Some(obj) = root.as_object() else {
        return map;
    };

    for (key, value) in obj {
        if is_rules_metadata_key(key) {
            continue;
        }

        if let Ok(patterns) = serde_json::from_value::<LanguagePatterns>(value.clone()) {
            insert_lang_patterns(&mut map, &normalize_language_key(key), Some(patterns));
        }
    }

    map
}

fn extract_auto_fix_patterns(root: &serde_json::Value) -> HashMap<String, Vec<AutoFixPattern>> {
    let mut map = HashMap::new();

    let Some(patterns) = root.get("patterns").and_then(|value| value.as_object()) else {
        return map;
    };

    for (key, value) in patterns {
        if let Ok(entries) = serde_json::from_value::<Vec<AutoFixPattern>>(value.clone()) {
            map.insert(normalize_language_key(key), entries);
        }
    }

    map
}

fn normalize_language_key(language: &str) -> String {
    match language.to_lowercase().as_str() {
        "typescript" | "ts" => "typescript".to_string(),
        "javascript" | "js" => "typescript".to_string(),
        "csharp" | "c#" => "csharp".to_string(),
        "python" | "py" => "python".to_string(),
        "go" | "golang" => "go".to_string(),
        "java" => "java".to_string(),
        "rust" | "rs" => "rust".to_string(),
        "cpp" | "c++" | "c" | "cc" | "cxx" | "hpp" | "hxx" => "cpp".to_string(),
        "docker" => "dockerfile".to_string(),
        "compose" => "docker-compose".to_string(),
        "k8s" => "kubernetes".to_string(),
        "tf" => "terraform".to_string(),
        "yml" => "yaml".to_string(),
        "github_workflows" | "github-actions" => "github-actions".to_string(),
        "gitlabci" | "gitlab-ci" => "gitlab-ci".to_string(),
        "azure" | "azure_pipelines" | "azure-pipelines" => "azure-pipelines".to_string(),
        "secret" | "secrets" => "generic".to_string(),
        other => other.to_string(),
    }
}

fn collect_language_extensions(
    prompts: &LanguagePromptsFile,
) -> HashMap<String, Vec<String>> {
    let mut map = HashMap::new();
    for (key, prompt) in &prompts.languages {
        let normalized = normalize_language_key(key);
        let entry = map.entry(normalized).or_insert_with(Vec::new);
        merge_string_values(entry, prompt.file_extensions.clone());
    }
    map
}

fn collect_language_file_names(
    prompts: &LanguagePromptsFile,
) -> HashMap<String, Vec<String>> {
    let mut map = HashMap::new();
    for (key, prompt) in &prompts.languages {
        if prompt.file_names.is_empty() {
            continue;
        }
        let normalized = normalize_language_key(key);
        let entry = map.entry(normalized).or_insert_with(Vec::new);
        merge_string_values(entry, prompt.file_names.clone());
    }
    map
}

fn merge_string_values(target: &mut Vec<String>, values: Vec<String>) {
    for value in values {
        if !target
            .iter()
            .any(|existing| existing.eq_ignore_ascii_case(&value))
        {
            target.push(value);
        }
    }
}

fn is_rules_metadata_key(key: &str) -> bool {
    matches!(
        key,
        "$schema"
            | "version"
            | "description"
            | "lastUpdated"
            | "totalPatterns"
            | "source"
            | "totalRules"
            | "statistics"
    )
}

fn insert_lang_patterns(
    map: &mut HashMap<String, Vec<PatternRule>>,
    key: &str,
    patterns: Option<LanguagePatterns>,
) {
    if let Some(p) = patterns {
        let mut rules = Vec::new();
        append_rules(
            &mut rules,
            p.vulnerabilities,
            PatternCategory::Vulnerability,
        );
        append_rules(
            &mut rules,
            p.security_hotspots,
            PatternCategory::SecurityHotspot,
        );
        append_rules(&mut rules, p.bugs, PatternCategory::Bug);
        append_rules(&mut rules, p.code_smells, PatternCategory::CodeSmell);
        append_rules(&mut rules, p.react, PatternCategory::React);
        map.insert(key.to_string(), rules);
    }
}

fn append_rules(
    out: &mut Vec<PatternRule>,
    entries: Option<Vec<RawPatternRule>>,
    category: PatternCategory,
) {
    if let Some(entries) = entries {
        out.extend(entries.into_iter().map(|r| PatternRule {
            rule_id: r.rule_id,
            category,
            patterns: r.patterns,
            message: r.message,
            suggestion: r.suggestion,
        }));
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LanguagePatterns {
    #[serde(default)]
    vulnerabilities: Option<Vec<RawPatternRule>>,
    #[serde(default)]
    security_hotspots: Option<Vec<RawPatternRule>>,
    #[serde(default)]
    bugs: Option<Vec<RawPatternRule>>,
    #[serde(default)]
    code_smells: Option<Vec<RawPatternRule>>,
    #[serde(default)]
    react: Option<Vec<RawPatternRule>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawPatternRule {
    rule_id: String,
    patterns: Vec<String>,
    message: String,
    suggestion: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LanguagePromptsFile {
    languages: HashMap<String, LanguagePrompt>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LanguagePrompt {
    file_extensions: Vec<String>,
    #[serde(default)]
    file_names: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rules_loads_embedded() {
        let rules = RulesService::load().unwrap();
        assert!(!rules.rules_version.is_empty());
        assert!(rules.find_rule("S3649").is_some());
    }

    #[test]
    fn test_detect_language_by_extension() {
        let rules = RulesService::load().unwrap();
        assert_eq!(
            rules.detect_language("src/file.ts").as_deref(),
            Some("typescript")
        );
    }

    #[test]
    fn test_rule_files_whitelist_contains_five_entries() {
        assert_eq!(RULE_FILES.len(), 5);
        assert!(RULE_FILES.contains(&"AllRules.json"));
        assert!(RULE_FILES.contains(&"AutoFixPatterns.json"));
    }

    #[test]
    fn test_get_auto_fix_patterns() {
        let rules = RulesService::load().unwrap();
        let patterns = rules.get_auto_fix_patterns("csharp", "S3649");
        assert!(!patterns.is_empty());
    }

    #[test]
    fn test_get_auto_fix_patterns_for_php_kotlin_and_ruby() {
        let rules = RulesService::load().unwrap();

        assert!(!rules.get_auto_fix_patterns("php", "S1656").is_empty());
        assert!(!rules.get_auto_fix_patterns("kotlin", "S1656").is_empty());
        assert!(!rules.get_auto_fix_patterns("ruby", "S1656").is_empty());
    }

    #[test]
    fn test_loads_cpp_patterns_from_custom_rules_dir() {
        use std::fs;
        use tempfile::tempdir;

        let temp_dir = tempdir().unwrap();
        let rules_dir = temp_dir.path();

        fs::write(
            rules_dir.join("AllRules.json"),
            r#"{
  "version": "test-1",
  "cpp": {
    "vulnerabilities": [
      {
        "id": "CPP-SEC-001",
        "name": "Unsafe copy",
        "severity": "CRITICAL",
        "cwe": ["CWE-120"],
        "canonicalCategory": "security",
        "canonicalSubcategory": "memory-safety",
        "owaspTop10": ["A03:2021"],
        "owaspAsvs": ["V5"],
        "complianceStandards": ["NIST SSDF"]
      }
    ]
  }
}"#,
        )
        .unwrap();
        fs::write(
            rules_dir.join("DetectionPatterns.json"),
            r#"{
  "version": "1.0.0",
  "cpp": {
    "vulnerabilities": [
      {
        "ruleId": "CPP-SEC-001",
        "patterns": ["strcpy\\s*\\("],
        "message": "Avoid unsafe copy",
        "suggestion": "Use strncpy"
      }
    ]
  }
}"#,
        )
        .unwrap();
        fs::write(
            rules_dir.join("CodeAnalysisRules.json"),
            r#"{"languageRules":{}}"#,
        )
        .unwrap();
        fs::write(
            rules_dir.join("LanguagePrompts.json"),
            r#"{
  "languages": {
    "cpp": {
      "fileExtensions": [".cpp", ".hpp"]
    }
  }
}"#,
        )
        .unwrap();
        fs::write(
            rules_dir.join("AutoFixPatterns.json"),
            r#"{
  "patterns": {
    "cpp": [
      {
        "ruleId": "CPP-SEC-001",
        "description": "Replace unsafe copy",
        "findPattern": "strcpy\\(([^,]+),\\s*([^)]+)\\)",
        "replaceTemplate": "strncpy($1, $2, sizeof($1) - 1)",
        "isSafe": false,
        "confidence": 0.7
      }
    ]
  }
}"#,
        )
        .unwrap();

        let rules = RulesService::load_from_dir(Some(rules_dir.to_path_buf())).unwrap();

        assert_eq!(
            rules.detect_language("src/native/foo.cpp").as_deref(),
            Some("cpp")
        );
        assert_eq!(rules.patterns_for_language("cpp").len(), 1);
        assert_eq!(rules.get_auto_fix_patterns("cpp", "CPP-SEC-001").len(), 1);
        let rule = rules.find_rule("CPP-SEC-001").unwrap();
        assert_eq!(rule.canonical_category.as_deref(), Some("security"));
        assert_eq!(rule.canonical_subcategory.as_deref(), Some("memory-safety"));
        assert!(rule.owasp_top10.contains(&"A03:2021".to_string()));
        assert!(rule.compliance_standards.contains(&"NIST SSDF".to_string()));
    }

    #[test]
    fn test_detect_language_with_special_file_names() {
        use std::fs;
        use tempfile::tempdir;

        let temp_dir = tempdir().unwrap();
        let rules_dir = temp_dir.path();

        fs::write(
            rules_dir.join("AllRules.json"),
            r#"{
  "version": "test-1",
  "dockerfile": {
    "vulnerabilities": [
      { "id": "DOCKER-001", "name": "Avoid root", "severity": "CRITICAL", "cwe": ["CWE-250"] }
    ]
  }
}"#,
        )
        .unwrap();
        fs::write(
            rules_dir.join("DetectionPatterns.json"),
            r#"{
  "version": "1.0.0",
  "dockerfile": {
    "vulnerabilities": [
      {
        "ruleId": "DOCKER-001",
        "patterns": ["USER\\s+root"],
        "message": "Avoid root"
      }
    ]
  }
}"#,
        )
        .unwrap();
        fs::write(
            rules_dir.join("CodeAnalysisRules.json"),
            r#"{"languageRules":{}}"#,
        )
        .unwrap();
        fs::write(
            rules_dir.join("LanguagePrompts.json"),
            r#"{
  "languages": {
    "dockerfile": {
      "fileExtensions": [],
      "fileNames": ["Dockerfile", "Containerfile"]
    }
  }
}"#,
        )
        .unwrap();
        fs::write(
            rules_dir.join("AutoFixPatterns.json"),
            r#"{"patterns":{"dockerfile":[]}}"#,
        )
        .unwrap();

        let rules = RulesService::load_from_dir(Some(rules_dir.to_path_buf())).unwrap();

        assert_eq!(
            rules
                .detect_language("/repo/services/api/Dockerfile")
                .as_deref(),
            Some("dockerfile")
        );
    }

    #[test]
    fn test_detect_language_with_embedded_catalog_file_names() {
        let rules = RulesService::load().unwrap();

        assert_eq!(
            rules
                .detect_language("/repo/infra/pipelines/azure-pipelines.yml")
                .as_deref(),
            Some("azure-pipelines")
        );
        assert_eq!(
            rules
                .detect_language("/repo/deploy/.gitlab-ci.yml")
                .as_deref(),
            Some("gitlab-ci")
        );
        assert_eq!(
            rules
                .detect_language("/repo/containers/docker-compose.yml")
                .as_deref(),
            Some("docker-compose")
        );
        assert_eq!(
            rules
                .detect_language("/repo/native/include/header.hpp")
                .as_deref(),
            Some("cpp")
        );
    }
}
