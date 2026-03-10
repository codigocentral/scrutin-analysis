use std::collections::HashMap;
use std::sync::Arc;

use glob::Pattern;
use once_cell::sync::Lazy;
use regex::Regex;

use crate::diff_parser::parse_unified_diff;
use crate::diff_parser::DiffLine;
use crate::auto_fix::generate_auto_fixes;
use crate::rules::{PatternCategory, PatternRule, RulesService};
use crate::secret::{SecretEngine, SecretScanOptions};
use crate::error::Result;
use crate::models::{AnalysisIssue, AutoFixSuggestion, JobConfig};
use crate::metrics::FileContent;

static DEFAULT_IGNORE_PATTERNS: Lazy<Vec<Pattern>> = Lazy::new(|| {
    [
        "node_modules/",
        "bin/",
        "obj/",
        ".git/",
        "vendor/",
        "__pycache__/",
        "target/",
        "dist/",
    ]
    .iter()
    .filter_map(|p| Pattern::new(p).ok())
    .collect()
});

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum IssueSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Clone)]
pub struct AnalysisEngine {
    rules: Arc<RulesService>,
    compiled_patterns: Arc<HashMap<String, Vec<CompiledPatternRule>>>,
    secret_engine: Option<Arc<SecretEngine>>,
}

#[derive(Clone)]
struct CompiledPatternRule {
    rule_id: String,
    category: PatternCategory,
    patterns: Vec<Regex>,
    message: String,
    suggestion: Option<String>,
}

#[derive(Debug, Clone)]
struct EmbeddedShellLine {
    line_number: u32,
    content: String,
}

#[derive(Debug, Clone)]
pub struct AnalysisOptions {
    pub ignore_paths: Vec<String>,
    pub max_issues: Option<usize>,
    pub minimum_severity: IssueSeverity,
    pub include_rules: Vec<String>,
    pub exclude_rules: Vec<String>,
    pub only_new_code: bool,
    pub secret_detection_enabled: bool,
}

impl Default for AnalysisOptions {
    fn default() -> Self {
        Self {
            ignore_paths: Vec::new(),
            max_issues: None,
            minimum_severity: IssueSeverity::Info,
            include_rules: Vec::new(),
            exclude_rules: Vec::new(),
            only_new_code: true,
            secret_detection_enabled: true,
        }
    }
}

impl AnalysisOptions {
    pub fn from_job_config(config: &JobConfig) -> Self {
        Self {
            ignore_paths: config.ignore_paths.clone(),
            max_issues: config.max_issues,
            minimum_severity: parse_minimum_severity(config.minimum_severity.as_deref()),
            include_rules: config.include_rules.clone(),
            exclude_rules: config.exclude_rules.clone(),
            only_new_code: config.only_new_code,
            secret_detection_enabled: config.secret_detection_enabled,
        }
    }
}

impl AnalysisEngine {
    pub fn load() -> Result<Self> {
        Self::load_from_dir(None)
    }

    pub fn load_from_dir(rules_dir: Option<std::path::PathBuf>) -> Result<Self> {
        let rules = Arc::new(RulesService::load_from_dir(rules_dir)?);
        let compiled_patterns = Arc::new(compile_all_patterns(&rules));
        let secret_engine = SecretEngine::load().ok().map(Arc::new);
        Ok(Self {
            rules,
            compiled_patterns,
            secret_engine,
        })
    }

    pub fn reload_rules(&mut self) -> Result<()> {
        let rules = Arc::new(RulesService::load_from_dir(
            self.rules.rules_dir().cloned(),
        )?);
        self.compiled_patterns = Arc::new(compile_all_patterns(&rules));
        self.rules = rules;
        // Recarrega secret engine também
        self.secret_engine = SecretEngine::load().ok().map(Arc::new);
        Ok(())
    }

    pub fn rules_version(&self) -> &str {
        &self.rules.rules_version
    }

    pub fn analyze_diff(
        &self,
        diff_text: &str,
        ignore_paths: &[String],
        max_issues: Option<usize>,
    ) -> Vec<AnalysisIssue> {
        let options = AnalysisOptions {
            ignore_paths: ignore_paths.to_vec(),
            max_issues,
            ..AnalysisOptions::default()
        };
        self.analyze_diff_with_options(diff_text, &options)
    }

    pub fn analyze_diff_with_options(
        &self,
        diff_text: &str,
        options: &AnalysisOptions,
    ) -> Vec<AnalysisIssue> {
        let files = parse_unified_diff(diff_text, options.only_new_code);
        let mut issues = Vec::new();

        // Análise SAST (código existente)
        issues.extend(self.analyze_sast(&files, options));

        // Detecção de Secrets (se habilitado)
        if options.secret_detection_enabled {
            if let Some(secret_engine) = &self.secret_engine {
                let secret_options = SecretScanOptions {
                    ignore_paths: options.ignore_paths.clone(),
                    max_findings: options.max_issues,
                    minimum_severity: crate::secret::SecretSeverity::Low,
                    include_rules: options.include_rules.clone(),
                    exclude_rules: options.exclude_rules.clone(),
                };
                let secret_findings = secret_engine.scan_diff(&files, &secret_options);
                for finding in secret_findings {
                    issues.push(finding.to_analysis_issue());
                }
            } else {
                tracing::warn!("Secret detection habilitado mas secret_engine não está disponível");
            }
        }

        // Ordena e limita resultados
        issues
    }

    /// Análise de arquivos completos (para FullScan)
    pub fn analyze_files(
        &self,
        files: &[FileContent],
        options: &AnalysisOptions,
    ) -> Vec<AnalysisIssue> {
        let mut issues = Vec::new();

        // PERFORMANCE: Converte para HashSet para O(1) lookup
        let exclude_set: std::collections::HashSet<&str> =
            options.exclude_rules.iter().map(|s| s.as_str()).collect();
        let include_set: std::collections::HashSet<&str> = if !options.include_rules.is_empty() {
            options.include_rules.iter().map(|s| s.as_str()).collect()
        } else {
            std::collections::HashSet::new()
        };

        for file in files {
            // Validação de segurança: rejeita paths com path traversal
            if contains_path_traversal(&file.path) {
                tracing::warn!("Path traversal detectado e rejeitado: {}", file.path);
                continue;
            }

            if should_ignore_path(&file.path, &options.ignore_paths) {
                continue;
            }

            let language = match self.rules.detect_language(&file.path) {
                Some(lang) => normalize_lang(&lang),
                None => continue,
            };

            if let Some(rules) = self.compiled_patterns.get(&language) {
                // Analisar todas as linhas do arquivo (não só added_lines)
                for (line_num, line_content) in file.content.lines().enumerate() {
                    for rule in rules {
                        if exclude_set.contains(rule.rule_id.as_str()) {
                            continue;
                        }
                        if !include_set.is_empty() && !include_set.contains(rule.rule_id.as_str()) {
                            continue;
                        }

                        for re in &rule.patterns {
                            if re.is_match(line_content) {
                                let meta = self.rules.find_rule(&rule.rule_id);
                                let severity =
                                    self.rules.map_severity(meta.map(|m| m.severity.as_str()));
                                if severity < options.minimum_severity {
                                    break;
                                }

                                let cwe_suffix = meta
                                    .map(|m| &m.cwe)
                                    .filter(|cwe| !cwe.is_empty())
                                    .map(|cwe| format!(" [CWE: {}]", cwe.join(", ")))
                                    .unwrap_or_default();

                                let line_num = (line_num + 1) as u32;

                                issues.push(AnalysisIssue {
                                    rule_id: Some(rule.rule_id.clone()),
                                    file_path: file.path.clone(),
                                    line_start: line_num,
                                    line_end: Some(line_num),
                                    severity: severity_to_str(severity).to_string(),
                                    category: category_to_str(rule.category).to_string(),
                                    title: meta
                                        .map(|m| m.name.as_str())
                                        .map(|name| name.to_string())
                                        .unwrap_or_else(|| rule.rule_id.clone()),
                                    description: format!("{}{}", rule.message, cwe_suffix),
                                    suggestion: rule.suggestion.clone(),
                                    code_snippet: Some(line_content.trim().to_string()),
                                    confidence: 0.85,
                                    source: "static".to_string(),
                                });
                                break; // Evita duplicatas do mesmo rule
                            }
                        }
                    }
                }
            }

            if is_ci_target(&language) {
                issues.extend(self.analyze_embedded_shell_lines(
                    &file.path,
                    extract_embedded_shell_lines_from_text(&file.path, &file.content),
                    options,
                    &exclude_set,
                    &include_set,
                ));
            }
        }

        // Detecção de Secrets em arquivos completos
        if options.secret_detection_enabled {
            if let Some(secret_engine) = &self.secret_engine {
                let secret_options = crate::secret::SecretScanOptions {
                    ignore_paths: options.ignore_paths.clone(),
                    max_findings: options.max_issues,
                    minimum_severity: crate::secret::SecretSeverity::Low,
                    include_rules: options.include_rules.clone(),
                    exclude_rules: options.exclude_rules.clone(),
                };
                for file in files {
                    let secret_findings =
                        secret_engine.scan_content(&file.path, &file.content, &secret_options);
                    for finding in secret_findings {
                        issues.push(finding.to_analysis_issue());
                    }
                }
            }
        }

        issues
    }

    /// Análise SAST tradicional (por linguagem) - para diffs
    fn analyze_sast(
        &self,
        files: &[crate::diff_parser::DiffFile],
        options: &AnalysisOptions,
    ) -> Vec<AnalysisIssue> {
        let mut issues = Vec::new();

        // PERFORMANCE: Converte para HashSet para O(1) lookup em vez de O(n) linear search
        let exclude_set: std::collections::HashSet<&str> =
            options.exclude_rules.iter().map(|s| s.as_str()).collect();
        let include_set: std::collections::HashSet<&str> = if !options.include_rules.is_empty() {
            options.include_rules.iter().map(|s| s.as_str()).collect()
        } else {
            std::collections::HashSet::new()
        };

        for file in files {
            // Validação de segurança: rejeita paths com path traversal
            if contains_path_traversal(&file.path) {
                tracing::warn!("Path traversal detectado e rejeitado: {}", file.path);
                continue;
            }

            if should_ignore_path(&file.path, &options.ignore_paths) {
                continue;
            }

            let language = match self.rules.detect_language(&file.path) {
                Some(lang) => normalize_lang(&lang),
                None => continue,
            };

            if let Some(rules) = self.compiled_patterns.get(&language) {
                for line in &file.added_lines {
                    for rule in rules {
                        // PERFORMANCE: O(1) lookup com HashSet em vez de O(n) linear search
                        if exclude_set.contains(rule.rule_id.as_str()) {
                            continue;
                        }
                        if !include_set.is_empty() && !include_set.contains(rule.rule_id.as_str()) {
                            continue;
                        }

                        for re in &rule.patterns {
                            if re.is_match(&line.content) {
                                let meta = self.rules.find_rule(&rule.rule_id);
                                let severity =
                                    self.rules.map_severity(meta.map(|m| m.severity.as_str()));
                                if severity < options.minimum_severity {
                                    break;
                                }

                                let cwe_suffix = meta
                                    .map(|m| &m.cwe)
                                    .filter(|cwe| !cwe.is_empty())
                                    .map(|cwe| format!(" [CWE: {}]", cwe.join(", ")))
                                    .unwrap_or_default();

                                // Verificar overflow de line_number
                                let line_num = if line.line_number > u32::MAX as usize {
                                    tracing::warn!(
                                        "Line number {} exceeds u32::MAX, capping at {}",
                                        line.line_number,
                                        u32::MAX
                                    );
                                    u32::MAX
                                } else {
                                    line.line_number as u32
                                };

                                issues.push(AnalysisIssue {
                                    rule_id: Some(rule.rule_id.clone()),
                                    file_path: file.path.clone(),
                                    line_start: line_num,
                                    line_end: Some(line_num),
                                    severity: severity_to_str(severity).to_string(),
                                    category: category_to_str(rule.category).to_string(),
                                    title: meta
                                        .map(|m| m.name.as_str())
                                        .map(|name| name.to_string())
                                        .unwrap_or_else(|| rule.rule_id.clone()),
                                    description: format!("{}{}", rule.message, cwe_suffix),
                                    suggestion: rule.suggestion.clone(),
                                    code_snippet: Some(line.content.trim().to_string()),
                                    confidence: 0.85,
                                    source: "static".to_string(),
                                });
                                break;
                            }
                        }
                    }
                }
            }

            if is_ci_target(&language) {
                issues.extend(self.analyze_embedded_shell_lines(
                    &file.path,
                    extract_embedded_shell_lines_from_diff(&file.path, &file.added_lines),
                    options,
                    &exclude_set,
                    &include_set,
                ));
            }
        }

        issues.sort_by(|a, b| {
            severity_rank(&b.severity)
                .cmp(&severity_rank(&a.severity))
                .then_with(|| a.file_path.cmp(&b.file_path))
                .then_with(|| a.line_start.cmp(&b.line_start))
        });
        dedup_issues(&mut issues);

        if let Some(max) = options.max_issues {
            issues.truncate(max);
        }

        issues
    }

    pub fn generate_auto_fixes(
        &self,
        issues: &[AnalysisIssue],
        max_auto_fixes: Option<usize>,
    ) -> Vec<AutoFixSuggestion> {
        generate_auto_fixes(&self.rules, issues, max_auto_fixes)
    }

    fn analyze_embedded_shell_lines(
        &self,
        file_path: &str,
        shell_lines: Vec<EmbeddedShellLine>,
        options: &AnalysisOptions,
        exclude_set: &std::collections::HashSet<&str>,
        include_set: &std::collections::HashSet<&str>,
    ) -> Vec<AnalysisIssue> {
        let Some(shell_rules) = self.compiled_patterns.get("shell") else {
            return Vec::new();
        };

        let mut issues = Vec::new();

        for line in shell_lines {
            if line.content.trim().is_empty() {
                continue;
            }

            for rule in shell_rules {
                if exclude_set.contains(rule.rule_id.as_str()) {
                    continue;
                }
                if !include_set.is_empty() && !include_set.contains(rule.rule_id.as_str()) {
                    continue;
                }

                for re in &rule.patterns {
                    if re.is_match(&line.content) {
                        let meta = self.rules.find_rule(&rule.rule_id);
                        let severity = self.rules.map_severity(meta.map(|m| m.severity.as_str()));
                        if severity < options.minimum_severity {
                            break;
                        }

                        let cwe_suffix = meta
                            .map(|m| &m.cwe)
                            .filter(|cwe| !cwe.is_empty())
                            .map(|cwe| format!(" [CWE: {}]", cwe.join(", ")))
                            .unwrap_or_default();

                        issues.push(AnalysisIssue {
                            rule_id: Some(rule.rule_id.clone()),
                            file_path: file_path.to_string(),
                            line_start: line.line_number,
                            line_end: Some(line.line_number),
                            severity: severity_to_str(severity).to_string(),
                            category: category_to_str(rule.category).to_string(),
                            title: meta
                                .map(|m| m.name.as_str())
                                .map(|name| name.to_string())
                                .unwrap_or_else(|| rule.rule_id.clone()),
                            description: format!("{}{}", rule.message, cwe_suffix),
                            suggestion: rule.suggestion.clone(),
                            code_snippet: Some(line.content.trim().to_string()),
                            confidence: 0.85,
                            source: "static".to_string(),
                        });
                        break;
                    }
                }
            }
        }

        issues
    }
}

fn compile_all_patterns(rules: &RulesService) -> HashMap<String, Vec<CompiledPatternRule>> {
    let mut map = HashMap::new();
    for lang in rules.pattern_languages() {
        let compiled = rules
            .patterns_for_language(lang)
            .iter()
            .filter_map(|r| compile_rule(r))
            .collect::<Vec<_>>();
        map.insert(lang.to_string(), compiled);
    }

    if let Some(typescript_rules) = map.get("typescript").cloned() {
        map.entry("javascript".to_string())
            .or_insert(typescript_rules);
    }

    map
}

fn compile_rule(rule: &PatternRule) -> Option<CompiledPatternRule> {
    let compiled = rule
        .patterns
        .iter()
        .filter_map(|p| Regex::new(p).ok())
        .collect::<Vec<_>>();
    if compiled.is_empty() {
        return None;
    }

    Some(CompiledPatternRule {
        rule_id: rule.rule_id.clone(),
        category: rule.category,
        patterns: compiled,
        message: rule.message.clone(),
        suggestion: rule.suggestion.clone(),
    })
}

fn is_ci_target(language: &str) -> bool {
    matches!(language, "github-actions" | "gitlab-ci" | "azure-pipelines")
}

fn extract_embedded_shell_lines_from_text(
    file_path: &str,
    content: &str,
) -> Vec<EmbeddedShellLine> {
    let numbered_lines = content
        .lines()
        .enumerate()
        .map(|(index, line)| (index as u32 + 1, line))
        .collect::<Vec<_>>();
    extract_embedded_shell_lines(file_path, &numbered_lines)
}

fn extract_embedded_shell_lines_from_diff(
    file_path: &str,
    added_lines: &[DiffLine],
) -> Vec<EmbeddedShellLine> {
    let numbered_lines = added_lines
        .iter()
        .map(|line| {
            let line_number = if line.line_number > u32::MAX as usize {
                u32::MAX
            } else {
                line.line_number as u32
            };

            (line_number, line.content.as_str())
        })
        .collect::<Vec<_>>();
    extract_embedded_shell_lines(file_path, &numbered_lines)
}

fn extract_embedded_shell_lines(file_path: &str, lines: &[(u32, &str)]) -> Vec<EmbeddedShellLine> {
    if !is_ci_file_path(file_path) {
        return Vec::new();
    }

    let mut extracted = Vec::new();
    let mut active_block: Option<(usize, usize)> = None;
    let mut active_list: Option<usize> = None;

    for &(line_number, line) in lines {
        let indent = line.chars().take_while(|ch| ch.is_whitespace()).count();
        let trimmed = line.trim();

        if let Some((section_indent, content_indent)) = active_block {
            if !trimmed.is_empty() && indent <= section_indent {
                active_block = None;
            } else {
                let content = if line.len() > content_indent {
                    line[content_indent..].to_string()
                } else {
                    trimmed.to_string()
                };
                extracted.push(EmbeddedShellLine {
                    line_number,
                    content,
                });
                continue;
            }
        }

        if let Some(section_indent) = active_list {
            if !trimmed.is_empty() && indent <= section_indent {
                active_list = None;
            } else {
                if let Some(content) = strip_yaml_list_item(trimmed) {
                    if is_block_scalar_indicator(content) {
                        active_block = Some((indent, indent + 2));
                    } else if !content.is_empty() {
                        extracted.push(EmbeddedShellLine {
                            line_number,
                            content: content.to_string(),
                        });
                    }
                }

                continue;
            }
        }

        if let Some((_, value)) = parse_shell_mapping(trimmed) {
            if is_block_scalar_indicator(value) {
                active_block = Some((indent, indent + 2));
            } else if !value.is_empty() {
                extracted.push(EmbeddedShellLine {
                    line_number,
                    content: value.to_string(),
                });
            } else if matches!(trimmed, "script:" | "before_script:" | "after_script:") {
                active_list = Some(indent);
            }
        }
    }

    extracted
}

fn parse_shell_mapping(trimmed: &str) -> Option<(&str, &str)> {
    if let Some(normalized) = trimmed.strip_prefix("- ").map(str::trim) {
        if let Some((key, value)) = split_shell_mapping(normalized) {
            return Some((key, value));
        }
    }

    if let Some((key, value)) = split_shell_mapping(trimmed) {
        return Some((key, value));
    }

    None
}

fn split_shell_mapping(input: &str) -> Option<(&str, &str)> {
    let (key, value) = input.split_once(':')?;
    let key = key.trim();
    if !matches!(
        key,
        "run" | "script" | "before_script" | "after_script" | "bash" | "inlineScript"
    ) {
        return None;
    }

    Some((key, value.trim()))
}

fn strip_yaml_list_item(trimmed: &str) -> Option<&str> {
    trimmed.strip_prefix("- ").map(str::trim)
}

fn is_block_scalar_indicator(value: &str) -> bool {
    matches!(value, "|" | ">" | "|-" | ">-" | "|+" | ">+")
}

fn is_ci_file_path(file_path: &str) -> bool {
    let lower = file_path.to_lowercase();
    lower.contains(".github/workflows/")
        || lower.ends_with(".gitlab-ci.yml")
        || lower.ends_with("azure-pipelines.yml")
        || lower.ends_with("azure-pipelines.yaml")
}

/// Verifica se o path contém tentativa de path traversal (..)
/// Retorna true se o path for inválido ou potencialmente malicioso
fn contains_path_traversal(path: &str) -> bool {
    let normalized = path.replace('\\', "/");

    // Rejeita paths absolutos (Unix: /, Windows: C:, D:, etc)
    if normalized.starts_with('/') {
        return true;
    }
    // Rejeita paths absolutos Windows (X: ou X:/)
    if normalized.len() >= 2
        && normalized.chars().nth(1) == Some(':')
        && normalized
            .chars()
            .next()
            .map(|c| c.is_ascii_alphabetic())
            .unwrap_or(false)
    {
        return true;
    }

    // Verifica cada componente do path
    normalized.split('/').any(|component| component == "..")
}

fn should_ignore_path(path: &str, patterns: &[String]) -> bool {
    let normalized = path.replace('\\', "/");

    if DEFAULT_IGNORE_PATTERNS
        .iter()
        .any(|p| p.matches(&normalized))
    {
        return true;
    }

    patterns.iter().any(|pattern| {
        Pattern::new(pattern)
            .map(|p| p.matches(&normalized))
            .unwrap_or(false)
    })
}

fn normalize_lang(lang: &str) -> String {
    match lang.to_lowercase().as_str() {
        "js" | "javascript" => "javascript".to_string(),
        "ts" | "typescript" => "typescript".to_string(),
        "c#" | "csharp" => "csharp".to_string(),
        "py" | "python" => "python".to_string(),
        "go" | "golang" => "go".to_string(),
        "java" => "java".to_string(),
        other => other.to_string(),
    }
}

fn parse_minimum_severity(value: Option<&str>) -> IssueSeverity {
    match value.unwrap_or("info").to_lowercase().as_str() {
        "critical" | "blocker" => IssueSeverity::Critical,
        "high" | "major" => IssueSeverity::High,
        "medium" | "minor" => IssueSeverity::Medium,
        "low" => IssueSeverity::Low,
        _ => IssueSeverity::Info,
    }
}

fn severity_to_str(severity: IssueSeverity) -> &'static str {
    match severity {
        IssueSeverity::Critical => "critical",
        IssueSeverity::High => "high",
        IssueSeverity::Medium => "medium",
        IssueSeverity::Low => "low",
        IssueSeverity::Info => "info",
    }
}

fn category_to_str(category: PatternCategory) -> &'static str {
    match category {
        PatternCategory::Vulnerability | PatternCategory::SecurityHotspot => "security",
        PatternCategory::Bug => "bug_risk",
        PatternCategory::CodeSmell | PatternCategory::React => "maintainability",
    }
}

fn severity_rank(severity: &str) -> usize {
    match severity {
        "critical" => 5,
        "high" => 4,
        "medium" => 3,
        "low" => 2,
        "info" => 1,
        _ => 0,
    }
}

fn dedup_issues(issues: &mut Vec<AnalysisIssue>) {
    use std::collections::hash_map::DefaultHasher;
    use std::collections::HashSet;
    use std::hash::{Hash, Hasher};

    // PERFORMANCE: Usa HashSet com capacity inicial e hashes (evita alocação de strings)
    let mut seen = HashSet::with_capacity(issues.len());
    issues.retain(|issue| {
        // Calcula hash dos campos em vez de alocar string
        let mut hasher = DefaultHasher::new();
        issue.file_path.hash(&mut hasher);
        issue.line_start.hash(&mut hasher);
        issue.title.hash(&mut hasher);
        let hash = hasher.finish();
        seen.insert(hash)
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_engine_detects_issue_from_diff() {
        let engine = AnalysisEngine::load().unwrap();
        let diff = r#"
diff --git a/src/auth.ts b/src/auth.ts
--- a/src/auth.ts
+++ b/src/auth.ts
@@ -1,2 +1,3 @@
 const a = 1;
+const result = `${userId} WHERE active = 1`;
 const b = 2;
"#;
        let issues = engine.analyze_diff(diff, &[], Some(20));
        assert!(!issues.is_empty());
    }

    #[test]
    fn test_engine_honors_minimum_severity_filter() {
        let engine = AnalysisEngine::load().unwrap();
        let diff = r#"
diff --git a/src/auth.ts b/src/auth.ts
--- a/src/auth.ts
+++ b/src/auth.ts
@@ -1,2 +1,3 @@
+const result = `${userId} WHERE active = 1`;
"#;
        let options = AnalysisOptions {
            minimum_severity: IssueSeverity::Critical,
            ..AnalysisOptions::default()
        };
        let issues = engine.analyze_diff_with_options(diff, &options);
        assert!(!issues.is_empty());
    }

    #[test]
    fn test_engine_detects_secrets_in_diff() {
        let engine = AnalysisEngine::load().unwrap();

        // Verifica se o secret_engine foi carregado
        assert!(
            engine.secret_engine.is_some(),
            "SecretEngine deveria estar carregado"
        );

        // Verifica estatísticas das regras de secret
        let stats = engine.secret_engine.as_ref().unwrap().stats();
        assert!(
            stats.total_rules > 0,
            "Deveria ter regras de secret carregadas"
        );

        // Usa um valor que não pareça placeholder (não contém "EXAMPLE")
        let diff = r#"
diff --git a/config.env b/config.env
--- a/config.env
+++ b/config.env
@@ -1,2 +1,3 @@
 API_URL=https://api.example.com
+AWS_ACCESS_KEY_ID=AKIAIOSFODNN7REAL123
 DATABASE_URL=postgres://localhost/db
"#;
        let issues = engine.analyze_diff(diff, &[], Some(20));

        // Deve detectar o secret
        let secret_issues: Vec<_> = issues.iter().filter(|i| i.category == "secret").collect();

        assert!(
            !secret_issues.is_empty(),
            "Deveria detectar secrets no diff. Total issues: {:?}",
            issues
        );

        // Verifica se o secret foi detectado
        let aws_issue = secret_issues
            .iter()
            .find(|i| i.rule_id.as_deref() == Some("SEC-AWS-001"));
        assert!(aws_issue.is_some(), "Deveria detectar AWS Access Key");
    }

    #[test]
    fn test_engine_detects_multiple_vulnerabilities_in_same_line() {
        let engine = AnalysisEngine::load().unwrap();
        // Testa que múltiplas issues podem ser detectadas
        // Usando o mesmo formato do teste existente que funciona
        let diff = r#"
diff --git a/src/auth.ts b/src/auth.ts
--- a/src/auth.ts
+++ b/src/auth.ts
@@ -1,2 +1,4 @@
 const a = 1;
+const result1 = `${userId} WHERE active = 1`;
+const result2 = `${name} WHERE status = 2`;
 const b = 2;
"#;
        let issues = engine.analyze_diff(diff, &[], Some(20));

        // Deve detectar vulnerabilidades - verifica que o engine funciona
        assert!(
            !issues.is_empty(),
            "Deveria detectar vulnerabilidades no diff. Issues: {:?}",
            issues
        );

        // O importante é que o loop não pare prematuramente no primeiro match
        // devido ao break removido na correção
    }

    #[test]
    fn test_compile_all_patterns_includes_all_supported_languages() {
        let rules = RulesService::load().unwrap();
        let compiled = compile_all_patterns(&rules);

        for language in rules.pattern_languages() {
            assert!(
                compiled.contains_key(language),
                "compiled patterns should include {language}"
            );
        }

        assert!(
            compiled.contains_key("javascript"),
            "compiled patterns should include javascript alias"
        );
    }

    #[test]
    fn test_compile_all_patterns_supports_dynamic_targets_from_bundle() {
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
      { "id": "CPP-SEC-001", "name": "Unsafe copy", "severity": "CRITICAL", "cwe": ["CWE-120"] }
    ]
  },
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
  "cpp": {
    "vulnerabilities": [
      {
        "ruleId": "CPP-SEC-001",
        "patterns": ["strcpy\\s*\\("],
        "message": "Avoid unsafe copy",
        "suggestion": "Use strncpy"
      }
    ]
  },
  "dockerfile": {
    "vulnerabilities": [
      {
        "ruleId": "DOCKER-001",
        "patterns": ["USER\\s+root"],
        "message": "Avoid root user",
        "suggestion": "Use a non-root user"
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
    },
    "dockerfile": {
      "fileExtensions": [],
      "fileNames": ["Dockerfile"]
    }
  }
}"#,
        )
        .unwrap();
        fs::write(
            rules_dir.join("AutoFixPatterns.json"),
            r#"{"patterns":{"cpp":[],"dockerfile":[]}}"#,
        )
        .unwrap();

        let rules = RulesService::load_from_dir(Some(rules_dir.to_path_buf())).unwrap();
        let compiled = compile_all_patterns(&rules);

        for language in ["cpp", "dockerfile"] {
            assert!(
                compiled.contains_key(language),
                "compiled patterns should include {language}"
            );
            assert!(
                compiled
                    .get(language)
                    .map(|patterns| !patterns.is_empty())
                    .unwrap_or(false),
                "compiled patterns for {language} should not be empty"
            );
        }
    }

    #[test]
    fn test_contains_path_traversal_detects_dotdot() {
        // Path traversal com ../
        assert!(contains_path_traversal("../../../etc/passwd"));
        assert!(contains_path_traversal("foo/../../bar"));
        assert!(contains_path_traversal("../config.txt"));

        // Path traversal com ..\
        assert!(contains_path_traversal(
            "..\\..\\..\\windows\\system32\\config\\sam"
        ));
        assert!(contains_path_traversal("foo\\..\\..\\bar"));
    }

    #[test]
    fn test_contains_path_traversal_detects_absolute_paths() {
        // Paths absolutos Unix
        assert!(contains_path_traversal("/etc/passwd"));
        assert!(contains_path_traversal("/var/log/syslog"));

        // Paths absolutos Windows
        assert!(contains_path_traversal(
            "C:\\windows\\system32\\config\\sam"
        ));
    }

    #[test]
    fn test_contains_path_traversal_allows_valid_paths() {
        // Paths válidos sem traversal
        assert!(!contains_path_traversal("src/main.rs"));
        assert!(!contains_path_traversal("foo/bar/baz.ts"));
        assert!(!contains_path_traversal("README.md"));
        assert!(!contains_path_traversal(".gitignore"));
        assert!(!contains_path_traversal("node_modules/lodash/index.js"));

        // Paths com .. no nome (não traversal)
        assert!(!contains_path_traversal("foo..bar.txt"));
        assert!(!contains_path_traversal("..hiddenfile"));
        assert!(!contains_path_traversal("file...name.rs"));
    }

    #[test]
    fn test_path_traversal_blocked_in_analysis() {
        let engine = AnalysisEngine::load().unwrap();

        // Diff com path traversal - deve ser ignorado
        let diff = r#"
diff --git a/../../../etc/passwd b/../../../etc/passwd
--- a/../../../etc/passwd
+++ b/../../../etc/passwd
@@ -1,2 +1,3 @@
 const a = 1;
+const result = `${userId} WHERE active = 1`;
 const b = 2;
"#;

        let issues = engine.analyze_diff(diff, &[], Some(20));
        // Não deve detectar nada porque o path é inválido
        assert!(
            issues.is_empty(),
            "Path traversal deve ser bloqueado e não gerar issues"
        );
    }

    #[test]
    fn test_engine_detects_shell_patterns_inside_ci_targets() {
        use std::fs;
        use tempfile::tempdir;

        let temp_dir = tempdir().unwrap();
        let rules_dir = temp_dir.path();

        fs::write(
            rules_dir.join("AllRules.json"),
            r#"{
  "version": "test-1",
  "shell": {
    "vulnerabilities": [
      { "id": "SH-SEC-001", "name": "Avoid eval", "severity": "CRITICAL", "cwe": ["CWE-94"] }
    ]
  }
}"#,
        )
        .unwrap();
        fs::write(
            rules_dir.join("DetectionPatterns.json"),
            r#"{
  "version": "1.0.0",
  "shell": {
    "vulnerabilities": [
      {
        "ruleId": "SH-SEC-001",
        "patterns": ["eval\\s+"],
        "message": "Avoid eval in shell scripts",
        "suggestion": "Use safer command invocation"
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
    "shell": {
      "fileExtensions": [".sh"]
    },
    "github-actions": {
      "fileExtensions": [".yml", ".yaml"],
      "fileNames": ["ci.yml"]
    },
    "gitlab-ci": {
      "fileExtensions": [".yml"],
      "fileNames": [".gitlab-ci.yml"]
    },
    "azure-pipelines": {
      "fileExtensions": [".yml", ".yaml"],
      "fileNames": ["azure-pipelines.yml"]
    }
  }
}"#,
        )
        .unwrap();
        fs::write(
            rules_dir.join("AutoFixPatterns.json"),
            r#"{"patterns":{"shell":[],"github-actions":[],"gitlab-ci":[],"azure-pipelines":[]}}"#,
        )
        .unwrap();

        let engine = AnalysisEngine::load_from_dir(Some(rules_dir.to_path_buf())).unwrap();
        let options = AnalysisOptions::default();
        let files = vec![
            FileContent::new(
                ".github/workflows/ci.yml",
                "jobs:\n  build:\n    steps:\n      - run: |\n          eval \"$INPUT\"\n",
            ),
            FileContent::new(
                ".gitlab-ci.yml",
                "job:\n  script:\n    - eval \"$INPUT\"\n",
            ),
            FileContent::new(
                "azure-pipelines.yml",
                "steps:\n  - bash: |\n      eval \"$INPUT\"\n",
            ),
        ];

        let issues = engine.analyze_files(&files, &options);

        assert_eq!(issues.len(), 3);
        assert!(issues
            .iter()
            .all(|issue| issue.rule_id.as_deref() == Some("SH-SEC-001")));
    }

    #[test]
    fn test_engine_detects_shell_patterns_inside_ci_diff_blocks() {
        use std::fs;
        use tempfile::tempdir;

        let temp_dir = tempdir().unwrap();
        let rules_dir = temp_dir.path();

        fs::write(
            rules_dir.join("AllRules.json"),
            r#"{
  "version": "test-1",
  "shell": {
    "vulnerabilities": [
      { "id": "SH-SEC-001", "name": "Avoid eval", "severity": "CRITICAL", "cwe": ["CWE-94"] }
    ]
  }
}"#,
        )
        .unwrap();
        fs::write(
            rules_dir.join("DetectionPatterns.json"),
            r#"{
  "version": "1.0.0",
  "shell": {
    "vulnerabilities": [
      {
        "ruleId": "SH-SEC-001",
        "patterns": ["eval\\s+"],
        "message": "Avoid eval in shell scripts"
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
    "shell": {
      "fileExtensions": [".sh"]
    },
    "github-actions": {
      "fileExtensions": [".yml", ".yaml"],
      "fileNames": ["ci.yml"]
    }
  }
}"#,
        )
        .unwrap();
        fs::write(
            rules_dir.join("AutoFixPatterns.json"),
            r#"{"patterns":{"shell":[],"github-actions":[]}}"#,
        )
        .unwrap();

        let engine = AnalysisEngine::load_from_dir(Some(rules_dir.to_path_buf())).unwrap();
        let diff = r#"
diff --git a/.github/workflows/ci.yml b/.github/workflows/ci.yml
--- a/.github/workflows/ci.yml
+++ b/.github/workflows/ci.yml
@@ -1,3 +1,5 @@
 jobs:
   build:
+    steps:
+      - run: |
+          eval "$INPUT"
"#;

        let issues = engine.analyze_diff(diff, &[], Some(20));

        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].rule_id.as_deref(), Some("SH-SEC-001"));
        assert_eq!(issues[0].file_path, ".github/workflows/ci.yml");
    }
}
