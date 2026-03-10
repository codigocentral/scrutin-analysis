//! IaC Security Engine
//!
//! Detecao de problemas de seguranca em arquivos de infraestrutura como codigo.
//! Reutiliza a infraestrutura do Rules Engine com category='iac'.
//!
//! Features:
//! - ~58 padroes regex (Dockerfile, K8s, Terraform, CI/CD)
//! - Deteccao automatica de tipos de arquivo IaC
//! - Integracao com diff de PRs

use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::diff_parser::{DiffFile, DiffLine};
use crate::error::Result;
use crate::models::AnalysisIssue;

/// Tipo de arquivo IaC detectado
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IacType {
    Dockerfile,
    DockerCompose,
    Kubernetes,
    Terraform,
    GitHubActions,
    GitLabCi,
    AzurePipelines,
    Unknown,
}

impl IacType {
    /// Retorna o nome em string
    pub fn as_str(&self) -> &'static str {
        match self {
            IacType::Dockerfile => "dockerfile",
            IacType::DockerCompose => "docker-compose",
            IacType::Kubernetes => "kubernetes",
            IacType::Terraform => "terraform",
            IacType::GitHubActions => "github-actions",
            IacType::GitLabCi => "gitlab-ci",
            IacType::AzurePipelines => "azure-pipelines",
            IacType::Unknown => "unknown",
        }
    }

    /// Detecta o tipo de IaC baseado no caminho do arquivo
    pub fn detect_from_path(file_path: &str) -> Self {
        let lower_path = file_path.to_lowercase();
        let file_name = std::path::Path::new(file_path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");

        // Dockerfile
        if file_name.to_lowercase().starts_with("dockerfile") || file_name.ends_with(".dockerfile")
        {
            return IacType::Dockerfile;
        }

        // Docker Compose
        if file_name.contains("docker-compose")
            || file_name == "compose.yml"
            || file_name == "compose.yaml"
        {
            return IacType::DockerCompose;
        }

        // Kubernetes
        if lower_path.contains("/k8s/")
            || lower_path.contains("/kubernetes/")
            || lower_path.contains("/manifests/")
            || lower_path.contains("/helm/")
            || ((file_name.ends_with(".yaml") || file_name.ends_with(".yml"))
                && (lower_path.contains("deployment")
                    || lower_path.contains("service")
                    || lower_path.contains("configmap")))
        {
            return IacType::Kubernetes;
        }

        // Terraform
        if file_name.ends_with(".tf") || file_name.ends_with(".tfvars") {
            return IacType::Terraform;
        }

        // GitHub Actions
        if lower_path.contains(".github/workflows/") {
            return IacType::GitHubActions;
        }

        // GitLab CI
        if file_name == ".gitlab-ci.yml" {
            return IacType::GitLabCi;
        }

        // Azure Pipelines
        if file_name.contains("azure-pipelines") {
            return IacType::AzurePipelines;
        }

        IacType::Unknown
    }
}

impl std::fmt::Display for IacType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Severidade de findings IaC
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum IacSeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for IacSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IacSeverity::Low => write!(f, "low"),
            IacSeverity::Medium => write!(f, "medium"),
            IacSeverity::High => write!(f, "high"),
            IacSeverity::Critical => write!(f, "critical"),
        }
    }
}

impl From<&str> for IacSeverity {
    fn from(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "critical" => IacSeverity::Critical,
            "high" => IacSeverity::High,
            "medium" => IacSeverity::Medium,
            "low" => IacSeverity::Low,
            _ => IacSeverity::Medium,
        }
    }
}

/// Representa um finding de seguranca IaC
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IacFinding {
    pub rule_id: String,
    pub file_path: String,
    pub line_number: u32,
    pub severity: IacSeverity,
    pub title: String,
    pub message: String,
    pub suggestion: String,
    pub iac_type: IacType,
    pub matched_pattern: String,
    pub source: String,
    pub confidence: f64,
}

impl IacFinding {
    /// Converte para AnalysisIssue (formato compativel com o sistema)
    pub fn to_analysis_issue(&self) -> AnalysisIssue {
        AnalysisIssue {
            rule_id: Some(self.rule_id.clone()),
            file_path: self.file_path.clone(),
            line_start: self.line_number,
            line_end: Some(self.line_number),
            severity: self.severity.to_string(),
            category: "iac".to_string(),
            title: self.title.clone(),
            description: self.message.clone(),
            suggestion: Some(self.suggestion.clone()),
            code_snippet: Some(self.matched_pattern.clone()),
            confidence: self.confidence,
            source: self.source.clone(),
        }
    }
}

/// Regra de deteccao IaC
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IacRule {
    pub rule_id: String,
    pub external_id: String,
    pub title: String,
    pub message: String,
    pub severity: String,
    pub patterns: Vec<String>,
    pub iac_type: String,
    pub suggestion: Option<String>,
    pub source: String,
    #[serde(default)]
    pub cwe_id: Option<String>,
}

/// Regra compilada (regex prontos)
#[derive(Clone)]
struct CompiledIacRule {
    rule: IacRule,
    patterns: Vec<Regex>,
}

/// Engine de analise IaC
pub struct IacEngine {
    rules: Vec<CompiledIacRule>,
    ignore_paths: Vec<Regex>,
}

/// Opcoes de scan
#[derive(Debug, Clone)]
pub struct IacScanOptions {
    pub ignore_paths: Vec<String>,
    pub max_findings: Option<usize>,
    pub minimum_severity: IacSeverity,
    pub include_rules: Vec<String>,
    pub exclude_rules: Vec<String>,
    pub iac_types: Vec<IacType>,
}

impl Default for IacScanOptions {
    fn default() -> Self {
        Self {
            ignore_paths: Vec::new(),
            max_findings: None,
            minimum_severity: IacSeverity::Low,
            include_rules: Vec::new(),
            exclude_rules: Vec::new(),
            iac_types: Vec::new(),
        }
    }
}

/// Configuracao para carregamento de regras
#[derive(Debug, Clone)]
pub struct IacEngineConfig {
    pub api_endpoint: Option<String>,
    pub api_token: Option<String>,
    pub cache_file: Option<std::path::PathBuf>,
    pub use_embedded_fallback: bool,
}

impl Default for IacEngineConfig {
    fn default() -> Self {
        Self {
            api_endpoint: std::env::var("SCRUTIN_API_URL").ok(),
            api_token: std::env::var("SCRUTIN_API_TOKEN").ok(),
            cache_file: dirs::home_dir().map(|d| d.join(".scrutin").join("iac_rules_cache.json")),
            use_embedded_fallback: true,
        }
    }
}

impl IacEngine {
    /// Carrega engine com regras embedded
    pub fn load() -> Result<Self> {
        let rules = load_embedded_rules();
        Self::from_rules(&rules)
    }

    /// Carrega engine com configuracao
    pub fn load_with_config(config: &IacEngineConfig) -> Result<Self> {
        if let Some(cache) = &config.cache_file {
            if cache.exists() {
                match Self::load_from_file(cache) {
                    Ok(engine) => {
                        tracing::info!("Loaded IaC rules from cache: {:?}", cache);
                        return Ok(engine);
                    }
                    Err(e) => {
                        tracing::warn!("Failed to load from cache: {}", e);
                    }
                }
            }
        }

        if config.use_embedded_fallback {
            tracing::info!("Using embedded IaC rules");
            Self::load()
        } else {
            Err(crate::error::AnalysisError::message(
                "No IaC rules available and fallback disabled",
            ))
        }
    }

    /// Carrega regras de um arquivo JSON
    pub fn load_from_file(path: &std::path::Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let rules: Vec<IacRule> = serde_json::from_str(&content)?;
        Self::from_rules(&rules)
    }

    /// Salva regras atuais para um arquivo JSON
    pub fn save_to_file(&self, path: &std::path::Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let rules: Vec<&IacRule> = self.rules.iter().map(|c| &c.rule).collect();

        let json = serde_json::to_string_pretty(&rules)?;
        std::fs::write(path, json)?;

        Ok(())
    }


    /// Carrega engine a partir de regras
    pub fn from_rules(rules: &[IacRule]) -> Result<Self> {
        let mut compiled = Vec::new();

        for rule in rules {
            let compiled_patterns = compile_patterns(&rule.patterns)?;

            compiled.push(CompiledIacRule {
                rule: rule.clone(),
                patterns: compiled_patterns,
            });
        }

        Ok(Self {
            rules: compiled,
            ignore_paths: build_ignore_path_patterns(),
        })
    }

    /// Scan de diff (arquivos modificados no PR)
    pub fn scan_diff(&self, files: &[DiffFile], options: &IacScanOptions) -> Vec<IacFinding> {
        let mut findings = Vec::new();

        for file in files {
            // Validação de segurança: rejeita paths com path traversal
            if contains_path_traversal(&file.path) {
                tracing::warn!("Path traversal detectado e rejeitado: {}", file.path);
                continue;
            }

            let iac_type = IacType::detect_from_path(&file.path);
            if iac_type == IacType::Unknown {
                continue;
            }

            if !options.iac_types.is_empty() && !options.iac_types.contains(&iac_type) {
                continue;
            }

            if should_ignore_path(&file.path, &options.ignore_paths) {
                continue;
            }

            if self.is_global_ignored_path(&file.path) {
                continue;
            }

            for line in &file.added_lines {
                if let Some(finding) = self.scan_line(&file.path, line, iac_type) {
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

    /// Scan de uma unica linha
    fn scan_line(&self, file_path: &str, line: &DiffLine, iac_type: IacType) -> Option<IacFinding> {
        let content = &line.content;

        for compiled in &self.rules {
            let rule_iac_type = IacType::from(compiled.rule.iac_type.as_str());
            if rule_iac_type != iac_type && rule_iac_type != IacType::Unknown {
                continue;
            }

            for pattern in &compiled.patterns {
                if let Some(mat) = pattern.find(content) {
                    let matched_text = mat.as_str().to_string();

                    if looks_like_placeholder(&matched_text) {
                        continue;
                    }

                    let severity = IacSeverity::from(compiled.rule.severity.as_str());

                    return Some(IacFinding {
                        rule_id: compiled.rule.rule_id.clone(),
                        file_path: file_path.to_string(),
                        line_number: line.line_number as u32,
                        severity,
                        title: compiled.rule.title.clone(),
                        message: compiled.rule.message.clone(),
                        suggestion: compiled
                            .rule
                            .suggestion
                            .clone()
                            .unwrap_or_else(|| "Review and fix this security issue.".to_string()),
                        iac_type,
                        matched_pattern: matched_text,
                        source: compiled.rule.source.clone(),
                        confidence: 0.90,
                    });
                }
            }
        }

        None
    }

    fn is_global_ignored_path(&self, path: &str) -> bool {
        self.ignore_paths.iter().any(|re| re.is_match(path))
    }

    /// Retorna estatisticas das regras carregadas
    pub fn stats(&self) -> IacEngineStats {
        let mut by_type: HashMap<String, usize> = HashMap::new();
        let mut by_severity: HashMap<String, usize> = HashMap::new();
        let mut by_source: HashMap<String, usize> = HashMap::new();

        for compiled in &self.rules {
            *by_type.entry(compiled.rule.iac_type.clone()).or_insert(0) += 1;
            *by_severity
                .entry(compiled.rule.severity.clone())
                .or_insert(0) += 1;
            *by_source.entry(compiled.rule.source.clone()).or_insert(0) += 1;
        }

        IacEngineStats {
            total_rules: self.rules.len(),
            by_type,
            by_severity,
            by_source,
        }
    }

    /// Scan de arquivo unico
    pub fn scan_file(
        &self,
        file_path: &std::path::Path,
        options: &IacScanOptions,
    ) -> Vec<IacFinding> {
        let path_str = file_path.to_string_lossy();

        let iac_type = IacType::detect_from_path(&path_str);
        if iac_type == IacType::Unknown {
            return Vec::new();
        }

        if should_ignore_path(&path_str, &options.ignore_paths)
            || self.is_global_ignored_path(&path_str)
        {
            return Vec::new();
        }

        let content = match std::fs::read_to_string(file_path) {
            Ok(c) => c,
            Err(_) => return Vec::new(),
        };

        self.scan_content(&path_str, &content, options)
    }

    /// Scan de conteudo em string
    pub fn scan_content(
        &self,
        file_path: &str,
        content: &str,
        options: &IacScanOptions,
    ) -> Vec<IacFinding> {
        let mut findings = Vec::new();

        let iac_type = IacType::detect_from_path(file_path);
        if iac_type == IacType::Unknown {
            return Vec::new();
        }

        if !options.iac_types.is_empty() && !options.iac_types.contains(&iac_type) {
            return Vec::new();
        }

        let lines: Vec<&str> = content.lines().collect();

        for (line_num, line_content) in lines.iter().enumerate() {
            let line = DiffLine {
                line_number: line_num + 1,
                content: line_content.to_string(),
            };

            if let Some(finding) = self.scan_line(file_path, &line, iac_type) {
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

    /// Scan recursivo de diretorio
    pub fn scan_directory(
        &self,
        dir_path: &std::path::Path,
        options: &IacScanOptions,
        max_files: Option<usize>,
    ) -> Vec<IacFinding> {
        let mut findings = Vec::new();
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
}

/// Estatisticas do engine
#[derive(Debug, Clone)]
pub struct IacEngineStats {
    pub total_rules: usize,
    pub by_type: HashMap<String, usize>,
    pub by_severity: HashMap<String, usize>,
    pub by_source: HashMap<String, usize>,
}

impl From<&str> for IacType {
    fn from(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "dockerfile" => IacType::Dockerfile,
            "docker-compose" | "docker_compose" | "compose" => IacType::DockerCompose,
            "kubernetes" | "k8s" => IacType::Kubernetes,
            "terraform" | "tf" => IacType::Terraform,
            "github-actions" | "github_actions" | "github" => IacType::GitHubActions,
            "gitlab-ci" | "gitlab_ci" | "gitlab" => IacType::GitLabCi,
            "azure-pipelines" | "azure_pipelines" | "azure" => IacType::AzurePipelines,
            _ => IacType::Unknown,
        }
    }
}

/// Compila lista de patterns regex
fn compile_patterns(patterns: &[String]) -> Result<Vec<Regex>> {
    patterns
        .iter()
        .map(|p| Regex::new(p).map_err(crate::error::AnalysisError::Regex))
        .collect()
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

/// Verifica se o path deve ser ignorado
fn should_ignore_path(path: &str, ignore_patterns: &[String]) -> bool {
    ignore_patterns.iter().any(|pattern| {
        if let Ok(re) = Regex::new(pattern) {
            re.is_match(path)
        } else {
            path.contains(pattern)
        }
    })
}

/// Build patterns de paths para ignorar
fn build_ignore_path_patterns() -> Vec<Regex> {
    let patterns = [
        r"vendor/",
        r"node_modules/",
        r"\.git/",
        r"__pycache__/",
        r"\.pytest_cache/",
        r"\.terraform/",
        r"\.terragrunt-cache/",
        r"target/",
        r"dist/",
        r"build/",
        r"\.idea/",
        r"\.vscode/",
    ];

    patterns.iter().filter_map(|p| Regex::new(p).ok()).collect()
}

/// Verifica se o texto parece um placeholder
fn looks_like_placeholder(text: &str) -> bool {
    let placeholder_patterns = [
        "EXAMPLE",
        "example",
        "TEST",
        "test",
        "DUMMY",
        "dummy",
        "FAKE",
        "fake",
        "PLACEHOLDER",
        "placeholder",
        "SAMPLE",
        "sample",
        "XXXXXX",
        "xxxxxx",
        "000000",
        "111111",
        "YOUR_VALUE_HERE",
        "REPLACE_ME",
        "replace_me",
        "INSERT_VALUE",
    ];

    let upper = text.to_uppercase();
    placeholder_patterns.iter().any(|p| upper.contains(p))
}

/// Carrega regras embedded
fn load_embedded_rules() -> Vec<IacRule> {
    let mut rules = Vec::new();

    // Dockerfile Rules
    rules.extend(vec![
        IacRule {
            rule_id: "DOCK-IAC-001".to_string(),
            external_id: "dockerfile.secrets-in-env".to_string(),
            title: "Secrets in ENV directive".to_string(),
            message: "Hardcoded secrets detected in ENV directive. Never store credentials in Docker images.".to_string(),
            severity: "critical".to_string(),
            patterns: vec!["ENV\\s+.*(?:PASSWORD|SECRET|TOKEN|KEY|API_KEY|PRIVATE_KEY)".to_string()],
            iac_type: "dockerfile".to_string(),
            suggestion: Some("Use Docker secrets, environment variables at runtime, or a secret management solution.".to_string()),
            source: "scrutin-iac".to_string(),
            cwe_id: Some("CWE-798".to_string()),
        },
        IacRule {
            rule_id: "DOCK-IAC-003".to_string(),
            external_id: "dockerfile.run-as-root".to_string(),
            title: "Running as root user".to_string(),
            message: "Container runs as root user. This is a security risk if the container is compromised.".to_string(),
            severity: "high".to_string(),
            patterns: vec!["USER\\s+root".to_string()],
            iac_type: "dockerfile".to_string(),
            suggestion: Some("Add 'USER nonroot' or 'USER 1000' directive before CMD/ENTRYPOINT.".to_string()),
            source: "hadolint".to_string(),
            cwe_id: Some("CWE-250".to_string()),
        },
        IacRule {
            rule_id: "DOCK-IAC-004".to_string(),
            external_id: "dockerfile.curl-pipe-shell".to_string(),
            title: "curl piped to shell".to_string(),
            message: "Downloading and executing scripts via curl/wget piped to shell is dangerous.".to_string(),
            severity: "high".to_string(),
            patterns: vec![
                "curl.*\\|\\s*(?:bash|sh)".to_string(),
                "wget.*\\|\\s*(?:bash|sh)".to_string(),
            ],
            iac_type: "dockerfile".to_string(),
            suggestion: Some("Download the script first, verify checksums, then execute.".to_string()),
            source: "scrutin-iac".to_string(),
            cwe_id: Some("CWE-829".to_string()),
        },
        IacRule {
            rule_id: "DOCK-IAC-006".to_string(),
            external_id: "dockerfile.latest-tag".to_string(),
            title: "Using latest tag".to_string(),
            message: "Base image uses 'latest' tag which may introduce breaking changes unpredictably.".to_string(),
            severity: "medium".to_string(),
            patterns: vec!["FROM\\s+\\w+:latest".to_string()],
            iac_type: "dockerfile".to_string(),
            suggestion: Some("Use a specific version tag like 'node:18.19-alpine3.19' for reproducible builds.".to_string()),
            source: "hadolint".to_string(),
            cwe_id: None,
        },
        IacRule {
            rule_id: "DOCK-IAC-008".to_string(),
            external_id: "dockerfile.exposed-sensitive-ports".to_string(),
            title: "Sensitive ports exposed".to_string(),
            message: "Exposing internal service ports like database or SSH ports may be unnecessary.".to_string(),
            severity: "medium".to_string(),
            patterns: vec!["EXPOSE\\s+(?:22|3306|5432|6379|27017|1433|1521)".to_string()],
            iac_type: "dockerfile".to_string(),
            suggestion: Some("Only expose ports that are needed by the application. Use internal networking for databases.".to_string()),
            source: "scrutin-iac".to_string(),
            cwe_id: Some("CWE-200".to_string()),
        },
        IacRule {
            rule_id: "DOCK-IAC-009".to_string(),
            external_id: "dockerfile.copy-all-files".to_string(),
            title: "COPY with all files".to_string(),
            message: "COPY . . copies all files including potentially sensitive ones without .dockerignore.".to_string(),
            severity: "medium".to_string(),
            patterns: vec!["COPY\\s+\\.\\s+".to_string()],
            iac_type: "dockerfile".to_string(),
            suggestion: Some("Use specific COPY commands or ensure .dockerignore excludes sensitive files.".to_string()),
            source: "scrutin-iac".to_string(),
            cwe_id: Some("CWE-200".to_string()),
        },
        IacRule {
            rule_id: "DOCK-IAC-010".to_string(),
            external_id: "dockerfile.sudo-usage".to_string(),
            title: "sudo usage detected".to_string(),
            message: "Using sudo in Dockerfile indicates the container is running as root.".to_string(),
            severity: "high".to_string(),
            patterns: vec!["sudo".to_string()],
            iac_type: "dockerfile".to_string(),
            suggestion: Some("Remove sudo and use USER directive to switch users properly.".to_string()),
            source: "scrutin-iac".to_string(),
            cwe_id: Some("CWE-250".to_string()),
        },
        IacRule {
            rule_id: "DOCK-IAC-011".to_string(),
            external_id: "dockerfile.add-instead-copy".to_string(),
            title: "ADD instead of COPY".to_string(),
            message: "ADD has more complex behavior than COPY and should be avoided for simple file copying.".to_string(),
            severity: "low".to_string(),
            patterns: vec!["^ADD\\s+[^h]".to_string()],
            iac_type: "dockerfile".to_string(),
            suggestion: Some("Use COPY for local files. Use ADD only for extracting tar files or remote URLs.".to_string()),
            source: "hadolint".to_string(),
            cwe_id: None,
        },
        IacRule {
            rule_id: "DOCK-IAC-012".to_string(),
            external_id: "dockerfile.no-pip-no-cache".to_string(),
            title: "pip install without --no-cache-dir".to_string(),
            message: "pip cache increases image size unnecessarily.".to_string(),
            severity: "low".to_string(),
            patterns: vec!["pip\\s+install\\s+[a-zA-Z]".to_string()],
            iac_type: "dockerfile".to_string(),
            suggestion: Some("Use pip install --no-cache-dir package-name".to_string()),
            source: "scrutin-iac".to_string(),
            cwe_id: None,
        },
        IacRule {
            rule_id: "DOCK-IAC-013".to_string(),
            external_id: "dockerfile.ssh-private-key".to_string(),
            title: "SSH private key in image".to_string(),
            message: "SSH private key detected in Dockerfile. Never include SSH keys in Docker images.".to_string(),
            severity: "critical".to_string(),
            patterns: vec!["-----BEGIN (?:RSA|OPENSSH|DSA|EC) PRIVATE KEY-----".to_string()],
            iac_type: "dockerfile".to_string(),
            suggestion: Some("Use SSH agent forwarding or build-time secrets for private repository access.".to_string()),
            source: "scrutin-iac".to_string(),
            cwe_id: Some("CWE-798".to_string()),
        },
        IacRule {
            rule_id: "DOCK-IAC-014".to_string(),
            external_id: "dockerfile.no-healthcheck".to_string(),
            title: "No HEALTHCHECK defined".to_string(),
            message: "Container has no health check defined for monitoring.".to_string(),
            severity: "low".to_string(),
            patterns: vec!["HEALTHCHECK".to_string()], // Detecta presença, ausência é verificada separadamente
            iac_type: "dockerfile".to_string(),
            suggestion: Some("Add HEALTHCHECK instruction: HEALTHCHECK --interval=30s --timeout=3s CMD curl -f http://localhost/ || exit 1".to_string()),
            source: "scrutin-iac".to_string(),
            cwe_id: None,
        },
        IacRule {
            rule_id: "DOCK-IAC-015".to_string(),
            external_id: "dockerfile.apt-get-upgrade".to_string(),
            title: "apt-get upgrade in Dockerfile".to_string(),
            message: "Running apt-get upgrade in Dockerfile is not recommended.".to_string(),
            severity: "low".to_string(),
            patterns: vec!["apt-get upgrade".to_string()],
            iac_type: "dockerfile".to_string(),
            suggestion: Some("Use a newer base image instead of apt-get upgrade.".to_string()),
            source: "hadolint".to_string(),
            cwe_id: None,
        },
    ]);

    // Docker Compose Rules
    rules.extend(vec![
        IacRule {
            rule_id: "COMP-IAC-001".to_string(),
            external_id: "docker-compose.privileged-mode".to_string(),
            title: "Privileged container mode".to_string(),
            message: "Container runs in privileged mode with full host access.".to_string(),
            severity: "critical".to_string(),
            patterns: vec!["privileged:\\s*true".to_string()],
            iac_type: "docker-compose".to_string(),
            suggestion: Some(
                "Remove privileged: true. Use specific capabilities with cap_add if needed."
                    .to_string(),
            ),
            source: "checkov".to_string(),
            cwe_id: Some("CWE-250".to_string()),
        },
        IacRule {
            rule_id: "COMP-IAC-002".to_string(),
            external_id: "docker-compose.host-network".to_string(),
            title: "Host network mode".to_string(),
            message: "Container uses host network mode, bypassing network isolation.".to_string(),
            severity: "high".to_string(),
            patterns: vec!["network_mode:\\s*['\"]?host".to_string()],
            iac_type: "docker-compose".to_string(),
            suggestion: Some(
                "Use bridge network mode or custom networks for better isolation.".to_string(),
            ),
            source: "checkov".to_string(),
            cwe_id: Some("CWE-284".to_string()),
        },
        IacRule {
            rule_id: "COMP-IAC-003".to_string(),
            external_id: "docker-compose.secrets-in-env".to_string(),
            title: "Secrets in environment variables".to_string(),
            message: "Hardcoded secrets detected in environment section.".to_string(),
            severity: "high".to_string(),
            patterns: vec!["(?i)environment:.*(?:PASSWORD|SECRET|TOKEN|KEY|API_KEY)".to_string()],
            iac_type: "docker-compose".to_string(),
            suggestion: Some(
                "Use Docker secrets or environment files (.env) excluded from version control."
                    .to_string(),
            ),
            source: "scrutin-iac".to_string(),
            cwe_id: Some("CWE-798".to_string()),
        },
        IacRule {
            rule_id: "COMP-IAC-004".to_string(),
            external_id: "docker-compose.host-pid".to_string(),
            title: "Host PID namespace".to_string(),
            message: "Container shares host PID namespace.".to_string(),
            severity: "high".to_string(),
            patterns: vec!["pid:\\s*['\"]?host".to_string()],
            iac_type: "docker-compose".to_string(),
            suggestion: Some(
                "Remove pid: host unless absolutely necessary for debugging.".to_string(),
            ),
            source: "checkov".to_string(),
            cwe_id: Some("CWE-284".to_string()),
        },
        IacRule {
            rule_id: "COMP-IAC-005".to_string(),
            external_id: "docker-compose.root-volume-mount".to_string(),
            title: "Sensitive host path mounted".to_string(),
            message: "Sensitive host directory mounted into container.".to_string(),
            severity: "high".to_string(),
            patterns: vec!["volumes:.*[/:](?:etc|var|root|boot|sys)".to_string()],
            iac_type: "docker-compose".to_string(),
            suggestion: Some(
                "Mount only specific directories needed by the application.".to_string(),
            ),
            source: "scrutin-iac".to_string(),
            cwe_id: Some("CWE-284".to_string()),
        },
        IacRule {
            rule_id: "COMP-IAC-006".to_string(),
            external_id: "docker-compose.docker-socket-mount".to_string(),
            title: "Docker socket mounted".to_string(),
            message: "Docker socket /var/run/docker.sock is mounted into container.".to_string(),
            severity: "medium".to_string(),
            patterns: vec!["/var/run/docker.sock".to_string()],
            iac_type: "docker-compose".to_string(),
            suggestion: Some(
                "Avoid mounting Docker socket. Use Docker API with TLS or alternative solutions."
                    .to_string(),
            ),
            source: "scrutin-iac".to_string(),
            cwe_id: Some("CWE-250".to_string()),
        },
        IacRule {
            rule_id: "COMP-IAC-007".to_string(),
            external_id: "docker-compose.no-resource-limits".to_string(),
            title: "No resource limits defined".to_string(),
            message: "Container has no CPU or memory limits defined.".to_string(),
            severity: "medium".to_string(),
            patterns: vec!["deploy:".to_string()], // Simplificado
            iac_type: "docker-compose".to_string(),
            suggestion: Some(
                "Add deploy.resources.limits with CPU and memory constraints.".to_string(),
            ),
            source: "scrutin-iac".to_string(),
            cwe_id: None,
        },
        IacRule {
            rule_id: "COMP-IAC-008".to_string(),
            external_id: "docker-compose.no-healthcheck".to_string(),
            title: "No health check defined".to_string(),
            message: "Service has no health check defined.".to_string(),
            severity: "low".to_string(),
            patterns: vec!["healthcheck:".to_string()],
            iac_type: "docker-compose".to_string(),
            suggestion: Some("Add healthcheck section with appropriate test command.".to_string()),
            source: "scrutin-iac".to_string(),
            cwe_id: None,
        },
        IacRule {
            rule_id: "COMP-IAC-009".to_string(),
            external_id: "docker-compose.no-restart-policy".to_string(),
            title: "No restart policy defined".to_string(),
            message: "Service has no restart policy defined.".to_string(),
            severity: "low".to_string(),
            patterns: vec!["restart:".to_string()],
            iac_type: "docker-compose".to_string(),
            suggestion: Some("Add restart: unless-stopped or restart: on-failure.".to_string()),
            source: "scrutin-iac".to_string(),
            cwe_id: None,
        },
        IacRule {
            rule_id: "COMP-IAC-010".to_string(),
            external_id: "docker-compose.latest-image-tag".to_string(),
            title: "Using latest image tag".to_string(),
            message: "Service uses :latest tag which is not deterministic.".to_string(),
            severity: "low".to_string(),
            patterns: vec!["image:.*:latest".to_string()],
            iac_type: "docker-compose".to_string(),
            suggestion: Some("Use specific version tags for reproducible deployments.".to_string()),
            source: "scrutin-iac".to_string(),
            cwe_id: None,
        },
    ]);

    // Kubernetes Rules
    rules.extend(vec![
        IacRule {
            rule_id: "K8S-IAC-001".to_string(),
            external_id: "kubernetes.run-as-root".to_string(),
            title: "Container running as root".to_string(),
            message:
                "Container is configured to run as root user (runAsUser: 0 or runAsNonRoot: false)."
                    .to_string(),
            severity: "critical".to_string(),
            patterns: vec![
                "runAsNonRoot:\\s*false".to_string(),
                "runAsUser:\\s*0".to_string(),
            ],
            iac_type: "kubernetes".to_string(),
            suggestion: Some(
                "Set runAsNonRoot: true and specify a non-zero runAsUser.".to_string(),
            ),
            source: "checkov".to_string(),
            cwe_id: Some("CWE-250".to_string()),
        },
        IacRule {
            rule_id: "K8S-IAC-002".to_string(),
            external_id: "kubernetes.privileged-container".to_string(),
            title: "Privileged container".to_string(),
            message: "Container runs in privileged mode with full host access.".to_string(),
            severity: "critical".to_string(),
            patterns: vec!["privileged:\\s*true".to_string()],
            iac_type: "kubernetes".to_string(),
            suggestion: Some(
                "Remove privileged: true. Use securityContext.capabilities.add for specific needs."
                    .to_string(),
            ),
            source: "checkov".to_string(),
            cwe_id: Some("CWE-250".to_string()),
        },
        IacRule {
            rule_id: "K8S-IAC-003".to_string(),
            external_id: "kubernetes.host-pid".to_string(),
            title: "Host PID namespace".to_string(),
            message: "Pod shares host PID namespace.".to_string(),
            severity: "critical".to_string(),
            patterns: vec!["hostPID:\\s*true".to_string()],
            iac_type: "kubernetes".to_string(),
            suggestion: Some(
                "Remove hostPID: true unless required for specific monitoring.".to_string(),
            ),
            source: "checkov".to_string(),
            cwe_id: Some("CWE-284".to_string()),
        },
        IacRule {
            rule_id: "K8S-IAC-005".to_string(),
            external_id: "kubernetes.host-network".to_string(),
            title: "Host network mode".to_string(),
            message: "Pod uses host network namespace.".to_string(),
            severity: "high".to_string(),
            patterns: vec!["hostNetwork:\\s*true".to_string()],
            iac_type: "kubernetes".to_string(),
            suggestion: Some(
                "Remove hostNetwork: true unless required for specific networking needs."
                    .to_string(),
            ),
            source: "checkov".to_string(),
            cwe_id: Some("CWE-284".to_string()),
        },
        IacRule {
            rule_id: "K8S-IAC-006".to_string(),
            external_id: "kubernetes.privilege-escalation".to_string(),
            title: "Allow privilege escalation".to_string(),
            message: "Container allows privilege escalation (allowPrivilegeEscalation: true)."
                .to_string(),
            severity: "high".to_string(),
            patterns: vec!["allowPrivilegeEscalation:\\s*true".to_string()],
            iac_type: "kubernetes".to_string(),
            suggestion: Some("Set allowPrivilegeEscalation: false in securityContext.".to_string()),
            source: "checkov".to_string(),
            cwe_id: Some("CWE-250".to_string()),
        },
        IacRule {
            rule_id: "K8S-IAC-008".to_string(),
            external_id: "kubernetes.writable-root-fs".to_string(),
            title: "Writable root filesystem".to_string(),
            message: "Container has writable root filesystem.".to_string(),
            severity: "high".to_string(),
            patterns: vec!["readOnlyRootFilesystem:\\s*false".to_string()],
            iac_type: "kubernetes".to_string(),
            suggestion: Some(
                "Set readOnlyRootFilesystem: true and use volumes for writable paths.".to_string(),
            ),
            source: "checkov".to_string(),
            cwe_id: Some("CWE-276".to_string()),
        },
        IacRule {
            rule_id: "K8S-IAC-010".to_string(),
            external_id: "kubernetes.latest-image-tag".to_string(),
            title: "Using latest image tag".to_string(),
            message: "Container image uses :latest tag.".to_string(),
            severity: "medium".to_string(),
            patterns: vec!["image:.*:latest".to_string()],
            iac_type: "kubernetes".to_string(),
            suggestion: Some("Use a specific image tag or digest.".to_string()),
            source: "checkov".to_string(),
            cwe_id: None,
        },
        IacRule {
            rule_id: "K8S-IAC-011".to_string(),
            external_id: "kubernetes.default-namespace".to_string(),
            title: "Using default namespace".to_string(),
            message: "Resource is using the default namespace.".to_string(),
            severity: "medium".to_string(),
            patterns: vec!["namespace:\\s*['\"]?default".to_string()],
            iac_type: "kubernetes".to_string(),
            suggestion: Some(
                "Create and use a dedicated namespace for your application.".to_string(),
            ),
            source: "checkov".to_string(),
            cwe_id: None,
        },
        IacRule {
            rule_id: "K8S-IAC-012".to_string(),
            external_id: "kubernetes.host-ipc".to_string(),
            title: "Host IPC namespace".to_string(),
            message: "Pod shares host IPC namespace.".to_string(),
            severity: "critical".to_string(),
            patterns: vec!["hostIPC:\\s*true".to_string()],
            iac_type: "kubernetes".to_string(),
            suggestion: Some("Remove hostIPC: true.".to_string()),
            source: "checkov".to_string(),
            cwe_id: Some("CWE-284".to_string()),
        },
        IacRule {
            rule_id: "K8S-IAC-013".to_string(),
            external_id: "kubernetes.no-resource-limits".to_string(),
            title: "No resource limits defined".to_string(),
            message: "Container has no CPU or memory limits defined.".to_string(),
            severity: "high".to_string(),
            patterns: vec!["resources:".to_string()],
            iac_type: "kubernetes".to_string(),
            suggestion: Some("Add resources.limits with cpu and memory constraints.".to_string()),
            source: "checkov".to_string(),
            cwe_id: None,
        },
        IacRule {
            rule_id: "K8S-IAC-014".to_string(),
            external_id: "kubernetes.capabilities-added".to_string(),
            title: "Dangerous capabilities added".to_string(),
            message: "Container adds dangerous capabilities like NET_ADMIN or SYS_ADMIN."
                .to_string(),
            severity: "high".to_string(),
            patterns: vec!["add:\\s*-\\s*(?:NET_ADMIN|SYS_ADMIN|SYS_PTRACE)".to_string()],
            iac_type: "kubernetes".to_string(),
            suggestion: Some(
                "Remove unnecessary capabilities. Use drop: ALL and add only required ones."
                    .to_string(),
            ),
            source: "checkov".to_string(),
            cwe_id: Some("CWE-250".to_string()),
        },
        IacRule {
            rule_id: "K8S-IAC-015".to_string(),
            external_id: "kubernetes.secrets-as-env".to_string(),
            title: "Secrets as environment variables".to_string(),
            message: "Sensitive data should not be stored in environment variables.".to_string(),
            severity: "medium".to_string(),
            patterns: vec!["valueFrom:\\s*secretKeyRef:".to_string()],
            iac_type: "kubernetes".to_string(),
            suggestion: Some(
                "Mount secrets as files instead of environment variables.".to_string(),
            ),
            source: "checkov".to_string(),
            cwe_id: Some("CWE-214".to_string()),
        },
    ]);

    // Terraform Rules
    rules.extend(vec![
        IacRule {
            rule_id: "TF-IAC-001".to_string(),
            external_id: "terraform.s3-public-read".to_string(),
            title: "Public S3 bucket access".to_string(),
            message: "S3 bucket is configured with public-read ACL.".to_string(),
            severity: "critical".to_string(),
            patterns: vec![
                "acl\\s*=\\s*[\"']?public-read".to_string(),
                "acl\\s*=\\s*[\"']?public-read-write".to_string(),
            ],
            iac_type: "terraform".to_string(),
            suggestion: Some(
                "Remove public ACL and use bucket policies with specific principal restrictions."
                    .to_string(),
            ),
            source: "checkov".to_string(),
            cwe_id: Some("CWE-284".to_string()),
        },
        IacRule {
            rule_id: "TF-IAC-002".to_string(),
            external_id: "terraform.security-group-open".to_string(),
            title: "Open security group ingress".to_string(),
            message: "Security group allows traffic from 0.0.0.0/0 to sensitive ports.".to_string(),
            severity: "critical".to_string(),
            patterns: vec!["cidr_blocks\\s*=\\s*\\[\"0\\.0\\.0\\.0/0\"\\]".to_string()],
            iac_type: "terraform".to_string(),
            suggestion: Some(
                "Restrict CIDR blocks to specific IP ranges or use security group references."
                    .to_string(),
            ),
            source: "checkov".to_string(),
            cwe_id: Some("CWE-284".to_string()),
        },
        IacRule {
            rule_id: "TF-IAC-004".to_string(),
            external_id: "terraform.hardcoded-password".to_string(),
            title: "Hardcoded password in Terraform".to_string(),
            message: "Hardcoded password detected in Terraform configuration.".to_string(),
            severity: "critical".to_string(),
            patterns: vec!["(?i)(?:password|master_password)\\s*=\\s*[\"][^$]".to_string()],
            iac_type: "terraform".to_string(),
            suggestion: Some(
                "Use variables with sensitive = true or integrate with a secret manager."
                    .to_string(),
            ),
            source: "scrutin-iac".to_string(),
            cwe_id: Some("CWE-798".to_string()),
        },
        IacRule {
            rule_id: "TF-IAC-005".to_string(),
            external_id: "terraform.ssh-open-world".to_string(),
            title: "SSH open to world".to_string(),
            message: "Security group allows SSH (port 22) from 0.0.0.0/0.".to_string(),
            severity: "critical".to_string(),
            patterns: vec![
                "from_port\\s*=\\s*22.*cidr.*0\\.0\\.0\\.0/0".to_string(),
                "port\\s*=\\s*22.*cidr.*0\\.0\\.0\\.0/0".to_string(),
            ],
            iac_type: "terraform".to_string(),
            suggestion: Some(
                "Restrict SSH access to specific bastion hosts or IP ranges.".to_string(),
            ),
            source: "checkov".to_string(),
            cwe_id: Some("CWE-284".to_string()),
        },
        IacRule {
            rule_id: "TF-IAC-006".to_string(),
            external_id: "terraform.rds-public".to_string(),
            title: "RDS publicly accessible".to_string(),
            message: "RDS instance is publicly accessible.".to_string(),
            severity: "critical".to_string(),
            patterns: vec!["publicly_accessible\\s*=\\s*true".to_string()],
            iac_type: "terraform".to_string(),
            suggestion: Some(
                "Set publicly_accessible = false and use VPC peering or VPN for access."
                    .to_string(),
            ),
            source: "checkov".to_string(),
            cwe_id: Some("CWE-284".to_string()),
        },
        IacRule {
            rule_id: "TF-IAC-007".to_string(),
            external_id: "terraform.rds-unencrypted".to_string(),
            title: "RDS storage unencrypted".to_string(),
            message: "RDS instance does not have storage encryption enabled.".to_string(),
            severity: "high".to_string(),
            patterns: vec!["storage_encrypted\\s*=\\s*false".to_string()],
            iac_type: "terraform".to_string(),
            suggestion: Some(
                "Set storage_encrypted = true and specify kms_key_id if needed.".to_string(),
            ),
            source: "checkov".to_string(),
            cwe_id: Some("CWE-311".to_string()),
        },
        IacRule {
            rule_id: "TF-IAC-008".to_string(),
            external_id: "terraform.ebs-unencrypted".to_string(),
            title: "EBS volume unencrypted".to_string(),
            message: "EBS volume does not have encryption enabled.".to_string(),
            severity: "high".to_string(),
            patterns: vec!["encrypted\\s*=\\s*false".to_string()],
            iac_type: "terraform".to_string(),
            suggestion: Some("Set encrypted = true on the EBS volume resource.".to_string()),
            source: "checkov".to_string(),
            cwe_id: Some("CWE-311".to_string()),
        },
        IacRule {
            rule_id: "TF-IAC-009".to_string(),
            external_id: "terraform.public-subnet-autoip".to_string(),
            title: "Public subnet auto-assigns public IP".to_string(),
            message: "Subnet automatically assigns public IP to instances.".to_string(),
            severity: "high".to_string(),
            patterns: vec!["map_public_ip_on_launch\\s*=\\s*true".to_string()],
            iac_type: "terraform".to_string(),
            suggestion: Some(
                "Set map_public_ip_on_launch = false. Use elastic IPs or ALBs for external access."
                    .to_string(),
            ),
            source: "checkov".to_string(),
            cwe_id: Some("CWE-284".to_string()),
        },
    ]);

    // CI/CD Rules
    rules.extend(vec![
        IacRule {
            rule_id: "CI-IAC-001".to_string(),
            external_id: "cicd.secrets-plain-text".to_string(),
            title: "Secrets in plain text".to_string(),
            message: "Hardcoded secrets detected in CI/CD configuration.".to_string(),
            severity: "critical".to_string(),
            patterns: vec!["(?i)(?:password|token|secret|api_key|apikey)\\s*:\\s*[^${]".to_string()],
            iac_type: "github-actions".to_string(),
            suggestion: Some("Use environment variables or secret management (GitHub secrets, GitLab CI variables).".to_string()),
            source: "scrutin-iac".to_string(),
            cwe_id: Some("CWE-798".to_string()),
        },
        IacRule {
            rule_id: "CI-IAC-002".to_string(),
            external_id: "cicd.script-injection".to_string(),
            title: "Script injection vulnerability".to_string(),
            message: "GitHub Actions expression in run command may allow script injection.".to_string(),
            severity: "critical".to_string(),
            patterns: vec!["run:.*\\$\\{\\{.*github\\.event".to_string()],
            iac_type: "github-actions".to_string(),
            suggestion: Some("Use intermediate environment variables to sanitize inputs.".to_string()),
            source: "scrutin-iac".to_string(),
            cwe_id: Some("CWE-94".to_string()),
        },
        IacRule {
            rule_id: "CI-IAC-004".to_string(),
            external_id: "cicd.unpinned-action".to_string(),
            title: "Unpinned action version".to_string(),
            message: "GitHub Action uses mutable reference (@main, @master, @v1).".to_string(),
            severity: "high".to_string(),
            patterns: vec!["uses:\\s*[^@]+@(?:main|master|latest|v?\\d+$)".to_string()],
            iac_type: "github-actions".to_string(),
            suggestion: Some("Pin to specific SHA or full version: actions/checkout@v4.1.1".to_string()),
            source: "scrutin-iac".to_string(),
            cwe_id: Some("CWE-829".to_string()),
        },
        IacRule {
            rule_id: "CI-IAC-005".to_string(),
            external_id: "cicd.pull-request-target".to_string(),
            title: "pull_request_target trigger".to_string(),
            message: "Workflow uses pull_request_target which runs with elevated permissions.".to_string(),
            severity: "high".to_string(),
            patterns: vec!["pull_request_target:".to_string()],
            iac_type: "github-actions".to_string(),
            suggestion: Some("Use pull_request trigger instead, or implement strict path filtering.".to_string()),
            source: "scrutin-iac".to_string(),
            cwe_id: Some("CWE-250".to_string()),
        },
        IacRule {
            rule_id: "CI-IAC-006".to_string(),
            external_id: "cicd.write-all-permissions".to_string(),
            title: "Overly permissive permissions".to_string(),
            message: "Workflow has write-all or overly broad permissions.".to_string(),
            severity: "high".to_string(),
            patterns: vec!["permissions:\\s*write-all".to_string()],
            iac_type: "github-actions".to_string(),
            suggestion: Some("Use minimal required permissions: permissions: contents: read".to_string()),
            source: "scrutin-iac".to_string(),
            cwe_id: Some("CWE-250".to_string()),
        },
        IacRule {
            rule_id: "CI-IAC-007".to_string(),
            external_id: "cicd.echo-secrets".to_string(),
            title: "Echoing secrets".to_string(),
            message: "Pipeline echoes secret values which may leak in logs.".to_string(),
            severity: "critical".to_string(),
            patterns: vec!["echo.*\\$\\{\\{.*secrets\\.".to_string()],
            iac_type: "github-actions".to_string(),
            suggestion: Some("Remove echo statements that reference secrets.".to_string()),
            source: "scrutin-iac".to_string(),
            cwe_id: Some("CWE-200".to_string()),
        },
        IacRule {
            rule_id: "CI-IAC-008".to_string(),
            external_id: "cicd.workflow-run-injection".to_string(),
            title: "Untrusted input in workflow_run".to_string(),
            message: "Workflow triggered by workflow_run may process untrusted input.".to_string(),
            severity: "high".to_string(),
            patterns: vec!["github\\.event\\.workflow_run".to_string()],
            iac_type: "github-actions".to_string(),
            suggestion: Some("Sanitize inputs and avoid using workflow_run data in shell commands.".to_string()),
            source: "scrutin-iac".to_string(),
            cwe_id: Some("CWE-94".to_string()),
        },
        IacRule {
            rule_id: "CI-IAC-009".to_string(),
            external_id: "cicd.no-timeout".to_string(),
            title: "No timeout defined".to_string(),
            message: "Job has no timeout-minutes defined.".to_string(),
            severity: "low".to_string(),
            patterns: vec!["timeout-minutes:".to_string()],
            iac_type: "github-actions".to_string(),
            suggestion: Some("Add timeout-minutes to jobs: timeout-minutes: 30".to_string()),
            source: "scrutin-iac".to_string(),
            cwe_id: None,
        },
        IacRule {
            rule_id: "CI-IAC-010".to_string(),
            external_id: "cicd.third-party-action".to_string(),
            title: "Third-party action without verification".to_string(),
            message: "Workflow uses third-party action that should be verified.".to_string(),
            severity: "medium".to_string(),
            patterns: vec!["uses:\\s*[^/@\\s]+/[^@]+".to_string()],
            iac_type: "github-actions".to_string(),
            suggestion: Some("Verify the action source, pin to SHA, and consider forking trusted actions.".to_string()),
            source: "scrutin-iac".to_string(),
            cwe_id: Some("CWE-829".to_string()),
        },
        IacRule {
            rule_id: "CI-IAC-011".to_string(),
            external_id: "cicd.gitlab-secrets".to_string(),
            title: "Secrets in GitLab CI variables".to_string(),
            message: "Hardcoded secrets detected in GitLab CI configuration.".to_string(),
            severity: "critical".to_string(),
            patterns: vec![
                "(?i)(?:password|token|secret|api_key).*:\\s*[^$]".to_string(),
            ],
            iac_type: "gitlab-ci".to_string(),
            suggestion: Some("Use GitLab CI/CD variables or a secret manager.".to_string()),
            source: "scrutin-iac".to_string(),
            cwe_id: Some("CWE-798".to_string()),
        },
        IacRule {
            rule_id: "CI-IAC-012".to_string(),
            external_id: "cicd.gitlab-docker-socket".to_string(),
            title: "Docker socket mounted in GitLab CI".to_string(),
            message: "Docker socket is mounted which may allow container escape.".to_string(),
            severity: "high".to_string(),
            patterns: vec![
                "docker:\\s*dind".to_string(),
                "/var/run/docker.sock".to_string(),
            ],
            iac_type: "gitlab-ci".to_string(),
            suggestion: Some("Use GitLab Runner with Docker-in-Docker service instead of socket binding.".to_string()),
            source: "scrutin-iac".to_string(),
            cwe_id: Some("CWE-250".to_string()),
        },
    ]);

    rules
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_embedded_rules() {
        let engine = IacEngine::load().unwrap();
        let stats = engine.stats();

        // Deve ter pelo menos 50 regras
        assert!(
            stats.total_rules >= 50,
            "Esperado pelo menos 50 regras, encontrado {}",
            stats.total_rules
        );

        // Deve ter regras de todas as categorias
        assert!(
            stats.by_type.contains_key("dockerfile"),
            "Deve ter regras de Dockerfile"
        );
        assert!(
            stats.by_type.contains_key("kubernetes"),
            "Deve ter regras de Kubernetes"
        );
        assert!(
            stats.by_type.contains_key("terraform"),
            "Deve ter regras de Terraform"
        );
    }

    #[test]
    fn test_detect_iac_type_dockerfile() {
        assert_eq!(IacType::detect_from_path("Dockerfile"), IacType::Dockerfile);
        assert_eq!(
            IacType::detect_from_path("dockerfile.prod"),
            IacType::Dockerfile
        );
        assert_eq!(
            IacType::detect_from_path("src/Dockerfile"),
            IacType::Dockerfile
        );
    }

    #[test]
    fn test_detect_iac_type_docker_compose() {
        assert_eq!(
            IacType::detect_from_path("docker-compose.yml"),
            IacType::DockerCompose
        );
        assert_eq!(
            IacType::detect_from_path("docker-compose.prod.yaml"),
            IacType::DockerCompose
        );
        assert_eq!(
            IacType::detect_from_path("compose.yml"),
            IacType::DockerCompose
        );
    }

    #[test]
    fn test_detect_iac_type_kubernetes() {
        assert_eq!(
            IacType::detect_from_path("k8s/deployment.yaml"),
            IacType::Kubernetes
        );
        assert_eq!(
            IacType::detect_from_path("manifests/service.yml"),
            IacType::Kubernetes
        );
    }

    #[test]
    fn test_detect_iac_type_terraform() {
        assert_eq!(IacType::detect_from_path("main.tf"), IacType::Terraform);
        assert_eq!(
            IacType::detect_from_path("variables.tfvars"),
            IacType::Terraform
        );
    }

    #[test]
    fn test_detect_iac_type_github_actions() {
        assert_eq!(
            IacType::detect_from_path(".github/workflows/deploy.yml"),
            IacType::GitHubActions
        );
    }

    #[test]
    fn test_scan_dockerfile_root_user() {
        let engine = IacEngine::load().unwrap();
        let content = r#"FROM node:18
USER root
RUN npm install
"#;

        let options = IacScanOptions::default();
        let findings = engine.scan_content("Dockerfile", content, &options);

        let root_finding = findings.iter().find(|f| f.rule_id == "DOCK-IAC-003");
        assert!(root_finding.is_some(), "Deve detectar uso de root");
    }

    #[test]
    fn test_scan_dockerfile_secrets_in_env() {
        let engine = IacEngine::load().unwrap();
        let content = r#"FROM node:18
ENV API_KEY=sk-1234567890abcdef
RUN npm start
"#;

        let options = IacScanOptions::default();
        let findings = engine.scan_content("Dockerfile", content, &options);

        let secret_finding = findings.iter().find(|f| f.rule_id == "DOCK-IAC-001");
        assert!(secret_finding.is_some(), "Deve detectar secrets em ENV");
    }

    #[test]
    fn test_scan_kubernetes_privileged() {
        let engine = IacEngine::load().unwrap();
        let content = r#"apiVersion: v1
kind: Pod
spec:
  containers:
  - name: app
    image: nginx
    securityContext:
      privileged: true
"#;

        let options = IacScanOptions::default();
        let findings = engine.scan_content("deployment.yaml", content, &options);

        let privileged_finding = findings.iter().find(|f| f.rule_id == "K8S-IAC-002");
        assert!(
            privileged_finding.is_some(),
            "Deve detectar container privilegiado"
        );
    }

    #[test]
    fn test_scan_terraform_public_s3() {
        let engine = IacEngine::load().unwrap();
        let content = r#"resource "aws_s3_bucket" "mybucket" {
  bucket = "my-bucket"
  acl    = "public-read"
}
"#;

        let options = IacScanOptions::default();
        let findings = engine.scan_content("main.tf", content, &options);

        let public_s3_finding = findings.iter().find(|f| f.rule_id == "TF-IAC-001");
        assert!(
            public_s3_finding.is_some(),
            "Deve detectar S3 bucket público"
        );
    }

    #[test]
    fn test_scan_cicd_unpinned_action() {
        let engine = IacEngine::load().unwrap();
        let content = r#"name: CI
jobs:
  build:
    steps:
    - uses: actions/checkout@main
"#;

        let options = IacScanOptions::default();
        let findings = engine.scan_content(".github/workflows/ci.yml", content, &options);

        let unpinned_finding = findings.iter().find(|f| f.rule_id == "CI-IAC-004");
        assert!(
            unpinned_finding.is_some(),
            "Deve detectar action não pinada"
        );
    }

    #[test]
    fn test_iac_severity_ordering() {
        assert!(IacSeverity::Critical > IacSeverity::High);
        assert!(IacSeverity::High > IacSeverity::Medium);
        assert!(IacSeverity::Medium > IacSeverity::Low);
    }

    #[test]
    fn test_finding_to_analysis_issue() {
        let finding = IacFinding {
            rule_id: "TEST-001".to_string(),
            file_path: "Dockerfile".to_string(),
            line_number: 5,
            severity: IacSeverity::High,
            title: "Test Finding".to_string(),
            message: "This is a test".to_string(),
            suggestion: "Fix it".to_string(),
            iac_type: IacType::Dockerfile,
            matched_pattern: "USER root".to_string(),
            source: "test".to_string(),
            confidence: 0.95,
        };

        let issue = finding.to_analysis_issue();

        assert_eq!(issue.rule_id, Some("TEST-001".to_string()));
        assert_eq!(issue.severity, "high");
        assert_eq!(issue.category, "iac");
    }
}
