use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use tracing::{debug, trace};
use walkdir::{DirEntry, WalkDir};

use crate::iac_engine::IacType;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Language {
    Dotnet,
    TypeScript,
    Python,
    Go,
    Rust,
    Java,
    Cpp,
    Php,
    Ruby,
    Kotlin,
    Shell,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectedProject {
    pub root: PathBuf,
    pub language: Language,
    pub marker_file: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ProjectLanguageProfile {
    pub languages: Vec<Language>,
    pub projects: Vec<DetectedProject>,
    pub auxiliary_targets: Vec<DetectedTarget>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum DetectedTargetKind {
    Iac,
    Cicd,
    Config,
    Template,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct DetectedTarget {
    pub path: PathBuf,
    pub key: String,
    pub kind: DetectedTargetKind,
    pub marker: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuggestedBuildTarget {
    pub language: Language,
    pub path: PathBuf,
    pub command: String,
}

impl ProjectLanguageProfile {
    pub fn target_keys(&self) -> Vec<String> {
        let mut targets = BTreeSet::new();
        for language in &self.languages {
            targets.insert(language.as_str().to_string());
        }
        for target in &self.auxiliary_targets {
            targets.insert(target.key.clone());
        }

        targets.into_iter().collect()
    }

    pub fn primary_language(&self) -> Language {
        self.languages.first().copied().unwrap_or(Language::Unknown)
    }

    pub fn is_polyglot(&self) -> bool {
        self.target_keys().len() > 1
    }

    pub fn label(&self) -> String {
        let targets = self.target_keys();
        match targets.as_slice() {
            [] => "unknown".to_string(),
            [single] => single.clone(),
            _ => "polyglot".to_string(),
        }
    }

    pub fn supported_extensions(&self) -> Vec<&'static str> {
        let mut extensions = BTreeSet::new();
        for language in &self.languages {
            for ext in language.file_extensions() {
                extensions.insert(*ext);
            }
        }
        for target in &self.auxiliary_targets {
            for ext in auxiliary_target_extensions(&target.key) {
                extensions.insert(*ext);
            }
        }
        extensions.into_iter().collect()
    }

    pub fn supported_file_names(&self) -> Vec<&'static str> {
        let mut names = BTreeSet::new();
        for target in &self.auxiliary_targets {
            for file_name in auxiliary_target_file_names(&target.key) {
                names.insert(*file_name);
            }
        }

        names.into_iter().collect()
    }
}

impl Language {
    pub fn as_str(&self) -> &'static str {
        match self {
            Language::Dotnet => "dotnet",
            Language::TypeScript => "typescript",
            Language::Python => "python",
            Language::Go => "go",
            Language::Rust => "rust",
            Language::Java => "java",
            Language::Cpp => "cpp",
            Language::Php => "php",
            Language::Ruby => "ruby",
            Language::Kotlin => "kotlin",
            Language::Shell => "shell",
            Language::Unknown => "unknown",
        }
    }

    pub fn default_command(&self) -> Option<&'static str> {
        match self {
            Language::Dotnet => Some("dotnet build"),
            Language::TypeScript => Some("npm run build"),
            Language::Python => Some("python -m compileall ."),
            Language::Go => Some("go build ./..."),
            Language::Rust => Some("cargo build"),
            Language::Java => Some("mvn compile"),
            Language::Cpp => Some("make"),
            Language::Php => Some("composer validate"),
            Language::Ruby => Some("bundle exec rubocop"),
            Language::Kotlin => Some("gradle build"),
            Language::Shell => None,
            Language::Unknown => None,
        }
    }

    pub fn lint_command(&self) -> Option<&'static str> {
        match self {
            Language::Dotnet => Some("dotnet build --verbosity normal"),
            Language::TypeScript => Some("npx tsc --noEmit"),
            Language::Python => Some("flake8 ."),
            Language::Go => Some("golangci-lint run"),
            Language::Rust => Some("cargo clippy"),
            Language::Java => Some("mvn checkstyle:check"),
            Language::Cpp => Some("cppcheck ."),
            Language::Php => Some("phpstan analyse"),
            Language::Ruby => Some("rubocop"),
            Language::Kotlin => Some("detekt"),
            Language::Shell => Some("shellcheck -f gcc"),
            Language::Unknown => None,
        }
    }

    /// Lista de ferramentas necessárias para o build
    pub fn required_tools(&self) -> Vec<&'static str> {
        match self {
            Language::Dotnet => vec!["dotnet"],
            Language::TypeScript => vec!["npm", "node"],
            Language::Python => vec!["python"],
            Language::Go => vec!["go"],
            Language::Rust => vec!["cargo", "rustc"],
            Language::Java => vec!["mvn"],
            Language::Cpp => vec!["gcc"],
            Language::Php => vec!["composer", "php"],
            Language::Ruby => vec!["ruby"],
            Language::Kotlin => vec!["gradle", "kotlinc"],
            Language::Shell => vec!["bash"],
            Language::Unknown => vec![],
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "dotnet" | "csharp" | "c#" => Some(Language::Dotnet),
            "typescript" | "ts" | "javascript" | "js" => Some(Language::TypeScript),
            "python" | "py" => Some(Language::Python),
            "go" | "golang" => Some(Language::Go),
            "rust" | "rs" => Some(Language::Rust),
            "java" => Some(Language::Java),
            "cpp" | "c++" | "c" => Some(Language::Cpp),
            "php" => Some(Language::Php),
            "ruby" | "rb" => Some(Language::Ruby),
            "kotlin" | "kt" => Some(Language::Kotlin),
            "shell" | "bash" | "sh" | "zsh" | "posix" => Some(Language::Shell),
            _ => None,
        }
    }

    pub fn file_extensions(&self) -> &'static [&'static str] {
        match self {
            Language::Dotnet => &[".cs", ".cshtml"],
            Language::TypeScript => &[".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"],
            Language::Python => &[".py"],
            Language::Go => &[".go"],
            Language::Rust => &[".rs"],
            Language::Java => &[".java"],
            Language::Cpp => &[".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx"],
            Language::Php => &[".php"],
            Language::Ruby => &[".rb", ".gemspec"],
            Language::Kotlin => &[".kt", ".kts"],
            Language::Shell => &[".sh", ".bash", ".zsh", ".ksh", ".csh"],
            Language::Unknown => &[],
        }
    }
}

pub fn detect_language(root: &Path) -> Language {
    let profile = detect_project_profile(root);
    let language = profile.primary_language();
    debug!(
        primary = %language.as_str(),
        polyglot = profile.is_polyglot(),
        detected_languages = ?profile.languages.iter().map(Language::as_str).collect::<Vec<_>>(),
        "Linguagem principal detectada"
    );
    language
}

pub fn detect_project_profile(root: &Path) -> ProjectLanguageProfile {
    debug!("Detectando linguagens do projeto em: {}", root.display());

    let mut projects = BTreeMap::<(PathBuf, Language, String), DetectedProject>::new();
    let mut languages = BTreeSet::<Language>::new();
    let mut auxiliary_targets = BTreeMap::<(PathBuf, String), DetectedTarget>::new();

    for entry in WalkDir::new(root)
        .into_iter()
        .filter_entry(should_visit_entry)
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_file())
    {
        let path = entry.path();
        let file_name = entry.file_name().to_string_lossy().to_lowercase();
        trace!("Verificando arquivo: {}", path.display());

        if let Some(language) = detect_source_language(path) {
            languages.insert(language);
        }

        if let Some(language) = detect_project_marker(&file_name) {
            let project_root = path.parent().unwrap_or(root).to_path_buf();
            projects.insert(
                (project_root.clone(), language, file_name.clone()),
                DetectedProject {
                    root: project_root,
                    language,
                    marker_file: file_name,
                },
            );
            languages.insert(language);
        }

        if let Some(target) = detect_auxiliary_target(path) {
            let scope = auxiliary_target_scope(path, &target.key);
            auxiliary_targets.insert(
                (scope.clone(), target.key.clone()),
                DetectedTarget {
                    path: scope,
                    key: target.key,
                    kind: target.kind,
                    marker: target.marker,
                },
            );
        }
    }

    let mut languages: Vec<_> = languages.into_iter().collect();
    languages.sort_by_key(|language| language_priority(*language));

    let mut projects: Vec<_> = projects.into_values().collect();
    projects.sort_by(|a, b| {
        let by_path = a.root.cmp(&b.root);
        if by_path == std::cmp::Ordering::Equal {
            language_priority(a.language).cmp(&language_priority(b.language))
        } else {
            by_path
        }
    });

    let auxiliary_targets = auxiliary_targets.into_values().collect();

    ProjectLanguageProfile {
        languages,
        projects,
        auxiliary_targets,
    }
}

pub fn suggest_build_targets(
    root: &Path,
    profile: &ProjectLanguageProfile,
) -> Vec<SuggestedBuildTarget> {
    profile
        .projects
        .iter()
        .filter_map(|project| project_to_build_target(root, project))
        .collect()
}

fn project_to_build_target(root: &Path, project: &DetectedProject) -> Option<SuggestedBuildTarget> {
    let relative = project
        .root
        .strip_prefix(root)
        .unwrap_or(&project.root)
        .to_path_buf();
    let rel = relative.to_string_lossy();
    let is_root = rel.is_empty() || rel == ".";

    let command = match project.language {
        Language::Dotnet => {
            if is_root {
                "dotnet build".to_string()
            } else {
                format!(
                    "dotnet build {}",
                    project.root.join(&project.marker_file).display()
                )
            }
        }
        Language::TypeScript => {
            if is_root {
                "npm run build".to_string()
            } else {
                format!("npm run build --prefix {}", relative.display())
            }
        }
        Language::Python => {
            if is_root {
                "python -m compileall .".to_string()
            } else {
                format!("python -m compileall {}", relative.display())
            }
        }
        Language::Go => {
            if is_root {
                "go build ./...".to_string()
            } else {
                format!("cd {} && go build ./...", relative.display())
            }
        }
        Language::Rust => {
            if is_root {
                "cargo build".to_string()
            } else {
                format!(
                    "cargo build --manifest-path {}",
                    project.root.join("Cargo.toml").display()
                )
            }
        }
        Language::Java => {
            if project.marker_file == "pom.xml" {
                if is_root {
                    "mvn compile".to_string()
                } else {
                    format!("mvn -f {} compile", project.root.join("pom.xml").display())
                }
            } else if is_root {
                "gradle build".to_string()
            } else {
                format!("gradle -p {} build", relative.display())
            }
        }
        Language::Cpp => {
            if project.marker_file == "cmakelists.txt" {
                if is_root {
                    "cmake --build .".to_string()
                } else {
                    format!("cmake --build {}", relative.display())
                }
            } else if is_root {
                "make".to_string()
            } else {
                format!("make -C {}", relative.display())
            }
        }
        Language::Php => {
            if is_root {
                "composer validate".to_string()
            } else {
                format!("composer --working-dir {} validate", relative.display())
            }
        }
        Language::Ruby => {
            if is_root {
                "bundle exec rubocop".to_string()
            } else {
                format!("cd {} && bundle exec rubocop", relative.display())
            }
        }
        Language::Kotlin => {
            if is_root {
                "gradle build".to_string()
            } else {
                format!("gradle -p {} build", relative.display())
            }
        }
        Language::Shell => return None,
        Language::Unknown => return None,
    };

    Some(SuggestedBuildTarget {
        language: project.language,
        path: project.root.clone(),
        command,
    })
}

fn detect_project_marker(file_name: &str) -> Option<Language> {
    match file_name {
        name if name.ends_with(".csproj") || name.ends_with(".sln") => Some(Language::Dotnet),
        "cargo.toml" => Some(Language::Rust),
        "go.mod" => Some(Language::Go),
        "pom.xml" | "settings.gradle" | "build.gradle" => Some(Language::Java),
        "build.gradle.kts" | "settings.gradle.kts" => Some(Language::Kotlin),
        "package.json" => Some(Language::TypeScript),
        "pyproject.toml" | "requirements.txt" | "setup.py" => Some(Language::Python),
        "composer.json" => Some(Language::Php),
        "gemfile" => Some(Language::Ruby),
        "makefile" | "cmakelists.txt" => Some(Language::Cpp),
        _ if file_name.ends_with(".gemspec") => Some(Language::Ruby),
        _ => None,
    }
}

fn detect_source_language(path: &Path) -> Option<Language> {
    let ext = path
        .extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| ext.to_ascii_lowercase())?;

    match ext.as_str() {
        "cs" | "cshtml" => Some(Language::Dotnet),
        "ts" | "tsx" | "js" | "jsx" | "mjs" | "cjs" => Some(Language::TypeScript),
        "py" => Some(Language::Python),
        "go" => Some(Language::Go),
        "rs" => Some(Language::Rust),
        "java" => Some(Language::Java),
        "c" | "cc" | "cpp" | "cxx" | "h" | "hh" | "hpp" | "hxx" => Some(Language::Cpp),
        "php" => Some(Language::Php),
        "rb" | "gemspec" => Some(Language::Ruby),
        "kt" | "kts" => Some(Language::Kotlin),
        "sh" | "bash" | "zsh" | "ksh" | "csh" => Some(Language::Shell),
        _ => None,
    }
}

#[derive(Debug, Clone)]
struct AuxiliaryTargetMatch {
    key: String,
    kind: DetectedTargetKind,
    marker: String,
}

fn detect_auxiliary_target(path: &Path) -> Option<AuxiliaryTargetMatch> {
    let path_str = path.to_string_lossy();
    let lower_path = path_str.to_lowercase();
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default()
        .to_lowercase();
    let extension = path
        .extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| ext.to_ascii_lowercase());

    match IacType::detect_from_path(&lower_path) {
        IacType::Dockerfile => {
            return Some(aux_target("dockerfile", DetectedTargetKind::Iac, file_name));
        }
        IacType::DockerCompose => {
            return Some(aux_target(
                "docker-compose",
                DetectedTargetKind::Iac,
                file_name,
            ));
        }
        IacType::Kubernetes => {
            return Some(aux_target("kubernetes", DetectedTargetKind::Iac, file_name));
        }
        IacType::Terraform => {
            return Some(aux_target("terraform", DetectedTargetKind::Iac, file_name));
        }
        IacType::GitHubActions => {
            return Some(aux_target(
                "github-actions",
                DetectedTargetKind::Cicd,
                file_name,
            ));
        }
        IacType::GitLabCi => {
            return Some(aux_target("gitlab-ci", DetectedTargetKind::Cicd, file_name));
        }
        IacType::AzurePipelines => {
            return Some(aux_target(
                "azure-pipelines",
                DetectedTargetKind::Cicd,
                file_name,
            ));
        }
        IacType::Unknown => {}
    }

    match extension.as_deref() {
        Some("jsp") | Some("jspx") => {
            return Some(aux_target("jsp", DetectedTargetKind::Template, file_name));
        }
        Some("page") | Some("component") => {
            return Some(aux_target("vf", DetectedTargetKind::Template, file_name));
        }
        Some("xml") => {
            return Some(aux_target("xml", DetectedTargetKind::Config, file_name));
        }
        Some("json") => {
            return Some(aux_target("json", DetectedTargetKind::Config, file_name));
        }
        Some("yaml") | Some("yml") => {
            return Some(aux_target("yaml", DetectedTargetKind::Config, file_name));
        }
        _ => {}
    }

    None
}

fn aux_target(key: &str, kind: DetectedTargetKind, marker: String) -> AuxiliaryTargetMatch {
    AuxiliaryTargetMatch {
        key: key.to_string(),
        kind,
        marker,
    }
}

fn auxiliary_target_scope(path: &Path, key: &str) -> PathBuf {
    match key {
        "github-actions" => find_ancestor_named(path, "workflows")
            .or_else(|| path.parent().map(Path::to_path_buf))
            .unwrap_or_else(|| path.to_path_buf()),
        "dockerfile" | "docker-compose" | "gitlab-ci" | "azure-pipelines" => path.to_path_buf(),
        _ => path
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| path.to_path_buf()),
    }
}

fn find_ancestor_named(path: &Path, name: &str) -> Option<PathBuf> {
    path.ancestors()
        .find(|ancestor| {
            ancestor
                .file_name()
                .and_then(|candidate| candidate.to_str())
                .is_some_and(|candidate| candidate.eq_ignore_ascii_case(name))
        })
        .map(Path::to_path_buf)
}

fn auxiliary_target_extensions(key: &str) -> &'static [&'static str] {
    match key {
        "terraform" => &[".tf", ".tfvars", ".hcl"],
        "kubernetes" | "yaml" | "github-actions" | "gitlab-ci" | "azure-pipelines" => {
            &[".yaml", ".yml"]
        }
        "json" => &[".json"],
        "xml" => &[".xml"],
        "jsp" => &[".jsp", ".jspx"],
        "vf" => &[".page", ".component"],
        _ => &[],
    }
}

fn auxiliary_target_file_names(key: &str) -> &'static [&'static str] {
    match key {
        "dockerfile" => &["dockerfile", "containerfile"],
        "docker-compose" => &[
            "docker-compose.yml",
            "docker-compose.yaml",
            "compose.yml",
            "compose.yaml",
        ],
        "gitlab-ci" => &[".gitlab-ci.yml"],
        "azure-pipelines" => &["azure-pipelines.yml", "azure-pipelines.yaml"],
        _ => &[],
    }
}

fn should_visit_entry(entry: &DirEntry) -> bool {
    if entry.depth() == 0 {
        return true;
    }

    if !entry.file_type().is_dir() {
        return true;
    }

    let name = entry.file_name().to_string_lossy();
    !matches!(
        name.as_ref(),
        "node_modules"
            | "target"
            | ".git"
            | "__pycache__"
            | "vendor"
            | "dist"
            | "build"
            | ".next"
            | "bin"
            | "obj"
            | ".idea"
            | ".vscode"
            | ".venv"
            | "coverage"
    )
}

fn language_priority(language: Language) -> usize {
    match language {
        Language::Dotnet => 0,
        Language::Rust => 1,
        Language::Go => 2,
        Language::Java => 3,
        Language::Kotlin => 4,
        Language::TypeScript => 5,
        Language::Python => 6,
        Language::Php => 7,
        Language::Ruby => 8,
        Language::Cpp => 9,
        Language::Shell => 10,
        Language::Unknown => 11,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{self, File};
    use std::io::Write;
    use tempfile::TempDir;

    #[test]
    fn test_detect_dotnet() {
        let dir = TempDir::new().unwrap();
        let mut file = File::create(dir.path().join("project.csproj")).unwrap();
        file.write_all(b"<Project></Project>").unwrap();

        let lang = detect_language(dir.path());
        assert!(matches!(lang, Language::Dotnet));
    }

    #[test]
    fn test_detect_rust() {
        let dir = TempDir::new().unwrap();
        File::create(dir.path().join("Cargo.toml")).unwrap();

        let lang = detect_language(dir.path());
        assert!(matches!(lang, Language::Rust));
    }

    #[test]
    fn test_detect_go() {
        let dir = TempDir::new().unwrap();
        File::create(dir.path().join("go.mod")).unwrap();

        let lang = detect_language(dir.path());
        assert!(matches!(lang, Language::Go));
    }

    #[test]
    fn test_detect_typescript() {
        let dir = TempDir::new().unwrap();
        File::create(dir.path().join("package.json")).unwrap();

        let lang = detect_language(dir.path());
        assert!(matches!(lang, Language::TypeScript));
    }

    #[test]
    fn test_detect_kotlin_from_gradle_kts() {
        let dir = TempDir::new().unwrap();
        File::create(dir.path().join("build.gradle.kts")).unwrap();

        let profile = detect_project_profile(dir.path());
        assert!(profile.languages.contains(&Language::Kotlin));
    }

    #[test]
    fn test_detect_polyglot_monorepo_profile() {
        let dir = TempDir::new().unwrap();

        fs::create_dir_all(dir.path().join("apps/web")).unwrap();
        fs::create_dir_all(dir.path().join("crates/core/src")).unwrap();
        fs::create_dir_all(dir.path().join("services/api")).unwrap();

        File::create(dir.path().join("apps/web/package.json")).unwrap();
        File::create(dir.path().join("crates/core/Cargo.toml")).unwrap();
        File::create(dir.path().join("services/api/pyproject.toml")).unwrap();

        let profile = detect_project_profile(dir.path());

        assert!(profile.is_polyglot());
        assert!(profile.languages.contains(&Language::TypeScript));
        assert!(profile.languages.contains(&Language::Rust));
        assert!(profile.languages.contains(&Language::Python));
        assert_eq!(profile.projects.len(), 3);
    }

    #[test]
    fn test_detect_auxiliary_targets_for_infra_and_templates() {
        let dir = TempDir::new().unwrap();

        fs::create_dir_all(dir.path().join("infra")).unwrap();
        fs::create_dir_all(dir.path().join(".github/workflows")).unwrap();
        fs::create_dir_all(dir.path().join("views")).unwrap();
        fs::create_dir_all(dir.path().join("containers")).unwrap();
        fs::write(
            dir.path().join("infra/main.tf"),
            "resource \"null_resource\" \"x\" {}\n",
        )
        .unwrap();
        fs::write(
            dir.path().join(".github/workflows/ci.yml"),
            "name: CI\non: [push]\n",
        )
        .unwrap();
        fs::write(dir.path().join("views/home.jsp"), "<html></html>").unwrap();
        fs::write(dir.path().join("appsettings.json"), "{}").unwrap();
        fs::write(
            dir.path().join("containers/Dockerfile"),
            "FROM alpine:3.20\n",
        )
        .unwrap();

        let profile = detect_project_profile(dir.path());
        let target_keys = profile.target_keys();

        assert!(target_keys.contains(&"terraform".to_string()));
        assert!(target_keys.contains(&"github-actions".to_string()));
        assert!(target_keys.contains(&"jsp".to_string()));
        assert!(target_keys.contains(&"json".to_string()));
        assert!(target_keys.contains(&"dockerfile".to_string()));
        assert!(profile.supported_file_names().contains(&"dockerfile"));
    }

    #[test]
    fn test_detect_nested_project_beyond_old_depth_limit() {
        let dir = TempDir::new().unwrap();
        let nested = dir.path().join("services/backend/api");
        fs::create_dir_all(&nested).unwrap();
        File::create(nested.join("go.mod")).unwrap();

        let profile = detect_project_profile(dir.path());
        assert!(profile.languages.contains(&Language::Go));
        assert_eq!(profile.projects.len(), 1);
    }

    #[test]
    fn test_suggest_build_targets_for_polyglot_monorepo() {
        let dir = TempDir::new().unwrap();

        fs::create_dir_all(dir.path().join("apps/web")).unwrap();
        fs::create_dir_all(dir.path().join("crates/core")).unwrap();

        File::create(dir.path().join("apps/web/package.json")).unwrap();
        File::create(dir.path().join("crates/core/Cargo.toml")).unwrap();

        let profile = detect_project_profile(dir.path());
        let targets = suggest_build_targets(dir.path(), &profile);

        assert_eq!(targets.len(), 2);
        assert!(targets.iter().any(|target| {
            target.language == Language::TypeScript
                && target.command.contains("npm run build --prefix apps/web")
        }));
        assert!(targets.iter().any(|target| {
            target.language == Language::Rust
                && target.command.contains("cargo build --manifest-path")
        }));
    }

    #[test]
    fn test_detect_unknown() {
        let dir = TempDir::new().unwrap();
        File::create(dir.path().join("readme.txt")).unwrap();

        let lang = detect_language(dir.path());
        assert!(matches!(lang, Language::Unknown));
    }

    #[test]
    fn test_detect_shell_scripts_as_language_target() {
        let dir = TempDir::new().unwrap();
        fs::write(
            dir.path().join("deploy.sh"),
            "#!/usr/bin/env bash\neval \"$INPUT\"\n",
        )
        .unwrap();

        let profile = detect_project_profile(dir.path());

        assert!(profile.languages.contains(&Language::Shell));
        assert!(profile.supported_extensions().contains(&".sh"));
        assert_eq!(detect_language(dir.path()), Language::Shell);
    }
}
