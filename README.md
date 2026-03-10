# scrutin-analysis

> Static code analysis engine — 900+ rules, 10+ languages, zero dependencies on cloud or AI.

Powers [Scrutin](https://scrutin.dev) and [scrutin-community](https://github.com/codigocentral/scrutin-community).

```toml
[dependencies]
scrutin-analysis = { git = "https://github.com/codigocentral/scrutin-analysis" }
```

---

## What it does

- **900+ rules** — SonarQube rule set (bugs, vulnerabilities, code smells)
- **OWASP/CWE security rules** — mapped to OWASP Top 10, CWE, NIST SSDF
- **10+ languages** — C#, TypeScript/JavaScript, Python, Go, Java, Rust, PHP, Kotlin, Ruby, C++
- **IaC scanning** — Dockerfile, Kubernetes, Terraform, GitHub Actions, GitLab CI
- **Secret detection** — 100+ patterns (API keys, tokens, credentials)
- **Code metrics** — cyclomatic complexity, Halstead, duplication, LOC
- **Auto-fix suggestions** — pattern-based fix hints for common issues
- **Fully offline** — no API calls, no account, embeds all rule files at compile time

---

## Quick start

```rust
use scrutin_analysis::{AnalysisEngine, AnalysisOptions, FileContent};

fn main() {
    let engine = AnalysisEngine::load().unwrap();

    let files = vec![
        FileContent::new("src/main.rs", std::fs::read_to_string("src/main.rs").unwrap()),
    ];

    let options = AnalysisOptions::default();
    let issues = engine.analyze_files(&files, &options);

    for issue in &issues {
        println!("[{}] {} — {}", issue.severity, issue.rule_id, issue.message);
    }
}
```

---

## Scanning a directory

```rust
use scrutin_analysis::{AnalysisEngine, AnalysisOptions};
use std::path::Path;

let engine = AnalysisEngine::load().unwrap();
let options = AnalysisOptions::default();
let issues = engine.analyze_path(Path::new("."), &options).unwrap();

println!("Found {} issues", issues.len());
```

---

## IaC scanning

```rust
use scrutin_analysis::{IacEngine, IacScanOptions};

let engine = IacEngine::load().unwrap();
let options = IacScanOptions::default();

let content = std::fs::read_to_string("Dockerfile").unwrap();
let issues = engine.scan_file("Dockerfile", &content, &options);

for issue in &issues {
    println!("Line {}: [{}] {}", issue.line, issue.rule_id, issue.message);
}
```

---

## Secret detection

```rust
use scrutin_analysis::secret::{SecretEngine, SecretScanOptions};

let engine = SecretEngine::load().unwrap();
let options = SecretScanOptions::default();

let content = std::fs::read_to_string("config.py").unwrap();
let findings = engine.scan_file("config.py", &content, &options);

for f in &findings {
    println!("Secret found: {} ({})", f.rule_id, f.message);
}
```

---

## Language detection

```rust
use scrutin_analysis::detect::detect_language;

let language = detect_language(std::path::Path::new("."));
println!("Detected: {:?}", language);
```

---

## Modules

| Module | Description |
|--------|-------------|
| `engine` | Main analysis engine — SAST rules, secrets, metrics |
| `iac_engine` | IaC scanner (Dockerfile, K8s, Terraform, CI/CD) |
| `rules` | Rule loader — AllRules, DetectionPatterns, OWASP/CWE |
| `secret` | Secret detection engine (gitleaks-compatible) |
| `metrics` | Code metrics (complexity, duplication, LOC) |
| `detect` | Language and project type detection |
| `auto_fix` | Auto-fix suggestion generator |
| `diff_parser` | Unified diff parser for PR analysis |

---

## Rule files

All rules are embedded at compile time via `include_str!()`:

| File | Contents |
|------|----------|
| `AllRules.json` | 927+ SonarQube rules with metadata |
| `DetectionPatterns.json` | Regex patterns by language and category |
| `CodeAnalysisRules.json` | OWASP/CWE security rules |
| `LanguagePrompts.json` | Language extensions and file name mappings |
| `AutoFixPatterns.json` | Find/replace auto-fix patterns |

---

## Supported languages

C#, TypeScript, JavaScript, Python, Go, Java, Rust, PHP, Kotlin, Ruby, C++

IaC: Dockerfile, Docker Compose, Kubernetes, Terraform, GitHub Actions, GitLab CI, Azure Pipelines

---

## License

MIT — see [LICENSE](LICENSE)

---

Built by [Código Central](https://github.com/codigocentral) · Used in [scrutin-community](https://github.com/codigocentral/scrutin-community) and [Scrutin](https://scrutin.dev)
