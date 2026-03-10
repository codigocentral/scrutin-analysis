//! Secret Detection Engine
//!
//! Módulo para detecção de credenciais, tokens e segredos vazados no código-fonte.
//!
//! # Features
//! - 200+ padrões regex (baseado no Gitleaks + extensões)
//! - Entropy-based detection para tokens aleatórios
//! - Allowlist para redução de falsos positivos
//! - Masking automático de valores sensíveis
//! - Parser para regras Gitleaks (TOML/JSON)
//! - Integração com AnalysisEngine
//!
//! # Arquitetura
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                    SecretEngine                             │
//! ├─────────────────────────────────────────────────────────────┤
//! │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
//! │  │   Parser     │  │   Engine     │  │  Allowlist   │      │
//! │  │  (TOML/JSON) │  │ (Regex+Entropy)│  │ (Filtros)   │      │
//! │  └──────────────┘  └──────────────┘  └──────────────┘      │
//! ├─────────────────────────────────────────────────────────────┤
//! │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
//! │  │   Patterns   │  │   Entropy    │  │    Mask      │      │
//! │  │  (~200 rules)│  │ (Shannon)    │  │ (Ocultação)  │      │
//! │  └──────────────┘  └──────────────┘  └──────────────┘      │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Uso Rápido
//!
//! ```rust,ignore
//! use scrutin_agent::secrets::{SecretEngine, SecretScanOptions};
//!
//! // Carrega engine com regras embarcadas (~200 regras)
//! let engine = SecretEngine::load()?;
//!
//! // Scan de conteúdo
//! let findings = engine.scan_content(
//!     "config.js",
//!     "const apiKey = 'AKIAIOSFODNN7EXAMPLE';",
//!     &SecretScanOptions::default()
//! );
//!
//! for finding in findings {
//!     println!("{}: {}", finding.rule_id, finding.masked_text);
//! }
//! ```
//!
//! # Providers Suportados
//!
//! ## Cloud Providers
//! - **AWS**: Access Key ID, Secret Key, MWS Key, Cognito Pool, S3 Bucket, SES SMTP
//! - **GCP**: API Key, OAuth Token, Firebase Key, Service Account
//! - **Azure**: Storage Key, AD Secret, Connection String, SAS Token
//!
//! ## Version Control
//! - **GitHub**: PAT, OAuth, App Token, Fine-grained PAT, Refresh Token
//! - **GitLab**: PAT, Runner Token, Deploy Token
//!
//! ## Communication
//! - **Slack**: Bot Token, Webhook, App Token, User Token
//! - **Discord**: Bot Token, Webhook
//! - **Telegram**: Bot Token
//!
//! ## Payment
//! - **Stripe**: Secret Key, Test Key, Restricted Key, Webhook Secret
//! - **Square**: Access Token, Application Secret
//!
//! ## AI/ML
//! - **OpenAI**: API Key, Project Key
//! - **Anthropic**: API Key
//! - **HuggingFace**: Token
//! - **DeepSeek**: API Key
//! - **Perplexity**: API Key
//! - **Groq**: API Key
//! - **Mistral**: API Key
//! - **Together AI**: API Key
//!
//! ## Database
//! - PostgreSQL, MySQL, MongoDB, Redis, MSSQL connection strings
//!
//! ## Cryptography
//! - RSA Private Key, EC Private Key, OpenSSH Private Key, PGP Private Key
//! - JWT Tokens
//!
//! ## Generic
//! - Generic API Keys, Secrets, Passwords hardcoded
//! - Bearer Tokens, Basic Auth
//!
//! # Formatos de Regras
//!
//! ## TOML (Gitleaks)
//! ```toml
//! [[rules]]
//! id = "aws-access-key-id"
//! description = "AWS Access Key ID"
//! regex = '''(A3T[A-Z0-9]|AKIA)[A-Z0-9]{16}'''
//! keywords = ["AKIA"]
//! tags = ["aws", "credentials"]
//!
//! [rules.allowlist]
//! regexes = ["EXAMPLE123"]
//! ```
//!
//! ## JSON (Interno)
//! ```json
//! {
//!   "rule_id": "SEC-AWS-001",
//!   "title": "AWS Access Key ID Detected",
//!   "severity": "critical",
//!   "patterns": ["AKIA[0-9A-Z]{16}"],
//!   "provider": "aws",
//!   "keywords": ["AKIA"]
//! }
//! ```
//!
//! # Sistema de Allowlist
//!
//! O engine implementa múltiplas camadas de allowlist:
//!
//! 1. **Global**: Placeholders comuns (EXAMPLE, test, DUMMY, etc.)
//! 2. **Por Regra**: Padrões específicos definidos na regra
//! 3. **Por Path**: Arquivos e diretórios ignorados
//!
//! # Entropy Detection
//!
//! Usa entropia de Shannon para detectar strings aleatórias:
//!
//! ```rust,ignore
//! use scrutin_agent::secrets::{calculate_entropy, has_high_entropy};
//!
//! let entropy = calculate_entropy("AKIAIOSFODNN7EXAMPLE1234");
//! assert!(entropy > 4.0); // Alta entropia = possível token
//! ```
//!
//! Thresholds típicos:
//! - Base64: 5.5
//! - Hex: 3.9
//! - Generic tokens: 4.0-4.8
//!
//! # Mascaramento
//!
//! Secrets são mascarados automaticamente para segurança:
//!
//! ```rust,ignore
//! use scrutin_agent::secrets::mask_secret;
//!
//! let masked = mask_secret("AKIAIOSFODNN7EXAMPLE");
//! assert_eq!(masked, "AKIA****MPLE");
//! ```
//!
//! # Integração com AnalysisEngine
//!
//! O SecretEngine está integrado ao AnalysisEngine para scan automático:
//!
//! ```rust,ignore
//! use scrutin_agent::analysis::{AnalysisEngine, AnalysisOptions};
//!
//! let engine = AnalysisEngine::load()?;
//! let options = AnalysisOptions {
//!     secret_detection_enabled: true,
//!     ..Default::default()
//! };
//!
//! let issues = engine.analyze_diff_with_options(diff, &options);
//! ```
//!
//! # Download de Regras
//!
//! Use o script fornecido para baixar regras atualizadas do Gitleaks:
//!
//! ```bash
//! # Download da versão mais recente
//! ./scripts/download-gitleaks-rules.sh
//!
//! # Download de versão específica
//! ./scripts/download-gitleaks-rules.sh -v v8.18.2
//! ```
//!
//! # Referências
//!
//! - [Gitleaks](https://github.com/gitleaks/gitleaks)
//! - [Shannon Entropy](https://shannonentropy.netmark.pl/)
//! - [OWASP Secrets Management](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)

mod allowlist;
mod engine;
mod entropy;
mod mask;
mod parser;
mod patterns;

pub use allowlist::{
    contains_path_traversal, get_global_allowlist, get_ignore_path_patterns, is_allowlisted,
    is_global_ignored_path, is_repetitive, looks_like_placeholder, should_ignore_path,
};
pub use engine::{
    SecretEngine, SecretEngineConfig, SecretEngineStats, SecretFinding, SecretRotationHelper,
    SecretRotationInfo, SecretScanOptions, SecretSeverity,
};
pub use entropy::{
    calculate_entropy, detect_high_entropy_base64, detect_high_entropy_hex,
    detect_high_entropy_tokens, has_high_entropy,
};
pub use mask::mask_secret;
pub use parser::{GitleaksConfig, GitleaksParser, GitleaksRule};
pub use patterns::SecretRule;

