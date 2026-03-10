//! `scrutin-analysis` — Static code analysis engine.
//!
//! Powers [Scrutin](https://scrutin.dev) and
//! [scrutin-community](https://github.com/codigocentral/scrutin-community).
//!
//! ## Quick start
//!
//! ```rust,no_run
//! use scrutin_analysis::{AnalysisEngine, AnalysisOptions, FileContent};
//!
//! let engine = AnalysisEngine::load().unwrap();
//! let files = vec![FileContent::new("src/main.rs", "fn main() { let x = 1; }")];
//! let options = AnalysisOptions::default();
//! let issues = engine.analyze_files(&files, &options);
//! println!("Found {} issues", issues.len());
//! ```

pub mod auto_fix;
pub mod chunker;
pub mod detect;
pub mod diff_parser;
pub mod engine;
pub mod error;
pub mod iac_engine;
pub mod metrics;
pub mod models;
pub mod rules;
pub mod secret;

// Public API re-exports
pub use engine::{AnalysisEngine, AnalysisOptions, IssueSeverity};
pub use error::{AnalysisError, Result};
pub use iac_engine::{IacEngine, IacScanOptions};
pub use metrics::FileContent;
pub use models::{AnalysisIssue, AutoFixSuggestion, JobConfig};
