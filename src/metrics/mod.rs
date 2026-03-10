//! Code Metrics Engine
//!
//! This module provides comprehensive code quality metrics including:
//! - Cyclomatic Complexity (McCabe)
//! - Cognitive Complexity (SonarQube method)
//! - Code Duplication Detection
//! - Halstead Complexity Metrics
//! - Lines of Code (LOC)
//!
//! # Example
//!
//! ```rust,ignore
//! use scrutin_agent::metrics::{MetricsEngine, FileContent, MetricsThresholds};
//!
//! let engine = MetricsEngine::with_defaults();
//! let files = vec![FileContent::new("main.rs", "fn main() { println!(\"Hello\"); }")];
//! let metrics = engine.calculate_metrics(&files, 50, 10);
//!
//! println!("Cyclomatic: {:?}", metrics.max_cyclomatic_complexity);
//! println!("Duplication: {:.1}%", metrics.duplication_percentage);
//! ```

pub mod complexity;
pub mod duplication;
pub mod engine;
pub mod halstead;
pub mod languages;
pub mod loc;
pub mod models;

pub use complexity::{
    calculate_cognitive_complexity, calculate_complexity, calculate_cyclomatic_complexity,
    ComplexityResult,
};
pub use duplication::{DuplicationConfig, DuplicationDetector};
pub use engine::MetricsEngine;
pub use halstead::HalsteadCalculator;
pub use languages::{detect_language_from_path, get_parser, FunctionParser};
pub use loc::LocCounter;
pub use models::*;
