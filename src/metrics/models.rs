//! Data models for code metrics
//!
//! Contains all structs used by the metrics engine for representing
//! code quality measurements.

use serde::{Deserialize, Serialize};

use crate::detect::Language;

/// Category of PR size based on total lines changed
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, Default)]
#[serde(rename_all = "UPPERCASE")]
pub enum PrSizeCategory {
    #[default]
    Xs,
    Small,
    Medium,
    Large,
    Xl,
}

impl PrSizeCategory {
    pub fn from_lines(total_lines: usize) -> Self {
        match total_lines {
            0..=50 => PrSizeCategory::Xs,
            51..=200 => PrSizeCategory::Small,
            201..=400 => PrSizeCategory::Medium,
            401..=1000 => PrSizeCategory::Large,
            _ => PrSizeCategory::Xl,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            PrSizeCategory::Xs => "XS",
            PrSizeCategory::Small => "Small",
            PrSizeCategory::Medium => "Medium",
            PrSizeCategory::Large => "Large",
            PrSizeCategory::Xl => "XL",
        }
    }
}

/// Alert level for metric thresholds
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MetricAlertLevel {
    Info,
    Warning,
    Error,
}

/// Complete metrics for an analysis
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct CodeMetrics {
    pub total_lines_added: usize,
    pub total_lines_removed: usize,
    pub total_files_changed: usize,
    pub pr_size_category: PrSizeCategory,

    pub max_cyclomatic_complexity: Option<u32>,
    pub avg_cyclomatic_complexity: Option<f64>,
    pub max_cognitive_complexity: Option<u32>,
    pub avg_cognitive_complexity: Option<f64>,
    pub max_function_length: Option<u32>,
    pub avg_function_length: Option<f64>,
    pub max_file_length: Option<u32>,
    pub avg_file_length: Option<f64>,
    pub max_nesting_depth: Option<u32>,
    pub duplication_percentage: f64,

    pub file_metrics: Vec<FileMetrics>,
    pub duplications: Vec<DuplicationGroup>,
    pub alerts: Vec<MetricAlert>,
}

/// Metrics for a single file
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileMetrics {
    pub file_path: String,
    pub language: String,
    pub lines: usize,
    pub loc: LocMetrics,
    pub functions: Vec<FunctionMetrics>,
    pub average_complexity: f64,
    pub duplication_percentage: f64,
}

/// Metrics for a single function/method
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FunctionMetrics {
    pub name: String,
    pub line_start: u32,
    pub line_end: u32,
    pub length: u32,
    pub cyclomatic_complexity: u32,
    pub cognitive_complexity: u32,
    pub max_nesting_depth: u32,
    pub parameter_count: u32,
    pub halstead: Option<HalsteadMetrics>,
}

/// Halstead complexity metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HalsteadMetrics {
    pub operators: usize,
    pub operands: usize,
    pub unique_operators: usize,
    pub unique_operands: usize,
    pub vocabulary: usize,
    pub length: usize,
    pub volume: f64,
    pub difficulty: f64,
    pub effort: f64,
    pub time_minutes: f64,
    pub bugs_estimate: f64,
}

impl HalsteadMetrics {
    pub fn new(
        operators: usize,
        operands: usize,
        unique_operators: usize,
        unique_operands: usize,
    ) -> Self {
        let vocabulary = unique_operators + unique_operands;
        let length = operators + operands;

        let volume = if vocabulary > 0 {
            (length as f64) * (vocabulary as f64).log2()
        } else {
            0.0
        };

        let difficulty = if unique_operands > 0 {
            (unique_operators as f64 / 2.0) * (operands as f64 / unique_operands as f64)
        } else {
            0.0
        };

        let effort = volume * difficulty;
        let time_minutes = effort / 18.0;
        let bugs_estimate = volume / 3000.0;

        Self {
            operators,
            operands,
            unique_operators,
            unique_operands,
            vocabulary,
            length,
            volume,
            difficulty,
            effort,
            time_minutes,
            bugs_estimate,
        }
    }
}

/// Lines of code metrics
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct LocMetrics {
    pub total_lines: usize,
    pub code_lines: usize,
    pub comment_lines: usize,
    pub blank_lines: usize,
}

/// A detected function span in source code
#[derive(Debug, Clone)]
pub struct FunctionSpan {
    pub name: String,
    pub start_line: usize,
    pub end_line: usize,
    pub body: String,
    pub parameters: Vec<String>,
}

/// Group of duplicated code blocks
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DuplicationGroup {
    pub hash: String,
    pub token_count: usize,
    pub line_count: usize,
    pub instances: Vec<DuplicationInstance>,
}

/// A single instance of duplicated code
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DuplicationInstance {
    pub file_path: String,
    pub line_start: usize,
    pub line_end: usize,
    pub content_preview: String,
}

/// Metric threshold alert
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MetricAlert {
    pub metric_type: String,
    pub level: MetricAlertLevel,
    pub file_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub function_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line_number: Option<u32>,
    pub current_value: u32,
    pub threshold: u32,
    pub message: String,
}

/// Configuration for metric thresholds
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MetricsThresholds {
    pub pr_size_warning: usize,
    pub pr_size_error: usize,
    pub files_changed_warning: usize,
    pub files_changed_error: usize,
    pub cyclomatic_warning: u32,
    pub cyclomatic_error: u32,
    pub cognitive_warning: u32,
    pub cognitive_error: u32,
    pub function_length_warning: u32,
    pub function_length_error: u32,
    pub file_length_warning: u32,
    pub file_length_error: u32,
    pub nesting_depth_warning: u32,
    pub nesting_depth_error: u32,
    pub duplication_warning: f64,
    pub duplication_error: f64,
}

impl Default for MetricsThresholds {
    fn default() -> Self {
        Self {
            pr_size_warning: 400,
            pr_size_error: 1000,
            files_changed_warning: 10,
            files_changed_error: 20,
            cyclomatic_warning: 10,
            cyclomatic_error: 20,
            cognitive_warning: 15,
            cognitive_error: 25,
            function_length_warning: 50,
            function_length_error: 100,
            file_length_warning: 300,
            file_length_error: 500,
            nesting_depth_warning: 4,
            nesting_depth_error: 6,
            duplication_warning: 5.0,
            duplication_error: 10.0,
        }
    }
}

/// Language-specific complexity thresholds
#[derive(Debug, Clone)]
pub struct LanguageThresholds {
    pub language: Language,
    pub cyclomatic_base: u32,
    pub cognitive_base: u32,
    pub function_length_base: u32,
}

impl LanguageThresholds {
    pub fn for_language(language: Language) -> Self {
        match language {
            Language::Rust => Self {
                language,
                cyclomatic_base: 10,
                cognitive_base: 15,
                function_length_base: 50,
            },
            Language::Go => Self {
                language,
                cyclomatic_base: 15,
                cognitive_base: 20,
                function_length_base: 60,
            },
            Language::Python => Self {
                language,
                cyclomatic_base: 10,
                cognitive_base: 15,
                function_length_base: 40,
            },
            Language::Java => Self {
                language,
                cyclomatic_base: 10,
                cognitive_base: 15,
                function_length_base: 50,
            },
            Language::Dotnet => Self {
                language,
                cyclomatic_base: 10,
                cognitive_base: 15,
                function_length_base: 50,
            },
            Language::TypeScript => Self {
                language,
                cyclomatic_base: 10,
                cognitive_base: 15,
                function_length_base: 40,
            },
            _ => Self {
                language,
                cyclomatic_base: 10,
                cognitive_base: 15,
                function_length_base: 50,
            },
        }
    }
}

/// Content of a file for analysis
#[derive(Debug, Clone)]
pub struct FileContent {
    pub path: String,
    pub content: String,
}

impl FileContent {
    pub fn new(path: impl Into<String>, content: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            content: content.into(),
        }
    }

    pub fn lines(&self) -> Vec<&str> {
        self.content.lines().collect()
    }
}
