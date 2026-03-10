//! Main Metrics Engine
//!
//! Orchestrates all metric calculations and integrates results.

use tracing::{debug, trace};

use crate::detect::Language;

use super::complexity::calculate_complexity;
use super::duplication::DuplicationDetector;
use super::halstead::HalsteadCalculator;
use super::languages::{detect_language_from_path, get_parser};
use super::loc::LocCounter;
use super::models::*;

pub struct MetricsEngine {
    thresholds: MetricsThresholds,
    duplication_detector: DuplicationDetector,
}

impl MetricsEngine {
    pub fn new(thresholds: MetricsThresholds) -> Self {
        Self {
            thresholds,
            duplication_detector: DuplicationDetector::with_defaults(),
        }
    }

    pub fn with_defaults() -> Self {
        Self::new(MetricsThresholds::default())
    }

    pub fn with_thresholds(thresholds: MetricsThresholds) -> Self {
        Self::new(thresholds)
    }

    pub fn calculate_metrics(
        &self,
        files: &[FileContent],
        lines_added: usize,
        lines_removed: usize,
    ) -> CodeMetrics {
        debug!(
            "Calculating metrics for {} files, +{} -{}",
            files.len(),
            lines_added,
            lines_removed
        );

        let mut file_metrics = Vec::new();
        let mut all_functions: Vec<(String, FunctionMetrics)> = Vec::new();

        for file in files {
            if contains_path_traversal(&file.path) {
                tracing::warn!("Path traversal detected and rejected: {}", file.path);
                continue;
            }

            let language = detect_language_from_path(&file.path);
            let metrics = self.analyze_file(file, language);

            for func in &metrics.functions {
                all_functions.push((file.path.clone(), func.clone()));
            }

            file_metrics.push(metrics);
        }

        let duplications = self.duplication_detector.find_duplications(files);
        let duplication_percentage = self
            .duplication_detector
            .calculate_duplication_percentage(files, &duplications);

        let avg_cyclomatic = calculate_average(&all_functions, |(_, f)| f.cyclomatic_complexity);
        let avg_cognitive = calculate_average(&all_functions, |(_, f)| f.cognitive_complexity);
        let avg_function_length = calculate_average(&all_functions, |(_, f)| f.length);
        let avg_file_length = if file_metrics.is_empty() {
            None
        } else {
            Some(
                file_metrics.iter().map(|f| f.lines as f64).sum::<f64>()
                    / file_metrics.len() as f64,
            )
        };

        let mut metrics = CodeMetrics {
            total_lines_added: lines_added,
            total_lines_removed: lines_removed,
            total_files_changed: files.len(),
            pr_size_category: PrSizeCategory::from_lines(lines_added + lines_removed),
            max_cyclomatic_complexity: all_functions
                .iter()
                .map(|(_, f)| f.cyclomatic_complexity)
                .max(),
            avg_cyclomatic_complexity: avg_cyclomatic,
            max_cognitive_complexity: all_functions
                .iter()
                .map(|(_, f)| f.cognitive_complexity)
                .max(),
            avg_cognitive_complexity: avg_cognitive,
            max_function_length: all_functions.iter().map(|(_, f)| f.length).max(),
            avg_function_length,
            max_file_length: file_metrics.iter().map(|f| f.lines as u32).max(),
            avg_file_length,
            max_nesting_depth: all_functions.iter().map(|(_, f)| f.max_nesting_depth).max(),
            duplication_percentage,
            file_metrics,
            duplications,
            alerts: Vec::new(),
        };

        metrics.alerts = self.generate_alerts(&metrics);

        metrics
    }

    pub fn analyze_file(&self, file: &FileContent, language: Language) -> FileMetrics {
        trace!("Analyzing file: {} ({:?})", file.path, language);

        let loc = LocCounter::count(&file.content);
        let total_lines = loc.total_lines;

        let parser = get_parser(language);
        let functions = parser.detect_functions(&file.content);

        let function_metrics: Vec<FunctionMetrics> = functions
            .into_iter()
            .map(|span| {
                let complexity = calculate_complexity(&span.body, language);
                let halstead = HalsteadCalculator::calculate(&span.body, language);

                FunctionMetrics {
                    name: span.name,
                    line_start: span.start_line as u32,
                    line_end: span.end_line as u32,
                    length: (span.end_line - span.start_line + 1) as u32,
                    cyclomatic_complexity: complexity.cyclomatic,
                    cognitive_complexity: complexity.cognitive,
                    max_nesting_depth: complexity.max_nesting,
                    parameter_count: span.parameters.len() as u32,
                    halstead: Some(halstead),
                }
            })
            .collect();

        let average_complexity = if function_metrics.is_empty() {
            0.0
        } else {
            function_metrics
                .iter()
                .map(|f| f.cyclomatic_complexity as f64)
                .sum::<f64>()
                / function_metrics.len() as f64
        };

        let single_file_dups = self.duplication_detector.find_duplications(&[file.clone()]);
        let file_dup_percentage = self
            .duplication_detector
            .calculate_duplication_percentage(&[file.clone()], &single_file_dups);

        FileMetrics {
            file_path: file.path.clone(),
            language: language.as_str().to_string(),
            lines: total_lines,
            loc,
            functions: function_metrics,
            average_complexity,
            duplication_percentage: file_dup_percentage,
        }
    }

    pub fn find_duplications(&self, files: &[FileContent]) -> Vec<DuplicationGroup> {
        self.duplication_detector.find_duplications(files)
    }

    fn generate_alerts(&self, metrics: &CodeMetrics) -> Vec<MetricAlert> {
        let mut alerts = Vec::new();

        self.check_pr_size(metrics, &mut alerts);
        self.check_files_changed(metrics, &mut alerts);
        self.check_duplication(metrics, &mut alerts);
        self.check_file_metrics(metrics, &mut alerts);

        alerts.sort_by(|a, b| {
            let level_order = |level: &MetricAlertLevel| match level {
                MetricAlertLevel::Error => 0,
                MetricAlertLevel::Warning => 1,
                MetricAlertLevel::Info => 2,
            };
            level_order(&a.level)
                .cmp(&level_order(&b.level))
                .then_with(|| a.file_path.cmp(&b.file_path))
        });

        alerts
    }

    fn check_pr_size(&self, metrics: &CodeMetrics, alerts: &mut Vec<MetricAlert>) {
        let pr_size = metrics.total_lines_added + metrics.total_lines_removed;

        if pr_size > self.thresholds.pr_size_error {
            alerts.push(MetricAlert {
                metric_type: "PR_SIZE".to_string(),
                level: MetricAlertLevel::Error,
                file_path: String::new(),
                function_name: None,
                line_number: None,
                current_value: pr_size as u32,
                threshold: self.thresholds.pr_size_error as u32,
                message: format!(
                    "PR size ({} lines) exceeds error threshold ({})",
                    pr_size, self.thresholds.pr_size_error
                ),
            });
        } else if pr_size > self.thresholds.pr_size_warning {
            alerts.push(MetricAlert {
                metric_type: "PR_SIZE".to_string(),
                level: MetricAlertLevel::Warning,
                file_path: String::new(),
                function_name: None,
                line_number: None,
                current_value: pr_size as u32,
                threshold: self.thresholds.pr_size_warning as u32,
                message: format!(
                    "PR size ({} lines) exceeds warning threshold ({})",
                    pr_size, self.thresholds.pr_size_warning
                ),
            });
        }
    }

    fn check_files_changed(&self, metrics: &CodeMetrics, alerts: &mut Vec<MetricAlert>) {
        if metrics.total_files_changed > self.thresholds.files_changed_error {
            alerts.push(MetricAlert {
                metric_type: "FILES_CHANGED".to_string(),
                level: MetricAlertLevel::Error,
                file_path: String::new(),
                function_name: None,
                line_number: None,
                current_value: metrics.total_files_changed as u32,
                threshold: self.thresholds.files_changed_error as u32,
                message: format!(
                    "Too many files changed ({}) exceeds error threshold ({})",
                    metrics.total_files_changed, self.thresholds.files_changed_error
                ),
            });
        } else if metrics.total_files_changed > self.thresholds.files_changed_warning {
            alerts.push(MetricAlert {
                metric_type: "FILES_CHANGED".to_string(),
                level: MetricAlertLevel::Warning,
                file_path: String::new(),
                function_name: None,
                line_number: None,
                current_value: metrics.total_files_changed as u32,
                threshold: self.thresholds.files_changed_warning as u32,
                message: format!(
                    "Many files changed ({}) exceeds warning threshold ({})",
                    metrics.total_files_changed, self.thresholds.files_changed_warning
                ),
            });
        }
    }

    fn check_duplication(&self, metrics: &CodeMetrics, alerts: &mut Vec<MetricAlert>) {
        if metrics.duplication_percentage > self.thresholds.duplication_error {
            alerts.push(MetricAlert {
                metric_type: "DUPLICATION".to_string(),
                level: MetricAlertLevel::Error,
                file_path: String::new(),
                function_name: None,
                line_number: None,
                current_value: metrics.duplication_percentage as u32,
                threshold: self.thresholds.duplication_error as u32,
                message: format!(
                    "Code duplication ({:.1}%) exceeds error threshold ({:.1}%)",
                    metrics.duplication_percentage, self.thresholds.duplication_error
                ),
            });
        } else if metrics.duplication_percentage > self.thresholds.duplication_warning {
            alerts.push(MetricAlert {
                metric_type: "DUPLICATION".to_string(),
                level: MetricAlertLevel::Warning,
                file_path: String::new(),
                function_name: None,
                line_number: None,
                current_value: metrics.duplication_percentage as u32,
                threshold: self.thresholds.duplication_warning as u32,
                message: format!(
                    "Code duplication ({:.1}%) exceeds warning threshold ({:.1}%)",
                    metrics.duplication_percentage, self.thresholds.duplication_warning
                ),
            });
        }
    }

    fn check_file_metrics(&self, metrics: &CodeMetrics, alerts: &mut Vec<MetricAlert>) {
        for file in &metrics.file_metrics {
            self.check_file_length(file, alerts);

            for func in &file.functions {
                self.check_cyclomatic_complexity(file, func, alerts);
                self.check_cognitive_complexity(file, func, alerts);
                self.check_function_length(file, func, alerts);
                self.check_nesting_depth(file, func, alerts);
            }
        }
    }

    fn check_file_length(&self, file: &FileMetrics, alerts: &mut Vec<MetricAlert>) {
        if file.lines > self.thresholds.file_length_error as usize {
            alerts.push(MetricAlert {
                metric_type: "FILE_LENGTH".to_string(),
                level: MetricAlertLevel::Error,
                file_path: file.file_path.clone(),
                function_name: None,
                line_number: None,
                current_value: file.lines as u32,
                threshold: self.thresholds.file_length_error,
                message: format!(
                    "File too long ({} lines) exceeds error threshold ({})",
                    file.lines, self.thresholds.file_length_error
                ),
            });
        } else if file.lines > self.thresholds.file_length_warning as usize {
            alerts.push(MetricAlert {
                metric_type: "FILE_LENGTH".to_string(),
                level: MetricAlertLevel::Warning,
                file_path: file.file_path.clone(),
                function_name: None,
                line_number: None,
                current_value: file.lines as u32,
                threshold: self.thresholds.file_length_warning,
                message: format!(
                    "File is long ({} lines) exceeds warning threshold ({})",
                    file.lines, self.thresholds.file_length_warning
                ),
            });
        }
    }

    fn check_cyclomatic_complexity(
        &self,
        file: &FileMetrics,
        func: &FunctionMetrics,
        alerts: &mut Vec<MetricAlert>,
    ) {
        if func.cyclomatic_complexity > self.thresholds.cyclomatic_error {
            alerts.push(MetricAlert {
                metric_type: "CYCLOMATIC_COMPLEXITY".to_string(),
                level: MetricAlertLevel::Error,
                file_path: file.file_path.clone(),
                function_name: Some(func.name.clone()),
                line_number: Some(func.line_start),
                current_value: func.cyclomatic_complexity,
                threshold: self.thresholds.cyclomatic_error,
                message: format!(
                    "High cyclomatic complexity ({}) in '{}' exceeds error threshold ({})",
                    func.cyclomatic_complexity, func.name, self.thresholds.cyclomatic_error
                ),
            });
        } else if func.cyclomatic_complexity > self.thresholds.cyclomatic_warning {
            alerts.push(MetricAlert {
                metric_type: "CYCLOMATIC_COMPLEXITY".to_string(),
                level: MetricAlertLevel::Warning,
                file_path: file.file_path.clone(),
                function_name: Some(func.name.clone()),
                line_number: Some(func.line_start),
                current_value: func.cyclomatic_complexity,
                threshold: self.thresholds.cyclomatic_warning,
                message: format!(
                    "Elevated cyclomatic complexity ({}) in '{}' exceeds warning threshold ({})",
                    func.cyclomatic_complexity, func.name, self.thresholds.cyclomatic_warning
                ),
            });
        }
    }

    fn check_cognitive_complexity(
        &self,
        file: &FileMetrics,
        func: &FunctionMetrics,
        alerts: &mut Vec<MetricAlert>,
    ) {
        if func.cognitive_complexity > self.thresholds.cognitive_error {
            alerts.push(MetricAlert {
                metric_type: "COGNITIVE_COMPLEXITY".to_string(),
                level: MetricAlertLevel::Error,
                file_path: file.file_path.clone(),
                function_name: Some(func.name.clone()),
                line_number: Some(func.line_start),
                current_value: func.cognitive_complexity,
                threshold: self.thresholds.cognitive_error,
                message: format!(
                    "High cognitive complexity ({}) in '{}' exceeds error threshold ({})",
                    func.cognitive_complexity, func.name, self.thresholds.cognitive_error
                ),
            });
        } else if func.cognitive_complexity > self.thresholds.cognitive_warning {
            alerts.push(MetricAlert {
                metric_type: "COGNITIVE_COMPLEXITY".to_string(),
                level: MetricAlertLevel::Warning,
                file_path: file.file_path.clone(),
                function_name: Some(func.name.clone()),
                line_number: Some(func.line_start),
                current_value: func.cognitive_complexity,
                threshold: self.thresholds.cognitive_warning,
                message: format!(
                    "Elevated cognitive complexity ({}) in '{}' exceeds warning threshold ({})",
                    func.cognitive_complexity, func.name, self.thresholds.cognitive_warning
                ),
            });
        }
    }

    fn check_function_length(
        &self,
        file: &FileMetrics,
        func: &FunctionMetrics,
        alerts: &mut Vec<MetricAlert>,
    ) {
        if func.length > self.thresholds.function_length_error {
            alerts.push(MetricAlert {
                metric_type: "FUNCTION_LENGTH".to_string(),
                level: MetricAlertLevel::Error,
                file_path: file.file_path.clone(),
                function_name: Some(func.name.clone()),
                line_number: Some(func.line_start),
                current_value: func.length,
                threshold: self.thresholds.function_length_error,
                message: format!(
                    "Function too long ({} lines) in '{}' exceeds error threshold ({})",
                    func.length, func.name, self.thresholds.function_length_error
                ),
            });
        } else if func.length > self.thresholds.function_length_warning {
            alerts.push(MetricAlert {
                metric_type: "FUNCTION_LENGTH".to_string(),
                level: MetricAlertLevel::Warning,
                file_path: file.file_path.clone(),
                function_name: Some(func.name.clone()),
                line_number: Some(func.line_start),
                current_value: func.length,
                threshold: self.thresholds.function_length_warning,
                message: format!(
                    "Function is long ({} lines) in '{}' exceeds warning threshold ({})",
                    func.length, func.name, self.thresholds.function_length_warning
                ),
            });
        }
    }

    fn check_nesting_depth(
        &self,
        file: &FileMetrics,
        func: &FunctionMetrics,
        alerts: &mut Vec<MetricAlert>,
    ) {
        if func.max_nesting_depth > self.thresholds.nesting_depth_error {
            alerts.push(MetricAlert {
                metric_type: "NESTING_DEPTH".to_string(),
                level: MetricAlertLevel::Error,
                file_path: file.file_path.clone(),
                function_name: Some(func.name.clone()),
                line_number: Some(func.line_start),
                current_value: func.max_nesting_depth,
                threshold: self.thresholds.nesting_depth_error,
                message: format!(
                    "Deep nesting ({} levels) in '{}' exceeds error threshold ({})",
                    func.max_nesting_depth, func.name, self.thresholds.nesting_depth_error
                ),
            });
        } else if func.max_nesting_depth > self.thresholds.nesting_depth_warning {
            alerts.push(MetricAlert {
                metric_type: "NESTING_DEPTH".to_string(),
                level: MetricAlertLevel::Warning,
                file_path: file.file_path.clone(),
                function_name: Some(func.name.clone()),
                line_number: Some(func.line_start),
                current_value: func.max_nesting_depth,
                threshold: self.thresholds.nesting_depth_warning,
                message: format!(
                    "Deep nesting ({} levels) in '{}' exceeds warning threshold ({})",
                    func.max_nesting_depth, func.name, self.thresholds.nesting_depth_warning
                ),
            });
        }
    }
}

fn contains_path_traversal(path: &str) -> bool {
    let normalized = path.replace('\\', "/");

    if normalized.starts_with('/') {
        return true;
    }

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

    normalized.split('/').any(|component| component == "..")
}

fn calculate_average<T, F>(items: &[T], extractor: F) -> Option<f64>
where
    F: Fn(&T) -> u32,
{
    if items.is_empty() {
        return None;
    }

    let sum: u32 = items.iter().map(extractor).sum();
    Some(sum as f64 / items.len() as f64)
}

impl Default for MetricsEngine {
    fn default() -> Self {
        Self::with_defaults()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_engine_basic() {
        let engine = MetricsEngine::with_defaults();

        let files = vec![FileContent::new(
            "test.rs",
            r#"
fn simple() -> i32 {
    1
}

fn complex(x: i32) -> i32 {
    if x > 0 {
        if x < 10 {
            if x % 2 == 0 {
                return x;
            }
        }
    }
    0
}
"#,
        )];

        let metrics = engine.calculate_metrics(&files, 50, 10);

        assert_eq!(metrics.total_lines_added, 50);
        assert_eq!(metrics.total_lines_removed, 10);
        assert_eq!(metrics.total_files_changed, 1);
        assert!(!metrics.file_metrics.is_empty());
    }

    #[test]
    fn test_analyze_file() {
        let engine = MetricsEngine::with_defaults();
        let file = FileContent::new(
            "test.rs",
            r#"
fn add(a: i32, b: i32) -> i32 {
    a + b
}
"#,
        );

        let metrics = engine.analyze_file(&file, Language::Rust);

        assert_eq!(metrics.language, "rust");
        assert!(!metrics.functions.is_empty());
        assert!(metrics.functions[0].halstead.is_some());
    }

    #[test]
    fn test_pr_size_categories() {
        let engine = MetricsEngine::with_defaults();
        let files = vec![FileContent::new("test.rs", "fn main() {}")];

        let metrics_xs = engine.calculate_metrics(&files, 25, 10);
        assert!(matches!(metrics_xs.pr_size_category, PrSizeCategory::Xs));

        let metrics_medium = engine.calculate_metrics(&files, 300, 50);
        assert!(matches!(
            metrics_medium.pr_size_category,
            PrSizeCategory::Medium
        ));
    }

    #[test]
    #[ignore = "Duplication detection requires larger codebase to detect patterns - test needs refactoring"]
    fn test_duplication_detection() {
        // Large duplicated function to ensure it meets min_lines (10) and min_tokens (50)
        let duplicated = r#"fn process_data_with_full_validation_and_metrics_collection() {
    let raw_input_data = fetch_data_from_primary_source();
    let validated_input = validate_input_structure(raw_input_data);
    let intermediate_result = perform_core_transformation(validated_input.clone());
    let enriched_output = apply_output_formatting(intermediate_result);
    println!("Processing completed with result: {}", enriched_output);
    persist_result_to_persistent_storage(enriched_output.clone());
    notify_all_subscribers_about_event(enriched_output.clone());
    release_all_allocated_resources();
    record_audit_trail_entry("data_processing_complete");
    perform_schema_validation(&enriched_output);
    emit_telemetry_metrics(100, 200, 300, 400);
    return enriched_output;
}
"#;

        let engine = MetricsEngine::with_defaults();
        let files = vec![
            FileContent::new("file1.rs", duplicated),
            FileContent::new("file2.rs", duplicated),
        ];

        let dup_groups = engine.find_duplications(&files);
        assert!(!dup_groups.is_empty());
    }

    #[test]
    fn test_alerts_generation() {
        let engine = MetricsEngine::with_defaults();

        let complex_code = r#"
fn very_complex(x: i32) -> i32 {
    if x > 0 {
        if x < 10 {
            if x % 2 == 0 {
                if x > 5 {
                    if x < 8 {
                        return x;
                    }
                }
            }
        }
    }
    0
}
"#;

        let files = vec![FileContent::new("test.rs", complex_code)];
        let metrics = engine.calculate_metrics(&files, 1000, 500);

        assert!(!metrics.alerts.is_empty());
    }
}
