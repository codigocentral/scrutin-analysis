//! Code duplication detection
//!
//! Implements hash-based duplication detection for code blocks.

use std::collections::HashMap;
use std::hash::{Hash, Hasher};

use crate::metrics::models::{DuplicationGroup, DuplicationInstance, FileContent};

#[derive(Debug, Clone)]
pub struct DuplicationConfig {
    pub min_lines: usize,
    pub min_tokens: usize,
    pub ignore_whitespace: bool,
    pub ignore_identifiers: bool,
}

impl Default for DuplicationConfig {
    fn default() -> Self {
        Self {
            min_lines: 10,
            min_tokens: 50,
            ignore_whitespace: true,
            ignore_identifiers: false,
        }
    }
}

pub struct DuplicationDetector {
    config: DuplicationConfig,
}

impl DuplicationDetector {
    pub fn new(config: DuplicationConfig) -> Self {
        Self { config }
    }

    pub fn with_defaults() -> Self {
        Self::new(DuplicationConfig::default())
    }

    pub fn find_duplications(&self, files: &[FileContent]) -> Vec<DuplicationGroup> {
        let mut blocks_by_hash: HashMap<u64, Vec<(String, usize, usize, String)>> = HashMap::new();

        for file in files {
            self.find_blocks_in_file(file, &mut blocks_by_hash);
        }

        let mut groups: Vec<DuplicationGroup> = Vec::new();

        for (hash, instances) in blocks_by_hash {
            if instances.len() >= 2 {
                let first = &instances[0];
                let line_count = first.2 - first.1 + 1;
                let token_count = count_tokens(&first.3);

                let duplication_instances: Vec<DuplicationInstance> = instances
                    .iter()
                    .map(
                        |(file_path, line_start, line_end, content)| DuplicationInstance {
                            file_path: file_path.clone(),
                            line_start: *line_start,
                            line_end: *line_end,
                            content_preview: content.lines().take(3).collect::<Vec<_>>().join("\n"),
                        },
                    )
                    .collect();

                groups.push(DuplicationGroup {
                    hash: format!("{:016x}", hash),
                    token_count,
                    line_count,
                    instances: duplication_instances,
                });
            }
        }

        groups.sort_by(|a, b| b.line_count.cmp(&a.line_count));
        groups
    }

    pub fn calculate_duplication_percentage(
        &self,
        files: &[FileContent],
        groups: &[DuplicationGroup],
    ) -> f64 {
        let total_lines: usize = files.iter().map(|f| f.content.lines().count()).sum();

        if total_lines == 0 {
            return 0.0;
        }

        let mut duplicated_lines = 0usize;
        let mut counted_ranges: Vec<(String, usize, usize)> = Vec::new();

        for group in groups {
            for instance in &group.instances {
                let already_counted = counted_ranges.iter().any(|(path, start, end)| {
                    path == &instance.file_path
                        && instance.line_start <= *end
                        && instance.line_end >= *start
                });

                if !already_counted {
                    duplicated_lines += group.line_count;
                    counted_ranges.push((
                        instance.file_path.clone(),
                        instance.line_start,
                        instance.line_end,
                    ));
                }
            }
        }

        (duplicated_lines as f64 / total_lines as f64) * 100.0
    }

    fn find_blocks_in_file(
        &self,
        file: &FileContent,
        blocks_by_hash: &mut HashMap<u64, Vec<(String, usize, usize, String)>>,
    ) {
        let lines: Vec<&str> = file.content.lines().collect();

        if lines.len() < self.config.min_lines {
            return;
        }

        for start in 0..=(lines.len().saturating_sub(self.config.min_lines)) {
            for end in (start + self.config.min_lines)..=lines.len() {
                let block: Vec<&str> = lines[start..end].to_vec();
                let normalized = self.normalize_block(&block);

                let token_count = count_tokens(&normalized);
                if token_count < self.config.min_tokens {
                    continue;
                }

                let hash = calculate_hash(&normalized);

                let content = block.join("\n");
                blocks_by_hash.entry(hash).or_insert_with(Vec::new).push((
                    file.path.clone(),
                    start + 1,
                    end,
                    content,
                ));
            }
        }

        self.merge_overlapping_blocks(blocks_by_hash, &file.path);
    }

    fn merge_overlapping_blocks(
        &self,
        blocks_by_hash: &mut HashMap<u64, Vec<(String, usize, usize, String)>>,
        file_path: &str,
    ) {
        for instances in blocks_by_hash.values_mut() {
            let file_instances: Vec<(String, usize, usize, String)> = instances
                .iter()
                .filter(|(path, _, _, _)| path == file_path)
                .cloned()
                .collect();

            if file_instances.len() <= 1 {
                continue;
            }

            let mut merged: Vec<(String, usize, usize, String)> = Vec::new();
            let mut sorted = file_instances.clone();
            sorted.sort_by_key(|(_, start, _, _)| *start);

            for instance in sorted {
                if let Some(last) = merged.last_mut() {
                    if instance.1 <= last.2 + 5 && instance.2 > last.2 {
                        last.2 = instance.2;
                        last.3 = format!("{}\n{}", last.3, instance.3);
                        continue;
                    }
                }
                merged.push(instance);
            }

            instances.retain(|(path, _, _, _)| path != file_path);
            instances.extend(merged);
        }
    }

    fn normalize_block(&self, lines: &[&str]) -> String {
        let mut normalized: Vec<String> = Vec::new();

        for line in lines {
            let mut line = line.to_string();

            if self.config.ignore_whitespace {
                line = line.split_whitespace().collect::<Vec<_>>().join(" ");
            }

            if self.config.ignore_identifiers {
                line = normalize_identifiers(&line);
            }

            normalized.push(line);
        }

        normalized.join("\n")
    }
}

fn normalize_identifiers(line: &str) -> String {
    use regex::Regex;
    static IDENTIFIER_REGEX: once_cell::sync::Lazy<Regex> =
        once_cell::sync::Lazy::new(|| Regex::new(r"\b[a-zA-Z_][a-zA-Z0-9_]*\b").unwrap());

    let mut result = line.to_string();
    let mut counter = 0;
    let mut replacements: HashMap<String, String> = HashMap::new();

    for cap in IDENTIFIER_REGEX.find_iter(line) {
        let ident = cap.as_str();
        if !is_keyword(ident) && !replacements.contains_key(ident) {
            counter += 1;
            replacements.insert(ident.to_string(), format!("$_{}", counter));
        }
    }

    for (original, replacement) in replacements {
        result = result.replace(&original, &replacement);
    }

    result
}

fn is_keyword(s: &str) -> bool {
    let keywords = [
        "if",
        "else",
        "elif",
        "for",
        "while",
        "do",
        "switch",
        "case",
        "default",
        "break",
        "continue",
        "return",
        "fn",
        "func",
        "function",
        "def",
        "class",
        "struct",
        "enum",
        "impl",
        "trait",
        "pub",
        "private",
        "protected",
        "public",
        "let",
        "const",
        "var",
        "import",
        "export",
        "from",
        "async",
        "await",
        "try",
        "catch",
        "finally",
        "throw",
        "new",
        "this",
        "self",
        "super",
        "true",
        "false",
        "null",
        "nil",
        "None",
        "Some",
        "Ok",
        "Err",
        "Result",
        "Option",
        "Vec",
        "String",
        "str",
        "int",
        "float",
        "bool",
        "void",
        "int32",
        "int64",
        "uint",
        "string",
        "object",
        "any",
        "never",
    ];
    keywords.contains(&s)
}

fn count_tokens(content: &str) -> usize {
    content.split_whitespace().filter(|t| t.len() > 1).count()
}

fn calculate_hash(content: &str) -> u64 {
    use std::collections::hash_map::DefaultHasher;

    let mut hasher = DefaultHasher::new();
    content.hash(&mut hasher);
    hasher.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_no_duplication() {
        let files = vec![
            FileContent::new("file1.rs", "fn foo() { println!(\"Hello\"); }"),
            FileContent::new("file2.rs", "fn bar() { println!(\"World\"); }"),
        ];

        let detector = DuplicationDetector::with_defaults();
        let groups = detector.find_duplications(&files);
        assert!(groups.is_empty());
    }

    #[test]
    fn test_exact_duplication() {
        let duplicated = r#"fn process() {
    let data = fetch_data();
    let result = transform(data);
    let output = format(result);
    println!("{}", output);
    save_to_database(output);
    notify_user(output);
    cleanup_resources();
    log_activity("process");
    return output;
}
"#;

        let files = vec![
            FileContent::new("file1.rs", duplicated),
            FileContent::new("file2.rs", duplicated),
        ];

        let config = DuplicationConfig {
            min_lines: 3,
            min_tokens: 10,
            ..Default::default()
        };
        let detector = DuplicationDetector::new(config);
        let groups = detector.find_duplications(&files);

        assert!(!groups.is_empty());
        assert!(groups[0].instances.len() >= 2);
    }

    #[test]
    fn test_duplication_percentage() {
        let code = r#"fn process() {
    let data = fetch_data();
    let result = transform(data);
    let output = format(result);
    println!("{}", output);
    save_to_database(output);
    notify_user(output);
    cleanup_resources();
    log_activity("process");
    return output;
}
"#;

        let files = vec![
            FileContent::new("file1.rs", code),
            FileContent::new("file2.rs", code),
        ];

        let config = DuplicationConfig {
            min_lines: 3,
            min_tokens: 10,
            ..Default::default()
        };
        let detector = DuplicationDetector::new(config);
        let groups = detector.find_duplications(&files);
        let percentage = detector.calculate_duplication_percentage(&files, &groups);

        assert!(percentage > 0.0);
    }

    #[test]
    fn test_normalize_whitespace() {
        let lines = vec!["  fn   foo ( )   {  ", "    let  x  =  1  ;  "];
        let config = DuplicationConfig {
            ignore_whitespace: true,
            ..Default::default()
        };
        let detector = DuplicationDetector::new(config);
        let normalized = detector.normalize_block(&lines);

        assert_eq!(normalized, "fn foo ( ) {\nlet x = 1 ;");
    }

    #[test]
    fn test_block_too_small() {
        let config = DuplicationConfig {
            min_lines: 10,
            ..Default::default()
        };
        let detector = DuplicationDetector::new(config);

        let files = vec![FileContent::new(
            "file.rs",
            "fn foo() {\n    println!(\"Hi\");\n}",
        )];

        let groups = detector.find_duplications(&files);
        assert!(groups.is_empty());
    }
}
