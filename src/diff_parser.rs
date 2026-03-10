#[derive(Debug, Clone)]
pub struct DiffLine {
    pub line_number: usize,
    pub content: String,
}

#[derive(Debug, Clone)]
pub struct DiffFile {
    pub path: String,
    pub added_lines: Vec<DiffLine>,
}

pub fn parse_unified_diff(diff: &str, only_new_code: bool) -> Vec<DiffFile> {
    let mut files = Vec::<DiffFile>::new();
    let mut current_path: Option<String> = None;
    let mut current_lines = Vec::<DiffLine>::new();
    let mut current_new_line = 0usize;
    let mut inside_hunk = false;

    for raw_line in diff.lines() {
        if raw_line.starts_with("diff --git ") {
            flush_file(&mut files, &mut current_path, &mut current_lines);
            inside_hunk = false;
            continue;
        }

        if let Some(path) = raw_line.strip_prefix("+++ ") {
            if path != "/dev/null" {
                current_path = Some(path.trim_start_matches("b/").to_string());
            }
            continue;
        }

        if raw_line.starts_with("@@ ") {
            inside_hunk = true;
            current_new_line = parse_new_line_start(raw_line).unwrap_or_else(|| {
                tracing::warn!(
                    "Falha ao fazer parse do número de linha do hunk: {}",
                    raw_line
                );
                1 // Melhor que 0, que seria inválido
            });
            continue;
        }

        if !inside_hunk {
            continue;
        }

        if raw_line.starts_with('+') && !raw_line.starts_with("+++") {
            current_lines.push(DiffLine {
                line_number: current_new_line,
                content: raw_line[1..].to_string(),
            });
            current_new_line += 1;
            continue;
        }

        if let Some(stripped) = raw_line.strip_prefix(' ') {
            if !only_new_code {
                current_lines.push(DiffLine {
                    line_number: current_new_line,
                    content: stripped.to_string(),
                });
            }
            current_new_line += 1;
            continue;
        }

        if raw_line.starts_with('-') {
            continue;
        }
    }

    flush_file(&mut files, &mut current_path, &mut current_lines);
    files
}

fn flush_file(
    files: &mut Vec<DiffFile>,
    current_path: &mut Option<String>,
    current_lines: &mut Vec<DiffLine>,
) {
    if let Some(path) = current_path.take() {
        files.push(DiffFile {
            path,
            added_lines: std::mem::take(current_lines),
        });
    }
}

fn parse_new_line_start(hunk: &str) -> Option<usize> {
    // @@ -10,4 +22,7 @@
    let start = hunk.find('+')?;
    let rest = &hunk[start + 1..];
    let number = rest
        .split(|c: char| c == ',' || c.is_whitespace())
        .next()?
        .parse::<usize>()
        .ok()?;
    Some(number)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_unified_diff_added_lines() {
        let diff = r#"
diff --git a/src/a.ts b/src/a.ts
--- a/src/a.ts
+++ b/src/a.ts
@@ -1,2 +1,3 @@
 const a = 1;
+const b = 2;
 const c = 3;
"#;
        let files = parse_unified_diff(diff, true);
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].path, "src/a.ts");
        assert_eq!(files[0].added_lines.len(), 1);
        assert_eq!(files[0].added_lines[0].line_number, 2);
    }

    #[test]
    fn test_parse_unified_diff_with_context_lines() {
        let diff = r#"
diff --git a/src/a.ts b/src/a.ts
--- a/src/a.ts
+++ b/src/a.ts
@@ -1,2 +1,3 @@
 const a = 1;
+const b = 2;
 const c = 3;
"#;
        let files = parse_unified_diff(diff, false);
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].added_lines.len(), 3);
        assert_eq!(files[0].added_lines[0].line_number, 1);
    }
}
