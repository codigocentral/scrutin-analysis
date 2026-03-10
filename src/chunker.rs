pub fn chunk_diff(diff_text: &str, max_lines: usize, max_chars: usize) -> Vec<String> {
    if diff_text.trim().is_empty() {
        return Vec::new();
    }

    let max_lines = max_lines.max(50);
    let max_chars = max_chars.max(2_000);

    let mut chunks = Vec::new();
    let mut current = String::new();
    let mut current_lines = 0usize;

    for line in diff_text.lines() {
        let candidate_len = current.len().saturating_add(line.len()).saturating_add(1);
        let should_split =
            !current.is_empty() && (current_lines >= max_lines || candidate_len >= max_chars);

        if should_split {
            chunks.push(current);
            current = String::new();
            current_lines = 0;
        }

        current.push_str(line);
        current.push('\n');
        current_lines += 1;
    }

    if !current.is_empty() {
        chunks.push(current);
    }

    chunks
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chunk_diff_splits_large_input() {
        let mut diff = String::new();
        diff.push_str("diff --git a/a.ts b/a.ts\n");
        for i in 0..700 {
            diff.push_str(&format!("+const v{} = {};\n", i, i));
        }

        let chunks = chunk_diff(&diff, 200, 4_000);
        assert!(chunks.len() > 1);
        assert!(chunks.iter().all(|c| !c.trim().is_empty()));
    }

    #[test]
    fn test_chunk_diff_returns_empty_for_empty_input() {
        let chunks = chunk_diff("", 100, 2000);
        assert!(chunks.is_empty());
    }
}
