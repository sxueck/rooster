//! 简单的行级统一 diff(LCS),供模板预览与配置历史对比。
//!
//! 50 节点规模的配置文本(几 KB)用 O(n·m) DP 足够;不引入外部依赖。

/// 计算行序列的最长公共子序列表。
fn lcs_table(a: &[&str], b: &[&str]) -> Vec<Vec<u32>> {
    let mut dp = vec![vec![0u32; b.len() + 1]; a.len() + 1];
    for i in (0..a.len()).rev() {
        for j in (0..b.len()).rev() {
            dp[i][j] = if a[i] == b[j] {
                dp[i + 1][j + 1] + 1
            } else {
                dp[i + 1][j].max(dp[i][j + 1])
            };
        }
    }
    dp
}

#[derive(Debug, Clone, PartialEq)]
pub enum DiffOp {
    Context(String),
    Add(String),
    Remove(String),
}

/// 生成编辑脚本(顺序:老串/新串混合游标推进)。
pub fn diff_lines(old: &str, new: &str) -> Vec<DiffOp> {
    let a: Vec<&str> = old.lines().collect();
    let b: Vec<&str> = new.lines().collect();
    let dp = lcs_table(&a, &b);
    let mut ops = Vec::new();
    let (mut i, mut j) = (0usize, 0usize);
    while i < a.len() && j < b.len() {
        if a[i] == b[j] {
            ops.push(DiffOp::Context(a[i].to_string()));
            i += 1;
            j += 1;
        } else if dp[i + 1][j] >= dp[i][j + 1] {
            ops.push(DiffOp::Remove(a[i].to_string()));
            i += 1;
        } else {
            ops.push(DiffOp::Add(b[j].to_string()));
            j += 1;
        }
    }
    while i < a.len() {
        ops.push(DiffOp::Remove(a[i].to_string()));
        i += 1;
    }
    while j < b.len() {
        ops.push(DiffOp::Add(b[j].to_string()));
        j += 1;
    }
    ops
}

const CONTEXT: usize = 3;

/// 渲染为统一 diff 文本(3 行上下文,真实 hunk 头)。内容一致时返回空串。
pub fn unified(old: &str, new: &str) -> String {
    if old == new {
        return String::new();
    }
    let ops = diff_lines(old, new);
    let changed: Vec<bool> = ops.iter().map(|o| !matches!(o, DiffOp::Context(_))).collect();
    let mut keep = vec![false; ops.len()];
    for (idx, c) in changed.iter().enumerate() {
        if *c {
            let lo = idx.saturating_sub(CONTEXT);
            let hi = (idx + CONTEXT).min(ops.len() - 1);
            for k in lo..=hi {
                keep[k] = true;
            }
        }
    }

    let mut out = String::new();
    let mut pos = 0usize;
    while pos < ops.len() {
        if !keep[pos] {
            pos += 1;
            continue;
        }
        // 一个 hunk = 连续 keep 的 ops 段。
        let start = pos;
        let mut end = pos;
        while end < ops.len() && keep[end] {
            end += 1;
        }
        // hunk 头需要老/新两侧的起始行号与行数(1-based)。
        let (mut old_start, mut new_start) = (1u32, 1u32);
        let (mut old_count, mut new_count) = (0u32, 0u32);
        // 先回溯:数出 hunk 之前消费的老/新行数。
        for op in &ops[..start] {
            match op {
                DiffOp::Context(_) => {
                    old_start += 1;
                    new_start += 1;
                }
                DiffOp::Remove(_) => old_start += 1,
                DiffOp::Add(_) => new_start += 1,
            }
        }
        for op in &ops[start..end] {
            match op {
                DiffOp::Context(_) => {
                    old_count += 1;
                    new_count += 1;
                }
                DiffOp::Remove(_) => old_count += 1,
                DiffOp::Add(_) => new_count += 1,
            }
        }
        if old_count == 0 {
            old_start = new_start;
        }
        out.push_str(&format!(
            "@@ -{old_start},{old_count} +{new_start},{new_count} @@\n"
        ));
        for op in &ops[start..end] {
            match op {
                DiffOp::Context(l) => out.push_str(&format!(" {l}\n")),
                DiffOp::Add(l) => out.push_str(&format!("+{l}\n")),
                DiffOp::Remove(l) => out.push_str(&format!("-{l}\n")),
            }
        }
        pos = end;
    }
    format!("--- old\n+++ new\n{out}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diff_detects_add_remove_modify() {
        let old = "a\nb\nc";
        let new = "a\nx\nc\nd";
        let ops = diff_lines(old, new);
        assert!(ops.contains(&DiffOp::Remove("b".into())));
        assert!(ops.contains(&DiffOp::Add("x".into())));
        assert!(ops.contains(&DiffOp::Add("d".into())));
        assert!(ops.contains(&DiffOp::Context("a".into())));
    }

    #[test]
    fn identical_input_empty_diff() {
        assert_eq!(unified("x\ny", "x\ny"), "");
    }

    #[test]
    fn unified_renders_markers_and_headers() {
        let d = unified("a\nb", "a\nc");
        assert!(d.contains("-b"));
        assert!(d.contains("+c"));
        assert!(d.contains(" a"));
        assert!(d.contains("@@ -1,2 +1,2 @@"));
    }

    #[test]
    fn far_apart_changes_make_two_hunks() {
        let old: Vec<String> = (0..20).map(|i| i.to_string()).collect();
        let mut new = old.clone();
        new[2] = "x".into();
        new[15] = "y".into();
        let d = unified(&old.join("\n"), &new.join("\n"));
        assert_eq!(d.matches("@@").count() / 2, 2, "two separate hunks");
    }
}
