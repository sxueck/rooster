//! SecLang 词法分析:逻辑行拼接、引号感知的注释剥离与切词。
//!
//! CRS v4 的动作块大量使用「行尾反斜杠续行」(规范未要求,但实际文件如此),
//! 因此在切分逻辑行时先做续行拼接,再做注释剥离。

/// 一条逻辑行(可能由多个物理行续行拼接而成),`line` 为起始物理行号。
pub(crate) struct LogicalLine {
    pub line: usize,
    pub text: String,
}

/// 把源文本切成逻辑行:
/// 1. 行尾 `\` 续行拼接(空格分隔);
/// 2. 引号外 `#` 之后视为注释剥离;
/// 3. 空行丢弃。
pub(crate) fn logical_lines(source: &str) -> Vec<LogicalLine> {
    let mut out: Vec<LogicalLine> = Vec::new();
    let mut start: Option<usize> = None;
    let mut buf = String::new();

    let flush = |start: &mut Option<usize>, buf: &mut String, out: &mut Vec<LogicalLine>| {
        if let Some(line) = start.take() {
            let text = strip_comment(buf);
            let text = text.trim();
            if !text.is_empty() {
                out.push(LogicalLine {
                    line,
                    text: text.to_string(),
                });
            }
        }
        buf.clear();
    };

    for (i, raw) in source.lines().enumerate() {
        let lineno = i + 1;
        let trimmed_end = raw.trim_end();
        if let Some(body) = trimmed_end.strip_suffix('\\') {
            // 续行:保留内容,等待下一物理行。
            if start.is_none() {
                start = Some(lineno);
            } else {
                buf.push(' ');
            }
            buf.push_str(body.trim());
        } else {
            if start.is_none() {
                start = Some(lineno);
            } else {
                buf.push(' ');
            }
            buf.push_str(raw.trim());
            flush(&mut start, &mut buf, &mut out);
        }
    }
    // 悬空续行(文件以 `\` 结尾)按普通行处理。
    flush(&mut start, &mut buf, &mut out);
    out
}

/// 剥离引号外的 `#` 注释。引号内的 `#` 保留;引号内反斜杠转义下一字符。
pub(crate) fn strip_comment(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut quote: Option<char> = None;
    let mut esc = false;
    for c in line.chars() {
        match quote {
            Some(q) => {
                out.push(c);
                if esc {
                    esc = false;
                } else if c == '\\' {
                    esc = true;
                } else if c == q {
                    quote = None;
                }
            }
            None => {
                if c == '#' {
                    break;
                }
                if c == '\'' || c == '"' {
                    quote = Some(c);
                }
                out.push(c);
            }
        }
    }
    out
}

/// 读取下一个词法单元:引号包裹则读到配对引号(内容不含引号),
/// 否则读到空白。返回 (token, 剩余文本)。
pub(crate) fn next_token(s: &str) -> Option<(String, &str)> {
    let s = s.trim_start();
    if s.is_empty() {
        return None;
    }
    let first = s.chars().next().unwrap();
    if first == '"' || first == '\'' {
        let mut inner = String::new();
        let mut esc = false;
        let mut rest = "";
        let mut consumed = s.len(); // 兜底
        for (i, c) in s.char_indices().skip(1) {
            if esc {
                // 引号串内:仅同引号字符与反斜杠本身使用反斜杠转义,
                // 其余(正则里的 \b、\d 等)原样保留。
                if c == first || c == '\\' {
                    inner.push(c);
                } else {
                    inner.push('\\');
                    inner.push(c);
                }
                esc = false;
                continue;
            }
            match c {
                '\\' => esc = true,
                c if c == first => {
                    consumed = i + c.len_utf8();
                    rest = &s[consumed..];
                    return Some((inner, rest));
                }
                c => inner.push(c),
            }
        }
        // 未闭合引号:整段视为 token。
        Some((inner, rest))
    } else {
        match s.find(char::is_whitespace) {
            Some(pos) => Some((s[..pos].to_string(), &s[pos..])),
            None => Some((s.to_string(), "")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn continuation_and_comments() {
        let src = "# 纯注释行\n\nSecRule X \"@rx a\" \\\n  \"id:1,phase:1,pass\" # 行尾注释\nSecMarker \"M\"\n";
        let lines = logical_lines(src);
        let texts: Vec<&str> = lines.iter().map(|l| l.text.as_str()).collect();
        assert_eq!(texts, vec![r#"SecRule X "@rx a" "id:1,phase:1,pass""#, "SecMarker \"M\""]);
        assert_eq!(lines[0].line, 3);
        assert_eq!(lines[1].line, 5);
    }

    #[test]
    fn comment_inside_quotes_kept() {
        assert_eq!(strip_comment(r#"msg:'a # b',pass"#), r#"msg:'a # b',pass"#);
        assert_eq!(strip_comment("a # c"), "a ");
    }

    #[test]
    fn tokens_quoted_and_escapes() {
        let (t, r) = next_token(r#"'it''s, x' tail"#).unwrap();
        // 内层未转义的同种引号会截断——SecLang 不允许;常规用双引号包裹单引号内容。
        assert_eq!(t, "it");
        let (t, _) = next_token(r#""@rx a\qb" "#).unwrap();
        assert_eq!(t, r"@rx a\qb");
        let (t, _) = next_token(r#""a \"b\" c" "#).unwrap();
        assert_eq!(t, r#"a "b" c"#);
        let (t, r) = next_token("  @detectSQLi  rest").unwrap();
        assert_eq!((t.as_str(), r), ("@detectSQLi", "  rest"));
    }
}
