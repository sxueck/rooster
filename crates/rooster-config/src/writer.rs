//! 保留注释回写与原子写入。
//!
//! 回写基于 YAML 补丁(yamlpatch),只改动命中的子树,其余注释、键顺序
//! 与格式保持原样。落盘走 tmp → fsync → rename,写前把旧版本归档到
//! `data/config-history/`(最多 20 份)。

use crate::error::ConfigError;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use yamlpatch::{Op, Patch};
use yamlpath::{Component, Document, Route};

pub const MAX_HISTORY: usize = 20;

/// 内容哈希(sha256 前 16 个十六进制字符),用于 If-Match 与自触发判断。
pub fn hash_content(raw: &str) -> String {
    let digest = Sha256::digest(raw.as_bytes());
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    hex[..16].to_string()
}

/// 路由段:key 或数组下标。
#[derive(Debug, Clone)]
pub enum Seg<'a> {
    K(&'a str),
    I(usize),
}

fn to_route(segs: &[Seg]) -> Route<'static> {
    let components: Vec<Component> = segs
        .iter()
        .map(|s| match s {
            Seg::K(k) => Component::from((*k).to_string()),
            Seg::I(i) => Component::from(*i),
        })
        .collect();
    Route::from(components)
}

fn json_to_yaml_value(value: &serde_json::Value) -> Result<yaml_serde::Value, ConfigError> {
    serde_json::from_value(value.clone())
        .map_err(|e| ConfigError::Patch(format!("value conversion failed: {e}")))
}

fn apply(raw: &str, route: Route<'static>, operation: Op<'static>) -> Result<String, ConfigError> {
    let doc = Document::new(raw.to_string())
        .map_err(|e| ConfigError::Patch(format!("document parse failed: {e}")))?;
    let patch = Patch { route, operation };
    let out = yamlpatch::apply_yaml_patches(&doc, std::slice::from_ref(&patch))
        .map_err(|e| ConfigError::Patch(e.to_string()))?;
    Ok(out.source().to_string())
}

/// 替换子树的值,保留文件其余部分的注释与格式。
pub fn replace_subtree(
    raw: &str,
    segs: &[Seg],
    value: &serde_json::Value,
) -> Result<String, ConfigError> {
    match apply(raw, to_route(segs), Op::Replace(json_to_yaml_value(value)?)) {
        Ok(out) => Ok(out),
        Err(direct) => {
            // flow 风格父节点(`plugins: { a: { .. } }`)下的子树 yamlpatch 定位不了。
            // 逐级往上把那个祖先连同新值整体重写为 block 风格:本次写入能成,
            // 该祖先之后的补丁也能成。
            for depth in (1..segs.len()).rev() {
                if let Ok(out) = replace_ancestor(raw, segs, depth, value) {
                    return Ok(out);
                }
            }
            Err(direct)
        }
    }
}

/// 把 `segs[..depth]` 指向的祖先节点连同深层新值一起 Replace。
fn replace_ancestor(
    raw: &str,
    segs: &[Seg],
    depth: usize,
    value: &serde_json::Value,
) -> Result<String, ConfigError> {
    let mut tree: serde_json::Value = serde_norway::from_str(raw)
        .map_err(|e| ConfigError::Patch(format!("value conversion failed: {e}")))?;
    write_deep(&mut tree, segs, value)?;
    let ancestor = read_deep(&tree, &segs[..depth])
        .ok_or_else(|| ConfigError::Patch("ancestor disappeared".into()))?;
    apply(
        raw,
        to_route(&segs[..depth]),
        Op::Replace(json_to_yaml_value(ancestor)?),
    )
}

fn write_deep(
    tree: &mut serde_json::Value,
    segs: &[Seg],
    value: &serde_json::Value,
) -> Result<(), ConfigError> {
    let bad = || ConfigError::Patch("route does not exist in the parsed document".into());
    let mut node = tree;
    for seg in &segs[..segs.len() - 1] {
        node = match (seg, node) {
            (Seg::K(k), serde_json::Value::Object(map)) => map.get_mut(&k[..]).ok_or_else(bad)?,
            (Seg::I(i), serde_json::Value::Array(items)) => items.get_mut(*i).ok_or_else(bad)?,
            _ => return Err(bad()),
        };
    }
    match (&segs[segs.len() - 1], node) {
        (Seg::K(k), serde_json::Value::Object(map)) => {
            map.insert((*k).to_string(), value.clone());
            Ok(())
        }
        (Seg::I(i), serde_json::Value::Array(items)) if *i < items.len() => {
            items[*i] = value.clone();
            Ok(())
        }
        _ => Err(bad()),
    }
}

fn read_deep<'a>(tree: &'a serde_json::Value, segs: &[Seg]) -> Option<&'a serde_json::Value> {
    let mut node = tree;
    for seg in segs {
        node = match (seg, node) {
            (Seg::K(k), serde_json::Value::Object(map)) => map.get(&k[..])?,
            (Seg::I(i), serde_json::Value::Array(items)) => items.get(*i)?,
            _ => return None,
        };
    }
    Some(node)
}

/// 向 route 指向的列表末尾追加一项。
pub fn append_item(
    raw: &str,
    segs: &[Seg],
    value: &serde_json::Value,
) -> Result<String, ConfigError> {
    apply(
        raw,
        to_route(segs),
        Op::Append {
            value: json_to_yaml_value(value)?,
        },
    )
}

/// 在 route 指向的 map 中新增一个键(键必须不存在)。
/// 缺失的父级 map 逐级补出来:省略可选段(如 `local.security`)是合法配置,
/// 而 yamlpatch 往不存在的父节点里 Add 会直接报 "mapping has no key",
/// 把合法配置变成 500(白名单写入正是这条路)。
pub fn add_key(
    raw: &str,
    segs: &[Seg],
    key: &str,
    value: &serde_json::Value,
) -> Result<String, ConfigError> {
    let buf = raw.to_string();
    // 缺失的父级一次性写入:分步补空 map 会把父节点渲染成 flow 风格
    // (`plugins: { http-guard: { .. } }`),之后对它的子树做任何 Replace 都会报错。
    let missing = (1..=segs.len()).find(|i| !subtree_exists(&buf, &segs[..*i]).unwrap_or(false));
    if let Some(i) = missing {
        let child = match &segs[i - 1] {
            // 下标父级不会"缺失"(列表项只能已存在)。
            Seg::I(_) => return Err(ConfigError::Patch("list parent is missing".into())),
            Seg::K(k) => (*k).to_string(),
        };
        let mut nested = serde_json::json!({ key: value });
        for seg in segs[i..].iter().rev() {
            let Seg::K(k) = seg else {
                return Err(ConfigError::Patch("list parent is missing".into()));
            };
            nested = serde_json::json!({ &k[..]: nested });
        }
        return apply(
            &buf,
            to_route(&segs[..i - 1]),
            Op::Add {
                key: child,
                value: json_to_yaml_value(&nested)?,
            },
        );
    }
    apply(
        &buf,
        to_route(segs),
        Op::Add {
            key: key.to_string(),
            value: json_to_yaml_value(value)?,
        },
    )
}

/// 删除 route 指向的子树。
pub fn remove_subtree(raw: &str, segs: &[Seg]) -> Result<String, ConfigError> {
    apply(raw, to_route(segs), Op::Remove)
}

/// route 是否存在(用于区分「空列表」与「键不存在」)。
pub fn subtree_exists(raw: &str, segs: &[Seg]) -> Result<bool, ConfigError> {
    let doc = Document::new(raw.to_string())
        .map_err(|e| ConfigError::Patch(format!("document parse failed: {e}")))?;
    let components: Vec<Component> = segs
        .iter()
        .map(|s| match s {
            Seg::K(k) => Component::from((*k).to_string()),
            Seg::I(i) => Component::from(*i),
        })
        .collect();
    Ok(doc.query_exists(&Route::from(components)))
}

pub struct ConfigWriter {
    path: PathBuf,
    history_dir: PathBuf,
}

impl ConfigWriter {
    pub fn new(path: impl Into<PathBuf>, data_dir: &Path) -> Self {
        Self {
            path: path.into(),
            history_dir: data_dir.join("config-history"),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn history_dir(&self) -> &Path {
        &self.history_dir
    }

    /// 旧版本归档后,tmp → fsync → rename 原子落盘。
    pub fn write_atomic(&self, new_raw: &str) -> std::io::Result<()> {
        if let Ok(old) = fs::read_to_string(&self.path) {
            if old != new_raw {
                // 归档失败不阻塞主写入:历史仅用于 diff/回滚辅助。
                let _ = self.archive(&old);
            }
        }
        let tmp = self.path.with_extension("yaml.tmp");
        let write = (|| {
            let mut f = fs::File::create(&tmp)?;
            f.write_all(new_raw.as_bytes())?;
            f.sync_all()?;
            fs::rename(&tmp, &self.path)
        })();
        if write.is_err() {
            let _ = fs::remove_file(&tmp);
            return write;
        }
        if let Some(dir) = self.path.parent() {
            if let Ok(d) = fs::File::open(dir) {
                let _ = d.sync_all();
            }
        }
        Ok(())
    }

    fn archive(&self, old: &str) -> std::io::Result<()> {
        fs::create_dir_all(&self.history_dir)?;
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let name = format!("{ts}-{}.yaml", &hash_content(old)[..8]);
        let dest = self.history_dir.join(name);
        if !dest.exists() {
            fs::write(&dest, old)?;
        }
        // 只保留最近 MAX_HISTORY 份;文件名以时间戳开头,字典序即时间序。
        let mut names: Vec<String> = fs::read_dir(&self.history_dir)?
            .filter_map(|e| e.ok())
            .filter_map(|e| e.file_name().into_string().ok())
            .filter(|n| n.ends_with(".yaml"))
            .collect();
        names.sort();
        while names.len() > MAX_HISTORY {
            let oldest = names.remove(0);
            let _ = fs::remove_file(self.history_dir.join(oldest));
        }
        Ok(())
    }

    pub fn list_history(&self) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(&self.history_dir)
            .map(|rd| {
                rd.filter_map(|e| e.ok())
                    .filter_map(|e| e.file_name().into_string().ok())
                    .filter(|n| n.ends_with(".yaml"))
                    .collect()
            })
            .unwrap_or_default();
        names.sort();
        names
    }

    /// 读取某份历史版本;name 只允许是文件名,防路径穿越。
    pub fn read_history(&self, name: &str) -> std::io::Result<String> {
        if name.contains('/') || name.contains("..") || !name.ends_with(".yaml") {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "invalid history file name",
            ));
        }
        fs::read_to_string(self.history_dir.join(name))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const SAMPLE: &str = r#"# rooster agent configuration
local:
  agent:
    node-name: web-01        # keep this comment
    data-dir: /tmp/rooster
  management:
    listen: 127.0.0.1:9870   # api
    secret-key: abc
  forwards:
    # forwards live here
    - id: mysql
      proto: tcp
      listen: 0.0.0.0:13306
      target: 10.0.1.20:3306
"#;

    #[test]
    fn replace_keeps_comments_and_layout() {
        let out = replace_subtree(
            SAMPLE,
            &[Seg::K("local"), Seg::K("agent"), Seg::K("node-name")],
            &json!("web-02"),
        )
        .unwrap();
        assert!(out.contains("# rooster agent configuration"));
        assert!(out.contains("# keep this comment"));
        assert!(out.contains("node-name: web-02"));
        assert!(out.contains("listen: 127.0.0.1:9870   # api"));
        assert!(!out.contains("web-01"));
    }

    #[test]
    fn add_key_creates_missing_parent_maps() {
        // 真实 E2E 报错路径:配置里没写可选的 local.security 时,白名单写入
        // 不得因 “mapping has no key `security`” 而 500。
        let raw = "local:\n  agent:\n    node-name: web-01\n";
        let out = add_key(
            raw,
            &[Seg::K("local"), Seg::K("security")],
            "admin-allowlist",
            &json!(["127.0.0.0/8"]),
        )
        .expect("add_key must create the missing local.security map");
        assert!(out.contains("node-name: web-01"), "其余内容不得丢失: {out}");
        let (_, eff) = crate::parse_and_validate(&out).expect("patched config parses");
        assert_eq!(
            eff.security.admin_allowlist,
            vec!["127.0.0.0/8".to_string()]
        );
    }

    #[test]
    fn add_key_fills_every_missing_level_and_keeps_siblings() {
        let out = add_key(
            SAMPLE,
            &[Seg::K("managed"), Seg::K("plugins")],
            "http-guard",
            &json!({ "enabled": true }),
        )
        .expect("missing managed: level must be created too");
        assert!(out.contains("# keep this comment"), "注释必须存活: {out}");
        assert!(out.contains("managed:"), "{out}");
        assert!(out.contains("http-guard"), "{out}");
    }

    #[test]
    fn replace_on_missing_path_still_errors() {
        // 只放宽 add_key。replace/remove 静默新建会让配置里凭空多出段。
        let err = replace_subtree(
            "local:\n  agent:\n    node-name: web-01\n",
            &[Seg::K("local"), Seg::K("security"), Seg::K("admin-allowlist")],
            &json!(["10.0.0.0/8"]),
        );
        assert!(err.is_err(), "replace on a missing path must stay an error");
    }

    #[test]
    fn append_and_remove_forward() {
        let rule = json!({
            "id": "redis",
            "proto": "udp",
            "listen": "0.0.0.0:16379",
            "target": "10.0.1.21:6379",
        });
        let out = append_item(
            SAMPLE,
            &[Seg::K("local"), Seg::K("forwards")],
            &rule,
        )
        .unwrap();
        assert!(out.contains("id: redis"));
        assert!(out.contains("# forwards live here"));

        let removed = remove_subtree(
            &out,
            &[Seg::K("local"), Seg::K("forwards"), Seg::I(0)],
        )
        .unwrap();
        assert!(!removed.contains("id: mysql"));
        assert!(removed.contains("id: redis"));
    }

    #[test]
    fn replace_flow_empty_list_with_block_list() {
        // `forwards: []` 是 flow 序列,yamlpatch 不支持对其 Append;
        // 整体 Replace 为 block 列表是支持的路径。
        let raw = "local:\n  agent:\n    node-name: t\n  forwards: []\n";
        assert!(subtree_exists(raw, &[Seg::K("local"), Seg::K("forwards")]).unwrap());
        let rule = json!({"id": "r", "proto": "tcp", "listen": "0.0.0.0:18080", "target": "127.0.0.1:8080"});
        let out = replace_subtree(raw, &[Seg::K("local"), Seg::K("forwards")], &json!([rule])).unwrap();
        assert!(out.contains("id: r"));
        let parsed: serde_json::Value = serde_norway::from_str(&out).unwrap();
        assert_eq!(parsed["local"]["forwards"][0]["id"], "r");
    }

    #[test]
    fn nested_replace_recovers_from_flow_ancestor() {
        // 早期版本会把自动补出的父 map 写成 flow 风格,之后对子树的任何
        // 替换都会失败(Nginx 接入第二个站点时的 409)。两条路径都要能走通。
        let flow = "managed:\n  sites: []\n  plugins: { http-guard: { enabled: true, listen-http: \"127.0.0.1:18080\" } }\n";
        let guard = json!({"enabled": true, "listen-http": "127.0.0.1:18081", "trusted-proxies": ["127.0.0.1/32"]});
        let out = replace_subtree(
            flow,
            &[Seg::K("managed"), Seg::K("plugins"), Seg::K("http-guard")],
            &guard,
        )
        .unwrap();
        let parsed: serde_json::Value = serde_norway::from_str(&out).unwrap();
        assert_eq!(parsed["managed"]["plugins"]["http-guard"]["listen-http"], "127.0.0.1:18081");
        // 修好后的文档还能继续接受同一路径的补丁。
        let again = replace_subtree(
            &out,
            &[Seg::K("managed"), Seg::K("plugins"), Seg::K("http-guard")],
            &guard,
        )
        .unwrap();
        let parsed: serde_json::Value = serde_norway::from_str(&again).unwrap();
        assert_eq!(parsed["managed"]["plugins"]["http-guard"]["listen-http"], "127.0.0.1:18081");
    }

    #[test]
    fn add_key_does_not_create_flow_parents() {
        let out = add_key(
            "managed:\n  sites: []\n",
            &[Seg::K("managed"), Seg::K("plugins")],
            "http-guard",
            &json!({"enabled": true, "trusted-proxies": ["127.0.0.1/32"]}),
        )
        .unwrap();
        assert!(out.contains("plugins:\n    http-guard:"), "{out}");
        // 新建的父节点下的子树必须可以直接再打一次补丁。
        let again = replace_subtree(
            &out,
            &[Seg::K("managed"), Seg::K("plugins"), Seg::K("http-guard")],
            &json!({"enabled": false}),
        )
        .unwrap();
        assert!(again.contains("enabled: false"), "{again}");
    }

    #[test]
    fn scalar_replacement_handles_special_chars() {
        let hash = "$2b$12$KIXQeQeJ8mZMCvkLFeP7Du2jQQ";
        let out = replace_subtree(
            SAMPLE,
            &[Seg::K("local"), Seg::K("management"), Seg::K("secret-key")],
            &json!(hash),
        )
        .unwrap();
        // 引号风格由 yamlpatch 决定(此处为 plain scalar),只验证值能无损读回。
        let parsed: serde_json::Value =
            serde_norway::from_str(&out).expect("round-trip parse");
        assert_eq!(
            parsed["local"]["management"]["secret-key"].as_str(),
            Some(hash)
        );
    }
}
