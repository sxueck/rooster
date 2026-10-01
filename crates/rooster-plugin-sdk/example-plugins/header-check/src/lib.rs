//! 示例插件:校验请求头 `X-Api-Key`,
//! 缺失 → Deny;值变更 → 记录到插件 kv;命中 → 上报事件。
//!
//! 构建为 wasm:
//! ```sh
//! cargo build -p rooster-example-header-check --release \
//!   --target wasm32-unknown-unknown \
//!   --manifest-path crates/rooster-plugin-sdk/example-plugins/header-check/Cargo.toml
//! ```

use rooster_plugin_sdk::{config, emit_event, headers, kv_get, kv_set, log, rooster_plugin, DENY};

rooster_plugin!(
    r#"{
  "name": "header-check",
  "version": "1.0.0",
  "hooks": ["on_http_request_headers"],
  "config_schema": {
    "type": "object",
    "properties": {
      "required-header": {"type": "string", "description": "必须存在的请求头名"}
    },
    "required": ["required-header"]
  }
}"#,
    hook
);

fn hook() -> i32 {
    let cfg = config();
    let required = serde_json_free::string_field(&cfg, "required-header")
        .unwrap_or_else(|| "x-api-key".to_string());

    let hdrs = headers();
    let Some(value) = hdrs
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(&required))
        .map(|(_, v)| v.clone())
    else {
        log(&format!("denied: missing `{required}` header"));
        emit_event(&format!("{{\"reason\":\"missing-header\",\"header\":\"{required}\"}}"));
        return DENY;
    };

    // kv 示例:记住该 key 上次的值,变化时记录。
    let key = "last-value";
    match kv_get(key) {
        Some(prev) if prev == value => {}
        _ => {
            kv_set(key, &value);
            log("api key changed since last request");
        }
    }
    rooster_plugin_sdk::CONTINUE
}

/// 无 serde 的最小 JSON 字符串字段读取(保持 guest 零依赖)。
mod serde_json_free {
    pub fn string_field(json: &str, field: &str) -> Option<String> {
        // 只支持 {"k":"v", ...} 的平面结构 —— 足够插件配置。
        let needle = format!("\"{field}\"");
        let start = json.find(&needle)? + needle.len();
        let rest = json[start..].trim_start();
        let rest = rest.strip_prefix(':')?.trim_start();
        let rest = rest.strip_prefix('"')?;
        let end = rest.find('"')?;
        Some(rest[..end].to_string())
    }
}
