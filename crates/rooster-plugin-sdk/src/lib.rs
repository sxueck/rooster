//! Rooster WASM 插件 guest SDK。
//!
//! 面向 `wasm32-unknown-unknown`。插件只依赖这里的宿主函数桥,没有任何
//! WASI(无文件系统/网络/时钟)。用法:
//!
//! ```ignore
//! rooster_plugin::rooster_plugin!(r#"{"name":"header-check","version":"1.0","hooks":["on_http_request_headers"]}"#, my_hook);
//!
//! fn my_hook() -> i32 {
//!     let headers = rooster_plugin::headers();
//!     if !headers.iter().any(|(k, _)| k == "x-api-key") {
//!         return rooster_plugin::DENY;
//!     }
//!     rooster_plugin::CONTINUE
//! }
//! ```
//!
//! 构建为 wasm:
//! `cargo build --release --target wasm32-unknown-unknown`,产物在
//! `target/wasm32-unknown-unknown/release/*.wasm`。
//!
//! ABI 约定(与宿主 `rooster-agent/src/wasmrt.rs` 成对维护):
//! - manifest:导出不可变全局 `rooster_manifest_ptr` / `rooster_manifest_len`,
//!   指向线性内存中的 JSON(宏自动生成);
//! - hook:`extern "C" fn on_http_request_headers() -> i32`(动作码)。

#![allow(clippy::missing_safety_doc)]

// ---------------------------------------------------------------------------
// 宿主函数桥(env 模块,无 WASI)

// wasm_import_module 指明导入来自宿主的 env 模块(与 wasmrt.rs 的
// Linker 注册一致);没有它 rust-lld 会把符号当未定义链接错误。
#[link(wasm_import_module = "env")]
extern "C" {
    fn rooster_log(ptr: *const u8, len: usize);
    fn rooster_header_count() -> usize;
    fn rooster_header_name(i: usize, ptr: *mut u8, cap: usize) -> isize;
    fn rooster_header_value(i: usize, ptr: *mut u8, cap: usize) -> isize;
    fn rooster_set_header(nptr: *const u8, nlen: usize, vptr: *const u8, vlen: usize) -> isize;
    fn rooster_kv_get(kptr: *const u8, klen: usize, buf: *mut u8, cap: usize) -> isize;
    fn rooster_kv_set(kptr: *const u8, klen: usize, vptr: *const u8, vlen: usize);
    fn rooster_emit_event(ptr: *const u8, len: usize);
    fn rooster_config(ptr: *mut u8, cap: usize) -> isize;
}

// ---------------------------------------------------------------------------
// 动作码(返回值)

pub const CONTINUE: i32 = 0;
pub const DENY: i32 = 1;
pub const BAN: i32 = 2;

// ---------------------------------------------------------------------------
// 安全封装

const SCRATCH: usize = 4096;

fn read_str_impl(call: impl Fn(*mut u8, usize) -> isize) -> Option<String> {
    // 先用小缓冲探测,返回 -2 表示缓冲不足时按 64KiB 上限重试;
    // -1 表示键不存在。闭包是 Fn,可重复调用。
    let mut buf = vec![0u8; SCRATCH];
    let n = call(buf.as_mut_ptr(), buf.len());
    let n = if n == -2 {
        buf = vec![0u8; 64 * 1024];
        call(buf.as_mut_ptr(), buf.len())
    } else {
        n
    };
    if n < 0 {
        return None;
    }
    buf.truncate(n as usize);
    String::from_utf8(buf).ok()
}

/// 记录日志(宿主 tracing,插件 id 自动附加)。
pub fn log(message: &str) {
    unsafe { rooster_log(message.as_ptr(), message.len()) }
}

/// 读取当前请求头(hook 执行期间)。
pub fn headers() -> Vec<(String, String)> {
    let count = unsafe { rooster_header_count() };
    let mut out = Vec::new();
    for i in 0..count {
        let name = read_str_impl(|p, c| unsafe { rooster_header_name(i, p, c) });
        let value = read_str_impl(|p, c| unsafe { rooster_header_value(i, p, c) });
        if let (Some(n), Some(v)) = (name, value) {
            out.push((n, v));
        }
    }
    out
}

/// 设置/覆盖请求头(同名整体替换)。
pub fn set_header(name: &str, value: &str) -> bool {
    unsafe {
        rooster_set_header(
            name.as_ptr(),
            name.len(),
            value.as_ptr(),
            value.len(),
        ) == 0
    }
}

/// 读取插件配置中的键值(按插件隔离的命名空间)。
pub fn kv_get(key: &str) -> Option<String> {
    read_str_impl(|p, c| unsafe { rooster_kv_get(key.as_ptr(), key.len(), p, c) })
}

/// 写入插件 kv(按插件隔离)。
pub fn kv_set(key: &str, value: &str) {
    unsafe { rooster_kv_set(key.as_ptr(), key.len(), value.as_ptr(), value.len()) }
}

/// 上报事件(payload 为 JSON 字符串,进节点事件流)。
pub fn emit_event(payload_json: &str) {
    unsafe { rooster_emit_event(payload_json.as_ptr(), payload_json.len()) }
}

/// 读取插件配置 JSON(来自 config.yaml 的 plugins 条目)。
pub fn config() -> String {
    read_str_impl(|p, c| unsafe { rooster_config(p, c) }).unwrap_or_else(|| "{}".to_string())
}

// ---------------------------------------------------------------------------
// 插件入口宏

/// 生成 manifest 导出与 hook 转发。
///
/// `$manifest` 是静态 JSON 字符串(结构:name/version/hooks/
/// config_schema);`hook` 是返回动作码的函数名。
///
/// 生成的导出:`rooster_manifest_ptr` / `rooster_manifest_len`(单 i32
/// 返回,见宿主 wasmrt.rs 的 ABI 说明)与 `on_http_request_headers`。
#[macro_export]
macro_rules! rooster_plugin {
    ($manifest:expr, $hook:ident) => {
        static MANIFEST: &str = $manifest;

        #[no_mangle]
        pub extern "C" fn rooster_manifest_ptr() -> u32 {
            MANIFEST.as_ptr() as u32
        }

        #[no_mangle]
        pub extern "C" fn rooster_manifest_len() -> u32 {
            MANIFEST.len() as u32
        }

        #[no_mangle]
        pub extern "C" fn on_http_request_headers() -> i32 {
            $hook()
        }
    };
}
