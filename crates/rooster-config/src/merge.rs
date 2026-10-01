//! 分层合并。
//!
//! 规则:
//! - map:递归合并,冲突时 local 为准;
//! - 列表元素均含字符串 `id` 字段:按 id 合并,同 id 时 local 整项覆盖
//!   (因此 local 中 `{ id: x, disabled: true }` 可屏蔽模板项);
//! - 其他列表:取并集(managed 全保留 + local 中 managed 没有的项);
//! - 标量:local 覆盖,local 缺失(`null`)时沿用 managed。

use serde_json::Value;

pub fn merge_values(managed: &Value, local: &Value) -> Value {
    match (managed, local) {
        (Value::Object(m), Value::Object(l)) => {
            let mut out = m.clone();
            for (k, lv) in l {
                let merged = match out.get(k) {
                    Some(mv) => merge_values(mv, lv),
                    None => lv.clone(),
                };
                out.insert(k.clone(), merged);
            }
            Value::Object(out)
        }
        (Value::Array(m), Value::Array(l)) => {
            if elements_have_id(m) && elements_have_id(l) {
                Value::Array(merge_by_id(m, l))
            } else {
                Value::Array(union(m, l))
            }
        }
        // local 未设置(null):沿用 managed。
        (managed, Value::Null) => managed.clone(),
        (_, local) => local.clone(),
    }
}

fn elements_have_id(items: &[Value]) -> bool {
    !items.is_empty()
        && items.iter().all(|v| {
            matches!(v, Value::Object(m) if m.get("id").is_some_and(|id| id.is_string()))
        })
}

fn id_of(v: &Value) -> Option<&str> {
    v.get("id").and_then(Value::as_str)
}

fn merge_by_id(managed: &[Value], local: &[Value]) -> Vec<Value> {
    let mut out = managed.to_vec();
    for lv in local {
        let Some(lid) = id_of(lv) else { continue };
        match out.iter().position(|mv| id_of(mv) == Some(lid)) {
            Some(i) => out[i] = lv.clone(),
            None => out.push(lv.clone()),
        }
    }
    out
}

fn union(managed: &[Value], local: &[Value]) -> Vec<Value> {
    let mut out = managed.to_vec();
    for lv in local {
        if !out.contains(lv) {
            out.push(lv.clone());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn map_recursive_local_wins() {
        let managed = json!({"a": {"x": 1, "y": 2}, "b": 1});
        let local = json!({"a": {"y": 3}});
        assert_eq!(
            merge_values(&managed, &local),
            json!({"a": {"x": 1, "y": 3}, "b": 1})
        );
    }

    #[test]
    fn null_local_keeps_managed() {
        let managed = json!({"a": 1});
        let local = json!({"a": null});
        assert_eq!(merge_values(&managed, &local), json!({"a": 1}));
    }

    #[test]
    fn id_lists_merge_by_id() {
        let managed = json!([{"id": "a", "port": 1}, {"id": "b", "port": 2}]);
        let local = json!([{"id": "b", "port": 9}, {"id": "c"}]);
        let merged = merge_values(&managed, &local);
        let ids: Vec<&str> = merged
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v["id"].as_str().unwrap())
            .collect();
        assert_eq!(ids, ["a", "b", "c"]);
        assert_eq!(merged[1]["port"], 9);
    }

    #[test]
    fn plain_lists_union() {
        let managed = json!(["10.0.0.0/8"]);
        let local = json!(["10.0.0.0/8", "192.168.0.0/16"]);
        assert_eq!(
            merge_values(&managed, &local),
            json!(["10.0.0.0/8", "192.168.0.0/16"])
        );
    }
}
