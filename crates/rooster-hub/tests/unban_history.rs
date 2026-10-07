use axum::body::Body;
use axum::http::{Request, StatusCode};
use rooster_hub::{config, pki, registry::Conn, store, HubState};
use rooster_proto::Frame;
use std::sync::{Arc, Mutex};
use tower::ServiceExt;

async fn unban_case(
    get_status: u16,
    body: &[u8],
    delete_status: u16,
    broken_history: bool,
    expected_status: StatusCode,
    expected_start: Option<u64>,
) {
    let dir = std::env::temp_dir().join(format!("rooster-unban-{}-{}", std::process::id(), rand::random::<u64>()));
    std::fs::create_dir_all(&dir).unwrap();
    let db_path = dir.join("hub.redb");
    let db = if broken_history {
        let db = redb::Database::create(&db_path).unwrap();
        let txn = db.begin_write().unwrap();
        {
            // A type mismatch forces a real storage error without a production fault-injection hook.
            txn.open_table(redb::TableDefinition::<&str, u64>::new("node_ban_history")).unwrap();
        }
        txn.commit().unwrap();
        db
    } else {
        store::open(&db_path).unwrap()
    };
    let store = store::Store::new(db);
    store.insert_session("session", store::now_secs() + 60).unwrap();
    let cfg = serde_norway::from_str(&config::default_hub_config_template()).unwrap();
    let (events_tx, _) = tokio::sync::broadcast::channel(8);
    let state = Arc::new(HubState {
        cfg,
        store,
        pki: pki::HubPki::ensure(&dir).unwrap(),
        registry: Default::default(),
        policy: Default::default(),
        login_gate: Default::default(),
        events_tx,
        recent: Default::default(),
    });
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let conn = Conn::new("node-a", tx);
    state.registry.register("node-a", conn.clone());
    let methods = Arc::new(Mutex::new(Vec::new()));
    let seen = methods.clone();
    let agent_state = state.clone();
    let body = body.to_vec();
    let agent = tokio::spawn(async move {
        while let Some(Frame::ApiRequest { id, method, .. }) = rx.recv().await {
            seen.lock().unwrap().push(method.clone());
            let (status, response) = if method == "GET" {
                (get_status, body.clone())
            } else {
                let records = agent_state.store.list_node_ban_history("node-a", 10).unwrap();
                assert_eq!(records.len(), 1, "snapshot must commit before DELETE is sent");
                assert_eq!(records[0].started_at, expected_start);
                assert_eq!(records[0].removed_at, None, "remote deletion is not yet confirmed");
                (delete_status, Vec::new())
            };
            assert!(conn.complete(id, Frame::ApiResponse {
                id, status, headers: vec![], body: response,
            }));
        }
    });
    let response = rooster_hub::api::router(state.clone()).oneshot(
        Request::builder()
            .method("DELETE")
            .uri("/v0/nodes/node-a/management/bans/203.0.113.7")
            .header("authorization", "Bearer session")
            .body(Body::empty()).unwrap(),
    ).await.unwrap();
    assert_eq!(response.status(), expected_status);
    let observed = methods.lock().unwrap().clone();
    if expected_status == StatusCode::NO_CONTENT || expected_status == StatusCode::SERVICE_UNAVAILABLE {
        assert_eq!(observed, vec!["GET", "DELETE"]);
        let records = state.store.list_node_ban_history("node-a", 10).unwrap();
        assert_eq!(records[0].started_at, expected_start);
        assert_eq!(records[0].removed_at.is_some(), delete_status == 204);
    } else {
        assert_eq!(observed, vec!["GET"], "failed snapshot must prevent DELETE");
    }
    agent.abort();
    let _ = agent.await;
    drop(state);
    let reopened = store::Store::new(redb::Database::create(&db_path).unwrap());
    if matches!(expected_status, StatusCode::NO_CONTENT | StatusCode::SERVICE_UNAVAILABLE) {
        let records = reopened.list_node_ban_history("node-a", 10).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].removed_at.is_some(), delete_status == 204);
    }
    drop(reopened);
    std::fs::remove_dir_all(dir).unwrap();
}

const BAN: &[u8] = br#"{"bans":[{"ip":"203.0.113.7","reason":"honeypot","plugin":"honeypot","scope":"local","started_at":100,"expires_at":4000,"ttl_secs":1800}]}"#;

#[tokio::test]
async fn unban_snapshot_precedes_delete_and_keeps_true_start() {
    unban_case(200, BAN, 204, false, StatusCode::NO_CONTENT, Some(100)).await;
}

#[tokio::test]
async fn legacy_agent_start_is_unknown_not_query_time() {
    let body = br#"{"bans":[{"ip":"203.0.113.7","expires_at":4000,"ttl_secs":1800}]}"#;
    unban_case(200, body, 204, false, StatusCode::NO_CONTENT, None).await;
}

#[tokio::test]
async fn failed_ban_read_prevents_delete() {
    unban_case(503, b"{}", 204, false, StatusCode::BAD_GATEWAY, None).await;
}

#[tokio::test]
async fn malformed_ban_list_prevents_delete() {
    unban_case(200, b"not json", 204, false, StatusCode::BAD_GATEWAY, None).await;
}

#[tokio::test]
async fn failed_snapshot_write_prevents_delete() {
    unban_case(200, BAN, 204, true, StatusCode::INTERNAL_SERVER_ERROR, Some(100)).await;
}

#[tokio::test]
async fn failed_remote_delete_keeps_unconfirmed_snapshot_across_reopen() {
    unban_case(200, BAN, 503, false, StatusCode::SERVICE_UNAVAILABLE, Some(100)).await;
}
