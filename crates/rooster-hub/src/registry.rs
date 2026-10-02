//! 在线节点连接注册表:node_id → 长连接发送端 + 请求多路复用。

use rooster_proto::Frame;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;
use tokio::sync::{mpsc, oneshot, watch};

/// 一条已建立的 Agent 长连接的 Hub 侧句柄。
pub struct Conn {
    node_id: String,
    peer_ip: Option<IpAddr>,
    tx: mpsc::UnboundedSender<Frame>,
    pending: Mutex<HashMap<u64, oneshot::Sender<Frame>>>,
    next_id: AtomicU64,
    /// 挂断信号:被新连接替换或节点被吊销时置位。用 watch 而非 Notify,
    /// 是因为挂断发生在会话循环开始 select 之前也必须能终止它(watch
    /// 保留历史值;Notify 的 permit 会被早已退出的等待者吃掉)。
    hangup_tx: watch::Sender<bool>,
    /// 与 hangup_tx 同时创建的接收端:clone 出去的 receiver 尚未“看过”
    /// 任何置位,所以 changed() 对任意时点的 hang_up 都会立即返回。
    hangup_rx: watch::Receiver<bool>,
}

#[derive(Debug, thiserror::Error)]
pub enum RequestError {
    #[error("node {0} is offline")]
    Offline(String),
    #[error("node connection closed before responding")]
    Closed,
    #[error("passthrough timed out")]
    Timeout,
}

impl Conn {
    pub fn new(node_id: &str, tx: mpsc::UnboundedSender<Frame>) -> Arc<Self> {
        Self::new_with_peer_ip(node_id, tx, None)
    }

    pub fn new_with_peer_ip(
        node_id: &str,
        tx: mpsc::UnboundedSender<Frame>,
        peer_ip: Option<IpAddr>,
    ) -> Arc<Self> {
        let (hangup_tx, hangup_rx) = watch::channel(false);
        Arc::new(Self {
            node_id: node_id.to_string(),
            peer_ip,
            tx,
            pending: Mutex::new(HashMap::new()),
            next_id: AtomicU64::new(1),
            hangup_tx,
            hangup_rx,
        })
    }

    pub fn node_id(&self) -> &str {
        &self.node_id
    }

    pub fn peer_ip(&self) -> Option<IpAddr> {
        self.peer_ip
    }

    /// 要求该连接立即退出(仅移除注册表项并不会关 socket:会话循环自己
    /// 持有 tx/hb_tx,rx 不会关闭)。
    pub fn hang_up(&self) {
        let _ = self.hangup_tx.send(true);
    }

    /// 会话循环在 select 里等待的挂断通知。
    pub fn subscribe_hangup(&self) -> watch::Receiver<bool> {
        self.hangup_rx.clone()
    }

    /// 发送一帧(不需要响应的:GlobalBan / EventAck / Upgrade 等)。
    pub fn send(&self, frame: Frame) -> Result<(), RequestError> {
        self.tx.send(frame).map_err(|_| RequestError::Closed)
    }

    fn alloc_id(&self) -> u64 {
        self.next_id.fetch_add(1, Ordering::Relaxed)
    }

    /// 发送带 id 的请求帧并等待同 id 响应(默认 10s 超时)。
    async fn request(&self, frame: Frame, timeout: Duration) -> Result<Frame, RequestError> {
        let id = match &frame {
            Frame::ApiRequest { id, .. } | Frame::ApplyTemplate { id, .. } => *id,
            _ => return Err(RequestError::Closed),
        };
        let (tx, rx) = oneshot::channel();
        self.pending.lock().unwrap().insert(id, tx);
        if self.tx.send(frame).is_err() {
            self.pending.lock().unwrap().remove(&id);
            return Err(RequestError::Closed);
        }
        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(resp)) => Ok(resp),
            Ok(Err(_)) => Err(RequestError::Closed),
            Err(_) => {
                self.pending.lock().unwrap().remove(&id);
                Err(RequestError::Timeout)
            }
        }
    }

    /// 收到响应帧时完成对应的 oneshot;返回是否有人还在等。
    pub fn complete(&self, id: u64, frame: Frame) -> bool {
        match self.pending.lock().unwrap().remove(&id) {
            Some(tx) => tx.send(frame).is_ok(),
            None => false,
        }
    }

    /// 构造 ApiRequest 并等待 ApiResponse(透传)。
    pub async fn api_request(
        &self,
        method: &str,
        path: &str,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
        timeout: Duration,
    ) -> Result<(u16, Vec<(String, String)>, Vec<u8>), RequestError> {
        let frame = Frame::ApiRequest {
            id: self.alloc_id(),
            method: method.to_string(),
            path: path.to_string(),
            headers,
            body,
        };
        match self.request(frame, timeout).await? {
            Frame::ApiResponse {
                status,
                headers,
                body,
                ..
            } => Ok((status, headers, body)),
            _ => Err(RequestError::Closed),
        }
    }

    /// 下发模板并等待 TemplateResult。
    pub async fn apply_template(&self, yaml: String, timeout: Duration) -> Result<Frame, RequestError> {
        let frame = Frame::ApplyTemplate {
            id: self.alloc_id(),
            yaml,
        };
        self.request(frame, timeout).await
    }
}

/// 全部在线连接;断开时由 ws 任务清理。
#[derive(Default)]
pub struct Registry {
    conns: RwLock<HashMap<String, Arc<Conn>>>,
}

impl Registry {
    pub fn register(&self, node_id: &str, conn: Arc<Conn>) {
        // 同一节点重复连接:新连接替换旧连接,并显式挂断旧的——旧会话
        // 自己持有发送端,不挂断就会双活抢帧。
        if let Some(old) = self.conns.write().unwrap().insert(node_id.to_string(), conn) {
            old.hang_up();
        }
    }

    /// 会话退出时摘除自己的连接:仅当表项仍是本会话(同一 Arc)才删。
    /// 否则分区重连场景下旧会话超时会把新建立的连接误标为离线,而 Agent
    /// 自己心跳正常永不自愈,透传/封禁/模板/升级全部默默丢投。
    pub fn unregister(&self, node_id: &str, conn: &Arc<Conn>) -> bool {
        let mut conns = self.conns.write().unwrap();
        match conns.get(node_id) {
            Some(current) if Arc::ptr_eq(current, conn) => conns.remove(node_id).is_some(),
            _ => false,
        }
    }

    /// 无条件摘除并挂断(管理员吊销节点用):不区分是哪一条连接,
    /// 摘除后存活会话必须立刻退出,否则吊销过的 socket 还能继续上报。
    pub fn disconnect(&self, node_id: &str) {
        if let Some(conn) = self.conns.write().unwrap().remove(node_id) {
            conn.hang_up();
        }
    }

    pub fn get(&self, node_id: &str) -> Option<Arc<Conn>> {
        self.conns.read().unwrap().get(node_id).cloned()
    }

    pub fn online_ids(&self) -> Vec<String> {
        self.conns.read().unwrap().keys().cloned().collect()
    }

    pub fn is_online(&self, node_id: &str) -> bool {
        self.conns.read().unwrap().contains_key(node_id)
    }

    /// 广播到全部在线节点;返回发送失败的节点(视为即将离线)。
    pub fn broadcast(&self, frame: Frame) -> Vec<String> {
        let mut failed = Vec::new();
        for (id, conn) in self.conns.read().unwrap().iter() {
            if conn.send(frame.clone()).is_err() {
                failed.push(id.clone());
            }
        }
        failed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unregister_only_removes_the_current_session() {
        // 分区重连:旧会话退出不得摘掉接管它的新连接(否则节点会被永久判离线)。
        let (tx1, _rx1) = mpsc::unbounded_channel();
        let (tx2, _rx2) = mpsc::unbounded_channel();
        let old = Conn::new("n1", tx1);
        let fresh = Conn::new("n1", tx2);
        let reg = Registry::default();
        reg.register("n1", old.clone());
        reg.register("n1", fresh.clone());

        assert!(!reg.unregister("n1", &old), "stale session must not evict the live one");
        assert!(reg.get("n1").is_some());
        assert!(reg.unregister("n1", &fresh));
        assert!(reg.get("n1").is_none());
    }

    #[tokio::test]
    async fn request_multiplexes_and_times_out() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let conn = Conn::new("n1", tx);
        let reg = Registry::default();
        reg.register("n1", conn.clone());

        // 模拟 Agent:收到 ApiRequest 后立即完成 pending oneshot
        // (真实链路中是 ws 读循环调 conn.complete)。
        let responder = {
            let conn = conn.clone();
            tokio::spawn(async move {
                while let Some(frame) = rx.recv().await {
                    if let Frame::ApiRequest { id, .. } = frame {
                        conn.complete(
                            id,
                            Frame::ApiResponse {
                                id,
                                status: 200,
                                headers: vec![],
                                body: b"ok".to_vec(),
                            },
                        );
                    }
                }
            })
        };

        let (status, _, body) = reg
            .get("n1")
            .unwrap()
            .api_request("GET", "/x", vec![], vec![], Duration::from_secs(1))
            .await
            .unwrap();
        assert_eq!(status, 200);
        assert_eq!(body, b"ok");
        assert!(!reg.is_online("n2"));
        responder.abort();

        // 无响应 → 超时。
        let (tx2, _rx2) = mpsc::unbounded_channel();
        let silent = Conn::new("n2", tx2);
        assert!(matches!(
            silent
                .api_request("GET", "/x", vec![], vec![], Duration::from_millis(20))
                .await,
            Err(RequestError::Timeout)
        ));
    }

    #[test]
    fn broadcast_reports_failed_senders() {
        let reg = Registry::default();
        let (tx, _rx) = mpsc::unbounded_channel();
        reg.register("alive", Conn::new("alive", tx));
        // 没有接收端读也不影响 unbounded send;失败只在对端 drop 时发生。
        let failed = reg.broadcast(Frame::Ping);
        assert!(failed.is_empty());
        assert_eq!(reg.online_ids(), vec!["alive".to_string()]);
    }

    #[test]
    fn register_replacement_and_disconnect_hang_up_old_conn() {
        let (tx1, _rx1) = mpsc::unbounded_channel();
        let (tx2, _rx2) = mpsc::unbounded_channel();
        let old = Conn::new("n1", tx1);
        let fresh = Conn::new("n1", tx2);
        let reg = Registry::default();
        reg.register("n1", old.clone());
        let h1 = old.subscribe_hangup();
        let h2 = fresh.subscribe_hangup();
        assert!(!*h1.borrow() && !*h2.borrow());

        reg.register("n1", fresh.clone());
        // 替换即挂断:旧会话不得与新会话双活。
        assert!(*h1.borrow(), "replaced conn must be hung up");
        assert!(!*h2.borrow(), "incoming conn must not be hung up");

        reg.disconnect("n1");
        assert!(*h2.borrow(), "disconnect must hang up the removed conn");
        assert!(reg.get("n1").is_none());
    }

    #[tokio::test]
    async fn disconnect_wakes_the_session_loop() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let conn = Conn::new("n", tx);
        let reg = Registry::default();
        reg.register("n", conn.clone());
        // 会话循环的等价物:select 里等待 hangup.changed()。
        let mut hangup = conn.subscribe_hangup();
        let watcher =
            tokio::spawn(async move { hangup.changed().await.is_ok() });
        tokio::time::sleep(Duration::from_millis(10)).await;
        reg.disconnect("n");
        let woke = tokio::time::timeout(Duration::from_secs(1), watcher)
            .await
            .expect("hangup must wake the session loop")
            .unwrap();
        assert!(woke);
    }

    /// 挂断早于会话循环开始轮询(吊销与重连竞争时序)也必须立即终止它:
    /// watch 保留历史值,这正是选 watch 而不是 Notify 的原因。
    #[tokio::test]
    async fn hangup_raised_before_polling_still_terminates() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let conn = Conn::new("n", tx);
        conn.hang_up();
        let mut hangup = conn.subscribe_hangup();
        assert!(
            tokio::time::timeout(Duration::from_millis(100), hangup.changed())
                .await
                .is_ok(),
            "a hang-up raised before subscribe must still fire"
        );
    }
}
