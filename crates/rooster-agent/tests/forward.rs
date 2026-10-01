//! 端口转发运行时集成测试:
//! TCP/UDP 回环转发、PROXY protocol v1/v2 收发、ACL、每 IP 限速与
//! 并发上限、热增删改不影响已有连接。全部走 127.0.0.1,端口随机分配。

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rooster_agent::forward::{ForwardRuntime, ForwardStats};
use rooster_agent::wasmrt::WasmRuntime;
use rooster_config::{AclConfig, ForwardLimits, ForwardProto, ForwardRule, ProxyProtocol, WasmPlugin};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

const TIMEOUT: Duration = Duration::from_secs(5);

// ---------------------------------------------------------------------------
// 辅助

/// 预留一个空闲端口(bind :0 后立即释放)。极小概率与并发用例竞争,
/// 失败时测试会以 bind error 暴露,可重跑。
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind ephemeral port")
        .local_addr()
        .expect("local addr")
        .port()
}

fn rule(id: &str, proto: ForwardProto, listen: SocketAddr, target: SocketAddr) -> ForwardRule {
    ForwardRule {
        id: id.to_string(),
        proto,
        listen,
        target: format!("{}:{}", target.ip(), target.port()),
        proxy_protocol: ProxyProtocol::None,
        udp_idle_timeout: None,
        accept_proxy_protocol: None,
        acl: None,
        limits: None,
        disabled: None,
    }
}

fn listen_on(port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], port))
}

/// 每 100ms 轮询断言,10s 内必须满足,否则 panic 并附描述。
async fn wait_until(desc: &str, mut cond: impl FnMut() -> bool) {
    for _ in 0..100 {
        if cond() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("condition not met within 10s: {desc}");
}

fn stat_for(rt: &ForwardRuntime, id: &str) -> Option<ForwardStats> {
    rt.stats().into_iter().find(|s| s.id == id)
}

/// TCP echo 上游(记录收到的全部字节)。
async fn echo_upstream() -> (SocketAddr, Arc<Mutex<Vec<u8>>>) {
    let l = TcpListener::bind("127.0.0.1:0").await.expect("bind upstream");
    let addr = l.local_addr().expect("upstream addr");
    let log = Arc::new(Mutex::new(Vec::new()));
    let log2 = log.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = l.accept().await else { return };
            let log = log2.clone();
            tokio::spawn(async move {
                let (mut r, mut w) = s.split();
                let mut buf = vec![0u8; 4096];
                loop {
                    match r.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            log.lock().unwrap().extend_from_slice(&buf[..n]);
                            if w.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    (addr, log)
}

/// 读满 n 字节(分多次 read),5s 超时。
async fn read_exact_timeout<S: AsyncReadExt + Unpin>(s: &mut S, n: usize) -> Vec<u8> {
    let mut out = vec![0u8; n];
    tokio::time::timeout(TIMEOUT, s.read_exact(&mut out))
        .await
        .expect("read within 5s")
        .expect("read ok");
    out
}

/// UDP echo 上游:原样回发给数据报来源。
async fn udp_echo_upstream() -> SocketAddr {
    let s = Arc::new(UdpSocket::bind("127.0.0.1:0").await.expect("bind udp upstream"));
    let addr = s.local_addr().expect("udp upstream addr");
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        loop {
            let Ok((n, from)) = s.recv_from(&mut buf).await else { return };
            let _ = s.send_to(&buf[..n], from).await;
        }
    });
    addr
}

async fn tcp_exchange(addr: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let mut c = TcpStream::connect(addr).await.expect("connect");
    c.write_all(payload).await.expect("write");
    read_exact_timeout(&mut c, payload.len()).await
}

/// TCP + UDP 同端口 echo 上游(TCP/UDP 端口空间独立):用于 TcpUdp 规则,
/// 一条规则的两个数据面指向同一 target,各自验证一次往返。
async fn dual_echo_upstream() -> SocketAddr {
    for _ in 0..16 {
        let l = TcpListener::bind("127.0.0.1:0").await.expect("bind tcp upstream");
        let addr = l.local_addr().expect("tcp upstream addr");
        let Ok(u) = UdpSocket::bind(("127.0.0.1", addr.port())).await else {
            continue; // UDP 侧端口冲突,换端口重试
        };
        tokio::spawn(async move {
            loop {
                let Ok((mut s, _)) = l.accept().await else { return };
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 4096];
                    loop {
                        match s.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                if s.write_all(&buf[..n]).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                });
            }
        });
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            loop {
                let Ok((n, from)) = u.recv_from(&mut buf).await else { return };
                let _ = u.send_to(&buf[..n], from).await;
            }
        });
        return addr;
    }
    panic!("cannot bind dual echo upstream");
}

// ---------------------------------------------------------------------------
// 1. TCP 基本转发 + 统计

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tcp_basic() {
    let (up, _log) = echo_upstream().await;
    let port = free_port();
    let rt = ForwardRuntime::new();
    rt.apply(vec![rule("t1", ForwardProto::Tcp, listen_on(port), up)]).await;

    let echoed = tcp_exchange(listen_on(port), b"hello rooster").await;
    assert_eq!(echoed, b"hello rooster", "payload must round-trip");
    // 等待规则计数赶上(连接任务退出后 conns_active 归零)。
    wait_until("stats drained", || {
        stat_for(&rt, "t1").map_or(false, |s| {
            s.listening && s.conns_total == 1 && s.conns_active == 0 && s.bytes_in > 0 && s.bytes_out > 0
        })
    })
    .await;
}

// ---------------------------------------------------------------------------
// 2. PROXY v1 发送:上游断言首行格式后再 echo。

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn proxy_v1_sent() {
    let l = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let up = l.local_addr().expect("addr");
    tokio::spawn(async move {
        let (mut s, _) = l.accept().await.expect("accept");
        let mut buf = Vec::new();
        let mut byte = [0u8; 1];
        // 读到 CRLF 为止(头先于业务数据)。
        loop {
            let n = s.read(&mut byte).await.expect("read header byte");
            assert_eq!(n, 1, "upstream eof inside header");
            buf.push(byte[0]);
            if buf.ends_with(b"\r\n") {
                break;
            }
            assert!(buf.len() <= 108, "v1 header longer than 108 bytes");
        }
        let line = String::from_utf8(buf.clone()).expect("ascii header");
        let toks: Vec<&str> = line.trim_end().split_whitespace().collect();
        assert_eq!(toks.len(), 6, "v1 header must have 6 fields: {line:?}");
        assert_eq!(toks[0], "PROXY");
        assert_eq!(toks[1], "TCP4");
        assert_eq!(toks[2], "127.0.0.1", "src must be real client ip");
        assert_eq!(toks[3], "127.0.0.1", "dst must be forward listen ip");
        let sport: u16 = toks[4].parse().expect("src port");
        assert!(sport > 0, "src port must be non-zero");
        // 头之后的第一段业务数据。
        let payload = read_exact_timeout(&mut s, 4).await;
        assert_eq!(payload, b"ping", "payload must follow the v1 header");
        // echo 回去
        let _ = s.write_all(b"pong").await;
    });

    let port = free_port();
    let rt = ForwardRuntime::new();
    let mut r = rule("p1", ForwardProto::Tcp, listen_on(port), up);
    r.proxy_protocol = ProxyProtocol::V1;
    rt.apply(vec![r]).await;

    let echoed = tcp_exchange(listen_on(port), b"ping").await;
    assert_eq!(echoed, b"pong");
}

// ---------------------------------------------------------------------------
// 3. PROXY v2 发送:上游断言 16 字节固定头 + 12 字节地址块。

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn proxy_v2_sent() {
    let l = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let up = l.local_addr().expect("addr");
    tokio::spawn(async move {
        let (mut s, _) = l.accept().await.expect("accept");
        let hdr = read_exact_timeout(&mut s, 16).await;
        let sig: [u8; 12] = hdr[..12].try_into().expect("sig");
        assert_eq!(
            sig,
            [0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A],
            "v2 signature"
        );
        assert_eq!(hdr[12], 0x21, "version=2, command=PROXY");
        assert_eq!(hdr[13], 0x11, "AF_INET | SOCK_STREAM");
        assert_eq!(u16::from_be_bytes([hdr[14], hdr[15]]), 12, "length=12");
        let block = read_exact_timeout(&mut s, 12).await;
        assert_eq!(&block[..4], &[127, 0, 0, 1], "src ip");
        assert_eq!(&block[4..8], &[127, 0, 0, 1], "dst ip");
        assert!(u16::from_be_bytes([block[8], block[9]]) > 0, "src port");
        // 固定应答:两次交换分别读 4 / 5 字节、回 "pong" / "pong2"。
        // 应答与请求内容、长度都不同,证明数据确实来自上游而非客户端回声。
        let p1 = read_exact_timeout(&mut s, 4).await;
        assert_eq!(p1, b"ping", "payload 1 must follow the v2 header");
        let _ = s.write_all(b"pong").await;
        let p2 = read_exact_timeout(&mut s, 5).await;
        assert_eq!(p2, b"ping2", "payload 2 after the first exchange");
        let _ = s.write_all(b"pong2").await;
        // 之后转纯 echo,连接保持到客户端关闭。
        let mut buf = vec![0u8; 4096];
        loop {
            match s.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if s.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            }
        }
    });

    let port = free_port();
    let rt = ForwardRuntime::new();
    let mut r = rule("p2", ForwardProto::Tcp, listen_on(port), up);
    r.proxy_protocol = ProxyProtocol::V2;
    rt.apply(vec![r]).await;

    // 两次写入都经同一条转发连接验证:头交换后连接保持双向可用,
    // 各自读回恰好等长的回显(第二次回显比请求长,覆盖读侧定长 bug)。
    let mut c = TcpStream::connect(listen_on(port)).await.expect("connect");
    c.write_all(b"ping").await.expect("write 1");
    assert_eq!(read_exact_timeout(&mut c, 4).await, b"pong", "first exchange");
    c.write_all(b"ping2").await.expect("write 2");
    assert_eq!(read_exact_timeout(&mut c, 5).await, b"pong2", "second exchange after v2 header");
}

// ---------------------------------------------------------------------------
// 4. 接收 PROXY v1:头中的真实源地址用于 ACL;头本身不透传。

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn accept_pp_v1() {
    let (up, log) = echo_upstream().await;
    let port = free_port();
    let rt = ForwardRuntime::new();
    let mut r = rule("a1", ForwardProto::Tcp, listen_on(port), up);
    r.accept_proxy_protocol = Some(true);
    // 只放行头部声明网段:证明 ACL 用的是头里的真实源地址,
    // 而非 socket peer 127.0.0.1(后者在 acl_deny 中被拒)。
    r.acl = Some(AclConfig { allow: vec!["10.0.0.0/8".to_string()] });
    rt.apply(vec![r]).await;

    let mut c = TcpStream::connect(listen_on(port)).await.expect("connect");
    // 头 + payload 一次写出,覆盖「多读出的前缀字节必须转交」的路径。
    let header = b"PROXY TCP4 10.0.0.9 10.0.0.1 11111 22222\r\n";
    let mut msg = header.to_vec();
    msg.extend_from_slice(b"payload-after-header");
    c.write_all(&msg).await.expect("write header+payload");
    let echoed = read_exact_timeout(&mut c, b"payload-after-header".len()).await;
    assert_eq!(echoed, b"payload-after-header");

    let received = log.lock().unwrap().clone();
    assert!(
        !received.starts_with(b"PROXY"),
        "header must be consumed, upstream got: {:?}",
        String::from_utf8_lossy(&received)
    );
    assert_eq!(received, b"payload-after-header");
}

// ---------------------------------------------------------------------------
// 5. ACL 拒绝:loopback 不在 allow 网段,连接被立即丢弃。

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn acl_deny() {
    let (up, _log) = echo_upstream().await;
    let port = free_port();
    let rt = ForwardRuntime::new();
    let mut r = rule("a2", ForwardProto::Tcp, listen_on(port), up);
    r.acl = Some(AclConfig { allow: vec!["10.0.0.0/8".to_string()] });
    rt.apply(vec![r]).await;

    let mut c = TcpStream::connect(listen_on(port)).await.expect("connect");
    let _ = c.write_all(b"let-me-in").await;
    let mut buf = [0u8; 16];
    match tokio::time::timeout(Duration::from_secs(2), c.read(&mut buf)).await {
        Ok(Ok(0)) => {}                     // 服务端 drop → EOF
        Ok(Err(_)) => {}                    // 或 RST
        Ok(Ok(n)) => panic!("denied conn must not receive data, got {n} bytes"),
        Err(_) => panic!("denied conn must close quickly, still open after 2s"),
    }
    wait_until("no counters for denied conn", || {
        stat_for(&rt, "a2").map_or(false, |s| s.conns_total == 0 && s.conns_active == 0)
    })
    .await;
}

// ---------------------------------------------------------------------------
// 6. max_conns_per_ip = 1:并发第二连接被丢,释放后第三连接放行。

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn max_conns_per_ip() {
    let (up, _log) = echo_upstream().await;
    let port = free_port();
    let fwd = listen_on(port);
    let rt = ForwardRuntime::new();
    let mut r = rule("m1", ForwardProto::Tcp, fwd, up);
    r.limits = Some(ForwardLimits { conn_rate: None, max_conns_per_ip: Some(1) });
    rt.apply(vec![r]).await;

    // 第一条:正常工作。
    let mut c1 = TcpStream::connect(fwd).await.expect("c1 connect");
    c1.write_all(b"one").await.expect("c1 write");
    assert_eq!(read_exact_timeout(&mut c1, 3).await, b"one");

    // 第二条并发:被丢弃(EOF,无 echo)。
    let mut c2 = TcpStream::connect(fwd).await.expect("c2 connect");
    let _ = c2.write_all(b"two").await;
    let mut buf = [0u8; 8];
    match tokio::time::timeout(Duration::from_secs(2), c2.read(&mut buf)).await {
        Ok(Ok(0)) | Ok(Err(_)) => {}
        Ok(Ok(n)) => panic!("c2 must be dropped, got {n} bytes"),
        Err(_) => panic!("c2 must be dropped quickly"),
    }

    // 关闭 c1 后名额释放,第三条允许。
    drop(c1);
    let mut ok = false;
    for _ in 0..100 {
        if let Ok(mut c3) = TcpStream::connect(fwd).await {
            if c3.write_all(b"three").await.is_ok() {
                if let Ok(Ok(n)) = tokio::time::timeout(Duration::from_secs(1), c3.read(&mut buf)).await {
                    if n == 5 && &buf[..n] == b"three" {
                        ok = true;
                        break;
                    }
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(ok, "third conn must be allowed after first closes");
}

// ---------------------------------------------------------------------------
// 7. 热删除保留已有连接。

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hot_reload_keeps_conn() {
    let (up, _log) = echo_upstream().await;
    let port = free_port();
    let fwd = listen_on(port);
    let rt = ForwardRuntime::new();
    rt.apply(vec![rule("h1", ForwardProto::Tcp, fwd, up)]).await;

    let mut c1 = TcpStream::connect(fwd).await.expect("connect");
    c1.write_all(b"before").await.expect("write");
    assert_eq!(read_exact_timeout(&mut c1, 6).await, b"before");

    // 删除规则:停止 accept,存量连接继续双向转发。
    rt.apply(vec![]).await;

    c1.write_all(b"after").await.expect("existing conn must still write");
    assert_eq!(read_exact_timeout(&mut c1, 5).await, b"after", "existing conn must still read");

    // 新连接被拒。
    let mut refused = false;
    for _ in 0..50 {
        if TcpStream::connect(fwd).await.is_err() {
            refused = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(refused, "new connects must be refused after rule removal");

    // 统计条目保留:listening=false,连接仍在。
    let s = stat_for(&rt, "h1").expect("stats entry must survive while conn is live");
    assert!(!s.listening, "removed rule must not be listening");
    assert!(s.conns_active >= 1, "existing conn still counted");

    // 连接结束后条目回收。
    drop(c1);
    wait_until("stats entry reaped after drain", || stat_for(&rt, "h1").is_none()).await;
}

// ---------------------------------------------------------------------------
// 8. 修改规则重新 bind:新连接到 B,旧连接继续到 A。

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rule_change_rebinds() {
    let (up_a, log_a) = echo_upstream().await;
    let (up_b, log_b) = echo_upstream().await;
    let port = free_port();
    let fwd = listen_on(port);
    let rt = ForwardRuntime::new();
    rt.apply(vec![rule("r1", ForwardProto::Tcp, fwd, up_a)]).await;

    let mut c1 = TcpStream::connect(fwd).await.expect("c1 connect");
    c1.write_all(b"to-a1").await.expect("c1 write");
    assert_eq!(read_exact_timeout(&mut c1, 5).await, b"to-a1");

    // 同 id 修改 target → 重建 listener,同端口重新 bind。
    rt.apply(vec![rule("r1", ForwardProto::Tcp, fwd, up_b)]).await;

    let echoed = tcp_exchange(fwd, b"to-b1").await;
    assert_eq!(echoed, b"to-b1", "new conn must reach target B");

    c1.write_all(b"to-a2").await.expect("old conn must still write");
    assert_eq!(read_exact_timeout(&mut c1, 5).await, b"to-a2", "old conn must still read");

    let a = log_a.lock().unwrap().clone();
    let b = log_b.lock().unwrap().clone();
    assert_eq!(a, b"to-a1to-a2", "upstream A must see only old conn traffic");
    assert_eq!(b, b"to-b1", "upstream B must see only new conn traffic");
}

// ---------------------------------------------------------------------------
// 9. UDP 往返。

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn udp_roundtrip() {
    let up = udp_echo_upstream().await;
    let port = free_port();
    let fwd = listen_on(port);
    let rt = ForwardRuntime::new();
    rt.apply(vec![rule("u1", ForwardProto::Udp, fwd, up)]).await;

    let c = UdpSocket::bind("127.0.0.1:0").await.expect("client bind");
    c.send_to(b"ping-udp", fwd).await.expect("send");
    let mut buf = [0u8; 64];
    let (n, from) = tokio::time::timeout(TIMEOUT, c.recv_from(&mut buf))
        .await
        .expect("udp reply within 5s")
        .expect("recv");
    assert_eq!(&buf[..n], b"ping-udp");
    assert_eq!(from, fwd, "reply must come from the forward listen addr");

    wait_until("udp stats", || {
        stat_for(&rt, "u1").map_or(false, |s| {
            s.udp_sessions >= 1 && s.conns_total >= 1 && s.bytes_in > 0 && s.bytes_out > 0
        })
    })
    .await;
}

// ---------------------------------------------------------------------------
// 10. UDP 空闲回收。

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn udp_idle_reap() {
    let up = udp_echo_upstream().await;
    let port = free_port();
    let fwd = listen_on(port);
    let rt = ForwardRuntime::new();
    let mut r = rule("u2", ForwardProto::Udp, fwd, up);
    r.udp_idle_timeout = Some(Duration::from_millis(300));
    rt.apply(vec![r]).await;

    let c = UdpSocket::bind("127.0.0.1:0").await.expect("client bind");
    c.send_to(b"once", fwd).await.expect("send");
    let mut buf = [0u8; 64];
    let (n, _) = tokio::time::timeout(TIMEOUT, c.recv_from(&mut buf))
        .await
        .expect("udp reply")
        .expect("recv");
    assert_eq!(&buf[..n], b"once");

    wait_until("udp session reaped after idle", || {
        stat_for(&rt, "u2").map_or(false, |s| s.udp_sessions == 0)
    })
    .await;
}

// ---------------------------------------------------------------------------
// 11. 连接速率限制:2/minute,窗口内第三连被拒。

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn conn_rate_limit() {
    let (up, _log) = echo_upstream().await;
    let port = free_port();
    let fwd = listen_on(port);
    let rt = ForwardRuntime::new();
    let mut r = rule("c1", ForwardProto::Tcp, fwd, up);
    r.limits = Some(ForwardLimits {
        conn_rate: Some("2/minute".to_string()),
        max_conns_per_ip: None,
    });
    rt.apply(vec![r]).await;

    assert_eq!(tcp_exchange(fwd, b"first").await, b"first");
    assert_eq!(tcp_exchange(fwd, b"second").await, b"second");

    // 窗口内第三连:被丢弃(EOF / RST,无 echo)。
    let mut c3 = TcpStream::connect(fwd).await.expect("c3 connect (agent accepted)");
    let _ = c3.write_all(b"third").await;
    let mut buf = [0u8; 8];
    match tokio::time::timeout(Duration::from_secs(2), c3.read(&mut buf)).await {
        Ok(Ok(0)) | Ok(Err(_)) => {}
        Ok(Ok(n)) => panic!("rate-limited conn must be dropped, got {n} bytes"),
        Err(_) => panic!("rate-limited conn must be dropped quickly"),
    }
    wait_until("third conn not counted", || {
        stat_for(&rt, "c1").map_or(false, |s| s.conns_total == 2 && s.conns_active == 0)
    })
    .await;
}

// ---------------------------------------------------------------------------
// 12. TcpUdp 合并统计 + shutdown 排空语义。
//
// shutdown() 只停 accept / 关监听;存量连接与 UDP 会话自然排空,
// 期间 ForwardStats 条目保留(listening=false)且计数器继续累加,
// 全部排空后条目才被回收。

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tcp_udp_merged_and_shutdown() {
    let up = dual_echo_upstream().await;
    let port = free_port();
    let fwd = listen_on(port);
    let rt = ForwardRuntime::new();
    let mut r = rule("x1", ForwardProto::TcpUdp, fwd, up);
    // UDP 会话空闲 300ms 即回收:排空阶段的确定性远小于 10s 轮询上限。
    r.udp_idle_timeout = Some(Duration::from_millis(300));
    rt.apply(vec![r]).await;

    let s = stat_for(&rt, "x1").expect("stats");
    assert_eq!(s.proto, "tcp+udp");
    assert!(s.listening, "both listeners bound");

    // TCP 侧:建立并保持一条连接(不关闭)。
    let mut c1 = TcpStream::connect(fwd).await.expect("tcp connect");
    c1.write_all(b"tp").await.expect("tcp write");
    assert_eq!(read_exact_timeout(&mut c1, 2).await, b"tp");

    // UDP 侧:同一条规则、同一 target 的另一个数据面往返。
    let u = UdpSocket::bind("127.0.0.1:0").await.expect("client bind");
    u.send_to(b"up", fwd).await.expect("udp send");
    let mut buf = [0u8; 64];
    let (n, from) = tokio::time::timeout(TIMEOUT, u.recv_from(&mut buf))
        .await
        .expect("udp reply within 5s")
        .expect("recv");
    assert_eq!(&buf[..n], b"up");
    assert_eq!(from, fwd, "udp reply must come from the forward listen addr");

    // 合并统计:TCP 并发与 UDP 会话分别计数,字节数两侧都在涨。
    wait_until("merged stats", || {
        stat_for(&rt, "x1").map_or(false, |s| {
            s.conns_active >= 1 && s.udp_sessions >= 1 && s.bytes_in > 0 && s.bytes_out > 0
        })
    })
    .await;

    rt.shutdown().await;

    let s = stat_for(&rt, "x1").expect("stats entry must survive shutdown while conns drain");
    assert!(!s.listening, "shutdown stops accept");
    assert!(s.conns_active >= 1, "live tcp conn still counted after shutdown");
    // UDP 会话随监听 socket 一起终止(SessionMap::drop):没有监听 socket
    // 就无法把上游回包送回客户端,会话不可能继续服务,因此 shutdown 时
    // 立即归零(「UDP 会话已排空」);只有 TCP 连接自然排空。
    assert_eq!(s.udp_sessions, 0, "udp sessions are torn down with the listener");

    // 新连接被拒。
    let mut refused = false;
    for _ in 0..50 {
        if TcpStream::connect(fwd).await.is_err() {
            refused = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(refused, "new connects refused after shutdown");

    // 排空:TCP 连接关闭立即结束;UDP 会话已在 shutdown 时终止;
    // 两者都归零后统计条目才消失。
    drop(c1);
    drop(u);
    wait_until("stats entry reaped after drain", || stat_for(&rt, "x1").is_none()).await;
}

// ---------------------------------------------------------------------------
// 13. B6:on_l4_accept 插件按对端拒连(真实 accept 路径)

/// 插件:conn_peer 以 "10.0.0.9" 开头 → Deny(1),否则 Continue(0)。
/// 对端经 accept-proxy-protocol 头注入,可精确区分“特定对端”。
const L4_PEER_DENY_WAT: &str = r#"
(module
  (import "env" "rooster_conn_peer" (func $peer (param i32 i32) (result i32)))
  (memory (export "memory") 1)
  (data (i32.const 0) "{\"n\":1}")
  (func (export "rooster_manifest_ptr") (result i32) (i32.const 0))
  (func (export "rooster_manifest_len") (result i32) (i32.const 7))
  (func (export "on_l4_accept") (result i32)
    (local $deny i32)
    (local.set $deny (i32.const 1))
    (drop (call $peer (i32.const 64) (i32.const 128)))
    ;; "10.0.0.9" 逐字节前缀比较('1''0''.''0''.''0''.''9')
    (if (i32.ne (i32.load8_u (i32.const 64)) (i32.const 49)) (then (local.set $deny (i32.const 0))))
    (if (i32.ne (i32.load8_u (i32.const 65)) (i32.const 48)) (then (local.set $deny (i32.const 0))))
    (if (i32.ne (i32.load8_u (i32.const 66)) (i32.const 46)) (then (local.set $deny (i32.const 0))))
    (if (i32.ne (i32.load8_u (i32.const 67)) (i32.const 48)) (then (local.set $deny (i32.const 0))))
    (if (i32.ne (i32.load8_u (i32.const 68)) (i32.const 46)) (then (local.set $deny (i32.const 0))))
    (if (i32.ne (i32.load8_u (i32.const 69)) (i32.const 48)) (then (local.set $deny (i32.const 0))))
    (if (i32.ne (i32.load8_u (i32.const 70)) (i32.const 46)) (then (local.set $deny (i32.const 0))))
    (if (i32.ne (i32.load8_u (i32.const 71)) (i32.const 57)) (then (local.set $deny (i32.const 0))))
    (local.get $deny))
)
"#;

/// B6 回归:on_l4_accept 必须真正挂在 forward accept 路径上:被点名的
/// 对端连接被拒(数据不到上游、不计数),其他对端照常转发。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn l4_accept_plugin_denies_peer_on_forward_path_b6() {
    let (up, log) = echo_upstream().await;
    let port = free_port();
    let fwd = listen_on(port);

    let wasm = WasmRuntime::new();
    let file = std::env::temp_dir().join(format!("rooster-fwd-l4-{}.wat", std::process::id()));
    std::fs::write(&file, L4_PEER_DENY_WAT).unwrap();
    wasm.reconfigure(
        &[WasmPlugin {
            id: "deny-10-0-0-9".to_string(),
            file: file.clone(),
            hooks: vec!["on_l4_accept".to_string()],
            sites: vec![],
            limits: None,
            on_error: None,
            config: None,
        }],
        |_| Some(file.clone()),
    );
    assert_eq!(
        wasm.plugin_status("deny-10-0-0-9"),
        "loaded",
        "{:?}",
        wasm.load_errors.lock().unwrap()
    );

    let rt = ForwardRuntime::new();
    // set_plugins 是快照式(只影响之后 start_rule 的监听任务):必须先于 apply。
    rt.set_plugins(Arc::new(wasm), None);
    let mut r = rule("w6", ForwardProto::Tcp, fwd, up);
    r.accept_proxy_protocol = Some(true); // 用 PROXY 头携带“真实对端”
    rt.apply(vec![r]).await;

    // 放行对端 10.0.0.8:PROXY 头被消费,payload 完整往返。
    let mut good = TcpStream::connect(fwd).await.expect("good connect");
    good.write_all(b"PROXY TCP4 10.0.0.8 10.0.0.1 11111 22222\r\ngood-payload")
        .await
        .expect("good write");
    assert_eq!(
        read_exact_timeout(&mut good, b"good-payload".len()).await,
        b"good-payload"
    );
    drop(good);

    // 被拒对端 10.0.0.9:连接被丢弃,数据永不达上游。
    let mut bad = TcpStream::connect(fwd).await.expect("bad connect");
    let _ = bad
        .write_all(b"PROXY TCP4 10.0.0.9 10.0.0.1 11111 22222\r\nbad-payload")
        .await;
    let mut buf = [0u8; 16];
    match tokio::time::timeout(Duration::from_secs(2), bad.read(&mut buf)).await {
        Ok(Ok(0)) | Ok(Err(_)) => {}
        Ok(Ok(n)) => panic!("denied conn must not receive data, got {n} bytes"),
        Err(_) => panic!("denied conn must close quickly"),
    }

    // 只有放行连接计数并到达上游;被拒连接不计数、不留数据。
    wait_until("denied conn not counted", || {
        stat_for(&rt, "w6").map_or(false, |s| s.conns_total == 1 && s.conns_active == 0)
    })
    .await;
    assert_eq!(
        log.lock().unwrap().clone(),
        b"good-payload",
        "上游必须只见放行对端的业务数据(PROXY 头已消费)"
    );
}
