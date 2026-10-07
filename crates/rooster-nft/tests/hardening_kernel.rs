//! 真内核加固规则测试 —— 只在独立网络命名空间里运行,显式触发:
//!
//! ```sh
//! ROOSTER_NFT_HOST_NETNS="$(readlink /proc/self/ns/net)" \
//!   unshare -Urn env ROOSTER_NFT_KTEST=1 \
//!   cargo test -p rooster-nft --test hardening_kernel -- --ignored --test-threads=1
//! ```
//!
//! 三重护栏:`#[ignore]` 显式选择、`ROOSTER_NFT_KTEST=1`、且当前 netns 必须
//! 与 init netns 不同(`/proc/self/ns/net` vs `/proc/1/ns/net`)—— 宿主网络
//! 栈上一条规则都不会碰。
//!
//! 数据面:veth 对 r0→r1 上用 AF_PACKET 注入手工构造的 SYN/ACK(带正确
//! 校验和,conntrack 会做真实状态机推进),内核 INPUT 钩子真实求值加固
//! 规则。交付断言用 raw IP 套接字:`ip_local_deliver_finish` 在 netfilter
//! INPUT 之后,被 drop 的包到不了 raw 套接字。本机地址只配 /32(/128),
//! 对注入源无路由 → 内核对关闭端口的 RST/SYN-ACK 发不出去,不产生二次
//! INPUT 噪声;rp_filter 清零避免反向路径校验丢包。

use rooster_nft::builders::{
    build_hardening_chain_rules, build_hardening_chains_create, hardening_chains, HardeningSpec,
    SET_HP_V4, SET_L4HIT_V4, SET_L4METER_V4, SET_SCANPORTS_V4, SET_SCANPORTS_V6, Seq,
};
use rooster_nft::NftHandle;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant};

const TCP_FIN: u8 = 0x01;
const TCP_SYN: u8 = 0x02;
const TCP_ACK: u8 = 0x10;
const TCP_SYNACK: u8 = TCP_SYN | TCP_ACK;
const TCP_PSHACK: u8 = 0x08 | TCP_ACK;
const EEXIST: i32 = 17;

// ---------- 护栏 ----------

fn ktest_ready() -> Result<(), String> {
    if std::env::var("ROOSTER_NFT_KTEST").ok().as_deref() != Some("1") {
        return Err("set ROOSTER_NFT_KTEST=1 (explicit opt-in)".into());
    }
    if unsafe { libc::geteuid() } != 0 {
        return Err("need euid 0 in the test netns (run under unshare -Urn)".into());
    }
    // User-namespace isolation alone does not prove network-namespace isolation.
    let own = std::fs::read_link("/proc/self/ns/net").map_err(|e| e.to_string())?;
    let host = std::env::var_os("ROOSTER_NFT_HOST_NETNS")
        .map(std::path::PathBuf::from)
        .or_else(|| std::fs::read_link("/proc/1/ns/net").ok())
        .ok_or("cannot prove netns isolation; set ROOSTER_NFT_HOST_NETNS before unshare")?;
    if own == host {
        return Err("refusing to mutate host nftables (use unshare -Urn)".into());
    }
    Ok(())
}

fn only_in_netns() -> bool {
    if std::env::var("ROOSTER_NFT_KTEST").ok().as_deref() == Some("1") {
        ktest_ready().expect("explicit kernel tests require a proven isolated network namespace");
        return true;
    }
    match ktest_ready() {
        Ok(()) => true,
        Err(e) => {
            eprintln!("skipping: {e}");
            false
        }
    }
}

/// 所有测试共享同一个 netns 里的 `table inet rooster`,必须串行。
fn table_lock() -> MutexGuard<'static, ()> {
    static M: OnceLock<Mutex<()>> = OnceLock::new();
    M.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|p| p.into_inner())
}

fn fresh_table() -> NftHandle {
    let h = NftHandle::open().expect("open netlink");
    h.delete_table().ok();
    h.ensure_table().expect("ensure_table");
    h
}

// ---------- 网络夹具:veth 对 + AF_PACKET 注入 + raw 交付断言 ----------

struct Net {
    r0_ifindex: i32,
    mac_r0: [u8; 6],
    mac_r1: [u8; 6],
    pkt_fd: i32,
}

static NET: OnceLock<Result<Net, String>> = OnceLock::new();

fn net() -> &'static Result<Net, String> {
    let result = NET.get_or_init(setup_net);
    assert!(result.is_ok(), "kernel network fixture failed: {:?}", result.as_ref().err());
    result
}

/// ioctl 取 ifindex / MAC(/sys 在未 remount 的 userns 里看不到新 netns 的类网条目)。
fn if_ioctl<T>(req: u64, name: &str, take: impl Fn(&libc::ifreq) -> T) -> Result<T, String> {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err("udp socket for ioctl".into());
    }
    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
    for (i, b) in name.as_bytes().iter().take(15).enumerate() {
        ifr.ifr_name[i] = *b as libc::c_char;
    }
    let r = unsafe { libc::ioctl(fd, req, &mut ifr) };
    let out = if r == 0 { Ok(take(&ifr)) } else { Err(format!("ioctl {name}")) };
    unsafe { libc::close(fd) };
    out
}

fn setup_net() -> Result<Net, String> {
    let ip = |args: &[&str]| -> Result<(), String> {
        let st = std::process::Command::new("ip")
            .args(args)
            .status()
            .map_err(|e| format!("ip {:?}: {e} (iproute2 required)", args))?;
        if st.success() {
            Ok(())
        } else {
            Err(format!("ip {:?} failed: {st}", args))
        }
    };
    let _ = ip(&["link", "del", "r0"]); // 重跑残留(成对删除)
    ip(&["link", "add", "r0", "type", "veth", "peer", "name", "r1"])?;
    ip(&["link", "set", "r0", "up"])?;
    ip(&["link", "set", "r1", "up"])?;
    // 本机只认单地址:对注入源无路由,内核的 RST/SYN-ACK 出不去。
    ip(&["addr", "add", "10.9.0.1/32", "dev", "r1"])?;
    ip(&["-6", "addr", "add", "2001:db8:ffff::1/128", "dev", "r1", "nodad"])?;
    for p in ["all", "default", "r0", "r1"] {
        std::fs::write(format!("/proc/sys/net/ipv4/conf/{p}/rp_filter"), b"0")
            .map_err(|e| format!("rp_filter {p}: {e}"))?;
        // 蜜罐测试需要「本机地址作源」的注入包不被 martian 检查丢弃
        // (模拟本机外连的 orig 方向,让 conntrack 条目能被 confirm)。
        std::fs::write(format!("/proc/sys/net/ipv4/conf/{p}/accept_local"), b"1")
            .map_err(|e| format!("accept_local {p}: {e}"))?;
    }
    let r0_ifindex = if_ioctl(libc::SIOCGIFINDEX as u64, "r0", |r| unsafe {
        r.ifr_ifru.ifru_ifindex
    })?;
    let if_mac = |n: &str| {
        if_ioctl(libc::SIOCGIFHWADDR as u64, n, |r| {
            let mut m = [0u8; 6];
            let sa = unsafe { r.ifr_ifru.ifru_hwaddr };
            for i in 0..6 {
                m[i] = sa.sa_data[i] as u8;
            }
            m
        })
    };
    let mac_r0 = if_mac("r0")?;
    let mac_r1 = if_mac("r1")?;
    let pkt_fd = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            (libc::ETH_P_ALL as u16).to_be() as i32,
        )
    };
    if pkt_fd < 0 {
        return Err("AF_PACKET socket (CAP_NET_RAW)".into());
    }
    Ok(Net { r0_ifindex, mac_r0, mac_r1, pkt_fd })
}

impl Net {
    /// 从 r0 发出 → veth 对端 r1 收到 → 内核 INPUT 路径(iif=r1)。
    fn inject(&self, ethertype: u16, payload: &[u8]) {
        let mut frame = Vec::with_capacity(14 + payload.len());
        frame.extend_from_slice(&self.mac_r1);
        frame.extend_from_slice(&self.mac_r0);
        frame.extend_from_slice(&ethertype.to_be_bytes());
        frame.extend_from_slice(payload);
        frame.resize(frame.len().max(60), 0); // 以太最小帧长
        let mut sa: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        sa.sll_family = libc::AF_PACKET as u16;
        sa.sll_ifindex = self.r0_ifindex;
        sa.sll_hatype = 1; // ARPHRD_ETHER
        sa.sll_halen = 6;
        sa.sll_addr[..6].copy_from_slice(&self.mac_r1);
        let n = unsafe {
            libc::sendto(
                self.pkt_fd,
                frame.as_ptr() as *const libc::c_void,
                frame.len(),
                0,
                &sa as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_ll>() as u32,
            )
        };
        assert_eq!(n as usize, frame.len(), "AF_PACKET inject");
    }

    fn inject4(&self, src: Ipv4Addr, sport: u16, dst: Ipv4Addr, dport: u16, flags: u8, seq: u32, ack: u32) {
        self.inject(0x0800, &tcp4(src, sport, dst, dport, flags, seq, ack));
    }

    fn inject6(&self, src: Ipv6Addr, sport: u16, dst: Ipv6Addr, dport: u16, flags: u8, seq: u32, ack: u32) {
        self.inject(0x86dd, &tcp6(src, sport, dst, dport, flags, seq, ack));
    }
}

/// 互联网校验和。
fn csum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn tcp_with_pseudo(pseudo: &[u8], src_port: u16, dst_port: u16, flags: u8, seq: u32, ack: u32) -> Vec<u8> {
    let mut tcp = vec![0u8; 20];
    tcp[0..2].copy_from_slice(&src_port.to_be_bytes());
    tcp[2..4].copy_from_slice(&dst_port.to_be_bytes());
    tcp[4..8].copy_from_slice(&seq.to_be_bytes());
    tcp[8..12].copy_from_slice(&ack.to_be_bytes());
    tcp[12] = 5 << 4; // data offset
    tcp[13] = flags;
    tcp[14..16].copy_from_slice(&65535u16.to_be_bytes()); // window
    let mut sum_buf = pseudo.to_vec();
    sum_buf.extend_from_slice(&tcp);
    let c = csum(&sum_buf);
    tcp[16..18].copy_from_slice(&c.to_be_bytes());
    tcp
}

fn tcp4(src: Ipv4Addr, sport: u16, dst: Ipv4Addr, dport: u16, flags: u8, seq: u32, ack: u32) -> Vec<u8> {
    let mut pseudo = Vec::with_capacity(12);
    pseudo.extend_from_slice(&src.octets());
    pseudo.extend_from_slice(&dst.octets());
    pseudo.extend_from_slice(&[0, 6, 0, 20]);
    let tcp = tcp_with_pseudo(&pseudo, sport, dport, flags, seq, ack);
    let mut ip = vec![0u8; 20];
    ip[0] = 0x45;
    ip[2..4].copy_from_slice(&((20 + tcp.len()) as u16).to_be_bytes());
    ip[4..6].copy_from_slice(&0x1234u16.to_be_bytes()); // id
    ip[8] = 64; // ttl
    ip[9] = 6; // tcp
    ip[12..16].copy_from_slice(&src.octets());
    ip[16..20].copy_from_slice(&dst.octets());
    let c = csum(&ip);
    ip[10..12].copy_from_slice(&c.to_be_bytes());
    ip.extend_from_slice(&tcp);
    ip
}

fn tcp6(src: Ipv6Addr, sport: u16, dst: Ipv6Addr, dport: u16, flags: u8, seq: u32, ack: u32) -> Vec<u8> {
    let mut pseudo = Vec::with_capacity(40);
    pseudo.extend_from_slice(&src.octets());
    pseudo.extend_from_slice(&dst.octets());
    pseudo.extend_from_slice(&20u32.to_be_bytes());
    pseudo.extend_from_slice(&[0, 0, 0, 6]);
    let tcp = tcp_with_pseudo(&pseudo, sport, dport, flags, seq, ack);
    let mut ip = vec![0u8; 40];
    ip[0] = 6 << 4;
    ip[4..6].copy_from_slice(&(tcp.len() as u16).to_be_bytes());
    ip[6] = 6; // next header
    ip[7] = 64; // hop limit
    ip[8..24].copy_from_slice(&src.octets());
    ip[24..40].copy_from_slice(&dst.octets());
    ip.extend_from_slice(&tcp);
    ip
}

/// raw IP 交付探针:INPUT 链 drop 的包不会到达这里。
struct RawTcp(i32);

fn open_raw() -> RawTcp {
    let fd = unsafe {
        libc::socket(libc::AF_INET, libc::SOCK_RAW | libc::SOCK_CLOEXEC, libc::IPPROTO_TCP)
    };
    assert!(fd >= 0, "raw tcp socket (CAP_NET_RAW)");
    let r = RawTcp(fd);
    r.set_timeout(20_000); // 默认 20ms 超时:expect/count 靠它周期性醒来查 deadline
    r
}

impl RawTcp {
    fn set_timeout(&self, us: i64) {
        let tv = libc::timeval {
            tv_sec: 0,
            tv_usec: us as libc::suseconds_t,
        };
        unsafe {
            libc::setsockopt(
                self.0,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &tv as *const _ as *const libc::c_void,
                std::mem::size_of_val(&tv) as libc::socklen_t,
            );
        }
    }

    fn recv_one(&self) -> Option<(Ipv4Addr, u16, u16, u8)> {
        let mut buf = [0u8; 2048];
        let n = unsafe { libc::recv(self.0, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
        if n < 40 {
            return None; // 超时(20ms)/短包
        }
        let ihl = ((buf[0] & 0xf) as usize) * 4;
        if buf[0] >> 4 != 4 || ihl < 20 || (n as usize) < ihl + 20 {
            return None;
        }
        let src = Ipv4Addr::new(buf[12], buf[13], buf[14], buf[15]);
        let sport = u16::from_be_bytes([buf[ihl], buf[ihl + 1]]);
        let dport = u16::from_be_bytes([buf[ihl + 2], buf[ihl + 3]]);
        Some((src, sport, dport, buf[ihl + 13]))
    }

    /// 在 deadline 内等到第一条匹配的分组的标志位;超时 false。
    fn expect(&self, within: Duration, f: impl Fn(Ipv4Addr, u16, u16, u8) -> bool) -> bool {
        let end = Instant::now() + within;
        while Instant::now() < end {
            if let Some(p) = self.recv_one() {
                if f(p.0, p.1, p.2, p.3) {
                    return true;
                }
            }
        }
        false
    }

    /// 清空积压。
    fn drain(&self) {
        self.set_timeout(5_000);
        while self.recv_one().is_some() {}
    }

    /// 计数窗口内到达的匹配分组数。
    fn count(&self, within: Duration, f: impl Fn(Ipv4Addr, u16, u16, u8) -> bool) -> usize {
        let end = Instant::now() + within;
        let mut n = 0;
        while Instant::now() < end {
            if let Some(p) = self.recv_one() {
                if f(p.0, p.1, p.2, p.3) {
                    n += 1;
                }
            }
        }
        n
    }
}

/// 内核独立视角(nft CLI 不可用时返回 None,断言降级)。
fn nft_view_set(set: &str) -> Option<String> {
    let out = std::process::Command::new("nft")
        .args(["list", "set", "inet", "rooster", set])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// ROOSTER_NFT_KTEST_DEBUG=1 时打印内核视角的 ruleset(规则 + set 元素)。
fn debug_ruleset(tag: &str) {
    if std::env::var_os("ROOSTER_NFT_KTEST_DEBUG").is_none() {
        return;
    }
    if let Ok(o) = std::process::Command::new("nft")
        .args(["-nn", "list", "ruleset"])
        .output()
    {
        eprintln!("=== ruleset {tag} ===\n{}", String::from_utf8_lossy(&o.stdout));
    }
    if let Ok(c) = std::fs::read_to_string("/proc/sys/net/netfilter/nf_conntrack_count") {
        eprintln!("=== conntrack count {tag}: {}", c.trim());
    }
}

// Use a real OUTPUT connection so conntrack confirms the outbound flow.
fn outbound_syn(net: &Net, port: u16) -> (std::net::TcpStream, u32) {
    use std::os::fd::FromRawFd;
    let mac = net.mac_r0.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(":");
    for args in [
        vec!["route", "replace", "10.9.0.2/32", "dev", "r1"],
        vec!["neigh", "replace", "10.9.0.2", "lladdr", &mac, "nud", "permanent", "dev", "r1"],
    ] {
        assert!(std::process::Command::new("ip").args(args).status().unwrap().success());
    }
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC, 0) };
    assert!(fd >= 0);
    let stream = unsafe { std::net::TcpStream::from_raw_fd(fd) };
    let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    addr.sin_family = libc::AF_INET as u16;
    addr.sin_port = port.to_be();
    addr.sin_addr.s_addr = u32::from_ne_bytes([10, 9, 0, 1]);
    let size = std::mem::size_of_val(&addr) as libc::socklen_t;
    assert_eq!(unsafe { libc::bind(fd, &addr as *const _ as *const libc::sockaddr, size) }, 0);
    addr.sin_port = 80u16.to_be();
    addr.sin_addr.s_addr = u32::from_ne_bytes([10, 9, 0, 2]);
    assert_eq!(unsafe { libc::connect(fd, &addr as *const _ as *const libc::sockaddr, size) }, -1);
    assert_eq!(std::io::Error::last_os_error().raw_os_error(), Some(libc::EINPROGRESS));
    let deadline = Instant::now() + Duration::from_secs(1);
    while Instant::now() < deadline {
        let mut packet = [0u8; 2048];
        let n = unsafe { libc::recv(net.pkt_fd, packet.as_mut_ptr().cast(), packet.len(), libc::MSG_DONTWAIT) };
        if n >= 54 && packet[12..14] == [0x08, 0x00] && packet[30..34] == [10, 9, 0, 2] {
            let tcp = 14 + ((packet[14] & 0x0f) as usize) * 4;
            if n as usize >= tcp + 20
                && u16::from_be_bytes([packet[tcp], packet[tcp + 1]]) == port
                && packet[tcp + 13] == TCP_SYN
            {
                let seq = u32::from_be_bytes(packet[tcp + 4..tcp + 8].try_into().unwrap());
                return (stream, seq);
            }
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    panic!("outbound SYN was not observed on the veth");
}

// ---------- 测试 ----------

/// L4 meter 与命中队列分离:低于速率 → 源进 meter 集但 hit 为空且包被放行;
/// 超过速率 → 源进 hit 集且包被丢。
#[test]
#[ignore = "isolated-netns only: unshare -Urn env ROOSTER_NFT_KTEST=1 cargo test -p rooster-nft --test hardening_kernel -- --ignored --test-threads=1"]
fn l4_below_rate_meter_entry_only_above_rate_hits() {
    if !only_in_netns() {
        return;
    }
    let _g = table_lock();
    let Ok(net) = net() else {
        eprintln!("skipping (net fixture unavailable)");
        return;
    };
    let h = fresh_table();
    let spec = HardeningSpec {
        l4_on: true,
        l4_rate: 3,
        l4_unit_ms: 1_000,
        l4_burst: 2,
        l4_set_timeout_ms: 0, // 未配置 → builders 钳 60s 下限
        ..HardeningSpec::default()
    };
    h.set_hardening(&spec, &[], &[]).expect("apply l4 spec");
    debug_ruleset("l4 applied");

    let raw = open_raw();
    let src = Ipv4Addr::new(10, 9, 0, 2);
    let dst = Ipv4Addr::new(10, 9, 0, 1);

    // 低于速率:单 SYN(令牌桶 burst=2)→ 放行交付,meter 有元素,hit 空。
    net.inject4(src, 51001, dst, 40081, TCP_SYN, 1000, 0);
    assert!(
        raw.expect(Duration::from_millis(400), |s, _, _, fl| s == src && fl == TCP_SYN),
        "低于速率的 SYN 应被放行交付"
    );
    let meter = h.list_set_elements(SET_L4METER_V4).expect("meter dump");
    let mine: Vec<_> = meter.iter().filter(|(a, _)| a == "10.9.0.2").collect();
    assert_eq!(mine.len(), 1, "发过包的源进 meter 集: {meter:?}");
    assert!(mine[0].1.is_some(), "meter 元素带剩余超时: {mine:?}");
    assert!(
        h.list_set_elements(SET_L4HIT_V4).unwrap().is_empty(),
        "未超速不得写命中队列"
    );

    // 超过速率:10 连发 → hit 出现,多数包被丢。
    for i in 0..10u16 {
        net.inject4(src, 51100 + i, dst, 40100 + i, TCP_SYN, 2000 + i as u32, 0);
    }
    raw.drain();
    let delivered = raw.count(Duration::from_millis(400), |s, sp, _, fl| {
        s == src && sp >= 51100 && fl == TCP_SYN
    });
    eprintln!("flood: delivered {delivered}/10");
    let hits = h.list_set_elements(SET_L4HIT_V4).expect("hit dump");
    debug_ruleset("l4 after flood");
    let hit: Vec<_> = hits.iter().filter(|(a, _)| a == "10.9.0.2").collect();
    assert_eq!(hit.len(), 1, "超速源进命中队列: {hits:?}");
    let rem = hit[0].1.expect("hit 元素带剩余超时");
    assert!(
        (50..=60).contains(&rem),
        "hit 保留钳 60s 下限(瞬时事件): {rem}s"
    );
    assert!(
        delivered <= 5,
        "超速后应丢包(10 发仅 {delivered} 交付)"
    );
    h.delete_table().expect("cleanup");
}

/// 扫描元组集:同端口重复探测不产生新元素(distinct-port 语义),开放端口
/// 不记录,v6 是 20 字节拼接键;元素寿命 = 配置的 find-time,没有 60s 垫底。
#[test]
#[ignore = "isolated-netns only: unshare -Urn env ROOSTER_NFT_KTEST=1 cargo test -p rooster-nft --test hardening_kernel -- --ignored --test-threads=1"]
fn scan_tuples_dedup_and_ipv6_concat_encoding() {
    if !only_in_netns() {
        return;
    }
    let _g = table_lock();
    let Ok(net) = net() else {
        eprintln!("skipping (net fixture unavailable)");
        return;
    };
    let h = fresh_table();
    let spec = HardeningSpec {
        scan_on: true,
        scan_set_timeout_ms: 5_000,
        open_ports: vec![80, 443],
        ..HardeningSpec::default()
    };
    h.set_hardening(&spec, &[], &[80, 443]).expect("apply scan spec");

    let src = Ipv4Addr::new(10, 9, 0, 2);
    let dst = Ipv4Addr::new(10, 9, 0, 1);
    net.inject4(src, 52001, dst, 40001, TCP_SYN, 1, 0);
    net.inject4(src, 52001, dst, 40001, TCP_SYN, 2, 0); // 同元组再探:UPDATE 不新增
    net.inject4(src, 52002, dst, 40002, TCP_SYN, 3, 0);
    net.inject4(src, 52003, dst, 80, TCP_SYN, 4, 0); // 开放端口不记录

    let tuples = h.list_scan_tuples(SET_SCANPORTS_V4).expect("scan tuple dump");
    let mut ports: Vec<u16> = tuples
        .iter()
        .filter(|((a, _), _)| matches!(a, IpAddr::V4(v) if v == &src))
        .map(|((_, p), _)| *p)
        .collect();
    ports.sort_unstable();
    assert_eq!(ports, vec![40001, 40002], "端口去重、开放端口不记: {tuples:?}");
    for ((_, _), rem) in &tuples {
        let r = rem.expect("元组带剩余毫秒");
        assert!((4_000..=5_000).contains(&r), "元组寿命 = find-time 5s(无 60s 垫底): {r}ms");
    }

    let src6 = Ipv6Addr::from([0x20, 0x01, 0x0d, 0xb8, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
    let dst6 = Ipv6Addr::from([0x20, 0x01, 0x0d, 0xb8, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    net.inject6(src6, 52101, dst6, 41001, TCP_SYN, 10, 0);
    net.inject6(src6, 52102, dst6, 41002, TCP_SYN, 11, 0);
    let t6 = h.list_scan_tuples(SET_SCANPORTS_V6).expect("scan6 tuple dump");
    assert_eq!(t6.len(), 2, "v6 元组: {t6:?}");
    assert!(
        t6.iter().any(|((a, p), _)| *a == IpAddr::V6(src6) && *p == 41001),
        "v6 拼接键解码(16B 地址 + 4B 对齐端口槽): {t6:?}"
    );
    // 独立视角:nft CLI 的 dump 应显示同样的 ip . port 元组(编码互检)。
    if let Some(view) = nft_view_set(SET_SCANPORTS_V6) {
        assert!(
            view.contains("2001:db8:ffff::2 . 41001") && view.contains("2001:db8:ffff::2 . 41002"),
            "nft CLI 视角: {view}"
        );
    }
    // 删单条元组:只清 41001,41002 保留。
    h.delete_scan_tuple(SET_SCANPORTS_V6, &IpAddr::V6(src6), 41001)
        .expect("delete tuple");
    let t6b = h.list_scan_tuples(SET_SCANPORTS_V6).unwrap();
    assert_eq!(t6b.len(), 1, "删单条后剩 1: {t6b:?}");
    assert_eq!(t6b[0].0, (IpAddr::V6(src6), 41002));
    h.delete_table().expect("cleanup");
}

/// flag-guard:established 流的纯 ACK 不得被丢(FSR 掩码必须含 ACK 位,
/// 旧 0x0f 掩码会把纯 ACK 当 NULL 扫描丢掉);NULL 扫描仍要被丢。
#[test]
#[ignore = "isolated-netns only: unshare -Urn env ROOSTER_NFT_KTEST=1 cargo test -p rooster-nft --test hardening_kernel -- --ignored --test-threads=1"]
fn established_ack_passes_flag_guard_null_scan_dropped() {
    if !only_in_netns() {
        return;
    }
    let _g = table_lock();
    let Ok(net) = net() else {
        eprintln!("skipping (net fixture unavailable)");
        return;
    };
    let h = fresh_table();
    let spec = HardeningSpec { flags_on: true, ..HardeningSpec::default() };
    h.set_hardening(&spec, &[], &[]).expect("apply flags spec");

    let raw = open_raw();
    let src = Ipv4Addr::new(10, 9, 0, 2);
    let dst = Ipv4Addr::new(10, 9, 0, 1);
    // 三步握手模拟:SYN(正)、SYN-ACK(反;dst 非本机,conntrack 在
    // prerouting 已把该流记为双向见过)。
    net.inject4(src, 53001, dst, 80, TCP_SYN, 1000, 0);
    net.inject4(dst, 80, src, 53001, TCP_SYNACK, 2000, 1001);
    raw.drain();
    net.inject4(src, 53001, dst, 80, TCP_ACK, 1001, 2001);
    assert!(
        raw.expect(Duration::from_millis(500), |s, sp, _, fl| {
            s == src && sp == 53001 && fl == TCP_ACK
        }),
        "established 流的纯 ACK 必须交付(掩码 0x17 含 ACK 位)"
    );
    // 对照:同链对 NULL 扫描(无标志位)仍在丢。
    net.inject4(src, 53009, dst, 80, 0, 5000, 0);
    assert!(
        !raw.expect(Duration::from_millis(300), |_, _, _, fl| fl == 0),
        "NULL 扫描应被 flag-guard 丢弃"
    );
    h.delete_table().expect("cleanup");
}

#[test]
#[ignore = "isolated-netns only"]
fn honeypot_upgrade_preserves_bans_and_replaces_legacy_keys() {
    use rooster_nft::builders::{hardening_meter_sets, HP_CHAIN, PRE_CHAIN};
    use rooster_nft::codec::*;
    use rooster_nft::consts::*;

    assert!(only_in_netns(), "requires an isolated network namespace");
    let _g = table_lock();
    let net = net().as_ref().expect("network fixture");
    let h = fresh_table();
    let mut seq = Seq::new();
    let mut ops = Vec::new();
    for (name, mut datatype, mut klen, id) in hardening_meter_sets() {
        if name == SET_HP_V4 {
            datatype = NFT_DATATYPE_IPADDR;
            klen = 4;
        } else if name == rooster_nft::builders::SET_HP_V6 {
            datatype = NFT_DATATYPE_IP6ADDR;
            klen = 16;
        }
        let pos = nf_msg_start(&mut ops, NFT_MSG_NEWSET, NFPROTO_INET,
            rooster_nft::builders::F_CREATE, seq.get());
        attr_str(&mut ops, NFTA_SET_TABLE, rooster_nft::TABLE);
        attr_str(&mut ops, NFTA_SET_NAME, name);
        attr_be32(&mut ops, NFTA_SET_KEY_TYPE, datatype);
        attr_be32(&mut ops, NFTA_SET_KEY_LEN, klen);
        attr_be32(&mut ops, NFTA_SET_ID, id);
        if datatype != NFT_DATATYPE_INET_SERVICE {
            attr_be32(&mut ops, NFTA_SET_FLAGS, NFT_SET_TIMEOUT | NFT_SET_EVAL);
            attr_be64(&mut ops, NFTA_SET_TIMEOUT, 60_000);
        }
        nf_msg_end(&mut ops, pos);
    }
    h.ktest_send_batch(&wrap_batch(&ops, seq.get(), seq.get()), &[]).unwrap();
    let chains: Vec<_> = hardening_chains().iter().map(|(name, _)| *name).collect();
    h.ktest_send_batch(&build_hardening_chains_create(&mut seq, &chains), &[]).unwrap();
    let spec = HardeningSpec {
        honeypot_on: true,
        honey_ports: vec![54321],
        honeypot_window_ms: 60_000,
        ..HardeningSpec::default()
    };
    h.ktest_send_batch(&rooster_nft::builders::build_replace_ports(&mut seq,
        rooster_nft::builders::SET_HONEYPORTS, &[54321]), &[]).unwrap();
    h.ktest_send_batch(&build_hardening_chain_rules(&mut seq, HP_CHAIN, &[], &spec), &[]).unwrap();
    h.add_set_element(rooster_nft::SET_BLOCK_V4, "203.0.113.9", Some(Duration::from_secs(3600))).unwrap();
    let raw = open_raw();
    let scanner = Ipv4Addr::new(10, 9, 0, 200);
    let dst = Ipv4Addr::new(10, 9, 0, 1);
    net.inject4(scanner, 33333, dst, 54321, TCP_SYN, 1, 0);
    assert!(!raw.expect(Duration::from_millis(300), |s, _, _, _| s == scanner));
    assert!(h.list_set_elements(SET_HP_V4).unwrap().iter().any(|(ip, _)| ip == "10.9.0.200"));

    h.set_hardening(&spec, &[54321], &[]).expect("upgrade legacy sets");
    assert!(h.list_set_elements(rooster_nft::SET_BLOCK_V4).unwrap().iter().any(|(ip, _)| ip == "203.0.113.9"));
    assert_eq!(h.ktest_rule_count(PRE_CHAIN).unwrap(), 6);
    net.inject4(scanner, 33334, dst, 54321, TCP_SYN, 2, 0);
    assert!(!raw.expect(Duration::from_millis(300), |s, _, _, _| s == scanner));
    assert!(h.list_scan_tuples(SET_HP_V4).unwrap().iter().any(|((ip, port), _)|
        ip.to_string() == "10.9.0.200" && *port == 54321));
    h.set_hardening(&spec, &[54321], &[]).expect("idempotent reapply");
    h.delete_table().expect("cleanup");
}

/// 蜜罐:向蜜罐端口的新建 SYN 被记录并丢弃;本机外连的 established 回程包
/// (源端口=蜜罐端口)不得当蜜罐命中(ct state new 排除)。
#[test]
#[ignore = "isolated-netns only: unshare -Urn env ROOSTER_NFT_KTEST=1 cargo test -p rooster-nft --test hardening_kernel -- --ignored --test-threads=1"]
fn honeypot_hits_new_syn_only_not_established_reply() {
    if !only_in_netns() {
        return;
    }
    let _g = table_lock();
    let Ok(net) = net() else {
        eprintln!("skipping (net fixture unavailable)");
        return;
    };
    let h = fresh_table();
    let spec = HardeningSpec {
        honeypot_on: true,
        honey_ports: vec![54321],
        honeypot_window_ms: 5_000,
        open_ports: vec![80],
        ..HardeningSpec::default()
    };
    h.set_hardening(&spec, &[54321], &[80]).expect("apply honeypot spec");

    let raw = open_raw();
    let dst = Ipv4Addr::new(10, 9, 0, 1);
    // 正向:陌生源 SYN → 蜜罐端口 → 记录 + 丢弃。
    let scanner = Ipv4Addr::new(10, 9, 0, 200);
    net.inject4(scanner, 33333, dst, 54321, TCP_SYN, 1, 0);
    assert!(
        !raw.expect(Duration::from_millis(300), |s, _, _, _| s == scanner),
        "蜜罐 SYN 应被 drop"
    );
    let hp = h.list_scan_tuples(SET_HP_V4).expect("hp tuple dump");
    let hit: Vec<_> = hp.iter().filter(|((ip, _), _)| ip.to_string() == "10.9.0.200").collect();
    assert_eq!(hit.len(), 1, "蜜罐命中: {hp:?}");
    assert_eq!(hit[0].0.1, 54321, "记录命中的目标端口");
    let rem = hit[0].1.expect("命中带剩余超时");
    assert!((4_000..=5_000).contains(&rem), "命中寿命 = 窗口 5s: {rem}ms");

    // Reverse-direction traffic must never ban an outbound peer, including SYN-ACK.
    let local = Ipv4Addr::new(10, 9, 0, 1);
    let peer = Ipv4Addr::new(10, 9, 0, 2);
    let (client, seq) = outbound_syn(net, 54321);
    net.inject4(peer, 80, local, 54321, TCP_SYNACK, 2000, seq.wrapping_add(1));
    assert!(raw.expect(Duration::from_millis(500), |s, sp, dp, fl| {
        s == peer && sp == 80 && dp == 54321 && fl == TCP_SYNACK
    }), "outbound SYN-ACK must be delivered");
    assert!(client.peer_addr().is_ok(), "real outbound handshake must complete");
    let hp2 = h.list_scan_tuples(SET_HP_V4).expect("hp tuple dump 2");
    assert!(
        !hp2.iter().any(|((ip, _), _)| ip.to_string() == "10.9.0.2"),
        "first outbound reply must not hit the honeypot: {hp2:?}"
    );
    // established 阶段的数据回程:dport=蜜罐端口但 ct state established → 不得命中。
    net.inject4(peer, 80, local, 54321, TCP_PSHACK, 2001, seq.wrapping_add(1));
    net.inject4(peer, 80, local, 54321, TCP_ACK, 2001, seq.wrapping_add(1));
    net.inject4(peer, 80, local, 54321, TCP_FIN | TCP_ACK, 2001, seq.wrapping_add(1));
    let hp3 = h.list_scan_tuples(SET_HP_V4).expect("hp tuple dump 3");
    assert!(
        !hp3.iter().any(|((ip, _), _)| ip.to_string() == "10.9.0.2"),
        "established 数据回程不得当蜜罐命中: {hp3:?}"
    );
    assert_eq!(hp2.iter().filter(|((ip, _), _)| ip.to_string() == "10.9.0.200").count(), 1);
    drop(client);
    assert!(std::process::Command::new("ip").args(["route", "del", "10.9.0.2/32", "dev", "r1"]).status().unwrap().success());
    h.delete_table().expect("cleanup");
}

/// 幂等与清理:重复 apply 规则数稳定;「链在、bypass 规则在、8 个状态集
/// 全缺」的升级现场上 clear_hardening 不得失败且不残留规则(旧实现对
/// 缺失 set 的 flush 会回滚整批,规则永久残留);全关后链只剩 bypass。
#[test]
#[ignore = "isolated-netns only: unshare -Urn env ROOSTER_NFT_KTEST=1 cargo test -p rooster-nft --test hardening_kernel -- --ignored --test-threads=1"]
fn apply_idempotent_and_cleanup_survives_legacy_missing_sets() {
    if !only_in_netns() {
        return;
    }
    let _g = table_lock();
    let chain_names: Vec<&'static str> = hardening_chains().iter().map(|(n, _)| *n).collect();

    // 空表:clear 是 no-op 且 Ok(ensure_table 的 6 个常驻集仍在,但加固集不存在)。
    {
        let h = fresh_table();
        h.clear_hardening().expect("clear on empty table must be Ok");
        let sets = h.dump_set_names().unwrap();
        for s in rooster_nft::builders::hardening_state_sets() {
            assert!(!sets.iter().any(|n| n == s), "clear 不得建集: {s}");
        }
        h.delete_table().unwrap();
    }

    // legacy 现场:链 + bypass 规则存在,加固状态集全部缺失。
    let h = fresh_table();
    let mut seq = Seq::new();
    let chains = build_hardening_chains_create(&mut seq, &chain_names);
    h.ktest_send_batch(&chains, &[EEXIST]).expect("legacy chains");
    for (chain, _) in hardening_chains() {
        let b = build_hardening_chain_rules(&mut seq, chain, &[], &HardeningSpec::default());
        h.ktest_send_batch(&b, &[]).expect("legacy bypass rules");
        assert_eq!(h.ktest_rule_count(chain).unwrap(), 3, "{chain} bypass×3");
    }
    h.clear_hardening().expect("cleanup must survive missing sets");
    for (chain, _) in hardening_chains() {
        assert_eq!(
            h.ktest_rule_count(chain).unwrap(),
            0,
            "{chain} 不得残留规则(缺失 set 的 flush 不得回滚链清空)"
        );
    }

    // 全量下发两次:幂等,规则数稳定。
    let spec = HardeningSpec {
        honey_ports: vec![54321],
        open_ports: vec![80, 443],
        honeypot_on: true,
        honeypot_window_ms: 300_000,
        scan_set_timeout_ms: 60_000,
        l4_set_timeout_ms: 60_000,
        scan_on: true,

        l4_on: true,
        l4_rate: 60,
        l4_unit_ms: 1_000,
        l4_burst: 20,
        flags_on: true,
    };
    h.set_hardening(&spec, &[54321], &[80, 443]).expect("apply full");
    let counts1: Vec<usize> = hardening_chains()
        .iter()
        .map(|(c, _)| h.ktest_rule_count(c).unwrap())
        .collect();
    assert_eq!(counts1, vec![7, 5, 5, 5], "flags 3+4 / l4 3+2 / scan 3+2 / hp 3+2");
    h.set_hardening(&spec, &[54321], &[80, 443]).expect("re-apply full");
    let counts2: Vec<usize> = hardening_chains()
        .iter()
        .map(|(c, _)| h.ktest_rule_count(c).unwrap())
        .collect();
    assert_eq!(counts1, counts2, "重复 apply 幂等");

    // 全关:链只剩 bypass,状态集清空。
    h.set_hardening(&HardeningSpec::default(), &[], &[]).expect("disable");
    for (chain, _) in hardening_chains() {
        assert_eq!(h.ktest_rule_count(chain).unwrap(), 3, "{chain} 只剩 bypass");
    }
    assert!(h.list_set_elements(SET_L4HIT_V4).unwrap().is_empty());

    // clear:无规则残留,链不删(只清不建也不删链)。
    h.clear_hardening().expect("clear after apply");
    for (chain, _) in hardening_chains() {
        assert_eq!(h.ktest_rule_count(chain).unwrap(), 0);
    }
    let chains_now = h.dump_chain_names().unwrap();
    for c in &chain_names {
        assert!(chains_now.iter().any(|n| n == c), "clear 不得删链: {c}");
    }
    h.delete_table().expect("cleanup");
}
