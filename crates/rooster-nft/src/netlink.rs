//! 底层 netlink socket(真实 libc 实现 + 可 mock trait)与 NftHandle 的高层操作。
//!
//! 写路径:全部走 NFNL_SUBSYS_NFTABLES 事务批(BATCH_BEGIN/ops/BATCH_END,NLM_F_ACK),
//! 逐条读取 ACK;NLMSG_ERROR 且 errno!=0 → `NftError::Netlink`(带 strerror 文本)。
//! 读路径:NLM_F_DUMP 请求,循环 recv 收集 multipart 直到 NLMSG_DONE。

use crate::builders::*;
use crate::codec::*;
use crate::consts::*;
use crate::{BanEntry, NftError, NetlinkSocket};
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Mutex;
use std::time::Duration;

const EEXIST: i32 = 17;
const ENOENT: i32 = 2;
const RECV_BUF: usize = 8192;

/// 真实 netlink socket(AF_NETLINK/SOCK_RAW/NETLINK_NETFILTER,libc 直调)。
struct RealSocket {
    fd: i32,
}

impl Drop for RealSocket {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.fd);
        }
    }
}

impl RealSocket {
    fn open() -> Result<Self, NftError> {
        let fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                libc::NETLINK_NETFILTER as i32,
            )
        };
        if fd < 0 {
            let e = -std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            return Err(NftError::Netlink(errno_text(e)));
        }
        let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        addr.nl_family = libc::AF_NETLINK as u16;
        addr.nl_pid = 0;
        addr.nl_groups = 0;
        let r = unsafe {
            libc::bind(
                fd,
                &addr as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_nl>() as u32,
            )
        };
        if r < 0 {
            let e = std::io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(NftError::Netlink(format!("bind netlink: {}", e)));
        }
        // 内核 extack 默认不下发给 socket,不开这个选项只能拿到裸 errno
        // (排查 NFTA_SET_ID 缺失时吃过这个亏:EINVAL 后面什么都没有)。
        // 老内核(<5.2)不支持,失败就留着裸 errno。
        const SOL_NETLINK: libc::c_int = 270;
        const NETLINK_EXT_ACK: libc::c_int = 11;
        unsafe {
            let on: libc::c_int = 1;
            libc::setsockopt(
                fd,
                SOL_NETLINK,
                NETLINK_EXT_ACK,
                &on as *const _ as *const libc::c_void,
                std::mem::size_of_val(&on) as libc::socklen_t,
            );
        }
        // 接收超时:批内某 op 失败后内核不再回应剩余 op,错误路径的排干
        // 循环靠它终止;正常路径一次 recv 内必有响应,2s 只作兜底。
        unsafe {
            let tv = libc::timeval {
                tv_sec: 2,
                tv_usec: 0,
            };
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &tv as *const _ as *const libc::c_void,
                std::mem::size_of_val(&tv) as libc::socklen_t,
            );
        }
        Ok(RealSocket { fd })
    }
}

impl NetlinkSocket for RealSocket {
    fn send(&mut self, buf: &[u8]) -> Result<(), NftError> {
        let n = unsafe {
            libc::send(
                self.fd,
                buf.as_ptr() as *const libc::c_void,
                buf.len(),
                libc::MSG_NOSIGNAL,
            )
        };
        if n < 0 || n as usize != buf.len() {
            return Err(NftError::Netlink(format!(
                "send netlink: {}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(())
    }
    fn recv(&mut self, buf: &mut [u8]) -> Result<usize, NftError> {
        let n = unsafe {
            libc::recv(
                self.fd,
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
                0,
            )
        };
        if n < 0 {
            return Err(NftError::Netlink(format!(
                "recv netlink: {}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(n as usize)
    }
}

/// nftables 句柄(直接 netlink,不调用 `nft` CLI)。
pub struct NftHandle {
    sock: Mutex<Box<dyn NetlinkSocket>>,
    seq: Mutex<Seq>,
}

impl NftHandle {
    pub fn open() -> Result<Self, NftError> {
        Ok(NftHandle {
            sock: Mutex::new(Box::new(RealSocket::open()?)),
            seq: Mutex::new(Seq::new()),
        })
    }

    pub fn with_socket(sock: Box<dyn NetlinkSocket>) -> Self {
        NftHandle {
            sock: Mutex::new(sock),
            seq: Mutex::new(Seq::new()),
        }
    }

    /// 发送一个写事务批,读取全部 ACK。`tolerated` 里的 errno 视为成功
    /// (幂等创建容忍 EEXIST,删元素容忍 ENOENT)。
    ///
    /// 批内某 op 失败后,内核仍可能对后续 op / BATCH_END 回应(ACK 或错误);
    /// 在首个错误上提前 return 会把这些残留留在 socket 里,毒化同句柄的
    /// 下一个事务(VM 6.12 实测:set_ssh_limit 失败后 set_allowlist 每次
    /// 都读到陈旧 errno → 白名单永不更新 → 封禁被旧名单全数拒绝)。
    /// 因此错误也计入应答数,收齐或超时(SO_RCVTIMEO)后统一返回首个错误。
    fn request(&self, batch: &[u8], tolerated: &[i32]) -> Result<(), NftError> {
        let expected = count_acked_ops(batch);
        let mut sock = self.sock.lock().unwrap();
        sock.send(batch)?;
        let mut leftover: Vec<u8> = Vec::new();
        let mut acks = 0usize;
        let mut first_err: Option<NftError> = None;
        while acks < expected {
            let mut buf = [0u8; RECV_BUF];
            let n = match sock.recv(&mut buf) {
                Ok(n) => n,
                Err(e) => {
                    if first_err.is_some() {
                        // 排干阶段:内核已放弃本批,超时/任何 recv 错误都视为排干结束。
                        tracing::debug!("netlink: drained after batch error ({e})");
                        break;
                    }
                    return Err(e);
                }
            };
            if n == 0 {
                return Err(NftError::Netlink("netlink socket closed".into()));
            }
            leftover.extend_from_slice(&buf[..n]);
            let (msgs, consumed) = parse_msgs(&leftover);
            for m in &msgs {
                if m.mtype == NLMSG_ERROR {
                    // nlmsgerr.error 为负 errno;0 表示 ACK
                    let errno = m.errno(&leftover).unwrap_or(0);
                    if errno == 0 || tolerated.contains(&errno.abs()) {
                        if errno != 0 {
                            tracing::debug!(errno, "netlink op tolerated");
                        }
                    } else if first_err.is_none() {
                        first_err = Some(err_with_extack(
                            "nftables batch rejected: ",
                            errno,
                            m.extack_msg(&leftover),
                        ));
                    }
                    acks += 1;
                } else if m.mtype == NLMSG_DONE {
                    // 批不应出现 DONE,防御性处理
                    acks = expected;
                }
            }
            leftover.drain(..consumed);
        }
        if let Some(e) = first_err {
            return Err(e);
        }
        Ok(())
    }

    /// 发送 dump 请求,收集所有响应消息的属性区(multipart 直到 NLMSG_DONE)。
    fn dump(&self, req: &[u8]) -> Result<Vec<Vec<u8>>, NftError> {
        let mut sock = self.sock.lock().unwrap();
        sock.send(req)?;
        let mut leftover: Vec<u8> = Vec::new();
        let mut out = Vec::new();
        loop {
            let mut buf = [0u8; RECV_BUF];
            let n = sock.recv(&mut buf)?;
            if n == 0 {
                return Err(NftError::Netlink("netlink socket closed".into()));
            }
            leftover.extend_from_slice(&buf[..n]);
            let (msgs, consumed) = parse_msgs(&leftover);
            let mut done = false;
            for m in &msgs {
                if m.mtype == NLMSG_DONE {
                    done = true;
                } else if m.mtype == NLMSG_ERROR {
                    let errno = m.errno(&leftover).unwrap_or(0);
                    if errno != 0 {
                        return Err(err_with_extack(
                            "nftables dump failed: ",
                            errno,
                            m.extack_msg(&leftover),
                        ));
                    }
                } else {
                    out.push(m.attrs(&leftover).to_vec());
                }
            }
            leftover.drain(..consumed);
            if done {
                return Ok(out);
            }
        }
    }

    /// 幂等建表:table inet rooster + 6 set + pre 链 + 6 条规则。
    /// 链已存在则先按 handle 清空(我们拥有 pre 链)再重加 6 条规则。
    pub fn ensure_table(&self) -> Result<(), NftError> {
        let batch = {
            let mut seq = self.seq.lock().unwrap();
            build_ensure_creates(&mut seq)
        };
        self.request(&batch, &[EEXIST])?;
        let handles = self.dump_rule_handles(PRE_CHAIN)?;
        let batch = {
            let mut seq = self.seq.lock().unwrap();
            build_ensure_rules(&mut seq, &handles)
        };
        self.request(&batch, &[])
    }

    /// ssh 连接速率限制 meter 链。重复调用先清空 ssh_limit 链再下发。
    pub fn set_ssh_rate_limit(&self, port: u16, rate: &str, burst: u32) -> Result<(), NftError> {
        let (n, unit_ms) = parse_rate(rate)?;
        let batch = {
            let mut seq = self.seq.lock().unwrap();
            build_ssh_creates(&mut seq)
        };
        self.request(&batch, &[EEXIST])?;
        let handles = self.dump_rule_handles(SSH_CHAIN)?;
        let batch = {
            let mut seq = self.seq.lock().unwrap();
            build_ssh_rules(&mut seq, &handles, port, n, unit_ms, burst)
        };
        self.request(&batch, &[])
    }

    pub fn add_set_element(
        &self,
        set: &str,
        ip_or_cidr: &str,
        timeout: Option<Duration>,
    ) -> Result<(), NftError> {
        let net = parse_ip_or_cidr(ip_or_cidr)?;
        let batch = {
            let mut seq = self.seq.lock().unwrap();
            build_new_setelem(&mut seq, set, &net, timeout)
        };
        self.request(&batch, &[EEXIST])
    }

    /// 元素不存在也返回 Ok(内核 ENOENT 容忍)。
    pub fn delete_set_element(&self, set: &str, ip_or_cidr: &str) -> Result<(), NftError> {
        let net = parse_ip_or_cidr(ip_or_cidr)?;
        let batch = {
            let mut seq = self.seq.lock().unwrap();
            build_del_setelem(&mut seq, set, &net)
        };
        self.request(&batch, &[ENOENT])
    }

    /// 清空整个 set(= `nft flush set`)。
    pub fn flush_set_elements(&self, set: &str) -> Result<(), NftError> {
        let batch = {
            let mut seq = self.seq.lock().unwrap();
            build_flush_setelem(&mut seq, set)
        };
        self.request(&batch, &[])
    }

    /// 全量替换 set 内容:flush 与写入在同一批次内,内核实为原子事务。
    pub fn replace_set_elements(
        &self,
        set: &str,
        rows: &[(String, Option<Duration>)],
    ) -> Result<(), NftError> {
        let nets: Vec<(ipnet::IpNet, Option<Duration>)> = rows
            .iter()
            .map(|(s, t)| -> Result<_, NftError> {
                Ok((parse_ip_or_cidr(s)?, *t))
            })
            .collect::<Result<_, _>>()?;
        let batch = {
            let mut seq = self.seq.lock().unwrap();
            build_replace_setelems(&mut seq, set, &nets)
        };
        self.request(&batch, &[])
    }

    /// dump 一个 set 的元素:(ip/cidr 字符串, 剩余 timeout 秒)。
    pub fn list_set_elements(&self, set: &str) -> Result<Vec<(String, Option<u64>)>, NftError> {
        let req = {
            let mut seq = self.seq.lock().unwrap();
            build_get_setelem(&mut seq, set)
        };
        let mut payloads = self.dump(&req)?;
        let klen = klen_of_set(set);
        let interval = set_is_interval(set);
        let mut out = Vec::new();
        for p in payloads.drain(..) {
            out.extend(parse_set_elements(&[p], klen, interval));
        }
        Ok(out)
    }

    pub fn delete_table(&self) -> Result<(), NftError> {
        let batch = {
            let mut seq = self.seq.lock().unwrap();
            build_del_table(&mut seq)
        };
        self.request(&batch, &[])
    }

    fn dump_rule_handles(&self, chain: &str) -> Result<Vec<u64>, NftError> {
        let req = {
            let mut seq = self.seq.lock().unwrap();
            build_get_rule(&mut seq, chain)
        };
        let mut payloads = self.dump(&req)?;
        let mut out = Vec::new();
        for p in payloads.drain(..) {
            out.extend(parse_rule_handles(&[p]));
        }
        Ok(out)
    }
}

/// 统计批里携带 NLM_F_ACK 的 nftables 子系统 op 数。
fn count_acked_ops(batch: &[u8]) -> usize {
    let mut n = 0;
    let mut off = 0;
    while off + NLMSG_HDRLEN <= batch.len() {
        let len = u32::from_le_bytes(batch[off..off + 4].try_into().unwrap()) as usize;
        if len < NLMSG_HDRLEN {
            break;
        }
        let mtype = u16::from_le_bytes(batch[off + 4..off + 6].try_into().unwrap());
        let flags = u16::from_le_bytes(batch[off + 6..off + 8].try_into().unwrap());
        if mtype >> 8 == NFNL_SUBSYS_NFTABLES && flags & NLM_F_ACK != 0 {
            n += 1;
        }
        off += align4(len);
    }
    n
}

/// 供 dump 解析用的辅助:提取每条消息的属性区。
pub fn iter_payloads(buf: &[u8]) -> Vec<(u16, u16, u32, &[u8])> {
    let (msgs, _) = parse_msgs(buf);
    msgs.iter()
        .map(|m| (m.mtype, m.flags, m.seq, m.attrs(buf)))
        .collect()
}

/// 把 (载荷列表) 再喂给 parse_set_elements/parse_rule_handles 的粘合类型。
pub fn payloads_to_buf(payloads: &[Vec<u8>]) -> Vec<u8> {
    // 测试/内部使用:将多段属性区重新拼成可解析形态。
    let mut out = Vec::new();
    for p in payloads {
        out.extend_from_slice(p);
    }
    out
}

/// ip 字符串 → 所属 set(按地址族)。
pub fn block_set_of(ip: &IpAddr) -> &'static str {
    match ip {
        IpAddr::V4(_) => crate::SET_BLOCK_V4,
        IpAddr::V6(_) => crate::SET_BLOCK_V6,
    }
}

/// BanEntry → IpNet(apply_ban 时解析失败报 InvalidAddress)。
pub fn entry_net(entry: &BanEntry) -> Result<ipnet::IpNet, NftError> {
    parse_ip_or_cidr(&entry.ip)
}

/// 允许网络列表包含该地址?
pub fn allow_contains(allow: &[ipnet::IpNet], ip: &IpAddr) -> bool {
    allow.iter().any(|n| n.contains(ip))
}

/// 清理用:把 u8 十六进制 dump 成行(调试)。
#[allow(dead_code)]
fn hexdump(b: &[u8]) {
    let mut o = std::io::stdout();
    for (i, c) in b.iter().enumerate() {
        if i % 16 == 0 {
            let _ = writeln!(o);
        }
        let _ = write!(o, "{:02x} ", c);
    }
    let _ = writeln!(o);
}

#[allow(dead_code)]
fn _unused(v4: Ipv4Addr, v6: Ipv6Addr) -> u8 {
    v4.octets()[0] ^ v6.octets()[0]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::shared_handle;
    use crate::SET_ALLOW_V4;
    use std::sync::Arc;
    use std::sync::Mutex;

    /// 回归(VM 6.12 实测):批内 op 失败后,内核的后续响应若不被排干,
    /// 会毒化同句柄的下一个事务——set_ssh_limit 失败后 set_allowlist
    /// 每次都读到陈旧 errno,白名单永不更新,封禁被旧名单全数拒绝。
    #[test]
    fn failed_batch_drains_socket_so_next_request_is_clean() {
        let mock = Arc::new(Mutex::new(crate::testutil::MockSocket::default()));
        let h = shared_handle(mock.clone());
        // replace = flush + add 两个 op;第一个 op 回 -34,第二个 op 的 ACK
        // 在另一个 datagram 里晚到(模拟内核批中止后的残留响应)。
        mock.lock().unwrap().error_split = Some(-34);
        let r1 = h.replace_set_elements(SET_ALLOW_V4, &[("10.0.0.0/8".to_string(), None)]);
        assert!(r1.is_err(), "首个事务应失败: {r1:?}");
        // 排干后同句柄的下一个事务必须拿到自己的 ACK,而不是残留错误。
        let r2 = h.replace_set_elements(SET_ALLOW_V4, &[("10.0.0.0/8".to_string(), None)]);
        assert!(r2.is_ok(), "残留响应毒化了下一个事务: {r2:?}");
        // 第三次确认状态稳定。
        assert!(h
            .replace_set_elements(SET_ALLOW_V4, &[("192.0.2.1".to_string(), None)])
            .is_ok());
    }
}
