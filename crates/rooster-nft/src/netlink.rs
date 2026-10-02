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
                libc::NETLINK_NETFILTER,
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
        log_acks("batch", batch, acks, expected);
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
        // 元素过期 = max(单位, 60s),走 set 级 timeout(F-014 根因修复:
        // dynset 不再带与 limit 互斥的 TIMEOUT 属性)。
        for set in ["sshm4", "sshm6"] {
            let batch = {
                let mut seq = self.seq.lock().unwrap();
                build_ssh_set_timeout_update(&mut seq, set, unit_ms.max(60_000))
            };
            self.request(&batch, &[EEXIST])?;
        }
        let handles = self.dump_rule_handles(SSH_CHAIN)?;
        let batch = {
            let mut seq = self.seq.lock().unwrap();
            build_ssh_rules(&mut seq, &handles, port, n, unit_ms, burst)
        };
        self.request(&batch, &[])
    }

    /// 下发整套加固规则:幂等创建 8 set + 4 链,逐链清旧规则重建,
    /// 全量替换蜜罐/开放端口集,并清空命中暂存(配置变更时窗口重新计数)。
    pub fn set_hardening(
        &self,
        spec: &HardeningSpec,
        honeyports: &[u16],
        openports: &[u16],
    ) -> Result<(), NftError> {
        // 端口集先建(仅缺失时;key 类型错误无法原地改的旧表在删表重建时
        // 自然修正);随后幂等建齐 8 set + 4 链。
        let reset = {
            let mut seq = self.seq.lock().unwrap();
            build_hardening_ports_reset(&mut seq)
        };
        self.request(&reset, &[EEXIST])
            .map_err(|e| annotate(e, "ports-ensure"))?;
        let batch = {
            let mut seq = self.seq.lock().unwrap();
            build_hardening_sets_create(&mut seq, spec)
        };
        if std::env::var_os("ROOSTER_NFT_DEBUG_BATCH").is_some() {
            std::fs::write("/tmp/nftbatch-creates.bin", &batch).ok();
        }
        self.request(&batch, &[])
            .map_err(|e| annotate(e, "sets-create"))?;
        // 只为缺失的链建批:存量链用 EXCL 重开会让内核 EEXIST 回滚同批。
        let have = self.dump_chain_names()?;
        let missing: Vec<&'static str> = hardening_chains()
            .into_iter()
            .map(|(n, _)| n)
            .filter(|n| !have.iter().any(|h| h == n))
            .collect();
        if !missing.is_empty() {
            let batch = {
                let mut seq = self.seq.lock().unwrap();
                build_hardening_chains_create(&mut seq, &missing)
            };
            self.request(&batch, &[EEXIST])
                .map_err(|e| annotate(e, "chains-create"))?;
        }
        for (chain, _prio) in hardening_chains() {
            let handles = self
                .dump_rule_handles(chain)
                .map_err(|e| annotate(e, chain))?;
            let batches = {
                let mut seq = self.seq.lock().unwrap();
                build_hardening_chain_rule_batches(&mut seq, chain, &handles, spec)
            };
            for (i, batch) in batches.into_iter().enumerate() {
                if std::env::var_os("ROOSTER_NFT_DEBUG_BATCH").is_some() {
                    std::fs::write(format!("/tmp/nftbatch-{chain}-{i}.bin"), &batch)
                        .ok();
                }
                self.request(&batch, &[])
                    .map_err(|e| annotate(e, &format!("{chain}#{i}")))?;
            }
        }
        for (set, ports) in [(SET_HONEYPORTS, honeyports), (SET_OPENPORTS, openports)] {
            let batch = {
                let mut seq = self.seq.lock().unwrap();
                build_replace_ports(&mut seq, set, ports)
            };
            self.request(&batch, &[ENOENT])
                .map_err(|e| annotate(e, set))?;
        }
        self.flush_hardening_hits()
            .map_err(|e| annotate(e, "flush-hits"))
    }

    /// 全关时的清理:**只删不建,且只碰 dump 确认存在的对象**。DELRULE 带
    /// table+chain 不带 handle = `nft flush chain`;DELSETELEM 不带
    /// ELEMENTS = `nft flush set`。批是原子事务:对缺失 set 的 flush 会
    /// ENOENT 并把同批的链清空一并回滚(6.18 实测,升级路径上 scanports_*
    /// 不存在时旧规则永久残留的根因),所以先 dump 链/集名单再组批;
    /// ENOENT 仍容忍 dump 与删除之间的竞态。不会新建任何规则、集合或链。
    /// l4meter 的令牌桶元素一并清空:规则都没了,状态留着无意义。
    pub fn clear_hardening(&self) -> Result<(), NftError> {
        let chains = self.dump_chain_names()?;
        let sets = self.dump_set_names()?;
        let mut ops = Vec::with_capacity(512);
        {
            let mut seq = self.seq.lock().unwrap();
            for (chain, _prio) in hardening_chains() {
                if chains.iter().any(|c| c == chain) {
                    ops.extend_from_slice(&crate::builders::plain_delrule_msg(&mut seq, chain));
                }
            }
            for set in hardening_state_sets() {
                if sets.iter().any(|s| s == set) {
                    ops.extend_from_slice(&del_setelem_msg(&mut seq, set, &[]));
                }
            }
        }
        if ops.is_empty() {
            return Ok(());
        }
        let batch = {
            let mut seq = self.seq.lock().unwrap();
            wrap_batch(&ops, seq.get(), seq.get())
        };
        self.request(&batch, &[ENOENT])
    }

    /// 清空命中/元组暂存集(禁用子项 / 重新应用时防止陈旧命中被误封)。
    /// l4meter 不在列:令牌桶状态有自己的生命周期,消费命中/重下发的
    /// 时候都不重置它,否则超速源每次都能白得一个新令牌桶。
    /// 与 clear_hardening 同理由:只 flush dump 里存在的集,缺失集的
    /// ENOENT 会回滚同批其余 flush(原子事务)。
    pub fn flush_hardening_hits(&self) -> Result<(), NftError> {
        let sets = self.dump_set_names()?;
        let existing: Vec<&str> = hardening_hit_sets()
            .into_iter()
            .filter(|s| sets.iter().any(|h| h == s))
            .collect();
        if existing.is_empty() {
            return Ok(());
        }
        let mut ops = Vec::with_capacity(384);
        {
            let mut seq = self.seq.lock().unwrap();
            for set in existing {
                ops.extend_from_slice(&del_setelem_msg(&mut seq, set, &[]));
            }
        }
        let batch = {
            let mut seq = self.seq.lock().unwrap();
            wrap_batch(&ops, seq.get(), seq.get())
        };
        self.request(&batch, &[ENOENT])
    }

    /// 从非区间命中集删单 IP(promoter 消费一条命中后清位)。
    pub fn delete_plain_element(&self, set: &str, ip: &str) -> Result<(), NftError> {
        let batch = {
            let mut seq = self.seq.lock().unwrap();
            build_del_plain_ip(&mut seq, set, ip)
        };
        if batch.is_empty() {
            return Err(NftError::InvalidAddress(ip.to_string()));
        }
        self.request(&batch, &[ENOENT])
    }

    /// dump 拼接元组集:((源 IP, 目的端口), 剩余毫秒)。扫描检测的
    /// distinct-port 计数用;klen 取自 hardening_meter_sets(v4 8 / v6 20)。
    pub fn list_scan_tuples(&self, set: &str) -> Result<Vec<((IpAddr, u16), Option<u64>)>, NftError> {
        let Some(klen) = hardening_hit_set_klen(set) else {
            return Err(NftError::InvalidAddress(set.to_string()));
        };
        let req = {
            let mut seq = self.seq.lock().unwrap();
            build_get_setelem(&mut seq, set)
        };
        let payloads = self.dump(&req)?;
        Ok(parse_set_tuples(&payloads, klen))
    }

    /// 从拼接元组集删元素(promoter 清理非路由源/封禁后的残留)。
    pub fn delete_scan_tuple(&self, set: &str, ip: &IpAddr, port: u16) -> Result<(), NftError> {
        let key = scan_tuple_key(ip, port);
        let mut m = Vec::with_capacity(160);
        let (m, s) = {
            let mut seq = self.seq.lock().unwrap();
            let s = seq.get();
            let pos = nf_msg_start(&mut m, NFT_MSG_DELSETELEM, NFPROTO_INET, F_ACK_ONLY, s);
            attr_str(&mut m, NFTA_SET_ELEM_LIST_TABLE, crate::TABLE);
            attr_str(&mut m, NFTA_SET_ELEM_LIST_SET, set);
            let els = nest_start(&mut m, NFTA_SET_ELEM_LIST_ELEMENTS);
            put_plain_elem(&mut m, &key);
            nest_end(&mut m, els);
            nf_msg_end(&mut m, pos);
            (wrap_batch(&m, seq.get(), seq.get()), s)
        };
        let _ = s;
        self.request(&m, &[ENOENT])
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

    /// GETCHAIN dump(table inet rooster)→ 链名列表。
    pub fn dump_chain_names(&self) -> Result<Vec<String>, NftError> {
        let req = {
            let mut seq = self.seq.lock().unwrap();
            build_get_chain(&mut seq)
        };
        let mut payloads = self.dump(&req)?;
        let mut out = Vec::new();
        for p in payloads.drain(..) {
            if let Some(n) = find_attr(&p, NFTA_CHAIN_NAME) {
                let s = String::from_utf8_lossy(n).trim_end_matches('\0').to_string();
                out.push(s);
            }
        }
        Ok(out)
    }

    /// GETSET dump(table inet rooster)→ set 名列表。clear/flush 先确认
    /// 对象存在再组批(对缺失 set 的 op 会让内核回滚同批事务)。
    pub fn dump_set_names(&self) -> Result<Vec<String>, NftError> {
        let req = {
            let mut seq = self.seq.lock().unwrap();
            build_get_sets(&mut seq)
        };
        let mut payloads = self.dump(&req)?;
        let mut out = Vec::new();
        for p in payloads.drain(..) {
            if let Some(n) = find_attr(&p, NFTA_SET_NAME) {
                let s = String::from_utf8_lossy(n).trim_end_matches('\0').to_string();
                out.push(s);
            }
        }
        Ok(out)
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

    /// 真内核隔离测试专用(netns 内):发送任意 builders 批,用于构造
    /// 「链在、规则在、新命名 set 缺失」的升级现场。
    #[doc(hidden)]
    pub fn ktest_send_batch(&self, batch: &[u8], tolerated: &[i32]) -> Result<(), NftError> {
        self.request(batch, tolerated)
    }

    /// 真内核隔离测试专用:链上规则 handle 数(清理断言)。
    #[doc(hidden)]
    pub fn ktest_rule_count(&self, chain: &str) -> Result<usize, NftError> {
        Ok(self.dump_rule_handles(chain)?.len())
    }
}

/// 批失败时标注是哪一步(chain / set / creates)+ ack 清单,供 agent 层
/// 日志直接定位(内核对批内 ACK 位缺失的 op 静默跳过,清单能暴露错位)。
fn annotate(e: NftError, step: &str) -> NftError {
    match e {
        NftError::Netlink(msg) => NftError::Netlink(format!("[{step}] {msg}")),
        other => other,
    }
}

/// debug:记录每个 request 的 ack 计数(需要 ROOSTER_NFT_DEBUG_BATCH)。
fn log_acks(step: &str, _batch: &[u8], acks: usize, expected: usize) {
    if std::env::var_os("ROOSTER_NFT_DEBUG_BATCH").is_some() {
        use std::io::Write;
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open("/tmp/nft-ack.log")
        {
            let _ = writeln!(f, "{step}: acks={acks}/{expected}");
        }
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
