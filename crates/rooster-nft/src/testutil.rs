//! 测试专用工具:协议感知的 netlink mock 与 canned 报文构造。
//!
//! `MockSocket` 按生产端相同的规则解读发出的批(NLM_F_ACK 计数、
//! NLM_F_DUMP 分派),回放预先配置的 ACK / dump 响应;
//! `recv` 在没有 canned 响应时 panic,保证测试确定性。

use crate::builders::parse_set_elements;
use crate::codec::{
    attr, attr_be32, attr_be64, attr_str, attr_str_of, find_attr, nest_end, nest_start, parse_msgs,
    AttrIter,
};
use crate::consts::*;
use crate::{NftError, NetlinkSocket};
use std::collections::VecDeque;

pub struct MockSocket {
    /// 每次 GETRULE dump 应答的载荷集(属性区),FIFO;缺省空(链上无规则)。
    pub rule_dumps: VecDeque<Vec<Vec<u8>>>,
    /// 每次 GETSETELEM dump 应答的载荷集(属性区),FIFO;缺省空。
    pub elem_dumps: VecDeque<Vec<Vec<u8>>>,
    /// 对下一个带 ACK 的批回该 errno(非 0 报错),之后恢复 ACK;用于
    /// 验证 tolerated 路径(ENOENT)与错误传播。
    pub error_once: Option<i32>,
    /// 对下一个带 ACK 的批(设为 N 个 op):第 1 个响应回该 errno,
    /// 其余 N-1 个回 ACK(模拟内核批中止后仍有后续响应,分两个 datagram
    /// 到达)。用于验证错误路径排干 socket、不毒化下一个事务。
    pub error_split: Option<i32>,
    /// 全部发送过的批,断言用。
    pub sent: Vec<Vec<u8>>,
    pending: VecDeque<Vec<u8>>,
}

impl Default for MockSocket {
    fn default() -> Self {
        MockSocket {
            rule_dumps: VecDeque::new(),
            elem_dumps: VecDeque::new(),
            error_once: None,
            error_split: None,
            sent: Vec::new(),
            pending: VecDeque::new(),
        }
    }
}

fn append_ack(buf: &mut Vec<u8>, errno: i32) {
    buf.extend_from_slice(&36u32.to_le_bytes()); // nlmsg_len = 16 + 20
    buf.extend_from_slice(&NLMSG_ERROR.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes()); // flags
    buf.extend_from_slice(&0u32.to_le_bytes()); // seq
    buf.extend_from_slice(&0u32.to_le_bytes()); // pid
    buf.extend_from_slice(&errno.to_le_bytes()); // nlmsgerr.error(0 = ACK)
    buf.extend_from_slice(&[0u8; 16]); // nlmsgerr.msg(原请求头,解析器不读)
}

/// 一条 dump 应答消息(nlmsghdr + nfgenmsg + 属性区)。
fn append_dump_msg(buf: &mut Vec<u8>, resp_type: u16, seq: u32, payload: &[u8]) {
    let pos = buf.len();
    buf.extend_from_slice(&0u32.to_le_bytes()); // len 回填
    buf.extend_from_slice(&(((NFNL_SUBSYS_NFTABLES) << 8) | resp_type).to_le_bytes());
    buf.extend_from_slice(&NLM_F_MULTI.to_le_bytes());
    buf.extend_from_slice(&seq.to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes()); // pid
    buf.push(NFPROTO_INET);
    buf.push(0); // version
    buf.extend_from_slice(&0u16.to_be_bytes()); // res_id
    buf.extend_from_slice(payload);
    let len = (buf.len() - pos) as u32;
    buf[pos..pos + 4].copy_from_slice(&len.to_le_bytes());
}

fn append_done(buf: &mut Vec<u8>, seq: u32) {
    buf.extend_from_slice(&20u32.to_le_bytes());
    buf.extend_from_slice(&NLMSG_DONE.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&seq.to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes());
    buf.extend_from_slice(&0i32.to_le_bytes()); // dump 返回码
}

impl MockSocket {
    /// GETSETELEM dump 的单条载荷,按**内核**的 interval 集合形态生成:
    /// 每个网段 = 起点节点(携带 timeout)+ 终点哨兵节点(键 = 闭区间末 +1,INTERVAL_END),
    /// 并按 key 降序输出、附一个回绕为 0 的孤立终点哨兵(6.12 实测形状)。
    /// `elems`: (ip 或 cidr, timeout 毫秒)。
    pub fn elem_payload(set: &str, elems: &[(&str, Option<u64>)]) -> Vec<u8> {
        let mut m = Vec::new();
        attr_str(&mut m, NFTA_SET_ELEM_LIST_TABLE, crate::TABLE);
        attr_str(&mut m, NFTA_SET_ELEM_LIST_SET, set);
        let mut nodes: Vec<(Vec<u8>, u32, Option<u64>)> = Vec::new();
        for (ip, tmo_ms) in elems {
            let net = crate::builders::parse_ip_or_cidr(ip).expect("test elem ip");
            let (start, end) = crate::builders::interval_keys(&net);
            nodes.push((start, 0, *tmo_ms));
            nodes.push((end, NFT_SET_ELEM_INTERVAL_END, None));
        }
        nodes.sort_by(|a, b| b.0.cmp(&a.0));
        let els = nest_start(&mut m, NFTA_SET_ELEM_LIST_ELEMENTS);
        for (key, flags, tmo) in &nodes {
            let el = nest_start(&mut m, NFTA_LIST_ELEM);
            let k = nest_start(&mut m, NFTA_SET_ELEM_KEY);
            attr(&mut m, NFTA_DATA_VALUE, key);
            nest_end(&mut m, k);
            if *flags != 0 {
                attr_be32(&mut m, NFTA_SET_ELEM_FLAGS, *flags);
            }
            if let Some(t) = tmo {
                attr_be64(&mut m, NFTA_SET_ELEM_TIMEOUT, *t);
            }
            nest_end(&mut m, el);
        }
        nest_end(&mut m, els);
        m
    }

    /// 是否发出过该 set 的 flush(DELSETELEM 不带 ELEMENTS 属性)。
    pub fn sent_flush(&self, set: &str) -> bool {
        let want = ((NFNL_SUBSYS_NFTABLES) << 8) | NFT_MSG_DELSETELEM;
        self.sent.iter().any(|batch| {
            parse_msgs(batch).0.into_iter().any(|m| {
                if m.mtype != want {
                    return false;
                }
                let attrs = m.attrs(batch);
                find_attr(attrs, NFTA_SET_ELEM_LIST_SET).map(attr_str_of).as_deref() == Some(set)
                    && find_attr(attrs, NFTA_SET_ELEM_LIST_ELEMENTS).is_none()
            })
        })
    }

    /// GETRULE dump 的单条载荷:规则 handle。
    pub fn rule_payload(chain: &str, handle: u64) -> Vec<u8> {
        let mut m = Vec::new();
        attr_str(&mut m, NFTA_RULE_TABLE, crate::TABLE);
        attr_str(&mut m, NFTA_RULE_CHAIN, chain);
        attr_be64(&mut m, NFTA_RULE_HANDLE, handle);
        m
    }

    /// 在已发送的批里找目标 set 的 NEWSETELEM / DELSETELEM 操作,
    /// 用生产解析器还原为 (ip/cidr, 剩余秒)。
    pub fn setelem_ops(&self, msg_type: u16, set: &str) -> Vec<(String, Option<u64>)> {
        let want = ((NFNL_SUBSYS_NFTABLES) << 8) | msg_type;
        let klen = crate::builders::klen_of_set(set);
        let mut out = Vec::new();
        for batch in &self.sent {
            for m in parse_msgs(batch).0 {
                if m.mtype != want {
                    continue;
                }
                let attrs = m.attrs(batch);
                let name = AttrIter::new(attrs)
                    .find(|(t, _)| *t == NFTA_SET_ELEM_LIST_SET)
                    .map(|(_, p)| crate::codec::attr_str_of(p));
                if name.as_deref() == Some(set) {
                    out.extend(parse_set_elements(&[attrs.to_vec()], klen, true));
                }
            }
        }
        out
    }
}

impl NetlinkSocket for MockSocket {
    fn send(&mut self, buf: &[u8]) -> Result<(), NftError> {
        self.sent.push(buf.to_vec());
        let (msgs, _) = parse_msgs(buf);
        let mut acks = 0usize;
        let mut dump_req: Option<(u16, u32)> = None;
        for m in &msgs {
            if m.mtype >> 8 != NFNL_SUBSYS_NFTABLES {
                continue; // BATCH_BEGIN/END
            }
            // NLM_F_DUMP = ROOT|MATCH 双位;EXCL 与 MATCH 同位,
            // CREATE|EXCL 的建链批不能误判为 dump(内核只对 GET 解读 DUMP)
            if (m.flags & NLM_F_DUMP) == NLM_F_DUMP {
                dump_req = Some((m.mtype & 0xff, m.seq));
            } else if m.flags & NLM_F_ACK != 0 {
                acks += 1;
            }
        }
        if let Some((low, seq)) = dump_req {
            let payloads = if low == NFT_MSG_GETRULE {
                self.rule_dumps.pop_front().unwrap_or_default()
            } else {
                self.elem_dumps.pop_front().unwrap_or_default()
            };
            let resp_type = if low == NFT_MSG_GETRULE {
                NFT_MSG_NEWRULE
            } else {
                NFT_MSG_NEWSETELEM
            };
            let mut buf = Vec::new();
            for p in &payloads {
                append_dump_msg(&mut buf, resp_type, seq, p);
            }
            append_done(&mut buf, seq);
            self.pending.push_back(buf);
        }
        if acks > 0 {
            if let Some(errno) = self.error_split.take() {
                let mut first = Vec::with_capacity(36);
                append_ack(&mut first, errno);
                self.pending.push_back(first);
                if acks > 1 {
                    let mut rest = Vec::with_capacity(36 * (acks - 1));
                    for _ in 0..acks - 1 {
                        append_ack(&mut rest, 0);
                    }
                    self.pending.push_back(rest);
                }
            } else {
                let errno = self.error_once.take().unwrap_or(0);
                let mut buf = Vec::with_capacity(36 * acks);
                for _ in 0..acks {
                    append_ack(&mut buf, errno);
                }
                self.pending.push_back(buf);
            }
        }
        Ok(())
    }

    fn recv(&mut self, buf: &mut [u8]) -> Result<usize, NftError> {
        let data = self
            .pending
            .pop_front()
            .expect("mock: recv without canned response");
        assert!(data.len() <= buf.len(), "mock response too large");
        buf[..data.len()].copy_from_slice(&data);
        Ok(data.len())
    }
}

/// 共享包装:测试同时持有 mock 的 Arc,便于事后断言 sent 序列。
pub struct SharedMock(pub std::sync::Arc<std::sync::Mutex<MockSocket>>);

impl NetlinkSocket for SharedMock {
    fn send(&mut self, buf: &[u8]) -> Result<(), NftError> {
        self.0.lock().unwrap().send(buf)
    }
    fn recv(&mut self, buf: &mut [u8]) -> Result<usize, NftError> {
        self.0.lock().unwrap().recv(buf)
    }
}

/// 构造 (共享 mock, 注入用 NftHandle)。
pub fn shared_handle(
    mock: std::sync::Arc<std::sync::Mutex<MockSocket>>,
) -> crate::NftHandle {
    crate::NftHandle::with_socket(Box::new(SharedMock(mock)))
}
