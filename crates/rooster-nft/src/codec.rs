//! netlink 字节级编码/解码原语与消息解析。
//!
//! 编码规则(与 libnftnl / rustables / google-nftables 一致,已交叉核对):
//! - `nlmsghdr`、`nlattr` 头部小端;
//! - nf_tables 的 NFTA_*_U32/U64 载荷统一 **大端**(内核策略 NLA_BE32/BE64,
//!   libnftnl 全部 `htonl`/`htobe64` 后写入);
//! - `nfgenmsg.res_id` 为 `__be16`,BATCH_BEGIN/END 里放 `htons(NFNL_SUBSYS_NFTABLES)`;
//! - 字符串属性带结尾 NUL;嵌套属性置 `NLA_F_NESTED`。

use crate::consts::*;
use crate::NftError;

/// 追加一个通用属性(len + type + payload,4 字节对齐)。
pub fn attr(out: &mut Vec<u8>, atype: u16, payload: &[u8]) {
    let len = (4 + payload.len()) as u16;
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(&(atype & 0xffff).to_le_bytes());
    out.extend_from_slice(payload);
    while out.len() % NLMSG_ALIGNTO != 0 {
        out.push(0);
    }
}

/// 嵌套属性:先写头,调用方填充内容后用 [`nest_end`] 回填长度。
pub fn nest_start(out: &mut Vec<u8>, atype: u16) -> usize {
    let pos = out.len();
    out.extend_from_slice(&4u16.to_le_bytes());
    out.extend_from_slice(&(atype | NLA_F_NESTED).to_le_bytes());
    pos
}

pub fn nest_end(out: &mut Vec<u8>, pos: usize) {
    let len = (out.len() - pos) as u16;
    out[pos..pos + 2].copy_from_slice(&len.to_le_bytes());
}

pub fn attr_str(out: &mut Vec<u8>, atype: u16, s: &str) {
    let mut p = Vec::with_capacity(s.len() + 1);
    p.extend_from_slice(s.as_bytes());
    p.push(0);
    attr(out, atype, &p);
}

pub fn attr_be32(out: &mut Vec<u8>, atype: u16, v: u32) {
    attr(out, atype, &v.to_be_bytes());
}

pub fn attr_be64(out: &mut Vec<u8>, atype: u16, v: u64) {
    attr(out, atype, &v.to_be_bytes());
}

/// 写一条 nftables 子系统消息头(nlmsghdr + nfgenmsg),返回消息起始位置。
/// `msg_type` 为低 8 位操作码,子系统号固定拼在高位(rustables nlmsg.rs 同款)。
pub fn nf_msg_start(out: &mut Vec<u8>, msg_type: u16, family: u8, flags: u16, seq: u32) -> usize {
    let pos = out.len();
    let nlmsg_type = (NFNL_SUBSYS_NFTABLES << 8) | (msg_type & 0xff);
    out.extend_from_slice(&0u32.to_le_bytes()); // nlmsg_len,回填
    out.extend_from_slice(&nlmsg_type.to_le_bytes());
    out.extend_from_slice(&(NLM_F_REQUEST | flags).to_le_bytes());
    out.extend_from_slice(&seq.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes()); // nlmsg_pid
    // nfgenmsg
    out.push(family);
    out.push(NFNETLINK_V0);
    out.extend_from_slice(&0u16.to_be_bytes()); // res_id,普通消息为 0
    pos
}

pub fn nf_msg_end(out: &mut Vec<u8>, pos: usize) {
    let len = (out.len() - pos) as u32;
    out[pos..pos + 4].copy_from_slice(&len.to_le_bytes());
}

/// 组装一个事务批:BATCH_BEGIN + ops + BATCH_END(单 buf)。
/// `ops` 由调用方先用 [`nf_msg_start`] 写好。
pub fn wrap_batch(ops: &[u8], seq_begin: u32, seq_end: u32) -> Vec<u8> {
    let mut buf = Vec::with_capacity(40 + ops.len());
    // nfnetlink 批消息:nlmsg_type 不带子系统号,res_id=htons(NFNL_SUBSYS_NFTABLES)
    for (mt, seq) in [
        (NFNL_MSG_BATCH_BEGIN, seq_begin),
        (NFNL_MSG_BATCH_END, seq_end),
    ] {
        let pos = buf.len();
        buf.extend_from_slice(&20u32.to_le_bytes()); // nlmsg_len = 16 + 4(nfgenmsg)
        buf.extend_from_slice(&mt.to_le_bytes());
        buf.extend_from_slice(&NLM_F_REQUEST.to_le_bytes());
        buf.extend_from_slice(&seq.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes()); // pid
        buf.push(0); // nfgen_family = AF_UNSPEC
        buf.push(NFNETLINK_V0);
        buf.extend_from_slice(&NFNL_SUBSYS_NFTABLES.to_be_bytes()); // __be16 res_id
        debug_assert_eq!(buf.len() - pos, 20);
    }
    let mut out = Vec::with_capacity(buf.len() + ops.len());
    out.extend_from_slice(&buf[..20]); // BEGIN
    out.extend_from_slice(ops);
    out.extend_from_slice(&buf[20..]); // END
    out
}

// ---------- 解析 ----------

/// 解析一段收到的字节里的所有 netlink 消息,返回 (type, flags, seq, 载荷起始, 消息总长)。
/// `consumed` 返回已完整解析的字节数,便于调用方保留残包。
pub fn parse_msgs(buf: &[u8]) -> (Vec<ParsedMsg>, usize) {
    let mut msgs = Vec::new();
    let mut off = 0;
    while off + NLMSG_HDRLEN <= buf.len() {
        let len = u32::from_le_bytes(buf[off..off + 4].try_into().unwrap()) as usize;
        if len < NLMSG_HDRLEN || off + len > buf.len() {
            break; // 残包,留待下次 recv
        }
        let mtype = u16::from_le_bytes(buf[off + 4..off + 6].try_into().unwrap());
        let flags = u16::from_le_bytes(buf[off + 6..off + 8].try_into().unwrap());
        let seq = u32::from_le_bytes(buf[off + 8..off + 12].try_into().unwrap());
        msgs.push(ParsedMsg {
            mtype,
            flags,
            seq,
            body: off..off + len,
        });
        off += align4(len);
    }
    (msgs, off)
}

#[derive(Debug, Clone)]
pub struct ParsedMsg {
    pub mtype: u16,
    pub flags: u16,
    pub seq: u32,
    /// 整条消息在输入 buf 中的范围
    pub body: std::ops::Range<usize>,
}

impl ParsedMsg {
    /// nlmsgerr.error(NLMSG_ERROR 时,消息体前 4 字节,i32,0 表示 ACK)
    pub fn errno(&self, buf: &[u8]) -> Option<i32> {
        if self.mtype != NLMSG_ERROR {
            return None;
        }
        buf.get(self.body.start + 16..self.body.start + 20)
            .map(|b| i32::from_le_bytes(b.try_into().unwrap()))
    }
    /// nftables 消息的属性区(nfgenmsg 之后)
    pub fn attrs<'a>(&self, buf: &'a [u8]) -> &'a [u8] {
        let s = self.body.start + NLMSG_HDRLEN + 4;
        let e = self.body.end.min(buf.len());
        if s > e {
            &[]
        } else {
            &buf[s..e]
        }
    }

    /// extack 文本(`NLMSGERR_ATTR_MSG`):内核拒绝整批时到底在哪个属性上不满意,
    /// 只有 errno 的话根本看不出来(EINVAL 尤其如此)。布局:
    /// nlmsghdr(16) + nlmsgerr.error(4) + 回显 nlmsghdr(16) + extack 属性区。
    pub fn extack_msg(&self, buf: &[u8]) -> Option<String> {
        if self.mtype != NLMSG_ERROR {
            return None;
        }
        let start = self.body.start + NLMSG_HDRLEN + 20;
        let end = self.body.end.min(buf.len());
        if start >= end {
            return None;
        }
        for (atype, val) in AttrIter::new(&buf[start..end]) {
            if atype & NLA_TYPE_MASK != NLMSGERR_ATTR_MSG {
                continue;
            }
            let cut = val.iter().position(|b| *b == 0).unwrap_or(val.len());
            let text = String::from_utf8_lossy(&val[..cut]).into_owned();
            if !text.is_empty() {
                return Some(text);
            }
        }
        None
    }
}

/// 属性遍历器。
pub struct AttrIter<'a> {
    buf: &'a [u8],
    off: usize,
}

impl<'a> AttrIter<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        AttrIter { buf, off: 0 }
    }
}

impl<'a> Iterator for AttrIter<'a> {
    type Item = (u16, &'a [u8]);
    fn next(&mut self) -> Option<Self::Item> {
        if self.off + 4 > self.buf.len() {
            return None;
        }
        let len = u16::from_le_bytes(self.buf[self.off..self.off + 2].try_into().unwrap()) as usize;
        if len < 4 || self.off + len > self.buf.len() {
            return None;
        }
        let atype = u16::from_le_bytes(self.buf[self.off + 2..self.off + 4].try_into().unwrap())
            & NLA_TYPE_MASK;
        let payload = &self.buf[self.off + 4..self.off + len];
        self.off += align4(len);
        Some((atype, payload))
    }
}

/// 在属性区里找指定类型的第一个属性载荷。
pub fn find_attr<'a>(buf: &'a [u8], atype: u16) -> Option<&'a [u8]> {
    AttrIter::new(buf).find(|(t, _)| *t == atype).map(|(_, p)| p)
}

pub fn attr_be32_of(payload: &[u8]) -> u32 {
    if payload.len() < 4 {
        return 0;
    }
    u32::from_be_bytes(payload[..4].try_into().unwrap())
}

pub fn attr_be64_of(payload: &[u8]) -> u64 {
    if payload.len() < 8 {
        return 0;
    }
    u64::from_be_bytes(payload[..8].try_into().unwrap())
}

/// NUL 结尾字符串属性。
pub fn attr_str_of(payload: &[u8]) -> String {
    let end = payload.iter().position(|&b| b == 0).unwrap_or(payload.len());
    String::from_utf8_lossy(&payload[..end]).into_owned()
}

/// 把 netlink 错误 errno 转成带 strerror 的文本。
pub fn errno_text(errno: i32) -> String {
    let e = std::io::Error::from_raw_os_error(errno.abs());
    format!("errno {} ({})", errno, e)
}

pub fn netlink_err(msg: impl std::fmt::Display) -> NftError {
    NftError::Netlink(msg.to_string())
}

/// 把内核 extack 拼到错误文本后面(没有则原样)。
pub fn err_with_extack(prefix: &str, errno: i32, extack: Option<String>) -> NftError {
    match extack {
        Some(msg) => NftError::Netlink(format!("{prefix}{}; kernel: {msg}", errno_text(errno))),
        None => NftError::Netlink(format!("{prefix}{}", errno_text(errno))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 构造一条带 extack 的 NLMSG_ERROR(errno + 回显头 + NLMSGERR_ATTR_MSG)。
    fn err_msg(errno: i32, extack: Option<&str>) -> Vec<u8> {
        let mut attrs = Vec::new();
        if let Some(text) = extack {
            let payload = format!("{text}\0");
            let len = 4 + payload.len();
            attrs.extend_from_slice(&(len as u16).to_le_bytes());
            attrs.extend_from_slice(&NLMSGERR_ATTR_MSG.to_le_bytes());
            attrs.extend_from_slice(payload.as_bytes());
            while attrs.len() % 4 != 0 {
                attrs.push(0);
            }
        }
        let mut buf = Vec::new();
        buf.extend_from_slice(&((36 + attrs.len()) as u32).to_le_bytes());
        buf.extend_from_slice(&NLMSG_ERROR.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.extend_from_slice(&7u32.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&errno.to_le_bytes());
        buf.extend_from_slice(&[0u8; 16]);
        buf.extend_from_slice(&attrs);
        buf
    }

    #[test]
    fn extack_msg_is_extracted_and_absent_is_none() {
        let buf = err_msg(-22, Some("flags interval and timeout are mutually exclusive"));
        let (msgs, _) = parse_msgs(&buf);
        let m = msgs.iter().find(|m| m.mtype == NLMSG_ERROR).expect("error msg");
        assert_eq!(m.errno(&buf), Some(-22));
        assert_eq!(
            m.extack_msg(&buf).as_deref(),
            Some("flags interval and timeout are mutually exclusive")
        );

        let plain = err_msg(-22, None);
        let (msgs, _) = parse_msgs(&plain);
        let m = msgs.iter().find(|m| m.mtype == NLMSG_ERROR).unwrap();
        assert_eq!(m.extack_msg(&plain), None, "无 extack 时不得误报");

        let text = err_with_extack("nftables batch rejected: ", -22, m.extack_msg(&plain)).to_string();
        assert!(text.contains("errno -22"), "got: {text}");
        assert!(!text.contains("kernel:"), "got: {text}");
    }
}
