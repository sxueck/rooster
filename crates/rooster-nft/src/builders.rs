//! nf_tables 消息构造器(NEWTABLE/NEWSET/NEWCHAIN/NEWRULE/NEWSETELEM/… 与 dump 请求)。
//!
//! 属性顺序镜像 rustables 0.5.x / libnftnl:
//! - NEWSET: TABLE, NAME, FLAGS, KEY_TYPE, KEY_LEN[, TIMEOUT]
//! - NEWCHAIN: TABLE, NAME, HOOK{HOOKNUM,PRIORITY}, POLICY, TYPE
//! - NEWRULE: TABLE, CHAIN, EXPRESSIONS{LIST_ELEM{EXPR_NAME, EXPR_DATA}}
//! - NEWSETELEM: TABLE, SET, ELEMENTS{LIST_ELEM{KEY}, LIST_ELEM{KEY, FLAGS=INTERVAL_END}}
//! 表达式属性顺序镜像 google-nftables / libnftnl 各 expr/*.c 的 build 函数。

use crate::codec::*;
use crate::consts::*;
use ipnet::IpNet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub const PRE_CHAIN: &str = "pre";
pub const SSH_CHAIN: &str = "ssh_limit";

/// 每个 set 的 (名称, klen, flags)。
pub fn set_specs() -> [(&'static str, u32, u32); 6] {
    [
        (crate::SET_ALLOW_V4, 4, NFT_SET_INTERVAL),
        (crate::SET_ALLOW_V6, 16, NFT_SET_INTERVAL),
        (
            crate::SET_BLOCK_V4,
            4,
            NFT_SET_INTERVAL | NFT_SET_TIMEOUT,
        ),
        (
            crate::SET_BLOCK_V6,
            16,
            NFT_SET_INTERVAL | NFT_SET_TIMEOUT,
        ),
        (crate::SET_GEO_V4, 4, NFT_SET_INTERVAL),
        (crate::SET_GEO_V6, 16, NFT_SET_INTERVAL),
    ]
}

pub struct Seq {
    next: u32,
}

impl Seq {
    pub fn new() -> Self {
        Seq { next: 1 }
    }
    pub fn get(&mut self) -> u32 {
        let v = self.next;
        self.next = self.next.wrapping_add(1);
        v
    }
}

fn op_msg(out: &mut Vec<u8>, msg_type: u16, flags: u16, seq: &mut Seq, family: u8, attrs: impl FnOnce(&mut Vec<u8>)) {
    let s = seq.get();
    let pos = nf_msg_start(out, msg_type, family, flags, s);
    attrs(out);
    nf_msg_end(out, pos);
}

/// CREATE|EXCL(幂等创建,EEXIST 由上层容忍)
pub const F_CREATE_EXCL: u16 = NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL;
pub const F_CREATE: u16 = NLM_F_ACK | NLM_F_CREATE;
pub const F_CREATE_APPEND: u16 = NLM_F_ACK | NLM_F_CREATE | NLM_F_APPEND;
pub const F_ACK_ONLY: u16 = NLM_F_ACK;

/// ensure_table 第一阶段:NEWTABLE + 6×NEWSET + NEWCHAIN pre。
/// family 全部为 NFPROTO_INET(table inet rooster)。
pub fn build_ensure_creates(seq: &mut Seq) -> Vec<u8> {
    let mut ops = Vec::with_capacity(1024);
    op_msg(&mut ops, NFT_MSG_NEWTABLE, F_CREATE_EXCL, seq, NFPROTO_INET, |a| {
        attr_str(a, NFTA_TABLE_NAME, crate::TABLE);
    });
    for (i, (name, klen, flags)) in set_specs().into_iter().enumerate() {
        op_msg(&mut ops, NFT_MSG_NEWSET, F_CREATE_EXCL, seq, NFPROTO_INET, |a| {
            attr_str(a, NFTA_SET_TABLE, crate::TABLE);
            attr_str(a, NFTA_SET_NAME, name);
            attr_be32(a, NFTA_SET_FLAGS, flags);
            attr_be32(
                a,
                NFTA_SET_KEY_TYPE,
                if klen == 4 {
                    NFT_DATATYPE_IPADDR
                } else {
                    NFT_DATATYPE_IP6ADDR
                },
            );
            attr_be32(a, NFTA_SET_KEY_LEN, klen);
            // 表内 id 必须唯一:常驻 6 个集合占 1..6,meter 集合从 7 起。
            attr_be32(a, NFTA_SET_ID, 1 + i as u32);
        });
    }
    op_msg(&mut ops, NFT_MSG_NEWCHAIN, F_CREATE_EXCL, seq, NFPROTO_INET, |a| {
        attr_str(a, NFTA_CHAIN_TABLE, crate::TABLE);
        attr_str(a, NFTA_CHAIN_NAME, PRE_CHAIN);
        let h = nest_start(a, NFTA_CHAIN_HOOK);
        attr_be32(a, NFTA_HOOK_HOOKNUM, NF_INET_PRE_ROUTING); // hook prerouting
        attr_be32(a, NFTA_HOOK_PRIORITY, (-300i32) as u32); // priority -300
        nest_end(a, h);
        attr_be32(a, NFTA_CHAIN_POLICY, NF_ACCEPT as u32); // policy accept
        attr_str(a, NFTA_CHAIN_TYPE, "filter");
    });
    wrap_batch(&ops, seq.get(), seq.get())
}

/// `ip/ip6 saddr @<set> <verdict>` 规则。
/// 显式协议族依赖 + payload 提取 + lookup + immediate verdict:
/// v4: [meta nfproto==ipv4][payload nh off 12 len 4 -> reg1][lookup]
/// v6: [meta nfproto==ipv6][payload nh off 8 len 16 -> reg1][lookup]
pub fn build_saddr_rule(seq: &mut Seq, set: &str, v6: bool, accept: bool) -> Vec<u8> {
    let mut ops = Vec::with_capacity(256);
    let mut exprs = Vec::with_capacity(200);
    // 1. meta nfproto => reg1;cmp == family
    expr_meta_nfproto(&mut exprs, if v6 { NFPROTO_IPV6 } else { NFPROTO_IPV4 });
    // 2. payload saddr => reg1
    expr_payload_saddr(&mut exprs, v6);
    // 3. lookup @set in reg1(verdict-free)
    {
        let e = nest_start(&mut exprs, NFTA_LIST_ELEM);
        let d = nest_start(&mut exprs, NFTA_EXPR_DATA);
        attr_be32(&mut exprs, NFTA_LOOKUP_SREG, NFT_REG_1);
        attr_str(&mut exprs, NFTA_LOOKUP_SET, set);
        nest_end(&mut exprs, d);
        attr_str(&mut exprs, NFTA_EXPR_NAME, "lookup");
        nest_end(&mut exprs, e);
    }
    // 4. immediate verdict
    expr_verdict(&mut exprs, if accept { NF_ACCEPT } else { NF_DROP });
    op_msg(&mut ops, NFT_MSG_NEWRULE, F_CREATE_APPEND, seq, NFPROTO_INET, |a| {
        attr_str(a, NFTA_RULE_TABLE, crate::TABLE);
        attr_str(a, NFTA_RULE_CHAIN, PRE_CHAIN);
        let x = nest_start(a, NFTA_RULE_EXPRESSIONS);
        a.extend_from_slice(&exprs);
        nest_end(a, x);
    });
    ops
}

/// ensure_table 第二阶段:清空 pre 链(按 handle DELRULE)后重加 6 条规则。
pub fn build_ensure_rules(seq: &mut Seq, old_handles: &[u64]) -> Vec<u8> {
    let mut ops = Vec::with_capacity(1024);
    for h in old_handles {
        op_msg(&mut ops, NFT_MSG_DELRULE, F_ACK_ONLY, seq, NFPROTO_INET, |a| {
            attr_str(a, NFTA_RULE_TABLE, crate::TABLE);
            attr_str(a, NFTA_RULE_CHAIN, PRE_CHAIN);
            attr_be64(a, NFTA_RULE_HANDLE, *h);
        });
    }
    for (set, v6, accept) in [
        (crate::SET_ALLOW_V4, false, true),
        (crate::SET_ALLOW_V6, true, true),
        (crate::SET_BLOCK_V4, false, false),
        (crate::SET_BLOCK_V6, true, false),
        (crate::SET_GEO_V4, false, false),
        (crate::SET_GEO_V6, true, false),
    ] {
        let mut r = build_saddr_rule(seq, set, v6, accept);
        ops.append(&mut r);
    }
    wrap_batch(&ops, seq.get(), seq.get())
}

// ---------- 表达式 ----------

/// [meta load nfproto => reg1][cmp eq reg1 <1 字节 family>]
fn expr_meta_nfproto(exprs: &mut Vec<u8>, nfproto: u8) {
    {
        let e = nest_start(exprs, NFTA_LIST_ELEM);
        let d = nest_start(exprs, NFTA_EXPR_DATA);
        attr_be32(exprs, NFTA_META_KEY, NFT_META_NFPROTO);
        attr_be32(exprs, NFTA_META_DREG, NFT_REG_1);
        nest_end(exprs, d);
        attr_str(exprs, NFTA_EXPR_NAME, "meta");
        nest_end(exprs, e);
    }
    expr_cmp_eq(exprs, &[nfproto]);
}

/// [payload load nh offset (12|8) len (4|16) => reg1]
pub fn expr_payload_saddr(exprs: &mut Vec<u8>, v6: bool) {
    let e = nest_start(exprs, NFTA_LIST_ELEM);
    let d = nest_start(exprs, NFTA_EXPR_DATA);
    attr_be32(exprs, NFTA_PAYLOAD_DREG, NFT_REG_1);
    attr_be32(exprs, NFTA_PAYLOAD_BASE, NFT_PAYLOAD_NETWORK_HEADER);
    attr_be32(exprs, NFTA_PAYLOAD_OFFSET, if v6 { 8 } else { 12 });
    attr_be32(exprs, NFTA_PAYLOAD_LEN, if v6 { 16 } else { 4 });
    nest_end(exprs, d);
    attr_str(exprs, NFTA_EXPR_NAME, "payload");
    nest_end(exprs, e);
}

/// [cmp eq reg1 <data>]
fn expr_cmp_eq(exprs: &mut Vec<u8>, data: &[u8]) {
    let e = nest_start(exprs, NFTA_LIST_ELEM);
    let d = nest_start(exprs, NFTA_EXPR_DATA);
    attr_be32(exprs, NFTA_CMP_SREG, NFT_REG_1);
    attr_be32(exprs, NFTA_CMP_OP, NFT_CMP_EQ);
    let cd = nest_start(exprs, NFTA_CMP_DATA);
    attr(exprs, NFTA_DATA_VALUE, data);
    nest_end(exprs, cd);
    nest_end(exprs, d);
    attr_str(exprs, NFTA_EXPR_NAME, "cmp");
    nest_end(exprs, e);
}

/// [immediate reg0 verdict code]
pub fn expr_verdict(exprs: &mut Vec<u8>, code: i32) {
    let e = nest_start(exprs, NFTA_LIST_ELEM);
    let d = nest_start(exprs, NFTA_EXPR_DATA);
    attr_be32(exprs, NFTA_IMMEDIATE_DREG, NFT_REG_VERDICT);
    let vd = nest_start(exprs, NFTA_IMMEDIATE_DATA);
    let v = nest_start(exprs, NFTA_DATA_VERDICT);
    attr_be32(exprs, NFTA_VERDICT_CODE, code as u32);
    nest_end(exprs, v);
    nest_end(exprs, vd);
    nest_end(exprs, d);
    attr_str(exprs, NFTA_EXPR_NAME, "immediate");
    nest_end(exprs, e);
}

/// [ct load state => reg1][bitwise reg1 = reg1 & 8 ^ 0][cmp neq reg1 0] —— `ct state new`
fn expr_ct_state_new(exprs: &mut Vec<u8>) {
    {
        let e = nest_start(exprs, NFTA_LIST_ELEM);
        let d = nest_start(exprs, NFTA_EXPR_DATA);
        attr_be32(exprs, NFTA_CT_KEY, NFT_CT_STATE);
        attr_be32(exprs, NFTA_CT_DREG, NFT_REG_1);
        nest_end(exprs, d);
        attr_str(exprs, NFTA_EXPR_NAME, "ct");
        nest_end(exprs, e);
    }
    {
        // bitwise mask 0x8(与大端掩码字节序一致:nft 生成 0x00000008)
        let e = nest_start(exprs, NFTA_LIST_ELEM);
        let d = nest_start(exprs, NFTA_EXPR_DATA);
        attr_be32(exprs, NFTA_BITWISE_SREG, NFT_REG_1);
        attr_be32(exprs, NFTA_BITWISE_DREG, NFT_REG_1);
        attr_be32(exprs, NFTA_BITWISE_LEN, 4);
        let m = nest_start(exprs, NFTA_BITWISE_MASK);
        attr(exprs, NFTA_DATA_VALUE, &CT_STATE_NEW_BIT.to_be_bytes());
        nest_end(exprs, m);
        let x = nest_start(exprs, NFTA_BITWISE_XOR);
        attr(exprs, NFTA_DATA_VALUE, &0u32.to_be_bytes());
        nest_end(exprs, x);
        nest_end(exprs, d);
        attr_str(exprs, NFTA_EXPR_NAME, "bitwise");
        nest_end(exprs, e);
    }
    {
        let e = nest_start(exprs, NFTA_LIST_ELEM);
        let d = nest_start(exprs, NFTA_EXPR_DATA);
        attr_be32(exprs, NFTA_CMP_SREG, NFT_REG_1);
        attr_be32(exprs, NFTA_CMP_OP, NFT_CMP_NEQ);
        let cd = nest_start(exprs, NFTA_CMP_DATA);
        attr(exprs, NFTA_DATA_VALUE, &0u32.to_be_bytes());
        nest_end(exprs, cd);
        nest_end(exprs, d);
        attr_str(exprs, NFTA_EXPR_NAME, "cmp");
        nest_end(exprs, e);
    }
}

/// [meta l4proto => reg1][cmp eq 6][payload th off 2 len 2 => reg1][cmp eq BE16 port]
fn expr_tcp_dport(exprs: &mut Vec<u8>, port: u16) {
    {
        let e = nest_start(exprs, NFTA_LIST_ELEM);
        let d = nest_start(exprs, NFTA_EXPR_DATA);
        attr_be32(exprs, NFTA_META_KEY, NFT_META_L4PROTO);
        attr_be32(exprs, NFTA_META_DREG, NFT_REG_1);
        nest_end(exprs, d);
        attr_str(exprs, NFTA_EXPR_NAME, "meta");
        nest_end(exprs, e);
    }
    expr_cmp_eq(exprs, &[IPPROTO_TCP]);
    {
        let e = nest_start(exprs, NFTA_LIST_ELEM);
        let d = nest_start(exprs, NFTA_EXPR_DATA);
        attr_be32(exprs, NFTA_PAYLOAD_DREG, NFT_REG_1);
        attr_be32(exprs, NFTA_PAYLOAD_BASE, NFT_PAYLOAD_TRANSPORT_HEADER);
        attr_be32(exprs, NFTA_PAYLOAD_OFFSET, 2);
        attr_be32(exprs, NFTA_PAYLOAD_LEN, 2);
        nest_end(exprs, d);
        attr_str(exprs, NFTA_EXPR_NAME, "payload");
        nest_end(exprs, e);
    }
    expr_cmp_eq(exprs, &port.to_be_bytes());
}

/// meter 规则(v4/v6 各一):
/// `tcp dport <port> ct state new meter <name> { ip/ip6 saddr limit rate over <rate> burst <burst> } drop`
/// = meta nfproto 依赖 + payload saddr + tcp dport 依赖链 + ct state new +
///   dynset{limit 嵌套} + immediate drop。
/// dynset 属性顺序镜像 libnftnl expr/dynset.c:SREG_KEY, OP, TIMEOUT, SET_NAME, [EXPR]。
/// NFTA_LIMIT_UNIT 内核按毫秒解释(nft_limit.c:`nsecs = unit * NSEC_PER_MSEC`),
/// NFTA_DYNSET_TIMEOUT 同样是毫秒;元素超时取 max(单位, 60s) 与 GC 对齐。
fn build_meter_rule(seq: &mut Seq, v6: bool, port: u16, rate: u64, unit_ms: u64, burst: u32, set: &str) -> Vec<u8> {
    let elem_ttl_ms = unit_ms.max(60_000);
    let mut exprs = Vec::with_capacity(512);
    expr_meta_nfproto(&mut exprs, if v6 { NFPROTO_IPV6 } else { NFPROTO_IPV4 });
    expr_payload_saddr(&mut exprs, v6);
    expr_tcp_dport(&mut exprs, port);
    expr_ct_state_new(&mut exprs);
    // dynset
    {
        let e = nest_start(&mut exprs, NFTA_LIST_ELEM);
        let d = nest_start(&mut exprs, NFTA_EXPR_DATA);
        attr_be32(&mut exprs, NFTA_DYNSET_SREG_KEY, NFT_REG_1);
        attr_be32(&mut exprs, NFTA_DYNSET_OP, NFT_DYNSET_OP_ADD);
        attr_be64(&mut exprs, NFTA_DYNSET_TIMEOUT, elem_ttl_ms);
        attr_str(&mut exprs, NFTA_DYNSET_SET_NAME, set);
        // NFTA_DYNSET_EXPR 嵌套 limit 表达式(libnftnl meter/dynset 方式)
        let x = nest_start(&mut exprs, NFTA_DYNSET_EXPR);
        let le = nest_start(&mut exprs, NFTA_LIST_ELEM);
        let ld = nest_start(&mut exprs, NFTA_EXPR_DATA);
        attr_be64(&mut exprs, NFTA_LIMIT_RATE, rate);
        attr_be64(&mut exprs, NFTA_LIMIT_UNIT, unit_ms);
        attr_be32(&mut exprs, NFTA_LIMIT_BURST, burst);
        attr_be32(&mut exprs, NFTA_LIMIT_TYPE, NFT_LIMIT_PKTS);
        attr_be32(&mut exprs, NFTA_LIMIT_FLAGS, NFT_LIMIT_F_INV); // rate *over*
        nest_end(&mut exprs, ld);
        attr_str(&mut exprs, NFTA_EXPR_NAME, "limit");
        nest_end(&mut exprs, le);
        nest_end(&mut exprs, x);
        nest_end(&mut exprs, d);
        attr_str(&mut exprs, NFTA_EXPR_NAME, "dynset");
        nest_end(&mut exprs, e);
    }
    expr_verdict(&mut exprs, NF_DROP);
    let mut ops = Vec::with_capacity(exprs.len() + 64);
    op_msg(&mut ops, NFT_MSG_NEWRULE, F_CREATE_APPEND, seq, NFPROTO_INET, |a| {
        attr_str(a, NFTA_RULE_TABLE, crate::TABLE);
        attr_str(a, NFTA_RULE_CHAIN, SSH_CHAIN);
        let x = nest_start(a, NFTA_RULE_EXPRESSIONS);
        a.extend_from_slice(&exprs);
        nest_end(a, x);
    });
    ops
}

/// `set_ssh_rate_limit` 第一阶段:2 个 meter set(EVAL|TIMEOUT)+ ssh_limit 基链。
pub fn build_ssh_creates(seq: &mut Seq) -> Vec<u8> {
    let mut ops = Vec::with_capacity(512);
    for (i, (name, klen)) in [("sshm4", 4u32), ("sshm6", 16u32)].into_iter().enumerate() {
        op_msg(&mut ops, NFT_MSG_NEWSET, F_CREATE_EXCL, seq, NFPROTO_INET, |a| {
            attr_str(a, NFTA_SET_TABLE, crate::TABLE);
            attr_str(a, NFTA_SET_NAME, name);
            attr_be32(a, NFTA_SET_FLAGS, NFT_SET_TIMEOUT | NFT_SET_EVAL);
            attr_be32(
                a,
                NFTA_SET_KEY_TYPE,
                if klen == 4 {
                    NFT_DATATYPE_IPADDR
                } else {
                    NFT_DATATYPE_IP6ADDR
                },
            );
            attr_be32(a, NFTA_SET_KEY_LEN, klen);
            attr_be32(a, NFTA_SET_ID, 7 + i as u32); // 避开常驻集合的 1..6
        });
    }
    op_msg(&mut ops, NFT_MSG_NEWCHAIN, F_CREATE_EXCL, seq, NFPROTO_INET, |a| {
        attr_str(a, NFTA_CHAIN_TABLE, crate::TABLE);
        attr_str(a, NFTA_CHAIN_NAME, SSH_CHAIN);
        let h = nest_start(a, NFTA_CHAIN_HOOK);
        attr_be32(a, NFTA_HOOK_HOOKNUM, NF_INET_LOCAL_IN); // hook input
        attr_be32(a, NFTA_HOOK_PRIORITY, 0);
        nest_end(a, h);
        attr_be32(a, NFTA_CHAIN_POLICY, NF_ACCEPT as u32);
        attr_str(a, NFTA_CHAIN_TYPE, "filter");
    });
    wrap_batch(&ops, seq.get(), seq.get())
}

/// `set_ssh_rate_limit` 第二阶段:清空 ssh_limit 链 + 两条 meter 规则。
/// `unit_ms` 为限速单位的毫秒数(1s/60s/3600s),meter 元素超时在规则内推导。
pub fn build_ssh_rules(seq: &mut Seq, old_handles: &[u64], port: u16, rate: u64, unit_ms: u64, burst: u32) -> Vec<u8> {
    let mut ops = Vec::with_capacity(2048);
    for h in old_handles {
        op_msg(&mut ops, NFT_MSG_DELRULE, F_ACK_ONLY, seq, NFPROTO_INET, |a| {
            attr_str(a, NFTA_RULE_TABLE, crate::TABLE);
            attr_str(a, NFTA_RULE_CHAIN, SSH_CHAIN);
            attr_be64(a, NFTA_RULE_HANDLE, *h);
        });
    }
    let mut r = build_meter_rule(seq, false, port, rate, unit_ms, burst, "sshm4");
    ops.append(&mut r);
    let mut r = build_meter_rule(seq, true, port, rate, unit_ms, burst, "sshm6");
    ops.append(&mut r);
    wrap_batch(&ops, seq.get(), seq.get())
}

// ---------- set 元素 ----------

/// 区间边界:内核把 interval 集合的元素存成 [start, end) 两个节点,
/// 尾节点带 NFT_SET_ELEM_INTERVAL_END,键值 = 闭区间末地址 +1;
/// 覆盖到地址上界时 +1 回绕成全零(6.12 实测与 nft CLI 一致)。
pub(crate) fn interval_keys(net: &IpNet) -> (Vec<u8>, Vec<u8>) {
    let (s, e) = match net {
        IpNet::V4(n) => (
            u32::from(n.network()) as u128,
            u32::from(n.broadcast()) as u128,
        ),
        IpNet::V6(n) => (u128::from(n.network()), u128::from(n.broadcast())),
    };
    let klen = match net {
        IpNet::V4(_) => 4,
        IpNet::V6(_) => 16,
    };
    let enc = |v: u128| {
        let raw = v.to_be_bytes();
        raw[16 - klen..].to_vec()
    };
    (enc(s), enc(e.wrapping_add(1)))
}

/// 单个 LIST_ELEM:key(+ 可选 interval 终点标志 / timeout)。
fn put_elem(a: &mut Vec<u8>, key: &[u8], interval_end: bool, timeout_ms: Option<u64>) {
    let el = nest_start(a, NFTA_LIST_ELEM);
    let k = nest_start(a, NFTA_SET_ELEM_KEY);
    attr(a, NFTA_DATA_VALUE, key);
    nest_end(a, k);
    if interval_end {
        attr_be32(a, NFTA_SET_ELEM_FLAGS, NFT_SET_ELEM_INTERVAL_END);
    }
    if let Some(t) = timeout_ms {
        attr_be64(a, NFTA_SET_ELEM_TIMEOUT, t);
    }
    nest_end(a, el);
}

/// 一个网段 → 起点节点 + 终点哨兵节点。timeout 只挂起点:两端都挂内核回 EINVAL(6.12 实测)。
pub fn put_interval_elems(a: &mut Vec<u8>, net: &IpNet, timeout: Option<std::time::Duration>) {
    let (start, end) = interval_keys(net);
    put_elem(a, &start, false, timeout.map(|t| t.as_millis() as u64));
    put_elem(a, &end, true, None);
}

fn setelem_msg(seq: &mut Seq, msg: u16, flags: u16, set: &str, body: impl FnOnce(&mut Vec<u8>)) -> Vec<u8> {
    let mut m = Vec::with_capacity(200);
    let s = seq.get();
    let pos = nf_msg_start(&mut m, msg, NFPROTO_INET, flags, s);
    attr_str(&mut m, NFTA_SET_ELEM_LIST_TABLE, crate::TABLE);
    attr_str(&mut m, NFTA_SET_ELEM_LIST_SET, set);
    body(&mut m);
    nf_msg_end(&mut m, pos);
    m
}

/// NEWSETELEM 裸消息(可批量多个区间)。
fn new_setelem_msg(
    seq: &mut Seq,
    set: &str,
    rows: &[(IpNet, Option<std::time::Duration>)],
) -> Vec<u8> {
    setelem_msg(seq, NFT_MSG_NEWSETELEM, F_CREATE, set, |m| {
        let els = nest_start(m, NFTA_SET_ELEM_LIST_ELEMENTS);
        for (net, t) in rows {
            put_interval_elems(m, net, *t);
        }
        nest_end(m, els);
    })
}

/// DELSETELEM 裸消息:`ranges` 为空即 flush 语义(不带 ELEMENTS 属性,同 `nft flush set X`)。
fn del_setelem_msg(seq: &mut Seq, set: &str, ranges: &[IpNet]) -> Vec<u8> {
    setelem_msg(seq, NFT_MSG_DELSETELEM, F_ACK_ONLY, set, |m| {
        if ranges.is_empty() {
            return;
        }
        let els = nest_start(m, NFTA_SET_ELEM_LIST_ELEMENTS);
        for net in ranges {
            put_interval_elems(m, net, None);
        }
        nest_end(m, els);
    })
}

/// NEWSETELEM 消息。timeout 毫秒。
pub fn build_new_setelem(
    seq: &mut Seq,
    set: &str,
    net: &IpNet,
    timeout: Option<std::time::Duration>,
) -> Vec<u8> {
    let m = new_setelem_msg(seq, set, &[(net.to_owned(), timeout)]);
    wrap_batch(&m, seq.get(), seq.get())
}

/// DELSETELEM 消息(元素不存在时内核回 ENOENT,上层容忍)。
/// 必须成对删:只删起点会把区间留在内核里。
pub fn build_del_setelem(seq: &mut Seq, set: &str, net: &IpNet) -> Vec<u8> {
    let m = del_setelem_msg(seq, set, std::slice::from_ref(net));
    wrap_batch(&m, seq.get(), seq.get())
}

/// 清空整个 set 的消息(FLUSH)。
pub fn build_flush_setelem(seq: &mut Seq, set: &str) -> Vec<u8> {
    let m = del_setelem_msg(seq, set, &[]);
    wrap_batch(&m, seq.get(), seq.get())
}

/// 全量替换 set 内容:flush + 一次 NEWSETELEM 写入全部元素。
/// 两者在同一批次里,内核实为原子事务 —— 切换期间不会出现「规则在跑但集合已空」的窗口,
/// 也顺带清掉旧版本误编码的开区间残留。
pub fn build_replace_setelems(
    seq: &mut Seq,
    set: &str,
    rows: &[(IpNet, Option<std::time::Duration>)],
) -> Vec<u8> {
    let mut ops = del_setelem_msg(seq, set, &[]);
    if !rows.is_empty() {
        ops.extend_from_slice(&new_setelem_msg(seq, set, rows));
    }
    wrap_batch(&ops, seq.get(), seq.get())
}

/// GETSETELEM dump 请求(NLM_F_DUMP)。
pub fn build_get_setelem(seq: &mut Seq, set: &str) -> Vec<u8> {
    let mut m = Vec::with_capacity(128);
    let s = seq.get();
    let pos = nf_msg_start(&mut m, NFT_MSG_GETSETELEM, NFPROTO_INET, NLM_F_DUMP, s);
    attr_str(&mut m, NFTA_SET_ELEM_LIST_TABLE, crate::TABLE);
    attr_str(&mut m, NFTA_SET_ELEM_LIST_SET, set);
    nf_msg_end(&mut m, pos);
    m
}

/// GETRULE dump 请求(带 table+chain 过滤,内核只回该链规则)。
pub fn build_get_rule(seq: &mut Seq, chain: &str) -> Vec<u8> {
    let mut m = Vec::with_capacity(128);
    let s = seq.get();
    let pos = nf_msg_start(&mut m, NFT_MSG_GETRULE, NFPROTO_INET, NLM_F_DUMP, s);
    attr_str(&mut m, NFTA_RULE_TABLE, crate::TABLE);
    attr_str(&mut m, NFTA_RULE_CHAIN, chain);
    nf_msg_end(&mut m, pos);
    m
}

/// DELTABLE(uninstall 用)。
pub fn build_del_table(seq: &mut Seq) -> Vec<u8> {
    let mut ops = Vec::with_capacity(128);
    op_msg(&mut ops, NFT_MSG_DELTABLE, F_ACK_ONLY, seq, NFPROTO_INET, |a| {
        attr_str(a, NFTA_TABLE_NAME, crate::TABLE);
    });
    wrap_batch(&ops, seq.get(), seq.get())
}

// ---------- dump 响应解析 ----------

/// 解析 GETRULE dump 载荷(各消息属性区):返回规则 handle 列表(u64 BE)。
pub fn parse_rule_handles(payloads: &[Vec<u8>]) -> Vec<u64> {
    let mut out = Vec::new();
    for m in payloads {
        if let Some(h) = find_attr(m, NFTA_RULE_HANDLE) {
            out.push(attr_be64_of(h));
        }
    }
    out
}

/// 解析 GETSETELEM dump 载荷:返回 (ip 或 cidr 字符串, 剩余 timeout 秒)。
///
/// `interval = true`(本模块创建的 6 个命名集合)时按内核的区间节点对还原:
/// 起点节点无标志、终点节点带 INTERVAL_END 且键为「闭区间末 +1」,两者在 dump 里
/// 不一定相邻(实测 6.12 按 key 降序输出),所以先按 key 升序再线性配对。
/// 落单的起点在内核里就是开区间(覆盖到地址上界),照实还原,回删才能命中它。
/// `interval = false`(meter 等非区间集合)时每个节点都是单点。
/// 另外兼容同元素 KEY_END 形态(uapi 有此属性,部分内核 dump 用它)。
pub fn parse_set_elements(
    payloads: &[Vec<u8>],
    klen: usize,
    interval: bool,
) -> Vec<(String, Option<u64>)> {
    // (key, 是否区间终点, 剩余秒, 同元素 KEY_END)
    let mut nodes: Vec<(Vec<u8>, bool, Option<u64>, Option<Vec<u8>>)> = Vec::new();
    for m in payloads {
        let Some(elems) = find_attr(m, NFTA_SET_ELEM_LIST_ELEMENTS) else {
            continue;
        };
        for (_, el) in AttrIter::new(elems) {
            let mut key: Option<Vec<u8>> = None;
            let mut key_end: Option<Vec<u8>> = None;
            let mut expiration_ms: Option<u64> = None;
            let mut timeout_ms: Option<u64> = None;
            let mut flags = 0u32;
            for (t, p) in AttrIter::new(el) {
                match t {
                    NFTA_SET_ELEM_KEY => {
                        key = find_attr(p, NFTA_DATA_VALUE).map(|v| v.to_vec());
                    }
                    NFTA_SET_ELEM_KEY_END => {
                        key_end = find_attr(p, NFTA_DATA_VALUE).map(|v| v.to_vec());
                    }
                    NFTA_SET_ELEM_TIMEOUT => timeout_ms = Some(attr_be64_of(p)),
                    NFTA_SET_ELEM_EXPIRATION => expiration_ms = Some(attr_be64_of(p)),
                    NFTA_SET_ELEM_FLAGS => flags = attr_be32_of(p),
                    _ => {}
                }
            }
            let Some(k) = key.filter(|k| k.len() == klen) else {
                continue;
            };
            let rem = match (expiration_ms, timeout_ms) {
                (Some(e), _) => Some(e / 1000),
                (None, Some(t)) => Some(t / 1000),
                (None, None) => None,
            };
            nodes.push((k, flags & NFT_SET_ELEM_INTERVAL_END != 0, rem, key_end));
        }
    }
    if !interval {
        return nodes
            .into_iter()
            .map(|(k, _, rem, _)| (addr_to_string(&k), rem))
            .collect();
    }
    nodes.sort_by(|a, b| a.0.cmp(&b.0));
    let ones = vec![0xffu8; klen];
    let mut out = Vec::new();
    let mut open: Option<(Vec<u8>, Option<u64>)> = None;
    for (k, is_end, rem, key_end) in nodes {
        if let Some(ke) = key_end.filter(|ke| ke.len() == klen) {
            out.push((bounds_to_string(&k, &ke), rem));
            continue;
        }
        if is_end {
            // 键为全零的终点 = 上一个区间的 +1 回绕,它闭合的起点已扫过,忽略即可:
            // 那个起点会作为「落单」在下面按开区间还原,语义相同。
            if let Some((s, tmo)) = open.take() {
                let end = dec_key(&k).unwrap_or_else(|| ones.clone());
                out.push((bounds_to_string(&s, &end), tmo));
            }
        } else {
            if let Some((s, tmo)) = open.take() {
                out.push((bounds_to_string(&s, &ones), tmo));
            }
            open = Some((k, rem));
        }
    }
    if let Some((s, tmo)) = open {
        out.push((bounds_to_string(&s, &ones), tmo));
    }
    out
}

/// 大端 key 减 1(不足则 None)。区间终点是「闭区间末 +1」,回退一位还原闭区间。
fn dec_key(b: &[u8]) -> Option<Vec<u8>> {
    let mut v = b.to_vec();
    for i in (0..v.len()).rev() {
        match v[i].checked_sub(1) {
            Some(n) => {
                v[i] = n;
                return Some(v);
            }
            None => v[i] = 0xff,
        }
    }
    None
}

fn addr_to_string(b: &[u8]) -> String {
    match b.len() {
        4 => Ipv4Addr::new(b[0], b[1], b[2], b[3]).to_string(),
        16 => Ipv6Addr::from(<[u8; 16]>::try_from(b).unwrap()).to_string(),
        _ => String::from_utf8_lossy(b).into_owned(),
    }
}

fn bounds_to_string(start: &[u8], end: &[u8]) -> String {
    if start == end {
        return addr_to_string(start); // 单地址区间不写成 x/32
    }
    if let Some(cidr) = range_to_cidr(start, end) {
        return cidr;
    }
    format!("{}-{}", addr_to_string(start), addr_to_string(end))
}

/// 起止地址恰好构成一个 CIDR 时返回前缀表示,否则 None。
fn range_to_cidr(start: &[u8], end: &[u8]) -> Option<String> {
    let bits = match (start.len(), end.len()) {
        (4, 4) => 32u32,
        (16, 16) => 128,
        _ => return None,
    };
    let s = be_to_u128(start);
    let e = be_to_u128(end);
    // span = e-s+1 在 128 位全地址空间下装不下,直接特判 /0。
    let prefix = if bits == 128 && s == 0 && e == u128::MAX {
        0
    } else {
        let span = e.checked_sub(s)?.checked_add(1)?;
        if span.count_ones() != 1 || s & (span - 1) != 0 {
            return None;
        }
        bits - span.trailing_zeros()
    };
    let ip = match bits {
        32 => Ipv4Addr::from(s as u32).to_string(),
        _ => Ipv6Addr::from(s.to_be_bytes()).to_string(),
    };
    Some(format!("{ip}/{prefix}"))
}

fn be_to_u128(b: &[u8]) -> u128 {
    let mut raw = [0u8; 16];
    raw[16 - b.len()..].copy_from_slice(b);
    u128::from_be_bytes(raw)
}

/// 本模块创建的命名集合是否带 NFT_SET_INTERVAL:区间集合的元素在内核里
/// 是起点 + 终点两个节点,meter 等非区间集合是单点。
pub fn set_is_interval(name: &str) -> bool {
    set_specs()
        .iter()
        .any(|(n, _, f)| *n == name && f & NFT_SET_INTERVAL != 0)
}

/// 解析 "N/(second|minute|hour)" → (N, 单位毫秒)。
pub fn parse_rate(rate: &str) -> Result<(u64, u64), crate::NftError> {
    let (n, unit) = rate
        .split_once('/')
        .ok_or_else(|| crate::NftError::InvalidAddress(rate.to_string()))?;
    let n: u64 = n
        .trim()
        .parse()
        .map_err(|_| crate::NftError::InvalidAddress(rate.to_string()))?;
    let unit_ms = match unit.trim() {
        "second" | "seconds" | "s" => 1_000u64,
        "minute" | "minutes" | "m" => 60_000,
        "hour" | "hours" | "h" => 3_600_000,
        _ => return Err(crate::NftError::InvalidAddress(rate.to_string())),
    };
    Ok((n, unit_ms))
}

/// "1.2.3.4" 或 "10.0.0.0/24" → IpNet(纯 IP 视为 /32 或 /128)。
pub fn parse_ip_or_cidr(s: &str) -> Result<IpNet, crate::NftError> {
    if let Ok(ip) = s.trim().parse::<IpAddr>() {
        return Ok(IpNet::from(ip));
    }
    s.trim()
        .parse::<IpNet>()
        .map_err(|_| crate::NftError::InvalidAddress(s.to_string()))
}

/// set 名 → klen。
pub fn klen_of_set(set: &str) -> usize {
    if set.ends_with("_v6") {
        16
    } else {
        4
    }
}

// ---------- 字节级单测(无 root)----------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::{find_attr, parse_msgs, AttrIter};
    use crate::{SET_ALLOW_V4, SET_ALLOW_V6, SET_BLOCK_V4, SET_BLOCK_V6};
    use std::time::Duration;

    /// 展开 buf 里全部消息:(nlmsg_type, flags, nfgenmsg 家族字节, 属性区)
    fn walk(buf: &[u8]) -> Vec<(u16, u16, u8, &[u8])> {
        parse_msgs(buf)
            .0
            .iter()
            .map(|m| {
                let family = buf.get(m.body.start + 16).copied().unwrap_or(0);
                (m.mtype, m.flags, family, m.attrs(buf))
            })
            .collect()
    }

    fn be32_at(attrs: &[u8], t: u16) -> u32 {
        attr_be32_of(find_attr(attrs, t).expect("attr present"))
    }

    #[test]
    fn ensure_creates_batch_bytes() {
        let mut seq = Seq::new();
        let batch = build_ensure_creates(&mut seq);
        let msgs = walk(&batch);
        let op = |t: u16| (NFNL_SUBSYS_NFTABLES << 8) | t;
        // 消息类型顺序:BATCH_BEGIN, NEWTABLE, 6×NEWSET, NEWCHAIN, BATCH_END
        let mut expected = vec![NFNL_MSG_BATCH_BEGIN, op(NFT_MSG_NEWTABLE)];
        expected.extend(std::iter::repeat(op(NFT_MSG_NEWSET)).take(6));
        expected.extend([op(NFT_MSG_NEWCHAIN), NFNL_MSG_BATCH_END]);
        let types: Vec<u16> = msgs.iter().map(|m| m.0).collect();
        assert_eq!(types, expected);
        // 批头 res_id = htons(NFNL_SUBSYS_NFTABLES)(大端 10 = 0x000A)
        assert_eq!(&batch[18..20], &[0x00, 0x0a]);
        // 全部 nft 操作消息族 = NFPROTO_INET(table inet)
        for m in &msgs[1..msgs.len() - 1] {
            assert_eq!(m.2, NFPROTO_INET);
        }
        // NEWTABLE:名字 "rooster\0"
        assert_eq!(find_attr(msgs[1].3, NFTA_TABLE_NAME).unwrap(), b"rooster\0");
        // block_v4 NEWSET(第 3 个 set,索引 2):flags/键类型/键长
        let set_attrs = |i: usize| msgs[2 + i].3;
        assert_eq!(find_attr(set_attrs(2), NFTA_SET_TABLE).unwrap(), b"rooster\0");
        assert_eq!(find_attr(set_attrs(2), NFTA_SET_NAME).unwrap(), b"block_v4\0");
        assert_eq!(be32_at(set_attrs(2), NFTA_SET_FLAGS), NFT_SET_INTERVAL | NFT_SET_TIMEOUT);
        assert_eq!(be32_at(set_attrs(2), NFTA_SET_KEY_TYPE), NFT_DATATYPE_IPADDR);
        assert_eq!(be32_at(set_attrs(2), NFTA_SET_KEY_LEN), 4);
        // allow_v6(索引 1):ip6addr/16
        assert_eq!(be32_at(set_attrs(1), NFTA_SET_KEY_TYPE), NFT_DATATYPE_IP6ADDR);
        assert_eq!(be32_at(set_attrs(1), NFTA_SET_KEY_LEN), 16);
        // NFTA_SET_ID 不得缺失:内核缺它直接 EINVAL(Debian 13 / 6.12 实测)
        assert_eq!(be32_at(set_attrs(0), NFTA_SET_ID), 1);
        assert_eq!(be32_at(set_attrs(2), NFTA_SET_ID), 3);
        assert_eq!(be32_at(set_attrs(5), NFTA_SET_ID), 6);
        // NEWCHAIN:hooknum=prerouting, priority=-300, policy=accept, type=filter
        // NEWCHAIN 在 BATCH_END 前一条
        let ch = msgs[msgs.len() - 2].3;
        let hook = find_attr(ch, NFTA_CHAIN_HOOK).expect("hook nest");
        assert_eq!(
            be32_at(hook, NFTA_HOOK_HOOKNUM),
            NF_INET_PRE_ROUTING as u32
        );
        assert_eq!(be32_at(hook, NFTA_HOOK_PRIORITY), (-300i32) as u32);
        assert_eq!(be32_at(ch, NFTA_CHAIN_POLICY), NF_ACCEPT as u32);
        assert_eq!(find_attr(ch, NFTA_CHAIN_TYPE).unwrap(), b"filter\0");
    }

    /// meter 集合也得带 NFTA_SET_ID,且 id 不能与常驻集合的 1..6 相撞。
    #[test]
    fn ssh_creates_batch_assigns_non_colliding_set_ids() {
        let mut seq = Seq::new();
        let batch = build_ssh_creates(&mut seq);
        let newset = ((NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWSET) as u16;
        let ids: Vec<u32> = walk(&batch)
            .iter()
            .filter(|m| m.0 == newset)
            .map(|m| be32_at(m.3, NFTA_SET_ID))
            .collect();
        assert_eq!(ids, vec![7, 8], "meter 集合 id 必须存在且避开 1..6");
    }

    /// 从一条 NEWRULE 的 EXPRESSIONS 里按序取表达式:(名字, [(atype, payload)])
    fn rule_exprs(attrs: &[u8]) -> Vec<(String, Vec<(u16, Vec<u8>)>)> {
        let exprs = find_attr(attrs, NFTA_RULE_EXPRESSIONS).expect("exprs");
        AttrIter::new(exprs)
            .filter(|(t, _)| *t == NFTA_LIST_ELEM)
            .map(|(_, el)| {
                let mut name = String::new();
                let mut data = Vec::new();
                for (t, p) in AttrIter::new(el) {
                    if t == NFTA_EXPR_NAME {
                        name = attr_str_of(p);
                    } else if t == NFTA_EXPR_DATA {
                        data = AttrIter::new(p).map(|(a, b)| (a, b.to_vec())).collect();
                    }
                }
                (name, data)
            })
            .collect()
    }

    #[test]
    fn ensure_rules_batch_bytes() {
        let mut seq = Seq::new();
        let batch = build_ensure_rules(&mut seq, &[]); // 新链:无旧规则
        let msgs = walk(&batch);
        assert_eq!(msgs.len(), 1 + 6 + 1); // BEGIN + 6×NEWRULE + END
        let names = ["allow_v4", "allow_v6", "block_v4", "block_v6", "geo_block_v4", "geo_block_v6"];
        for (i, m) in msgs[1..7].iter().enumerate() {
            let attrs = m.3;
            assert_eq!(m.2, NFPROTO_INET);
            assert_eq!(find_attr(attrs, NFTA_RULE_TABLE).unwrap(), b"rooster\0");
            assert_eq!(find_attr(attrs, NFTA_RULE_CHAIN).unwrap(), b"pre\0");
            let exprs = rule_exprs(attrs);
            let v6 = i % 2 == 1;
            // meta nfproto:数据属性序 [KEY, DREG];值断言用 attr_be32_of
            assert_eq!(exprs[0].0, "meta");
            assert_eq!(exprs[0].1[0].0, NFTA_META_KEY);
            assert_eq!(attr_be32_of(&exprs[0].1[0].1), NFT_META_NFPROTO);
            assert_eq!(exprs[1].0, "cmp");
            assert_eq!(
                find_attr(&exprs[1].1[2].1, NFTA_DATA_VALUE).unwrap(),
                &[if v6 { NFPROTO_IPV6 } else { NFPROTO_IPV4 }]
            );
            // payload saddr:off 12/len 4(v4)或 off 8/len 16(v6)
            assert_eq!(exprs[2].0, "payload");
            assert_eq!(exprs[2].1[0].0, NFTA_PAYLOAD_DREG);
            assert_eq!(attr_be32_of(&exprs[2].1[0].1), NFT_REG_1);
            assert_eq!(exprs[2].1[1].0, NFTA_PAYLOAD_BASE);
            assert_eq!(attr_be32_of(&exprs[2].1[1].1), NFT_PAYLOAD_NETWORK_HEADER);
            assert_eq!(exprs[2].1[2].0, NFTA_PAYLOAD_OFFSET);
            assert_eq!(attr_be32_of(&exprs[2].1[2].1), if v6 { 8 } else { 12 });
            assert_eq!(exprs[2].1[3].0, NFTA_PAYLOAD_LEN);
            assert_eq!(attr_be32_of(&exprs[2].1[3].1), if v6 { 16 } else { 4 });
            // lookup:set 名匹配
            assert_eq!(exprs[3].0, "lookup");
            assert_eq!(exprs[3].1[1].0, NFTA_LOOKUP_SET);
            assert_eq!(attr_str_of(&exprs[3].1[1].1), names[i]);
            // verdict:allow=ACCEPT(1),block/geo=DROP(0);
            // IMMEDIATE_DATA 里嵌 DATA_VERDICT,再嵌 VERDICT_CODE
            assert_eq!(exprs[4].0, "immediate");
            let want = if i < 2 { NF_ACCEPT } else { NF_DROP };
            let vd = find_attr(&exprs[4].1[1].1, NFTA_DATA_VERDICT).unwrap();
            assert_eq!(be32_at(vd, NFTA_VERDICT_CODE), want as u32);
        }
    }

    #[test]
    fn meter_rule_limit_unit_is_millis() {
        let mut seq = Seq::new();
        let batch = build_ssh_rules(&mut seq, &[], 22, 10, 60_000, 5);
        // 找 dynset 表达式的嵌套 limit:unit 必须是毫秒(60_000),不能折成秒
        for m in walk(&batch)[1..3].iter() {
            let exprs = rule_exprs(m.3);
            let dynset = exprs.iter().find(|(n, _)| n == "dynset").expect("dynset");
            let dget = |t: u16| dynset.1.iter().find(|(a, _)| *a == t).unwrap().1.clone();
            assert_eq!(attr_be64_of(&dget(NFTA_DYNSET_TIMEOUT)), 60_000);
            // EXPR 的 payload 就是 LIST_ELEM 区;其内才是 [EXPR_DATA, EXPR_NAME]
            let nest = dget(NFTA_DYNSET_EXPR);
            let limit = AttrIter::new(&nest).next().unwrap().1;
            let mut lname = String::new();
            let mut ldata = Vec::new();
            for (t, p) in AttrIter::new(limit) {
                if t == NFTA_EXPR_NAME { lname = attr_str_of(p); } else if t == NFTA_EXPR_DATA { ldata = p.to_vec(); }
            }
            assert_eq!(lname, "limit");
            assert_eq!(attr_be64_of(find_attr(&ldata, NFTA_LIMIT_RATE).unwrap()), 10);
            assert_eq!(attr_be64_of(find_attr(&ldata, NFTA_LIMIT_UNIT).unwrap()), 60_000);
            assert_eq!(be32_at(&ldata, NFTA_LIMIT_FLAGS), NFT_LIMIT_F_INV); // rate over
        }
    }

    /// ELEMENTS nest → [(key, flags, timeout_ms)]。KEY 是嵌套数据(DATA_VALUE 在 KEY nest 里),
    /// flat find_attr 会误配同号的 SET_ELEM_KEY(=1),故逐层 AttrIter 走。
    fn elem_nodes(msg_attrs: &[u8]) -> Vec<(Vec<u8>, u32, Option<u64>)> {
        let els = find_attr(msg_attrs, NFTA_SET_ELEM_LIST_ELEMENTS).unwrap();
        AttrIter::new(els)
            .map(|(_, el)| {
                let mut key = Vec::new();
                let mut flags = 0;
                let mut tmo = None;
                for (t, p) in AttrIter::new(el) {
                    match t {
                        NFTA_SET_ELEM_KEY => {
                            key = find_attr(p, NFTA_DATA_VALUE).map(|v| v.to_vec()).unwrap_or_default()
                        }
                        NFTA_SET_ELEM_FLAGS => flags = attr_be32_of(p),
                        NFTA_SET_ELEM_TIMEOUT => tmo = Some(attr_be64_of(p)),
                        _ => {}
                    }
                }
                (key, flags, tmo)
            })
            .collect()
    }

    #[test]
    fn setelem_key_encoding() {
        let mut seq = Seq::new();
        let b = build_new_setelem(&mut seq, SET_BLOCK_V4, &"203.0.113.5/32".parse::<IpNet>().unwrap(), Some(Duration::from_secs(30)));
        let nodes = elem_nodes(&walk(&b)[1].3);
        // 内核的 interval 集合把每个网段存成 [起点, 终点哨兵);只发起点会被当成开区间
        // (封一个 IP 等于封到 255.255.255.255)。
        assert_eq!(nodes.len(), 2);
        assert_eq!(nodes[0].0, [203, 0, 113, 5]);
        assert_eq!(nodes[0].1, 0);
        assert_eq!(nodes[0].2, Some(30_000)); // timeout 只挂起点,两端都挂内核回 EINVAL
        assert_eq!(nodes[1].0, [203, 0, 113, 6]); // 闭区间末 +1
        assert_eq!(nodes[1].1, NFT_SET_ELEM_INTERVAL_END);
        assert_eq!(nodes[1].2, None);

        let mut seq = Seq::new();
        let b = build_new_setelem(&mut seq, SET_ALLOW_V4, &"10.0.0.0/8".parse::<IpNet>().unwrap(), None);
        let nodes = elem_nodes(&walk(&b)[1].3);
        assert_eq!((nodes[0].0.as_slice(), nodes[1].0.as_slice()), ([10, 0, 0, 0].as_slice(), [11, 0, 0, 0].as_slice()));

        // 覆盖到地址上界时 +1 回绕成全零,与 nft CLI 的 dump 一致
        let mut seq = Seq::new();
        let b = build_new_setelem(&mut seq, SET_ALLOW_V4, &"0.0.0.0/0".parse::<IpNet>().unwrap(), None);
        let nodes = elem_nodes(&walk(&b)[1].3);
        assert_eq!((nodes[0].0.as_slice(), nodes[1].0.as_slice(), nodes[1].1), ([0, 0, 0, 0].as_slice(), [0, 0, 0, 0].as_slice(), NFT_SET_ELEM_INTERVAL_END));

        // v6 /128 → 起点 + 末字节 +1
        let mut seq = Seq::new();
        let b = build_new_setelem(&mut seq, SET_BLOCK_V6, &"2001:db8::1/128".parse::<IpNet>().unwrap(), None);
        let nodes = elem_nodes(&walk(&b)[1].3);
        let mut expect_end = [0u8; 16];
        expect_end[..15].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        expect_end[15] = 2;
        assert_eq!(nodes[0].0.len(), 16);
        assert_eq!(nodes[1].0, expect_end.to_vec());

        // 删除同样成对
        let mut seq = Seq::new();
        let b = build_del_setelem(&mut seq, SET_BLOCK_V4, &"203.0.113.5/32".parse::<IpNet>().unwrap());
        let nodes = elem_nodes(&walk(&b)[1].3);
        assert_eq!(nodes.len(), 2);
        assert_eq!(nodes[1].1, NFT_SET_ELEM_INTERVAL_END);

        // flush:DELSETELEM 不带 ELEMENTS 属性
        let mut seq = Seq::new();
        let b = build_flush_setelem(&mut seq, SET_ALLOW_V4);
        let m = &walk(&b)[1];
        assert!(find_attr(m.3, NFTA_SET_ELEM_LIST_ELEMENTS).is_none());

        // replace = flush + 一条带全部元素的 NEWSETELEM(同批次,原子切换)
        let mut seq = Seq::new();
        let rows: Vec<(IpNet, Option<Duration>)> = vec![
            ("203.0.113.5/32".parse().unwrap(), Some(Duration::from_secs(60))),
            ("198.51.100.0/24".parse().unwrap(), None),
        ];
        let b = build_replace_setelems(&mut seq, SET_BLOCK_V4, &rows);
        let ops: Vec<_> = walk(&b)
            .into_iter()
            .filter(|m| m.0 >> 8 == NFNL_SUBSYS_NFTABLES)
            .collect();
        let dels: Vec<_> = ops.iter().filter(|m| m.0 & 0xff == NFT_MSG_DELSETELEM).collect();
        let adds: Vec<_> = ops.iter().filter(|m| m.0 & 0xff == NFT_MSG_NEWSETELEM).collect();
        assert_eq!(dels.len(), 1);
        assert!(find_attr(dels[0].3, NFTA_SET_ELEM_LIST_ELEMENTS).is_none());
        assert_eq!(adds.len(), 1);
        assert_eq!(elem_nodes(&adds[0].3).len(), 4); // 2 个网段×2 节点

        // 空替换 = 只 flush(不再发一个带空 ELEMENTS 的新增批)
        let mut seq = Seq::new();
        let b = build_replace_setelems(&mut seq, SET_BLOCK_V4, &[]);
        let ops: Vec<_> = walk(&b)
            .into_iter()
            .filter(|m| m.0 >> 8 == NFNL_SUBSYS_NFTABLES)
            .collect();
        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0].0 & 0xff, NFT_MSG_DELSETELEM);
    }

    fn dump_payload(elems: &[(IpNet, Option<u64>, Option<u64>)], set: &str) -> Vec<Vec<u8>> {
        // 模拟内核 GETSETELEM dump 的一条 NEWSETELEM 响应(属性区):起点节点带
        // timeout/expiration,终点节点只带 INTERVAL_END 标志。
        let mut m = Vec::new();
        attr_str(&mut m, NFTA_SET_ELEM_LIST_TABLE, crate::TABLE);
        attr_str(&mut m, NFTA_SET_ELEM_LIST_SET, set);
        let els = nest_start(&mut m, NFTA_SET_ELEM_LIST_ELEMENTS);
        for (net, tmo, exp) in elems {
            let (start, end) = interval_keys(net);
            let el = nest_start(&mut m, NFTA_LIST_ELEM);
            let k = nest_start(&mut m, NFTA_SET_ELEM_KEY);
            attr(&mut m, NFTA_DATA_VALUE, &start);
            nest_end(&mut m, k);
            if let Some(t) = tmo { attr_be64(&mut m, NFTA_SET_ELEM_TIMEOUT, *t); }
            if let Some(e) = exp { attr_be64(&mut m, NFTA_SET_ELEM_EXPIRATION, *e); }
            nest_end(&mut m, el);
            let el = nest_start(&mut m, NFTA_LIST_ELEM);
            let k = nest_start(&mut m, NFTA_SET_ELEM_KEY);
            attr(&mut m, NFTA_DATA_VALUE, &end);
            nest_end(&mut m, k);
            attr_be32(&mut m, NFTA_SET_ELEM_FLAGS, NFT_SET_ELEM_INTERVAL_END);
            nest_end(&mut m, el);
        }
        nest_end(&mut m, els);
        vec![m]
    }

    #[test]
    fn parse_set_elements_shapes() {
        // 单 ip + timeout/expiration 毫秒 → 秒
        let p = dump_payload(
            &[("203.0.113.5/32".parse().unwrap(), Some(120_000), Some(61_000))],
            SET_BLOCK_V4,
        );
        assert_eq!(
            parse_set_elements(&p, 4, true),
            vec![("203.0.113.5".to_string(), Some(61))]
        ); // expiration 优先,单地址不写成 /32
           // cidr → cidr 字符串
        let p = dump_payload(&[("10.0.0.0/24".parse().unwrap(), None, None)], SET_ALLOW_V4);
        assert_eq!(parse_set_elements(&p, 4, true), vec![("10.0.0.0/24".to_string(), None)]);
        // 非对齐区间 → "a-b"
        let mut m = Vec::new();
        attr_str(&mut m, NFTA_SET_ELEM_LIST_TABLE, crate::TABLE);
        attr_str(&mut m, NFTA_SET_ELEM_LIST_SET, SET_ALLOW_V4);
        let els = nest_start(&mut m, NFTA_SET_ELEM_LIST_ELEMENTS);
        put_elem(&mut m, &[172, 16, 0, 5], false, None);
        put_elem(&mut m, &[172, 16, 9, 10], true, None);
        nest_end(&mut m, els);
        assert_eq!(
            parse_set_elements(&[m], 4, true),
            vec![("172.16.0.5-172.16.9.9".to_string(), None)]
        );
        // 全地址空间:span = 2^32 溢出路径
        let p = dump_payload(&[("0.0.0.0/0".parse().unwrap(), None, None)], SET_ALLOW_V4);
        assert_eq!(parse_set_elements(&p, 4, true), vec![("0.0.0.0/0".to_string(), None)]);
        // 落单起点 = 内核里的开区间(旧版本误编码的残留),按实际语义还原才能回删
        let mut m = Vec::new();
        attr_str(&mut m, NFTA_SET_ELEM_LIST_TABLE, crate::TABLE);
        attr_str(&mut m, NFTA_SET_ELEM_LIST_SET, SET_BLOCK_V4);
        let els = nest_start(&mut m, NFTA_SET_ELEM_LIST_ELEMENTS);
        put_elem(&mut m, &[203, 0, 113, 9], false, Some(30_000));
        nest_end(&mut m, els);
        assert_eq!(
            parse_set_elements(&[m], 4, true),
            vec![("203.0.113.9-255.255.255.255".to_string(), Some(30))]
        );
        // 同元素 KEY_END 形态(uapi 有此属性,部分内核 dump 用它)
        let mut m = Vec::new();
        attr_str(&mut m, NFTA_SET_ELEM_LIST_TABLE, crate::TABLE);
        attr_str(&mut m, NFTA_SET_ELEM_LIST_SET, SET_ALLOW_V4);
        let els = nest_start(&mut m, NFTA_SET_ELEM_LIST_ELEMENTS);
        let el = nest_start(&mut m, NFTA_LIST_ELEM);
        let k = nest_start(&mut m, NFTA_SET_ELEM_KEY);
        attr(&mut m, NFTA_DATA_VALUE, &[192, 168, 0, 0]);
        nest_end(&mut m, k);
        let k = nest_start(&mut m, NFTA_SET_ELEM_KEY_END);
        attr(&mut m, NFTA_DATA_VALUE, &[192, 168, 0, 255]);
        nest_end(&mut m, k);
        nest_end(&mut m, el);
        nest_end(&mut m, els);
        assert_eq!(
            parse_set_elements(&[m], 4, true),
            vec![("192.168.0.0/24".to_string(), None)]
        );
        // 非区间集合(meter):每个节点都是单点,不当开区间还原
        let mut m = Vec::new();
        attr_str(&mut m, NFTA_SET_ELEM_LIST_TABLE, crate::TABLE);
        attr_str(&mut m, NFTA_SET_ELEM_LIST_SET, "sshm4");
        let els = nest_start(&mut m, NFTA_SET_ELEM_LIST_ELEMENTS);
        put_elem(&mut m, &[10, 0, 0, 1], false, None);
        put_elem(&mut m, &[10, 0, 0, 2], false, None);
        nest_end(&mut m, els);
        assert_eq!(
            parse_set_elements(&[m], 4, false),
            vec![
                ("10.0.0.1".to_string(), None),
                ("10.0.0.2".to_string(), None)
            ]
        );
        // v6 单地址 + v6 /32
        let p = dump_payload(&[("2001:db8::1/128".parse().unwrap(), Some(5_000), None)], SET_BLOCK_V6);
        assert_eq!(
            parse_set_elements(&p, 16, true),
            vec![("2001:db8::1".to_string(), Some(5))]
        );
        let p = dump_payload(&[("2001:db8::/32".parse().unwrap(), None, None)], SET_ALLOW_V6);
        assert_eq!(
            parse_set_elements(&p, 16, true),
            vec![("2001:db8::/32".to_string(), None)]
        );
    }

    /// 回归夹具:Debian 13 / 6.12.111 上 `nft` 写入 198.51.100.61(单地址)、
    /// 10.1.0.0/24、172.16.0.5-172.16.9.9 后 GETSETELEM 的真实响应字节
    /// (dump 按 key 降序返回,终点哨兵的键是闭区间末 +1,末尾还有一个回绕成 0 的终点)。
    #[test]
    fn parse_set_elements_matches_real_kernel_dump() {
        let hex = "180001000c00010008000100c633643e0800030000000001100001000c00010008000100c633643d180001000c00010008000100ac10090a0800030000000001100001000c00010008000100ac100005180001000c000100080001000a0101000800030000000001100001000c000100080001000a010000180001000c00010008000100000000000800030000000001";
        let elems: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect();
        let mut m = Vec::new();
        attr_str(&mut m, NFTA_SET_ELEM_LIST_TABLE, crate::TABLE);
        attr_str(&mut m, NFTA_SET_ELEM_LIST_SET, SET_BLOCK_V4);
        let pos = nest_start(&mut m, NFTA_SET_ELEM_LIST_ELEMENTS);
        m.extend_from_slice(&elems);
        nest_end(&mut m, pos);
        assert_eq!(
            parse_set_elements(&[m], 4, true),
            vec![
                ("10.1.0.0/24".to_string(), None),
                ("172.16.0.5-172.16.9.9".to_string(), None),
                ("198.51.100.61".to_string(), None),
            ]
        );
    }

    #[test]
    fn parse_rate_and_helpers() {
        assert_eq!(parse_rate("10/minute").unwrap(), (10, 60_000));
        assert_eq!(parse_rate("3/second").unwrap(), (3, 1_000));
        assert_eq!(parse_rate("1/hour").unwrap(), (1, 3_600_000));
        assert!(parse_rate("banana").is_err());
        let n = parse_ip_or_cidr("192.0.2.1").unwrap();
        assert_eq!(n.prefix_len(), 32);
        assert_eq!(parse_ip_or_cidr("192.0.2.0/24").unwrap().prefix_len(), 24);
        assert!(parse_ip_or_cidr("nope").is_err());
        assert_eq!(klen_of_set("block_v6"), 16);
        assert_eq!(klen_of_set("allow_v4"), 4);
    }
}

