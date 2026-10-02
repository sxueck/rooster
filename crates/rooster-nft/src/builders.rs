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
// 加固链(全部 input hook,按优先级排序):
// ct state invalid / TCP flag 异常 → 全局新建连接限速 → 端口扫描 → 蜜罐。
pub const FLAGS_CHAIN: &str = "hard_flags";
pub const L4_CHAIN: &str = "hard_l4";
pub const SCAN_CHAIN: &str = "hard_scan";
pub const HP_CHAIN: &str = "hard_hp";
// 命中暂存集(非区间、TIMEOUT|EVAL,由包路径 dynset 写入,agent 轮询提升为封禁)。
pub const SET_HP_V4: &str = "honeypot_v4";
pub const SET_HP_V6: &str = "honeypot_v6";
/// 扫描检测的元组集:键 = 源 IP . 目的端口(每字段 4 字节对齐,
/// v4 klen 8 / v6 klen 20)。与旧 scan_v4/v6(纯 IP 键 + 令牌桶)不同:
/// 这里记录「同一窗口内碰过哪些不同端口」,阈值判定在用户态做
/// (内核令牌桶数不出 distinct 端口数,重复打同一端口不得累计)。
pub const SET_SCANPORTS_V4: &str = "scanports_v4";
pub const SET_SCANPORTS_V6: &str = "scanports_v6";
/// L4 限速的命中队列:仅当内联 limit 判定「超速」(规则继续求值)时才写入。
pub const SET_L4HIT_V4: &str = "l4hit_v4";
pub const SET_L4HIT_V6: &str = "l4hit_v6";
/// L4 限速的 meter 状态集:每个新建连接的源都会进这里(dynset 内联
/// limit 在元素上求值)。它与命中队列必须分离:把两者放进同一个集,
/// promoter 会把「只要发过包的源」全数封禁,且消费命中时的删除会把
/// 令牌桶一并重置(6.18 内核 nft_dynset_eval 实测语义)。
pub const SET_L4METER_V4: &str = "l4meter_v4";
pub const SET_L4METER_V6: &str = "l4meter_v6";
// 端口集(inet_service 单键,agent 全量替换)
pub const SET_HONEYPORTS: &str = "honeyports";
pub const SET_OPENPORTS: &str = "openports";
/// ssh meter set(sshm4/6)的 set 级 timeout 更新批。
pub fn build_ssh_set_timeout_update(seq: &mut Seq, set: &str, timeout_ms: u64) -> Vec<u8> {
    let mut ops = Vec::with_capacity(128);
    let klen = if set.ends_with('6') { 16u32 } else { 4u32 };
    let key_type = if klen == 4 { NFT_DATATYPE_IPADDR } else { NFT_DATATYPE_IP6ADDR };
    op_msg(&mut ops, NFT_MSG_NEWSET, F_CREATE, seq, NFPROTO_INET, |a| {
        attr_str(a, NFTA_SET_TABLE, crate::TABLE);
        attr_str(a, NFTA_SET_NAME, set);
        attr_be32(a, NFTA_SET_FLAGS, NFT_SET_TIMEOUT | NFT_SET_EVAL);
        attr_be32(a, NFTA_SET_KEY_TYPE, key_type);
        attr_be32(a, NFTA_SET_KEY_LEN, klen);
        attr_be32(a, NFTA_SET_ID, if set == "sshm4" { 7 } else { 8 });
        attr_be64(a, NFTA_SET_TIMEOUT, timeout_ms);
    });
    wrap_batch(&ops, seq.get(), seq.get())
}

/// 超时更新批专用:NEWSET(F_CREATE,无 EXCL)消息,携带 set 级 timeout。
pub fn build_set_timeout_update(seq: &mut Seq, set: &str, timeout_ms: u64) -> Vec<u8> {
    let mut ops = Vec::with_capacity(128);
    let Some((_, key_type, klen, _)) = hardening_meter_sets()
        .into_iter()
        .find(|(n, _, _, _)| *n == set)
    else {
        return Vec::new();
    };
    op_msg(&mut ops, NFT_MSG_NEWSET, F_CREATE, seq, NFPROTO_INET, |a| {
        hardening_newset(a, set, key_type, klen, hardening_set_id(set), Some(timeout_ms));
    });
    wrap_batch(&ops, seq.get(), seq.get())
}

/// set 名 → 表内 id(与 build_hardening_sets_create 一致,供超时更新批复用)。
pub fn hardening_set_id(name: &str) -> u32 {
    hardening_meter_sets()
        .into_iter()
        .find(|(n, _, _, _)| *n == name)
        .map(|(_, _, _, id)| id)
        .unwrap_or(0)
}

/// 命中/元组集名 → dump 解析用 klen(纯 IP 集 4/16;扫描元组集 8/20,
/// 每拼接字段向上取整到 4 字节,nf_tables_api.c nft_set_desc_concat)。
pub fn hardening_hit_set_klen(set: &str) -> Option<usize> {
    hardening_meter_sets()
        .into_iter()
        .find(|(n, _, _, _)| *n == set)
        .map(|(_, _, klen, _)| klen as usize)
}

/// 加固 set 规格:(名称, key_type, klen, set_id)。
pub type HardeningSetSpec = (&'static str, u32, u32, u32);

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

impl Default for Seq {
    fn default() -> Self {
        Self::new()
    }
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
        // ct state 掩码按主机序:内核把状态位图以 native u32 写入寄存器,
        // 大端掩码在 x86 上永不相与(F-014:ssh meter 从未生效的另一半根因)。
        let e = nest_start(exprs, NFTA_LIST_ELEM);
        let d = nest_start(exprs, NFTA_EXPR_DATA);
        attr_be32(exprs, NFTA_BITWISE_SREG, NFT_REG_1);
        attr_be32(exprs, NFTA_BITWISE_DREG, NFT_REG_1);
        attr_be32(exprs, NFTA_BITWISE_LEN, 4);
        let m = nest_start(exprs, NFTA_BITWISE_MASK);
        attr(exprs, NFTA_DATA_VALUE, &CT_STATE_NEW_BIT.to_ne_bytes());
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

/// NFTA_LIMIT_UNIT 的单位是**秒**(内核 nft_limit_init:`unit * NSEC_PER_SEC`,
/// 6.18 源码核对;nft CLI `rate 6/minute` 也发 60)。毫秒会让限速慢 1000 倍。
pub fn limit_unit_secs(unit_ms: u64) -> u64 {
    (unit_ms / 1000).max(1)
}

/// meter 规则(v4/v6 各一):
/// `tcp dport <port> ct state new meter <name> { ip/ip6 saddr limit rate over <rate> burst <burst> } drop`
/// = meta nfproto 依赖 + payload saddr + tcp dport 依赖链 + ct state new +
///   dynset{limit 嵌套} + immediate drop。
/// dynset 属性顺序镜像 libnftnl expr/dynset.c:SREG_KEY, OP, TIMEOUT, SET_NAME, [EXPR]。
/// NFTA_LIMIT_UNIT 内核按秒解释(nft_limit.c:`nsecs = unit * NSEC_PER_SEC`,
/// 毫秒会让窗口拉长 1000 倍);NFTA_DYNSET_TIMEOUT 仍是毫秒
/// (nf_msecs_to_jiffies64),两者不要共用同一个数。
fn build_meter_rule(seq: &mut Seq, v6: bool, port: u16, rate: u64, unit_ms: u64, burst: u32, set: &str) -> Vec<u8> {
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
        // 内核禁止 dynset TIMEOUT+EXPR 并存(F-014 的根因);元素过期由
        // sshm4/6 的 set 级 timeout 承担(set_ssh_rate_limit 随配置更新)。
        attr_str(&mut exprs, NFTA_DYNSET_SET_NAME, set);
        // 内核要求:带 EXPR 的 dynset 必须置 NFT_DYNSET_F_EXPR,否则 EOPNOTSUPP
        //(F-014:ssh meter 规则在 VM 上从未生效的根因)。
        attr_be32(&mut exprs, NFTA_DYNSET_FLAGS, NFT_DYNSET_F_EXPR);
        // NFTA_DYNSET_EXPR 直连 [NAME, DATA](内核 nft_dynset_expr_setup 语义)
        let x = nest_start(&mut exprs, NFTA_DYNSET_EXPR);
        attr_str(&mut exprs, NFTA_EXPR_NAME, "limit");
        let ld = nest_start(&mut exprs, NFTA_EXPR_DATA);
        attr_be64(&mut exprs, NFTA_LIMIT_RATE, rate);
        attr_be64(&mut exprs, NFTA_LIMIT_UNIT, limit_unit_secs(unit_ms));
        attr_be32(&mut exprs, NFTA_LIMIT_BURST, burst);
        attr_be32(&mut exprs, NFTA_LIMIT_TYPE, NFT_LIMIT_PKTS);
        attr_be32(&mut exprs, NFTA_LIMIT_FLAGS, NFT_LIMIT_F_INV); // rate *over*
        nest_end(&mut exprs, ld);
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

/// DELRULE(table+chain,无 handle)= `nft flush chain`:删除该链全部规则。
/// 链不存在时内核回 ENOENT,调用方容忍。不会创建任何对象。
pub fn plain_delrule_msg(seq: &mut Seq, chain: &str) -> Vec<u8> {
    let mut m = Vec::with_capacity(64);
    let s = seq.get();
    let pos = nf_msg_start(&mut m, NFT_MSG_DELRULE, NFPROTO_INET, F_ACK_ONLY, s);
    attr_str(&mut m, NFTA_RULE_TABLE, crate::TABLE);
    attr_str(&mut m, NFTA_RULE_CHAIN, chain);
    nf_msg_end(&mut m, pos);
    m
}

/// `set_ssh_rate_limit` 第一阶段:2 个 meter set(EVAL|TIMEOUT)+ ssh_limit 基链。
pub fn build_ssh_creates(seq: &mut Seq) -> Vec<u8> {
    let mut ops = Vec::with_capacity(512);
    for (i, (name, klen)) in [("sshm4", 4u32), ("sshm6", 16u32)].into_iter().enumerate() {
        op_msg(&mut ops, NFT_MSG_NEWSET, F_CREATE_EXCL, seq, NFPROTO_INET, |a| {
            attr_str(a, NFTA_SET_TABLE, crate::TABLE);
            attr_str(a, NFTA_SET_NAME, name);
            attr_be32(a, NFTA_SET_FLAGS, NFT_SET_TIMEOUT | NFT_SET_EVAL);
            attr_be64(a, NFTA_SET_TIMEOUT, 600_000);
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

// ---------- 加固(hardening)----------

/// 包路径可写的命中暂存集:非区间、TIMEOUT|EVAL(dynset 写入需 EVAL,同 sshm4 验证过的形状)。
/// 扫描元组集的键是拼接型:每字段向上取整到 4 字节(v4 8 / v6 20)。
pub fn hardening_meter_sets() -> [HardeningSetSpec; 10] {
    [
        (SET_HONEYPORTS, NFT_DATATYPE_INET_SERVICE, 2, 9),
        (SET_OPENPORTS, NFT_DATATYPE_INET_SERVICE, 2, 10),
        (SET_HP_V4, NFT_DATATYPE_IPADDR, 4, 11),
        (SET_HP_V6, NFT_DATATYPE_IP6ADDR, 16, 12),
        (SET_SCANPORTS_V4, concat_datatype(NFT_DATATYPE_IPADDR, NFT_DATATYPE_INET_SERVICE), 8, 13),
        (SET_SCANPORTS_V6, concat_datatype(NFT_DATATYPE_IP6ADDR, NFT_DATATYPE_INET_SERVICE), 20, 14),
        (SET_L4HIT_V4, NFT_DATATYPE_IPADDR, 4, 15),
        (SET_L4HIT_V6, NFT_DATATYPE_IP6ADDR, 16, 16),
        (SET_L4METER_V4, NFT_DATATYPE_IPADDR, 4, 17),
        (SET_L4METER_V6, NFT_DATATYPE_IP6ADDR, 16, 18),
    ]
}

/// 四链的 (名称, 优先级)。flags 最先(最便宜、覆盖面最大),蜜罐最后。
pub fn hardening_chains() -> [(&'static str, i32); 4] {
    [
        (FLAGS_CHAIN, -300),
        (L4_CHAIN, -270),
        (SCAN_CHAIN, -240),
        (HP_CHAIN, -210),
    ]
}

/// 蜜罐/扫描封禁的运行时输入(由 agent 从 config 解析;rate 字段已拆成
/// (n, unit_ms) 避免 rooster-nft 依赖 rooster-config)。
#[derive(Debug, Clone, Default)]
pub struct HardeningSpec {
    /// 下发时一并携带:空集时相应链只保留 bypass(空 inet_service 集合的
    /// 取反 lookup 永真会放行全部新连接,正向 lookup 永假是死规则)。
    pub honey_ports: Vec<u16>,
    pub open_ports: Vec<u16>,
    pub honeypot_on: bool,
    pub honeypot_window_ms: u64,
    /// set 级元素超时(内核禁止 dynset 同时携带 TIMEOUT 与 limit EXPR;
    /// meter 语义的元素过期一律走 set 默认超时)。
    pub scan_set_timeout_ms: u64,
    pub l4_set_timeout_ms: u64,
    pub scan_on: bool,

    pub l4_on: bool,
    pub l4_rate: u64,
    pub l4_unit_ms: u64,
    pub l4_burst: u32,
    pub flags_on: bool,
}

fn hardening_newset(a: &mut Vec<u8>, name: &str, key_type: u32, klen: u32, id: u32, set_timeout_ms: Option<u64>) {
    attr_str(a, NFTA_SET_TABLE, crate::TABLE);
    attr_str(a, NFTA_SET_NAME, name);
    let flags = if key_type == NFT_DATATYPE_INET_SERVICE {
        0
    } else {
        NFT_SET_TIMEOUT | NFT_SET_EVAL
    };
    attr_be32(a, NFTA_SET_FLAGS, flags);
    attr_be32(a, NFTA_SET_KEY_TYPE, key_type);
    attr_be32(a, NFTA_SET_KEY_LEN, klen);
    attr_be32(a, NFTA_SET_ID, id);
    if let Some(t) = set_timeout_ms {
        attr_be64(a, NFTA_SET_TIMEOUT, t);
    }
}

/// 命中集当前应生效的 set 级超时(随配置变化,用 NEWSET 幂等更新)。
/// l4hit/l4meter 钳到 ≥60s:命中是瞬时事件,保留期只需盖过 promoter
/// 轮询间隔(2s),60s 无害且与 meter 令牌桶自身的存活期一致。
/// scanports **不**做 60s 垫底:元素寿命必须等于配置的 find-time,
/// 否则 distinct-port 窗口被拉长,扫描计数虚高。
pub fn hardening_set_timeouts(spec: &HardeningSpec) -> Vec<(&'static str, u64)> {
    let mut out = Vec::new();
    let l4_t = spec.l4_set_timeout_ms.max(60_000);
    for (set, t) in [
        (SET_HP_V4, spec.honeypot_window_ms),
        (SET_HP_V6, spec.honeypot_window_ms),
        (SET_SCANPORTS_V4, spec.scan_set_timeout_ms),
        (SET_SCANPORTS_V6, spec.scan_set_timeout_ms),
        (SET_L4HIT_V4, l4_t),
        (SET_L4HIT_V6, l4_t),
        (SET_L4METER_V4, l4_t),
        (SET_L4METER_V6, l4_t),
    ] {
        if t > 0 {
            out.push((set, t));
        }
    }
    out
}

/// clear_hardening 要清空的全部状态集(命中 + 元组 + meter 令牌桶)。
pub fn hardening_state_sets() -> [&'static str; 8] {
    [
        SET_HP_V4,
        SET_HP_V6,
        SET_SCANPORTS_V4,
        SET_SCANPORTS_V6,
        SET_L4HIT_V4,
        SET_L4HIT_V6,
        SET_L4METER_V4,
        SET_L4METER_V6,
    ]
}

/// flush_hardening_hits 清空的集:命中 + 元组,**不含 meter** ——
/// 令牌桶状态有自己的生命周期,消费命中时重置它等于给超速源白送新桶。
pub fn hardening_hit_sets() -> [&'static str; 6] {
    [
        SET_HP_V4,
        SET_HP_V6,
        SET_SCANPORTS_V4,
        SET_SCANPORTS_V6,
        SET_L4HIT_V4,
        SET_L4HIT_V6,
    ]
}

/// 端口集仅在缺失时创建(存量 set 被规则引用时不可删;键类型与元素
/// 宽度都由 klen=2 决定,显示名不影响内核匹配,旧 type 11 存量集可继续
/// 使用,agent 生命周期内清表时自然重建为 13)。
pub fn build_hardening_ports_reset(seq: &mut Seq) -> Vec<u8> {
    let mut ops = Vec::with_capacity(256);
    for (name, key_type, klen, id) in hardening_meter_sets() {
        if key_type != NFT_DATATYPE_INET_SERVICE {
            continue;
        }
        op_msg(&mut ops, NFT_MSG_NEWSET, F_CREATE_EXCL, seq, NFPROTO_INET, |a| {
            hardening_newset(a, name, key_type, klen, id, None);
        });
    }
    wrap_batch(&ops, seq.get(), seq.get())
}

/// 动态命中集的幂等创建。**不带 EXCL**:批是原子事务,EXCL 撞存量集会把
/// 整批(含同批链)回滚,agent 侧 tolerated-EEXIST 又掩盖了失败(VM 实测:
/// 链全部"消失")。无 EXCL 的 NEWSET 对存量集是内核级幂等。
/// timeout 与超时更新批同源(spec),否则存量集参数不符同样回滚。
pub fn build_hardening_sets_create(seq: &mut Seq, spec: &HardeningSpec) -> Vec<u8> {
    let mut ops = Vec::with_capacity(1024);
    let timeouts = hardening_set_timeouts(spec);
    for (name, key_type, klen, id) in hardening_meter_sets() {
        op_msg(&mut ops, NFT_MSG_NEWSET, F_CREATE, seq, NFPROTO_INET, |a| {
            let t = if key_type == NFT_DATATYPE_INET_SERVICE {
                None
            } else {
                timeouts
                    .iter()
                    .find(|(s, _)| *s == name)
                    .map(|(_, ms)| *ms)
                    .or(Some(600_000u64))
            };
            hardening_newset(a, name, key_type, klen, id, t);
        });
    }
    wrap_batch(&ops, seq.get(), seq.get())
}

/// 仅创建缺失的链(存量链用 EXCL 重开会毒化整批,由调用方 dump 出名单)。
pub fn build_hardening_chains_create(seq: &mut Seq, missing: &[&'static str]) -> Vec<u8> {
    let mut ops = Vec::with_capacity(512);
    for (name, prio) in hardening_chains() {
        if !missing.contains(&name) {
            continue;
        }
        op_msg(&mut ops, NFT_MSG_NEWCHAIN, F_CREATE_EXCL, seq, NFPROTO_INET, |a| {
            attr_str(a, NFTA_CHAIN_TABLE, crate::TABLE);
            attr_str(a, NFTA_CHAIN_NAME, name);
            let h = nest_start(a, NFTA_CHAIN_HOOK);
            attr_be32(a, NFTA_HOOK_HOOKNUM, NF_INET_LOCAL_IN);
            attr_be32(a, NFTA_HOOK_PRIORITY, prio as u32); // attr_be32 内部已按 netlink be32(htonl)编码
            nest_end(a, h);
            attr_be32(a, NFTA_CHAIN_POLICY, NF_ACCEPT as u32);
            attr_str(a, NFTA_CHAIN_TYPE, "filter");
        });
    }
    wrap_batch(&ops, seq.get(), seq.get())
}

/// [meta iif => reg1][cmp eq 1(lo)][accept] —— lo 流量不参与任何加固判定
/// (本机服务监听蜜罐列表内端口是开发机常态)。
fn expr_lo_accept(exprs: &mut Vec<u8>) {
    {
        let e = nest_start(exprs, NFTA_LIST_ELEM);
        let d = nest_start(exprs, NFTA_EXPR_DATA);
        attr_be32(exprs, NFTA_META_KEY, NFT_META_IIF);
        attr_be32(exprs, NFTA_META_DREG, NFT_REG_1);
        nest_end(exprs, d);
        attr_str(exprs, NFTA_EXPR_NAME, "meta");
        nest_end(exprs, e);
    }
    expr_cmp_eq(exprs, &1u32.to_ne_bytes());
    expr_verdict(exprs, NF_ACCEPT);
}

/// [meta nfproto][payload th dport => reg1](不 cmp,交给 lookup)
fn expr_payload_dport(exprs: &mut Vec<u8>) {
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
}

/// [payload th off 13 len 1 => reg1](单字节 TCP flags)
fn expr_payload_tcp_flags(exprs: &mut Vec<u8>) {
    {
        let e = nest_start(exprs, NFTA_LIST_ELEM);
        let d = nest_start(exprs, NFTA_EXPR_DATA);
        attr_be32(exprs, NFTA_PAYLOAD_DREG, NFT_REG_1);
        attr_be32(exprs, NFTA_PAYLOAD_BASE, NFT_PAYLOAD_TRANSPORT_HEADER);
        attr_be32(exprs, NFTA_PAYLOAD_OFFSET, TCP_FLAGS_OFFSET);
        attr_be32(exprs, NFTA_PAYLOAD_LEN, 1);
        nest_end(exprs, d);
        attr_str(exprs, NFTA_EXPR_NAME, "payload");
        nest_end(exprs, e);
    }
}

/// [meta l4proto => reg1][cmp eq tcp]
fn expr_meta_tcp(exprs: &mut Vec<u8>) {
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
}

/// [bitwise reg1 = reg1 & mask](1/4 字节宽,mask 按大端编码)。
/// kernel nft_bitwise_init 要求 XOR 属性存在(即使为 0):缺失直接 EINVAL。
fn expr_bitwise_mask(exprs: &mut Vec<u8>, mask: &[u8]) {
    let e = nest_start(exprs, NFTA_LIST_ELEM);
    let d = nest_start(exprs, NFTA_EXPR_DATA);
    attr_be32(exprs, NFTA_BITWISE_SREG, NFT_REG_1);
    attr_be32(exprs, NFTA_BITWISE_DREG, NFT_REG_1);
    attr_be32(exprs, NFTA_BITWISE_LEN, mask.len() as u32);
    let m = nest_start(exprs, NFTA_BITWISE_MASK);
    attr(exprs, NFTA_DATA_VALUE, mask);
    nest_end(exprs, m);
    {
        let x = nest_start(exprs, NFTA_BITWISE_XOR);
        attr(exprs, NFTA_DATA_VALUE, &vec![0u8; mask.len()]);
        nest_end(exprs, x);
    }
    nest_end(exprs, d);
    attr_str(exprs, NFTA_EXPR_NAME, "bitwise");
    nest_end(exprs, e);
}

// Reply packets must not enter detectors for incoming connection attempts.
fn expr_ct_original(exprs: &mut Vec<u8>) {
    let e = nest_start(exprs, NFTA_LIST_ELEM);
    let d = nest_start(exprs, NFTA_EXPR_DATA);
    attr_be32(exprs, NFTA_CT_KEY, NFT_CT_DIRECTION);
    attr_be32(exprs, NFTA_CT_DREG, NFT_REG_1);
    nest_end(exprs, d);
    attr_str(exprs, NFTA_EXPR_NAME, "ct");
    nest_end(exprs, e);
    expr_cmp_eq(exprs, &[0]);
}

/// [ct load state => reg1][bitwise & mask][cmp neq 0] —— `ct state <bits>`
fn expr_ct_state_bits(exprs: &mut Vec<u8>, mask: u32) {
    {
        let e = nest_start(exprs, NFTA_LIST_ELEM);
        let d = nest_start(exprs, NFTA_EXPR_DATA);
        attr_be32(exprs, NFTA_CT_KEY, NFT_CT_STATE);
        attr_be32(exprs, NFTA_CT_DREG, NFT_REG_1);
        nest_end(exprs, d);
        attr_str(exprs, NFTA_EXPR_NAME, "ct");
        nest_end(exprs, e);
    }
    expr_bitwise_mask(exprs, &mask.to_ne_bytes());
    expr_cmp_neq_zero_u32(exprs);
}

/// [cmp neq reg1 0]
fn expr_cmp_neq_zero_u32(exprs: &mut Vec<u8>) {
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

/// [lookup reg1 in @set](invert = `!= @set`);sreg 位宽须与 set 键宽一致
fn expr_lookup(exprs: &mut Vec<u8>, set: &str, invert: bool) {
    // 默认窗口 = NFT_REG_1 兼容区(与 payload dreg 常量 NFT_REG_1 对齐);
    // 32 位寄存器编号是另一套(8..23),混用会让 lookup 读错单元。
    let e = nest_start(exprs, NFTA_LIST_ELEM);
    let d = nest_start(exprs, NFTA_EXPR_DATA);
    attr_be32(exprs, NFTA_LOOKUP_SREG, NFT_REG_1);
    attr_str(exprs, NFTA_LOOKUP_SET, set);
    if invert {
        attr_be32(exprs, NFTA_LOOKUP_FLAGS, NFT_LOOKUP_F_INV);
    }
    nest_end(exprs, d);
    attr_str(exprs, NFTA_EXPR_NAME, "lookup");
    nest_end(exprs, e);
}

/// dynset:把 reg1(必须是最后一个写入 reg1 的表达式)加入 `set`,
/// 元素超时 `timeout_ms`;`limit = Some((rate, unit_ms, burst))` 时仅在
/// `limit rate over` 命中(令牌桶耗尽)时才继续求值后续表达式 —— 与
/// build_meter_rule 同机制。
/// 内核 nft_dynset_init 禁止 TIMEOUT 与 EXPR(limit)并存(EOPNOTSUPP):
/// meter 语义的元素过期由 set 级 default timeout 承担,timeout_ms 仅用于
/// 无 limit 的纯 add(蜜罐)。
fn expr_dynset(exprs: &mut Vec<u8>, set: &str, timeout_ms: Option<u64>, limit: Option<(u64, u64, u32)>) {
    expr_dynset_inner(exprs, set, NFT_DYNSET_OP_ADD, timeout_ms, limit.map(|(r, u, b)| (r, u, b, None)));
}

fn expr_dynset_inner(
    exprs: &mut Vec<u8>,
    set: &str,
    op: u32,
    timeout_ms: Option<u64>,
    limit: Option<(u64, u64, u32, Option<&str>)>,
) {
    let e = nest_start(exprs, NFTA_LIST_ELEM);
    let d = nest_start(exprs, NFTA_EXPR_DATA);
    attr_be32(exprs, NFTA_DYNSET_SREG_KEY, NFT_REG_1);
    attr_be32(exprs, NFTA_DYNSET_OP, op);
    // 不发 SREG_DATA:内核据此启用 data 寄存器语义(元素带状态数据),
    // 与 EVAL+limit 的 meter 用法互斥 → EOPNOTSUPP。libnftnl 同样只在
    // 显式 update data 时才写它。
    if let Some(t) = timeout_ms {
        attr_be64(exprs, NFTA_DYNSET_TIMEOUT, t);
    }
    attr_str(exprs, NFTA_DYNSET_SET_NAME, set);
    if limit.is_some() {
        attr_be32(exprs, NFTA_DYNSET_FLAGS, NFT_DYNSET_F_EXPR);
    }
    if let Some((rate, unit_ms, burst, name)) = limit {
        // 内核 nft_dynset_expr_setup 对 EXPR 直接 nla_parse_nested(NFTA_EXPR_*):
        // 只放 [EXPR_NAME, EXPR_DATA],不得再包 LIST_ELEM(l4 链 VM 实测:
        // 直连形态被接受,包 LIST_ELEM 反而 EINVAL/ERANGE)。
        let x = nest_start(exprs, NFTA_DYNSET_EXPR);
        attr_str(exprs, NFTA_EXPR_NAME, name.unwrap_or("limit"));
        let ld = nest_start(exprs, NFTA_EXPR_DATA);
        attr_be64(exprs, NFTA_LIMIT_RATE, rate);
        attr_be64(exprs, NFTA_LIMIT_UNIT, limit_unit_secs(unit_ms));
        attr_be32(exprs, NFTA_LIMIT_BURST, burst);
        attr_be32(exprs, NFTA_LIMIT_TYPE, NFT_LIMIT_PKTS);
        attr_be32(exprs, NFTA_LIMIT_FLAGS, NFT_LIMIT_F_INV);
        nest_end(exprs, ld);
        nest_end(exprs, x);
    }
    nest_end(exprs, d);
    attr_str(exprs, NFTA_EXPR_NAME, "dynset");
    nest_end(exprs, e);
}

fn hardening_rule(seq: &mut Seq, chain: &str, exprs: &[u8]) -> Vec<u8> {
    let mut ops = Vec::with_capacity(exprs.len() + 64);
    op_msg(&mut ops, NFT_MSG_NEWRULE, F_CREATE_APPEND, seq, NFPROTO_INET, |a| {
        attr_str(a, NFTA_RULE_TABLE, crate::TABLE);
        attr_str(a, NFTA_RULE_CHAIN, chain);
        let x = nest_start(a, NFTA_RULE_EXPRESSIONS);
        a.extend_from_slice(exprs);
        nest_end(a, x);
    });
    ops
}

/// 链头部三件套:lo accept + allow_v4 accept + allow_v6 accept。
fn hardening_bypass_rules(seq: &mut Seq, chain: &str, out: &mut Vec<u8>) {
    let mut exprs = Vec::with_capacity(256);
    expr_lo_accept(&mut exprs);
    out.extend_from_slice(&hardening_rule(seq, chain, &exprs));
    for (set, v6) in [(crate::SET_ALLOW_V4, false), (crate::SET_ALLOW_V6, true)] {
        let mut exprs = Vec::with_capacity(256);
        expr_meta_nfproto(&mut exprs, if v6 { NFPROTO_IPV6 } else { NFPROTO_IPV4 });
        expr_payload_saddr(&mut exprs, v6);
        expr_lookup(&mut exprs, set, false);
        expr_verdict(&mut exprs, NF_ACCEPT);
        out.extend_from_slice(&hardening_rule(seq, chain, &exprs));
    }
}

/// 同 build_hardening_chain_rules,但拆成"旧规则删除+bypass 一起一批、
/// 每条功能规则单独一批"。set_hardening 用它:单批失败时 annotate 的
/// 步名能定位到具体规则(v4/v6/flags#n),不必再猜内核在哪条表达式上
/// 返回 EOPNOTSUPP。
pub fn build_hardening_chain_rule_batches(
    seq: &mut Seq,
    chain: &'static str,
    old_handles: &[u64],
    spec: &HardeningSpec,
) -> Vec<Vec<u8>> {
    let full = build_hardening_chain_rules(seq, chain, old_handles, spec);
    // 拆分:逐 op 重新包装。full 结构 = BEGIN + [ops...] + END;
    // 简单可靠的做法是重建:先数 op 边界再按 op 切(此处 op 数小,
    // 直接用 op 级消息长度遍历)。
    let mut out = Vec::new();
    let mut off = 20; // skip BEGIN
    let end_limit = full.len() - 20;
    while off + 16 <= end_limit {
        let ln = u32::from_le_bytes(full[off..off + 4].try_into().unwrap()) as usize;
        if ln < 16 || off + ln > end_limit {
            break;
        }
        out.push(wrap_batch(&full[off..off + ln], seq.get(), seq.get()));
        off += ln.max(4);
    }
    out
}

/// 单条链的规则集:旧 handle 全删 + bypass 头部 + 按 spec 追加功能规则
/// (`match chain` 只挑本链分支——四链全量下发由 set_hardening 逐链调用完成)。
pub fn build_hardening_chain_rules(
    seq: &mut Seq,
    chain: &'static str,
    old_handles: &[u64],
    spec: &HardeningSpec,
) -> Vec<u8> {
    let mut ops = Vec::with_capacity(4096);
    for h in old_handles {
        op_msg(&mut ops, NFT_MSG_DELRULE, F_ACK_ONLY, seq, NFPROTO_INET, |a| {
            attr_str(a, NFTA_RULE_TABLE, crate::TABLE);
            attr_str(a, NFTA_RULE_CHAIN, chain);
            attr_be64(a, NFTA_RULE_HANDLE, *h);
        });
    }
    hardening_bypass_rules(seq, chain, &mut ops);
    match chain {
        FLAGS_CHAIN => {
            if spec.flags_on {
                // ct state invalid drop
                let mut exprs = Vec::with_capacity(256);
                expr_ct_state_bits(&mut exprs, CT_STATE_INVALID_BIT);
                expr_verdict(&mut exprs, NF_DROP);
                ops.extend_from_slice(&hardening_rule(seq, chain, &exprs));
                // tcp flags & (fin|syn|rst|ack) == none → NULL 扫描
                for (mask, val) in [
                    (TCP_FLAGS_FSR_MASK, 0u8),
                    (TCP_FLAGS_FSR_MASK, TCP_FLAG_FIN | TCP_FLAG_SYN),
                    (TCP_FLAG_FIN | TCP_FLAG_PSH | TCP_FLAG_URG, TCP_XMAS),
                ] {
                    let mut exprs = Vec::with_capacity(256);
                    expr_meta_tcp(&mut exprs);
                    expr_payload_tcp_flags(&mut exprs);
                    expr_bitwise_mask(&mut exprs, &[mask]);
                    expr_cmp_eq(&mut exprs, &[val]);
                    expr_verdict(&mut exprs, NF_DROP);
                    ops.extend_from_slice(&hardening_rule(seq, chain, &exprs));
                }
            }
        }
        L4_CHAIN => {
            if spec.l4_on {
                // `ct state new meter l4meter_X { saddr limit rate over R/U burst B }
                //  add @l4hit_X { saddr timeout D } drop`(nft CLI 同款,6.18 实测):
                // 令牌桶求值发生在 dynset 内部,未超速 → NFT_BREAK 终止本规则,
                // 命中 dynset 不执行;超速 → 继续求值 → 写命中队列 + drop。
                for (meter, hit, v6) in [
                    (SET_L4METER_V4, SET_L4HIT_V4, false),
                    (SET_L4METER_V6, SET_L4HIT_V6, true),
                ] {
                    let mut exprs = Vec::with_capacity(768);
                    expr_meta_nfproto(&mut exprs, if v6 { NFPROTO_IPV6 } else { NFPROTO_IPV4 });
                    expr_ct_state_bits(&mut exprs, CT_STATE_NEW_BIT);
                    expr_ct_original(&mut exprs);
                    expr_payload_saddr(&mut exprs, v6);
                    expr_dynset(
                        &mut exprs,
                        meter,
                        None,
                        Some((spec.l4_rate, spec.l4_unit_ms, spec.l4_burst)),
                    );
                    // 命中保留 ≥ promoter 轮询间隔(瞬时事件,60s 垫底无害)。
                    expr_dynset(
                        &mut exprs,
                        hit,
                        Some(spec.l4_set_timeout_ms.max(60_000)),
                        None,
                    );
                    expr_verdict(&mut exprs, NF_DROP);
                    ops.extend_from_slice(&hardening_rule(seq, chain, &exprs));
                }
            }
        }
        SCAN_CHAIN => {
            if spec.scan_on && !spec.open_ports.is_empty() {
                // `ct state new tcp dport != @openports update @scanports_X
                //  { saddr . tcp dport timeout D }`(记录型,不在此丢包):
                // 拼接键布局 = 每字段 4 字节对齐 —— saddr → reg1,
                // dport → reg32 紧随其后(v4: NFT_REG32_01=9,v6: NFT_REG_2=2),
                // dynset sreg=reg1,klen 8/20(nft CLI 1.1.6 同款,6.18 实测)。
                // OP_UPDATE:元素已存在时刷新 expiration(滑动窗口);OP_ADD
                // 不刷新,重复探到同一端口会提前从窗口里掉出去。
                for (set, v6, dport_reg) in [
                    (SET_SCANPORTS_V4, false, 9u32),
                    (SET_SCANPORTS_V6, true, 2u32),
                ] {
                    let mut exprs = Vec::with_capacity(640);
                    expr_meta_nfproto(&mut exprs, if v6 { NFPROTO_IPV6 } else { NFPROTO_IPV4 });
                    expr_meta_tcp(&mut exprs);
                    expr_ct_state_bits(&mut exprs, CT_STATE_NEW_BIT);
                    expr_ct_original(&mut exprs);
                    // dport→reg1(内核 nft_reg_store16 高位清零,CLI 同款);
                    expr_payload_dport(&mut exprs);
                    expr_lookup(&mut exprs, SET_OPENPORTS, true);
                    // 重读 saddr 覆盖 reg1,再取 dport 到拼接的下一个槽位。
                    expr_payload_saddr(&mut exprs, v6);
                    {
                        let e = nest_start(&mut exprs, NFTA_LIST_ELEM);
                        let d = nest_start(&mut exprs, NFTA_EXPR_DATA);
                        attr_be32(&mut exprs, NFTA_PAYLOAD_DREG, dport_reg);
                        attr_be32(&mut exprs, NFTA_PAYLOAD_BASE, NFT_PAYLOAD_TRANSPORT_HEADER);
                        attr_be32(&mut exprs, NFTA_PAYLOAD_OFFSET, 2);
                        attr_be32(&mut exprs, NFTA_PAYLOAD_LEN, 2);
                        nest_end(&mut exprs, d);
                        attr_str(&mut exprs, NFTA_EXPR_NAME, "payload");
                        nest_end(&mut exprs, e);
                    }
                    expr_dynset_inner(
                        &mut exprs,
                        set,
                        NFT_DYNSET_OP_UPDATE,
                        Some(spec.scan_set_timeout_ms.max(1)),
                        None,
                    );
                    ops.extend_from_slice(&hardening_rule(seq, chain, &exprs));
                }
            }
        }
        HP_CHAIN
            if spec.honeypot_on && !spec.honey_ports.is_empty() => {
                // meta l4proto tcp + ct state new:蜜罐命中必须是「向蜜罐端口的
                // 新建 TCP 连接」。不带 ct new 时,本机主动外连的回包(源端口
                // 撞上蜜罐端口)会被当成蜜罐命中,把自己的客户封掉。
                for (set, v6) in [(SET_HP_V4, false), (SET_HP_V6, true)] {
                    let mut exprs = Vec::with_capacity(640);
                    expr_meta_nfproto(&mut exprs, if v6 { NFPROTO_IPV6 } else { NFPROTO_IPV4 });
                    expr_meta_tcp(&mut exprs);
                    expr_ct_state_bits(&mut exprs, CT_STATE_NEW_BIT);
                    expr_ct_original(&mut exprs);
                    expr_payload_dport(&mut exprs);
                    expr_lookup(&mut exprs, SET_HONEYPORTS, false);
                    expr_payload_saddr(&mut exprs, v6);
                    expr_dynset(&mut exprs, set, Some(spec.honeypot_window_ms.max(1000)), None);
                    expr_verdict(&mut exprs, NF_DROP);
                    ops.extend_from_slice(&hardening_rule(seq, chain, &exprs));
                }
            }
        _ => {}
    }
    wrap_batch(&ops, seq.get(), seq.get())
}

// ---------- 非区间 set 元素(加固专用)----------

/// 扫描元组键编码:源 IP . 目的端口,每字段 4 字节对齐 ——
/// v4 = 8 字节 [saddr BE][port BE][00 00],v6 = 20 字节同构。
/// 与内核一致的两条路径都对齐:CLI NEWSETELEM 的 concat nft_data 与
/// payload 载荷入寄存器(skb_copy_bits 原样拷贝 + 尾部清零,6.18 实测)。
pub fn scan_tuple_key(ip: &IpAddr, port: u16) -> Vec<u8> {
    let mut key = Vec::with_capacity(20);
    match ip {
        IpAddr::V4(v4) => key.extend_from_slice(&v4.octets()),
        IpAddr::V6(v6) => key.extend_from_slice(&v6.octets()),
    }
    key.extend_from_slice(&port.to_be_bytes());
    key.extend_from_slice(&[0u8, 0]);
    key
}

/// 逆向:8/20 字节元组键 → (IP, 端口);宽度或填充不符返回 None
/// (填充非零说明键格式变化,宁丢不可误判)。
pub fn parse_scan_tuple(key: &[u8]) -> Option<(IpAddr, u16)> {
    let (ip_len, ip): (usize, IpAddr) = match key.len() {
        8 => (4, IpAddr::V4(Ipv4Addr::new(key[0], key[1], key[2], key[3]))),
        20 => (
            16,
            IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&key[..16]).ok()?)),
        ),
        _ => return None,
    };
    if key[ip_len + 2..ip_len + 4].iter().any(|b| *b != 0) {
        return None;
    }
    let port = u16::from_be_bytes([key[ip_len], key[ip_len + 1]]);
    Some((ip, port))
}

/// 拼接集 dump 解析:((源 IP, 目的端口), 剩余毫秒)。毫秒精度供
/// promoter 计算元素年龄(retention - remaining)后按 find-time 过滤;
/// 非拼接键(宽度不符)跳过 —— 与 IP 集解析互不混用。
pub fn parse_set_tuples(payloads: &[Vec<u8>], klen: usize) -> Vec<((IpAddr, u16), Option<u64>)> {
    walk_set_elems(payloads, klen)
        .into_iter()
        .filter_map(|(k, _, rem, _)| parse_scan_tuple(&k).map(|t| (t, rem)))
        .collect()
}

/// 单键元素(INET_SERVICE / 单 IP):LIST_ELEM{KEY{DATA_VALUE}}。
pub(crate) fn put_plain_elem(a: &mut Vec<u8>, key: &[u8]) {
    let el = nest_start(a, NFTA_LIST_ELEM);
    let k = nest_start(a, NFTA_SET_ELEM_KEY);
    attr(a, NFTA_DATA_VALUE, key);
    nest_end(a, k);
    nest_end(a, el);
}

fn plain_setelem_msg(seq: &mut Seq, set: &str, keys: &[&[u8]]) -> Vec<u8> {
    let mut m = Vec::with_capacity(256);
    let s = seq.get();
    let pos = nf_msg_start(&mut m, NFT_MSG_NEWSETELEM, NFPROTO_INET, F_CREATE, s);
    attr_str(&mut m, NFTA_SET_ELEM_LIST_TABLE, crate::TABLE);
    attr_str(&mut m, NFTA_SET_ELEM_LIST_SET, set);
    let els = nest_start(&mut m, NFTA_SET_ELEM_LIST_ELEMENTS);
    for k in keys {
        put_plain_elem(&mut m, k);
    }
    nest_end(&mut m, els);
    nf_msg_end(&mut m, pos);
    m
}

/// 端口集全量替换:flush + 全量 u16 元素(同一原子批)。
pub fn build_replace_ports(seq: &mut Seq, set: &str, ports: &[u16]) -> Vec<u8> {
    let mut ops = del_setelem_msg(seq, set, &[]);
    if !ports.is_empty() {
        let keys: Vec<Vec<u8>> = ports.iter().map(|p| p.to_be_bytes().to_vec()).collect();
        let refs: Vec<&[u8]> = keys.iter().map(|k| k.as_slice()).collect();
        ops.extend_from_slice(&plain_setelem_msg(seq, set, &refs));
    }
    wrap_batch(&ops, seq.get(), seq.get())
}

/// 从非区间 set 删单 IP 元素(promoter 消费命中后清位)。纯 IP,非区间编码。
pub fn build_del_plain_ip(seq: &mut Seq, set: &str, ip: &str) -> Vec<u8> {
    let Ok(addr) = ip.parse::<IpAddr>() else {
        return Vec::new();
    };
    let key = match addr {
        IpAddr::V4(v4) => v4.octets().to_vec(),
        IpAddr::V6(v6) => v6.octets().to_vec(),
    };
    let s = seq.get();
    let mut m = Vec::with_capacity(128);
    let pos = nf_msg_start(&mut m, NFT_MSG_DELSETELEM, NFPROTO_INET, F_ACK_ONLY, s);
    attr_str(&mut m, NFTA_SET_ELEM_LIST_TABLE, crate::TABLE);
    attr_str(&mut m, NFTA_SET_ELEM_LIST_SET, set);
    let els = nest_start(&mut m, NFTA_SET_ELEM_LIST_ELEMENTS);
    put_plain_elem(&mut m, &key);
    nest_end(&mut m, els);
    nf_msg_end(&mut m, pos);
    wrap_batch(&m, seq.get(), seq.get())
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
pub(crate) fn del_setelem_msg(seq: &mut Seq, set: &str, ranges: &[IpNet]) -> Vec<u8> {
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

/// GETSET dump 请求(按 table 过滤):回应 NEWSET 消息,含 NFTA_SET_NAME。
/// clear/flush 用它先确认对象存在,避免对缺失 set 的操作把整批事务回滚。
pub fn build_get_sets(seq: &mut Seq) -> Vec<u8> {
    let mut m = Vec::with_capacity(64);
    let s = seq.get();
    let pos = nf_msg_start(&mut m, NFT_MSG_GETSET, NFPROTO_INET, NLM_F_DUMP, s);
    attr_str(&mut m, NFTA_SET_TABLE, crate::TABLE);
    nf_msg_end(&mut m, pos);
    m
}

/// GETCHAIN dump 请求(按 table 过滤)。
pub fn build_get_chain(seq: &mut Seq) -> Vec<u8> {
    let mut m = Vec::with_capacity(128);
    let s = seq.get();
    let pos = nf_msg_start(&mut m, NFT_MSG_GETCHAIN, NFPROTO_INET, NLM_F_DUMP, s);
    attr_str(&mut m, NFTA_CHAIN_TABLE, crate::TABLE);
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

/// GETSETELEM dump 里的原始节点:(key, 是否区间终点, 剩余毫秒, 同元素 KEY_END)。
/// expiration 优先;没有 expiration 的静态元素回退 timeout 毫秒。
fn walk_set_elems(
    payloads: &[Vec<u8>],
    klen: usize,
) -> Vec<(Vec<u8>, bool, Option<u64>, Option<Vec<u8>>)> {
    let mut nodes = Vec::new();
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
            let rem = expiration_ms.or(timeout_ms);
            nodes.push((k, flags & NFT_SET_ELEM_INTERVAL_END != 0, rem, key_end));
        }
    }
    nodes
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
        expected.extend(std::iter::repeat_n(op(NFT_MSG_NEWSET), 6));
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
            NF_INET_PRE_ROUTING
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
        let newset = NFNL_SUBSYS_NFTABLES << 8 | NFT_MSG_NEWSET;
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
            // F-014 修复:dynset 不得再携带 TIMEOUT(与嵌套 limit EXPR 互斥,
            // 内核 EOPNOTSUPP);过期由 sshm set 级 timeout 承担(见下批断言)。
            assert!(dynset.1.iter().all(|(a, _)| *a != NFTA_DYNSET_TIMEOUT));
            // EXPR 直连 [EXPR_NAME, EXPR_DATA](无 LIST_ELEM 包装)
            let arr = dget(NFTA_DYNSET_EXPR);
            let mut lname = String::new();
            let mut ldata = Vec::new();
            for (t, p) in AttrIter::new(&arr) {
                if t == NFTA_EXPR_NAME { lname = attr_str_of(p); } else if t == NFTA_EXPR_DATA { ldata = p.to_vec(); }
            }
            assert_eq!(lname, "limit");
            assert_eq!(attr_be64_of(find_attr(&ldata, NFTA_LIMIT_RATE).unwrap()), 10);
            // F-2:内核 nft_limit_init 按 unit * NSEC_PER_SEC 解读 → 必须发秒(60),
        // 发毫秒(60_000)会让限速窗口慢 1000 倍。
        assert_eq!(attr_be64_of(find_attr(&ldata, NFTA_LIMIT_UNIT).unwrap()), 60);
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
        let nodes = elem_nodes(walk(&b)[1].3);
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
        let nodes = elem_nodes(walk(&b)[1].3);
        assert_eq!((nodes[0].0.as_slice(), nodes[1].0.as_slice()), ([10, 0, 0, 0].as_slice(), [11, 0, 0, 0].as_slice()));

        // 覆盖到地址上界时 +1 回绕成全零,与 nft CLI 的 dump 一致
        let mut seq = Seq::new();
        let b = build_new_setelem(&mut seq, SET_ALLOW_V4, &"0.0.0.0/0".parse::<IpNet>().unwrap(), None);
        let nodes = elem_nodes(walk(&b)[1].3);
        assert_eq!((nodes[0].0.as_slice(), nodes[1].0.as_slice(), nodes[1].1), ([0, 0, 0, 0].as_slice(), [0, 0, 0, 0].as_slice(), NFT_SET_ELEM_INTERVAL_END));

        // v6 /128 → 起点 + 末字节 +1
        let mut seq = Seq::new();
        let b = build_new_setelem(&mut seq, SET_BLOCK_V6, &"2001:db8::1/128".parse::<IpNet>().unwrap(), None);
        let nodes = elem_nodes(walk(&b)[1].3);
        let mut expect_end = [0u8; 16];
        expect_end[..15].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        expect_end[15] = 2;
        assert_eq!(nodes[0].0.len(), 16);
        assert_eq!(nodes[1].0, expect_end.to_vec());

        // 删除同样成对
        let mut seq = Seq::new();
        let b = build_del_setelem(&mut seq, SET_BLOCK_V4, &"203.0.113.5/32".parse::<IpNet>().unwrap());
        let nodes = elem_nodes(walk(&b)[1].3);
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
        assert_eq!(elem_nodes(adds[0].3).len(), 4); // 2 个网段×2 节点

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

    // ---------- 加固(hardening)字节级单测 ----------

    /// 按目标链筛 NEWRULE 消息的属性区。
    fn newrules_for_chain<'b>(batch: &'b [u8], chain: &str) -> Vec<&'b [u8]> {
        let op_newrule = NFNL_SUBSYS_NFTABLES << 8 | NFT_MSG_NEWRULE;
        walk(batch)
            .into_iter()
            .filter(|(t, _, _, _)| *t == op_newrule)
            .filter(|(_, _, _, attrs)| {
                find_attr(attrs, NFTA_RULE_CHAIN)
                    .map(|c| c == format!("{chain}\0").as_bytes())
                    .unwrap_or(false)
            })
            .map(|(_, _, _, attrs)| attrs)
            .collect()
    }

    /// 表达式属性表:(attr 号, 值)。
    type ExprAttrs = Vec<(u16, Vec<u8>)>;
    /// rule_exprs 输出:[(表达式名, 属性表)]。
    type RuleExprs = Vec<(String, ExprAttrs)>;

    /// 在 rule_exprs 已拆好的属性表里找一项。
    fn attr_in(attrs: &[(u16, Vec<u8>)], t: u16) -> Option<&[u8]> {
        attrs.iter().find(|(a, _)| *a == t).map(|(_, p)| p.as_slice())
    }

    /// 取 dynset 表达式:(集名, 元素超时 ms, OP, 是否嵌套 limit)。
    fn dynset_of(exprs: &RuleExprs) -> (String, u64, u32, bool) {
        let (_, d) = exprs
            .iter()
            .find(|(n, _)| n == "dynset")
            .expect("dynset expr")
            .clone();
        let d: Vec<(u16, Vec<u8>)> = d;
        // 硬编码键位断言:生产码与测试共用常量时,常量本身写错自证无效。
        // enum nft_dynset_attributes: NAME=1 ID=2 OP=3 SREG_KEY=4 SREG_DATA=5 TIMEOUT=6 EXPR=7 FLAGS=9(EXPR 位=1<<1)。
        assert!(attr_in(&d, 1).is_some(), "NFTA_DYNSET_SET_NAME 必须是属性 1");
        assert!(attr_in(&d, 4).is_some(), "NFTA_DYNSET_SREG_KEY 必须是属性 4");
        // 属性 6(timeout)与 EXPR 互斥,meter 规则合法缺省。
        if attr_in(&d, 7).is_some() {
            assert_eq!(
                attr_be32_of(attr_in(&d, 9).expect("EXPR 存在时必须有 NFTA_DYNSET_FLAGS=9")),
                NFT_DYNSET_F_EXPR,
                "内核对 EXPR 的要求"
            );
        }
        let set = attr_str_of(attr_in(&d, NFTA_DYNSET_SET_NAME).expect("set name"))
            .trim_end_matches('\0')
            .to_string();
        let timeout = attr_in(&d, NFTA_DYNSET_TIMEOUT).map(attr_be64_of).unwrap_or(0);
        let op = attr_in(&d, NFTA_DYNSET_OP).map(attr_be32_of).unwrap_or(0);
        (set, timeout, op, attr_in(&d, NFTA_DYNSET_EXPR).is_some())
    }

    fn lookup_name(exprs: &RuleExprs, idx: usize) -> String {
        attr_str_of(attr_in(&exprs[idx].1, NFTA_LOOKUP_SET).expect("lookup set"))
            .trim_end_matches('\0')
            .to_string()
    }

    fn spec_all_on() -> HardeningSpec {
        HardeningSpec {
            honey_ports: vec![4444, 6379],
            open_ports: vec![22, 80, 443],
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
        }
    }

    #[test]
    fn hardening_creates_ids_avoid_existing_sets_and_hooks_are_input() {
        let mut seq = Seq::new();
        let mut batch = build_hardening_sets_create(&mut seq, &HardeningSpec::default());
        let chains = build_hardening_chains_create(
            &mut seq,
            &hardening_chains().into_iter().map(|(n, _)| n).collect::<Vec<_>>(),
        );
        // 两批拼起来做消息遍历(去掉 chains 批的 BEGIN/END 头尾)
        let cl = 20; // wrap_batch BEGIN len
        let _ = cl;
        let msgs_at = batch.len();
        batch.extend_from_slice(&chains[20..chains.len() - 20]);
        let op_newset = NFNL_SUBSYS_NFTABLES << 8 | NFT_MSG_NEWSET;
        let op_newchain = NFNL_SUBSYS_NFTABLES << 8 | NFT_MSG_NEWCHAIN;
        let _ = msgs_at;
        let ids: Vec<u32> = walk(&batch)
            .iter()
            .filter(|m| m.0 == op_newset)
            .map(|m| be32_at(m.3, NFTA_SET_ID))
            .collect();
        assert_eq!(ids, (9u32..19).collect::<Vec<_>>(), "常驻 1..6、sshm 7..8 之后,10 个加固集 9..18");
        for m in walk(&batch).iter().filter(|m| m.0 == op_newset) {
            let name = attr_str_of(find_attr(m.3, NFTA_SET_NAME).unwrap())
                .trim_end_matches('\0')
                .to_string();
            let flags = be32_at(m.3, NFTA_SET_FLAGS);
            if name == SET_HONEYPORTS || name == SET_OPENPORTS {
                assert_eq!(flags, 0, "{name}: 静态端口集");
                assert_eq!(be32_at(m.3, NFTA_SET_KEY_TYPE), NFT_DATATYPE_INET_SERVICE);
                assert_eq!(be32_at(m.3, NFTA_SET_KEY_LEN), 2);
            } else {
                assert_eq!(flags, NFT_SET_TIMEOUT | NFT_SET_EVAL, "{name} 必须可包路径写入");
            }
        }
        let mut prios: Vec<i32> = Vec::new();
        for m in walk(&batch).iter().filter(|m| m.0 == op_newchain) {
            let hook = find_attr(m.3, NFTA_CHAIN_HOOK).expect("hook");
            assert_eq!(be32_at(hook, NFTA_HOOK_HOOKNUM), NF_INET_LOCAL_IN);
            prios.push(be32_at(hook, NFTA_HOOK_PRIORITY) as i32);
        }
        assert_eq!(prios, vec![-300, -270, -240, -210], "flags < l4 < scan < honeypot");
    }

    #[test]
    fn honeypot_rule_adds_unconditional_dynset_and_drops() {
        let spec = spec_all_on();
        let mut seq = Seq::new();
        let batch = build_hardening_chain_rules(&mut seq, HP_CHAIN, &[], &spec);
        let rules = newrules_for_chain(&batch, HP_CHAIN);
        assert_eq!(rules.len(), 5, "3 bypass + v4/v6");
        let exprs = rule_exprs(rules[3]);
        let names: Vec<&str> = exprs.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(
            names,
            vec![
                "meta", "cmp",          // nfproto
                "meta", "cmp",          // l4proto tcp(F-4:非 TCP 不得当蜜罐命中)
                "ct", "bitwise", "cmp",
                "ct", "cmp",
                "payload", "lookup", "payload", "dynset", "immediate",
            ],
            "nfproto→tcp→ct new→dport lookup→saddr→dynset→drop"
        );
        assert_eq!(lookup_name(&exprs, 10), SET_HONEYPORTS);
        assert!(
            attr_in(&exprs[10].1, NFTA_LOOKUP_FLAGS).is_none(),
            "蜜罐 lookup 不取反(builder 仅在 invert 时写该属性)"
        );
        let (set, timeout, _op, has_limit) = dynset_of(&exprs);
        assert_eq!(set, SET_HP_V4);
        assert_eq!(timeout, 300_000);
        assert!(!has_limit, "蜜罐是无条件 add(非 meter)");
    }

    #[test]
    fn scan_rule_records_concat_tuple_with_update_op() {
        let spec = spec_all_on();
        let mut seq = Seq::new();
        let batch = build_hardening_chain_rules(&mut seq, SCAN_CHAIN, &[], &spec);
        let rules = newrules_for_chain(&batch, SCAN_CHAIN);
        assert_eq!(rules.len(), 5);
        let exprs = rule_exprs(rules[3]);
        // [meta nfproto][cmp][meta l4proto][cmp][ct][bitwise][cmp][payload dport]
        // [lookup inv][payload saddr][payload dport→reg32 槽][dynset](无 drop:
        // 阈值判定在用户态按 distinct 端口数做,内核不再令牌桶计数)
        let lk = exprs.iter().position(|(n, _)| n == "lookup").expect("lookup expr");
        assert_eq!(lookup_name(&exprs, lk), SET_OPENPORTS);
        assert!(
            attr_in(&exprs[lk].1, NFTA_LOOKUP_FLAGS).is_some(),
            "对 openports 取反查 = 未监听端口(builder 仅 invert 时写 INV 属性)"
        );
        assert!(
            exprs.iter().all(|(n, _)| n != "immediate"),
            "记录型规则不携带 verdict"
        );
        let (set, timeout, op, has_limit) = dynset_of(&exprs);
        assert_eq!(set, SET_SCANPORTS_V4);
        assert_eq!(timeout, 60_000, "元素超时 = 保留期(滑动窗口语义由 UPDATE 刷新)");
        assert_eq!(op, NFT_DYNSET_OP_UPDATE, "UPDATE:重复探同一端口刷新 expiration");
        assert!(!has_limit, "拼接集不带内联 limit(令牌桶数不出 distinct 端口)");
        // 拼接装载:saddr→reg1(4B),dport→紧随的 4 字节槽(reg32_01=9);
        // dynset sreg=reg1、klen=8(见 hardening_meter_sets)。
        let loads: Vec<_> = exprs
            .iter()
            .filter(|(n, _)| n == "payload")
            .map(|(_, d)| (
                attr_be32_of(attr_in(d, NFTA_PAYLOAD_DREG).unwrap()),
                attr_be32_of(attr_in(d, NFTA_PAYLOAD_LEN).unwrap()),
                attr_be32_of(attr_in(d, NFTA_PAYLOAD_BASE).unwrap()),
            ))
            .collect();
        assert!(
            loads.contains(&(9, 2, NFT_PAYLOAD_TRANSPORT_HEADER)),
            "dport 必须装载到 saddr 之后的 4 字节槽(v4: reg32_01=9): {loads:?}"
        );
        // v6 规则:saddr 16B→reg1,dport→reg2(reg1 后的第一个 16B 槽)
        let exprs6 = rule_exprs(rules[4]);
        let loads6: Vec<_> = exprs6
            .iter()
            .filter(|(n, _)| n == "payload")
            .map(|(_, d)| (
                attr_be32_of(attr_in(d, NFTA_PAYLOAD_DREG).unwrap()),
                attr_be32_of(attr_in(d, NFTA_PAYLOAD_LEN).unwrap()),
            ))
            .collect();
        assert!(
            loads6.contains(&(1, 16)) && loads6.contains(&(2, 2)),
            "v6 拼接:saddr(16B)→reg1,dport(2B)→紧随的 reg2 槽: {loads6:?}"
        );
        assert_eq!(dynset_of(&exprs6).0, SET_SCANPORTS_V6);
    }

    #[test]
    fn l4_rule_matches_ct_new_with_meter_ttl_floor() {
        let spec = HardeningSpec { l4_on: true, l4_unit_ms: 1_000, ..Default::default() };
        let mut seq = Seq::new();
        let batch = build_hardening_chain_rules(&mut seq, L4_CHAIN, &[], &spec);
        let rules = newrules_for_chain(&batch, L4_CHAIN);
        assert_eq!(rules.len(), 5);
        let exprs = rule_exprs(rules[3]);
        let names: Vec<&str> = exprs.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(
            names,
            vec![
                "meta", "cmp", "ct", "bitwise", "cmp", "ct", "cmp", "payload",
                "dynset", "dynset", "immediate",
            ],
            "nfproto→ct new→saddr→meter dynset→hit dynset→drop"
        );
        // F-1 双 dynset:meter(内联 limit,无 timeout)+ 命中队列(仅超速时
        // 才被求值到,带元素超时,与 meter 分离的生命周期)。
        let ds: Vec<_> = exprs.iter().filter(|(n, _)| n == "dynset").collect();
        let (m_set, m_tmo, m_op, m_limit) = dynset_of(&vec![ds[0].clone()]);
        assert_eq!(m_set, SET_L4METER_V4);
        assert_eq!(m_tmo, 0, "meter dynset 禁带 TIMEOUT(与 limit EXPR 互斥)");
        assert_eq!(m_op, NFT_DYNSET_OP_ADD, "CLI meter 同款(nftables 1.1.6 netlink_gen_meter_stmt)");
        assert!(m_limit);
        let (h_set, h_tmo, h_op, h_limit) = dynset_of(&vec![ds[1].clone()]);
        assert_eq!(h_set, SET_L4HIT_V4);
        assert_eq!(h_tmo, 60_000, "命中保留 ≥ promoter 轮询间隔");
        assert_eq!(h_op, NFT_DYNSET_OP_ADD);
        assert!(!h_limit, "命中 dynset 无内联 limit:未超速时 meter 已 NFT_BREAK");
        // set 级超时更新批携带 max(unit,60s)
        let b2 = build_set_timeout_update(&mut seq, SET_L4HIT_V4, 60_000);
        let op_newset = NFNL_SUBSYS_NFTABLES << 8 | NFT_MSG_NEWSET;
        let m = walk(&b2).into_iter().find(|m| m.0 == op_newset).expect("newset");
        assert_eq!(attr_be64_of(find_attr(m.3, NFTA_SET_TIMEOUT).unwrap()), 60_000);
        assert_eq!(be32_at(m.3, NFTA_SET_FLAGS), NFT_SET_TIMEOUT | NFT_SET_EVAL);
    }

    #[test]
    fn flags_chain_counts_and_disable_leaves_bypass_only() {
        let spec = spec_all_on();
        let mut seq = Seq::new();
        let batch = build_hardening_chain_rules(&mut seq, FLAGS_CHAIN, &[], &spec);
        let rules = newrules_for_chain(&batch, FLAGS_CHAIN);
        assert_eq!(rules.len(), 3 + 4, "invalid + NULL + SYN/FIN + XMAS");
        let exprs = rule_exprs(rules[3]);
        assert_eq!(exprs[0].0, "ct");
        let mask_nest = attr_in(&exprs[1].1, NFTA_BITWISE_MASK).unwrap();
        let mask = find_attr(mask_nest, NFTA_DATA_VALUE).unwrap();
        assert_eq!(mask, CT_STATE_INVALID_BIT.to_ne_bytes().as_slice());
        // 全关:链只余 3 条 bypass;旧 handle 照常删除(不删链)
        let mut seq2 = Seq::new();
        let b2 =
            build_hardening_chain_rules(&mut seq2, HP_CHAIN, &[7, 9], &HardeningSpec::default());
        assert_eq!(newrules_for_chain(&b2, HP_CHAIN).len(), 3);
        let op_delrule = NFNL_SUBSYS_NFTABLES << 8 | NFT_MSG_DELRULE;
        assert_eq!(walk(&b2).iter().filter(|m| m.0 == op_delrule).count(), 2);
    }

    #[test]
    fn port_set_replace_flush_plus_be16_keys() {
        let mut seq = Seq::new();
        let batch = build_replace_ports(&mut seq, SET_HONEYPORTS, &[23, 445]);
        let op_del = NFNL_SUBSYS_NFTABLES << 8 | NFT_MSG_DELSETELEM;
        let op_new = NFNL_SUBSYS_NFTABLES << 8 | NFT_MSG_NEWSETELEM;
        let msgs = walk(&batch);
        assert_eq!(msgs.iter().filter(|m| m.0 == op_del).count(), 1, "flush 一条");
        let add = msgs.iter().find(|m| m.0 == op_new).expect("add");
        let els = find_attr(add.3, NFTA_SET_ELEM_LIST_ELEMENTS).unwrap();
        let keys: Vec<Vec<u8>> = AttrIter::new(els)
            .map(|(_, el)| {
                let k = find_attr(el, NFTA_SET_ELEM_KEY).unwrap();
                find_attr(k, NFTA_DATA_VALUE).unwrap().to_vec()
            })
            .collect();
        assert_eq!(keys, vec![23u16.to_be_bytes().to_vec(), 445u16.to_be_bytes().to_vec()]);
    }

    #[test]
    fn bypass_lo_rule_keys_meta_iif_not_len() {
        // NFT_META_IIF 历史上误用过 0(=LEN),VM 6.12 实测 nft 回读成
        // `meta length` 且永不命中:键位断言把这个坑钉死。
        let mut seq = Seq::new();
        let batch = build_hardening_chain_rules(&mut seq, HP_CHAIN, &[], &HardeningSpec::default());
        let rules = newrules_for_chain(&batch, HP_CHAIN);
        let exprs = rule_exprs(rules[0]); // 第一条 bypass = lo accept
        assert_eq!(exprs[0].0, "meta");
        assert_eq!(
            attr_be32_of(attr_in(&exprs[0].1, NFTA_META_KEY).unwrap()),
            NFT_META_IIF
        );
        assert_eq!(NFT_META_IIF, 4, "enum nft_meta_keys: IIF=4, 0 是 LEN");
        let cmp = &exprs[1].1;
        let data = attr_in(cmp, NFTA_CMP_DATA).and_then(|d| find_attr(d, NFTA_DATA_VALUE).map(|v| v.to_vec()));
        assert_eq!(data, Some(1u32.to_ne_bytes().to_vec()), "lo ifindex=1;寄存器存主机序整数");
    }

    #[test]
    fn plain_ip_delete_is_single_node() {
        let mut seq = Seq::new();
        let del = build_del_plain_ip(&mut seq, SET_HP_V4, "203.0.113.7");
        let op_del = NFNL_SUBSYS_NFTABLES << 8 | NFT_MSG_DELSETELEM;
        let msgs = walk(&del);
        let dm = msgs.iter().find(|m| m.0 == op_del).expect("del msg");
        let els = find_attr(dm.3, NFTA_SET_ELEM_LIST_ELEMENTS).unwrap();
        let one: Vec<_> = AttrIter::new(els).collect();
        assert_eq!(one.len(), 1, "非区间:单节点，无 interval-end");
        let k = find_attr(one[0].1, NFTA_SET_ELEM_KEY).unwrap();
        assert_eq!(
            find_attr(k, NFTA_DATA_VALUE).unwrap(),
            [203, 0, 113, 7],
            "4 字节裸地址编码"
        );
    }

    // ---------- 扫描元组键 / dump 解析 ----------

    /// 模拟内核 GETSETELEM 对拼接元组集的 dump 载荷(非区间单点,
    /// 携带 expiration 毫秒)。
    fn tuple_dump_payload(set: &str, elems: &[((IpAddr, u16), Option<u64>)]) -> Vec<u8> {
        let mut m = Vec::new();
        attr_str(&mut m, NFTA_SET_ELEM_LIST_TABLE, crate::TABLE);
        attr_str(&mut m, NFTA_SET_ELEM_LIST_SET, set);
        let els = nest_start(&mut m, NFTA_SET_ELEM_LIST_ELEMENTS);
        for ((ip, port), rem) in elems {
            let el = nest_start(&mut m, NFTA_LIST_ELEM);
            let k = nest_start(&mut m, NFTA_SET_ELEM_KEY);
            attr(&mut m, NFTA_DATA_VALUE, &scan_tuple_key(ip, *port));
            nest_end(&mut m, k);
            if let Some(r) = rem {
                attr_be64(&mut m, NFTA_SET_ELEM_EXPIRATION, *r);
            }
            nest_end(&mut m, el);
        }
        nest_end(&mut m, els);
        m
    }

    #[test]
    fn scan_tuple_key_roundtrip_v4_v6_and_bad_padding() {
        let v4 = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9));
        let v6 = IpAddr::V6(Ipv6Addr::from([
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
        ]));
        let k4 = scan_tuple_key(&v4, 40001);
        let k6 = scan_tuple_key(&v6, 65535);
        assert_eq!(k4.len(), 8, "v4: 4 字节 saddr + 4 字节对齐端口槽");
        assert_eq!(k6.len(), 20, "v6: 16 字节 saddr + 4 字节对齐端口槽");
        assert_eq!(&k4[4..6], &40001u16.to_be_bytes(), "端口大端在前两字节");
        assert_eq!(&k4[6..8], &[0, 0], "槽尾两字节零填充");
        assert_eq!(parse_scan_tuple(&k4), Some((v4, 40001)));
        assert_eq!(parse_scan_tuple(&k6), Some((v6, 65535)));
        // 填充非零 / 宽度不符:宁丢不可误判
        let mut bad = k4.clone();
        bad[7] = 1;
        assert_eq!(parse_scan_tuple(&bad), None);
        assert_eq!(parse_scan_tuple(&k4[..7]), None);
    }

    #[test]
    fn parse_set_tuples_decodes_concat_elements_with_ms() {
        let v4 = IpAddr::V4(Ipv4Addr::new(10, 9, 0, 2));
        let v6 = IpAddr::V6(Ipv6Addr::from([
            0x20, 0x01, 0x0d, 0xb8, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
        ]));
        let p4 = tuple_dump_payload(
            SET_SCANPORTS_V4,
            &[((v4, 40001), Some(4321)), ((v4, 40002), None)],
        );
        assert_eq!(
            parse_set_tuples(&[p4], 8),
            vec![((v4, 40001), Some(4321)), ((v4, 40002), None)]
        );
        let p6 = tuple_dump_payload(SET_SCANPORTS_V6, &[((v6, 61001), Some(999))]);
        assert_eq!(parse_set_tuples(&[p6], 20), vec![((v6, 61001), Some(999))]);
        // klen 不匹配的载荷(误用纯 IP 集)不产出元组
        assert!(parse_set_tuples(&[tuple_dump_payload(SET_SCANPORTS_V6, &[((v6, 61001), None)])], 16).is_empty());
    }

    #[test]
    fn scan_set_timeout_has_no_60s_padding_but_l4_does() {
        let spec = HardeningSpec {
            scan_set_timeout_ms: 5_000,
            l4_set_timeout_ms: 0,
            ..Default::default()
        };
        let timeouts = hardening_set_timeouts(&spec);
        let get = |n: &str| timeouts.iter().find(|(s, _)| *s == n).copied().map(|(_, t)| t);
        assert_eq!(get(SET_SCANPORTS_V4), Some(5_000), "扫描元组寿命 = 配置的 find-time,不垫 60s");
        assert_eq!(get(SET_SCANPORTS_V6), Some(5_000));
        assert_eq!(get(SET_L4HIT_V4), Some(60_000), "l4 命中是瞬时事件,仅钳 promoter 轮询下限");
        assert_eq!(get(SET_L4METER_V4), Some(60_000));
        // 链内 dynset 元素超时同源:l4hit 下限 60s,scanports 原样(毫秒级)。
        let mut seq = Seq::new();
        let b = build_hardening_chain_rules(&mut seq, SCAN_CHAIN, &[], &spec);
        let rules = newrules_for_chain(&b, SCAN_CHAIN);
        assert_eq!(rules.len(), 3, "open_ports 为空时 scan_on 也不下功能规则(取反 lookup 永真陷阱)");
        let mut spec2 = spec.clone();
        spec2.open_ports = vec![80];
        spec2.scan_on = true;
        let mut seq = Seq::new();
        let b = build_hardening_chain_rules(&mut seq, SCAN_CHAIN, &[], &spec2);
        let rules = newrules_for_chain(&b, SCAN_CHAIN);
        let (_, tmo, _, _) = dynset_of(&rule_exprs(rules[3]));
        assert_eq!(tmo, 5_000, "dynset 元素超时 = scan_set_timeout_ms(无 60s 垫底)");
    }
}

