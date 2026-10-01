//! 从 uapi 头文件手工转录的 nf_tables / netlink 常量(仅取值,不 bindgen)。
//! 来源注释标注各常量所在的内核头文件,便于核对。

// ---- linux/netlink.h ----
pub const NLM_F_REQUEST: u16 = 0x01; // netlink.h
pub const NLM_F_MULTI: u16 = 0x02;
pub const NLM_F_ACK: u16 = 0x04;
pub const NLM_F_ROOT: u16 = 0x100;
pub const NLM_F_MATCH: u16 = 0x200;
pub const NLM_F_EXCL: u16 = 0x200; // 新建类标志位,数值与 MATCH 相同
pub const NLM_F_CREATE: u16 = 0x400;
pub const NLM_F_APPEND: u16 = 0x800;
pub const NLM_F_DUMP: u16 = NLM_F_ROOT | NLM_F_MATCH; // 0x300
pub const NLMSG_ERROR: u16 = 0x2;
pub const NLMSG_DONE: u16 = 0x3;
pub const NLMSG_HDRLEN: usize = 16; // sizeof(struct nlmsghdr)
pub const NLA_F_NESTED: u16 = 1 << 15;
pub const NLA_TYPE_MASK: u16 = !(NLA_F_NESTED) & 0xffff;
/// `linux/netlink.h` 的 extack 属性:`NLMSGERR_ATTR_MSG` 带内核原文原因。
pub const NLMSGERR_ATTR_MSG: u16 = 1;

// ---- linux/netfilter/nfnetlink.h ----
pub const NFNL_SUBSYS_NFTABLES: u16 = 10; // NFNL_SUBSYS_NFTABLES
pub const NFNL_MSG_BATCH_BEGIN: u16 = 16; // NLMSG_MIN_TYPE
pub const NFNL_MSG_BATCH_END: u16 = 17; // NLMSG_MIN_TYPE + 1
pub const NFNETLINK_V0: u8 = 0;

// ---- linux/netfilter.h ----
pub const NF_DROP: i32 = 0; // nf_tables: verdict code
pub const NF_ACCEPT: i32 = 1;
pub const NF_INET_PRE_ROUTING: u32 = 0; // enum nf_inet_hooks
pub const NF_INET_LOCAL_IN: u32 = 1;

// ---- linux/netfilter/nf_tables.h: enum nf_tables_msg_types ----
pub const NFT_MSG_NEWTABLE: u16 = 0;
pub const NFT_MSG_DELTABLE: u16 = 2;
pub const NFT_MSG_NEWCHAIN: u16 = 3;
pub const NFT_MSG_NEWRULE: u16 = 6;
pub const NFT_MSG_GETRULE: u16 = 7;
pub const NFT_MSG_DELRULE: u16 = 8;
pub const NFT_MSG_NEWSET: u16 = 9;
pub const NFT_MSG_NEWSETELEM: u16 = 12;
pub const NFT_MSG_GETSETELEM: u16 = 13;
pub const NFT_MSG_DELSETELEM: u16 = 14;

// ---- nf_tables.h: enum nft_registers ----
pub const NFT_REG_VERDICT: u32 = 0;
pub const NFT_REG_1: u32 = 1;

// ---- nf_tables.h: enum nft_set_flags ----
pub const NFT_SET_INTERVAL: u32 = 0x4;
pub const NFT_SET_TIMEOUT: u32 = 0x10;
pub const NFT_SET_EVAL: u32 = 0x20; // 可从求值路径更新(dynset/meter 需要)

// ---- nf_tables.h: enum nft_set_elem_flags ----
pub const NFT_SET_ELEM_INTERVAL_END: u32 = 0x1;

// ---- nf_tables.h: enum nft_payload_bases ----
pub const NFT_PAYLOAD_NETWORK_HEADER: u32 = 1;
pub const NFT_PAYLOAD_TRANSPORT_HEADER: u32 = 2;

// ---- nf_tables.h: enum nft_cmp_ops ----
pub const NFT_CMP_EQ: u32 = 0;
pub const NFT_CMP_NEQ: u32 = 1;

// ---- nf_tables.h: enum nft_meta_keys ----
pub const NFT_META_NFPROTO: u32 = 15;
pub const NFT_META_L4PROTO: u32 = 16;

// ---- nf_tables.h: enum nft_ct_keys ----
pub const NFT_CT_STATE: u32 = 0;

// ---- nf_tables.h: enum nft_dynset_ops / flags ----
pub const NFT_DYNSET_OP_ADD: u32 = 0;

// ---- nf_tables.h: enum nft_limit_* ----
pub const NFT_LIMIT_PKTS: u32 = 0;
pub const NFT_LIMIT_F_INV: u32 = 1; // rate over

// ---- nf_tables.h: enum nft_*_attributes(全部按声明顺序从 0 递增) ----
pub const NFTA_TABLE_NAME: u16 = 1;

pub const NFTA_CHAIN_TABLE: u16 = 1;
pub const NFTA_CHAIN_NAME: u16 = 3;
pub const NFTA_CHAIN_HOOK: u16 = 4;
pub const NFTA_CHAIN_POLICY: u16 = 5;
pub const NFTA_CHAIN_TYPE: u16 = 7;

pub const NFTA_HOOK_HOOKNUM: u16 = 1;
pub const NFTA_HOOK_PRIORITY: u16 = 2;

pub const NFTA_RULE_TABLE: u16 = 1;
pub const NFTA_RULE_CHAIN: u16 = 2;
pub const NFTA_RULE_HANDLE: u16 = 3;
pub const NFTA_RULE_EXPRESSIONS: u16 = 4;

pub const NFTA_SET_TABLE: u16 = 1;
pub const NFTA_SET_NAME: u16 = 2;
pub const NFTA_SET_FLAGS: u16 = 3;
pub const NFTA_SET_KEY_TYPE: u16 = 4;
pub const NFTA_SET_KEY_LEN: u16 = 5;
/// 集合 id。内核对 `NFT_MSG_NEWSET` 要求该属性存在（缺则直接 EINVAL，
/// 也不给 extack 文本），所以所有建集合的消息都必须带它。
pub const NFTA_SET_ID: u16 = 10;
pub const NFTA_SET_TIMEOUT: u16 = 11;

pub const NFTA_SET_ELEM_LIST_TABLE: u16 = 1;
pub const NFTA_SET_ELEM_LIST_SET: u16 = 2;
pub const NFTA_SET_ELEM_LIST_ELEMENTS: u16 = 3;

pub const NFTA_SET_ELEM_KEY: u16 = 1;
pub const NFTA_SET_ELEM_FLAGS: u16 = 3;
pub const NFTA_SET_ELEM_TIMEOUT: u16 = 4;
pub const NFTA_SET_ELEM_EXPIRATION: u16 = 5;
pub const NFTA_SET_ELEM_KEY_END: u16 = 10;

pub const NFTA_LIST_ELEM: u16 = 1;

pub const NFTA_EXPR_NAME: u16 = 1;
pub const NFTA_EXPR_DATA: u16 = 2;

pub const NFTA_IMMEDIATE_DREG: u16 = 1;
pub const NFTA_IMMEDIATE_DATA: u16 = 2;

pub const NFTA_CMP_SREG: u16 = 1;
pub const NFTA_CMP_OP: u16 = 2;
pub const NFTA_CMP_DATA: u16 = 3;

pub const NFTA_META_DREG: u16 = 1;
pub const NFTA_META_KEY: u16 = 2;

pub const NFTA_PAYLOAD_DREG: u16 = 1;
pub const NFTA_PAYLOAD_BASE: u16 = 2;
pub const NFTA_PAYLOAD_OFFSET: u16 = 3;
pub const NFTA_PAYLOAD_LEN: u16 = 4;

pub const NFTA_LOOKUP_SET: u16 = 1;
pub const NFTA_LOOKUP_SREG: u16 = 2;

pub const NFTA_CT_DREG: u16 = 1;
pub const NFTA_CT_KEY: u16 = 2;

pub const NFTA_BITWISE_SREG: u16 = 1;
pub const NFTA_BITWISE_DREG: u16 = 2;
pub const NFTA_BITWISE_LEN: u16 = 3;
pub const NFTA_BITWISE_MASK: u16 = 4;
pub const NFTA_BITWISE_XOR: u16 = 5;

pub const NFTA_DATA_VALUE: u16 = 1;
pub const NFTA_DATA_VERDICT: u16 = 2;
pub const NFTA_VERDICT_CODE: u16 = 1;

pub const NFTA_DYNSET_SET_NAME: u16 = 1;
pub const NFTA_DYNSET_SET_ID: u16 = 2;
pub const NFTA_DYNSET_OP: u16 = 3;
pub const NFTA_DYNSET_SREG_KEY: u16 = 4;
pub const NFTA_DYNSET_TIMEOUT: u16 = 6;
pub const NFTA_DYNSET_EXPR: u16 = 7;
pub const NFTA_DYNSET_FLAGS: u16 = 9;

pub const NFTA_LIMIT_RATE: u16 = 1;
pub const NFTA_LIMIT_UNIT: u16 = 2;
pub const NFTA_LIMIT_BURST: u16 = 3;
pub const NFTA_LIMIT_TYPE: u16 = 4;
pub const NFTA_LIMIT_FLAGS: u16 = 5;

// ---- 其他 ----
pub const NFPROTO_INET: u8 = 1; // linux/in.h: NFPROTO_INET(table inet 用)
pub const NFPROTO_IPV4: u8 = 2;
pub const NFPROTO_IPV6: u8 = 10;
pub const IPPROTO_TCP: u8 = 6; // linux/in.h
/// nft 用户态 datatype 编号(rustables data_type.rs / nft datatype.h):ipaddr=7, ip6addr=8
pub const NFT_DATATYPE_IPADDR: u32 = 7;
pub const NFT_DATATYPE_IP6ADDR: u32 = 8;
/// conntrack IP_CT_NEW(nf_conntrack.h):ct state new 的比较位
pub const CT_STATE_NEW_BIT: u32 = 8;

/// netlink 属性对齐长度(linux/netlink.h NLA_ALIGNTO/NLMSG_ALIGNTO)
pub const NLMSG_ALIGNTO: usize = 4;

#[inline]
pub fn align4(n: usize) -> usize {
    (n + NLMSG_ALIGNTO - 1) & !(NLMSG_ALIGNTO - 1)
}
