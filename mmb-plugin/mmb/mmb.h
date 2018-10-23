/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 *
 * Author: Korian Edeline
 */

#ifndef __included_mmb_h__
#define __included_mmb_h__

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>

#include <vppinfra/error.h>

#include <mmb/mmb_opts.h>
#include <mmb/mmb_classify.h>
#include <mmb/mmb_conn.h>

/* Comment out to remove calls to vlib_cli_output() */
#define MMB_DEBUG

#define MMB_PLUGIN_BUILD_VER "0.3.3"

#define foreach_mmb_type \
  _(FIELD)               \
  _(CONDITION)           \
  _(VALUE)               \
  _(TARGET)              \
  _(FIELD_OPT)

#define foreach_mmb_condition \
  _(EQ,  "==")                \
  _(NEQ, "!=")                \
  _(LEQ, "<=")                \
  _(GEQ, ">=")                \
  _(LT,  "<")                 \
  _(GT,  ">")

#define foreach_mmb_target \
  _(DROP)                  \
  _(STRIP)                 \
  _(MODIFY)                \
  _(ADD)                   \
  _(LB)                    \
  _(MAP)                   \
  _(SHUFFLE)  

/* macro, CLI name, size, fixed len */
#define foreach_mmb_field                         \
  _(INTERFACE_IN, "in", 4, 1)                     \
  _(INTERFACE_OUT, "out", 4, 1)                   \
                                                  \
  _(NET_PROTO, "net-proto", 2, 1)                 \
                                                  \
  _(IP4_VER, "ip-ver", 1, 1)                      \
  _(IP4_IHL, "ip-ihl", 1, 1)                      \
  _(IP4_DSCP, "ip-dscp", 1, 1)                    \
  _(IP4_ECN, "ip-ecn", 1, 1)                      \
  _(IP4_NON_ECT, "ip-non-ect", 1, 1)              \
  _(IP4_ECT0, "ip-ect0", 1, 1)                    \
  _(IP4_ECT1, "ip-ect1", 1, 1)                    \
  _(IP4_CE, "ip-ce", 1, 1)                        \
  _(IP4_LEN, "ip-len", 2, 1)                      \
  _(IP4_ID, "ip-id", 2, 1)                        \
  _(IP4_FLAGS, "ip-flags", 1, 1)                  \
  _(IP4_RES, "ip-res", 1, 1)                      \
  _(IP4_DF, "ip-df", 1, 1)                        \
  _(IP4_MF, "ip-mf", 1, 1)                        \
  _(IP4_FRAG_OFFSET, "ip-frag-offset", 2, 1)      \
  _(IP4_TTL, "ip-ttl", 1, 1)                      \
  _(IP4_PROTO, "ip-proto", 1, 1)                  \
  _(IP4_CHECKSUM, "ip-checksum", 2, 1)            \
  _(IP4_SADDR, "ip-saddr", 5, 1)                  \
  _(IP4_DADDR, "ip-daddr", 5, 1)                  \
  _(IP4_PAYLOAD, "ip-payload", 0, 0)              \
                                                  \
  _(IP6_VER, "ip6-ver", 1, 1)                     \
  _(IP6_TRAFFIC_CLASS, "ip6-traffic-class", 1, 1) \
  _(IP6_FLOW_LABEL, "ip6-flow-label", 3, 1)       \
  _(IP6_LEN, "ip6-len", 2, 1)                     \
  _(IP6_NEXT, "ip6-next", 1, 1)                   \
  _(IP6_HOP_LIMIT, "ip6-hop-limit", 1, 1)         \
  _(IP6_SADDR, "ip6-saddr", 17, 1)                \
  _(IP6_DADDR, "ip6-daddr", 17, 1)                \
  _(IP6_PAYLOAD, "ip6-payload", 0, 0)             \
                                                  \
  _(ICMP_TYPE, "icmp-type", 1, 1)                 \
  _(ICMP_CODE, "icmp-code", 1, 1)                 \
  _(ICMP_CHECKSUM, "icmp-checksum", 2, 1)         \
  _(ICMP_PAYLOAD, "icmp-payload", 0, 0)           \
                                                  \
  _(UDP_SPORT, "udp-sport", 2, 1)                 \
  _(UDP_DPORT, "udp-dport", 2, 1)                 \
  _(UDP_LEN, "udp-len", 2, 1)                     \
  _(UDP_CHECKSUM, "udp-checksum", 2, 1)           \
  _(UDP_PAYLOAD, "udp-payload", 0, 0)             \
                                                  \
  _(TCP_SPORT, "tcp-sport", 2, 1)                 \
  _(TCP_DPORT, "tcp-dport", 2, 1)                 \
  _(TCP_SEQ_NUM, "tcp-seq-num", 4, 1)             \
  _(TCP_ACK_NUM, "tcp-ack-num", 4, 1)             \
  _(TCP_OFFSET, "tcp-offset", 1, 1)               \
  _(TCP_RESERVED, "tcp-reserved", 1, 1)           \
  _(TCP_FLAGS, "tcp-flags", 1, 1)                 \
  _(TCP_CWR, "tcp-cwr", 1, 1)                     \
  _(TCP_ECE, "tcp-ece", 1, 1)                     \
  _(TCP_URG, "tcp-urg", 1, 1)                     \
  _(TCP_ACK, "tcp-ack", 1, 1)                     \
  _(TCP_PUSH, "tcp-push", 1, 1)                   \
  _(TCP_RST, "tcp-rst", 1, 1)                     \
  _(TCP_SYN, "tcp-syn", 1, 1)                     \
  _(TCP_FIN, "tcp-fin", 1, 1)                     \
  _(TCP_WINDOW, "tcp-win", 2, 1)                  \
  _(TCP_CHECKSUM, "tcp-checksum", 2, 1)           \
  _(TCP_URG_PTR, "tcp-urg-ptr", 2, 1)             \
  _(TCP_PAYLOAD, "tcp-payload", 0, 0)             \
                                                  \
  _(TCP_OPT_MSS, "tcp-opt-mss", 2, 1)             \
  _(TCP_OPT_WSCALE, "tcp-opt-wscale", 1, 1)       \
  _(TCP_OPT_SACKP, "tcp-opt-sackp", 0, 1)         \
  _(TCP_OPT_SACK, "tcp-opt-sack", 0, 0)           \
  _(TCP_OPT_TIMESTAMP, "tcp-opt-timestamp", 8, 1) \
  _(TCP_OPT_FAST_OPEN, "tcp-opt-fast-open", 0, 0) \
  _(TCP_OPT_MPTCP, "tcp-opt-mptcp", 0, 0)         \
  _(TCP_OPT, "tcp-opt", 0, 0)                     \
                                                  \
  _(IP6_EH_HOPBYHOP, "ip6-eh-hopbyhop", 8, 1)     \
  _(IP6_EH_ROUTING, "ip6-eh-routing", 8, 1)       \
  _(IP6_EH_FRAGMENT, "ip6-eh-fragment", 8, 1)     \
  _(IP6_EH_ESP, "ip6-eh-esp", 8, 1)               \
  _(IP6_EH_AH, "ip6-eh-ah", 8, 1)                 \
  _(IP6_EH_DESTOPT, "ip6-eh-destopt", 8, 1)       \
  _(IP6_EH_MOBILITY, "ip6-eh-mobility", 8, 1)     \
  _(IP6_EH_HIP, "ip6-eh-hip", 8, 1)               \
  _(IP6_EH_SHIM6, "ip6-eh-shim6", 8, 1)           \
  _(IP6_EH, "ip6-eh", 8, 1)                       \
                                                  \
  _(ALL, "all", 0, 1)

enum
{
  /* TYPES */
  MMB_0_TYPE,
#define _(m) MMB_TYPE_##m,
  foreach_mmb_type
#undef _
  MMB_N_TYPE,

  /* CONDITIONS */
  MMB_0_COND,
#define _(m, s) MMB_COND_##m,
  foreach_mmb_condition
#undef _
  MMB_N_COND,

  /* TARGETS */
  MMB_0_TARGET,
#define _(m) MMB_TARGET_##m,
  foreach_mmb_target
#undef _
  MMB_N_TARGET,

  /* FIELDS */
  MMB_0_FIELD,
#define _(m, s, l, fl) MMB_FIELD_##m,
  foreach_mmb_field
#undef _
  MMB_N_FIELD,

  /* Private (only for cli->nodes) */
  MMB_FIELD_TCP_OPT_ALL,
};

#define is_macro_mmb_type(x) (x > MMB_0_TYPE && x < MMB_N_TYPE)
#define is_macro_mmb_condition(x) (x > MMB_0_COND && x < MMB_N_COND)
#define is_macro_mmb_target(x) (x > MMB_0_TARGET && x < MMB_N_TARGET)
#define is_macro_mmb_field(x) (x > MMB_0_FIELD && x < MMB_N_FIELD)

#define get_number_fields() MMB_N_FIELD-MMB_0_FIELD-1
#define get_number_conditions() MMB_N_COND-MMB_0_COND-1

#define field_toindex(macro) macro-MMB_0_FIELD-1
#define field_tomacro(index) index+MMB_0_FIELD+1
#define cond_toindex(macro) macro-MMB_0_COND-1
#define cond_tomacro(index) index+MMB_0_COND+1

#define MMB_MAX_FIELD_LEN 64
#define MMB_MAX_DROP_RATE_VALUE 100000

/* cli-name,protocol-name */
#define foreach_mmb_transport_proto \
_(tcp,TCP)                          \
_(udp,UDP)                          \
_(icmp,ICMP)
     
/* cli-name,protocol-name */                          
#define foreach_mmb_network_proto \
_(ip4,IP4)                        \
_(ip6,IP6)

#define is_drop(rule)\
     (vec_len(rule->targets) == 1 && rule->targets[0].keyword == MMB_TARGET_DROP)
#define next_if_match(rule)\
    (is_drop(rule)\
     ? MMB_CLASSIFY_NEXT_INDEX_DROP : MMB_CLASSIFY_NEXT_INDEX_MATCH)

#define MMB_TABLE_SIZE_INIT 2
#define MMB_TABLE_SIZE_INC_RATIO 2
#define MMB_TABLE_SIZE_DEC_RATIO 2
#define MMB_TABLE_SIZE_DEC_THRESHOLD 4

typedef struct {
   u8 *key;
   u32 lookup_index;
   u32 next;
} mmb_session_t;

typedef struct {
   u32 *rule_indexes; /*! vec of rule_index */
   /* XXX: rule_has_opt_match flag for slow pathing */
} mmb_lookup_entry_t;

typedef struct {

  u32 index; /* index in classifier */
  u32 next_index; /*! double-linked list for easy classifier update */
  u32 previous_index;
  u32 entry_count; /*! table occupation */
  u32 size;   /*! table capacity */

  u8 *mask; 
  u32 skip;
  u32 match;

  mmb_session_t *sessions;

} mmb_table_t;

typedef struct {
   u8 l4;
   u8 kind;
   u8 *value;
} mmb_transport_option_t;

typedef struct {
   u8 field; /*! The field to match on */
   u8 opt_kind; /*! The kind of option, if the field is one */
   u8 condition; /*! The constraint condition (optional) */
   u8 *value; /*! The constraint value (optional) */ 
   u8 reverse; /*! reverse matching (boolean not) */
} mmb_match_t;

typedef struct {
   u8 keyword; /*! The target keyword */ 
   u8 field;  /*! The field to modify */
   u8 opt_kind;  /*! The kind of option, if the field is one */
   u8 *value; /*! The value to write */ 
   u8 reverse; /*! whitelist (strip only) */
} mmb_target_t;

typedef struct {
  u16 l3; /*! l3 protocol */
  u8 l4; /*! l4 protocol */
  u32 in; /*! input if */
  u32 out; /*! output if */

  /* matches/constraints */
  mmb_match_t *matches; /*! Matches vector */
  mmb_match_t *opt_matches; /*! Options (tcp, ip6) */
  u32 match_count; /*! count of matched packets */

  /* targets/modifications */
  mmb_target_t           *targets; /*! Targets vector */
  uword                  *opt_strips;
  mmb_target_t           *opt_mods;
  mmb_transport_option_t *opt_adds;
  mmb_target_t           *shuffle_targets;
  mmb_target_t           *map_targets;

  /* mmb_classify */
  u8 *classify_mask;
  u32 classify_skip; 
  u32 classify_match;
  u8 *classify_key;
  u32 classify_table_index; /*! index of table in classifier */
  u32 lookup_index; /*! index for session to list of rules mapping */

  /* mmb_rewrite */
  u8 *rewrite_mask; 
  u32 rewrite_skip;
  u32 rewrite_match;
  u8 *rewrite_key;

  /* drop rate, unit is 0.001% */
  u32 drop_rate;

  /* flags */
  u8 has_strips:1;
  u8 whitelist:1;
  u8 opts_in_matches:1;
  u8 opts_in_targets:1;
  u8 lb:1;
  u8 stateful:1;
  u8 shuffle:1;
  u8 map:1; 

} mmb_rule_t;

typedef struct {
   /* API message ID base */
   u16 msg_id_base;

   mmb_rule_t *rules;  /*! Rules vector, per if, per dir */
   mmb_table_t *tables; /*! Tables vector */   
   mmb_lookup_entry_t *lookup_pool; /*! rule lookup pool */

   u8 feature_arc_index;
   u32 *sw_if_indexes;

   /* convenience */
   vlib_main_t *vlib_main;
   vnet_main_t *vnet_main;
   mmb_classify_main_t *mmb_classify_main;
   mmb_conn_table_t *mmb_conn_table;
   u64 last_conn_table_timeout_check;

   u8 opts_in_rules:1;
   u8 enabled:1;
   u8 unused:6;

   u32 random_seed;

} mmb_main_t;

mmb_main_t mmb_main;

extern const u8 fields_len;
extern const char* fields[];
extern const u8 lens[];
extern const u8 conditions_len;
extern const char* conditions[];

/**
 * get_field_protocol
 * 
 * @return protocol related to given field
 */
u16 get_field_protocol(u8 field);

/**
 * is_fixed_length
 *
 * @return 1 if field has fixed len in mmb, else 0
 */
u8 is_fixed_length(u8 field);

/**
 * bytes_to_u32
 * 
 * converts byte vector to a u32
 */
inline u32 bytes_to_u32(u8 *bytes) {
  u32 value = 0;
  u32 index = 0;
  const u32 len = clib_min(3,vec_len(bytes)-1);

  vec_foreach_index(index, bytes) {
    value += ((u32) bytes[index]) << (len-index)*8;
    if (index == len) 
      break;
  }

  return value;
}
/**
 * bytes_to_u64
 *
 * converts byte vector to a u64
 */
inline u64 bytes_to_u64(u8 *bytes) {
  u64 value = 0;
  u32 index = 0;
  const u32 len = clib_min(7,vec_len(bytes)-1);

  vec_foreach_index(index, bytes) {
    value += ((u64) bytes[index]) << (len-index)*8;
    if (index==len) break;
  }

  return value;
}

#endif /* __included_mmb_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
