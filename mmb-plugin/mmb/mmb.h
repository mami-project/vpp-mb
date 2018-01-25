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
 */
#ifndef __included_mmb_h__
#define __included_mmb_h__

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>

#include <vppinfra/error.h>

#include <mmb/mmb_classify.h>

/* Comment out to remove calls to vlib_cli_output() */
//#define MMB_DEBUG

#define MMB_PLUGIN_BUILD_VER "0.1"

#define MMB_TYPE_FIELD           1
#define MMB_TYPE_CONDITION       2
#define MMB_TYPE_VALUE           3
#define MMB_TYPE_TARGET          4
#define MMB_TYPE_FIELD_OPT       5

#define MMB_COND_EQ              10
#define MMB_COND_NEQ             11
#define MMB_COND_LEQ             12
#define MMB_COND_GEQ             13
#define MMB_COND_LT              14
#define MMB_COND_GT              15

#define MMB_TARGET_DROP          20
#define MMB_TARGET_STRIP         21
#define MMB_TARGET_MODIFY        22
#define MMB_TARGET_ADD           23

/* field macros */
#define MMB_FIELD_INTERFACE_IN   108
#define MMB_FIELD_INTERFACE_OUT  109

#define MMB_FIELD_NET_PROTO         110
#define MMB_FIELD_IP4_VER           111
#define MMB_FIELD_IP4_IHL           112
#define MMB_FIELD_IP4_DSCP          113
#define MMB_FIELD_IP4_ECN           114
#define MMB_FIELD_IP4_NON_ECT       115
#define MMB_FIELD_IP4_ECT0          116
#define MMB_FIELD_IP4_ECT1          117
#define MMB_FIELD_IP4_CE            118
#define MMB_FIELD_IP4_LEN           119
#define MMB_FIELD_IP4_ID            120
#define MMB_FIELD_IP4_FLAGS         121
#define MMB_FIELD_IP4_RES           122
#define MMB_FIELD_IP4_DF            123
#define MMB_FIELD_IP4_MF            124
#define MMB_FIELD_IP4_FRAG_OFFSET   125
#define MMB_FIELD_IP4_TTL           126
#define MMB_FIELD_IP4_PROTO         127
#define MMB_FIELD_IP4_CHECKSUM      128
#define MMB_FIELD_IP4_SADDR         129
#define MMB_FIELD_IP4_DADDR         130
#define MMB_FIELD_IP4_PAYLOAD       131

#define MMB_FIELD_IP6_VER           132
#define MMB_FIELD_IP6_TRAFFIC_CLASS 133
#define MMB_FIELD_IP6_FLOW_LABEL    134
#define MMB_FIELD_IP6_LEN           135
#define MMB_FIELD_IP6_NEXT          136
#define MMB_FIELD_IP6_HOP_LIMIT     137
#define MMB_FIELD_IP6_SADDR         138
#define MMB_FIELD_IP6_DADDR         139
#define MMB_FIELD_IP6_PAYLOAD       140

#define MMB_FIELD_ICMP_TYPE      141
#define MMB_FIELD_ICMP_CODE      142
#define MMB_FIELD_ICMP_CHECKSUM  143
#define MMB_FIELD_ICMP_PAYLOAD   144

#define MMB_FIELD_UDP_SPORT      145
#define MMB_FIELD_UDP_DPORT      146
#define MMB_FIELD_UDP_LEN        147
#define MMB_FIELD_UDP_CHECKSUM   148
#define MMB_FIELD_UDP_PAYLOAD    149

#define MMB_FIELD_TCP_SPORT      150
#define MMB_FIELD_TCP_DPORT      151
#define MMB_FIELD_TCP_SEQ_NUM    152
#define MMB_FIELD_TCP_ACK_NUM    153
#define MMB_FIELD_TCP_OFFSET     154
#define MMB_FIELD_TCP_RESERVED   155
#define MMB_FIELD_TCP_FLAGS      156
#define MMB_FIELD_TCP_CWR        157
#define MMB_FIELD_TCP_ECE        158
#define MMB_FIELD_TCP_URG        159
#define MMB_FIELD_TCP_ACK        160
#define MMB_FIELD_TCP_PUSH       161
#define MMB_FIELD_TCP_RST        162
#define MMB_FIELD_TCP_SYN        163
#define MMB_FIELD_TCP_FIN        164
#define MMB_FIELD_TCP_WINDOW     165
#define MMB_FIELD_TCP_CHECKSUM   166
#define MMB_FIELD_TCP_URG_PTR    167
#define MMB_FIELD_TCP_PAYLOAD    168

#define MMB_FIELD_TCP_OPT_MSS        169
#define MMB_FIELD_TCP_OPT_WSCALE     170
#define MMB_FIELD_TCP_OPT_SACKP      171
#define MMB_FIELD_TCP_OPT_SACK       172
#define MMB_FIELD_TCP_OPT_TIMESTAMP  173
#define MMB_FIELD_TCP_OPT_FAST_OPEN  174
#define MMB_FIELD_TCP_OPT_MPTCP      175
#define MMB_FIELD_TCP_OPT            176

#define MMB_FIELD_ALL                177

/* opt_kind macro for 'strip all' */
#define MMB_FIELD_TCP_OPT_ALL        255

#define MMB_FIRST_FIELD MMB_FIELD_INTERFACE_IN
#define MMB_LAST_FIELD MMB_FIELD_ALL
#define MMB_FIRST_COND MMB_COND_EQ
#define MMB_LAST_COND MMB_COND_GT

/* mapping macros */
#define field_toindex(macro) macro-MMB_FIRST_FIELD
#define field_tomacro(index) index+MMB_FIRST_FIELD
#define cond_toindex(macro) macro-MMB_FIRST_COND
#define cond_tomacro(index) index+MMB_FIRST_COND

/* cli-name,protocol-name */
#define foreach_mmb_transport_proto       \
_(tcp,TCP)                                    \
_(udp,UDP)                                    \
_(icmp,ICMP)     
     
/* cli-name,protocol-name */                          
#define foreach_mmb_network_proto       \
_(ip4,IP4)                                    \
_(ip6,IP6)                                   

/* mmb-const,cli-name,opt-kind */
#define foreach_mmb_tcp_opts            \
_(MMB_FIELD_TCP_OPT_MSS,MSS,2)            \
_(MMB_FIELD_TCP_OPT_WSCALE,WScale,3)         \
_(MMB_FIELD_TCP_OPT_SACKP,SACK-P,4)          \
_(MMB_FIELD_TCP_OPT_SACK,SACK,5)           \
_(MMB_FIELD_TCP_OPT_TIMESTAMP,Timestamp,8)      \
_(MMB_FIELD_TCP_OPT_FAST_OPEN,FastOpen,34)      \
_(MMB_FIELD_TCP_OPT_MPTCP,MPTCP,30)                                    

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

#define is_drop(rule)\
     (vec_len(rule->targets) == 1 && rule->targets[0].keyword == MMB_TARGET_DROP)
#define next_if_match(rule)\
    (is_drop(rule)\
     ? MMB_CLASSIFY_NEXT_INDEX_DROP : MMB_CLASSIFY_NEXT_INDEX_MATCH)

#define MMB_TABLE_SIZE_INIT 2
#define MMB_TABLE_SIZE_RATIO 4

typedef struct {

  u32 index;
  u32 next_index;
  u32 previous_index;
  u32 entry_count; 
  u32 size;   /*! table capacity */

  u8 *mask;
  u32 skip;
  u32 match;
  
} mmb_table_t;

typedef struct {
  u16 l3;
  u8 l4;
  u32 in;
  u32 out;

  mmb_match_t *matches; /*! Matches vector */
  mmb_target_t *targets; /*! Targets vector */
  uword                  *opt_strips;
  mmb_target_t           *opt_mods;
  mmb_transport_option_t *opt_adds;

  uword match_count;

  u8 *classify_mask;
  u32 classify_skip; 
  u32 classify_match;
  u8 *classify_key;
  u32 classify_table_index;

  u8 *rewrite_mask; /* XXX: in dedicated struct for efficient access in node */
  u32 rewrite_skip;
  u32 rewrite_match;
  u8 *rewrite_key;

  u8 has_strips:1;
  u8 whitelist:1;
  u8 has_adds:1;
  u8 opts_in_matches:1;
  u8 opts_in_targets:1;
  u8 last_match:1;

} mmb_rule_t;

typedef struct {
   /* API message ID base */
   u16 msg_id_base;

   mmb_rule_t *rules;  /*! Rules vector, per if, per dir */
   mmb_table_t *tables; /*! Tables vector */   

   u8 feature_arc_index;
   u32 *sw_if_indexes;
   /* convenience */
   vlib_main_t * vlib_main;
   vnet_main_t *vnet_main;
   vnet_classify_main_t *classify_main;

   u8 opts_in_rules:1;
   u8 enabled:1;
} mmb_main_t;

mmb_main_t mmb_main;

//extern vlib_node_registration_t mmb_node;

extern const u8 fields_len;
extern const char* fields[];
extern const u8 lens[];
extern const u8 conditions_len;
extern const char* conditions[];

u16 get_field_protocol(u8 field);
u8 is_fixed_length(u8 field);

#endif /* __included_mmb_h__ */
