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

#define MMB_FIELD_PROTO_IP       70
#define MMB_FIELD_PROTO_ICMP     71
#define MMB_FIELD_PROTO_TCP      72
#define MMB_FIELD_PROTO_UDP      73

#define MMB_FIELD_NET_PROTO      110
#define MMB_FIELD_IP_VER         111
#define MMB_FIELD_IP_IHL         112
#define MMB_FIELD_IP_DSCP        113
#define MMB_FIELD_IP_ECN         114
#define MMB_FIELD_IP_NON_ECT     115
#define MMB_FIELD_IP_ECT0        116
#define MMB_FIELD_IP_ECT1        117
#define MMB_FIELD_IP_CE          118
#define MMB_FIELD_IP_LEN         119
#define MMB_FIELD_IP_ID          120
#define MMB_FIELD_IP_FLAGS       121
#define MMB_FIELD_IP_RES         122
#define MMB_FIELD_IP_DF          123
#define MMB_FIELD_IP_MF          124
#define MMB_FIELD_IP_FRAG_OFFSET 125
#define MMB_FIELD_IP_TTL         126
#define MMB_FIELD_IP_PROTO       127
#define MMB_FIELD_IP_CHECKSUM    128
#define MMB_FIELD_IP_SADDR       129
#define MMB_FIELD_IP_DADDR       130

#define MMB_FIELD_ICMP_TYPE      131
#define MMB_FIELD_ICMP_CODE      132
#define MMB_FIELD_ICMP_CHECKSUM  133
#define MMB_FIELD_ICMP_PAYLOAD   134

#define MMB_FIELD_UDP_SPORT      135
#define MMB_FIELD_UDP_DPORT      136
#define MMB_FIELD_UDP_LEN        137
#define MMB_FIELD_UDP_CHECKSUM   138
#define MMB_FIELD_UDP_PAYLOAD    139

#define MMB_FIELD_TCP_SPORT      140
#define MMB_FIELD_TCP_DPORT      141
#define MMB_FIELD_TCP_SEQ_NUM    142
#define MMB_FIELD_TCP_ACK_NUM    143
#define MMB_FIELD_TCP_OFFSET     144
#define MMB_FIELD_TCP_RESERVED   145
#define MMB_FIELD_TCP_FLAGS      146
#define MMB_FIELD_TCP_CWR        147
#define MMB_FIELD_TCP_ECE        148
#define MMB_FIELD_TCP_URG        149
#define MMB_FIELD_TCP_ACK        150
#define MMB_FIELD_TCP_PUSH       151
#define MMB_FIELD_TCP_RST        152
#define MMB_FIELD_TCP_SYN        153
#define MMB_FIELD_TCP_FIN        154
#define MMB_FIELD_TCP_WINDOW     155
#define MMB_FIELD_TCP_CHECKSUM   156
#define MMB_FIELD_TCP_URG_PTR    157

#define MMB_FIELD_TCP_PAYLOAD    158

#define MMB_FIELD_TCP_OPT_MSS        159
#define MMB_FIELD_TCP_OPT_WSCALE     160
#define MMB_FIELD_TCP_OPT_SACKP      161
#define MMB_FIELD_TCP_OPT_SACK       162
#define MMB_FIELD_TCP_OPT_TIMESTAMP  163
#define MMB_FIELD_TCP_OPT_FAST_OPEN  164
#define MMB_FIELD_TCP_OPT_MPTCP      165
#define MMB_FIELD_TCP_OPT            166

#define MMB_FIELD_ALL                167

#define field_toindex(macro) macro-MMB_FIELD_NET_PROTO
#define field_tomacro(index) index+MMB_FIELD_NET_PROTO
#define cond_toindex(macro) macro-MMB_COND_EQ
#define cond_tomacro(index) index+MMB_COND_EQ

#define MMB_MAX_FIELD_LEN 32

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
_(MMB_FIELD_TCP_OPT_FAST_OPEN,Fast Open,34)      \
_(MMB_FIELD_TCP_OPT_MPTCP,MPTCP,30)                                    

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
  u16 l3;
  u8 l4;
  mmb_match_t *matches; /*! Matches vector */
  mmb_target_t *targets; /*! Targets vector */

/* mmb_rule_t flags */
#define MMB_RULE_CONTAIN_STRIPS (1 << 0)
#define MMB_RULE_WHITELIST (1 << 1)
#define MMB_RULE_MATCHES_CONTAIN_OPTS (1 << 2)
#define MMB_RULE_TARGETS_CONTAIN_OPTS (1 << 3)
  u8 flags;
  u8 *opts;
} mmb_rule_t;

typedef struct {
   /* API message ID base */
   u16 msg_id_base;

   mmb_rule_t *rules;  /*! Rules vector */

   u32 *sw_if_indexes;
   /* convenience */
   vnet_main_t *vnet_main;
} mmb_main_t;

mmb_main_t mmb_main;

extern vlib_node_registration_t mmb_node;

extern const u8 fields_len;
extern const char* fields[];
extern const u8 lens_len;
extern const u8 lens[];
extern const u8 conditions_len;
extern const char* conditions[];

u16 get_field_protocol(u8 field);

#endif /* __included_mmb_h__ */
