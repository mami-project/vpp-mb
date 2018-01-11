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
#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/pg/pg.h>
#include <vppinfra/error.h>
#include <mmb/node.h>

static uword get_ip_field(ip4_header_t *, u8);
static uword get_tcp_field(tcp_header_t *, u8);
static u16 get_icmp_field(icmp46_header_t *, u8);
static u16 get_udp_field(udp_header_t *, u8);
static void set_ip_field(ip4_header_t *, u8, u64);
static void set_icmp_field(icmp46_header_t *, u8, u64);
static void set_udp_field(udp_header_t *, u8, u64);
static void set_tcp_field(tcp_header_t *, u8, u64);

static u8 rule_requires_tcp_options(mmb_rule_t *);
static u8 tcp_option_exists(mmb_tcp_options_t *, u8);
static u8 mmb_parse_tcp_options(tcp_header_t *, mmb_tcp_options_t *);
static u8 mmb_rewrite_tcp_options(mmb_tcp_options_t *);
static u8 mmb_padding_tcp_options(u8 *, u8);

static u8 mmb_true_condition(u8, u8);
static u8 mmb_memcpy(u8 *, u8 *, u8);
static u64 mmb_bytes_to_u64(u8 *);
static u64 mmb_n_bytes_to_u64(u8 *, u8);
static void mmb_parse_ip4_cidr_address(u8 *, u32 *, u32 *);
static u8 mmb_value_compare(u64, u64, u8, u8);
static u8 mmb_value_starts_with(u8 *, u8, u8 *);
static void recompute_l3_checksum(ip4_header_t *);
static void recompute_l4_checksum(vlib_main_t *, vlib_buffer_t *, ip4_header_t *);

static u8 packet_matches(ip4_header_t *, mmb_rule_t *, mmb_tcp_options_t *, vlib_buffer_t *, int);
static u8 mmb_matching_ip4(ip4_header_t *, mmb_match_t *, vlib_buffer_t *, int);
static u8 mmb_matching_icmp(ip4_header_t *, mmb_match_t *, vlib_buffer_t *, int);
static u8 mmb_matching_udp(ip4_header_t *, mmb_match_t *, vlib_buffer_t *, int);
static u8 mmb_matching_tcp(ip4_header_t *, mmb_match_t *, vlib_buffer_t *, int);
static u8 mmb_matching_tcp_options(mmb_tcp_options_t *, mmb_match_t *);

static u8 packet_apply_targets(ip4_header_t *, mmb_rule_t *, mmb_tcp_options_t *, u8 *);
static u8 mmb_target_modify_field(ip4_header_t *, mmb_target_t *);
static u8 mmb_target_add_option(u8 *, mmb_transport_option_t *);
static u8 mmb_target_modify_option(mmb_tcp_options_t *, u8, u8 *);
static void mmb_target_strip_option(mmb_tcp_options_t *, u8);

vlib_node_registration_t mmb_node;

static_always_inline void init_tcp_options(mmb_tcp_options_t *options)
{
  memset(options, 0, sizeof(mmb_tcp_options_t));
  vec_validate(options->idx, 254);
  clib_bitmap_alloc(options->found, 255);
}

static void free_tcp_options(mmb_tcp_options_t *options)
{
  vec_free(options->idx);
  vec_free(options->parsed);
  clib_bitmap_free(options->found);
}

/************************
 *   MMB Node format
 ***********************/

static_always_inline u8* mmb_format_next_node(u8* s, va_list *args)
{
  u8 keyword = va_arg(*args, u32);
  char *keyword_str = "";

  switch(keyword)
  {
#define _(n,string) case MMB_NEXT_##n: { keyword_str = string; break; }
    foreach_mmb_next_node
#undef _
    default:
       break;
  }

  return format(s, "%s", keyword_str);
}

static_always_inline void 
mmb_trace_ip_packet(vlib_main_t * vm, vlib_buffer_t *b, vlib_node_runtime_t * node,
                    ip4_header_t *iph, u32 next, u32 sw_if_index, u32 applied_rule)
{
   mmb_trace_t *t = vlib_add_trace (vm, node, b, sizeof (*t));

   t->proto = iph->protocol;
   t->rule_index = applied_rule;
   t->src_address.as_u32 = iph->src_address.as_u32;
   t->dst_address.as_u32 = iph->dst_address.as_u32;
   t->next = next;
   t->sw_if_index = sw_if_index;
   t->iph=iph;
}

/* packet trace format function */
static u8 * format_mmb_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  mmb_trace_t * t = va_arg (*args, mmb_trace_t *);
  mmb_main_t mm = mmb_main;

  if (t->rule_index != 0) 
    s = format(s, "mmb: if:%U sa:%U da:%U %U pkt matched rule %u, target %U\n",
                   format_vnet_sw_if_index_name, mm.vnet_main, t->sw_if_index,
                   format_ip4_address, t->src_address.data,
                   format_ip4_address, t->dst_address.data,
                   format_ip_protocol, t->proto,
                   t->rule_index,
                   mmb_format_next_node, t->next);
  else 
    s = format(s, "mmb: if:%U sa:%U da:%U %U pkt unmatched\n", 
                   format_vnet_sw_if_index_name, mm.vnet_main, t->sw_if_index,
                   format_ip4_address, t->src_address.data,
                   format_ip4_address, t->dst_address.data,
                   format_ip_protocol, t->proto);

  s = format(s, "  mmb: %U", 
             format_ip4_header, t->iph, t->iph->length);

  return s;
}

/************************
 *      IP fields
 ***********************/

uword get_ip_field(ip4_header_t *iph, u8 field)
{
  uword value;

  switch(field)
  {
    case MMB_FIELD_IP4_VER:
      value = iph->ip_version_and_header_length >> 4;
      break;
    case MMB_FIELD_IP4_IHL:
      value = iph->ip_version_and_header_length & 0xf;
      break;
    case MMB_FIELD_IP4_DSCP:
      value = iph->tos >> 2;
      break;
    case MMB_FIELD_IP4_ECN:
      value = iph->tos & 0x3;
      break;
    case MMB_FIELD_IP4_LEN:
      value = clib_net_to_host_u16(iph->length);
      break;
    case MMB_FIELD_IP4_ID:
      value = clib_net_to_host_u16(iph->fragment_id);
      break;
    case MMB_FIELD_IP4_FLAGS:
      value = clib_net_to_host_u16(iph->flags_and_fragment_offset) >> 13;
      break;
    case MMB_FIELD_IP4_RES:
      value = clib_net_to_host_u16(iph->flags_and_fragment_offset) >> 15;
      break;
    case MMB_FIELD_IP4_DF:
      value = (clib_net_to_host_u16(iph->flags_and_fragment_offset) >> 14) & 0x1;
      break;
    case MMB_FIELD_IP4_MF:
      value = (clib_net_to_host_u16(iph->flags_and_fragment_offset) >> 13) & 0x1;
      break;
    case MMB_FIELD_IP4_FRAG_OFFSET:
      value = clib_net_to_host_u16(iph->flags_and_fragment_offset) & 0x1fff;
      break;
    case MMB_FIELD_IP4_TTL:
      value = iph->ttl;
      break;
    case MMB_FIELD_IP4_PROTO:
      value = iph->protocol;
      break;
    case MMB_FIELD_IP4_CHECKSUM:
      value = clib_net_to_host_u16(iph->checksum);
      break;
    case MMB_FIELD_IP4_SADDR:
      value = clib_net_to_host_u32(iph->src_address.as_u32);
      break;
    case MMB_FIELD_IP4_DADDR:
      value = clib_net_to_host_u32(iph->dst_address.as_u32);
      break;
    default:
      value = ~0;
      break;
  }

  return value;
}

void set_ip_field(ip4_header_t *iph, u8 field, u64 value)
{
  switch(field)
  {
    case MMB_FIELD_IP4_VER:
      iph->ip_version_and_header_length = (iph->ip_version_and_header_length & 0xf) | (value << 4);
      break;
    case MMB_FIELD_IP4_IHL:
      iph->ip_version_and_header_length = (iph->ip_version_and_header_length & 0xf0) | value;
      break;
    case MMB_FIELD_IP4_DSCP:
      iph->tos = (iph->tos & 0x3) | (value << 2);
      break;
    case MMB_FIELD_IP4_ECN:
      iph->tos = (iph->tos & 0xfc) | value;
      break;
    case MMB_FIELD_IP4_LEN:
      iph->length = clib_host_to_net_u16(value);
      break;
    case MMB_FIELD_IP4_ID:
      iph->fragment_id = clib_host_to_net_u16(value);
      break;
    case MMB_FIELD_IP4_FLAGS:
      iph->flags_and_fragment_offset = clib_host_to_net_u16((clib_net_to_host_u16(iph->flags_and_fragment_offset) & 0x1fff) | (value << 13));
      break;
    case MMB_FIELD_IP4_RES:
      iph->flags_and_fragment_offset = clib_host_to_net_u16((clib_net_to_host_u16(iph->flags_and_fragment_offset) & 0x7fff) | (value << 15));
      break;
    case MMB_FIELD_IP4_DF:
      iph->flags_and_fragment_offset = clib_host_to_net_u16((clib_net_to_host_u16(iph->flags_and_fragment_offset) & 0xbfff) | (value << 14));
      break;
    case MMB_FIELD_IP4_MF:
      iph->flags_and_fragment_offset = clib_host_to_net_u16((clib_net_to_host_u16(iph->flags_and_fragment_offset) & 0xdfff) | (value << 13));
      break;
    case MMB_FIELD_IP4_FRAG_OFFSET:
      iph->flags_and_fragment_offset = clib_host_to_net_u16((clib_net_to_host_u16(iph->flags_and_fragment_offset) & 0xe000) | value);
      break;
    case MMB_FIELD_IP4_TTL:
      iph->ttl = value;
      break;
    case MMB_FIELD_IP4_PROTO:
      iph->protocol = value;
      break;
    case MMB_FIELD_IP4_CHECKSUM:
      iph->checksum = clib_host_to_net_u16(value);
      break;
    case MMB_FIELD_IP4_SADDR:
      iph->src_address.as_u32 = clib_host_to_net_u32(value);
      break;
    case MMB_FIELD_IP4_DADDR:
      iph->dst_address.as_u32 = clib_host_to_net_u32(value);
      break;
    default:
      break;
  }
}

/************************
 *     ICMP fields
 ***********************/

u16 get_icmp_field(icmp46_header_t *icmph, u8 field)
{
  u16 value;

  switch(field)
  {
    case MMB_FIELD_ICMP_TYPE:
      value = icmph->type;
      break;
    case MMB_FIELD_ICMP_CODE:
      value = icmph->code;
      break;
    case MMB_FIELD_ICMP_CHECKSUM:
      value = clib_net_to_host_u16(icmph->checksum);
      break;
    default:
      value = ~0;
      break;
  }

  return value;
}

void set_icmp_field(icmp46_header_t *icmph, u8 field, u64 value)
{
  switch(field)
  {
    case MMB_FIELD_ICMP_TYPE:
      icmph->type = value;
      break;
    case MMB_FIELD_ICMP_CODE:
      icmph->code = value;
      break;
    case MMB_FIELD_ICMP_CHECKSUM:
      icmph->checksum = clib_host_to_net_u16(value);
      break;
    default:
      break;
  }
}

/************************
 *      UDP fields
 ***********************/

u16 get_udp_field(udp_header_t *udph, u8 field)
{
  u16 value;

  switch(field)
  {
    case MMB_FIELD_UDP_SPORT:
      value = clib_net_to_host_u16(udph->src_port);
      break;
    case MMB_FIELD_UDP_DPORT:
      value = clib_net_to_host_u16(udph->dst_port);
      break;
    case MMB_FIELD_UDP_LEN:
      value = clib_net_to_host_u16(udph->length);
      break;
    case MMB_FIELD_UDP_CHECKSUM:
      value = clib_net_to_host_u16(udph->checksum);
      break;
    default:
      value = ~0;
      break;
  }

  return value;
}

void set_udp_field(udp_header_t *udph, u8 field, u64 value)
{
  switch(field)
  {
    case MMB_FIELD_UDP_SPORT:
      udph->src_port = clib_host_to_net_u16(value);
      break;
    case MMB_FIELD_UDP_DPORT:
      udph->dst_port = clib_host_to_net_u16(value);
      break;
    case MMB_FIELD_UDP_LEN:
      udph->length = clib_host_to_net_u16(value);
      break;
    case MMB_FIELD_UDP_CHECKSUM:
      udph->checksum = clib_host_to_net_u16(value);
      break;
    default:
      break;
  }
}

/************************
 *      TCP fields
 ***********************/

uword get_tcp_field(tcp_header_t *tcph, u8 field)
{
  uword value;

  switch(field)
  {
    case MMB_FIELD_TCP_SPORT:
      value = clib_net_to_host_u16(tcph->src_port);
      break;
    case MMB_FIELD_TCP_DPORT:
      value = clib_net_to_host_u16(tcph->dst_port);
      break;
    case MMB_FIELD_TCP_SEQ_NUM:
      value = clib_net_to_host_u32(tcph->seq_number);
      break;
    case MMB_FIELD_TCP_ACK_NUM:
      value = clib_net_to_host_u32(tcph->ack_number);
      break;
    case MMB_FIELD_TCP_OFFSET:
      value = tcph->data_offset_and_reserved >> 4;
      break;
    case MMB_FIELD_TCP_RESERVED:
      value = tcph->data_offset_and_reserved & 0xf;
      break;
    case MMB_FIELD_TCP_FLAGS:
      value = tcph->flags;
      break;
    case MMB_FIELD_TCP_CWR:
      value = tcph->flags >> 7;
      break;
    case MMB_FIELD_TCP_ECE:
      value = (tcph->flags >> 6) & 0x1;
      break;
    case MMB_FIELD_TCP_URG:
      value = (tcph->flags >> 5) & 0x1;
      break;
    case MMB_FIELD_TCP_ACK:
      value = (tcph->flags >> 4) & 0x1;
      break;
    case MMB_FIELD_TCP_PUSH:
      value = (tcph->flags >> 3) & 0x1;
      break;
    case MMB_FIELD_TCP_RST:
      value = (tcph->flags >> 2) & 0x1;
      break;
    case MMB_FIELD_TCP_SYN:
      value = (tcph->flags >> 1) & 0x1;
      break;
    case MMB_FIELD_TCP_FIN:
      value = tcph->flags & 0x1;
      break;
    case MMB_FIELD_TCP_WINDOW:
      value = clib_net_to_host_u16(tcph->window);
      break;
    case MMB_FIELD_TCP_CHECKSUM:
      value = clib_net_to_host_u16(tcph->checksum);
      break;
    case MMB_FIELD_TCP_URG_PTR:
      value = clib_net_to_host_u16(tcph->urgent_pointer);
      break;
    default:
      value = ~0;
      break;
  }

  return value;
}

void set_tcp_field(tcp_header_t *tcph, u8 field, u64 value)
{
  switch(field)
  {
    case MMB_FIELD_TCP_SPORT:
      tcph->src_port = clib_host_to_net_u16(value);
      break;
    case MMB_FIELD_TCP_DPORT:
      tcph->dst_port = clib_host_to_net_u16(value);
      break;
    case MMB_FIELD_TCP_SEQ_NUM:
      tcph->seq_number = clib_host_to_net_u32(value);
      break;
    case MMB_FIELD_TCP_ACK_NUM:
      tcph->ack_number = clib_host_to_net_u32(value);
      break;
    case MMB_FIELD_TCP_OFFSET:
      tcph->data_offset_and_reserved = (tcph->data_offset_and_reserved & 0xf) | (value << 4);
      break;
    case MMB_FIELD_TCP_RESERVED:
      tcph->data_offset_and_reserved = (tcph->data_offset_and_reserved & 0xf0) | value;
      break;
    case MMB_FIELD_TCP_FLAGS:
      tcph->flags = value;
      break;
    case MMB_FIELD_TCP_CWR:
      tcph->flags = (tcph->flags & 0x7f) | (value << 7);
      break;
    case MMB_FIELD_TCP_ECE:
      tcph->flags = (tcph->flags & 0xbf) | (value << 6);
      break;
    case MMB_FIELD_TCP_URG:
      tcph->flags = (tcph->flags & 0xdf) | (value << 5);
      break;
    case MMB_FIELD_TCP_ACK:
      tcph->flags = (tcph->flags & 0xef) | (value << 4);
      break;
    case MMB_FIELD_TCP_PUSH:
      tcph->flags = (tcph->flags & 0xf7) | (value << 3);
      break;
    case MMB_FIELD_TCP_RST:
      tcph->flags = (tcph->flags & 0xfb) | (value << 2);
      break;
    case MMB_FIELD_TCP_SYN:
      tcph->flags = (tcph->flags & 0xfd) | (value << 1);
      break;
    case MMB_FIELD_TCP_FIN:
      tcph->flags = (tcph->flags & 0xfe) | value;
      break;
    case MMB_FIELD_TCP_WINDOW:
      tcph->window = clib_host_to_net_u16(value);
      break;
    case MMB_FIELD_TCP_CHECKSUM:
      tcph->checksum = clib_host_to_net_u16(value);
      break;
    case MMB_FIELD_TCP_URG_PTR:
      tcph->urgent_pointer = clib_host_to_net_u16(value);
      break;
    default:
      break;
  }
}

/************************
 *      TCP options
 ***********************/

static_always_inline u8 tcp_option_exists(mmb_tcp_options_t *options, u8 kind)
{
  return clib_bitmap_get_no_check(options->found, kind);
}

static_always_inline u8 rule_requires_tcp_options(mmb_rule_t *rule)
{
  return (rule->opts_in_matches || rule->opts_in_targets);
}

u8 mmb_parse_tcp_options(tcp_header_t *tcph, mmb_tcp_options_t *options)
{
  u8 offset, opt_len, kind;
  u8 opts_len = (tcp_doff(tcph) << 2) - sizeof(tcp_header_t);

  const u8 *data = (const u8 *)(tcph + 1);
  options->data = (u8 *)(tcph + 1);

  clib_bitmap_zero(options->found);

  if (vec_len(options->parsed) > 0)
    vec_delete(options->parsed, vec_len(options->parsed), 0);

  for(offset = 0; opts_len > 0; opts_len -= opt_len, data += opt_len, offset += opt_len)
  {
    kind = data[0];

    if (kind == TCP_OPTION_EOL)
    {
      break;
    }
    else if (kind == TCP_OPTION_NOOP)
    {
      opt_len = 1;
      continue;
    }
    else
    {
      /* Broken options */
      if (opts_len < 2)
        return 0;

      opt_len = data[1];
      if (opt_len < 2 || opt_len > opts_len)
        return 0;
    }

    mmb_tcp_option_t option;
    option.is_stripped = 0;
    option.offset = offset;
    option.data_length = opt_len-2;
    option.new_value = 0;

    clib_bitmap_set_no_check(options->found, kind, 1);
    vec_add1(options->parsed, option);
    options->idx[kind] = (u8) vec_len(options->parsed)-1;
  }

  return 1;
}

u8 mmb_rewrite_tcp_options(mmb_tcp_options_t *opts)
{
  u8 offset = 0; //writing cursor's position
  u8 shift = 0; //cumulative shift offset to the right (after a specific resize -see below-)

  u8 *data = opts->data;

  u8 i;
  vec_foreach_index(i, opts->parsed)
  {
    mmb_tcp_option_t *opt = &opts->parsed[i];

    if (opt->is_stripped)
      continue;

    if (vec_len(opt->new_value) > 0)
    {
      /* MODIFIED */
      u8 old_data_length = opt->data_length;
      u8 new_data_length = vec_len(opt->new_value);
      u8 new_opt_len = new_data_length + 2;

      if (old_data_length == new_data_length)
      {
        offset += mmb_memcpy(&data[offset], &data[opt->offset+shift], 2);
        offset += mmb_memcpy(&data[offset], &opt->new_value[0], new_data_length);
      }
      else if (old_data_length > new_data_length)
      {
        offset += mmb_memcpy(&data[offset], &data[opt->offset+shift], 1);
        offset += mmb_memcpy(&data[offset], &new_opt_len, 1);
        offset += mmb_memcpy(&data[offset], &opt->new_value[0], new_data_length);
      }
      else
      {
        /* New size is bigger than old size -> check if we have to make room */

        /* Get very next not-to-be-stripped option in the list */
        u8 j;
        for(j=i+1; j < vec_len(opts->parsed) && opts->parsed[j].is_stripped; j++);

        if (j < vec_len(opts->parsed))
        {
          mmb_tcp_option_t *next_opt = &opts->parsed[j];

          u8 offset_after_modify = offset + 2 + new_data_length;
          u8 overlap_offset = next_opt->offset + shift;
          
          if (offset_after_modify > overlap_offset)
          {
            /* Shift of *needed* bytes to the right */
            memmove(&data[offset_after_modify], &data[overlap_offset], /*TODO*/100);
            shift += (offset_after_modify - overlap_offset);
          }

          offset += mmb_memcpy(&data[offset], &data[opt->offset], 1);
          offset += mmb_memcpy(&data[offset], &new_opt_len, 1);
          offset += mmb_memcpy(&data[offset], &opt->new_value[0], new_data_length);
        }
        else
        {
          offset += mmb_memcpy(&data[offset], &data[opt->offset+shift], 1);
          offset += mmb_memcpy(&data[offset], &new_opt_len, 1);
          offset += mmb_memcpy(&data[offset], &opt->new_value[0], new_data_length);
        }
      }
    }
    else
    {
      /* NOT MODIFIED, rewrite */
      offset += mmb_memcpy(&data[offset], &data[opt->offset+shift], opt->data_length+2);
    }
  }

  return offset;
}

u8 mmb_padding_tcp_options(u8 *data, u8 offset)
{
  // Terminate TCP options
  if (offset % 4)
    data[offset++] = TCP_OPTION_EOL;

  // Padding to reach a u32 boundary
  while(offset % 4)
    data[offset++] = TCP_OPTION_NOOP;

  return offset;
  //TODO is this the right way vpp uses ? 
  //From my understanding, NOOPs should fill extra bits to align options on boundaries (not necessarily at the end)...
}

/************************
 *  Utility functions
 ***********************/

static_always_inline u8 mmb_true_condition(u8 condition, u8 reverse)
{
  return condition != reverse;
}

static_always_inline u8 mmb_memcpy(u8 *dst, u8 *from, u8 length)
{
  clib_memcpy(dst, from, length);
  return length;
}

static_always_inline void mmb_parse_ip4_cidr_address(u8 *bytes, u32 *ip_addr, u32 *mask)
{
  *mask = vec_pop(bytes);
  *ip_addr = mmb_bytes_to_u64(bytes);
  vec_add1(bytes, *mask);
}

static_always_inline u64 mmb_bytes_to_u64(u8 *bytes)
{
  return mmb_n_bytes_to_u64(bytes, vec_len(bytes));
}

u64 mmb_n_bytes_to_u64(u8 *data, u8 length)
{
  u64 value = 0;
  u32 len = length-1;

  u32 i;
  for(i = 0; i < length; i++) {
    value += ((u64) *data++) << ((len - i) * 8);
  }

  return value;
}

u8 mmb_value_compare(u64 a, u64 b, u8 condition, u8 reverse)
{
  u8 res;

  switch(condition)
  {
    case MMB_COND_EQ:
      res = (a == b);
      break;

    case MMB_COND_NEQ:
      res = (a != b);
      break;

    case MMB_COND_LEQ:
      res = (a <= b);
      break;

    case MMB_COND_GEQ:
      res = (a >= b);
      break;

    case MMB_COND_LT:
      res = (a < b);
      break;

    case MMB_COND_GT:
      res = (a > b);
      break;

    default:
      return 0;
  }

  if (reverse)
    return !res;

  return res;
}

u8 mmb_value_starts_with(u8 *pkt_data, u8 pkt_data_length, u8 *value)
{
  /* Packet data can't start with value if the latter is bigger */
  if (vec_len(value) > pkt_data_length)
    return 0;

  /* Compare each value byte to packet data ones */
  u32 i;
  vec_foreach_index(i, value)
  {
    /* Mismatch -> can't start with */
    if (pkt_data[i] != value[i])
      return 0;
  }

  /* Packet data starts with value */
  return 1;
}

void recompute_l4_checksum(vlib_main_t *vm, vlib_buffer_t *buffer, ip4_header_t *iph)
{
  switch(iph->protocol)
  {
    case IP_PROTOCOL_ICMP: ;
      icmp46_header_t *icmph = ip4_next_header(iph);
      icmph->checksum = 0;
      ip_csum_t csum = ip_incremental_checksum(0, icmph, clib_net_to_host_u16(iph->length) - sizeof(*iph));
      icmph->checksum = ~ip_csum_fold(csum);
      break;

    case IP_PROTOCOL_UDP: ;
      udp_header_t *udph = ip4_next_header(iph);
      udph->checksum = ip4_tcp_udp_compute_checksum(vm, buffer, iph);
      /* RFC 7011 section 10.3.2 */
      if (udph->checksum == 0)
        udph->checksum = 0xffff;
      break;

    case IP_PROTOCOL_TCP: ;
      tcp_header_t *tcph = ip4_next_header(iph);
      tcph->checksum = ip4_tcp_udp_compute_checksum(vm, buffer, iph);
      break;
    }
}

static_always_inline void recompute_l3_checksum(ip4_header_t *iph)
{
  iph->checksum = ip4_header_checksum(iph);
}

static_always_inline u32 get_sw_if_index(vlib_buffer_t *b, int is_output)
{
  return vnet_buffer(b)->sw_if_index[is_output];
}

static_always_inline u8 *get_ip_header(vlib_buffer_t *b, int is_output)
{
  u8 *p = vlib_buffer_get_current(b);
  if (is_output)
    p += ethernet_buffer_header_size(b);
  return p;
}

/************************
 *  MATCHING functions
 ***********************/

u8 packet_matches(ip4_header_t *iph, mmb_rule_t *rule, mmb_tcp_options_t *tcp_options, vlib_buffer_t *b, int is_output)
{
  u8 l4 = rule->l4;
  //u16 l3 = rule->l3; //used to distinguish ipv4/ipv6 rules

  /* Don't apply rules with a layer 4 different than the packet's one */
  /* Note: except for case l4 = IP_PROTOCOL_RESERVED -> "all" or only "ip-fields" in matching */
  if (l4 != IP_PROTOCOL_RESERVED && iph->protocol != l4)
    return 0;

  uword i;
  vec_foreach_index(i, rule->matches)
  {
    mmb_match_t *match = &rule->matches[i];

    /* "all" field -> MATCH */
    if (match->field == MMB_FIELD_ALL)
      return 1;

    /* check protocol condition */
    u16 field_protocol = get_field_protocol(match->field);
    switch(field_protocol)
    {
      /* IP field */
      case ETHERNET_TYPE_IP4:
        if (!mmb_matching_ip4(iph, match, b, is_output))
          return 0;
        break;

      /* ICMP field */
      case IP_PROTOCOL_ICMP:
        if (!mmb_matching_icmp(iph, match, b, is_output))
          return 0;
        break;

      /* UDP field */
      case IP_PROTOCOL_UDP:
        if (!mmb_matching_udp(iph, match, b, is_output))
          return 0;
        break;

      /* TCP field */
      case IP_PROTOCOL_TCP:
        if (match->field == MMB_FIELD_TCP_OPT)
        {
          if (!mmb_matching_tcp_options(tcp_options, match))
            return 0;
        }
        else if (!mmb_matching_tcp(iph, match, b, is_output))
          return 0;
        break;

      /* Unexpected field */
      default:
        return 0;
    }
  }

  /* MATCH: none of the conditions triggered "false" */
  return 1;
}

u8 mmb_matching_ip4(ip4_header_t *iph, mmb_match_t *match, vlib_buffer_t *b, int is_output)
{
  /* "!ip-field" is always false for an IP packet */
  if (match->condition == 0 && match->reverse == 1)
    return 0;

  switch(match->field)
  {
    case MMB_FIELD_IP4_PAYLOAD: ;
      //TODO skip options if any ?
      u8 *payload = get_ip_header(b, is_output) + sizeof(ip4_header_t);
      u32 payload_length = b->current_length - sizeof(ip4_header_t);
      if (!mmb_true_condition(mmb_value_starts_with(payload, payload_length, match->value),
                              match->reverse))
        return 0;
      break;

    case MMB_FIELD_IP4_SADDR:
    case MMB_FIELD_IP4_DADDR: ;
      u32 rule_addr, rule_slash_mask;
      mmb_parse_ip4_cidr_address(match->value, &rule_addr, &rule_slash_mask);
      u32 rule_netmask = 0xffffffff << (32 - rule_slash_mask);
      u32 ip_addr = get_ip_field(iph, match->field);
      if (!mmb_value_compare((ip_addr & rule_netmask), (rule_addr & rule_netmask), match->condition, match->reverse))
        return 0;
      break;

    default:
      if (!mmb_value_compare(get_ip_field(iph, match->field), mmb_bytes_to_u64(match->value), match->condition, match->reverse))
        return 0;
  }

   return 1;
}

u8 mmb_matching_icmp(ip4_header_t *iph, mmb_match_t *match, vlib_buffer_t *b, int is_output)
{
  /* "!icmp-field" is always false for an ICMP packet */
  if (match->condition == 0 && match->reverse == 1)
    return 0;

  if (match->field == MMB_FIELD_ICMP_PAYLOAD)
  {
    u8 *payload = get_ip_header(b, is_output) + sizeof(ip4_header_t) + sizeof(icmp46_header_t);
    u32 payload_length = b->current_length - sizeof(ip4_header_t) - sizeof(icmp46_header_t);
    if (!mmb_true_condition(mmb_value_starts_with(payload, payload_length, match->value),
                            match->reverse))
      return 0;
  }
  else
  {
      icmp46_header_t *icmph = ip4_next_header(iph);
      if (!mmb_value_compare(get_icmp_field(icmph, match->field), mmb_bytes_to_u64(match->value), match->condition, match->reverse))
        return 0;
  }

  return 1;
}

u8 mmb_matching_udp(ip4_header_t *iph, mmb_match_t *match, vlib_buffer_t *b, int is_output)
{
  /* "!udp-field" is always false for a UDP packet */
  if (match->condition == 0 && match->reverse == 1)
    return 0;

  if (match->field == MMB_FIELD_UDP_PAYLOAD)
  {
    u8 *payload = get_ip_header(b, is_output) + sizeof(ip4_header_t) + sizeof(udp_header_t);
    u32 payload_length = b->current_length - sizeof(ip4_header_t) - sizeof(udp_header_t);
    if (!mmb_true_condition(mmb_value_starts_with(payload, payload_length, match->value),
                            match->reverse))
      return 0;
  }
  else
  {
    udp_header_t *udph = ip4_next_header(iph);
    if (!mmb_value_compare(get_udp_field(udph, match->field), mmb_bytes_to_u64(match->value), match->condition, match->reverse))
      return 0;
  }

  return 1;
}

u8 mmb_matching_tcp(ip4_header_t *iph, mmb_match_t *match, vlib_buffer_t *b, int is_output)
{
  /* "!tcp-field" is always false for a TCP packet */
  if (match->condition == 0 && match->reverse == 1)
    return 0;

  if (match->field == MMB_FIELD_TCP_PAYLOAD)
  {
    //TODO skip options if any ?
    u8 *payload = get_ip_header(b, is_output) + sizeof(ip4_header_t) + sizeof(tcp_header_t);
    u32 payload_length = b->current_length - sizeof(ip4_header_t) - sizeof(tcp_header_t);
    if (!mmb_true_condition(mmb_value_starts_with(payload, payload_length, match->value),
                            match->reverse))
      return 0;
  }
  else
  {
    tcp_header_t *tcph = ip4_next_header(iph);
    if (!mmb_value_compare(get_tcp_field(tcph, match->field), mmb_bytes_to_u64(match->value), match->condition, match->reverse))
      return 0;
  }

  return 1;
}

u8 mmb_matching_tcp_options(mmb_tcp_options_t *options, mmb_match_t *match)
{
  //TODO replace opt_kind=0 by opt_kind=ALL (to distinguish option 0 and this case) -> see how Korian will handle it in the CLI
  if (match->opt_kind == 0 || match->opt_kind == MMB_FIELD_TCP_OPT_ALL)
  {
    /* do we have TCP options in this packet ? */
    if (!mmb_true_condition(vec_len(options->parsed) > 0, 
                            match->reverse))
      return 0;
  }
  else if (match->condition == 0)
  {
    /* only search for the existence of an option */
    if (!mmb_true_condition(tcp_option_exists(options, match->opt_kind),
                            match->reverse))
      return 0;
  }
  else
  {
    /* search for an option and its value */
    if (!tcp_option_exists(options, match->opt_kind))
      return 0;

    u8 opt_idx = options->idx[match->opt_kind];
    u8 opt_offset = options->parsed[opt_idx].offset;
    u8 opt_length = options->parsed[opt_idx].data_length;
    u8 *opt_data_ptr = &options->data[opt_offset+2];

    if (vec_len(match->value) > 8)
    {
      /* values > u64 */
      if (!mmb_true_condition(mmb_value_starts_with(opt_data_ptr, opt_length, match->value),
                              match->reverse))
        return 0;
    }
    else if (!mmb_value_compare(mmb_n_bytes_to_u64(opt_data_ptr, opt_length), 
                                mmb_bytes_to_u64(match->value), 
                                match->condition, match->reverse))
      return 0;
  }

  return 1;
}

/************************
 *   TARGET functions
 ***********************/

u8 packet_apply_targets(ip4_header_t *iph, mmb_rule_t *rule, mmb_tcp_options_t *tcp_options, u8 *l4_modified)
{
  u32 i;
  u8 old_opts_len = 0, new_opts_len = 0, opts_modified = 0;

  //TODO payload targets are not implemented
  /* TARGETS (drop, modify -other than options-) */
  vec_foreach_index(i, rule->targets)
  {
    mmb_target_t *target = &rule->targets[i];

    switch(target->keyword)
    {
      case MMB_TARGET_DROP:
        return MMB_NEXT_DROP;

      case MMB_TARGET_MODIFY:
          *l4_modified |= mmb_target_modify_field(iph, target);
        break;
    }
  }

  /* STRIPS (options only) */
  if (rule->has_strips)
  {
    uword *found_to_strip = clib_bitmap_dup_and(tcp_options->found, rule->opt_strips);
    if (!clib_bitmap_is_zero(found_to_strip))
    {
      clib_bitmap_foreach(i, found_to_strip, mmb_target_strip_option(tcp_options, i));
      opts_modified = 1;
    }
  }

  /* MODS (options only) */
  vec_foreach_index(i, rule->opt_mods)
  {
    mmb_target_t *opt_modified = &rule->opt_mods[i];
    opts_modified |= mmb_target_modify_option(tcp_options, opt_modified->opt_kind, opt_modified->value);
  }

  /* Rewrite TCP options (if needed) */
  if (opts_modified)
  {
    tcp_header_t *tcph = ip4_next_header(iph);
    old_opts_len = (tcp_doff(tcph) << 2) - sizeof(tcp_header_t);
    new_opts_len = mmb_rewrite_tcp_options(tcp_options);
  }
  else if (iph->protocol == IP_PROTOCOL_TCP)
  {
    tcp_header_t *tcph = ip4_next_header(iph);
    old_opts_len = (tcp_doff(tcph) << 2) - sizeof(tcp_header_t);
    new_opts_len = old_opts_len;
  }

  /* ADDS (options only) */
  vec_foreach_index(i, rule->opt_adds)
  {
    mmb_transport_option_t *opt_added = &rule->opt_adds[i];
    new_opts_len += mmb_target_add_option(&tcp_options->data[new_opts_len], opt_added);
    opts_modified = 1;
  }

  /* Padding for options (if needed) */
  if (opts_modified)
  {
    tcp_header_t *tcph = ip4_next_header(iph);
    new_opts_len = mmb_padding_tcp_options((u8 *)(tcph + 1), new_opts_len);

    /* can't overflow 40 bytes otherwise data_offset becomes crap */
    if (new_opts_len > 40)
      new_opts_len = 40;
    
    set_tcp_field(tcph, MMB_FIELD_TCP_OFFSET, (new_opts_len + sizeof(tcp_header_t)) >> 2);

    //TODO take care of fragmentation if any
    //u16 pkt_ip_length = get_ip_field(iph, MMB_FIELD_IP4_LEN);
    //set_ip_field(iph, MMB_FIELD_IP4_LEN, pkt_ip_length+new_opts_len-old_opts_len);
  }

  *l4_modified |= opts_modified;
  return MMB_NEXT_FORWARD;
}

u8 mmb_target_modify_field(ip4_header_t *iph, mmb_target_t *target)
{
  u16 field_protocol = get_field_protocol(target->field);

  switch(field_protocol)
  {
    case ETHERNET_TYPE_IP4:
      set_ip_field(iph, target->field, mmb_bytes_to_u64(target->value));
      return 0;

    case IP_PROTOCOL_ICMP:
      set_icmp_field(ip4_next_header(iph), target->field, mmb_bytes_to_u64(target->value));
      return 1;

    case IP_PROTOCOL_UDP:
      set_udp_field(ip4_next_header(iph), target->field, mmb_bytes_to_u64(target->value));
      return 1;

    case IP_PROTOCOL_TCP:
      set_tcp_field(ip4_next_header(iph), target->field, mmb_bytes_to_u64(target->value));
      return 1;
  }

  return 0;
}

static_always_inline u8 mmb_target_add_option(u8 *data, mmb_transport_option_t *option)
{
  u8 opt_len = vec_len(option->value)+2;

  *data++ = option->kind;
  *data++ = opt_len;
  clib_memcpy(data, option->value, opt_len-2);

  return opt_len;
}

static_always_inline u8 mmb_target_modify_option(mmb_tcp_options_t *tcp_options, u8 kind, u8 *new_value)
{
  if (tcp_option_exists(tcp_options, kind))
  {
    tcp_options->parsed[tcp_options->idx[kind]].new_value = new_value;
    return 1;
  }

  return 0;
}

static_always_inline void mmb_target_strip_option(mmb_tcp_options_t *tcp_options, u8 kind)
{
  u8 idx = tcp_options->idx[kind];
  tcp_options->parsed[idx].is_stripped = 1;
}

/************************
 *  Node entry function
 ***********************/

static uword
mmb_node_fn(vlib_main_t *vm, vlib_node_runtime_t *node,
            vlib_frame_t *frame, int is_ip6, int is_output,
            vlib_node_registration_t *mmb_node)
{
  mmb_main_t *mm = &mmb_main;
  mmb_rule_t *rules = mm->rules;

  u32 n_left_from, *from, *to_next;
  mmb_next_t next_index;
  u32 pkts_done = 0;

  mmb_tcp_options_t tcp_options;
  init_tcp_options(&tcp_options);
  u8 tcp_opts_loaded;

  from = vlib_frame_vector_args(frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  u32 sw_if_index = get_sw_if_index(vlib_get_buffer(vm, from[0]), is_output);

  while (n_left_from > 0)
  {
    u32 n_left_to_next;

    vlib_get_next_frame (vm, node, next_index,
			 to_next, n_left_to_next);

    /* one packet at a time */
    while (n_left_from > 0 && n_left_to_next > 0)
    {
      u32 bi0;
      vlib_buffer_t *b0;
      u32 next0 = MMB_NEXT_FORWARD;
      ip4_header_t *ip0;

      /* speculatively enqueue b0 to the current next frame */
      bi0 = from[0];
      to_next[0] = bi0;
      from += 1;
      to_next += 1;
      n_left_from -= 1;
      n_left_to_next -= 1;

      /* get vlib buffer, IP header */
      b0 = vlib_get_buffer (vm, bi0);
      ip0 = (ip4_header_t *) get_ip_header(b0, is_output);

      u32 i, applied_rule_index = ~0;
      u8 l4_modified = 0;
      tcp_opts_loaded = 0;

      /* fetch each rule to find a match */
      vec_foreach_index(i, rules)
      {
        mmb_rule_t *rule = rules+i;

        /* parse TCP options if necessary */
        if (ip0->protocol == IP_PROTOCOL_TCP && rule_requires_tcp_options(rule))
        {
          if (!tcp_opts_loaded && !mmb_parse_tcp_options(ip4_next_header(ip0), &tcp_options))
          {
            /* Malformed TCP options -> let the packet go */
            break;
          }

          tcp_opts_loaded = 1;
        }

        if (packet_matches(ip0, rule, &tcp_options, b0, is_output))
        {
          /* MATCH: apply targets to packet */
          next0 = packet_apply_targets(ip0, rule, &tcp_options, &l4_modified);
          applied_rule_index = i;
          rule->match_count++;

          if (next0 == MMB_NEXT_DROP || rule->last_match)
            break;
        }
      }

      /* Recompute checksum(s) if needed */
      if (next0 != MMB_NEXT_DROP)
      {
        if (l4_modified)
          recompute_l4_checksum(vm, b0, ip0);
        recompute_l3_checksum(ip0);
      }

      /* one more packet processed */
      pkts_done++;

      /* node trace (if enabled) */
      if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE) 
                        && (b0->flags & VLIB_BUFFER_IS_TRACED)))
      {
        mmb_trace_ip_packet(vm, b0, node, ip0, next0, sw_if_index, 
                            (applied_rule_index == ~0) ? 0 : applied_rule_index+1);
      }

      /* verify speculative enqueue, maybe switch current next frame */
      vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
				       to_next, n_left_to_next,
				       bi0, next0);
    }

    vlib_put_next_frame (vm, node, next_index, n_left_to_next);
  }

  vlib_node_increment_counter (vm, mmb_node->index, 
                               MMB_ERROR_DONE, pkts_done);

  //TODO If we allocated it somewhere else, deallocation must go elsewhere too
  free_tcp_options(&tcp_options);

  return frame->n_vectors;
}

/*************************************
 * IP4/IP6 In/Out Nodes configuration
 *************************************/

vlib_node_registration_t mmb_ip4_in_node;
static uword
mmb_node_ip4_in_fn(vlib_main_t *vm, vlib_node_runtime_t *node, 
                    vlib_frame_t *frame) {
  return mmb_node_fn(vm, node, frame, 0, 0, &mmb_ip4_in_node);
}

vlib_node_registration_t mmb_ip4_out_node;
static uword
mmb_node_ip4_out_fn(vlib_main_t *vm, vlib_node_runtime_t *node, 
                    vlib_frame_t *frame) {
  return mmb_node_fn(vm, node, frame, 0, 1, &mmb_ip4_out_node);
}

/*vlib_node_registration_t mmb_ip6_in_node;
static uword
mmb_node_ip6_in_fn(vlib_main_t *vm, vlib_node_runtime_t *node, 
                    vlib_frame_t *frame) {
  return mmb_node_fn(vm, node, frame, 1, 0, &mmb_ip6_in_node);
}

vlib_node_registration_t mmb_ip6_out_node;
static uword
mmb_node_ip6_out_fn(vlib_main_t *vm, vlib_node_runtime_t *node, 
                    vlib_frame_t *frame) {
  return mmb_node_fn(vm, node, frame, 1, 1, &mmb_ip6_out_node);
}*/

VLIB_REGISTER_NODE(mmb_ip4_in_node) =
{
  .function = mmb_node_ip4_in_fn,
  .name = "mmb-plugin-ip4-in",
  .vector_size = sizeof (u32),
  .format_trace = format_mmb_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(mmb_error_strings),
  .error_strings = mmb_error_strings,

  .n_next_nodes = MMB_N_NEXT,
  .next_nodes = {
    [MMB_NEXT_FORWARD]   = "ip4-lookup",
    [MMB_NEXT_DROP]   = "error-drop",
  }
};

VNET_FEATURE_INIT (mmb_ip4_in_feature, static) = {
  .arc_name = "ip4-unicast",
  .node_name = "mmb-plugin-ip4-in",
  .runs_before = VNET_FEATURES("ip4-lookup"), 
};

VLIB_REGISTER_NODE(mmb_ip4_out_node) =
{
  .function = mmb_node_ip4_out_fn,
  .name = "mmb-plugin-ip4-out",
  .vector_size = sizeof(u32),
  .format_trace = format_mmb_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(mmb_error_strings),
  .error_strings = mmb_error_strings,

  .n_next_nodes = MMB_N_NEXT,
  .next_nodes = {
    [MMB_NEXT_FORWARD]   = "interface-output",
    [MMB_NEXT_DROP]   = "error-drop",
  }
};

VNET_FEATURE_INIT (mmb_ip4_out_feature, static) = {
  .arc_name = "ip4-output",
  .node_name = "mmb-plugin-ip4-out",
  .runs_before = VNET_FEATURES("interface-output"), 
};


/*VLIB_REGISTER_NODE(mmb_ip6_in_node) =
{
  .function = mmb_node_ip6_in_fn,
  .name = "mmb-plugin-ip6-in",
  .vector_size = sizeof(u32),
  .format_trace = format_mmb_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(mmb_error_strings),
  .error_strings = mmb_error_strings,

  .n_next_nodes = MMB_N_NEXT,
  .next_nodes = {
    [MMB_NEXT_FORWARD]   = "ip6-lookup",
    [MMB_NEXT_DROP]   = "error-drop",
  }
};

VNET_FEATURE_INIT (mmb_ip6_in_feature, static) = {
  .arc_name = "ip6-unicast",
  .node_name = "mmb-plugin-ip6-in",
  .runs_before = VNET_FEATURES("ip6-lookup"), 
};

VLIB_REGISTER_NODE(mmb_ip6_out_node) =
{
  .function = mmb_node_ip6_out_fn,
  .name = "mmb-plugin-ip6-out",
  .vector_size = sizeof(u32),
  .format_trace = format_mmb_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(mmb_error_strings),
  .error_strings = mmb_error_strings,

  .n_next_nodes = MMB_N_NEXT,
  .next_nodes = {
    [MMB_NEXT_FORWARD]   = "interface-output",
    [MMB_NEXT_DROP] = "error-drop",
  }
};

VNET_FEATURE_INIT (mmb_ip6_out_feature, static) = {
  .arc_name = "ip6-output",
  .node_name = "mmb-plugin-ip6-out",
  .runs_before = VNET_FEATURES("interface-output"), 
};*/

