#ifndef __included_mmb_node_h__
#define __included_mmb_node_h__

#include <mmb/mmb.h>


#define foreach_mmb_next_node \
  _(FORWARD, "Forward")         \
  _(DROP, "Drop")

typedef enum {
#define _(n,str) MMB_NEXT_##n,
  foreach_mmb_next_node
#undef _
  MMB_N_NEXT
} mmb_next_t;


#define foreach_mmb_error \
_(DONE, "MMB packets processed")

typedef enum {
#define _(sym,str) MMB_ERROR_##sym,
  foreach_mmb_error
#undef _
  MMB_N_ERROR,
} mmb_error_t;

static char * mmb_error_strings[] = {
#define _(sym,string) string,
  foreach_mmb_error
#undef _
};


typedef struct {
  u32 rule_index;
  u8  proto;
  ip4_address_t src_address;
  ip4_address_t dst_address;
  u32 sw_if_index;
  u32 next;
} mmb_trace_t;

typedef struct {
  u64 flags[4]; // 4 ranges for bits [0-63] [64-127] [128-191] [192-255]
  u8 data_length[255];
  u8 data_offset[255];
  u8* data;
} mmb_tcp_options_t;


static void mmb_target_modify(ip4_header_t *, mmb_target_t *, u8 *);
static void mmb_target_strip(mmb_tcp_options_t *, mmb_target_t *, u8 *);
static void mmb_rewrite_tcp_options(u8 *, mmb_tcp_options_t *);
static u8 rule_requires_tcp_options(mmb_rule_t *);
static void recompute_l4_checksum(vlib_main_t *, vlib_buffer_t *, ip4_header_t *);
static void recompute_l3_checksum(ip4_header_t *);
static u64 mmb_bytes_to_u64(u8 *);
static void mmb_parse_ip4_cidr_address(u8 *, u32 *, u32 *);
static u8 mmb_value_compare(u64, u64, u8, u8);
static u8 mmb_parse_tcp_options(tcp_header_t *, mmb_tcp_options_t *);
static u8 packet_matches(ip4_header_t *, mmb_rule_t *, mmb_tcp_options_t *);
static u32 packet_apply_targets(ip4_header_t *, mmb_target_t *, mmb_tcp_options_t *, u8 *);

vlib_node_registration_t mmb_node;


/************************
 *      IP fields
 ***********************/

u64 get_ip_field(ip4_header_t *iph, u8 field)
{
  u64 value = ~0;

  switch(field)
  {
    case MMB_FIELD_IP_VER:
      value = iph->ip_version_and_header_length >> 4;
      break;
    case MMB_FIELD_IP_IHL:
      value = iph->ip_version_and_header_length & 0xf;
      break;
    case MMB_FIELD_IP_DSCP:
      value = iph->tos >> 2;
      break;
    case MMB_FIELD_IP_ECN:
      value = iph->tos & 0x3;
      break;
    case MMB_FIELD_IP_LEN:
      value = clib_net_to_host_u16(iph->length);
      break;
    case MMB_FIELD_IP_ID:
      value = clib_net_to_host_u16(iph->fragment_id);
      break;
    case MMB_FIELD_IP_FLAGS:
      value = clib_net_to_host_u16(iph->flags_and_fragment_offset) >> 13;
      break;
    case MMB_FIELD_IP_RES:
      value = clib_net_to_host_u16(iph->flags_and_fragment_offset) >> 15;
      break;
    case MMB_FIELD_IP_DF:
      value = (clib_net_to_host_u16(iph->flags_and_fragment_offset) >> 14) & 0x1;
      break;
    case MMB_FIELD_IP_MF:
      value = (clib_net_to_host_u16(iph->flags_and_fragment_offset) >> 13) & 0x1;
      break;
    case MMB_FIELD_IP_FRAG_OFFSET:
      value = clib_net_to_host_u16(iph->flags_and_fragment_offset) & 0x1fff;
      break;
    case MMB_FIELD_IP_TTL:
      value = iph->ttl;
      break;
    case MMB_FIELD_IP_PROTO:
      value = iph->protocol;
      break;
    case MMB_FIELD_IP_CHECKSUM:
      value = clib_net_to_host_u16(iph->checksum);
      break;
    case MMB_FIELD_IP_SADDR:
      value = clib_net_to_host_u32(iph->src_address.as_u32);
      break;
    case MMB_FIELD_IP_DADDR:
      value = clib_net_to_host_u32(iph->dst_address.as_u32);
      break;
    default:
      break;
  }

  return value;
}

void set_ip_field(ip4_header_t *iph, u8 field, u64 value)
{
  switch(field)
  {
    case MMB_FIELD_IP_VER:
      iph->ip_version_and_header_length = (iph->ip_version_and_header_length & 0xf) | (value << 4);
      break;
    case MMB_FIELD_IP_IHL:
      iph->ip_version_and_header_length = (iph->ip_version_and_header_length & 0xf0) | value;
      break;
    case MMB_FIELD_IP_DSCP:
      iph->tos = (iph->tos & 0x3) | (value << 2);
      break;
    case MMB_FIELD_IP_ECN:
      iph->tos = (iph->tos & 0xfc) | value;
      break;
    case MMB_FIELD_IP_LEN:
      iph->length = clib_host_to_net_u16(value);
      break;
    case MMB_FIELD_IP_ID:
      iph->fragment_id = clib_host_to_net_u16(value);
      break;
    case MMB_FIELD_IP_FLAGS:
      iph->flags_and_fragment_offset = clib_host_to_net_u16((clib_net_to_host_u16(iph->flags_and_fragment_offset) & 0x1fff) | (value << 13));
      break;
    case MMB_FIELD_IP_RES:
      iph->flags_and_fragment_offset = clib_host_to_net_u16((clib_net_to_host_u16(iph->flags_and_fragment_offset) & 0x7fff) | (value << 15));
      break;
    case MMB_FIELD_IP_DF:
      iph->flags_and_fragment_offset = clib_host_to_net_u16((clib_net_to_host_u16(iph->flags_and_fragment_offset) & 0xbfff) | (value << 14));
      break;
    case MMB_FIELD_IP_MF:
      iph->flags_and_fragment_offset = clib_host_to_net_u16((clib_net_to_host_u16(iph->flags_and_fragment_offset) & 0xdfff) | (value << 13));
      break;
    case MMB_FIELD_IP_FRAG_OFFSET:
      iph->flags_and_fragment_offset = clib_host_to_net_u16((clib_net_to_host_u16(iph->flags_and_fragment_offset) & 0xe000) | value);
      break;
    case MMB_FIELD_IP_TTL:
      iph->ttl = value;
      break;
    case MMB_FIELD_IP_PROTO:
      iph->protocol = value;
      break;
    case MMB_FIELD_IP_CHECKSUM:
      iph->checksum = clib_host_to_net_u16(value);
      break;
    case MMB_FIELD_IP_SADDR:
      iph->src_address.as_u32 = clib_host_to_net_u32(value);
      break;
    case MMB_FIELD_IP_DADDR:
      iph->dst_address.as_u32 = clib_host_to_net_u32(value);
      break;
    default:
      break;
  }
}


/************************
 *     ICMP fields
 ***********************/

u64 get_icmp_field(icmp46_header_t *icmph, u8 field)
{
  u64 value = ~0;

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
    case MMB_FIELD_ICMP_PAYLOAD:
      //TODO
      break;
    default:
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
    case MMB_FIELD_ICMP_PAYLOAD:
      //TODO
      break;
    default:
      break;
  }
}


/************************
 *      UDP fields
 ***********************/

u64 get_udp_field(udp_header_t *udph, u8 field)
{
  u64 value = ~0;

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
    case MMB_FIELD_UDP_PAYLOAD:
      //TODO
      break;
    default:
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
    case MMB_FIELD_UDP_PAYLOAD:
      //TODO
      break;
    default:
      break;
  }
}


/************************
 *      TCP fields
 ***********************/

u64 get_tcp_field(tcp_header_t *tcph, u8 field)
{
  u64 value = ~0;

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
    case MMB_FIELD_TCP_PAYLOAD:
      //TODO
      break;
    default:
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
    case MMB_FIELD_TCP_PAYLOAD:
      //TODO
      break;
    default:
      break;
  }
}


/************************
 *      TCP options
 ***********************/

u8 tcp_option_exists(mmb_tcp_options_t *options, u8 kind)
{
  u64 flag_mask = 1L << (kind & 63);
  return (options->flags[kind >> 6] & flag_mask) != 0;
}

void tcp_option_set(mmb_tcp_options_t *options, u8 kind, u8 *value)
{
  //TODO add if not present ? ignore ?
}

void tcp_option_strip(mmb_tcp_options_t *options, u8 kind)
{
  u64 flag_mask = 1L << (kind & 63);
  options->flags[kind >> 6] &= ~flag_mask;
}

#endif /* __included_mmb_node_h__ */
