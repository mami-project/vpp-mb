#ifndef __included_mmb_node_h__
#define __included_mmb_node_h__

#include <mmb/mmb.h>

#define SET_IP_FIELD(pkt, field, value) \
\
  (field == MMB_FIELD_IP_VER) ? \
    (value == -1) ? (pkt->ip_version_and_header_length >> 4) : \
                    (pkt->ip_version_and_header_length = (pkt->ip_version_and_header_length & 0xf) | (value << 4), 0) : \
\
  (field == MMB_FIELD_IP_IHL) ? \
    (value == -1) ? (pkt->ip_version_and_header_length & 0xf) : \
                    (pkt->ip_version_and_header_length = (pkt->ip_version_and_header_length & 0xf0) | value, 0) : \
\
  (field == MMB_FIELD_IP_DSCP) ? \
    (value == -1) ? (pkt->tos >> 2) : (pkt->tos = (pkt->tos & 0x3) | (value << 2), 0) : \
\
  (field == MMB_FIELD_IP_ECN) ? \
    (value == -1) ? (pkt->tos & 0x3) : (pkt->tos = (pkt->tos & 0xfc) | value, 0) : \
\
  (field == MMB_FIELD_IP_LEN) ? \
    (value == -1) ? clib_net_to_host_u16(pkt->length) : (pkt->length = clib_host_to_net_u16(value), 0) : \
\
  (field == MMB_FIELD_IP_ID) ? \
    (value == -1) ? clib_net_to_host_u16(pkt->fragment_id) : (pkt->fragment_id = clib_host_to_net_u16(value), 0) : \
\
  (field == MMB_FIELD_IP_FLAGS) ? \
    (value == -1) ? (clib_net_to_host_u16(pkt->flags_and_fragment_offset) >> 13) : \
                    (pkt->flags_and_fragment_offset = \
                      clib_host_to_net_u16((clib_net_to_host_u16(pkt->flags_and_fragment_offset) & 0x1fff) | (value << 13)), 0) : \
\
  (field == MMB_FIELD_IP_RES) ? \
    (value == -1) ? (clib_net_to_host_u16(pkt->flags_and_fragment_offset) >> 15) : \
                    (pkt->flags_and_fragment_offset = \
                      clib_host_to_net_u16((clib_net_to_host_u16(pkt->flags_and_fragment_offset) & 0x7fff) | (value << 15)), 0) : \
\
  (field == MMB_FIELD_IP_DF) ? \
    (value == -1) ? ((clib_net_to_host_u16(pkt->flags_and_fragment_offset) >> 14) & 0x1) : \
                    (pkt->flags_and_fragment_offset = \
                      clib_host_to_net_u16((clib_net_to_host_u16(pkt->flags_and_fragment_offset) & 0xbfff) | (value << 14)), 0) : \
\
  (field == MMB_FIELD_IP_MF) ? \
    (value == -1) ? ((clib_net_to_host_u16(pkt->flags_and_fragment_offset) >> 13) & 0x1) : \
                    (pkt->flags_and_fragment_offset = \
                      clib_host_to_net_u16((clib_net_to_host_u16(pkt->flags_and_fragment_offset) & 0xdfff) | (value << 13)), 0) : \
\
  (field == MMB_FIELD_IP_FRAG_OFFSET) ? \
    (value == -1) ? (clib_net_to_host_u16(pkt->flags_and_fragment_offset) & 0x1fff) : \
                    (pkt->flags_and_fragment_offset = \
                      clib_host_to_net_u16((clib_net_to_host_u16(pkt->flags_and_fragment_offset) & 0xe000) | value), 0) : \
\
  (field == MMB_FIELD_IP_TTL) ? \
    (value == -1) ? pkt->ttl : (pkt->ttl = value, 0) : \
\
  (field == MMB_FIELD_IP_PROTO) ? \
    (value == -1) ? pkt->protocol : (pkt->protocol = value, 0) : \
\
  (field == MMB_FIELD_IP_CHECKSUM) ? \
    (value == -1) ? clib_net_to_host_u16(pkt->checksum) : (pkt->checksum = clib_host_to_net_u16(value), 0) : \
\
  (field == MMB_FIELD_IP_SADDR) ? \
    (value == -1) ? clib_net_to_host_u32(pkt->src_address.as_u32) : (pkt->src_address.as_u32 = clib_host_to_net_u32(value), 0) : \
\
  (field == MMB_FIELD_IP_DADDR) ? \
    (value == -1) ? clib_net_to_host_u32(pkt->dst_address.as_u32) : (pkt->dst_address.as_u32 = clib_host_to_net_u32(value), 0) : \
\
  -1

#define SET_ICMP_FIELD(pkt, field, value) \
\
  (field == MMB_FIELD_ICMP_TYPE) ? \
    (value == -1) ? pkt->type : (pkt->type = value, 0) : \
\
  (field == MMB_FIELD_ICMP_CODE) ? \
    (value == -1) ? pkt->code : (pkt->code = value, 0) : \
\
  (field == MMB_FIELD_ICMP_CHECKSUM) ? \
    (value == -1) ? clib_net_to_host_u16(pkt->checksum) : (pkt->checksum = clib_host_to_net_u16(value), 0) : \
\
/*TODO: MMB_FIELD_ICMP_PAYLOAD */\
\
  -1

#define SET_UDP_FIELD(pkt, field, value) \
\
  (field == MMB_FIELD_UDP_SPORT) ? \
    (value == -1) ? clib_net_to_host_u16(pkt->src_port) : (pkt->src_port = clib_host_to_net_u16(value), 0) : \
\
  (field == MMB_FIELD_UDP_DPORT) ? \
    (value == -1) ? clib_net_to_host_u16(pkt->dst_port) : (pkt->dst_port = clib_host_to_net_u16(value), 0) : \
\
  (field == MMB_FIELD_UDP_LEN) ? \
    (value == -1) ? clib_net_to_host_u16(pkt->length) : (pkt->length = clib_host_to_net_u16(value), 0) : \
\
  (field == MMB_FIELD_UDP_CHECKSUM) ? \
    (value == -1) ? clib_net_to_host_u16(pkt->checksum) : (pkt->checksum = clib_host_to_net_u16(value), 0) : \
\
/*TODO: MMB_FIELD_UDP_PAYLOAD */\
\
  -1

#define SET_TCP_FIELD(pkt, field, value) \
\
  (field == MMB_FIELD_TCP_SPORT) ? \
    (value == -1) ? clib_net_to_host_u16(pkt->src_port) : (pkt->src_port = clib_host_to_net_u16(value), 0) : \
\
  (field == MMB_FIELD_TCP_DPORT) ? \
    (value == -1) ? clib_net_to_host_u16(pkt->dst_port) : (pkt->dst_port = clib_host_to_net_u16(value), 0) : \
\
  (field == MMB_FIELD_TCP_SEQ_NUM) ? \
    (value == -1) ? clib_net_to_host_u32(pkt->seq_number) : (pkt->seq_number = clib_host_to_net_u32(value), 0) : \
\
  (field == MMB_FIELD_TCP_ACK_NUM) ? \
    (value == -1) ? clib_net_to_host_u32(pkt->ack_number) : (pkt->ack_number = clib_host_to_net_u32(value), 0) : \
\
  (field == MMB_FIELD_TCP_OFFSET) ? \
    (value == -1) ? (pkt->data_offset_and_reserved >> 4) : \
                      (pkt->data_offset_and_reserved = (pkt->data_offset_and_reserved & 0xf) | (value << 4), 0) : \
\
  (field == MMB_FIELD_TCP_RESERVED) ? \
    (value == -1) ? (pkt->data_offset_and_reserved & 0xf) : \
                      (pkt->data_offset_and_reserved = (pkt->data_offset_and_reserved & 0xf0) | value, 0) : \
\
  (field == MMB_FIELD_TCP_FLAGS) ? \
    (value == -1) ? pkt->flags : (pkt->flags = value, 0) : \
\
  (field == MMB_FIELD_TCP_CWR) ? \
    (value == -1) ? (pkt->flags >> 7) : (pkt->flags = (pkt->flags & 0x7f) | (value << 7), 0) : \
\
  (field == MMB_FIELD_TCP_ECE) ? \
    (value == -1) ? ((pkt->flags >> 6) & 0x1) : (pkt->flags = (pkt->flags & 0xbf) | (value << 6), 0) : \
\
  (field == MMB_FIELD_TCP_URG) ? \
    (value == -1) ? ((pkt->flags >> 5) & 0x1) : (pkt->flags = (pkt->flags & 0xdf) | (value << 5), 0) : \
\
  (field == MMB_FIELD_TCP_ACK) ? \
    (value == -1) ? ((pkt->flags >> 4) & 0x1) : (pkt->flags = (pkt->flags & 0xef) | (value << 4), 0) : \
\
  (field == MMB_FIELD_TCP_PUSH) ? \
    (value == -1) ? ((pkt->flags >> 3) & 0x1) : (pkt->flags = (pkt->flags & 0xf7) | (value << 3), 0) : \
\
  (field == MMB_FIELD_TCP_RST) ? \
    (value == -1) ? ((pkt->flags >> 2) & 0x1) : (pkt->flags = (pkt->flags & 0xfb) | (value << 2), 0) : \
\
  (field == MMB_FIELD_TCP_SYN) ? \
    (value == -1) ? ((pkt->flags >> 1) & 0x1) : (pkt->flags = (pkt->flags & 0xfd) | (value << 1), 0) : \
\
  (field == MMB_FIELD_TCP_FIN) ? \
    (value == -1) ? (pkt->flags & 0x1) : (pkt->flags = (pkt->flags & 0xfe) | value, 0) : \
\
  (field == MMB_FIELD_TCP_WINDOW) ? \
    (value == -1) ? clib_net_to_host_u16(pkt->window) : (pkt->window = clib_host_to_net_u16(value), 0) : \
\
  (field == MMB_FIELD_TCP_CHECKSUM) ? \
    (value == -1) ? clib_net_to_host_u16(pkt->checksum) : (pkt->checksum = clib_host_to_net_u16(value), 0) : \
\
  (field == MMB_FIELD_TCP_URG_PTR) ? \
    (value == -1) ? clib_net_to_host_u16(pkt->urgent_pointer) : (pkt->urgent_pointer = clib_host_to_net_u16(value), 0) : \
\
/*TODO: MMB_FIELD_TCP_PAYLOAD */\
/*TODO: TCP options */\
\
  -1

#define GET_IP_FIELD(pkt, field) SET_IP_FIELD(pkt, field, -1)
#define GET_ICMP_FIELD(pkt, field) SET_ICMP_FIELD(pkt, field, -1)
#define GET_UDP_FIELD(pkt, field) SET_UDP_FIELD(pkt, field, -1)
#define GET_TCP_FIELD(pkt, field) SET_TCP_FIELD(pkt, field, -1)

#endif /* __included_mmb_node_h__ */
