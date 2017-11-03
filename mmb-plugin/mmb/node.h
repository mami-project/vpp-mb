#ifndef __included_mmb_node_h__
#define __included_mmb_node_h__

#include <mmb/mmb.h>

//TODO: maybe we also need to handle endianness by doing the opposite of clib_net_to_host_u16 (32,64) in setters ?

#define IP_FIELD_SET(pkt, field, value) \
\
  ((field) == MMB_FIELD_IP_VER) ? \
    ((value) == -1) ? ((pkt)->ip_version_and_header_length >> 4) : \
                      ((pkt)->ip_version_and_header_length = ((pkt)->ip_version_and_header_length & 0xf) | ((value) << 4), 0) : \
\
  ((field) == MMB_FIELD_IP_IHL) ? \
    ((value) == -1) ? ((pkt)->ip_version_and_header_length & 0xf) : \
                      ((pkt)->ip_version_and_header_length = ((pkt)->ip_version_and_header_length & 0xf0) | (value), 0) : \
\
  ((field) == MMB_FIELD_IP_DSCP) ? \
    ((value) == -1) ? ((pkt)->tos >> 2) : ((pkt)->tos = ((pkt)->tos & 0x3) | ((value) << 2), 0) : \
\
  ((field) == MMB_FIELD_IP_ECN) ? \
    ((value) == -1) ? ((pkt)->tos & 0x3) : ((pkt)->tos = ((pkt)->tos & 0xfc) | (value), 0) : \
\
  ((field) == MMB_FIELD_IP_LEN) ? \
    ((value) == -1) ? clib_net_to_host_u16((pkt)->length) : ((pkt)->length = value, 0) : \
\
  ((field) == MMB_FIELD_IP_ID) ? \
    ((value) == -1) ? clib_net_to_host_u16((pkt)->fragment_id) : ((pkt)->fragment_id = value, 0) : \
\
  ((field) == MMB_FIELD_IP_TTL) ? \
    ((value) == -1) ? (pkt)->ttl : ((pkt)->ttl = value, 0) : \
\
  ((field) == MMB_FIELD_IP_PROTO) ? \
    ((value) == -1) ? (pkt)->protocol : ((pkt)->protocol = value, 0) : \
\
  ((field) == MMB_FIELD_IP_CHECKSUM) ? \
    ((value) == -1) ? clib_net_to_host_u16((pkt)->checksum) : \
                      ((pkt)->checksum = value, 0) : \
\
  -1

#define IP_FIELD_GET(pkt, field) IP_FIELD_SET((pkt), (field), -1)


#endif /* __included_mmb_node_h__ */
