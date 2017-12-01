#ifndef __included_mmb_node_h__
#define __included_mmb_node_h__

#include <mmb/mmb.h>

#define foreach_mmb_next_node \
  _(FORWARD, "Forward")       \
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
  MMB_N_ERROR
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
  ip4_header_t *iph;
} mmb_trace_t;

typedef struct {
  u8 is_stripped:1;
  u8 offset;
  u8 data_length;
  u8 *new_value;
} mmb_tcp_option_t;

typedef struct {
  uword *found; // bitmap 255 bits (options 0-254)
  u8 *idx; // parsed vector's position of an option
  mmb_tcp_option_t *parsed; // parsed options vector (in parsing order)
  u8 *data;
} mmb_tcp_options_t;

#endif /* __included_mmb_node_h__ */
