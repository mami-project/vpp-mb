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
#include <vnet/classify/vnet_classify.h>
#include <mmb/mmb.h>

#define foreach_mmb_next_node \
  _(FORWARD, "Forward")     /*\
  _(SLOW_PATH, "Slow Path")*/

typedef enum {
#define _(sym,str) MMB_NEXT_##sym,
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
  u8 is_stripped:1; // flag to tell if this option has been stripped
  u8 offset;        // real offset in the pkt data
  u8 data_length;   // length of data
  u8 *new_value;    // new value if modified
} mmb_tcp_option_t;

typedef struct {
  uword *found;             // bitmap 255 bits (options 0-254)
  u8 *idx;                  // parsed vector's position of an option
  mmb_tcp_option_t *parsed; // parsed options vector (in parsing order)
  u8 *data;                 // pointer to the pkt data
} mmb_tcp_options_t;

static u8 mmb_parse_tcp_options(tcp_header_t *, mmb_tcp_options_t *);
static u8 mmb_rewrite_tcp_options(mmb_tcp_options_t *);
static void target_tcp_options(ip4_header_t *, mmb_rule_t *, mmb_tcp_options_t *);

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
                    ip4_header_t *iph, u32 next, u32 sw_if_index)
{
   mmb_trace_t *t = vlib_add_trace (vm, node, b, sizeof (*t));

   t->proto = iph->protocol;
   t->rule_index = vnet_buffer(b)->l2_classify.opaque_index;
   t->src_address.as_u32 = iph->src_address.as_u32;
   t->dst_address.as_u32 = iph->dst_address.as_u32;
   t->next = next;
   t->sw_if_index = sw_if_index;
   t->iph = iph;
}

/* packet trace format function */
static u8 * format_mmb_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  mmb_trace_t * t = va_arg (*args, mmb_trace_t *);
  mmb_main_t mm = mmb_main;

  if (t->rule_index != ~0) 
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
 *  Utility functions
 ***********************/

static_always_inline u8 mmb_memcpy(u8 *dst, u8 *from, u8 length)
{
  clib_memcpy(dst, from, length);
  return length;
}

static_always_inline u32 get_sw_if_index(vlib_buffer_t *b) {
  return vnet_buffer(b)->sw_if_index[VLIB_RX];
}

static_always_inline void *get_ip_header(vlib_buffer_t *b) {
  u8 *p = vlib_buffer_get_current(b);
  p += ethernet_buffer_header_size(b);
  return p;
}

/************************
 *      TCP options
 ***********************/

static_always_inline void init_tcp_options(mmb_tcp_options_t *options)
{
  memset(options, 0, sizeof(mmb_tcp_options_t));
  vec_validate(options->idx, 254);
  clib_bitmap_alloc(options->found, 255);
}

static_always_inline void free_tcp_options(mmb_tcp_options_t *options)
{
  vec_free(options->idx);
  vec_free(options->parsed);
  clib_bitmap_free(options->found);
}

static_always_inline u8 tcp_option_exists(mmb_tcp_options_t *options, u8 kind)
{
  return clib_bitmap_get_no_check(options->found, kind);
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

static_always_inline u8 mmb_padding_tcp_options(u8 *data, u8 offset)
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

/**********************************************
 *   Rewrite TCP options (TARGETS) functions
 *********************************************/

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

void target_tcp_options(ip4_header_t *iph, mmb_rule_t *rule, mmb_tcp_options_t *tcp_options)
{
  u32 i;
  u8 old_opts_len = 0, new_opts_len = 0, opts_modified = 0;

  /* STRIP tcp options, if any */
  if (rule->has_strips)
  {
    uword *found_to_strip = clib_bitmap_dup_and(tcp_options->found, rule->opt_strips);
    if (!clib_bitmap_is_zero(found_to_strip))
    {
      clib_bitmap_foreach(i, found_to_strip, mmb_target_strip_option(tcp_options, i));
      opts_modified = 1;
    }
  }

  /* MODIFY tcp options, if any */
  vec_foreach_index(i, rule->opt_mods)
  {
    mmb_target_t *opt_modified = rule->opt_mods+i;
    opts_modified |= mmb_target_modify_option(tcp_options, opt_modified->opt_kind, opt_modified->value);
  }

  /* Rewrite tcp options, if needed */
  tcp_header_t *tcph = ip4_next_header(iph);
  old_opts_len = (tcp_doff(tcph) << 2) - sizeof(tcp_header_t);
  if (opts_modified)
  {
    new_opts_len = mmb_rewrite_tcp_options(tcp_options);
  }
  else
  {
    new_opts_len = old_opts_len;
  }

  /* ADD tcp options, if any */
  vec_foreach_index(i, rule->opt_adds)
  {
    mmb_transport_option_t *opt_added = rule->opt_adds+i;
    new_opts_len += mmb_target_add_option(&tcp_options->data[new_opts_len], opt_added);
    opts_modified = 1;
  }

  /* Pad tcp options, if needed */
  if (opts_modified)
  {
    new_opts_len = mmb_padding_tcp_options((u8 *)(tcph + 1), new_opts_len);

    /* can't overflow 40 bytes otherwise data_offset becomes crap */
    if (new_opts_len > 40)
      new_opts_len = 40;
    
    tcph->data_offset_and_reserved = (tcph->data_offset_and_reserved & 0xf) | (((new_opts_len + sizeof(tcp_header_t)) >> 2) << 4);

    //TODO take care of fragmentation if any
    //u16 pkt_ip_length = get_ip_field(iph, MMB_FIELD_IP4_LEN);
    //set_ip_field(iph, MMB_FIELD_IP4_LEN, pkt_ip_length+new_opts_len-old_opts_len);
  }
}

/************************
 *  Node entry function
 ***********************/

static uword
mmb_node_fn(vlib_main_t *vm, vlib_node_runtime_t *node,
            vlib_frame_t *frame, int is_ip6,
            vlib_node_registration_t *mmb_node)
{
  mmb_main_t *mm = &mmb_main;
  mmb_rule_t *rules = mm->rules;

  u32 n_left_from, *from, *to_next;
  mmb_next_t next_index;
  u32 pkts_done = 0;

  mmb_tcp_options_t tcp_options;
  init_tcp_options(&tcp_options);

  from = vlib_frame_vector_args(frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  u32 sw_if_index = get_sw_if_index(vlib_get_buffer(vm, from[0]));

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
      ip0 = get_ip_header(b0);

      /* If packet matched */
      u32 rule_index = vnet_buffer(b0)->l2_classify.opaque_index;
      if (rule_index != ~0 /*TODO remove when only tcp (with options) packets are coming here*/ && ip0->protocol == IP_PROTOCOL_TCP)
      {
        mmb_rule_t *rule = rules+rule_index;
        if (rule->opts_in_targets)//TODO should (normally) be removed when only packets with targets-containing-tcp-options are coming here
        {
          mmb_parse_tcp_options(ip4_next_header(ip0), &tcp_options);
          target_tcp_options(ip0, rule, &tcp_options);
        }

        rule->match_count++;
      }

      /* one more packet processed */
      pkts_done++;

      /* node trace (if enabled) */
      if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE) 
                        && (b0->flags & VLIB_BUFFER_IS_TRACED)))
      {
        mmb_trace_ip_packet(vm, b0, node, ip0, next0, sw_if_index);
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
  
  free_tcp_options(&tcp_options);

  return frame->n_vectors;
}

vlib_node_registration_t ip4_mmb_rewrite_node;
static uword
mmb_node_ip4_rewrite_fn(vlib_main_t *vm, vlib_node_runtime_t *node, 
                    vlib_frame_t *frame) {
  return mmb_node_fn(vm, node, frame, 0, &ip4_mmb_rewrite_node);
}

vlib_node_registration_t ip6_mmb_rewrite_node;
static uword
mmb_node_ip6_rewrite_fn(vlib_main_t *vm, vlib_node_runtime_t *node, 
                    vlib_frame_t *frame) {
  return mmb_node_fn(vm, node, frame, 1, &ip6_mmb_rewrite_node);
}

VLIB_REGISTER_NODE(ip4_mmb_rewrite_node) =
{
  .function = mmb_node_ip4_rewrite_fn,
  .name = "ip4-mmb-rewrite",
  .vector_size = sizeof (u32),
  .format_trace = format_mmb_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(mmb_error_strings),
  .error_strings = mmb_error_strings,

  .n_next_nodes = MMB_N_NEXT,
  .next_nodes = {
    [MMB_NEXT_FORWARD] = "ip4-lookup"
  }
};

VLIB_NODE_FUNCTION_MULTIARCH(ip4_mmb_rewrite_node, mmb_node_ip4_rewrite_fn);

VNET_FEATURE_INIT (ip4_mmb_rewrite_feature, static) = {
  .arc_name = "ip4-unicast",
  .node_name = "ip4-mmb-rewrite",
  .runs_before = VNET_FEATURES("ip4-lookup"),
};

VLIB_REGISTER_NODE(ip6_mmb_rewrite_node) =
{
  .function = mmb_node_ip6_rewrite_fn,
  .name = "ip6-mmb-rewrite",
  .vector_size = sizeof(u32),
  .format_trace = format_mmb_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(mmb_error_strings),
  .error_strings = mmb_error_strings,

  .n_next_nodes = MMB_N_NEXT,
  .next_nodes = {
    [MMB_NEXT_FORWARD] = "ip6-lookup"
  }
};

VLIB_NODE_FUNCTION_MULTIARCH(ip6_mmb_rewrite_node, mmb_node_ip6_rewrite_fn);

VNET_FEATURE_INIT (ip6_mmb_rewrite_feature, static) = {
  .arc_name = "ip6-unicast",
  .node_name = "ip6-mmb-rewrite",
  .runs_before = VNET_FEATURES("ip6-lookup"), 
};

static clib_error_t *
mmb_rewrite_init (vlib_main_t *vm)
{
  mmb_main.feature_arc_index = vlib_node_add_next(vm, ip4_mmb_rewrite_node.index, ip4_rewrite_node.index);
  return 0;
}

VLIB_INIT_FUNCTION(mmb_rewrite_init);

