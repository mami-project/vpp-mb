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
  _(FORWARD, "Forward")    

/*  \
  _(SLOW_PATH, "Slow Path")*/

#define foreach_mmb_error \
_(DONE, "MMB packets processed")

typedef enum {
#define _(sym,str) MMB_ERROR_##sym,
  foreach_mmb_error
#undef _
  MMB_N_ERROR,
} mmb_error_t;


typedef struct {
  u32 rule_index;
  u8  proto;
  ip4_address_t src_address;
  ip4_address_t dst_address;
  u32 sw_if_index;
  u32 next;

  ip4_header_t *ip;
} mmb_trace_t;

typedef enum {
#define _(sym,str) MMB_NEXT_##sym,
  foreach_mmb_next_node
#undef _
  MMB_N_NEXT,
} mmb_next_t;

static char * mmb_error_strings[] = {
#define _(sym,string) string,
  foreach_mmb_error
#undef _
};

static_always_inline u8* mmb_format_next_node(u8* s, va_list *args)
{
  u8 keyword = va_arg(*args, u32);
  char *keyword_str = "";
  switch(keyword)
  {
#define _(n,string) case MMB_NEXT_##n: { keyword_str = string; break; }
    foreach_mmb_next_node
#undef _
    case MMB_N_NEXT:
      keyword_str = "n-next";
      break;
    default:
       break;
  }

  return format(s, "%s", keyword_str);
}

static_always_inline void 
mmb_trace_ip_packet(vlib_main_t * vm, vlib_buffer_t *b, vlib_node_runtime_t * node,
                    ip4_header_t *ip, u32 next, u32 sw_if_index) {
   mmb_trace_t *t = vlib_add_trace (vm, node, b, sizeof (*t));
   t->proto = ip->protocol;
   t->src_address.as_u32 = ip->src_address.as_u32;
   t->dst_address.as_u32 = ip->dst_address.as_u32;
   t->next = next;
   t->sw_if_index = sw_if_index;
   t->ip=ip;
   t->rule_index = vnet_buffer(b)->l2_classify.opaque_index;
}

/* packet trace format function */
static u8 * format_mmb_trace(u8 * s, va_list * args)
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
                   format_ip_protocol, t->proto,
                   mmb_format_next_node, t->next);

   s = format(s, "  mmb: %U", 
                   format_ip4_header, t->ip, t->ip->length);
  return s;
}

static_always_inline u32 get_sw_if_index(vlib_buffer_t *b) {
  return vnet_buffer(b)->sw_if_index[VLIB_RX];
}

static_always_inline void *get_ip_header(vlib_buffer_t *b) {
  u8 *p = vlib_buffer_get_current(b);
  p += ethernet_buffer_header_size(b);
  return p;
}

static uword
mmb_node_fn(vlib_main_t *vm, vlib_node_runtime_t *node,
            vlib_frame_t *frame, int is_ip6,
            vlib_node_registration_t *mmb_node) {
  mmb_main_t *mm = &mmb_main;
  mmb_rule_t *rules = mm->rules;

  u32 n_left_from, *from, *to_next;
  mmb_next_t next_index;
  u32 pkts_done = 0;

  from = vlib_frame_vector_args(frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  u32 sw_if_index = get_sw_if_index(vlib_get_buffer(vm, from[0]));

  while (n_left_from > 0) { // Outter loop

    u32 n_left_to_next;

    vlib_get_next_frame (vm, node, next_index,
			 to_next, n_left_to_next);

    while (n_left_from > 0 && n_left_to_next > 0) {// Loop 1 packet
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

      /* get vlib buffer */
      b0 = vlib_get_buffer (vm, bi0);
      ip0 = get_ip_header(b0);

      u32 i, applied_rule_index = ~0;
      //vnet_buffer(b)->l2_classify.opaque_index;

      /* example: modify TTL and update checksum */
      //ip0->ttl -= pkts_count+1;
      //ip0->checksum = ip4_header_checksum(ip0);

      /*
        Idea of matching/action algorithm

        - for each rule
           - for each match in this rule
              - MATCH: process each target in this rule
              - NO MATCH: go to next rule
      uword index_rule = 0;

      vec_foreach_index(index_rule, rules)
      {
        mmb_rule_t *rule = &rules[index_rule];
        uword index_match = 0;

        vec_foreach_index(index_match, rule->matches)
        {
          mmb_match_t *match = &rule->matches[index_match];

          // case: ip-proto == 1 (icmp) and current packet matches
          if (match->field == MMB_FIELD_IP4_PROTO && match->condition == MMB_COND_EQ 
              //&& !strcmp(match->value, "0000000000000001") 
                && ip0->protocol == IP_PROTOCOL_ICMP)
          {
            uword index_target = 0;
            vec_foreach_index(index_target, rule->targets)
            {
              mmb_target_t *target = &rule->targets[index_target];

              // case: DROP
              if (target->keyword == MMB_TARGET_DROP)
                next0 = MMB_NEXT_DROP;
            }
          }
        }
      }
      // apply rules on TCP and UDP packets only 
      switch(ip0->protocol)
      {
        case IP_PROTOCOL_TCP: ;
          tcp_header_t *tcp = ip4_next_header(ip0);
          //Example: DROP all TCP packets
          next0 = MMB_NEXT_DROP;
          break;

        case IP_PROTOCOL_UDP: ;
          udp_header_t *udp = ip4_next_header(ip0);
          break;

        default: ;
      }*/

      pkts_done += 1;

      if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE) 
                        && (b0->flags & VLIB_BUFFER_IS_TRACED)))
      {
        mmb_trace_ip_packet(vm, b0, node, ip0, next0, sw_if_index);
      }

      /* verify speculative enqueue, maybe switch current next frame */
      vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
				       to_next, n_left_to_next,
				       bi0, next0);
    } // End of loop 1 packet

    vlib_put_next_frame (vm, node, next_index, n_left_to_next);
  } // End outter loop

  vlib_node_increment_counter (vm, mmb_node->index, 
                               MMB_ERROR_DONE, pkts_done);
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
    [MMB_NEXT_FORWARD]   = "ip4-lookup",
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
    [MMB_NEXT_FORWARD]   = "ip6-lookup",
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
