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
#include <mmb/mmb.h>

typedef struct {
  u8  proto;
  u32 next;
} mmb_trace_t;

typedef enum {
  MMB_NEXT_LOOKUP,
  MMB_NEXT_DROP,
  MMB_N_NEXT,
} mmb_next_t;

vlib_node_registration_t mmb_node;

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

/* packet trace format function */
static u8 * format_mmb_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  mmb_trace_t * t = va_arg (*args, mmb_trace_t *);
  
  s = format (s, "MMB: packet with action %d (%s) / protocol %d (%s)\n",
              t->next, t->next == MMB_NEXT_DROP ? "DROP" : "LOOKUP", t->proto, 
              ((t->proto == IP_PROTOCOL_TCP) ? "TCP" : ((t->proto == IP_PROTOCOL_UDP) ? "UDP" : ((t->proto == IP_PROTOCOL_ICMP) ? "ICMP" : "OTHER"))));

  return s;
}

static uword
mmb_node_fn (vlib_main_t * vm,
		  vlib_node_runtime_t * node,
		  vlib_frame_t * frame)
{
  mmb_main_t *mm = &mmb_main;
  mmb_rule_t *rules = mm->rules;

  u32 n_left_from, * from, * to_next;
  mmb_next_t next_index;
  u32 pkts_done = 0;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
  {
    u32 n_left_to_next;

    vlib_get_next_frame (vm, node, next_index,
			 to_next, n_left_to_next);

    while (n_left_from >= 4 && n_left_to_next >= 2)
    {
      u32 next0 = MMB_NEXT_LOOKUP;
      u32 next1 = MMB_NEXT_LOOKUP;
      ip4_header_t *ip0, *ip1;
      u32 bi0, bi1;
      vlib_buffer_t * b0, * b1;
          
      /* Prefetch next iteration. */
      {
        vlib_buffer_t * p2, * p3;
            
        p2 = vlib_get_buffer (vm, from[2]);
        p3 = vlib_get_buffer (vm, from[3]);
            
        vlib_prefetch_buffer_header (p2, LOAD);
        vlib_prefetch_buffer_header (p3, LOAD);

        CLIB_PREFETCH (p2->data, CLIB_CACHE_LINE_BYTES, STORE);
        CLIB_PREFETCH (p3->data, CLIB_CACHE_LINE_BYTES, STORE);
      }

      /* speculatively enqueue b0 and b1 to the current next frame */
      to_next[0] = bi0 = from[0];
      to_next[1] = bi1 = from[1];
      from += 2;
      to_next += 2;
      n_left_from -= 2;
      n_left_to_next -= 2;

      b0 = vlib_get_buffer (vm, bi0);
      b1 = vlib_get_buffer (vm, bi1);
      
      ip0 = vlib_buffer_get_current (b0);
      ip1 = vlib_buffer_get_current (b1);

      pkts_done += 2;

      if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE)))
      {
        if (b0->flags & VLIB_BUFFER_IS_TRACED) 
        {
          mmb_trace_t *t = vlib_add_trace (vm, node, b0, sizeof (*t));
          t->proto = ip0->protocol;
          t->next = next0;
        }

        if (b1->flags & VLIB_BUFFER_IS_TRACED) 
        {
          mmb_trace_t *t = vlib_add_trace (vm, node, b1, sizeof (*t));
          t->proto = ip1->protocol;
          t->next = next1;
        }
      }
            
      /* verify speculative enqueues, maybe switch current next frame */
      vlib_validate_buffer_enqueue_x2 (vm, node, next_index,
                                       to_next, n_left_to_next,
                                       bi0, bi1, next0, next1);
    }

    while (n_left_from > 0 && n_left_to_next > 0)
    {
      u32 bi0;
      vlib_buffer_t * b0;
      u32 next0 = MMB_NEXT_LOOKUP;
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
      
      /* get IP header */
      ip0 = vlib_buffer_get_current (b0);

      /* example: modify TTL and update checksum */
      //ip0->ttl -= pkts_count+1;
      //ip0->checksum = ip4_header_checksum(ip0);

      /*
        Idea of matching/action algorithm

        - for each rule
           - for each match in this rule
              - MATCH: process each target in this rule
              - NO MATCH: go to next rule
      */
      uword index_rule = 0;
      vec_foreach_index(index_rule, rules)
      {
        mmb_rule_t *rule = &rules[index_rule];
        uword index_match = 0;

        vec_foreach_index(index_match, rule->matches)
        {
          mmb_match_t *match = &rule->matches[index_match];

          // case: ip-proto == 1 (icmp) and current packet matches
          if (match->field == MMB_FIELD_IP_PROTO && match->condition == MMB_COND_EQ 
              /*&& !strcmp(match->value, "0000000000000001")*/ && ip0->protocol == IP_PROTOCOL_ICMP)
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

      /* apply rules on TCP and UDP packets only */
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
      }

      pkts_done += 1;

      if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE) 
                        && (b0->flags & VLIB_BUFFER_IS_TRACED)))
      {
        mmb_trace_t *t = vlib_add_trace (vm, node, b0, sizeof (*t));
        t->proto = ip0->protocol;
        t->next = next0;
      }

      /* verify speculative enqueue, maybe switch current next frame */
      vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
				       to_next, n_left_to_next,
				       bi0, next0);
    }

    vlib_put_next_frame (vm, node, next_index, n_left_to_next);
  }

  vlib_node_increment_counter (vm, mmb_node.index, 
                               MMB_ERROR_DONE, pkts_done);
  return frame->n_vectors;
}

VLIB_REGISTER_NODE (mmb_node) = {
  .function = mmb_node_fn,
  .name = "mmb",
  .vector_size = sizeof (u32),
  .format_trace = format_mmb_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  
  .n_errors = ARRAY_LEN(mmb_error_strings),
  .error_strings = mmb_error_strings,

  .n_next_nodes = MMB_N_NEXT,

  /* edit / add dispositions here */
  //TODO: we may need to change next nodes defined below
  .next_nodes = {
        [MMB_NEXT_LOOKUP] = "ip4-lookup",
        [MMB_NEXT_DROP]   = "error-drop", //ip4-drop
  },
};

VLIB_NODE_FUNCTION_MULTIARCH(mmb_node, mmb_node_fn);

