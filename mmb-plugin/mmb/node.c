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
  u32 pkt_id;
  u8  ttl;
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
  
  s = format (s, "MMB: packet %d, action %d (%s) - TTL = %d\n",
              t->pkt_id, t->next, t->next == MMB_NEXT_DROP ? "DROP" : "LOOKUP", t->ttl);

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
  static u32 pkts_count = 0;

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
      //ip4_header_t *ip0, *ip1;
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

      //TODO
      //ASSERT (b0->current_data == 0);
      //ASSERT (b1->current_data == 0);
      
      //TODO
      //ip0 = vlib_buffer_get_current (b0);
      //ip1 = vlib_buffer_get_current (b1);

      pkts_done += 2;
      pkts_count += 2;

      if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE)))
      {
        if (b0->flags & VLIB_BUFFER_IS_TRACED) 
        {
          //TODO trace for b0 packets
          mmb_trace_t *t = vlib_add_trace (vm, node, b0, sizeof (*t));
          t->pkt_id = pkts_count-1;
          t->next = MMB_NEXT_LOOKUP;
        }

        if (b1->flags & VLIB_BUFFER_IS_TRACED) 
        {
          //TODO trace for b1 packets
          mmb_trace_t *t = vlib_add_trace (vm, node, b1, sizeof (*t));
          t->pkt_id = pkts_count;
          t->next = MMB_NEXT_LOOKUP;
        }
      }

      //TODO try droping each time 1 pkts over 2
      next1 = MMB_NEXT_DROP;
            
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

      b0 = vlib_get_buffer (vm, bi0);
      /* 
       * Direct from the driver, we should be at offset 0
       * aka at &b0->data[0]
       */
      //TODO
      //ASSERT (b0->current_data == 0);
      
      //TODO
      ip0 = vlib_buffer_get_current (b0);
      ip0->ttl -= pkts_count+1;
      ip0->checksum = ip4_header_checksum(ip0);

      pkts_done += 1;
      pkts_count += 1;

      if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE) 
                        && (b0->flags & VLIB_BUFFER_IS_TRACED)))
      {
        //TODO trace
        mmb_trace_t *t = vlib_add_trace (vm, node, b0, sizeof (*t));
        t->pkt_id = pkts_count;
        t->ttl = ip0->ttl;
        t->next = (pkts_count%2 == 0) ? MMB_NEXT_DROP : MMB_NEXT_LOOKUP;
      }

      //TODO try droping each time 1 pkts over 2
      if (pkts_count%2 == 0)
        next0 = MMB_NEXT_DROP;

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

