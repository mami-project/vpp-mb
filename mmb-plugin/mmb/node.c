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

typedef struct {
  u8  proto;
  u32 next;
} mmb_trace_t;

typedef enum {
  MMB_NEXT_LOOKUP,
  MMB_NEXT_DROP,
  MMB_N_NEXT
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

u8 value_compare(u64 a, u64 b, u8 condition)
{
  //TODO: remove (debug)
  FILE *f = fopen("/home/vagrant/cmp.txt", "a");
  if (f != NULL)
  {
    fprintf(f, "compare %lu (%lx) with %lu (%lx)\n", a, a, b, b);
    fclose(f);
  }
  //

  switch(condition)
  {
    case MMB_COND_EQ:
      return a == b;

    case MMB_COND_NEQ:
      return a != b;

    case MMB_COND_LEQ:
      return a <= b;

    case MMB_COND_GEQ:
      return a >= b;

    case MMB_COND_LT:
      return a < b;

    case MMB_COND_GT:
      return a > b;

    default:
      break;
  }

  return 0;
}

u64 bytes_to_u64(u8 *bytes)
{
  u64 value = 0;
  u32 i = 0;
  u32 len = vec_len(bytes) - 1;

  vec_foreach_index(i, bytes)
    value += (bytes[i] << ((len - i) * 8));

  return value;
}

u8 check_ip_condition(ip4_header_t *ip, mmb_match_t *match)
{
  // (u8)  ip_version_and_header_length:  "ip-ver" (4 bits) ; "ip-ihl" (4 bits)
  // (u8)  tos:                           "ip-dscp" (6 bits) ; "ip-ecn" (2 bits) contains "ip-non-ect", "ip-ect0", "ip-ect1" and "ip-ce"
  // (u16) length:                        "ip-len"
  // (u16) fragment_id:                   "ip-id"
  //TODO (u16) flags_and_fragment_offset:     "ip-flags" (3 bits) contains "ip-res", "ip-df" and "ip-mf" ; "ip-frag-offset" (13 bits)
  // (u8)  ttl:                           "ip-ttl"
  // (u8)  protocol:                      "ip-proto"
  // (u16) checksum:                      "ip-checksum"
  //TODO union address: "ip-saddr", "ip-daddr"

  //MMB_FIELD_IP_FLAGS
  //MMB_FIELD_IP_FRAG_OFFSET

  switch(match->field)
  {
    /*
     * read field's value in the packet and compare it to user's (rule) value
     */

#define MMB_FIELD_IP_FLAGS       121
#define MMB_FIELD_IP_RES         122
#define MMB_FIELD_IP_DF          123
#define MMB_FIELD_IP_MF          124
#define MMB_FIELD_IP_FRAG_OFFSET 125
#define MMB_FIELD_IP_SADDR       129
#define MMB_FIELD_IP_DADDR       130

    case MMB_FIELD_IP_VER:
    case MMB_FIELD_IP_IHL:
    case MMB_FIELD_IP_DSCP:
    case MMB_FIELD_IP_ECN:
    case MMB_FIELD_IP_LEN:
    case MMB_FIELD_IP_ID:
    //etc...
    case MMB_FIELD_IP_TTL:
    case MMB_FIELD_IP_PROTO:
    case MMB_FIELD_IP_CHECKSUM:
      /* search for "ip-field" or "!ip-field" match */
      if (match->condition == 0)
      {
        /* "ip-field" is always found in an IP packet */
        if (match->reverse == 0)
          return 1;

        /* "!ip-field" is always false for an IP packet */
        return 0;
      }

      /* compare packet field and matching values */
      return value_compare(IP_FIELD_GET(ip, match->field), bytes_to_u64(match->value), match->condition);

    default:
      break;
  }

  return 0;
}

u8 check_icmp_condition(icmp46_header_t *icmp, mmb_match_t *match)
{
  //TODO
  return 0;
}

u8 check_udp_condition(udp_header_t *udp, mmb_match_t *match)
{
  //TODO
  return 0;
}

u8 check_tcp_condition(tcp_header_t *tcp, mmb_match_t *match)
{
  //TODO
  return 0;
}

u8 packet_matches(ip4_header_t *ip, mmb_match_t *matches, u16 l3, u8 l4)
{
  /* Don't apply rules concerning layer 3 other than IP4 */
  if (l3 != ETHERNET_TYPE_IP4)
    return 0;

  /* Don't touch packets with layer 4 different than ICMP,UDP,TCP */
  if (ip->protocol != IP_PROTOCOL_ICMP 
      && ip->protocol != IP_PROTOCOL_UDP 
      && ip->protocol != IP_PROTOCOL_TCP)
  {
    return 0;
  }

  /* Don't apply rules with a layer 4 different than the packet's one */
  /* Note: case l4 = IP_PROTOCOL_RESERVED when "all" or only "ip-fields" in matching */
  if (l4 != IP_PROTOCOL_RESERVED && ip->protocol != l4)
    return 0;

  /* Rule could be applied to packet, let's check all matching conditions */
  uword imatch = 0;
  vec_foreach_index(imatch, matches)
  {
    mmb_match_t *match = &matches[imatch];

    if (match->field == MMB_FIELD_ALL)
      continue;

    u16 field_protocol = get_field_protocol(match->field);
    switch(field_protocol)
    {
      /* IP field */
      case ETHERNET_TYPE_IP4:
        if (!check_ip_condition(ip, match))
          return 0;
        break;

      /* ICMP field */
      case IP_PROTOCOL_ICMP:
        /* If not an ICMP packet, don't match */
        if (ip->protocol != field_protocol)
          return 0;

        icmp46_header_t *icmp = ip4_next_header(ip);
        if (!check_icmp_condition(icmp, match))
          return 0;
        break;

      /* UDP field */
      case IP_PROTOCOL_UDP:
        /* If not an UDP packet, don't match */
        if (ip->protocol != field_protocol)
          return 0;

        udp_header_t *udp = ip4_next_header(ip);
        if (!check_udp_condition(udp, match))
          return 0;
        break;

      /* TCP field */
      case IP_PROTOCOL_TCP:
        /* If not a TCP packet, don't match */
        if (ip->protocol != field_protocol)
          return 0;

        tcp_header_t *tcp = ip4_next_header(ip);
        if (!check_tcp_condition(tcp, match))
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

u32 packet_apply_targets(ip4_header_t *ip, mmb_target_t *targets)
{
  uword itarget = 0;
  vec_foreach_index(itarget, targets)
  {
    mmb_target_t *target = &targets[itarget];

    switch(target->keyword)
    {
      case MMB_TARGET_DROP:
        return MMB_NEXT_DROP;

      case MMB_TARGET_STRIP:
        //TODO (+ recompute checksum ?)
        break;

      case MMB_TARGET_MODIFY:
        //TODO (+ recompute checksum ?)
        break;

      default:
        break;
    }
  }

  return MMB_NEXT_LOOKUP;
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

      /* fetch each rule to find a match */
      uword irule = 0;
      vec_foreach_index(irule, rules)
      {
        mmb_rule_t *rule = &rules[irule];

        if (packet_matches(ip0, rule->matches, rule->l3, rule->l4))
        {
          /* MATCH: apply targets to packet */
          next0 = packet_apply_targets(ip0, rule->targets);
          //TODO trace: add triggered rule id
          break;
        }
      }

      /* one more packet processed */
      pkts_done += 1;

      /* node trace (if enabled) */
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

