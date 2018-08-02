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
 *
 *
 * Author: Korian Edeline
 */
#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/pg/pg.h>
#include <vppinfra/error.h>
#include <vppinfra/random.h>
#include <time.h>
#include <vnet/classify/vnet_classify.h>
#include <mmb/mmb.h>
#include <mmb/mmb_opts.h>

#define foreach_mmb_next_node \
  _(FORWARD, "Forward")     \
  _(LOOP, "Loop")         /*\
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

#define ip46_address_type(ip46) \
  (ip46_address_is_ip4(ip46) ? IP46_TYPE_IP4 : IP46_TYPE_IP6)

typedef struct {
  u32 *rule_indexes;
  u8 proto;
  ip46_address_t src_address;
  ip46_address_t dst_address;
  u32 sw_if_index;
  u32 next;
  union {
    ip4_header_t *ip4h;
    ip6_header_t *ip6h;
  };
} mmb_trace_t;

static u8 mmb_rewrite_tcp_options(vlib_buffer_t *, mmb_tcp_options_t *);
static void target_tcp_options(vlib_buffer_t *, u8 *, mmb_rule_t *, 
                               mmb_tcp_options_t *, u8, mmb_conn_t *conn, u32 dir);

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
                    u8 *p, u32 next, u32 sw_if_index, u8 is_ip6) {

  mmb_trace_t *t = vlib_add_trace (vm, node, b, sizeof (*t));

  t->next = next;
  t->sw_if_index = sw_if_index;
  t->rule_indexes = vec_dup((u32*)vnet_buffer(b)->l2_classify.hash);

  if (is_ip6) {
    ip6_header_t *iph = (ip6_header_t*)p;
    t->proto = iph->protocol;
    clib_memcpy(&t->src_address.ip6, &iph->src_address, sizeof(ip6_address_t));
    clib_memcpy(&t->dst_address.ip6, &iph->dst_address, sizeof(ip6_address_t));
    t->ip6h = iph;
  } else {
    ip4_header_t *iph = (ip4_header_t*)p;
    t->proto = iph->protocol;
    t->src_address.ip4.as_u32 = iph->src_address.as_u32;
    t->dst_address.ip4.as_u32 = iph->dst_address.as_u32;
    t->ip4h = iph;
  }
}

/* packet trace format function */
static u8 * format_mmb_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  mmb_trace_t * t = va_arg (*args, mmb_trace_t *);
  mmb_main_t mm = mmb_main;
  u32 *rule_index;

  vec_foreach(rule_index, t->rule_indexes) {
    s = format(s, "pkt matched rule %u, target %U\n  ",           
                  *rule_index,
                  mmb_format_next_node, t->next);
  }

  s = format(s, "mmb: if:%U sa:%U da:%U %U\n",
                format_vnet_sw_if_index_name, mm.vnet_main, t->sw_if_index,
                format_ip46_address, &t->src_address, ip46_address_type(&t->src_address),
                format_ip46_address, &t->dst_address, ip46_address_type(&t->dst_address),
                format_ip_protocol, t->proto);

  if (ip46_address_is_ip4(&t->src_address))
    s = format(s, "  mmb: %U", 
                  format_ip4_header, t->ip4h, sizeof(ip4_header_t));
  else
    s = format(s, "  mmb: %U",
                  format_ip6_header, t->ip6h, sizeof(ip6_header_t));

  return s;
}

/************************
 *  Utility functions
 ***********************/

static_always_inline u8 mmb_memmove(u8 *dst, u8 *from, u8 length)
{
  memmove(dst, from, length);
  return length;
}

static_always_inline u16 get_ip_protocol(u8 *p, u8 is_ip6)
{
  if (is_ip6)
    return ((ip6_header_t*)p)->protocol;

  return ((ip4_header_t*)p)->protocol;
}

/************************
 *      TCP options
 ***********************/

u8 mmb_rewrite_tcp_options(vlib_buffer_t *b, mmb_tcp_options_t *opts)
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
        offset += mmb_memmove(&data[offset], &data[opt->offset+shift], 2);
        offset += mmb_memmove(&data[offset], opt->new_value, new_data_length);
      }
      else if (old_data_length > new_data_length)
      {
        offset += mmb_memmove(&data[offset], &data[opt->offset+shift], 1);
        offset += mmb_memmove(&data[offset], &new_opt_len, 1);
        offset += mmb_memmove(&data[offset], opt->new_value, new_data_length);
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
            shift += (offset_after_modify - overlap_offset);
            //size_t len = b->current_length - (b->current_data + sizeof(ip4_header_t) + sizeof(tcp_header_t)) - shift;
            memmove(&data[offset_after_modify], &data[overlap_offset], /*len*/100); //TODO crash when using len
          }

          offset += mmb_memmove(&data[offset], &data[opt->offset], 1);
          offset += mmb_memmove(&data[offset], &new_opt_len, 1);
          offset += mmb_memmove(&data[offset], opt->new_value, new_data_length);
        }
        else
        {
          offset += mmb_memmove(&data[offset], &data[opt->offset+shift], 1);
          offset += mmb_memmove(&data[offset], &new_opt_len, 1);
          offset += mmb_memmove(&data[offset], opt->new_value, new_data_length);
        }
      }
    }
    else
    {
      /* NOT MODIFIED, rewrite */
      offset += mmb_memmove(&data[offset], &data[opt->offset+shift], opt->data_length+2);
    }
  }

  return offset;
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

static_always_inline u8 mmb_target_modify_option(mmb_tcp_options_t *tcp_options, 
                                                 u8 kind, u8 *new_value) {
  if (tcp_option_exists(tcp_options, kind)) {
    tcp_options->parsed[tcp_options->idx[kind]].new_value = new_value;
    return 1;
  }

  return 0;
}

static_always_inline void mmb_target_strip_option(mmb_tcp_options_t *tcp_options, 
                                                  u8 kind) {
  u8 idx = tcp_options->idx[kind];
  tcp_options->parsed[idx].is_stripped = 1;
}

void target_tcp_options(vlib_buffer_t *b, u8 *p, mmb_rule_t *rule, 
                        mmb_tcp_options_t *tcp_options, u8 is_ip6,
                        mmb_conn_t *conn, u32 dir) {

  u32 i;
  u8 old_opts_len = 0, new_opts_len = 0, opts_modified = 0;

  /* STRIP tcp options, if any */
  if (rule->has_strips) {
    uword *found_to_strip = clib_bitmap_dup_and(tcp_options->found, rule->opt_strips);
    if (!clib_bitmap_is_zero(found_to_strip)) {
      clib_bitmap_foreach(i, found_to_strip, mmb_target_strip_option(tcp_options, i));
      opts_modified = 1;
    }
  }

  /* MODIFY tcp options, if any */
  vec_foreach_index(i, rule->opt_mods) {
    mmb_target_t *opt_modified = rule->opt_mods+i;
    opts_modified |= mmb_target_modify_option(tcp_options, opt_modified->opt_kind, opt_modified->value);
  }

  /* Rewrite tcp options, if needed */
  tcp_header_t *tcph = is_ip6 ? ip6_next_header((ip6_header_t*)p) : ip4_next_header((ip4_header_t*)p);
  old_opts_len = (tcp_doff(tcph) << 2) - sizeof(tcp_header_t);
  if (opts_modified)
    new_opts_len = mmb_rewrite_tcp_options(b, tcp_options);
  else
    new_opts_len = old_opts_len;

  /* ADD tcp options, if any */
  vec_foreach_index(i, rule->opt_adds) {
    mmb_transport_option_t *opt_added = rule->opt_adds+i;
    new_opts_len += mmb_target_add_option(&tcp_options->data[new_opts_len], opt_added);
    opts_modified = 1;
  }

  /* Pad tcp options, if needed */
  if (opts_modified) {

    new_opts_len = mmb_padding_tcp_options((u8 *)(tcph + 1), new_opts_len);

    /* can't overflow 40 bytes otherwise data_offset becomes crap */
    if (new_opts_len > 40)
      new_opts_len = 40;
    
    /* update length fields */
    tcph->data_offset_and_reserved = (tcph->data_offset_and_reserved & 0xf) 
                                  | (((new_opts_len + sizeof(tcp_header_t)) >> 2) << 4);
    
    if (is_ip6) {
      ip6_header_t *iph = (ip6_header_t*)p;
      u16 new_ip_len = clib_net_to_host_u16(iph->payload_length)+new_opts_len-old_opts_len;
      iph->payload_length = clib_host_to_net_u16(new_ip_len);
    } else {
      ip4_header_t *iph = (ip4_header_t*)p;
      u16 new_ip_len = clib_net_to_host_u16(iph->length)+new_opts_len-old_opts_len;
      iph->length = clib_host_to_net_u16(new_ip_len);
    }

    // It looks like just incrementing the buffer length is enough since we can assume it is very large
    b->current_length = b->current_length + new_opts_len-old_opts_len;

    //TODO take care of IPv4 fragmentation (if any)
  }
}

static_always_inline void icmp_checksum(vlib_main_t *vm, vlib_buffer_t *b, 
                                        u8 *p, icmp46_header_t *icmph, u8 is_ip6) {

  icmph->checksum = 0;

  if (is_ip6) {
    int bogus_lengthp;
    icmph->checksum = ip6_tcp_udp_icmp_compute_checksum(vm, b, (ip6_header_t*)p, &bogus_lengthp);
  } else {
    ip4_header_t *iph = (ip4_header_t*)p;
    ip_csum_t csum = ip_incremental_checksum(0, icmph, clib_net_to_host_u16(iph->length) - sizeof(*iph));
    icmph->checksum = ~ip_csum_fold(csum);
  }
}

static_always_inline void udp_checksum(vlib_main_t *vm, vlib_buffer_t *b, 
                                       u8 *p, udp_header_t *udph, u8 is_ip6)
{
  int bogus_lengthp;
  udph->checksum = 0;

  if (is_ip6)
    udph->checksum = ip6_tcp_udp_icmp_compute_checksum(vm, b, (ip6_header_t*)p, &bogus_lengthp);
  else
    udph->checksum = ip4_tcp_udp_compute_checksum(vm, b, (ip4_header_t*)p);

  // RFC 7011 section 10.3.2 
  if (udph->checksum == 0)
    udph->checksum = 0xffff;
}

static_always_inline void tcp_checksum(vlib_main_t *vm, vlib_buffer_t *b, 
                                       u8 *p, tcp_header_t *tcph, u8 is_ip6) {
  int bogus_lengthp;
  tcph->checksum = 0;

  if (is_ip6)
    tcph->checksum = ip6_tcp_udp_icmp_compute_checksum(vm, b, (ip6_header_t*)p, &bogus_lengthp);
  else
    tcph->checksum = ip4_tcp_udp_compute_checksum(vm, b, (ip4_header_t*)p);
}

static_always_inline void mmb_map_sack(mmb_tcp_options_t *tcp_options, u8 is_ip6,
                                       mmb_conn_t *conn, u32 dir) {
   //TODO
}

static_always_inline void mmb_map_shuffle(u8 *p, mmb_conn_t *conn, u32 dir, u8 is_ip6) {

  tcp_header_t *tcph;  

   if (!is_ip6) {
      ip4_header_t *iph4 = (ip4_header_t*)p;
      tcph = ip4_next_header(iph4);
      if(conn->ip_id) 
         conn->ip_id = (conn->ip_id + 1) % 0x00010000;
   } else {
      ip6_header_t *iph6 = (ip6_header_t*)p;
      tcph = ip6_next_header(iph6);
      if(conn->ip_id)
         conn->ip_id = (conn->ip_id + 1) % 0x00100000;
   }

   if (conn->tcp_seq_offset) {
      if (!dir) 
         tcph->seq_number = clib_host_to_net_u32(
                              (clib_net_to_host_u32(tcph->seq_number)
                                 + conn->tcp_seq_offset) % 0x100000000);
      else
         tcph->ack_number =  clib_host_to_net_u32(
                                 (clib_net_to_host_u32(tcph->ack_number) 
                                    - conn->tcp_seq_offset + 0x100000000) 
                                          % 0x100000000);
   } 
   if(conn->tcp_ack_offset) {
      if (!dir) { 
         if (!(tcph->flags & TCP_FLAG_SYN))
            tcph->ack_number = clib_host_to_net_u32(
                                 (clib_net_to_host_u32(tcph->ack_number) 
                                    - conn->tcp_ack_offset + 0x100000000)
                                      % 0x100000000);
      } else
         tcph->seq_number = clib_host_to_net_u32(
                              (clib_net_to_host_u32(tcph->seq_number) 
                                 + conn->tcp_ack_offset) % 0x100000000);
   } 

   if(conn->sport) {
      if (!dir) 
         tcph->src_port = conn->sport;
      else 
         tcph->dst_port = conn->initial_sport;
   }
   if(conn->dport) {
      if (!dir) 
         tcph->dst_port = conn->dport;
      else 
         tcph->src_port = conn->initial_dport;
   }
}


static_always_inline 
u32 mmb_rewrite(mmb_conn_table_t *mct, vlib_main_t *vm, mmb_rule_t *rule, 
               vlib_buffer_t *b, u8 *p, 
               u32 next, u8 tcpo, mmb_tcp_options_t *tcp_options, u8 is_ip6) {

  /* lb */
  if (rule->lb) {
    static u32 seed = 0;
    if (!seed) seed = time(NULL);
    u8 *fibs = rule->targets[0].value;
    u8 fib_count = vec_len(fibs);
    u8 fib_index = random_u32(&seed) % fib_count;
    vnet_buffer(b)->sw_if_index[VLIB_TX] = fibs[fib_index];
    return next;
  }

  u32 skip_u64 = rule->rewrite_skip * 2;
  u32 match = rule->rewrite_match;
  u64 *key = (u64 *)rule->rewrite_key;
  u64 *mask = (u64 *)rule->rewrite_mask;
  u64 *data64 = (u64 *)p;  

  switch (match) {
    case 5:
      data64[8 + skip_u64] = (data64[8 + skip_u64] & mask[8]) | key[8];
      data64[9 + skip_u64] = (data64[9 + skip_u64] & mask[9]) | key[9];
      /* FALLTHROUGH */
    case 4:
      data64[6 + skip_u64] = (data64[6 + skip_u64] & mask[6]) | key[6];
      data64[7 + skip_u64] = (data64[7 + skip_u64] & mask[7]) | key[7];
      /* FALLTHROUGH */
    case 3:
      data64[4 + skip_u64] = (data64[4 + skip_u64] & mask[4]) | key[4];
      data64[5 + skip_u64] = (data64[5 + skip_u64] & mask[5]) | key[5];
      /* FALLTHROUGH */
    case 2:
      data64[2 + skip_u64] = (data64[2 + skip_u64] & mask[2]) | key[2];
      data64[3 + skip_u64] = (data64[3 + skip_u64] & mask[3]) | key[3];
      /* FALLTHROUGH */
    case 1:
      data64[0 + skip_u64] = (data64[0 + skip_u64] & mask[0]) | key[0];
      data64[1 + skip_u64] = (data64[1 + skip_u64] & mask[1]) | key[1];
    default:
      break;
  }

  u32 conn_index = vnet_buffer(b)->unused[0];
  u32 conn_dir   = vnet_buffer(b)->unused[1];
  mmb_conn_t *conn = NULL;

  if (rule->shuffle) {

    if (!pool_is_free_index(mct->conn_pool, conn_index)) {/* for safety */
      conn = pool_elt_at_index(mct->conn_pool, conn_index);
      mmb_map_shuffle(p, conn, conn_dir, is_ip6);
    }
  }

  /* tcp opts */
  if (tcpo)
    target_tcp_options(b, p, rule, tcp_options, is_ip6, conn, conn_dir);
 
  /* ip4 checksum */
  if (!is_ip6) {
    ip4_header_t *iph = (ip4_header_t*)p;
    iph->checksum = ip4_header_checksum(iph);
  }

  u16 ip_proto = get_ip_protocol(p, is_ip6);

  /* l4 checksum include pseudoheader */
  int compute_l4_checksum;
  if (rule->l4 == IP_PROTOCOL_RESERVED
       && (ip_proto == IP_PROTOCOL_TCP || ip_proto == IP_PROTOCOL_UDP))
    compute_l4_checksum = ip_proto;
  else 
    compute_l4_checksum = rule->l4;   

  void *next_header = is_ip6 ? 
      ip6_next_header((ip6_header_t*)p) : ip4_next_header((ip4_header_t*)p);
  switch (compute_l4_checksum) { 
    case IP_PROTOCOL_ICMP: 
    case IP_PROTOCOL_ICMP6:
      icmp_checksum(vm, b, p, (icmp46_header_t*) next_header, is_ip6);
      break;

    case IP_PROTOCOL_UDP: 
      udp_checksum(vm, b, p, (udp_header_t*) next_header, is_ip6);
      break;

    case IP_PROTOCOL_TCP: 
      tcp_checksum(vm, b, p, (tcp_header_t*) next_header, is_ip6);
      break;

    default:
      break;
  }

  return next;
}

/************************
 *  Node entry function
 ***********************/

static uword
mmb_node_fn(vlib_main_t *vm, vlib_node_runtime_t *node,
            vlib_frame_t *frame, u8 is_ip6,
            vlib_node_registration_t *mmb_node) {

  mmb_main_t *mm = &mmb_main;
  mmb_rule_t *rules = mm->rules;

  u32 n_left_from, *from, *to_next;
  mmb_next_t next_index;
  u32 pkts_done = 0;

  mmb_tcp_options_t tcp_options0, tcp_options1;
  init_tcp_options(&tcp_options0);
  init_tcp_options(&tcp_options1);

  from = vlib_frame_vector_args(frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
  {
    u32 n_left_to_next;

    vlib_get_next_frame (vm, node, next_index,
			 to_next, n_left_to_next);

    /* Two packets at a time (if possible) */
    while (n_left_from >= 4 && n_left_to_next >= 2)
    {
      u32 bi0, bi1;
      vlib_buffer_t *b0, *b1;
      u32 next0 = MMB_NEXT_FORWARD;
      u32 next1 = MMB_NEXT_FORWARD;
      u32 sw_if_index0, sw_if_index1;
      u8 *p0, *p1, tcpo0 = 0, tcpo1 = 0;

      /* Prefetch next iteration */
      {
        vlib_buffer_t *p2, *p3;

        p2 = vlib_get_buffer(vm, from[2]);
        p3 = vlib_get_buffer(vm, from[3]);

        vlib_prefetch_buffer_header(p2, LOAD);
        vlib_prefetch_buffer_header(p3, LOAD);

        CLIB_PREFETCH(p2->data, CLIB_CACHE_LINE_BYTES, STORE);
        CLIB_PREFETCH(p3->data, CLIB_CACHE_LINE_BYTES, STORE);
      }

      /* speculatively enqueue b0 and b1 to the current next frame */
      to_next[0] = bi0 = from[0];
      to_next[1] = bi1 = from[1];
      from += 2;
      to_next += 2;
      n_left_from -= 2;
      n_left_to_next -= 2;

      /* get vlib buffers */
      b0 = vlib_get_buffer(vm, bi0);
      b1 = vlib_get_buffer(vm, bi1);

      /* get IP headers as raw data */
      p0 = vlib_buffer_get_current(b0);
      p1 = vlib_buffer_get_current(b1);  

      /* get matched rules & rewrite */
      mmb_rule_t *ri0, *ri1;
      u32 *rule_index0, *rule_index1; 
      u32 *rule_indexes0 = (u32 *)vnet_buffer(b0)->l2_classify.hash;
      u32 *rule_indexes1 = (u32 *)vnet_buffer(b1)->l2_classify.hash;   /*XXX vec_free */

      vec_foreach(rule_index0, rule_indexes0) { 
         ri0 = rules+*rule_index0; /** XXX preload? **/
         if (ri0->opts_in_targets) {// && !tcpo0) {
             if (is_ip6)
               tcpo0 = mmb_parse_tcp_options(ip6_next_header((ip6_header_t*)p0), &tcp_options0);
             else
               tcpo0 = mmb_parse_tcp_options(ip4_next_header((ip4_header_t*)p0), &tcp_options0);
         } 
         next0 = mmb_rewrite(mm->mmb_conn_table, vm, ri0, b0, p0, 
                             next0, tcpo0, &tcp_options0, is_ip6);
      }

      vec_foreach(rule_index1, rule_indexes1) { 
         ri1 = rules+*rule_index1;
         if (ri1->opts_in_targets) { //  && !tcpo1) {
             if (is_ip6)
               tcpo1 = mmb_parse_tcp_options(ip6_next_header((ip6_header_t*)p1), &tcp_options1);
             else
               tcpo1 = mmb_parse_tcp_options(ip4_next_header((ip4_header_t*)p1), &tcp_options1);
         } 
         next1 = mmb_rewrite(mm->mmb_conn_table, vm, ri1, b1, p1, 
                             next1, tcpo1, &tcp_options1, is_ip6);
      }

      /* get incoming interfaces */
      sw_if_index0 = vnet_buffer(b0)->sw_if_index[VLIB_RX];
      sw_if_index1 = vnet_buffer(b1)->sw_if_index[VLIB_RX];

      /* two more packets processed */
      pkts_done += 2;

      /* node trace (if enabled) */
      if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE))) {
         if (b0->flags & VLIB_BUFFER_IS_TRACED)
            mmb_trace_ip_packet(vm, b0, node, p0, next0, sw_if_index0, is_ip6);

         if (b1->flags & VLIB_BUFFER_IS_TRACED)
            mmb_trace_ip_packet(vm, b1, node, p1, next1, sw_if_index1, is_ip6);
      }

      vec_free(rule_indexes0);
      vec_free(rule_indexes1);

      /* verify speculative enqueue, maybe switch current next frame */
      vlib_validate_buffer_enqueue_x2(vm, node, next_index,
				       to_next, n_left_to_next,
				       bi0, bi1, next0, next1);
    }

    /* One packet at a time, otherwise */
    while (n_left_from > 0 && n_left_to_next > 0)
    {
      u32 bi0;
      vlib_buffer_t *b0;
      u32 next0 = MMB_NEXT_FORWARD;
      u32 sw_if_index0;
      u8 *p0, tcpo0 = 0;

      /* speculatively enqueue b0 to the current next frame */
      to_next[0] = bi0 = from[0];
      from += 1;
      to_next += 1;
      n_left_from -= 1;
      n_left_to_next -= 1;

      /* get vlib buffer */
      b0 = vlib_get_buffer(vm, bi0);

      /* get IP header as raw data */
      p0 = vlib_buffer_get_current(b0);

      /* get matched rule */
      mmb_rule_t *ri0;
      u32* rule_index0;
      u32 *rule_indexes0 = (u32 *)vnet_buffer(b0)->l2_classify.hash;

      vec_foreach(rule_index0, rule_indexes0) { 
         ri0 = rules+*rule_index0;
         if (ri0->opts_in_targets) { // && !tcpo0) {
             if (is_ip6)
               tcpo0 = mmb_parse_tcp_options(ip6_next_header((ip6_header_t*)p0), &tcp_options0);
             else
               tcpo0 = mmb_parse_tcp_options(ip4_next_header((ip4_header_t*)p0), &tcp_options0);
         } 
         next0 = mmb_rewrite(mm->mmb_conn_table, vm, ri0, b0, p0, 
                             next0, tcpo0, &tcp_options0, is_ip6);
      }

      /* get incoming interface */
      sw_if_index0 = vnet_buffer(b0)->sw_if_index[VLIB_RX];

      /* one more packet processed */
      pkts_done++;

      /* node trace (if enabled) */
      if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE) 
                        && (b0->flags & VLIB_BUFFER_IS_TRACED))) {
         mmb_trace_ip_packet(vm, b0, node, p0, next0, sw_if_index0, is_ip6);
      }

      vec_free(rule_indexes0);

      /* verify speculative enqueue, maybe switch current next frame */
      vlib_validate_buffer_enqueue_x1(vm, node, next_index,
				       to_next, n_left_to_next,
				       bi0, next0);
    }

    vlib_put_next_frame(vm, node, next_index, n_left_to_next);
  }

  vlib_node_increment_counter(vm, mmb_node->index, 
                              MMB_ERROR_DONE, pkts_done);
  
  free_tcp_options(&tcp_options0);
  free_tcp_options(&tcp_options1);

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
    [MMB_NEXT_FORWARD] = "ip4-lookup",//"interface-output",
    [MMB_NEXT_LOOP] = "ip4-input",
  }
};

VLIB_NODE_FUNCTION_MULTIARCH(ip4_mmb_rewrite_node, mmb_node_ip4_rewrite_fn);

VNET_FEATURE_INIT (ip4_mmb_rewrite_feature, static) = {
  .arc_name = "ip4-unicast",//"ip4-output",
  .node_name = "ip4-mmb-rewrite",
  .runs_before = VNET_FEATURES("ip4-lookup"),//"interface-output"),
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
    [MMB_NEXT_FORWARD] = "ip6-lookup",
    [MMB_NEXT_LOOP] = "ip6-input",
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
  //mmb_main.feature_arc_index = vlib_node_add_next(vm, ip4_mmb_rewrite_node.index, ip4_rewrite_node.index);
  return 0;
}

VLIB_INIT_FUNCTION(mmb_rewrite_init);
