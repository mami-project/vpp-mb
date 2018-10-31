/*
 * Copyright (c) 2018 Cisco and/or its affiliates.
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
 * @file mmb_classify.c
 * @brief mmb classify node
 * @author Korian Edeline
 */

#include <stdint.h>

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/classify/vnet_classify.h>

#include <mmb/mmb_classify.h>
#include <mmb/mmb.h>
#include <mmb/mmb_opts.h>

typedef struct {
  u32 sw_if_index;
  u32 next_index;
  u32 *rule_indexes;
  u32 offset;
  u8 packet_data[16];

  u32 conn_index;
  u32 conn_dir;
  mmb_5tuple_t packet_5tuple;
} mmb_classify_trace_t;

static u8 *format_mmb_classify_trace(u8 * s, va_list * args)
{
  CLIB_UNUSED(vlib_main_t * vm) = va_arg(*args, vlib_main_t *);
  CLIB_UNUSED(vlib_node_t * node) = va_arg(*args, vlib_node_t *);
  mmb_classify_trace_t * t = va_arg(*args, mmb_classify_trace_t *);

  u32 *index;
  vec_foreach(index, t->rule_indexes) {
     s = format(s, "match: sw_if_index %d rule %d next %d offset %d\n  ",
                 t->sw_if_index, *index, t->next_index, t->offset);
  }

  if (vec_len(t->rule_indexes) == 0)
     s = format(s, "\tno match: sw_if_index %d next %d\n  ",
                 t->sw_if_index, t->next_index);

  if (t->conn_index != ~0)
    s = format(s, "conn id: %u dir:%u\n", t->conn_index, t->conn_dir);

  return s;
}

#define foreach_mmb_classify_error                 \
_(MISS, "Flow classify misses")                    \
_(HIT, "Flow classify hits")                       \
_(DROP, "Flow classify action drop")

typedef enum {
#define _(sym,str) MMB_CLASSIFY_ERROR_##sym,
  foreach_mmb_classify_error
#undef _
  MMB_CLASSIFY_N_ERROR,
} mmb_classify_error_t;

static char * mmb_classify_error_strings[] = {
#define _(sym,string) string,
  foreach_mmb_classify_error
#undef _
};

static_always_inline int mmb_true_condition(u8 condition, u8 reverse) {
  return condition != reverse;
}

static u8 mmb_value_starts_with(u8 *pkt_data, u8 pkt_data_length, u8 *value) {
  /* Packet data can't start with value if the latter is bigger */
  if (vec_len(value) > pkt_data_length)
    return 0;

  /* Compare each value byte to packet data ones */
  u32 i;
  vec_foreach_index(i, value)
  {
    /* Mismatch -> can't start with */
    if (pkt_data[i] != value[i])
      return 0;
  }

  /* Packet data starts with value */
  return 1;
}

static u8 mmb_value_compare(u64 a, u64 b, u8 condition, u8 reverse) {
  u8 res;

  switch(condition) {
    case MMB_COND_EQ:
      res = (a == b);
      break;

    case MMB_COND_NEQ:
      res = (a != b);
      break;

    case MMB_COND_LEQ:
      res = (a <= b);
      break;

    case MMB_COND_GEQ:
      res = (a >= b);
      break;

    case MMB_COND_LT:
      res = (a < b);
      break;

    case MMB_COND_GT:
      res = (a > b);
      break;

    default:
      return 0;
  }

  if (reverse)
    return !res;

  return res;
}

static_always_inline u64 n_bytes_to_u64(u8 *data, u8 length) {
  u64 value = 0;
  u32 len = length-1;

  u32 i;
  for(i = 0; i < length; i++) {
    value += ((u64) *data++) << ((len - i) * 8);
  }

  return value;
}

static inline int mmb_match_opt(mmb_match_t *match, mmb_tcp_options_t *options) {

  // TODO: replace opt_kind=0 by opt_kind=ALL (to distinguish option 0 and this case)
  if (match->opt_kind == 0 || match->opt_kind == MMB_FIELD_TCP_OPT_ALL) {
    /* do we have any TCP option in this packet */
    if (!mmb_true_condition(vec_len(options->parsed) > 0,
                            match->reverse))
      return 0;
  } else if (match->condition == 0) {
    /* only search for the existence of an option */
    if (!mmb_true_condition(tcp_option_exists(options, match->opt_kind),
                            match->reverse))
      return 0;
  } else {
    /* search for an option and its value */
    if (!tcp_option_exists(options, match->opt_kind))
      return 0;

    u8 opt_idx = options->idx[match->opt_kind];
    u8 opt_offset = options->parsed[opt_idx].offset;
    u8 opt_length = options->parsed[opt_idx].data_length;
    u8 *opt_data_ptr = &options->data[opt_offset+2];

    if (vec_len(match->value) > 8) {
      /* values > u64 */
      if (!mmb_true_condition(mmb_value_starts_with(opt_data_ptr, opt_length, match->value),
                              match->reverse))
        return 0;
    }
    else if (!mmb_value_compare(n_bytes_to_u64(opt_data_ptr, opt_length),
                                bytes_to_u64(match->value),
                                match->condition, match->reverse))
      return 0;
  }


   return 1;
}

static inline int mmb_match_opts(mmb_rule_t *rule, u8 *p0,
                       mmb_tcp_options_t *tcpo0, u8 *tcpo0_flag, u8 is_ip6) {

   mmb_match_t *opt_matches = rule->opt_matches, *match;

   if (*tcpo0_flag == 0) { /* parse options */
      tcp_header_t *tcph;
      if (is_ip6)
         tcph = ip6_next_header((ip6_header_t*)p0);
      else
         tcph = ip4_next_header((ip4_header_t*)p0);
      mmb_parse_tcp_options(tcph, tcpo0);
      *tcpo0_flag = 1;
   }

   /* match */
   vec_foreach(match, opt_matches) {
      if (!mmb_match_opt(match, tcpo0))
         return 0;
   }

   return 1;
}

static_always_inline int random_drop(mmb_main_t *mm, u32 drop_rate) {

   u32 random_value = random_u32(&mm->random_seed) % (MMB_MAX_DROP_RATE_VALUE+1);
   return random_value < drop_rate;
}

static inline uword
mmb_classify_inline(vlib_main_t * vm,
                     vlib_node_runtime_t * node,
                     vlib_frame_t * frame,
                     mmb_classify_table_id_t tid)
{
  u32 n_left_from, *from, *to_next;
  mmb_classify_next_index_t next_index;
  mmb_main_t *mm = &mmb_main;
  mmb_classify_main_t *mcm = mm->mmb_classify_main;
  vnet_classify_main_t *vcm = mcm->vnet_classify_main;
  mmb_conn_table_t *mct = mm->mmb_conn_table;

  mmb_rule_t *rules = mm->rules;
  mmb_lookup_entry_t *lookup_pool = mm->lookup_pool, *lookup_entry;
  u32 *rule_index, accept0, drop0;
  f64 now = vlib_time_now(vm);
  u64 now_ticks = clib_cpu_time_now();

  u32 hits = 0;
  u32 drop = 0;

  mmb_tcp_options_t tcpo0;
  init_tcp_options(&tcpo0);

  from = vlib_frame_vector_args(frame);
  n_left_from = frame->n_vectors;

  /* First pass: compute hashes */
  while (n_left_from > 2)
  {
      vlib_buffer_t *b0, *b1;
      u32 bi0, bi1;
      u8 *h0, *h1;
      u32 sw_if_index0, sw_if_index1;
      u32 table_index0, table_index1;
      vnet_classify_table_t *t0, *t1;

      /* Prefetch next iteration */
      {
        vlib_buffer_t *p1, *p2;

        p1 = vlib_get_buffer(vm, from[1]);
        p2 = vlib_get_buffer(vm, from[2]);

        vlib_prefetch_buffer_header(p1, STORE);
        CLIB_PREFETCH(p1->data, CLIB_CACHE_LINE_BYTES, STORE);
        vlib_prefetch_buffer_header(p2, STORE);
        CLIB_PREFETCH(p2->data, CLIB_CACHE_LINE_BYTES, STORE);
      }

      bi0 = from[0];
      b0 = vlib_get_buffer(vm, bi0);
      h0 = vlib_buffer_get_current(b0);

      bi1 = from[1];
      b1 = vlib_get_buffer(vm, bi1);
      h1 = vlib_buffer_get_current(b1);

      sw_if_index0 = vnet_buffer(b0)->sw_if_index[VLIB_RX];
      table_index0 = mcm->classify_table_index_by_sw_if_index[tid][sw_if_index0];

      sw_if_index1 = vnet_buffer(b1)->sw_if_index[VLIB_RX];
      table_index1 = mcm->classify_table_index_by_sw_if_index[tid][sw_if_index1];

      t0 = pool_elt_at_index(vcm->tables, table_index0);
      t1 = pool_elt_at_index(vcm->tables, table_index1);

      vnet_buffer(b0)->l2_classify.hash =
        vnet_classify_hash_packet(t0, (u8 *) h0);
      vnet_classify_prefetch_bucket(t0, vnet_buffer(b0)->l2_classify.hash);

      vnet_buffer(b1)->l2_classify.hash =
        vnet_classify_hash_packet(t1, (u8 *) h1);
      vnet_classify_prefetch_bucket(t1, vnet_buffer(b1)->l2_classify.hash);

      vnet_buffer(b0)->l2_classify.table_index = table_index0;
      vnet_buffer(b1)->l2_classify.table_index = table_index1;

      from += 2;
      n_left_from -= 2;
  }

  while (n_left_from > 0) {

     vlib_buffer_t *b0;
     u32 bi0;
     u8 *h0;
     u32 sw_if_index0;
     u32 table_index0;
     vnet_classify_table_t *t0;

     bi0 = from[0];
     b0 = vlib_get_buffer(vm, bi0);
     h0 = vlib_buffer_get_current(b0);

     sw_if_index0 = vnet_buffer(b0)->sw_if_index[VLIB_RX];
     table_index0 = mcm->classify_table_index_by_sw_if_index[tid][sw_if_index0];

     t0 = pool_elt_at_index(vcm->tables, table_index0);
     vnet_buffer(b0)->l2_classify.hash =
        vnet_classify_hash_packet(t0,(u8 *) h0);

     vnet_buffer(b0)->l2_classify.table_index = table_index0;
     vnet_classify_prefetch_bucket(t0, vnet_buffer(b0)->l2_classify.hash);

     from++;
     n_left_from--;
  }

  next_index = node->cached_next_index;
  from = vlib_frame_vector_args(frame);
  n_left_from = frame->n_vectors;

  /* perform timeout check if needed */
  if (mct->conn_hash_is_initialized
      && get_conn_table_check_time(vm, mm->last_conn_table_timeout_check) < now_ticks) {

     if (purge_conn_expired(mct, now_ticks))
         mm->last_conn_table_timeout_check = now_ticks;
  }

  while (n_left_from > 0) {

     u32 n_left_to_next;

     vlib_get_next_frame(vm, node, next_index, to_next, n_left_to_next);

     /* Not enough load/store slots to dual loop... */
     while (n_left_from > 0 && n_left_to_next > 0) {

         u32 bi0;
         vlib_buffer_t *b0;
         u32 next0 = MMB_CLASSIFY_NEXT_INDEX_MISS;
         u32 table_index0;
         vnet_classify_table_t *t0;
         vnet_classify_entry_t *e0;
         u64 hash0;
         u8 *h0;
         u32 *matches, *matches_stateful;
         mmb_rule_t *rule;
         u32 conn_index, conn_dir;
         u8 tcpo0_flag;
         mmb_5tuple_t pkt_5tuple;
         clib_bihash_kv_48_8_t pkt_conn_index;

         /* Stride 3 seems to work best */
         if (PREDICT_TRUE(n_left_from > 3)) {
             vlib_buffer_t *p1 = vlib_get_buffer(vm, from[3]);
             vnet_classify_table_t *tp1;
             u32 table_index1;
             u64 phash1;

             table_index1 = vnet_buffer(p1)->l2_classify.table_index;

             if (PREDICT_TRUE(table_index1 != ~0)) {
                 tp1 = pool_elt_at_index(vcm->tables, table_index1);
                 phash1 = vnet_buffer(p1)->l2_classify.hash;
                 vnet_classify_prefetch_entry(tp1, phash1);
             }
         }

         /* Speculatively enqueue b0 to the current next frame */
         bi0 = from[0];
         to_next[0] = bi0;
         from += 1;
         to_next += 1;
         n_left_from -= 1;
         n_left_to_next -= 1;

         b0 = vlib_get_buffer(vm, bi0);
         h0 = vlib_buffer_get_current(b0);
         table_index0 = vnet_buffer(b0)->l2_classify.table_index;
         e0 = 0;
         t0 = 0;
         matches = 0;
         matches_stateful = 0;
         tcpo0_flag = 0;
         conn_index = ~0;
         conn_dir = 0;
         accept0 = 0;
         drop0 = 0;

         mmb_fill_5tuple(b0, h0, tid, &pkt_5tuple);

         /* matching stateless rules */
         if (PREDICT_TRUE(table_index0 != ~0)) {

             hash0 = vnet_buffer(b0)->l2_classify.hash;
             t0 = pool_elt_at_index(vcm->tables, table_index0);
             e0 = vnet_classify_find_entry(t0, h0, hash0, now);

             if (e0) { /* match */
                 lookup_entry = pool_elt_at_index(lookup_pool, e0->opaque_index);

                 vec_foreach(rule_index, lookup_entry->rule_indexes) {

                    rule = rules+*rule_index;
                    if (rule->opts_in_matches
                        && !mmb_match_opts(rule, h0, &tcpo0, &tcpo0_flag, tid))
                       continue;

                    if (rule->stateful == 0) { /* stateless */

                       vec_add1(matches, *rule_index);

                       if (rule->accept == 0 && rule->drop_rate == 0)
                          next0 = MMB_CLASSIFY_NEXT_INDEX_MATCH;
                       else if (rule->accept == 1)
                          accept0 = 1;
                       else if (rule->drop_rate == MMB_MAX_DROP_RATE_VALUE
                              || random_drop(mm, rule->drop_rate))
                          drop0 = 1;

                     } else {
                        vec_add1(matches_stateful, *rule_index);
                     }

                     rule->match_count++;
                 }
                 hits++;
             }

             while (t0->next_table_index != ~0) {
                  t0 = pool_elt_at_index(vcm->tables,
                                          t0->next_table_index);

                hash0 = vnet_classify_hash_packet(t0, h0);
                e0 = vnet_classify_find_entry(t0, h0, hash0, now);

                if (e0) {

                   lookup_entry = pool_elt_at_index(lookup_pool, e0->opaque_index);
                   vec_foreach(rule_index, lookup_entry->rule_indexes) {

                      rule = rules+*rule_index;
                      if (rule->opts_in_matches
                           && !mmb_match_opts(rule, h0, &tcpo0, &tcpo0_flag, tid))
                         continue;



                      if (rule->stateful == 0) { /* stateless */

                         vec_add1(matches, *rule_index);

                         if (rule->accept == 0 && rule->drop_rate == 0)
                            next0 = MMB_CLASSIFY_NEXT_INDEX_MATCH;
                         else if (rule->accept == 1)
                           accept0 = 1;
                         else if (rule->drop_rate == MMB_MAX_DROP_RATE_VALUE
                              || random_drop(mm, rule->drop_rate))
                           drop0 = 1;

                      } else {
                        vec_add1(matches_stateful, *rule_index);
                      }

                      rule->match_count++;
                   }
                   hits++;
                }
             }
         }

         /* stateful matching */
         if (mct->conn_hash_is_initialized) {
             mmb_conn_t *conn;
             mmb_conn_id_t conn_id;

            if (mmb_find_conn(mct, &pkt_5tuple, &pkt_conn_index)) {
               /* found connection, update entry and add rule indexes  */

               conn_id.as_u64 = pkt_conn_index.value;
               conn_index = conn_id.conn_index;
               conn_dir   = conn_id.dir;

               conn = pool_elt_at_index(mct->conn_pool, conn_index);
               mmb_track_conn(conn, &pkt_5tuple, conn_dir, now_ticks);

               vec_append(matches, conn->rule_indexes);

               if (conn->accept == 0)
                  next0 = conn->next;
               else
                  accept0 = 1;

            } else if (vec_len(matches_stateful) != 0
                        && pkt_5tuple.pkt_info.l4_valid == 1) {
               /* new valid connection matched */

               conn = mmb_add_conn(mct, &pkt_5tuple, matches_stateful, now_ticks);
               conn_index = pkt_5tuple.pkt_info.conn_index;

               vec_append(matches, matches_stateful);

               if (conn->accept == 0)
                  next0 = conn->next;
               else
                  accept0 = 1;
            }
         }

         /* summarize stateless drop&accept targets */
         if (drop0 == 1 && accept0 == 0)
            next0 = MMB_CLASSIFY_NEXT_INDEX_DROP;

         /* pass matches & conn id to next node */
         vnet_buffer(b0)->l2_classify.hash = (u64)matches;
         vnet_buffer(b0)->unused[0] = conn_index;
         vnet_buffer(b0)->unused[1] = conn_dir;

         if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE)
                            && (b0->flags & VLIB_BUFFER_IS_TRACED))) {
              mmb_classify_trace_t * t =
                vlib_add_trace(vm, node, b0, sizeof(*t));
              t->sw_if_index = vnet_buffer(b0)->sw_if_index[VLIB_RX];
              t->next_index = next0;
              t->rule_indexes = vec_dup((u32*)vnet_buffer(b0)->l2_classify.hash);
              /*clib_memcpy(&t->packet_5tuple, &pkt_5tuple,
		                    sizeof(pkt_5tuple));
              clib_memcpy(t->packet_data, h0,
		                    sizeof(t->packet_data)); */ /* offsetof */
              t->conn_index = conn_index;
              t->conn_dir = conn_dir;
         }

         vec_free(matches_stateful);

         /* Verify speculative enqueue, maybe switch current next frame */
         vlib_validate_buffer_enqueue_x1(vm, node, next_index, to_next,
                                           n_left_to_next, bi0, next0);
     }

     vlib_put_next_frame(vm, node, next_index, n_left_to_next);
  }

  vlib_node_increment_counter(vm, node->node_index,
                               MMB_CLASSIFY_ERROR_HIT,
                               hits);
  vlib_node_increment_counter(vm, node->node_index,
                               MMB_CLASSIFY_ERROR_DROP,
                               drop);


  return frame->n_vectors;
}

static uword
ip4_mmb_classify(vlib_main_t * vm,
                   vlib_node_runtime_t * node,
                   vlib_frame_t * frame)
{
  return mmb_classify_inline(vm, node, frame, MMB_CLASSIFY_TABLE_IP4);
}

vlib_node_registration_t ip4_mmb_classify_node;
/* *INDENT-OFF* */
VLIB_REGISTER_NODE(ip4_mmb_classify_node) = {
  .function = ip4_mmb_classify,
  .name = "ip4-mmb-classify",
  .vector_size = sizeof(u32),
  .format_trace = format_mmb_classify_trace,
  .n_errors = ARRAY_LEN(mmb_classify_error_strings),
  .error_strings = mmb_classify_error_strings,
  .n_next_nodes = MMB_CLASSIFY_NEXT_INDEX_N_NEXT,
  .next_nodes = {
    [MMB_CLASSIFY_NEXT_INDEX_MATCH] = "ip4-mmb-rewrite",
    [MMB_CLASSIFY_NEXT_INDEX_MISS] = "ip4-lookup",
    [MMB_CLASSIFY_NEXT_INDEX_DROP] = "error-drop",
  },
};
/* *INDENT-ON* */

VNET_FEATURE_INIT(ip4_mmb_classify_feature, static) =
{
  .arc_name = "ip4-unicast",
  .node_name = "ip4-mmb-classify",
  .runs_before = VNET_FEATURES("ip4-mmb-rewrite"),
};

static uword
ip6_mmb_classify(vlib_main_t * vm,
                   vlib_node_runtime_t * node,
                   vlib_frame_t * frame)
{
  return mmb_classify_inline(vm, node, frame, MMB_CLASSIFY_TABLE_IP6);
}

vlib_node_registration_t ip6_mmb_classify_node;
/* *INDENT-OFF* */
VLIB_REGISTER_NODE(ip6_mmb_classify_node) = {
  .function = ip6_mmb_classify,
  .name = "ip6-mmb-classify",
  .vector_size = sizeof(u32),
  .format_trace = format_mmb_classify_trace,
  .n_errors = ARRAY_LEN(mmb_classify_error_strings),
  .error_strings = mmb_classify_error_strings,
  .n_next_nodes = MMB_CLASSIFY_NEXT_INDEX_N_NEXT,
  .next_nodes = {
    [MMB_CLASSIFY_NEXT_INDEX_MATCH] = "ip6-mmb-rewrite",
    [MMB_CLASSIFY_NEXT_INDEX_MISS] = "ip6-lookup",
    [MMB_CLASSIFY_NEXT_INDEX_DROP] = "error-drop",
  },
};
/* *INDENT-ON* */

VNET_FEATURE_INIT(ip6_mmb_classify_feature, static) =
{
  .arc_name = "ip6-unicast",
  .node_name = "ip6-mmb-classify",
  .runs_before = VNET_FEATURES("ip6-mmb-rewrite"),
};

static clib_error_t *
mmb_classify_init(vlib_main_t *vm) {

  // TODO: move init code from mmb_init() to here ?

  return 0;
}

VLIB_INIT_FUNCTION(mmb_classify_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
