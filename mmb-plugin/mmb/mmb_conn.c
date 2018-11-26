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
 * @file mmb_conn.c
 * @brief connection tables for stateful rules
 * @author Korian Edeline
 */

#include <mmb/mmb.h>
#include <mmb/mmb_opts.h>
#include <mmb/mmb_conn.h>

#ifdef MMB_DEBUG
#  define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#else
#  define vl_print(handle, ...)
#endif

#define UDP_SESSION_IDLE_TIMEOUT_SEC 600
#define TCP_SESSION_IDLE_TIMEOUT_SEC (3600*4)
#define TCP_SESSION_TRANSIENT_TIMEOUT_SEC 120

#define MMB_CONN_TABLE_DEFAULT_HASH_NUM_BUCKETS (64 * 1024)
#define MMB_CONN_TABLE_DEFAULT_HASH_MEMORY_SIZE (1<<30)
#define MMB_CONN_TABLE_DEFAULT_MAX_ENTRIES 1000000

/**
 * purge_conn
 *
 * remove conn_id's in purge_indexes from pool&bihash
 */
static void purge_conn(mmb_conn_table_t *mct, u32 *purge_indexes);

/**
 *
 * @see update_conn_pool
 */
static void update_conn_pool_internal(mmb_conn_table_t *mct, u32 rule_index);

/**
 * wait for connection handling lock to be available
 */
static_always_inline void wait_and_lock_connection_handling(mmb_conn_table_t *mct);

/**
 * init_conn_map()
 *
 * init shuffle mapping offset
 */
static_always_inline void init_conn_map(mmb_main_t *mm,
                                        mmb_conn_t *conn,
                                        mmb_rule_t *rule);

/**
 * update_conn_map_shuffle
 *
 * update connection map/shufle information when rule is deleted
 */
void update_conn_map_shuffle(mmb_conn_t *conn, mmb_target_t *targets);

/**
 * update_conn
 *
 * update conn info from remaining rules, after deletion of rule_index
 */
static_always_inline void update_conn(mmb_conn_t *conn, u32 rule_index);

/**
 * random_bounded_u16()
 *
 * @return random u16 in [lo; hi+1]
 */
static_always_inline u16 random_bounded_u16(u32 *seed, uword lo, uword hi);

/**
 * init_conn_shuffle()
 *
 * init shuffle mapping offset
 */
static_always_inline void init_conn_shuffle(mmb_main_t *mm,
                                            mmb_conn_t *conn,
                                            mmb_rule_t *rule);

/**
 * return index of val in vec, ~0 if vec does not contain val
 */
static_always_inline u32 vec_find(u32 *vec, u32 val) {
   u32 vec_index = 0;
   vec_foreach_index(vec_index, vec) {
      if (vec[vec_index] == val)
         return vec_index;
   }

   return ~0;
}

static_always_inline int mmb_del_5tuple(mmb_conn_table_t *mct, clib_bihash_kv_48_8_t *conn_key) {
  return BV (clib_bihash_add_del) (&mct->conn_hash,
			    conn_key, 0);
}

static_always_inline int mmb_add_5tuple(mmb_conn_table_t *mct, clib_bihash_kv_48_8_t *conn_key) {
  return BV (clib_bihash_add_del) (&mct->conn_hash,
			    conn_key, 1);
}

int mmb_find_conn(mmb_conn_table_t *mct, mmb_5tuple_t *pkt_5tuple,
		            clib_bihash_kv_48_8_t *pkt_conn_id) {
  return (BV(clib_bihash_search)
            (&mct->conn_hash, &pkt_5tuple->kv, pkt_conn_id) == 0);
}

u64 get_conn_timeout_time(mmb_conn_table_t *mct, mmb_conn_t *conn) {

   mmb_main_t *mm = &mmb_main;

   int timeout_type = get_conn_timeout_type(mct, conn);
   u64 timeout_ticks = mct->timeouts_value[timeout_type];
   timeout_ticks *= mm->vlib_main->clib_time.clocks_per_second;

   return timeout_ticks + conn->last_active_time;
}

void purge_conn_forced(mmb_conn_table_t *mct) {

  mmb_conn_t *conn;

  wait_and_lock_connection_handling(mct);

  /* purge hash */
  mct->conn_hash_is_initialized = 0;
  BV(clib_bihash_free) (&mct->conn_hash);

  /* purge pool */
  pool_flush(conn, mct->conn_pool, ({
      vec_free(conn->rule_indexes);
  }));
  pool_free(mct->conn_pool);

  mct->currently_handling_connections = 0;
}

int purge_conn_expired_now(mmb_conn_table_t *mct) {
   return purge_conn_expired(mct, clib_cpu_time_now());
}

int purge_conn_expired(mmb_conn_table_t *mct, u64 now) {

   mmb_conn_t *conn;
   u32 *purge_indexes = 0;
   u64 timeout_time;

   /* connetions are already being checked, aborting */
   if (mct->currently_handling_connections)
      return 0;
   else
      mct->currently_handling_connections = 1;

   /* remove rule_index from connections */
   /* *INDENT-OFF* */
   pool_foreach(conn, mct->conn_pool, ({
      timeout_time = get_conn_timeout_time(mct, conn);

      /* timeout */
      if (now > timeout_time)
         vec_add1(purge_indexes, conn - mct->conn_pool);

   }));
   /* *INDENT-ON* */

   purge_conn(mct, purge_indexes);

   mct->currently_handling_connections = 0;
   return 1;
}

static_always_inline void copy_reverse_5tuple(mmb_5tuple_t *to, mmb_conn_t *from) {
   to->addr[0] = (!ip46_address_is_zero(&from->daddr)) ? from->daddr : from->info.addr[1];
   to->addr[1] = (!ip46_address_is_zero(&from->saddr)) ? from->saddr :from->info.addr[0];
   to->l4.port[0] = from->dport ? ntohs(from->dport) : from->info.l4.port[1];
   to->l4.port[1] = from->sport ? ntohs(from->sport) : from->info.l4.port[0];
}

static_always_inline void copy_forward_5tuple(mmb_5tuple_t *to, mmb_conn_t *from) {
   to->kv.key[0] = from->info.kv.key[0];
   to->kv.key[1] = from->info.kv.key[1];
   to->kv.key[2] = from->info.kv.key[2];
   to->kv.key[3] = from->info.kv.key[3];
   to->kv.key[4] = from->info.kv.key[4];
   to->kv.key[5] = from->info.kv.key[5];
}

void purge_conn(mmb_conn_table_t *mct, u32 *purge_indexes) {

   mmb_conn_t *conn;
   mmb_5tuple_t conn_key;
   u32 *purge_index;

   vec_foreach(purge_index, purge_indexes) {

      conn = pool_elt_at_index(mct->conn_pool, *purge_index);

      /* purge bihash */
      copy_forward_5tuple(&conn_key, conn);
      mmb_del_5tuple(mct, &conn_key.kv);

      copy_reverse_5tuple(&conn_key, conn);
      mmb_del_5tuple(mct, &conn_key.kv);

      vec_free(conn->rule_indexes);

      pool_put(mct->conn_pool, conn);
   }
}

void wait_and_lock_connection_handling(mmb_conn_table_t *mct) {

   mmb_main_t *mm = &mmb_main;

   while (mct->currently_handling_connections) {
      vlib_process_suspend(mm->vlib_main, 0.0001);
   }
   mct->currently_handling_connections = 1;
}

void update_conn_map_shuffle(mmb_conn_t *conn, mmb_target_t *targets) {

   mmb_target_t *target;

   vec_foreach(target, targets) {
      switch (target->field) {
         case MMB_FIELD_TCP_SPORT:
         case MMB_FIELD_UDP_SPORT:
            conn->sport = 0;
            conn->initial_sport = 0;
            break;
         case MMB_FIELD_TCP_DPORT:
         case MMB_FIELD_UDP_DPORT:
            conn->dport = 0;
            conn->initial_dport = 0;
            break;
         case MMB_FIELD_IP4_SADDR:
            conn->saddr.ip4.as_u32 = 0;
            conn->initial_saddr.as_u64[0] = 0;
            conn->initial_saddr.as_u64[1] = 0;
            break;
        case MMB_FIELD_IP4_DADDR:
            conn->daddr.ip4.as_u32 = 0;
            conn->initial_daddr.as_u64[0] = 0;
            conn->initial_daddr.as_u64[1] = 0;
            break;
         case MMB_FIELD_IP6_SADDR:
            conn->saddr.as_u64[0] = 0;
            conn->saddr.as_u64[1] = 0;
            conn->initial_saddr.as_u64[0] = 0;
            conn->initial_saddr.as_u64[1] = 0;
            break;
         case MMB_FIELD_IP6_DADDR:
            conn->daddr.as_u64[0] = 0;
            conn->daddr.as_u64[1] = 0;
            conn->initial_daddr.as_u64[0] = 0;
            conn->initial_daddr.as_u64[1] = 0;
            break;
         case MMB_FIELD_IP4_ID :
         case MMB_FIELD_IP6_FLOW_LABEL:
            conn->ip_id = 0;
            break;
         case MMB_FIELD_TCP_SEQ_NUM:
            conn->tcp_seq_offset = 0;
            break;
         case MMB_FIELD_TCP_ACK_NUM:
            conn->tcp_ack_offset = 0;
            break;
         case MMB_FIELD_TCP_OPT: /* opt_kind is guaranteed to be 5 here */
            conn->tcp_seq_offset = 0;
            conn->tcp_ack_offset = 0;
            conn->mapped_sack = 0;
            break;
         default:
            break;
      }
   }
}

void update_conn(mmb_conn_t *conn, u32 rule_index) {

   mmb_main_t *mm = &mmb_main;
   mmb_rule_t *rule, *deleted = &mm->rules[rule_index];
   u32 *remaining_rule;

   if (deleted->map)
      update_conn_map_shuffle(conn, deleted->map_targets);
   if (deleted->shuffle)
      update_conn_map_shuffle(conn, deleted->shuffle_targets);

   /* update accept & target */
   conn->next = MMB_CLASSIFY_NEXT_INDEX_MISS;
   vec_foreach(remaining_rule, conn->rule_indexes) {
      rule = mm->rules + *remaining_rule;

      if (rule->accept)
         conn->accept = 1;
      if (rule->rewrite)
         conn->next = MMB_CLASSIFY_NEXT_INDEX_MATCH;
   }
}

void purge_conn_index(mmb_conn_table_t *mct, u32 rule_index) {

   mmb_conn_t *conn;
   u32 *purge_indexes = 0, index_of_index;

   wait_and_lock_connection_handling(mct);

   /* remove rule_index from connections */
   /* *INDENT-OFF* */
   pool_foreach(conn, mct->conn_pool, ({

      index_of_index = vec_find(conn->rule_indexes, rule_index);
      if (index_of_index == ~0)
         continue;

      if (vec_len(conn->rule_indexes) == 1) {
         vec_add1(purge_indexes, conn - mct->conn_pool);
         vec_free(conn->rule_indexes);
      } else { /* conn still used by other rules */
         vec_delete(conn->rule_indexes, 1, index_of_index);
         update_conn(conn, rule_index);
      }

   }));
   /* *INDENT-ON* */

   /* decrement rules with index > rule_index */
   update_conn_pool_internal(mct, rule_index);

   purge_conn(mct, purge_indexes);

   mct->currently_handling_connections = 0;
}

void update_conn_pool(mmb_conn_table_t *mct, u32 rule_index) {

   wait_and_lock_connection_handling(mct);
   update_conn_pool_internal(mct, rule_index);
   mct->currently_handling_connections = 0;
}

void update_conn_pool_internal(mmb_conn_table_t *mct, u32 rule_index) {

   u32 *current_rule_index;
   mmb_conn_t *conn;

   /* *INDENT-OFF* */
   pool_foreach(conn, mct->conn_pool, ({

      vec_foreach(current_rule_index, conn->rule_indexes) {
         if (*current_rule_index > rule_index)
            (*current_rule_index)--;
      }
   }));
   /* *INDENT-ON* */
}

u16 random_bounded_u16(u32 *seed, uword lo, uword hi) {
   if (lo == hi)
      return lo;

   return (u16) ((random_u32(seed) % (hi - lo + 1)) + lo);
}

void init_conn_shuffle(mmb_main_t *mm,
                       mmb_conn_t *conn,
                       mmb_rule_t *rule) {
   mmb_target_t *target;

   vec_foreach(target, rule->shuffle_targets) {
      switch (target->field) {
         case MMB_FIELD_TCP_SEQ_NUM:
            if (!conn->tcp_seq_offset)
               conn->tcp_seq_offset = random_u32(&mm->random_seed);
            break;
         case MMB_FIELD_TCP_ACK_NUM:
            if (!conn->tcp_ack_offset)
               conn->tcp_ack_offset = random_u32(&mm->random_seed);
            break;
         case MMB_FIELD_TCP_SPORT:
         case MMB_FIELD_UDP_SPORT:
            conn->sport = clib_host_to_net_u16(
                            (u16) random_bounded_u16(&mm->random_seed,
                               MMB_MIN_SHUFFLE_PORT, MMB_MAX_SHUFFLE_PORT-1));
            conn->initial_sport = clib_host_to_net_u16(conn->info.l4.port[0]);
            break;
         case MMB_FIELD_TCP_DPORT:
         case MMB_FIELD_UDP_DPORT:
            conn->dport = clib_host_to_net_u16(
                            (u16) random_bounded_u16(&mm->random_seed,
                               MMB_MIN_SHUFFLE_PORT, MMB_MAX_SHUFFLE_PORT-1));
            conn->initial_dport = clib_host_to_net_u16(conn->info.l4.port[1]);
            break;
         case MMB_FIELD_TCP_OPT: /* opt_kind is guaranteed to be 5 here */
            if (!conn->tcp_seq_offset)
               conn->tcp_seq_offset = random_u32(&mm->random_seed);
            if (!conn->tcp_ack_offset)
               conn->tcp_ack_offset = random_u32(&mm->random_seed);
            conn->mapped_sack = 1;
            break;
         case MMB_FIELD_IP4_ID :
            conn->ip_id = random_u32(&mm->random_seed);
            break;
         case MMB_FIELD_IP6_FLOW_LABEL:
            conn->ip_id = random_u32(&mm->random_seed);
            break;
         default:
            break;
      }
   }
}

void init_conn_map(mmb_main_t *mm,
                   mmb_conn_t *conn,
                   mmb_rule_t *rule) {
   mmb_target_t *target;

   vec_foreach(target, rule->map_targets) {
      switch (target->field) {
         case MMB_FIELD_TCP_SPORT:
         case MMB_FIELD_UDP_SPORT:
            conn->sport = clib_host_to_net_u16((u16) bytes_to_u32(target->value));
            conn->initial_sport = clib_host_to_net_u16(conn->info.l4.port[0]);
            break;
         case MMB_FIELD_TCP_DPORT:
         case MMB_FIELD_UDP_DPORT:
            conn->dport = clib_host_to_net_u16((u16) bytes_to_u32(target->value));
            conn->initial_dport = clib_host_to_net_u16(conn->info.l4.port[1]);
            break;
         case MMB_FIELD_IP4_SADDR:
            conn->saddr.ip4.as_u32 = clib_host_to_net_u32(bytes_to_u32(target->value));
            conn->initial_saddr.as_u64[0] = conn->info.addr[0].as_u64[0];
            conn->initial_saddr.as_u64[1] = conn->info.addr[0].as_u64[1];
            break;
        case MMB_FIELD_IP4_DADDR:
            conn->daddr.ip4.as_u32 = clib_host_to_net_u32(bytes_to_u32(target->value));
            conn->initial_daddr.as_u64[0] = conn->info.addr[1].as_u64[0];
            conn->initial_daddr.as_u64[1] = conn->info.addr[1].as_u64[1];
            break;
         case MMB_FIELD_IP6_SADDR:
            conn->saddr.as_u64[0] = clib_host_to_net_u64(bytes_to_u64(target->value));
            conn->saddr.as_u64[1] = clib_host_to_net_u64(bytes_to_u64(target->value+8));
            conn->initial_saddr.as_u64[0] = conn->info.addr[0].as_u64[0];
            conn->initial_saddr.as_u64[1] = conn->info.addr[0].as_u64[1];
            break;
         case MMB_FIELD_IP6_DADDR:
            conn->daddr.as_u64[0] = clib_host_to_net_u64(bytes_to_u64(target->value) );
            conn->daddr.as_u64[1] = clib_host_to_net_u64(bytes_to_u64(target->value+8));
            conn->initial_daddr.as_u64[0] = conn->info.addr[1].as_u64[0];
            conn->initial_daddr.as_u64[1] = conn->info.addr[1].as_u64[1];
            break;
         case MMB_FIELD_IP4_ID :
            conn->ip_id = random_u32(&mm->random_seed);
            break;
         case MMB_FIELD_IP6_FLOW_LABEL:
            conn->ip_id = random_u32(&mm->random_seed);
            break;
         default:
            break;
      }
   }
}

mmb_conn_t *mmb_add_conn(mmb_conn_table_t *mct, mmb_5tuple_t *pkt_5tuple,
                  u32 *matches_stateful, u64 now) {

   mmb_main_t *mm = &mmb_main;
   mmb_conn_id_t conn_id;
   mmb_5tuple_t conn_key;
   mmb_conn_t *conn;
   mmb_rule_t *rule;
   u32 *match;

   /* init connection state*/
   pool_get(mct->conn_pool, conn);
   memset(conn, 0, sizeof(*conn));
   conn_id.conn_index = conn - mct->conn_pool;
   clib_memcpy(conn, pkt_5tuple, sizeof(pkt_5tuple->kv.key));
   conn->last_active_time = now;
   conn->rule_indexes = vec_dup(matches_stateful);
   conn->tcp_flags_seen.as_u16 = 0;
   if (pkt_5tuple->pkt_info.tcp_flags_valid)
      conn->tcp_flags_seen.as_u8[0] = pkt_5tuple->pkt_info.tcp_flags;

   /* init connection from matched rules */
   conn->next = MMB_CLASSIFY_NEXT_INDEX_MISS;
   vec_foreach(match, matches_stateful) {
      rule = mm->rules + *match;

      if (rule->shuffle)
         init_conn_shuffle(mm, conn, rule);
      if (rule->map)
         init_conn_map(mm, conn, rule);

      if (rule->accept)
         conn->accept = 1;
      if (rule->rewrite)
         conn->next = MMB_CLASSIFY_NEXT_INDEX_MATCH;
   }

   /* adding forward 5tuple */
   copy_forward_5tuple(&conn_key, conn);
   conn_key.kv.value = conn_id.as_u64;
   mmb_add_5tuple(mct, &conn_key.kv);

   /* adding backward 5tuple */
   copy_reverse_5tuple(&conn_key, conn);
   conn_id.dir = 1;
   conn_key.kv.value = conn_id.as_u64; // TODO: replace with bitwise operation
   mmb_add_5tuple(mct, &conn_key.kv);

   /* put conn_index in 5tuple for the classify node */
   pkt_5tuple->pkt_info.conn_index = conn_id.conn_index;

   return conn;
}

void mmb_track_conn(mmb_conn_t *conn, mmb_5tuple_t *pkt_5tuple, u8 dir, u64 now) {

  conn->last_active_time = now;
  if (pkt_5tuple->pkt_info.tcp_flags_valid) {
      conn->tcp_flags_seen.as_u8[dir] |= pkt_5tuple->pkt_info.tcp_flags;
  }
}

static_always_inline int offset_within_packet(vlib_buffer_t *b0, int offset) {
  /* For the purposes of this code, "within" means we have at least 8 bytes after it */
  return (offset <= (b0->current_length - 8));
}

void mmb_fill_5tuple(vlib_buffer_t *b0, u8 *h0, int is_ip6, mmb_5tuple_t *pkt_5tuple) {

   int l4_offset;
   u16 ports[2];
   u16 proto;

   pkt_5tuple->kv.key[4] = 0;
   pkt_5tuple->kv.key[5] = 0; // TODO: drop when going from 48_8 to 40_8 
   pkt_5tuple->kv.value = 0;

   if (is_ip6) {
      clib_memcpy (&pkt_5tuple->addr, h0 + offsetof(ip6_header_t,src_address),
		             sizeof(pkt_5tuple->addr));
      proto = *(u8 *) (h0 + offsetof(ip6_header_t, protocol));

      l4_offset = sizeof(ip6_header_t);
      // TODO: skip extension headers
   } else { /* ip4 */
      pkt_5tuple->kv.key[0] = 0;
      pkt_5tuple->kv.key[1] = 0;
      pkt_5tuple->kv.key[2] = 0;
      pkt_5tuple->kv.key[3] = 0;
      clib_memcpy(&pkt_5tuple->addr[0].ip4, h0 + offsetof(ip4_header_t,src_address),
		             sizeof(pkt_5tuple->addr[0].ip4));
      clib_memcpy(&pkt_5tuple->addr[1].ip4, h0 + offsetof(ip4_header_t,dst_address),
		             sizeof(pkt_5tuple->addr[1].ip4));
      proto = *(u8 *)(h0 + offsetof(ip4_header_t,protocol));
      l4_offset = sizeof(ip4_header_t);

      // TODO: handle nonfirst fragments here
   }

   pkt_5tuple->l4.proto = proto;
   if (PREDICT_TRUE(offset_within_packet(b0, l4_offset))) {

      if ((proto == IPPROTO_TCP) || (proto == IPPROTO_UDP)) {

	     clib_memcpy(&ports, h0 + l4_offset + offsetof(tcp_header_t, src_port),
		               sizeof(ports));
        // TODO: do not translates ports in conn table
	     pkt_5tuple->l4.port[0] = ntohs(ports[0]);
	     pkt_5tuple->l4.port[1] = ntohs(ports[1]);

	     pkt_5tuple->pkt_info.tcp_flags = *(u8 *)(h0 + l4_offset + offsetof(tcp_header_t, flags));
	     pkt_5tuple->pkt_info.tcp_flags_valid = (proto == IPPROTO_TCP);
        pkt_5tuple->pkt_info.l4_valid = 1;
	   } else if ((proto == IP_PROTOCOL_ICMP) || (proto == IP_PROTOCOL_ICMP6)) {

        // TODO: match icmp quoted packet here
        pkt_5tuple->l4.port[0] =
           *(u8 *) (h0 + l4_offset + offsetof(icmp46_header_t, type));
        pkt_5tuple->l4.port[1] =
           *(u8 *) (h0 + l4_offset + offsetof(icmp46_header_t, code));
        pkt_5tuple->pkt_info.l4_valid = 1;
        pkt_5tuple->pkt_info.is_quoted_packet = 1;
      }
   }
}

void mmb_conn_hash_init() {
   mmb_conn_table_t *mct = &mmb_conn_table;

   if (!mct->conn_hash_is_initialized) {
      BV (clib_bihash_init) (&mct->conn_hash, "MMB plugin conn lookup",
                             MMB_CONN_TABLE_DEFAULT_HASH_NUM_BUCKETS,
                             MMB_CONN_TABLE_DEFAULT_HASH_MEMORY_SIZE);
      mct->conn_hash_is_initialized = 1;
   }

}

clib_error_t *mmb_conn_table_init(vlib_main_t *vm) {

   clib_error_t *error = 0;
   mmb_conn_table_t *mct = &mmb_conn_table;
   memset (mct, 0, sizeof (mmb_conn_table_t));

   mct->timeouts_value[MMB_TIMEOUT_TCP_TRANSIENT] = TCP_SESSION_TRANSIENT_TIMEOUT_SEC;
   mct->timeouts_value[MMB_TIMEOUT_TCP_IDLE] = TCP_SESSION_IDLE_TIMEOUT_SEC;
   mct->timeouts_value[MMB_TIMEOUT_UDP_IDLE] = UDP_SESSION_IDLE_TIMEOUT_SEC;

   return error;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
