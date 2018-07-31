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
 * conn table, not to be confused with classifier conn.
 *
 * Author: Korian Edeline
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

/**
 * get_conn_timeout_time
 * 
 * return absolute ticks timeout value of conn
 */
static_always_inline u64 get_conn_timeout_time(mmb_conn_table_t *mct, mmb_conn_t *conn) {

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
   pool_foreach(conn, mct->conn_pool, ({
      timeout_time = get_conn_timeout_time(mct, conn);

      /* timeout */
      if (now > timeout_time) 
         vec_add1(purge_indexes, conn - mct->conn_pool);

   }));  

   purge_conn(mct, purge_indexes);

   mct->currently_handling_connections = 0;
   return 1;
}

void purge_conn(mmb_conn_table_t *mct, u32 *purge_indexes) {

   mmb_conn_t *conn;
   mmb_5tuple_t conn_key;
   u32 *purge_index;

   vec_foreach(purge_index, purge_indexes) {

      conn = pool_elt_at_index(mct->conn_pool, *purge_index);

      /* purge bihash */
      conn_key.kv.key[0] = conn->info.kv.key[0];
      conn_key.kv.key[1] = conn->info.kv.key[1];
      conn_key.kv.key[2] = conn->info.kv.key[2];
      conn_key.kv.key[3] = conn->info.kv.key[3];
      conn_key.kv.key[4] = conn->info.kv.key[4];
      conn_key.kv.key[5] = conn->info.kv.key[5];
      mmb_del_5tuple(mct, &conn_key.kv);

      /* XXX: make an inline function */
      conn_key.addr[0] = conn->info.addr[1];
      conn_key.addr[1] = conn->info.addr[0];
      conn_key.l4.port[0] = conn->dport ? ntohs(conn->dport) : pkt_5tuple->l4.port[1];
      conn_key.l4.port[1] = conn->sport ? ntohs(conn->sport) : pkt_5tuple->l4.port[0]; 
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

void purge_conn_index(mmb_conn_table_t *mct, u32 rule_index) {

   mmb_conn_t *conn;
   u32 *purge_indexes = 0, index_of_index;   

   wait_and_lock_connection_handling(mct);

   /* remove rule_index from connections */
   pool_foreach(conn, mct->conn_pool, ({

      index_of_index = vec_find(conn->rule_indexes, rule_index);
      if (index_of_index == ~0)
         continue;

      if (vec_len(conn->rule_indexes) == 1) {
         vec_add1(purge_indexes, conn - mct->conn_pool);
         vec_free(conn->rule_indexes);
      } else { /* conn still used by other rules */
         vec_delete(conn->rule_indexes, 1, index_of_index);
      }

   }));
   
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

   pool_foreach(conn, mct->conn_pool, ({

      vec_foreach(current_rule_index, conn->rule_indexes) {
         if (*current_rule_index > rule_index) 
            (*current_rule_index)--;
      }
   }));
}

/**
 * random_bounded_u16()
 *
 * @return random u16 in [lo; hi+1]
 */
static_always_inline u16 random_bounded_u16(u32 *seed, uword lo, uword hi) {
   if (lo == hi)  
      return lo;

   return (u16) ((random_u32(seed) % (hi - lo + 1)) + lo);
}

/**
 * init_conn_shuffle_seed()
 *
 * init shuffle mapping offset
 */
static_always_inline void init_conn_shuffle_seed(mmb_main_t *mm,
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
            break;
         case MMB_FIELD_TCP_DPORT:
         case MMB_FIELD_UDP_DPORT:
            conn->dport = clib_host_to_net_u16(
                            (u16) random_bounded_u16(&mm->random_seed, 
                               MMB_MIN_SHUFFLE_PORT, MMB_MAX_SHUFFLE_PORT-1));
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


void mmb_add_conn(mmb_conn_table_t *mct, mmb_5tuple_t *pkt_5tuple, 
                  u32 *matches_stateful, u32 *matches_shuffle, u64 now) {

   mmb_main_t *mm = &mmb_main;
   mmb_conn_id_t conn_id;
   mmb_5tuple_t conn_key;
   mmb_conn_t *conn;
   mmb_rule_t *rule;
   u32 *match;

   pool_get(mct->conn_pool, conn);
   memset(conn, 0, sizeof(*conn));
   conn_id.conn_index = conn - mct->conn_pool;

   /* adding forward 5tuple */
   conn_key.kv.key[0] = pkt_5tuple->kv.key[0];
   conn_key.kv.key[1] = pkt_5tuple->kv.key[1];
   conn_key.kv.key[2] = pkt_5tuple->kv.key[2];
   conn_key.kv.key[3] = pkt_5tuple->kv.key[3];
   conn_key.kv.key[4] = pkt_5tuple->kv.key[4];
   conn_key.kv.key[5] = pkt_5tuple->kv.key[5];
   conn_key.kv.value = conn_id.as_u64; 
   mmb_add_5tuple(mct, &conn_key.kv);  

   /* init connection state*/
   clib_memcpy(conn, pkt_5tuple, sizeof(pkt_5tuple->kv.key));
   conn->last_active_time = now;
   conn->rule_indexes = vec_dup(matches_stateful);
   conn->tcp_flags_seen.as_u16 = 0;
   if (pkt_5tuple->pkt_info.tcp_flags_valid) 
      conn->tcp_flags_seen.as_u8[0] = pkt_5tuple->pkt_info.tcp_flags;

   /* init shuffle offset if needed */
   vec_foreach(match, matches_shuffle) {
      rule = mm->rules + *match;
      init_conn_shuffle_seed(mm, conn, rule);
   }

   /* adding backward 5tuple */
   conn_key.addr[0] = pkt_5tuple->addr[1];
   conn_key.addr[1] = pkt_5tuple->addr[0];
   conn_key.l4.port[0] = conn->dport ? ntohs(conn->dport) : pkt_5tuple->l4.port[1];
   conn_key.l4.port[1] = conn->sport ? ntohs(conn->sport) : pkt_5tuple->l4.port[0]; 
   conn_id.dir = 1;
   conn_key.kv.value = conn_id.as_u64; 
   conn_id.dir = 0; /* XXX replace with & */
   mmb_add_5tuple(mct, &conn_key.kv);

   /* put conn_index in 5tuple for the classify node */
   pkt_5tuple->pkt_info.conn_index = conn_id.conn_index; 
}

void mmb_track_conn(mmb_conn_t *conn, mmb_5tuple_t *pkt_5tuple, u8 dir, u64 now) {

  conn->last_active_time = now;
  if (pkt_5tuple->pkt_info.tcp_flags_valid) {
      /* */
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
   pkt_5tuple->kv.key[5] = 0; /*XXX 48_8*/
   pkt_5tuple->kv.value = 0;

   if (is_ip6) {
      clib_memcpy (&pkt_5tuple->addr, h0 + offsetof(ip6_header_t,src_address),
		             sizeof(pkt_5tuple->addr));
      proto = *(u8 *) (h0 + offsetof(ip6_header_t, protocol));

      l4_offset = sizeof(ip6_header_t);
      /* XXX skip extension headers */
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

      /** XXX handle nonfirst fragments here */
   }

   pkt_5tuple->l4.proto = proto;
   if (PREDICT_TRUE(offset_within_packet(b0, l4_offset))) {

      if ((proto == IPPROTO_TCP) || (proto == IPPROTO_UDP)) {

	     clib_memcpy(&ports, h0 + l4_offset + offsetof(tcp_header_t, src_port),
		               sizeof(ports));
	     pkt_5tuple->l4.port[0] = ntohs(ports[0]);
	     pkt_5tuple->l4.port[1] = ntohs(ports[1]);

	     pkt_5tuple->pkt_info.tcp_flags = *(u8 *)(h0 + l4_offset + offsetof(tcp_header_t, flags));
	     pkt_5tuple->pkt_info.tcp_flags_valid = (proto == IPPROTO_TCP);
        pkt_5tuple->pkt_info.l4_valid = 1;
	   } else if ((proto == IP_PROTOCOL_ICMP) || (proto == IP_PROTOCOL_ICMP6)) {
         

        /** XXX match quoted packet here */
        pkt_5tuple->l4.port[0] =
           *(u8 *) (h0 + l4_offset + offsetof(icmp46_header_t, type));
        pkt_5tuple->l4.port[1] =
           *(u8 *) (h0 + l4_offset + offsetof(icmp46_header_t, code));
        pkt_5tuple->pkt_info.l4_valid = 1;
        pkt_5tuple->pkt_info.is_quoted_packet = 1;
      }
   }
}

void mmb_print_5tuple(mmb_5tuple_t* pkt_5tuple) {
   mmb_main_t *mm = &mmb_main;

   vl_print(mm->vlib_main, 
     "5-tuple %016llx %016llx %016llx %016llx %016llx : %016llx",
     pkt_5tuple->kv.key[0], pkt_5tuple->kv.key[1], pkt_5tuple->kv.key[2],
     pkt_5tuple->kv.key[3], pkt_5tuple->kv.key[4], pkt_5tuple->kv.value);
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
