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

#include <netinet/in.h>

#include <mmb/mmb.h>
#include <mmb/mmb_opts.h>
#include <mmb/mmb_conn.h>

#ifdef MMB_DEBUG
#  define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#else
#  define vl_print(handle, ...) 
#endif

/*****
- extract 5tuple from packet
- match an existing conn
- if matches
   - get conn
   - update state (timer, flags)
   - 
****/

/**
 * mmb_get_5tuple_conn_key
 *
 * fill conn_key with this 5tuple conn key
 */
static void mmb_get_5tuple_conn_key(mmb_5tuple_t *pkt_5tuple, mmb_5tuple_t *conn_key);

/**
 * mmb_get_5tuple_conn_key
 *
 * fill conn_key with this 5tuple conn key
 */
static void mmb_add_conn(mmb_5tuple_t *conn_key, u64 now);

/*static int
acl_mmb_find_conn (acl_main_t * am, u32 sw_if_index0, mmb_5tuple_t * p5tuple,
		     clib_bihash_kv_40_8_t * pvalue_sess)
{
  return (BV (clib_bihash_search)
	  (&am->mmb_conns_hash, &p5tuple->kv,
	   pvalue_sess) == 0);
}*/

//void mmb_add_conn(mmb_5tuple_t *conn_key, u64 now) {
   /** get in conn pool, fill conn, add to bihash **/

 /* BV (clib_bihash_add_del) (&am->mmb_conn_hash,
			    &kv, 1);
}*/

void mmb_get_5tuple_conn_key(mmb_5tuple_t *pkt_5tuple, mmb_5tuple_t *conn_key) {
   return;
}


static_always_inline int offset_within_packet (vlib_buffer_t * b0, int offset)
{
  /* For the purposes of this code, "within" means we have at least 8 bytes after it */
  return (offset <= (b0->current_length - 8));
}

void mmb_fill_5tuple(vlib_buffer_t *b0, int is_ip6, mmb_5tuple_t *pkt_5tuple) {

   int l4_offset;
   u16 ports[2];
   u16 proto;

   pkt_5tuple->kv.key[4] = 0;
   pkt_5tuple->kv.key[5] = 0; /*XXX 48_8*/
   pkt_5tuple->kv.value = 0;

   if (is_ip6) {
      clib_memcpy (&pkt_5tuple->addr, b0 + offsetof(ip6_header_t,src_address),
		             sizeof(pkt_5tuple->addr));
      proto = *(u8 *) (b0 + offsetof(ip6_header_t, protocol));

      l4_offset = sizeof(ip6_header_t);
      /* XXX skip extension headers */
   } else { /* ip4 */
      pkt_5tuple->kv.key[0] = 0;
      pkt_5tuple->kv.key[1] = 0;
      pkt_5tuple->kv.key[2] = 0;
      pkt_5tuple->kv.key[3] = 0;
      clib_memcpy (&pkt_5tuple->addr[0].ip4, b0 + offsetof(ip4_header_t,src_address),
		             sizeof(pkt_5tuple->addr[0].ip4));
      clib_memcpy (&pkt_5tuple->addr[1].ip4, b0 + offsetof(ip4_header_t,dst_address),
		             sizeof(pkt_5tuple->addr[1].ip4));
      proto = *(u8 *)(b0 + offsetof(ip4_header_t,protocol));
      l4_offset = sizeof(ip4_header_t);

      /** XXX handle nonfirst fragments here */
   }

   pkt_5tuple->l4.proto = proto;
   if (PREDICT_TRUE(offset_within_packet(b0, l4_offset))) {
      pkt_5tuple->pkt_info.l4_valid = 1;

      if ((proto == IPPROTO_TCP) || (proto == IPPROTO_UDP)) {
	     clib_memcpy(&ports, b0 + l4_offset + offsetof(tcp_header_t, src_port),
		               sizeof(ports));
	     pkt_5tuple->l4.port[0] = ntohs(ports[0]);
	     pkt_5tuple->l4.port[1] = ntohs(ports[1]);

	     pkt_5tuple->pkt_info.tcp_flags = *(u8 *)(b0 + l4_offset + offsetof(tcp_header_t, flags));
	     pkt_5tuple->pkt_info.tcp_flags_valid = (proto == IPPROTO_TCP);
	   } else if ((proto == IP_PROTOCOL_ICMP) || (proto == IP_PROTOCOL_ICMP6)) {
        /** match quoted packet here */
        pkt_5tuple->l4.port[0] =
          *(u8 *) (b0 + l4_offset + offsetof (icmp46_header_t, type));
        pkt_5tuple->l4.port[1] =
          *(u8 *) (b0 + l4_offset + offsetof (icmp46_header_t, code));
      }
      
   }
}

void mmb_add_conn(mmb_5tuple_t *conn_key, u64 now) {
   return;
}

void mmb_print_5tuple(mmb_5tuple_t* pkt_5tuple) {
   mmb_main_t *mm = &mmb_main;

   vl_print(mm->vlib_main, 
     "5-tuple %016llx %016llx %016llx %016llx %016llx : %016llx",
     pkt_5tuple->kv.key[0], pkt_5tuple->kv.key[1], pkt_5tuple->kv.key[2],
     pkt_5tuple->kv.key[3], pkt_5tuple->kv.key[4], pkt_5tuple->kv.value);
}

void mmb_conn_hash_init() {
   mmb_conn_table_t *mst = &mmb_conn_table;

   if (!mst->conn_hash_is_initialized) {
      BV (clib_bihash_init) (&mst->conn_hash, "MMB plugin conn lookup",
                             mst->conn_table_hash_num_buckets, 
                             mst->conn_table_hash_memory_size);
      mst->conn_hash_is_initialized = 1;
   }

}

clib_error_t *mmb_conn_table_init(vlib_main_t *vm) {
   
   clib_error_t *error = 0;
   mmb_conn_table_t *mst = &mmb_conn_table;
   memset (mst, 0, sizeof (mmb_conn_table_t));

   mst->conn_table_hash_num_buckets = MMB_CONN_TABLE_DEFAULT_HASH_NUM_BUCKETS;
   mst->conn_table_hash_memory_size = MMB_CONN_TABLE_DEFAULT_HASH_MEMORY_SIZE;
   mst->conn_table_max_entries = MMB_CONN_TABLE_DEFAULT_MAX_ENTRIES;
/*

   mst->acl_mheap_size = ACL_FA_DEFAULT_HEAP_SIZE;
   mst->hash_lookup_mheap_size = ACL_PLUGIN_HASH_LOOKUP_HEAP_SIZE;
   mst->hash_lookup_hash_buckets = ACL_PLUGIN_HASH_LOOKUP_HASH_BUCKETS;
   mst->hash_lookup_hash_memory = ACL_PLUGIN_HASH_LOOKUP_HASH_MEMORY;


   
   mst->session_timeout_sec[ACL_TIMEOUT_TCP_TRANSIENT] = TCP_SESSION_TRANSIENT_TIMEOUT_SEC;
   mst->session_timeout_sec[ACL_TIMEOUT_TCP_IDLE] = TCP_SESSION_IDLE_TIMEOUT_SEC;
   mst->session_timeout_sec[ACL_TIMEOUT_UDP_IDLE] = UDP_SESSION_IDLE_TIMEOUT_SEC;

*/
   return error;
}
