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
 * connection tables.
 *
 * Author: Korian Edeline
 */

#ifndef __included_mmb_conn_h__
#define __included_mmb_conn_h__

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>

#include <stddef.h>
#include <vppinfra/bihash_48_8.h>
#include <vppinfra/error.h>

#define MMB_CONN_TABLE_DEFAULT_HASH_NUM_BUCKETS (64 * 1024)
#define MMB_CONN_TABLE_DEFAULT_HASH_MEMORY_SIZE (1<<30)
#define MMB_CONN_TABLE_DEFAULT_MAX_ENTRIES 1000000

enum mmb_timeout_e {
  MMB_TIMEOUT_UDP_IDLE = 0,
  MMB_TIMEOUT_TCP_IDLE,
  MMB_TIMEOUT_TCP_TRANSIENT,
  MMB_N_TIMEOUTS
};

typedef union {
  u64 as_u64;
  struct {
    u16 port[2];
    u16 proto;
    u16 unused;
  };
} mmb_conn_l4_key_t;

typedef union {
  u64 as_u64;
  struct {
    u32 unused1;
    u16 unused2;
    u8 tcp_flags;
    u8 tcp_flags_valid:1;
    u8 is_input:1;
    u8 l4_valid:1;
    u8 is_nonfirst_fragment:1;
    u8 is_ip6:1;
    u8 flags_reserved:3;
  };
} mmb_packet_info_t;

/*
 * ip4 5tuple: saddr (4) + daddr (4) + protocol (1) + sport (2) + dport (2) = 13
 * ip6 5tuple: saddr (16) + daddr (16) + protocol (1) + sport (2) + dport (2) = 37
 * would fit in bihash_40_8 
 */
typedef union {
  struct {
    ip46_address_t addr[2]; // 32
    mmb_conn_l4_key_t l4; // 8
    u64 unused; // 8
    /* This field should align with u64 value in bihash_48_8 keyvalue struct */
    mmb_packet_info_t pkt_info;
  };
  clib_bihash_kv_48_8_t kv; 
} mmb_5tuple_t;

typedef struct {
  mmb_5tuple_t info; /* 56 */
} mmb_conn_t;

typedef struct {
  mmb_conn_t *conn_pool;   /* connection pool */

  int conn_hash_is_initialized;   /* bihash for connections index lookup */
  clib_bihash_48_8_t conn_hash; /* XXX replace with bihash_40_8 */

  /* conn table parameters XXX: move out of this struct*/
  u32 conn_table_hash_num_buckets;
  uword conn_table_hash_memory_size;
  u64 conn_table_max_entries; 

} mmb_conn_table_t;

mmb_conn_table_t mmb_conn_table;


/** 
 * mmb_fill_5tuple
 *
 * extract 5tuple from packet
 */
void mmb_fill_5tuple(vlib_buffer_t *b0, int is_ip6, mmb_5tuple_t *pkt_5tuple);

void mmb_print_5tuple(mmb_5tuple_t *pkt_5tuple);


/**
 *
 *
 */
clib_error_t *mmb_conn_table_init(vlib_main_t *vm);

/**
 *
 *
 */
void mmb_conn_hash_init();

#endif
