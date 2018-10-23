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
 * connection tables for stateful rules.
 *
 * Author: Korian Edeline
 */

#ifndef __included_mmb_conn_h__
#define __included_mmb_conn_h__

#include <netinet/in.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>

#include <stddef.h>
#include <vppinfra/bihash_48_8.h>
#include <vppinfra/error.h>

/* XXX: add max entries val */
/**
 *
 * min interval for in-node timeout checking of connections.
 */
#define MMB_CONN_TABLE_TIMEOUT_CHECK_INTERVAL_SEC 5

#define MMB_MIN_SHUFFLE_PORT 49152
#define MMB_MAX_SHUFFLE_PORT 65535

#define TCP_FLAGS_RSTFINACKSYN 0x17
#define TCP_FLAGS_ACKSYN 0x12

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
    u32 conn_index;
    u16 unused;
    u8 tcp_flags;
    u8 tcp_flags_valid:1;
    u8 is_quoted_packet:1; /* contains icmp quoted values */
    /* contains enough data to read ports and protocol is supported by conn table */
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
  u64 last_active_time;   /* +8 bytes = 64 */
  u32 *rule_indexes;  /* +4 = 4 */
  union {
    u8 as_u8[2];
    u16 as_u16;
  } tcp_flags_seen;   /* +2 bytes = 6 */

  /* 'shuffle' state */
  u32 tcp_seq_offset;
  u32 tcp_ack_offset;
  u16 sport; /* in network byte order */ 
  u16 initial_sport;
  u16 dport;/* in network byte order */
  u16 initial_dport;
  u32 ip_id; /* +20 = 26 */
  u8 mapped_sack:1;
  u8 unused1:7;/* +1 = 27 */
  u8 unused2; /* +1 = 28 */
  u32 unused3; /* +4 = 32 */
  
  ip46_address_t saddr;
  ip46_address_t initial_saddr;
  ip46_address_t daddr;
  ip46_address_t initial_daddr; /* +64 = 96 */
  u64 unused4[4]; /* + 32 = 128 */
} mmb_conn_t;

typedef struct {
  union {
    u64 as_u64;
    struct {
      u32 conn_index; /* pool indices are 32b */
      u8 dir; /* 0: first seen direction (SYN) 1: other direction (SYNACK) */
      u8 reserved[3];
    };
  };
} mmb_conn_id_t;

typedef struct {
  mmb_conn_t *conn_pool;   /* connection pool */

  int conn_hash_is_initialized;   /* bihash for connections index lookup */
  clib_bihash_48_8_t conn_hash; /* XXX replace with bihash_40_8 */

  /* indicates that the connection checking is in progress */
  u32 currently_handling_connections;

  u32 timeouts_value[3];

} mmb_conn_table_t;

mmb_conn_table_t mmb_conn_table;


/** 
 * mmb_fill_5tuple
 *
 * extract 5tuple from packet
 */
void mmb_fill_5tuple(vlib_buffer_t *b0, u8* h0, int is_ip6, mmb_5tuple_t *pkt_5tuple);


/**
 * mmb_add_conn
 *
 * add a connection to connection hash and pool, set timestamp&rule indices to pool
 *
 * @param matches_stateful contains indexes of all matched stateful rules
 */
void mmb_add_conn(mmb_conn_table_t *mct, mmb_5tuple_t *conn_key, 
                  u32 *matches_stateful, u64 now);

/**
 * mmb_find_conn
 *
 * lookup connection bihash to find if 5tuple is registered
 * if it is, set value of pkt_conn_id to connection_index
 */
int mmb_find_conn(mmb_conn_table_t *mct, mmb_5tuple_t *pkt_5tuple, 
                  clib_bihash_kv_48_8_t *pkt_conn_id);

/**
 * mmb_track_conn
 *
 * update connection state
 */
void mmb_track_conn(mmb_conn_t *conn, mmb_5tuple_t *pkt_5tuple, u8 dir, u64 now);

/** 
 * update_conn_pool
 *
 * update pool when rule_index is deleted 
 **/
void update_conn_pool(mmb_conn_table_t *mct, u32 rule_index);

/**
 * purge_conn_index
 *
 * remove connections that only maps to rule_index
 */
void purge_conn_index(mmb_conn_table_t *mct, u32 rule_index);

/**
 * purge_conn_expired_now
 *
 * remove expired connections that are now expired
 *
 * @return 1 if connections were purged, 0 if not
 */
int purge_conn_expired_now(mmb_conn_table_t *mct);
int purge_conn_expired(mmb_conn_table_t *mct, u64 now);

/**
 * purge_conn_forced
 *
 * purge all entries in connection tables
 */
void purge_conn_forced(mmb_conn_table_t *mct);

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

/**
 * get_conn_timeout_time
 * 
 * return absolute ticks timeout value of conn
 */
u64 get_conn_timeout_time(mmb_conn_table_t *mct, mmb_conn_t *conn);

/**
 * return timestamp of next conn table check time 
 *
 */
inline u64 get_conn_table_check_time(vlib_main_t *vm, u64 last_check) {
   return last_check +
      MMB_CONN_TABLE_TIMEOUT_CHECK_INTERVAL_SEC
      * vm->clib_time.clocks_per_second;
}

inline int get_conn_timeout_type(mmb_conn_table_t *mct, mmb_conn_t *conn) {
  /* seen both SYNs and ACKs but not FIN/RST means we are in establshed state */
  u16 masked_flags =
    conn->tcp_flags_seen.as_u16 & ((TCP_FLAGS_RSTFINACKSYN << 8) +
				   TCP_FLAGS_RSTFINACKSYN);
  switch (conn->info.l4.proto) {
    case IPPROTO_TCP:
      if (((TCP_FLAGS_ACKSYN << 8) + TCP_FLAGS_ACKSYN) == masked_flags)
	      return MMB_TIMEOUT_TCP_IDLE;
      else
	      return MMB_TIMEOUT_TCP_TRANSIENT;
    case IPPROTO_UDP:
      return MMB_TIMEOUT_UDP_IDLE;
    default:
      return MMB_TIMEOUT_UDP_IDLE;
  }
}

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
