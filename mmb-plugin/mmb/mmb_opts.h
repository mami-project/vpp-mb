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
 * Author: Korian Edeline, Justin Iurman
 */
#ifndef __included_mmb_opts_h__
#define __included_mmb_opts_h__

typedef struct {
  u8 is_stripped:1; // flag to tell if this option has been stripped
  u8 offset;        // real offset in the pkt data
  u8 data_length;   // length of data
  u8 *new_value;    // new value if modified
} mmb_tcp_option_t;

typedef struct {
  uword *found;             // bitmap 255 bits (options 0-254)
  u8 *idx;                  // parsed vector's position of an option
  mmb_tcp_option_t *parsed; // parsed options vector (in parsing order)
  u8 *data;                 // pointer to the pkt data
} mmb_tcp_options_t;

u8 mmb_parse_tcp_options(tcp_header_t *, mmb_tcp_options_t *);

static_always_inline void init_tcp_options(mmb_tcp_options_t *options) {
  memset(options, 0, sizeof(mmb_tcp_options_t));
  vec_validate(options->idx, 254);
  clib_bitmap_alloc(options->found, 255);
}

static_always_inline u8 tcp_option_exists(mmb_tcp_options_t *options, u8 kind) {
  return clib_bitmap_get_no_check(options->found, kind);
}

static_always_inline u8 mmb_padding_tcp_options(u8 *data, u8 offset) {

  // Terminate TCP options
  if (offset % 4)
    data[offset++] = TCP_OPTION_EOL;

  // Padding to reach a u32 boundary
  while(offset % 4)
    data[offset++] = TCP_OPTION_NOOP;

  return offset;
  //TODO is this the right way vpp uses ? 
  //From my understanding, NOOPs should fill extra bits to align options on boundaries (not necessarily at the end)...
}

static_always_inline void free_tcp_options(mmb_tcp_options_t *options) {
  vec_free(options->idx);
  vec_free(options->parsed);
  clib_bitmap_free(options->found);
}

#endif

