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
 * @file mmb_opts.c
 * @brief option parsing
 * @author: Korian Edeline, Justin Iurman
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>

#include <mmb/mmb_opts.h>

u8 mmb_parse_tcp_options(tcp_header_t *tcph, mmb_tcp_options_t *options) {
  u8 offset, opt_len, kind;
  u8 opts_len = (tcp_doff(tcph) << 2) - sizeof(tcp_header_t);

  const u8 *data = (const u8 *)(tcph + 1);
  options->data = (u8 *)(tcph + 1);

  clib_bitmap_zero(options->found);

  if (vec_len(options->parsed) > 0)
    vec_delete(options->parsed, vec_len(options->parsed), 0);

  for(offset = 0; opts_len > 0; opts_len -= opt_len, data += opt_len, offset += opt_len)
  {
    kind = data[0];

    if (kind == TCP_OPTION_EOL)
    {
      break;
    }
    else if (kind == TCP_OPTION_NOOP)
    {
      opt_len = 1;
      continue;
    }
    else
    {
      /* Broken options */
      if (opts_len < 2)
        return 0;

      opt_len = data[1];
      if (opt_len < 2 || opt_len > opts_len)
        return 0;
    }

    mmb_tcp_option_t option;
    option.is_stripped = 0;
    option.offset = offset;
    option.data_length = opt_len-2;
    option.new_value = 0;

    clib_bitmap_set_no_check(options->found, kind, 1);
    vec_add1(options->parsed, option);
    options->idx[kind] = (u8) vec_len(options->parsed)-1;
  }

  return 1;
}



/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
