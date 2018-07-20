/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
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

#ifndef __included_mmb_classify_h__
#define __included_mmb_classify_h__

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/classify/vnet_classify.h>

#define MMB_CLASSIFY_MAX_MASK_LEN (5*sizeof(u32x4))

typedef enum {
  MMB_CLASSIFY_TABLE_IP4=0,
  MMB_CLASSIFY_TABLE_IP6=1,
  MMB_CLASSIFY_N_TABLES=2,
} mmb_classify_table_id_t;

typedef enum {
  MMB_CLASSIFY_NEXT_INDEX_MATCH,
  MMB_CLASSIFY_NEXT_INDEX_MISS,
  MMB_CLASSIFY_NEXT_INDEX_DROP,
  MMB_CLASSIFY_NEXT_INDEX_N_NEXT,
} mmb_classify_next_index_t;

typedef struct {
  /* Classifier table vectors */
  u32 * classify_table_index_by_sw_if_index [MMB_CLASSIFY_N_TABLES];

  vnet_classify_main_t *vnet_classify_main;
} mmb_classify_main_t;

mmb_classify_main_t mmb_classify_main;

#endif /* __included_mmb_classify_h__ */
