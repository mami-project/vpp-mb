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
 */
/*
 *------------------------------------------------------------------
 * mmb_test.c - test harness plugin
 *------------------------------------------------------------------
 */

#include <vat/vat.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
/*#include <vlibsocket/api.h>*/
#include <vppinfra/error.h>

#define __plugin_msg_base mmb_test_main.msg_id_base
#include <vlibapi/vat_helper_macros.h>

uword unformat_sw_if_index (unformat_input_t * input, va_list * args);

/* Declare message IDs */
#include <mmb/mmb_msg_enum.h>

/* define message structures */
#define vl_typedefs
#include <mmb/mmb_all_api_h.h> 
#undef vl_typedefs

/* declare message handlers for each api */

#define vl_endianfun             /* define message structures */
#include <mmb/mmb_all_api_h.h> 
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...)
#define vl_printfun
#include <mmb/mmb_all_api_h.h> 
#undef vl_printfun

/* Get the API version number. */
#define vl_api_version(n,v) static u32 api_version=(v);
#include <mmb/mmb_all_api_h.h>
#undef vl_api_version


typedef struct {
    /* API message ID base */
    u16 msg_id_base;
    vat_main_t *vat_main;
} mmb_test_main_t;

mmb_test_main_t mmb_test_main;

#define foreach_standard_reply_retval_handler  \
_(mmb_table_flush_reply)                       \
_(mmb_remove_rule_reply)

#define _(n)                                            \
    static void vl_api_##n##_t_handler                  \
    (vl_api_##n##_t * mp)                               \
    {                                                   \
        vat_main_t * vam = mmb_test_main.vat_main;   \
        i32 retval = ntohl(mp->retval);                 \
        if (vam->async_mode) {                          \
            vam->async_errors += (retval < 0);          \
        } else {                                        \
            vam->retval = retval;                       \
            vam->result_ready = 1;                      \
        }                                               \
    }
foreach_standard_reply_retval_handler;
#undef _

/* 
 * Table of message reply handlers, must include boilerplate handlers
 * we just generated
 */
#define foreach_vpe_api_reply_msg                \
_(MMB_TABLE_FLUSH_REPLY, mmb_table_flush_reply)  \
_(MMB_REMOVE_RULE_REPLY, mmb_remove_rule_reply)


static int api_mmb_table_flush(vat_main_t *vam)
{
  vl_api_mmb_table_flush_t *mp;
  int ret = 0;

  /* Construct the API message */
  M(MMB_TABLE_FLUSH, mp);

  /* send it... */
  S(mp);

  /* Wait for a reply... */
  W(ret);
  return ret;
}

static int api_mmb_remove_rule(vat_main_t *vam)
{
  unformat_input_t *i = vam->input;
  vl_api_mmb_remove_rule_t *mp;
  u32 rule_num;
  int ret = 0;

  if (!unformat(i, "%u", &rule_num))
  {
    errmsg ("rule number must be an integer greater than 0\n");
    return -1;
  }
    
  /* Construct the API message */
  M(MMB_REMOVE_RULE, mp);
  mp->rule_num = ntohl(rule_num);

  /* send it... */
  S(mp);

  /* Wait for a reply... */
  W(ret);
  return ret;
}

/* 
 * List of messages that the api test plugin sends,
 * and that the data plane plugin processes
 */
#define foreach_vpe_api_msg         \
_(mmb_table_flush, "")              \
_(mmb_remove_rule, "<rule_index>")

static void mmb_api_hookup (vat_main_t *vam)
{
    mmb_test_main_t * mm = &mmb_test_main;
    /* Hook up handlers for replies from the data plane plug-in */
#define _(N,n)                                                  \
    vl_msg_api_set_handlers((VL_API_##N + mm->msg_id_base),     \
                           #n,                                  \
                           vl_api_##n##_t_handler,              \
                           vl_noop_handler,                     \
                           vl_api_##n##_t_endian,               \
                           vl_api_##n##_t_print,                \
                           sizeof(vl_api_##n##_t), 1); 
    foreach_vpe_api_reply_msg;
#undef _

    /* API messages we can send */
#define _(n,h) hash_set_mem (vam->function_by_name, #n, api_##n);
    foreach_vpe_api_msg;
#undef _    
    
    /* Help strings */
#define _(n,h) hash_set_mem (vam->help_by_name, #n, h);
    foreach_vpe_api_msg;
#undef _
}

clib_error_t * vat_plugin_register (vat_main_t *vam)
{
  mmb_test_main_t * mm = &mmb_test_main;
  u8 * name;

  mm->vat_main = vam;

  name = format (0, "mmb_%08x%c", api_version, 0);
  mm->msg_id_base = vl_client_get_first_plugin_msg_id ((char *) name);

  if (mm->msg_id_base != (u16) ~0)
    mmb_api_hookup (vam);
  
  vec_free(name);
  
  return 0;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
