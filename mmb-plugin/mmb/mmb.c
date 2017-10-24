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
/**
 * @file
 * @brief MMB Plugin, plugin API / trace / CLI handling.
 * @author J.Iurman K.Edeline
 */

#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <mmb/mmb.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>
/*#include <vlibsocket/api.h>*/

/* define message IDs */
#include <mmb/mmb_msg_enum.h>

/* define message structures */
#define vl_typedefs
#include <mmb/mmb_all_api_h.h> 
#undef vl_typedefs

/* define generated endian-swappers */
#define vl_endianfun
#include <mmb/mmb_all_api_h.h> 
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#define vl_printfun
#include <mmb/mmb_all_api_h.h> 
#undef vl_printfun

/* Get the API version number */
#define vl_api_version(n,v) static u32 api_version=(v);
#include <mmb/mmb_all_api_h.h>
#undef vl_api_version

#define REPLY_MSG_ID_BASE sm->msg_id_base
#include <vlibapi/api_helper_macros.h>

/* List of message types that this plugin understands */

#define foreach_mmb_plugin_api_msg

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () = {
    .version = MMB_PLUGIN_BUILD_VER,
    .description = "Modular Middlebox",
};
/* *INDENT-ON* */

#define MMB_DEFAULT_MATCH_CONDITION MMB_COND_EQ

static u8 fields_len = 58;
static char* fields[] = {
  "net-proto", "ip-ver", "ip-ihl",
  "ip-dscp", "ip-ecn", "ip-non-ect",
  "ip-ect0", "ip-ect1", "ip-ce",
  "ip-len", "ip-id", "ip-flags",
  "ip-res", "ip-df", "ip-mf",
  "ip-frag-offset", "ip-ttl", "ip-proto",
  "ip-checksum", "ip-saddr", "ip-daddr",
  "icmp-type", "icmp-code", "icmp-checksum",
  "icmp-payload", "udp-sport", "udp-dport",
  "udp-len", "udp-checksum", "udp-payload",
  "tcp-sport", "tcp-dport", "tcp-seq-num",
  "tcp-ack-num", "tcp-offset", "tcp-reserved",
  "tcp-urg-ptr", "tcp-cwr", "tcp-ece", 
  "tcp-urg", "tcp-ack", "tcp-push", 
  "tcp-res", "tcp-syn", "tcp-fin", 
  "tcp-flags", "tcp-win", "tcp-checksum", 
  "tcp-payload",  "tcp-opt-mss", "tcp-opt-wscale", 
  "tcp-opt-sackp", "tcp-opt-sack", "tcp-opt-timestamp", 
  "tcp-opt-fast-open", "tcp-opt-mptcp", "tcp-opt",
  "all"
};

static u8 conditions_len = 6;
static char* conditions[] = {"==", "!=", "<=", ">=", "<", ">"};

static u8 parse_match(unformat_input_t * input, mmb_match_t *match);
static u8 parse_target(unformat_input_t * input, mmb_target_t *target);
static void print_match(vlib_main_t * vm, mmb_match_t *match);
static void print_target(vlib_main_t * vm, mmb_target_t *target);
static u8* field_tostr(u8 field, u8 kind);
static char* condition_tostr(u8 condition);
static char* keyword_tostr(u8 keyword);
static uword unformat_field(unformat_input_t * input, va_list * va);
static uword unformat_condition(unformat_input_t * input, va_list * va);
static uword unformat_value(unformat_input_t * input, va_list * va);

static clib_error_t *
enable_command_fn (vlib_main_t * vm,
                   unformat_input_t * input,
                   vlib_cli_command_t * cmd)
{
  if (!unformat_is_eof(input))
    return clib_error_return(0, "Syntax error: unexpected additional element");

  //TODO: enable
  return 0;
}

static clib_error_t *
disable_command_fn (vlib_main_t * vm,
                   unformat_input_t * input,
                   vlib_cli_command_t * cmd)
{
  if (!unformat_is_eof(input))
    return clib_error_return(0, "Syntax error: unexpected additional element");

  //TODO: disable
  return 0;
}

static clib_error_t *
display_rules_command_fn (vlib_main_t * vm,
                          unformat_input_t * input,
                          vlib_cli_command_t * cmd)
{
  if (!unformat_is_eof(input))
    return clib_error_return(0, "Syntax error: unexpected additional element");

  //TODO: display all rules
  return 0;
}

uword unformat_field(unformat_input_t * input, va_list * va)
{
  u8 *field = va_arg (*va, u8*);
  u8 *kind  = va_arg (*va, u8*);
  for (u8 i=0; i<fields_len; i++) {
    if (unformat (input, fields[i])) {
      *field = MMB_FIELD_NET_PROTO+i;
 
      /* optional kind */
      if (*field == MMB_FIELD_TCP_OPT
          && unformat(input, "%d", kind) 
          && unformat(input, "x%x", kind))
        ;
      return 1;
    }
  }

  return 0;
}

uword unformat_condition(unformat_input_t * input, va_list * va)
{
  u8 *cond = va_arg (*va, u8*);
  for (u8 i=0; i<conditions_len; i++) {
    if (unformat (input, conditions[i])) {
      *cond = MMB_COND_EQ+i;
      return 1;
    }
  }

  return 0;
}

uword unformat_value(unformat_input_t * input, va_list * va)
{
  u8 **hex_value = va_arg (*va, u8**);
  if (unformat (input, "0x%U", unformat_hex_string, hex_value))
    ;
  else if (unformat (input, "x%U", unformat_hex_string, hex_value))
    ; 
  else if (unformat (input, "%U", unformat_hex_string, hex_value))
    ;
  else {
    /* try adding a single hex digit
    TODO: this is a hack, fix it or secure it.
    */
    unformat_put_input(input);
    input->buffer[input->index] = '0';
    if (!unformat (input, "%U", unformat_hex_string, hex_value))
      return 0;
  }

  return 1;
}

u8* field_tostr(u8 field, u8 kind) 
{
   if (field < MMB_FIELD_NET_PROTO 
    || field > MMB_FIELD_NET_PROTO+fields_len)
     return NULL;

   u8 field_index = field-MMB_FIELD_NET_PROTO;
   u8 * field_str = format(0, "");
   if (field == MMB_FIELD_TCP_OPT && kind) {
     field_str = format(field_str, "%s %d", fields[field_index], kind);
   } else
     field_str = format(field_str, "%s", fields[field_index]);

   vec_terminate_c_string(field_str);
   return field_str;
}

char* condition_tostr(u8 condition) 
{
   if (condition < MMB_COND_EQ 
    || condition > MMB_COND_EQ+conditions_len)
     return NULL;
   return conditions[condition-MMB_COND_EQ];
}

char* keyword_tostr(u8 keyword) 
{
   switch(keyword) {
      case MMB_TARGET_DROP:
         return "drop";
      case MMB_TARGET_MODIFY:
         return "mod";
      case MMB_TARGET_STRIP:
         return "strip";
      default:
         return NULL;
   }
}

u8 parse_target(unformat_input_t * input, mmb_target_t *target) 
{
   if (unformat(input, "strip ! %U", unformat_field, 
               &target->field, &target->opt_kind)) {
     target->keyword=MMB_TARGET_STRIP;
     target->reverse=1;
   } else if (unformat(input, "strip %U", unformat_field, 
                      &target->field, &target->opt_kind)) 
     target->keyword=MMB_TARGET_STRIP;
   else if (unformat(input, "mod %U %U", unformat_field, 
                    &target->field, &target->opt_kind, 
                    unformat_value, &target->value))
     target->keyword=MMB_TARGET_MODIFY; 
   else if (unformat(input, "drop"))
     target->keyword=MMB_TARGET_DROP; 
   else 
     return 0;
   return 1;
}

u8 parse_match(unformat_input_t * input, mmb_match_t *match) 
{
   if (unformat(input, "!"))
     match->reverse = 1;

   if (unformat(input, "%U %U %U", unformat_field, 
                    &match->field, &match->opt_kind, unformat_condition, 
                    &match->condition, unformat_value, &match->value)) 
     ;
   else if (unformat(input, "%U %U", unformat_field, 
                    &match->field, &match->opt_kind, 
                    unformat_value, &match->value)) 
     match->condition = MMB_DEFAULT_MATCH_CONDITION;
   else if (unformat(input, "%U", unformat_field, 
                    &match->field, &match->opt_kind)) 
     ;
   else 
     return 0;
   return 1;
}

static clib_error_t *
add_rule_command_fn (vlib_main_t * vm, unformat_input_t * input, 
                     vlib_cli_command_t * cmd)
{
   /* parse matches */
  mmb_match_t *matches = 0, match;
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
  {
    memset(&match, 0, sizeof (mmb_match_t));
    if (!parse_match(input, &match)) 
      break;
    else vec_add1(matches, match);
  } 
  if (vec_len(matches) < 1)
     return clib_error_return (0, "at least one <match> must be set");

  /* parse targets */
  mmb_target_t *targets = 0, target;
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
  {
    memset(&target, 0, sizeof (mmb_target_t));
    if (!parse_target(input, &target)) 
      break;
    else vec_add1(targets, target);
  }

  if (vec_len(targets) < 1)
     return clib_error_return (0, "at least one <target> must be set");

  if (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) {
    return clib_error_return(0, "Could not parse whole input");
  }

  for (int i=0;i<vec_len(matches);i++) 
    print_match(vm, &matches[i]);
  vlib_cli_output(vm, "end of matching");
  vlib_cli_output(vm, "\n");
  for (int i=0;i<vec_len(targets);i++) 
    print_target(vm, &targets[i]);
  vlib_cli_output(vm, "end of targets");
  vlib_cli_output(vm, "\n");

  //TODO validate args
  return 0;
}

void print_match(vlib_main_t * vm, mmb_match_t *match) {
  if (match->reverse)
   vlib_cli_output(vm, "! ");
  u8 *field_str = field_tostr(match->field, match->opt_kind);
  vlib_cli_output(vm, "%s ", field_str);
  if (match->condition)
    vlib_cli_output(vm, "%s ", condition_tostr(match->condition)); 
    for (int i = 0; i < vec_len (match->value); i++)
      vlib_cli_output(vm, "%02x", match->value[i]);
  vlib_cli_output(vm, "\n"); 
}

void print_target(vlib_main_t * vm, mmb_target_t *target) {
  if (target->reverse)
    vlib_cli_output(vm, "! ");
  vlib_cli_output(vm, "%s ", keyword_tostr(target->keyword));
  if (target->field) {;
     u8 *field_str = field_tostr(target->field, target->opt_kind);
     vlib_cli_output(vm, "%s ", field_str);
  } 
  for (int i = 0; i < vec_len (target->value); i++)
    vlib_cli_output(vm, "%02x", target->value[i]);
  vlib_cli_output(vm, "\n"); 
}

static clib_error_t *
del_rule_command_fn (vlib_main_t * vm,
                   unformat_input_t * input,
                   vlib_cli_command_t * cmd)
{
  u32 ruleId;

  if (unformat(input, "%u", &ruleId) && ruleId > 0)
  {
    if (unformat_is_eof(input))
    {
      //TODO: remove rule ruleId
      return 0;
    }

    return clib_error_return(0, "Syntax error: unexpected additional element");
  }

  return clib_error_return(0, "Syntax error: rule number must be an integer greater than 0");
}

/**
 * @brief CLI command to enable the mmb plugin.
 */
VLIB_CLI_COMMAND (sr_content_command_enable, static) = {
    .path = "mmb enable",
    .short_help = "Enable the MMB plugin",
    .function = enable_command_fn,
};

/**
 * @brief CLI command to disable the mmb plugin.
 */
VLIB_CLI_COMMAND (sr_content_command_disable, static) = {
    .path = "mmb disable",
    .short_help = "Disable the MMB plugin",
    .function = disable_command_fn,
};

/**
 * @brief CLI command to list all rules.
 */
VLIB_CLI_COMMAND (sr_content_command_display_rules, static) = {
    .path = "mmb list",
    .short_help = "Display all rules",
    .function = display_rules_command_fn,
};

/**
 * @brief CLI command to add a new rule.
 */
VLIB_CLI_COMMAND (sr_content_command_add_rule, static) = {
    .path = "mmb add",
    .short_help = "Add a rule: mmb add <field> [[<cond>] <value>] [<field> [[<cond>] <value>] ...] <strip <option-field> [strip|mod ...]|mod [<field>] <value> [strip|mod ...]|drop>",
    .function = add_rule_command_fn,
};

/**
 * @brief CLI command to remove a rule.
 */
VLIB_CLI_COMMAND (sr_content_command_del_rule, static) = {
    .path = "mmb del",
    .short_help = "Remove a rule: mmb del <rule-number>",
    .function = del_rule_command_fn,
};

/**
 * @brief Set up the API message handling tables.
 */
static clib_error_t *
mmb_plugin_api_hookup (vlib_main_t *vm)
{
  CLIB_UNUSED(mmb_main_t) * sm = &mmb_main;
#define _(N,n)                                                  \
    vl_msg_api_set_handlers((VL_API_##N + sm->msg_id_base),     \
                           #n,					\
                           vl_api_##n##_t_handler,              \
                           vl_noop_handler,                     \
                           vl_api_##n##_t_endian,               \
                           vl_api_##n##_t_print,                \
                           sizeof(vl_api_##n##_t), 1); 
    foreach_mmb_plugin_api_msg;
#undef _

    return 0;
}

#define vl_msg_name_crc_list
#include <mmb/mmb_all_api_h.h>
#undef vl_msg_name_crc_list

static void 
setup_message_id_table (mmb_main_t * sm, api_main_t *am)
{
#define _(id,n,crc) \
  vl_msg_api_add_msg_name_crc (am, #n "_" #crc, id + sm->msg_id_base);
  foreach_vl_msg_name_crc_mmb;
#undef _
}

/**
 * @brief Initialize the mmb plugin.
 */
static clib_error_t * mmb_init (vlib_main_t * vm)
{
  mmb_main_t * sm = &mmb_main;
  clib_error_t * error = 0;
  u8 * name;

  sm->vnet_main =  vnet_get_main ();

  name = format (0, "mmb_%08x%c", api_version, 0);

  /* Ask for a correctly-sized block of API message decode slots */
  sm->msg_id_base = vl_msg_api_get_msg_ids 
      ((char *) name, VL_MSG_FIRST_AVAILABLE);

  error = mmb_plugin_api_hookup (vm);

  /* Add our API messages to the global name_crc hash table */
  setup_message_id_table (sm, &api_main);

  vec_free(name);

  return error;
}

VLIB_INIT_FUNCTION (mmb_init);

/**
 * @brief Hook the mmb plugin into the VPP graph hierarchy.
 */
//TODO: change values
VNET_FEATURE_INIT (mmb, static) = 
{
  .arc_name = "device-input",
  .node_name = "mmb",
  .runs_before = VNET_FEATURES ("ethernet-input"),
};
