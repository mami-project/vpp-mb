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

#define REPLY_MSG_ID_BASE mm->msg_id_base
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

static uword unformat_field(unformat_input_t * input, va_list * va);
static uword unformat_condition(unformat_input_t * input, va_list * va);
static uword unformat_value(unformat_input_t * input, va_list * va);
static u8 *mmb_format_rule(u8 *s, va_list *args);
static u8 *mmb_format_match(u8 *s, va_list *args);
static u8 *mmb_format_target(u8 *s, va_list *args);
static u8* mmb_format_field(u8 *s, va_list *args);
static u8* mmb_format_condition(u8 *s, va_list *args);
static u8* mmb_format_keyword(u8 *s, va_list *args);

static u8 parse_match(unformat_input_t * input, mmb_match_t *match);
static u8 parse_target(unformat_input_t * input, mmb_target_t *target);
static void mmb_free_rule(mmb_rule_t *rule);

static clib_error_t *validate_rule();
static void print_rules(vlib_main_t * vm, mmb_rule_t *rules);

char *mmb_debug = 0;

/**
 * @brief Enable/disable the mmb plugin. 
 *
 * Action function shared between message handler and debug CLI.
 */

int mmb_enable_disable (mmb_main_t * mm, u32 sw_if_index,
                                   int enable_disable)
{
  vnet_sw_interface_t * sw;
  int rv = 0;

  /* Utterly wrong? */
  if (pool_is_free_index (mm->vnet_main->interface_main.sw_interfaces, 
                          sw_if_index))
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  /* Not a physical port? */
  sw = vnet_get_sw_interface (mm->vnet_main, sw_if_index);
  if (sw->type != VNET_SW_INTERFACE_TYPE_HARDWARE)
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;
  
  vnet_feature_enable_disable ("ip4-unicast", "mmb",
                               sw_if_index, enable_disable, 0, 0);

  return rv;
}

static clib_error_t *
mmb_enable_disable_fn (vlib_main_t * vm,
                   unformat_input_t * input,
                   vlib_cli_command_t * cmd,
                   int enable_disable)
{
  mmb_main_t *mm = &mmb_main;
  u32 sw_if_index = ~0;
    
  int rv;

  while(unformat_check_input(input) != UNFORMAT_END_OF_INPUT)
  {
    if (!unformat(input, "%U", unformat_vnet_sw_interface, mm->vnet_main, &sw_if_index))
      break;
  }

  if (sw_if_index == ~0)
    return clib_error_return(0, "Please specify an interface...");
    
  rv = mmb_enable_disable(mm, sw_if_index, enable_disable);

  switch(rv)
  {
    case 0:
      break;

    case VNET_API_ERROR_INVALID_SW_IF_INDEX:
      return clib_error_return(0, "Invalid interface, only works on physical ports");

    case VNET_API_ERROR_UNIMPLEMENTED:
      return clib_error_return(0, "Device driver doesn't support redirection");

    default:
      return clib_error_return(0, "mmb_enable_disable returned %d", rv);
  }

  return 0;
}

static clib_error_t *
enable_command_fn (vlib_main_t * vm,
                   unformat_input_t * input,
                   vlib_cli_command_t * cmd)
{
  return mmb_enable_disable_fn(vm, input, cmd, /* enable */ 1);
}

static clib_error_t *
disable_command_fn (vlib_main_t * vm,
                   unformat_input_t * input,
                   vlib_cli_command_t * cmd)
{
  return mmb_enable_disable_fn(vm, input, cmd, /* disable */ 0);
}

static clib_error_t *
display_rules_command_fn (vlib_main_t * vm,
                          unformat_input_t * input,
                          vlib_cli_command_t * cmd)
{
  if (!unformat_is_eof(input))
    return clib_error_return(0, "Syntax error: unexpected additional element");

  mmb_main_t *mm = &mmb_main;
  print_rules(vm, mm->rules);

  return 0;
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

  /*uword index = 0;
  vec_foreach_index(index, matches) {
  vl_print(vm, "%U%s", mmb_format_match, &matches[index],
                               (index != vec_len(matches)-1) ? " AND ":"\t");
  }*/

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

  mmb_rule_t rule;
  memset(&rule, 0, sizeof(mmb_rule_t));
  rule.matches  = matches;
  rule.targets = targets;

  clib_error_t *error;
  if ( (error = validate_rule(&rule)) )
    return error;

  vl_print(vm, "%U", mmb_format_rule, &rule);
  mmb_main_t *mm = &mmb_main;
  vec_add1(mm->rules, rule);
  return 0;
}

clib_error_t *validate_rule(mmb_rule_t *rule) {
   //TODO
   return NULL;
}

static clib_error_t *
del_rule_command_fn (vlib_main_t * vm,
                     unformat_input_t * input,
                     vlib_cli_command_t * cmd)
{
  u32 rule_index;
  mmb_main_t *mm = &mmb_main;
  mmb_rule_t *rules = mm->rules;
  vl_print(vm, "%d", vec_len(rules));

  if (unformat(input, "%u", &rule_index))
  {

   if (rule_index > 0 && rule_index <= vec_len(rules)) {

       if (unformat_is_eof(input))
       {
         rule_index--; 
         mmb_rule_t *rule = &rules[rule_index];
         vec_del1(rules, rule_index);
         mmb_free_rule(rule);

         return 0;
       } 
       return clib_error_return(0, 
        "Syntax error: unexpected additional element");
    }
        return clib_error_return(0, "No rule at this index");
  } 

  return clib_error_return(0, 
    "Syntax error: rule number must be an integer greater than 0");
}

uword unformat_field(unformat_input_t * input, va_list * va)
{
  u8 *field = va_arg(*va, u8*);
  u8 *kind  = va_arg(*va, u8*);
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
  u8 *cond = va_arg(*va, u8*);
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
  u8 **bytes = va_arg(*va, u8**);
  u64 decimal = 0;

  if (unformat (input, "0x") 
    || unformat (input, "x")) {
    /* hex value */ 

    u8 *hex_str = 0;
    if (unformat (input, "%U", unformat_hex_string, bytes))
      ;
    else if (unformat (input, "%s", &hex_str)) {

      /* add an extra 0 for parity */  
      unformat_input_t str_input = {0}, *sub_input = &str_input; 
      unformat_init_vector(sub_input, format(0, "0%s", hex_str));
      if (!unformat (sub_input, "%U", unformat_hex_string, bytes)) {
        unformat_free(sub_input);
        return 0;
      }
      unformat_free(sub_input);
    }
    
  } else if (unformat (input, "%lu", &decimal)) {
    /* dec value */
    for (int i=7; i>=0; i--)
      vec_add1(*bytes, (decimal>>(i*8)) & 0xff); 
  } else 
    return 0;

  return 1;
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
   else if (unformat(input, "%U", unformat_field, //TODO: donot match
                    &match->field, &match->opt_kind)) 
     ;
   else 
     return 0;
   return 1;
}

u8* mmb_format_field(u8* s, va_list *args) 
{
   u8 field = *va_arg(*args, u8*); 
   u8 kind  = *va_arg(*args, u8*);

   u8 field_index = field-MMB_FIELD_NET_PROTO;
   if (field < MMB_FIELD_NET_PROTO 
    || field > MMB_FIELD_NET_PROTO+fields_len)
     ; 
   else if (field == MMB_FIELD_TCP_OPT && kind) 
     s = format(s, "%s %d", fields[field_index], kind);
   else
     s = format(s, "%s", fields[field_index]);

   return s;
}

u8* mmb_format_condition(u8* s, va_list *args) 
{
  u8 condition = *va_arg(*args, u8*);
  if (condition >= MMB_COND_EQ 
    &&  condition <= MMB_COND_EQ+conditions_len)
    s = format(s, "%s", conditions[condition-MMB_COND_EQ]);
  
  return s;
}

u8* mmb_format_keyword(u8* s, va_list *args) 
{
  u8 keyword = *va_arg(*args, u8*);
   
  char *keyword_str = "";
  switch(keyword) {
    case MMB_TARGET_DROP:
       keyword_str = "drop";
       break;
    case MMB_TARGET_MODIFY:
       keyword_str =  "mod";
       break;
    case MMB_TARGET_STRIP:
       keyword_str =  "strip";
       break;
    default:
       break;
  }

  s = format(s, "%s", keyword_str);
  return s;
}

void print_rules(vlib_main_t * vm, mmb_rule_t *rules) {
   //TODO: output alignment
   vl_print(vm, "\tIndex\tMatches\t\t\t\tTargets\n");

   uword rule_index = 0;
   vec_foreach_index(rule_index, rules) {
     vl_print(vm, "%d\t%U\n", rule_index+1, mmb_format_rule, &rules[rule_index]);
   }
}

u8 *mmb_format_rule(u8 *s, va_list *args) {
  mmb_rule_t *rule = va_arg(*args, mmb_rule_t*);

  uword index = 0;
  vec_foreach_index(index, rule->matches) {
    s = format(s, "%U%s", mmb_format_match, &rule->matches[index],
                               (index != vec_len(rule->matches)-1) ? " AND ":"\t");
  }

  vec_foreach_index(index, rule->targets) {
    s = format(s, "%U%s", mmb_format_target, &rule->targets[index],  
                               (index != vec_len(rule->targets)-1) ? ", ":"\n");
  }
  return s;
}

static inline u8 *mmb_format_bytes(u8 *s, va_list *args) {
  u8 *byte, *bytes = va_arg(*args, u8*); 
  vec_foreach(byte, bytes) {
    s = format(s, "%02x", *byte);
  }
  return s;
}

u8 *mmb_format_match(u8 *s, va_list *args) {

  mmb_match_t *match = va_arg(*args, mmb_match_t*);
  s = format(s, "%s %U %U %U", (match->reverse) ? "! ":"",
                          mmb_format_field, &match->field, &match->opt_kind,
                          mmb_format_condition, &match->condition,
                          mmb_format_bytes, match->value
                          );
  return s;
} 

u8 *mmb_format_target(u8 *s, va_list *args) {

  mmb_target_t *target = va_arg(*args, mmb_target_t*);
  s = format(s, "%s %U %U %U", (target->reverse) ? "! ":"",
                         mmb_format_keyword, &target->keyword,
                         mmb_format_field, &target->field, &target->opt_kind,
                         mmb_format_bytes, target->value
                         );
  return s; 
}

void mmb_free_rule(mmb_rule_t *rule) {
  uword index;
  vec_foreach_index(index, rule->matches) {
    vec_free(rule->matches[index].value);
  }
  vec_free(rule->matches);
  vec_foreach_index(index, rule->targets) {
    vec_free(rule->targets[index].value);
  }
  vec_free(rule->targets);
}

/**
 * @brief CLI command to enable the mmb plugin.
 */
VLIB_CLI_COMMAND (sr_content_command_enable, static) = {
    .path = "mmb enable",
    .short_help = "mmb enable <interface-name> (enable the MMB plugin on a given interface)",
    .function = enable_command_fn,
};

/**
 * @brief CLI command to disable the mmb plugin.
 */
VLIB_CLI_COMMAND (sr_content_command_disable, static) = {
    .path = "mmb disable",
    .short_help = "mmb disable <interface-name> (disable the MMB plugin on a given interface)",
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
  CLIB_UNUSED(mmb_main_t) * mm = &mmb_main;
#define _(N,n)                                                  \
    vl_msg_api_set_handlers((VL_API_##N + mm->msg_id_base),     \
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
setup_message_id_table (mmb_main_t * mm, api_main_t *am)
{
#define _(id,n,crc) \
  vl_msg_api_add_msg_name_crc (am, #n "_" #crc, id + mm->msg_id_base);
  foreach_vl_msg_name_crc_mmb;
#undef _
}

/**
 * @brief Initialize the mmb plugin.
 */
static clib_error_t * mmb_init (vlib_main_t * vm)
{
  mmb_main_t * mm = &mmb_main;
  clib_error_t * error = 0;
  u8 * name;

  mm->vnet_main =  vnet_get_main ();
  mm->rules = 0;

  name = format (0, "mmb_%08x%c", api_version, 0);

  /* Ask for a correctly-sized block of API message decode slots */
  mm->msg_id_base = vl_msg_api_get_msg_ids 
      ((char *) name, VL_MSG_FIRST_AVAILABLE);

  error = mmb_plugin_api_hookup (vm);

  /* Add our API messages to the global name_crc hash table */
  setup_message_id_table (mm, &api_main);

  vec_free(name);

  return error;
}

VLIB_INIT_FUNCTION (mmb_init);

/**
 * @brief Hook the mmb plugin into the VPP graph hierarchy.
 */
//TODO: work in progress (we may need to change the node location...)
VNET_FEATURE_INIT (mmb, static) = 
{
  .arc_name = "ip4-unicast", //ip4-output
  .node_name = "mmb",
  .runs_before = VNET_FEATURES ("ip4-lookup"), //interface-output
};
