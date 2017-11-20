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
 * @author 
 */

#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>

#include <mmb/mmb.h>
#include <mmb/mmb_format.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>

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

#include <ctype.h>

/* List of message types that this plugin understands */
#define foreach_mmb_plugin_api_msg

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () = {
    .version = MMB_PLUGIN_BUILD_VER,
    .description = "Modular Middlebox",
};
/* *INDENT-ON* */

const u8 fields_len = 58;
const char* fields[] = {
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
  "tcp-rst", "tcp-syn", "tcp-fin", 
  "tcp-flags", "tcp-win", "tcp-checksum", 
  "tcp-payload",  "tcp-opt-mss", "tcp-opt-wscale", 
  "tcp-opt-sackp", "tcp-opt-sack", "tcp-opt-timestamp", 
  "tcp-opt-fast-open", "tcp-opt-mptcp", "tcp-opt",
  "all"
};

const u8 lens_len = 58;
const u8 lens[] = {
  2, 1, 1,
  1, 1, 1,
  1, 1, 1,
  2, 2, 1,
  1, 1, 1,
  2, 1, 1,
  2, 5, 5,
  1, 1, 2,
  0, 2, 2,
  2, 2, 0,
  2, 2, 4,
  4, 1, 1,
  2, 1, 1, 
  1, 1, 1, 
  1, 1, 1, 
  1, 2, 2, 
  0, 2, 1, 
  0, 0, 8, 
  0, 0, 0,
  0
};

const u8 conditions_len = 6;
const char* conditions[] = {"==", "!=", "<=", ">=", "<", ">"};

static void mmb_free_rule(mmb_rule_t *rule);
static clib_error_t *validate_rule();

/**
 * @brief Enable/disable the mmb plugin. 
 *
 * Action function shared between message handler and debug CLI.
 */

int mmb_enable_disable (mmb_main_t *mm, u32 sw_if_index,
                                   int enable_disable) {
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
                   int enable_disable) {
  unformat_input_tolower(input);
  mmb_main_t *mm = &mmb_main;
  u32 sw_if_index = ~0;
    
  int rv = 0;
  while(unformat_check_input(input) != UNFORMAT_END_OF_INPUT) {
    if (!unformat(input, "%U", unformat_vnet_sw_interface, 
                  mm->vnet_main, &sw_if_index))
      break;
  }

  if (sw_if_index == ~0)
    return clib_error_return(0, "Please specify an interface...");
    
  //rv = mmb_enable_disable(mm, sw_if_index, enable_disable);
  vnet_feature_enable_disable ("ip4-unicast", "mmb",
                               sw_if_index, enable_disable, 0, 0);
  //TODO check if itf is not already enabled
  switch(rv) {
    case 0:
      break;

    case VNET_API_ERROR_INVALID_SW_IF_INDEX:
      return clib_error_return(0, "Invalid interface, only works on "
                                  "physical ports");

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
                   vlib_cli_command_t * cmd) {
  return mmb_enable_disable_fn(vm, input, cmd, /* enable */ 1);
}

static clib_error_t *
disable_command_fn (vlib_main_t * vm,
                   unformat_input_t * input,
                   vlib_cli_command_t * cmd) {
  return mmb_enable_disable_fn(vm, input, cmd, /* disable */ 0);
}

static clib_error_t *
list_rules_command_fn (vlib_main_t * vm,
                          unformat_input_t * input,
                          vlib_cli_command_t * cmd) {
  if (!unformat_is_eof(input))
    return clib_error_return(0, "Syntax error: unexpected additional element");

  mmb_main_t *mm = &mmb_main;
  vl_print(vm, "%U", mmb_format_rules, mm->rules);

  return 0;
}

static clib_error_t *
flush_rules_command_fn (vlib_main_t * vm,
                        unformat_input_t * input,
                        vlib_cli_command_t * cmd) {
  unformat_input_tolower(input);
  if (!unformat_is_eof(input))
    return clib_error_return(0, "Syntax error: unexpected additional element");

  mmb_main_t *mm = &mmb_main;
  mmb_rule_t *rules = mm->rules;

  uword rule_index;
  vec_foreach_index(rule_index, rules) {
    mmb_rule_t *rule = &rules[rule_index];
    mmb_free_rule(rule);
  }

  if (vec_len(rules))
    vec_delete(rules, vec_len(rules), 0);

  return 0;
}

static clib_error_t *
add_rule_command_fn (vlib_main_t * vm, unformat_input_t * input, 
                     vlib_cli_command_t * cmd) {
  unformat_input_tolower(input);
  
   /* parse matches */
  mmb_match_t *matches = 0, match;
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) {
    memset(&match, 0, sizeof (mmb_match_t));
    if (!unformat(input, "%U", mmb_unformat_match, &match)) 
      break;
    else vec_add1(matches, match);
  } 
  if (vec_len(matches) < 1)
     return clib_error_return (0, "at least one <match> must be set");

  /* parse targets */
  mmb_target_t *targets = 0, target;
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) {
    memset(&target, 0, sizeof (mmb_target_t));
    if (!unformat(input, "%U", mmb_unformat_target, &target)) 
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
  rule.matches = matches;
  rule.targets = targets;

  clib_error_t *error;
  if ( (error = validate_rule(&rule)) )
    return error;

  vl_print(vm, "%U", mmb_format_rule, &rule);
  mmb_main_t *mm = &mmb_main;
  vec_add1(mm->rules, rule);
  return 0;
}

static_always_inline void translate_ip4_ecn(u8 field, u8 **value) {
  switch (field) {
    case MMB_FIELD_IP_NON_ECT:
      vec_add1(*value, 0);
      break;
    case MMB_FIELD_IP_ECT0:
      vec_add1(*value, 2);
      break;
    case MMB_FIELD_IP_ECT1:
      vec_add1(*value, 1);
      break;
    case MMB_FIELD_IP_CE:
      vec_add1(*value, 3);
      break;
    default:
      break;
  }
}

static_always_inline void translate_match_ip4_ecn(mmb_match_t *match) {
  translate_ip4_ecn(match->field, &match->value);
  match->field = MMB_FIELD_IP_ECN;
  match->condition = MMB_COND_EQ;
}

static_always_inline void translate_target_ip4_ecn(mmb_target_t *target) {
  translate_ip4_ecn(target->field, &target->value);
  target->field = MMB_FIELD_IP_ECN;
}

static_always_inline void translate_match_bit_flags(mmb_match_t *match) {
  match->condition = MMB_COND_EQ;
  vec_add1(match->value, 1);
}

u16 get_field_protocol(u8 field) {
  if (MMB_FIELD_NET_PROTO <= field && field <= MMB_FIELD_IP_DADDR)
     return ETHERNET_TYPE_IP4;
   else if (MMB_FIELD_ICMP_TYPE <= field && field <= MMB_FIELD_ICMP_PAYLOAD)
     return IP_PROTOCOL_ICMP;
   else if (MMB_FIELD_UDP_SPORT <= field && field <= MMB_FIELD_UDP_PAYLOAD)
     return IP_PROTOCOL_UDP;
   else if (MMB_FIELD_TCP_SPORT <= field && field <= MMB_FIELD_TCP_OPT)
     return IP_PROTOCOL_TCP;
   return 0;
}

static clib_error_t *derive_l4(mmb_rule_t *rule) {
  u8 l4 = IP_PROTOCOL_RESERVED;
  
  inline clib_error_t *update_l4(u8 field, u8 *derived_l4) {
    
    u16 proto = get_field_protocol(field);
    switch (proto) {
      case IP_PROTOCOL_ICMP:case IP_PROTOCOL_UDP:
      case IP_PROTOCOL_TCP:

         if (*derived_l4 == IP_PROTOCOL_RESERVED) 
           *derived_l4 = proto;
         else if (*derived_l4 != proto)
           return clib_error_return(0, "Multiple l4 protocols");
      default:
        break;
    }

    return NULL;
  }

  clib_error_t *error;
  uword index;
  vec_foreach_index(index, rule->matches) {
    mmb_match_t *match = &rule->matches[index];
    u8 field = match->field;
    if ( (error = update_l4(field, &l4)) )
      return error;
  }
  vec_foreach_index(index, rule->targets) {
    mmb_target_t *target = &rule->targets[index];
    u8 field = target->field;
    if ( (error = update_l4(field, &l4)) )
      return error;
  }

  rule->l4 = l4;
  return NULL;
}

clib_error_t *validate_rule(mmb_rule_t *rule) {
   //TODO: validate
   uword index = 0;
   
   clib_error_t *error;
   if ( (error = derive_l4(rule)) )
     return error;
   rule->l3 = ETHERNET_TYPE_IP4;

   /* matches */
   vec_foreach_index(index, rule->matches) {
     mmb_match_t *match = &rule->matches[index];

     switch (match->field) {
       case MMB_FIELD_ALL:
         /* other fields must be empty, and no other matches */
         if (match->condition || vec_len(match->value) > 0 || match->reverse
             || vec_len(rule->matches) > 1)
           return clib_error_return(0, "'all' in a <match> must be used alone");
         break;

       case MMB_FIELD_IP_NON_ECT:case MMB_FIELD_IP_ECT0:
       case MMB_FIELD_IP_ECT1:case MMB_FIELD_IP_CE:
         if (vec_len(match->value) > 0)
           return clib_error_return(0, "%s does not take a condition nor a value", 
                                    fields[field_toindex(match->field)]);
         translate_match_ip4_ecn(match);
         break;

       case MMB_FIELD_TCP_FLAGS:
         break; // TODO: translate to bits
       case MMB_FIELD_IP_FLAGS:
         break; // TODO: translate to bits

       case MMB_FIELD_IP_RES:case MMB_FIELD_IP_DF:case MMB_FIELD_IP_MF:
       case MMB_FIELD_TCP_CWR:case MMB_FIELD_TCP_ECE:case MMB_FIELD_TCP_URG:
       case MMB_FIELD_TCP_ACK:case MMB_FIELD_TCP_PUSH:case MMB_FIELD_TCP_RST:
       case MMB_FIELD_TCP_SYN:case MMB_FIELD_TCP_FIN:
         /* "bit-field" or "!bit-field" means "bit-field == 1" or "bit-field == 0" */
         /* so this does NOT mean "bit-field is (not) present in current packet" */
         if (vec_len(match->value) == 0)
           translate_match_bit_flags(match);
         break;
#define _(a,b,c) case a: {match->field = MMB_FIELD_TCP_OPT; match->opt_kind=c;break;}
   foreach_mmb_tcp_opts
#undef _
       default:
         break;
     }
   }

   /* targets */
   vec_foreach_index(index, rule->targets) {
     mmb_target_t *target = &rule->targets[index];

     switch (target->field) {
       case MMB_FIELD_ALL:
         if (target->keyword != MMB_TARGET_STRIP || vec_len(target->value))
           return clib_error_return(0, "'all' in a <target> can only be used"
                                     " with the 'strip' keyword and no value");
         if (target->reverse)
           return clib_error_return(0, "<target> has no effect");
         break;

       case MMB_FIELD_IP_NON_ECT:case MMB_FIELD_IP_ECT0:
       case MMB_FIELD_IP_ECT1:case MMB_FIELD_IP_CE:
         if (vec_len(target->value) > 0)
           return clib_error_return(0, "%s does not take a condition nor a value", 
                                    fields[field_toindex(target->field)]);
         translate_target_ip4_ecn(target);
         break;

#define _(a,b,c) case a: {target->field = MMB_FIELD_TCP_OPT; target->opt_kind=c;break;}
   foreach_mmb_tcp_opts
#undef _

       //TODO: other "bit fields" (see above in "matches" part)
       default:
         break;
     }

     /* Ensure that field of strip target is a tcp opt. */
     if (target->keyword == MMB_TARGET_STRIP) {

       if  (!(MMB_FIELD_TCP_OPT_MSS <= target->field 
             && target->field <= MMB_FIELD_ALL))
         return clib_error_return(0, "strip <field> must be a tcp option or 'all'");

       /* build option strip list  */
       if (vec_len(rule->opts) == 0)
         rule->whitelist = target->reverse;
       else if (rule->whitelist != target->reverse)
         return clib_error_return(0, "inconsistent use of ! in strip");
       vec_add1(rule->opts, target->opt_kind);

     } else if (target->keyword == MMB_TARGET_MODIFY) 
       ;
   }

   return NULL;
}

static clib_error_t *
del_rule_command_fn (vlib_main_t * vm,
                     unformat_input_t * input,
                     vlib_cli_command_t * cmd) {
  unformat_input_tolower(input);
  u32 rule_index;
  mmb_main_t *mm = &mmb_main;
  mmb_rule_t *rules = mm->rules;

  if (unformat(input, "%u", &rule_index)) {

   if (rule_index > 0 && rule_index <= vec_len(rules)) {

       if (unformat_is_eof(input)) {
         rule_index--; 
         mmb_rule_t *rule = &rules[rule_index];
         mmb_free_rule(rule);
         vec_delete(rules, 1, rule_index);

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
VLIB_CLI_COMMAND(sr_content_command_enable, static) = {
    .path = "mmb enable",
    .short_help = "mmb enable <interface-name> "
                  "(enable the MMB plugin on a given interface)",
    .function = enable_command_fn,
};

/**
 * @brief CLI command to disable the mmb plugin.
 */
VLIB_CLI_COMMAND(sr_content_command_disable, static) = {
    .path = "mmb disable",
    .short_help = "mmb disable <interface-name> "
                  "(disable the MMB plugin on a given interface)",
    .function = disable_command_fn,
};

/**
 * @brief CLI command to list all rules.
 */
VLIB_CLI_COMMAND(sr_content_command_list_rules, static) = {
    .path = "mmb list",
    .short_help = "Display all rules",
    .function = list_rules_command_fn,
};

/**
 * @brief CLI command to add a new rule.
 */
VLIB_CLI_COMMAND(sr_content_command_add_rule, static) = {
    .path = "mmb add",
    .short_help = "Add a rule: mmb add <field> [[<cond>] <value>] "
                  "[<field> [[<cond>] <value>] ...] <strip <option-field> "
                  "[strip|mod ...]|mod [<field>] <value> [strip|mod ...]|drop>",
    .function = add_rule_command_fn,
};

/**
 * @brief CLI command to remove a rule.
 */
VLIB_CLI_COMMAND(sr_content_command_del_rules, static) = {
    .path = "mmb del",
    .short_help = "Remove a rule: mmb del <rule-number>",
    .function = del_rule_command_fn,
};

/**
 * @brief CLI command to remove all rules.
 */
VLIB_CLI_COMMAND(sr_content_command_flush_rule, static) = {
    .path = "mmb flush",
    .short_help = "Remove all rules",
    .function = flush_rules_command_fn,
};

/**
 * @brief Set up the API message handling tables.
 */
static clib_error_t *
mmb_plugin_api_hookup(vlib_main_t *vm) {
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
setup_message_id_table(mmb_main_t * mm, api_main_t *am) {
#define _(id,n,crc) \
  vl_msg_api_add_msg_name_crc (am, #n "_" #crc, id + mm->msg_id_base);
  foreach_vl_msg_name_crc_mmb;
#undef _
}

/**
 * @brief Initialize the mmb plugin.
 */
static clib_error_t * mmb_init(vlib_main_t * vm) {
  mmb_main_t * mm = &mmb_main;
  clib_error_t * error = 0;
  u8 * name;

  memset(mm, 0, sizeof(mmb_main_t));
  mm->vnet_main =  vnet_get_main();

  name = format (0, "mmb_%08x%c", api_version, 0);

  /* Ask for a correctly-sized block of API message decode slots */
  mm->msg_id_base = vl_msg_api_get_msg_ids 
      ((char *) name, VL_MSG_FIRST_AVAILABLE);

  error = mmb_plugin_api_hookup(vm);

  /* Add our API messages to the global name_crc hash table */
  setup_message_id_table(mm, &api_main);

  vec_free(name);

  return error;
}

VLIB_INIT_FUNCTION (mmb_init);

/**
 * @brief Hook the mmb plugin into the VPP graph hierarchy.
 */
VNET_FEATURE_INIT (mmb, static) = {
  .arc_name = "ip4-unicast", //ip4-output
  .node_name = "mmb",
  .runs_before = VNET_FEATURES("ip4-lookup"), //interface-output
};

