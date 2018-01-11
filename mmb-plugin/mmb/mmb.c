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

/* internal macros */
#define MMB_MAX_FIELD_LEN 64
#define MMB_DEFAULT_ETHERNET_TYPE ETHERNET_TYPE_IP4

#define vec_insert_elt_last(V,E) vec_insert_elts(V,E,1,vec_len(V))
#define vec_insert_elt(V,E,I) vec_insert_elts(V,E,1,I)

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () = {
    .version = MMB_PLUGIN_BUILD_VER,
    .description = "Modular Middlebox",
};
/* *INDENT-ON* */

const u8 fields_len = 70;
const char* fields[] = {
  "in", "out",
  "net-proto", "ip-ver", "ip-ihl",
  "ip-dscp", "ip-ecn", "ip-non-ect",
  "ip-ect0", "ip-ect1", "ip-ce",
  "ip-len", "ip-id", "ip-flags",
  "ip-res", "ip-df", "ip-mf",
  "ip-frag-offset", "ip-ttl", "ip-proto",
  "ip-checksum", "ip-saddr", "ip-daddr",
  "ip-payload",

  "ip6-ver", "ip6-traffic-class", "ip6-flow-label",
  "ip6-len", "ip6-next", "ip6-hop-limit",
  "ip6-saddr", "ip6-daddr", "ip6-payload",          /* 10 */

  "icmp-type", "icmp-code", "icmp-checksum",
  "icmp-payload", "udp-sport", "udp-dport",
  "udp-len", "udp-checksum", "udp-payload", 
  "tcp-sport", "tcp-dport", "tcp-seq-num", 
  "tcp-ack-num", "tcp-offset", "tcp-reserved",
  "tcp-urg-ptr", "tcp-cwr", "tcp-ece", 
  "tcp-urg", "tcp-ack", "tcp-push", 
  "tcp-rst", "tcp-syn", "tcp-fin", 
  "tcp-flags", "tcp-win", "tcp-checksum", 
  "tcp-payload",  "tcp-opt-mss", "tcp-opt-wscale",      /* 20 */
  "tcp-opt-sackp", "tcp-opt-sack", "tcp-opt-timestamp", 
  "tcp-opt-fast-open", "tcp-opt-mptcp", "tcp-opt",
  "all"
};

const u8 lens[] = {
  4, 4,
  2, 1, 1,
  1, 1, 1,
  1, 1, 1,
  2, 2, 1,
  1, 1, 1,
  2, 1, 1,
  2, 5, 5,
  0,
  1, 1, 3,
  2, 1, 1,
  17,17,0,   /* 10 */

  1, 1, 2,
  0, 2, 2,
  2, 2, 0, 
  2, 2, 4,
  4, 1, 1,
  2, 1, 1, 
  1, 1, 1, 
  1, 1, 1, 
  1, 2, 2, 
  0, 2, 1,  /* 20 */
  0, 0, 8, 
  0, 0, 0,
  0
};

const u8 fixed_len[] = {
  1, 1,
  1, 1, 1,
  1, 1, 1,
  1, 1, 1,
  1, 1, 1,
  1, 1, 1,
  1, 1, 1,
  1, 1, 1,
  0,
  1, 1, 1,
  1, 1, 1,
  1, 1, 0,  /* 10 */
  1, 1, 1,
  0, 1, 1,
  1, 1, 0, 
  1, 1, 1,
  1, 1, 1,
  1, 1, 1,
  1, 1, 1, 
  1, 1, 1, 
  1, 1, 1,
  0, 1, 1, /* 20 */
  1, 0, 1, 
  0, 0, 0,
  1
};

const u8 conditions_len = 6;
const char* conditions[] = {"==", "!=", "<=", ">=", "<", ">"};

static void free_rule(mmb_rule_t *rule);
static void init_rule(mmb_rule_t *rule);
static clib_error_t* parse_and_validate_rule(unformat_input_t * input, 
                                                 mmb_rule_t *rule);
static clib_error_t* validate_rule();
static clib_error_t* validate_matches(mmb_rule_t *rule);
static clib_error_t* validate_targets(mmb_rule_t *rule);
static clib_error_t* mmb_enable_disable_fn(vlib_main_t * vm,
                                           unformat_input_t * input,
                                           vlib_cli_command_t * cmd,
                                           u32 *sw_if_index);

static_always_inline u8 rule_has_tcp_options(mmb_rule_t *rule)
{
  return rule->opts_in_matches || rule->opts_in_targets;
}

static_always_inline void reset_flags(mmb_main_t *mm) {
   mm->opts_in_rules = 0;
} 

static_always_inline void update_flags(mmb_main_t *mm, mmb_rule_t *rules) {
   mmb_rule_t *rule;
   vec_foreach(rule, rules) {
      if (rule_has_tcp_options(rule)) {
          mm->opts_in_rules = 1;
          return;
      }
   }
   mm->opts_in_rules = 0;
} 

static_always_inline void mmb_enable_disable(u32 sw_if_index, int enable_disable) {
   vnet_feature_enable_disable("ip4-unicast", "mmb-plugin-ip4-in", 
                               sw_if_index, enable_disable, 0, 0);
   vnet_feature_enable_disable("ip6-unicast", "mmb-plugin-ip6-in", 
                               sw_if_index, enable_disable, 0, 0);
   vnet_feature_enable_disable("ip4-output", "mmb-plugin-ip4-out", 
                               sw_if_index, enable_disable, 0, 0);
   vnet_feature_enable_disable("ip6-output", "mmb-plugin-ip6-out", 
                               sw_if_index, enable_disable, 0, 0);
}

clib_error_t* mmb_enable_disable_fn(vlib_main_t * vm,
                                    unformat_input_t * input,
                                    vlib_cli_command_t * cmd,
                                    u32 *sw_if_index) {
  unformat_input_tolower(input);
  mmb_main_t *mm = &mmb_main;
  *sw_if_index = ~0;
  
  while(unformat_check_input(input) != UNFORMAT_END_OF_INPUT) {
    if (!unformat(input, "%U", unformat_vnet_sw_interface, 
                  mm->vnet_main, sw_if_index))
      break;
  }

  if (*sw_if_index == ~0)
    return clib_error_return(0, "Please specify an interface...");

  /* Utterly wrong? */
  if (pool_is_free_index (mm->vnet_main->interface_main.sw_interfaces, 
                          *sw_if_index))
    return clib_error_return(0, "Invalid interface, only works on "
                                 "physical ports");
  return 0;
}

static clib_error_t *
enable_command_fn(vlib_main_t * vm,
                  unformat_input_t * input,
                  vlib_cli_command_t * cmd) {
   u8 index;
   u32 sw_if_index, enabled_sw_if_index;
   mmb_main_t *mm = &mmb_main;
   clib_error_t *error;

   if ( (error = mmb_enable_disable_fn(vm, input, cmd, &sw_if_index)) )
     return error;

   /* if already enabled ? */
   vec_foreach_index(index, mm->sw_if_indexes) {
      enabled_sw_if_index = mm->sw_if_indexes[index];
      if (sw_if_index == enabled_sw_if_index) 
         return clib_error_return(0, "mmb is already enabled on %U\n", 
                       format_vnet_sw_if_index_name, 
                       mm->vnet_main, sw_if_index);
   }

   vec_add1(mm->sw_if_indexes, sw_if_index);
   mmb_enable_disable(sw_if_index, 1);
   vl_print(vm, "mmb enabled on %U\n", format_vnet_sw_if_index_name, 
             mm->vnet_main, sw_if_index);

   return 0;
}

static clib_error_t*
disable_command_fn(vlib_main_t * vm,
                   unformat_input_t * input,
                   vlib_cli_command_t * cmd) {
   u8 enabled = 0, index = 0;
   u32 sw_if_index, enabled_sw_if_index;
   mmb_main_t *mm = &mmb_main;
   clib_error_t *error;

   if ( (error = mmb_enable_disable_fn(vm, input, cmd, &sw_if_index)) )
     return error;

   /* if already disabled ? */
   vec_foreach_index(index, mm->sw_if_indexes) {
      enabled_sw_if_index = mm->sw_if_indexes[index];
      if (sw_if_index == enabled_sw_if_index) {
         enabled = 1;
         break;
      }
   }
   if (!enabled)
      return clib_error_return(0, "mmb is not enabled on %U\n", 
              format_vnet_sw_if_index_name, 
              mm->vnet_main, sw_if_index);

   vec_delete(mm->sw_if_indexes, 1, index);
   mmb_enable_disable(sw_if_index, 0);
   vl_print(vm, "mmb disabled on %U\n", format_vnet_sw_if_index_name, 
          mm->vnet_main, sw_if_index);

  return 0;
}

static clib_error_t*
list_rules_command_fn(vlib_main_t * vm,
                          unformat_input_t * input,
                          vlib_cli_command_t * cmd) {
  if (!unformat_is_eof(input))
    return clib_error_return(0, "Syntax error: unexpected additional element");

  mmb_main_t *mm = &mmb_main;
  vl_print(vm, "%U", mmb_format_rules, mm->rules);

  return 0;
}

static clib_error_t*
flush_rules_command_fn(vlib_main_t * vm,
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
    free_rule(rule);
  }

  if (vec_len(rules))
    vec_delete(rules, vec_len(rules), 0);

  reset_flags(mm);

  return 0;
}

static clib_error_t*
insert_rule_command_fn(vlib_main_t * vm,
                     unformat_input_t * input,
                     vlib_cli_command_t * cmd) {
   unformat_input_tolower(input);
   u32 rule_index;
   mmb_main_t *mm = &mmb_main;
   mmb_rule_t *rules = mm->rules;

   if (unformat(input, "%u", &rule_index)) {
      /* oow index */
      if (rule_index <= 0)
         rule_index = 0;
      else if (rule_index > vec_len(rules))
         rule_index = vec_len(rules);
      else 
         rule_index--;
      
      mmb_rule_t rule;
      clib_error_t *error;
      init_rule(&rule);

      if (unformat(input, "last")) 
         rule.last_match = 1;
      if ( (error = parse_and_validate_rule(input, &rule)) )
         return error;

      vec_insert_elt(mm->rules,&rule,rule_index);

      /* flags */
      if (rule_has_tcp_options(&rule))
         mm->opts_in_rules = 1;

      vl_print(vm, "Inserted rule at index %u: %U", 
               rule_index+1, mmb_format_rule, &rule);
      return 0;
   } 
   return clib_error_return(0, 
    "Syntax error: rule number must be an integer greater than 0");
}

static clib_error_t *
add_rule_command_fn (vlib_main_t * vm, unformat_input_t * input, 
                     vlib_cli_command_t * cmd) {
  unformat_input_tolower(input);

  mmb_rule_t rule;
  clib_error_t *error;
  init_rule(&rule);

  if (unformat(input, "last")) 
    rule.last_match = 1;
  if ( (error = parse_and_validate_rule(input, &rule)) )
    return error;
  
  mmb_main_t *mm = &mmb_main;
  vec_add1(mm->rules, rule);

  /* flags */
  if (rule_has_tcp_options(&rule))
     mm->opts_in_rules = 1;

  vl_print(vm, "Added rule: %U", mmb_format_rule, &rule);
  return 0;
}

clib_error_t *parse_and_validate_rule(unformat_input_t * input, 
                                      mmb_rule_t *rule) {
  if (!unformat(input, "%U", mmb_unformat_rule, rule))
    return clib_error_return(0, "Invalid rule");

  clib_error_t *error;
  if ( (error = validate_rule(rule)) )
    return error;
  return 0;
}

static clib_error_t*
del_rule_command_fn(vlib_main_t *vm,
                    unformat_input_t *input,
                    vlib_cli_command_t *cmd) {
   unformat_input_tolower(input);
   u32 rule_index;
   mmb_main_t *mm = &mmb_main;
   mmb_rule_t *rules = mm->rules;

   if (unformat(input, "%u", &rule_index)) {

      if (rule_index > 0 && rule_index <= vec_len(rules)) {

         if (unformat_is_eof(input)) {
            rule_index--; 
            mmb_rule_t *rule = &rules[rule_index];
            free_rule(rule);
            vec_delete(rules, 1, rule_index);

            /* flags */
            update_flags(mm, rules);

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

static_always_inline void translate_ip4_ecn(u8 field, u8 **value) {
  switch (field) {
    case MMB_FIELD_IP4_NON_ECT:
      vec_add1(*value, 0);
      break;
    case MMB_FIELD_IP4_ECT0:
      vec_add1(*value, 2);
      break;
    case MMB_FIELD_IP4_ECT1:
      vec_add1(*value, 1);
      break;
    case MMB_FIELD_IP4_CE:
      vec_add1(*value, 3);
      break;
    default:
      break;
  }
}

static_always_inline void translate_match_ip4_ecn(mmb_match_t *match) {
  translate_ip4_ecn(match->field, &match->value);
  match->field = MMB_FIELD_IP4_ECN;
  match->condition = MMB_COND_EQ;
}

static_always_inline void translate_target_ip4_ecn(mmb_target_t *target) {
  translate_ip4_ecn(target->field, &target->value);
  target->field = MMB_FIELD_IP4_ECN;
}

static_always_inline void translate_match_bit_flags(mmb_match_t *match) {
  match->condition = MMB_COND_EQ;
  vec_add1(match->value, 1);
}

u16 get_field_protocol(u8 field) {
  if (MMB_FIELD_IP4_VER <= field && field <= MMB_FIELD_IP4_PAYLOAD)
     return ETHERNET_TYPE_IP4;
  if (MMB_FIELD_IP6_VER <= field && field <= MMB_FIELD_IP6_PAYLOAD)
     return ETHERNET_TYPE_IP6;
   else if (MMB_FIELD_ICMP_TYPE <= field && field <= MMB_FIELD_ICMP_PAYLOAD)
     return IP_PROTOCOL_ICMP;
   else if (MMB_FIELD_UDP_SPORT <= field && field <= MMB_FIELD_UDP_PAYLOAD)
     return IP_PROTOCOL_UDP;
   else if (MMB_FIELD_TCP_SPORT <= field && field <= MMB_FIELD_TCP_OPT)
     return IP_PROTOCOL_TCP;
   return IP_PROTOCOL_RESERVED;
}

u8 is_fixed_length(u8 field) {
   u8 index = field_toindex(field);
   if (index < fields_len)
      return fixed_len[index];
   return 0;
}

static_always_inline clib_error_t *update_l3(u8 field, u16 *derived_l3) {
 u16 proto = get_field_protocol(field);

 switch (proto) {
   case ETHERNET_TYPE_IP4:
   case ETHERNET_TYPE_IP6:

      if (*derived_l3 == 0) 
        *derived_l3 = proto;
      else if (*derived_l3 != proto)
        return clib_error_return(0, "Multiple l3 protocols");
   default:
     break;
 }
 return NULL;
}

static_always_inline clib_error_t *update_l4(u8 field, u8 *derived_l4) {
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

static_always_inline u32 bytes_to_u32(u8 *bytes) {
  u32 value = 0;
  u32 index = 0;
  const u32 len = 3;

  vec_foreach_index(index, bytes) 
    value += ((u32) bytes[index]) << (len-index)*8;

  return value;
}

static_always_inline clib_error_t*
validate_if(mmb_rule_t *rule, mmb_match_t *match, u8 field) {
   mmb_main_t mm = mmb_main;

   if (vec_len(match->value) == 0)
      return clib_error_return(0, "missing interface name/index"); 
   if (match->reverse || match->condition != MMB_COND_EQ)
      return clib_error_return(0, "invalid interface definition");

   u32 sw_if_index = bytes_to_u32(match->value); 
   if (vnet_get_sw_interface_safe (mm.vnet_main, sw_if_index) == NULL)
      return clib_error_return(0, "invalid interface index:%u", sw_if_index);

   if (field == MMB_FIELD_INTERFACE_IN && rule->in == ~0) 
      rule->in = sw_if_index;
   else if (field == MMB_FIELD_INTERFACE_OUT && rule->out == ~0)
      rule->out = sw_if_index;
   else
      return clib_error_return(0, "multiple interfaces");
   
   return NULL;
}

clib_error_t* validate_matches(mmb_rule_t *rule) {
   clib_error_t *error;
   uword index = 0;
   uword *if_indexes = 0, *if_index;

   vec_foreach_index(index, rule->matches) {
     mmb_match_t *match = &rule->matches[index];
     u8 field = match->field, reverse = match->reverse;
     u8 condition = match->condition, *value = match->value;

     if ( (error = update_l3(field, &rule->l3))
           || (error = update_l4(field, &rule->l4)) )
       return error;

     switch (field) {
       case MMB_FIELD_ALL:
         /* other fields must be empty, and no other matches */
         if (condition || vec_len(value) > 0 || reverse
             || vec_len(rule->matches) > 1)
           return clib_error_return(0, "'all' in a <match> must be used alone");
         break;

       case MMB_FIELD_IP4_NON_ECT:case MMB_FIELD_IP4_ECT0:
       case MMB_FIELD_IP4_ECT1:case MMB_FIELD_IP4_CE:
         if (vec_len(value) > 0)
           return clib_error_return(0, "%s does not take a condition nor a value", 
                                    fields[field_toindex(field)]);
         translate_match_ip4_ecn(match);
         break;

       case MMB_FIELD_TCP_FLAGS:
         break; // TODO: translate to bits
       case MMB_FIELD_IP4_FLAGS:
         break; // TODO: translate to bits

       case MMB_FIELD_IP4_RES:case MMB_FIELD_IP4_DF:case MMB_FIELD_IP4_MF:
       case MMB_FIELD_TCP_CWR:case MMB_FIELD_TCP_ECE:case MMB_FIELD_TCP_URG:
       case MMB_FIELD_TCP_ACK:case MMB_FIELD_TCP_PUSH:case MMB_FIELD_TCP_RST:
       case MMB_FIELD_TCP_SYN:case MMB_FIELD_TCP_FIN:
         /* "bit-field" or "!bit-field" means "bit-field == 1" or "bit-field == 0" */
         /* so this does NOT mean "bit-field is (not) present in current packet" */
         if (vec_len(value) == 0)
           translate_match_bit_flags(match);
         break;
#define _(a,b,c) case a: {match->field=MMB_FIELD_TCP_OPT; match->opt_kind=c;\
                          rule->opts_in_matches=1; break;}
   foreach_mmb_tcp_opts
#undef _
       case MMB_FIELD_TCP_OPT:
         rule->opts_in_matches=1;
         break;
       case MMB_FIELD_INTERFACE_IN:  
       case MMB_FIELD_INTERFACE_OUT:
          if ( (error = validate_if(rule, match, field)) )
            return error;
          vec_insert_elt_last(if_indexes, &index);
          break;        
       default:
         break;
     }
   }

   /* delete interface fields */
   vec_foreach(if_index, if_indexes) {
     mmb_match_t *match = &rule->matches[*if_index];
     vec_free(match->value);
     if (vec_len(rule->matches) == 1) {
       match->field = MMB_FIELD_ALL;
       match->condition = 0;
     } else  /* del */  
       vec_delete(rule->matches, 1, *if_index);
   }

   return NULL;
}

static_always_inline mmb_transport_option_t to_transport_option(mmb_target_t *target) {
   mmb_transport_option_t opt;
   memset(&opt, 0, sizeof(mmb_transport_option_t));
   opt.l4 = IP_PROTOCOL_TCP;
   opt.kind = target->opt_kind;
   opt.value = target->value;
   return opt;
}

clib_error_t *validate_targets(mmb_rule_t *rule) {
   clib_error_t *error;
   uword index = 0;
   uword *rm_indexes = 0, *rm_index;

   vec_foreach_index(index, rule->targets) {
     mmb_target_t *target = &rule->targets[index];
     u8 field = target->field, reverse = target->reverse;
     u8 keyword = target->keyword, *value = target->value;

     if ( (error = update_l3(field, &rule->l3))
           || (error = update_l4(field, &rule->l4)) )
       return error;

     switch (field) {
       case MMB_FIELD_ALL:
         if (keyword != MMB_TARGET_STRIP || vec_len(value))
           return clib_error_return(0, "'all' in a <target> can only be used"
                                     " with the 'strip' keyword and no value");
         if (reverse)
           return clib_error_return(0, "<target> has no effect");
         
         break;
       case MMB_FIELD_INTERFACE_IN:
       case MMB_FIELD_INTERFACE_OUT:
          return clib_error_return(0, "invalid field in target");
       case MMB_FIELD_IP4_NON_ECT:case MMB_FIELD_IP4_ECT0:
       case MMB_FIELD_IP4_ECT1:case MMB_FIELD_IP4_CE:
         if (vec_len(value) > 0)
           return clib_error_return(0, "%s does not take a condition nor a value", 
                                    fields[field_toindex(field)]);
         translate_target_ip4_ecn(target);
         break;

#define _(a,b,c) case a: {target->field = MMB_FIELD_TCP_OPT; target->opt_kind=c;\
                          rule->opts_in_targets=1; break;}
   foreach_mmb_tcp_opts
#undef _
       //TODO: other "bit fields" (see above in "matches" part)
       case MMB_FIELD_TCP_OPT:
         rule->opts_in_targets=1;
         break;
       default:
         break;
     }
     
     if (keyword == MMB_TARGET_STRIP) {

       /* Ensure that field of strip target is a tcp opt. */
       if  (!(MMB_FIELD_TCP_OPT_MSS <= field 
             && field <= MMB_FIELD_ALL))
         return clib_error_return(0, "strip <field> must be a tcp option or 'all'");

       /* build option strip list  */
       if (!rule->has_strips)  {
         rule->has_strips = 1; 
         /* first strip target, set type */
         if (reverse) {
            rule->whitelist = 1;
            /* flip bitmap to 1s XXX: typo in func name !!*/
            clfib_bitmap_set_region(rule->opt_strips, 0, 1, 255);
         }
       } else if (rule->whitelist != reverse)
         return clib_error_return(0, "inconsistent use of ! in strip");

       if (field == MMB_FIELD_ALL) /* strip all */
         target->opt_kind = MMB_FIELD_TCP_OPT_ALL;

       clib_bitmap_set_no_check(rule->opt_strips, target->opt_kind, !rule->whitelist);
       vec_insert_elt_last(rm_indexes, &index);
     } else if (keyword == MMB_TARGET_ADD) { 

        /* Ensure that field of strip target is a tcp opt. */
       if  (!(MMB_FIELD_TCP_OPT_MSS <= field 
             && field < MMB_FIELD_ALL))
         return clib_error_return(0, "add <field> must be a tcp option");

       /* empty value should be fixed len and len = 0 */
       if (vec_len(value) == 0 
             && !(is_fixed_length(field) && lens[field_toindex(field)]==0) )
         return clib_error_return(0, "add <field> missing value");

       /* add transport opt to add-list and register for deletion */
       mmb_transport_option_t opt = to_transport_option(target);
       vec_add1(rule->opt_adds, opt);
       rule->has_adds = 1;
       vec_insert_elt_last(rm_indexes, &index);
     } else if (keyword == MMB_TARGET_MODIFY) { 
        if  (MMB_FIELD_TCP_OPT_MSS <= field 
             && field < MMB_FIELD_ALL) {
          vec_add1(rule->opt_mods, *target);
          vec_insert_elt_last(rm_indexes, &index);
        }
     }
   } 

   /* delete strips and adds from targets */ 
   vec_foreach(rm_index, rm_indexes) {
     vec_delete(rule->targets, 1, *rm_index);
   }
   
   return NULL;
}

clib_error_t *validate_rule(mmb_rule_t *rule) {
   clib_error_t *error; //TODO: more validation

   rule->l3 = 0;
   rule->l4 = IP_PROTOCOL_RESERVED;

   if ( (error = validate_matches(rule)) )
      return error;
   if ( (error = validate_targets(rule)) )
      return error; 

   if (rule->l3 == 0)
      rule->l3 = MMB_DEFAULT_ETHERNET_TYPE;

   return NULL;
}

void init_rule(mmb_rule_t *rule) {
  memset(rule, 0, sizeof(mmb_rule_t));
  rule->in = rule->out = ~0;
  clib_bitmap_alloc(rule->opt_strips, 255);
  clib_bitmap_zero(rule->opt_strips);
}

void free_rule(mmb_rule_t *rule) {
  uword index;

  vec_foreach_index(index, rule->matches) {
    vec_free(rule->matches[index].value);
  }
  vec_free(rule->matches);

  vec_foreach_index(index, rule->targets) {
    vec_free(rule->targets[index].value);
  }
  vec_free(rule->targets);

  clib_bitmap_free(rule->opt_strips);

  vec_foreach_index(index, rule->opt_adds) {
    vec_free(rule->opt_adds[index].value);
  }
  vec_free(rule->opt_adds);
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
 * @brief CLI command to insert a rule.
 */
VLIB_CLI_COMMAND(sr_content_command_insert_rule, static) = {
    .path = "mmb insert",
    .short_help = "Insert a rule: mmb insert [last] <index> <rule>",
    .function = insert_rule_command_fn,
};

/**
 * @brief CLI command to remove a rule.
 */
VLIB_CLI_COMMAND(sr_content_command_del_rules, static) = {
    .path = "mmb delete",
    .short_help = "Remove a rule: mmb delete <rule-number>",
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
