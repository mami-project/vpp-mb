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

#include <ctype.h>

/* List of message types that this plugin understands */

#define foreach_mmb_plugin_api_msg

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () = {
    .version = MMB_PLUGIN_BUILD_VER,
    .description = "Modular Middlebox",
};
/* *INDENT-ON* */

#define MMB_MAX_FIELD_LEN 32

/* cli-name,protocol-name */
#define foreach_mmb_transport_proto       \
_(tcp,TCP)                                    \
_(udp,UDP)                                    \
_(icmp,ICMP)     
                               
#define foreach_mmb_network_proto       \
_(ip4,IP4)                                    \
_(ip6,IP6)                                   

#define foreach_mmb_tcp_opts            \
_(MMB_FIELD_TCP_OPT_MSS,MSS,2)            \
_(MMB_FIELD_TCP_OPT_WSCALE,WScale,3)         \
_(MMB_FIELD_TCP_OPT_SACKP,SACK-P,4)          \
_(MMB_FIELD_TCP_OPT_SACK,SACK,5)           \
_(MMB_FIELD_TCP_OPT_TIMESTAMP,Timestamp,8)      \
_(MMB_FIELD_TCP_OPT_FAST_OPEN,Fast Open,34)      \
_(MMB_FIELD_TCP_OPT_MPTCP,MPTCP,30)                                    


static const char* blanks = "                                                "
                            "                                                "
                            "                                                "
                            "                                                ";

static const u8 fields_len = 58;
static const char* fields[] = {
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

static const u8 lens_len = 58;
static const u8 lens[] = {
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

static const u8 conditions_len = 6;
static const char* conditions[] = {"==", "!=", "<=", ">=", "<", ">"};

static uword unformat_field(unformat_input_t * input, va_list * va);
static uword unformat_condition(unformat_input_t * input, va_list * va);
static uword unformat_value(unformat_input_t * input, va_list * va);
static u8 *mmb_format_rule(u8 *s, va_list *args);
static u8 *mmb_format_rule_column(u8 *s, va_list *args);
static u8 *mmb_format_match(u8 *s, va_list *args);
static u8 *mmb_format_target(u8 *s, va_list *args);
static u8* mmb_format_field(u8 *s, va_list *args);
static u8* mmb_format_condition(u8 *s, va_list *args);
static u8* mmb_format_keyword(u8 *s, va_list *args);

static u8 parse_match(unformat_input_t * input, mmb_match_t *match);
static u8 parse_target(unformat_input_t * input, mmb_target_t *target);
static void mmb_free_rule(mmb_rule_t *rule);

static clib_error_t *validate_rule();
static_always_inline void print_rules(vlib_main_t * vm, mmb_rule_t *rules);

static_always_inline u8 *str_tolower(u8 *str) {
  for(int i = 0; str[i]; i++){
    str[i] = tolower(str[i]);
  }
  return str;
}

static_always_inline void unformat_input_tolower(unformat_input_t *input) {
  str_tolower(input->buffer);
}

static_always_inline u8 field_toindex(u8 macro) {
  return macro-MMB_FIELD_NET_PROTO;
}
static_always_inline u8 field_tomacro(u8 index) {
  return index+MMB_FIELD_NET_PROTO;
}
static_always_inline u8 cond_toindex(u8 macro) {
  return macro-MMB_COND_EQ;
}
static_always_inline u8 cond_tomacro(u8 index) {
  return index+MMB_COND_EQ;
}

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
    
  int rv;
  while(unformat_check_input(input) != UNFORMAT_END_OF_INPUT) {
    if (!unformat(input, "%U", unformat_vnet_sw_interface, 
                  mm->vnet_main, &sw_if_index))
      break;
  }

  if (sw_if_index == ~0)
    return clib_error_return(0, "Please specify an interface...");
    
  rv = mmb_enable_disable(mm, sw_if_index, enable_disable);

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
  print_rules(vm, mm->rules);

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
    if (!parse_match(input, &match)) 
      break;
    else vec_add1(matches, match);
  } 
  if (vec_len(matches) < 1)
     return clib_error_return (0, "at least one <match> must be set");

  /* parse targets */
  mmb_target_t *targets = 0, target;
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) {
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

static_always_inline void resize_value(u8 field, u8 **value) {
  u8 user_len = vec_len(*value);
  if (user_len == 0) return;

  u8 proper_len = lens[field_toindex(field)];
  if (proper_len == 0) return;

  if (user_len > proper_len)
    vec_delete(*value, user_len-proper_len, 0);
  else if (user_len < proper_len)
    vec_insert(*value, proper_len-user_len, 0);
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
         /* so this is NOT "bit-field is present in current packet" */
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

uword unformat_field(unformat_input_t * input, va_list * va) {
  u8 *field = va_arg(*va, u8*);
  u8 *kind  = va_arg(*va, u8*);
  for (u8 i=0; i<fields_len; i++) {
    if (unformat (input, fields[i])) {
      *field = field_tomacro(i);
 
      /* optional kind */
      if (*field == MMB_FIELD_TCP_OPT
          && (unformat(input, "x%x", kind)
              || unformat(input, "0x%x", kind) 
              || unformat(input, "%d", kind)))
        ;
      return 1;
    }
  }

  return 0;
}

uword unformat_condition(unformat_input_t * input, va_list * va) {
  u8 *cond = va_arg(*va, u8*);
  for (u8 i=0; i<conditions_len; i++) {
    if (unformat (input, conditions[i])) {
      *cond = cond_tomacro(i);
      return 1;
    }
  }

  return 0;
}

static_always_inline void u64_tobytes(u8 **bytes, u64 value, u8 count) {
  for (int i=count-1; i>=0; i--)
    vec_add1(*bytes, value>>(i*8)); 
}

/* Parse an IP4 address %d.%d.%d.%d[/%d] */
uword
mmb_unformat_ip4_address (unformat_input_t * input, va_list * args) {
  u8 **result = va_arg (*args, u8 **);
  unsigned a[5];

  if (unformat (input, "%d.%d.%d.%d/%d", &a[0], &a[1], &a[2], &a[3], &a[4])) {
    if (a[4] > 32)
      return 0;
  } else if (unformat (input, "%d.%d.%d.%d", &a[0], &a[1], &a[2], &a[3])) 
    a[4] = 32;
  else return 0;

  if (a[0] >= 256 || a[1] >= 256 || a[2] >= 256 || a[3] >= 256)
    return 0;

  vec_add1 (*result, a[0]);
  vec_add1 (*result, a[1]);
  vec_add1 (*result, a[2]);
  vec_add1 (*result, a[3]);
  vec_add1 (*result, a[4]);

  return 1;
}

uword unformat_value(unformat_input_t * input, va_list * va) {
  u8 **bytes = va_arg(*va, u8**);
  u8 found_l4 = 0;
  u16 found_l3 = 0;
  u64 decimal = 0;

   if (0);
#define _(a,b) else if (unformat (input, #a)) found_l4 = IP_PROTOCOL_##b;
   foreach_mmb_transport_proto
#undef _
#define _(a,b) else if (unformat (input, #a)) found_l3 = ETHERNET_TYPE_##b;
   foreach_mmb_network_proto
#undef _

  if (found_l4) {
    u64_tobytes(bytes, found_l4, 1);
    return 1;
  } else if (found_l3) {
    u64_tobytes(bytes, found_l3, 2);
    return 1;
  }

  if (unformat(input, "%U", mmb_unformat_ip4_address, bytes))   
    ;
  else if (unformat (input, "0x") 
    || unformat (input, "x")) {
    /* hex value */ 

    u8 *hex_str = 0;
    if (unformat (input, "%U", unformat_hex_string, bytes))
      ;
    else if (unformat (input, "%s", &hex_str)) {

      /* add an extra 0 for parity */  
      unformat_input_t str_input, *sub_input = &str_input; 
      unformat_init(sub_input, 0, 0);
      unformat_init_vector(sub_input, format(0, "0%s", hex_str));
      if (!unformat (sub_input, "%U", unformat_hex_string, bytes)) {
        unformat_free(sub_input);
        return 0;
      }
      unformat_free(sub_input);
    }
    
  } else if (unformat (input, "%lu", &decimal)) {
     u64_tobytes(bytes, decimal, 8);
  } else 
    return 0;

  return 1;
}

u8 parse_target(unformat_input_t * input, mmb_target_t *target) {
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
   
   resize_value(target->field, &target->value);
   return 1;
}

u8 parse_match(unformat_input_t * input, mmb_match_t *match) {
   if (unformat(input, "!"))
     match->reverse = 1;
   
   if (unformat(input, "%U %U %U", unformat_field, 
                    &match->field, &match->opt_kind, unformat_condition, 
                    &match->condition, unformat_value, &match->value)) 
     ;
   else if (unformat(input, "%U %U", unformat_field, 
                    &match->field, &match->opt_kind, 
                    unformat_value, &match->value)) 
     match->condition = MMB_COND_EQ;
   else if (unformat(input, "%U", unformat_field,
                    &match->field, &match->opt_kind)) 
     ;
   else 
     return 0;

   resize_value(match->field, &match->value);
   return 1;
}

u8* mmb_format_field(u8* s, va_list *args) {
   u8 field = *va_arg(*args, u8*); 
   u8 kind  = *va_arg(*args, u8*);

   u8 field_index = field_toindex(field);
   if (field < MMB_FIELD_NET_PROTO 
    || field > MMB_FIELD_NET_PROTO+fields_len)
     ; 
   else if (field == MMB_FIELD_TCP_OPT && kind) {
     if (0);
#define _(a,b,c) else if (kind == c) s = format(s, "%s %s", fields[field_index], #b);
   foreach_mmb_tcp_opts
#undef _
     else s = format(s, "%s %d", fields[field_index], kind);
   } else
     s = format(s, "%s", fields[field_index]);

   return s;
}

u8* mmb_format_condition(u8* s, va_list *args) {
  u8 condition = *va_arg(*args, u8*);
  if (condition >= MMB_COND_EQ 
    &&  condition <= MMB_COND_EQ+conditions_len)
    s = format(s, "%s", conditions[cond_toindex(condition)]);
  
  return s;
}

u8* mmb_format_keyword(u8* s, va_list *args) {
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

static_always_inline u8 *mmb_format_ip_protocol (u8 * s, va_list * args)
{
  u8 protocol = va_arg (*args, ip_protocol_t);
  if (protocol == IP_PROTOCOL_RESERVED)
    return format(s, "all");
  return format(s, "%U", format_ip_protocol, protocol);
}

static_always_inline void print_rules(vlib_main_t * vm, mmb_rule_t *rules) {
   vl_print(vm, " Index%2sL3%4sL4%6sMatches%33sTargets\n", 
                blanks, blanks, blanks, blanks);
   uword rule_index = 0;
   vec_foreach_index(rule_index, rules) {
     vl_print(vm, " %d\t%U%s", rule_index+1, 
              mmb_format_rule_column, &rules[rule_index], 
              rule_index == vec_len(rules)-1 ? "" : "\n");
   }
}

u8 *mmb_format_rule(u8 *s, va_list *args) {
  mmb_rule_t *rule = va_arg(*args, mmb_rule_t*);
  s = format(s, "%-4U\t%-8U", format_ethernet_type, rule->l3, 
                              mmb_format_ip_protocol, rule->l4); 
  
  uword index = 0;
  vec_foreach_index(index, rule->matches) {
    s = format(s, "%U%s", mmb_format_match, &rule->matches[index],
                        (index != vec_len(rule->matches)-1) ? " AND ":"\t");
  }

  vec_foreach_index(index, rule->targets) {
    s = format(s, "%U%s", mmb_format_target, &rule->targets[index],  
                        (index != vec_len(rule->targets)-1) ? ", ":"");
  }
  return s;
}

u8 *mmb_format_rule_column(u8 *s, va_list *args) {
  mmb_rule_t *rule = va_arg(*args, mmb_rule_t*);
  s = format(s, "%-4U  %-8U", format_ethernet_type, rule->l3, 
                              mmb_format_ip_protocol, rule->l4); 
  
  for (uword index = 0; 
       index<clib_max(vec_len(rule->matches), vec_len(rule->targets)); 
       index++) {
    if (index < vec_len(rule->matches)) {
      /* tabulate empty line */
      if (index) 
        s = format(s, "%22s", "AND ");
      s = format(s, "%-40U", mmb_format_match, &rule->matches[index]);

    } else  
      s = format(s, "%62s", blanks);

    if (index < vec_len(rule->targets)) 
      s = format(s, "%-40U", mmb_format_target, &rule->targets[index]);
    s = format(s, "\n");

  }
  return s;
}

static_always_inline u8 *mmb_format_bytes(u8 *s, va_list *args) {
  u8 *byte, *bytes = va_arg(*args, u8*);
  u8 field = va_arg(*args, u32);
  switch (field) {
    case MMB_FIELD_IP_SADDR:
    case MMB_FIELD_IP_DADDR:
      s = format(s, "%U", format_ip4_address_and_length, bytes, bytes[4]);
      break;

    
    default:
      vec_foreach(byte, bytes) {
        s = format(s, "%02x", *byte);
      }
    break;
  }
  return s;
}

u8 *mmb_format_match(u8 *s, va_list *args) {

  mmb_match_t *match = va_arg(*args, mmb_match_t*);
  s = format(s, "%s%U %U %U", (match->reverse) ? "! ":"",
                          mmb_format_field, &match->field, &match->opt_kind,
                          mmb_format_condition, &match->condition,
                          mmb_format_bytes, match->value, match->field
                          );
  return s;
} 

u8 *mmb_format_target(u8 *s, va_list *args) {

  mmb_target_t *target = va_arg(*args, mmb_target_t*);
  s = format(s, "%s%U %U %U", (target->reverse) ? "! ":"",
                         mmb_format_keyword, &target->keyword,
                         mmb_format_field, &target->field, &target->opt_kind,
                         mmb_format_bytes, target->value, target->field
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
//TODO: work in progress (we may need to change the node location...)
VNET_FEATURE_INIT (mmb, static) = {
  .arc_name = "ip4-unicast", //ip4-output
  .node_name = "mmb",
  .runs_before = VNET_FEATURES ("ip4-lookup"), //interface-output
};
