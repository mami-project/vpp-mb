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
 * @brief MMB Plugin, format / unformat
 * @author K.Edeline
 */

#include <vppinfra/string.h>
#include <vlib/vlib.h>
#include <ctype.h>

#include <mmb/mmb_format.h>

#define MMB_DISPLAY_MAX_BYTES 14

#define bitmap_size(ai) vec_len(ai)*BITS(uword)

static uword mmb_unformat_field(unformat_input_t *input, va_list *args);
static uword mmb_unformat_condition(unformat_input_t *input, va_list *args);
static uword mmb_unformat_value(unformat_input_t *input, va_list *args);
static uword mmb_unformat_ip4_address (unformat_input_t *input, va_list *args);
static u8* mmb_format_match(u8 *s, va_list *args);
static u8* mmb_format_target(u8 *s, va_list *args);
static u8* mmb_format_field(u8 *s, va_list *args);
static u8* mmb_format_condition(u8 *s, va_list *args);
static u8* mmb_format_keyword(u8 *s, va_list *args);
static u8* mmb_format_rule_column(u8 *s, va_list *args);

static const char* blanks = "                                                "
                            "                                                "
                            "                                                "
                            "                                                ";

static_always_inline u8 *str_tolower(u8 *str) {
  for(int i = 0; str[i]; i++){
    str[i] = tolower(str[i]);
  }
  return str;
}

void unformat_input_tolower(unformat_input_t *input) {
  str_tolower(input->buffer);
}

/**
 * resize value of fixed length field,
 *
 * @return vec_len(value) 
 */
static_always_inline int resize_value(u8 field, u8 **value) {
  u8 user_len = vec_len(*value);
  u8 proper_len = lens[field_toindex(field)];

  if (!is_fixed_length(field)) return user_len;
  if (user_len == 0) return 0;

  /* left padding/truncating */
  if (user_len > proper_len)
    vec_delete(*value, user_len-proper_len, 0);
  else if (user_len < proper_len)
    vec_insert(*value, proper_len-user_len, 0);
  return vec_len(*value);
}

uword mmb_unformat_field(unformat_input_t *input, va_list *args) {
  u8 *field = va_arg(*args, u8*);
  u8 *kind  = va_arg(*args, u8*);
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

uword mmb_unformat_condition(unformat_input_t *input, va_list *args) {
  u8 *cond = va_arg(*args, u8*);
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

/** 
 * Parse an IP4 address %d.%d.%d.%d[/%d] 
 * 
 * (modified from vnet/ip/ip4_format.c)
 **/
uword mmb_unformat_ip4_address(unformat_input_t *input, va_list *args) {
  u8 **result = va_arg(*args, u8**);
  unsigned a[5], i;

  if (unformat(input, "%d.%d.%d.%d/%d", &a[0], &a[1], &a[2], &a[3], &a[4])) {
    if (a[4] > 32)
      return 0;
  } else if (unformat(input, "%d.%d.%d.%d", &a[0], &a[1], &a[2], &a[3])) 
    a[4] = 32;
  else return 0;

  if (a[0] >= 256 || a[1] >= 256 || a[2] >= 256 || a[3] >= 256)
    return 0;

  for (i=0; i<5; i++)
    vec_add1(*result, a[i]);

  return 1;
}

/** Parse an IP6 address. 
 *  
 * (modified from vnet/ip/ip6_format.c)
 **/
uword
mmb_unformat_ip6_address(unformat_input_t *input, va_list *args) {
  u16 **result = va_arg(*args, u16**);
  u8 **bytes = (u8**)result; /* is this ok ? */
  u16 hex_quads[8];
  uword hex_quad, n_hex_quads, hex_digit, n_hex_digits;
  uword c, n_colon, double_colon_index;

  n_hex_quads = hex_quad = n_hex_digits = n_colon = 0;
  double_colon_index = ARRAY_LEN(hex_quads);
  while ((c = unformat_get_input(input)) != UNFORMAT_END_OF_INPUT) {
      hex_digit = 16;
      if (c >= '0' && c <= '9')
         hex_digit = c - '0';
      else if (c >= 'a' && c <= 'f')
	      hex_digit = c + 10 - 'a';
      else if (c >= 'A' && c <= 'F')
	      hex_digit = c + 10 - 'A';
      else if (c == ':' && n_colon < 2)
	      n_colon++;
      else {
	      unformat_put_input(input);
	      break;
      }

      /* Too many hex quads. */
      if (n_hex_quads >= ARRAY_LEN(hex_quads))
	      return 0;

      if (hex_digit < 16) {
	      hex_quad = (hex_quad << 4) | hex_digit;

	      /* Hex quad must fit in 16 bits. */
	      if (n_hex_digits >= 4)
	         return 0;

	      n_colon = 0;
	      n_hex_digits++;
      }

      /* Save position of :: */
      if (n_colon == 2) {
	      /* More than one :: ? */
	      if (double_colon_index < ARRAY_LEN(hex_quads))
	         return 0;
	      double_colon_index = n_hex_quads;
      }

      if (n_colon > 0 && n_hex_digits > 0) {
	      hex_quads[n_hex_quads++] = hex_quad;
	      hex_quad = 0;
	      n_hex_digits = 0;
	   }
   }

   if (n_hex_digits > 0)
      hex_quads[n_hex_quads++] = hex_quad;

   {
      word i;

      /* Expand :: to appropriate number of zero hex quads. */
      if (double_colon_index < ARRAY_LEN(hex_quads)) {
         word n_zero = ARRAY_LEN(hex_quads) - n_hex_quads;

         for (i = n_hex_quads - 1; i >= (signed) double_colon_index; i--)
            hex_quads[n_zero + i] = hex_quads[i];

	      for (i = 0; i < n_zero; i++) {
            ASSERT((double_colon_index + i) < ARRAY_LEN(hex_quads));
	         hex_quads[double_colon_index + i] = 0;
         }

	      n_hex_quads = ARRAY_LEN(hex_quads);
      }

      /* Too few hex quads given. */
      if (n_hex_quads < ARRAY_LEN(hex_quads))
         return 0;

      for (i = 0; i < ARRAY_LEN(hex_quads); i++)
         vec_add1(*result, clib_host_to_net_u16(hex_quads[i]));

      /* parse mask */
      vec_validate(*bytes, 16);
      u32 mask = 128;
      unformat(input, "/%d", &mask);
      (*bytes)[16] = mask;

      return 1;
   }
}

static_always_inline uword mmb_unformat_transport_protocol(
            unformat_input_t *input, va_list *args) {
   u8 *l4 = va_arg(*args, u8*);
   if (0);
#define _(a,b) else if (unformat(input, "%_"#a)) {*l4 = IP_PROTOCOL_##b;\
                 return unformat_peek_input(input) == ' ';}
   foreach_mmb_transport_proto
#undef _
   return 0;
}

static_always_inline uword mmb_unformat_network_protocol(
            unformat_input_t *input, va_list *args) {
   u16 *l3 = va_arg(*args, u16*);
   if (0);
#define _(a,b) else if (unformat(input, "%_"#a)) {*l3 = ETHERNET_TYPE_##b;\
                 return unformat_peek_input(input) == ' ';}
   foreach_mmb_network_proto
#undef _
   return 0;
}

uword mmb_unformat_value(unformat_input_t *input, va_list *args) {
   u8 **bytes = va_arg(*args, u8**);
   u8 l4 = 0;
   u16 l3 = 0;
   u32 if_sw_index = ~0;
   u64 decimal = 0;
   mmb_main_t mm = mmb_main;

   /* protocol names */
  if (unformat(input, "%U", mmb_unformat_transport_protocol, &l4)) {
    u64_tobytes(bytes, l4, 1);
    return 1;
  } else if (unformat(input, "%U", mmb_unformat_network_protocol, &l3)) {
    u64_tobytes(bytes, l3, 2);
    return 1;
  }

  /* if names */
  if (unformat(input, "%U", unformat_vnet_sw_interface, 
               mm.vnet_main, &if_sw_index)) {
    u64_tobytes(bytes, if_sw_index, 4);
    return 1;
  }

  /* dec/hex value */
  if (unformat(input, "%U", mmb_unformat_ip4_address, bytes))   
    ;
  else if (unformat(input, "%U", mmb_unformat_ip6_address, bytes))
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

uword mmb_unformat_target(unformat_input_t *input, va_list *args) {
   mmb_target_t *target = va_arg(*args, mmb_target_t*);

   if (unformat(input, "strip ! %U", mmb_unformat_field, 
               &target->field, &target->opt_kind)) {
     target->keyword=MMB_TARGET_STRIP;
     target->reverse=1;
   } else if (unformat(input, "strip %U", mmb_unformat_field, 
                      &target->field, &target->opt_kind)) 
     target->keyword=MMB_TARGET_STRIP;
   else if (unformat(input, "mod %U %U", mmb_unformat_field, 
                    &target->field, &target->opt_kind, 
                    mmb_unformat_value, &target->value))
     target->keyword=MMB_TARGET_MODIFY; 
   else if (unformat(input, "add %U %U", mmb_unformat_field, 
                      &target->field, &target->opt_kind, 
                      mmb_unformat_value, &target->value)) 
     target->keyword=MMB_TARGET_ADD;
   else if (unformat(input, "add %U", mmb_unformat_field, 
                      &target->field, &target->opt_kind)) 
     target->keyword=MMB_TARGET_ADD;
   else if (unformat(input, "drop"))
     target->keyword=MMB_TARGET_DROP; 
   else 
     return 0;
   
   resize_value(target->field, &target->value);
   return 1;
}

uword mmb_unformat_match(unformat_input_t *input, va_list *args) {
   mmb_match_t *match = va_arg(*args, mmb_match_t*);

   if (unformat(input, "!"))
     match->reverse = 1;
   
   if (unformat(input, "%U %U %U", mmb_unformat_field, 
                    &match->field, &match->opt_kind, mmb_unformat_condition, 
                    &match->condition, mmb_unformat_value, &match->value)) 
     ;
   else if (unformat(input, "%U %U", mmb_unformat_field, 
                    &match->field, &match->opt_kind, 
                    mmb_unformat_value, &match->value)) 
     match->condition = MMB_COND_EQ;
   else if (unformat(input, "%U", mmb_unformat_field,
                    &match->field, &match->opt_kind)) 
     ;
   else 
     return 0;

   if (resize_value(match->field, &match->value) == 0)
      match->condition = 0;
   else if (!is_fixed_length(match->field) && match->condition != MMB_COND_EQ 
                                    && match->condition != MMB_COND_NEQ)
      return 0;
   return 1;
}

uword mmb_unformat_rule(unformat_input_t *input, va_list *args) {
   mmb_rule_t *rule = va_arg(*args, mmb_rule_t*);

   /* parse matches */
   mmb_match_t *matches = 0, match;
   while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) {
      memset(&match, 0, sizeof (mmb_match_t));
      if (!unformat(input, "%U", mmb_unformat_match, &match)) 
         break;
      else vec_add1(matches, match);
   } 
   if (vec_len(matches) < 1)
      return 0;

   /* parse targets */
   mmb_target_t *targets = 0, target;
   while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) {
      memset(&target, 0, sizeof (mmb_target_t));
      if (!unformat(input, "%U", mmb_unformat_target, &target)) 
         break;
      else vec_add1(targets, target);
   }
   if (vec_len(targets) < 1)
      return 0;

   rule->matches = matches;
   rule->targets = targets;

   return 1;
}

u8* mmb_format_field(u8 *s, va_list *args) {
   u8 field = *va_arg(*args, u8*); 
   u8 kind  = *va_arg(*args, u8*);

   u8 field_index = field_toindex(field);
   if (field < MMB_FIRST_FIELD 
    || field > MMB_LAST_FIELD)
     ; 
   else if (field == MMB_FIELD_TCP_OPT && kind) {
     if (0);//TODO: print kind 0 in strip
#define _(a,b,c) else if (kind == c) s = format(s, "%s %s", fields[field_index], #b);
   foreach_mmb_tcp_opts
#undef _
     else if (kind == MMB_FIELD_TCP_OPT_ALL)
       s = format(s, "%s all", fields[field_index]);
     else s = format(s, "%s %d", fields[field_index], kind);
   } else
     s = format(s, "%s", fields[field_index]);

   return s;
}

u8* mmb_format_condition(u8 *s, va_list *args) {
  u8 condition = *va_arg(*args, u8*);
  if (condition >= MMB_COND_EQ 
    &&  condition <= MMB_COND_EQ+conditions_len)
    s = format(s, "%s", conditions[cond_toindex(condition)]);
  
  return s;
}

u8* mmb_format_keyword(u8 *s, va_list *args) {
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
    case MMB_TARGET_ADD:
       keyword_str =  "add";
       break;
    default:
       break;
  }

  return format(s, "%s", keyword_str);
}

static_always_inline u8 *mmb_format_ip_protocol (u8 *s, va_list *args) {
  u8 protocol = va_arg (*args, ip_protocol_t);
  if (protocol == IP_PROTOCOL_RESERVED)
    return format(s, "all");
  return format(s, "%U", format_ip_protocol, protocol);
}

static_always_inline u8 *mmb_format_if_sw_index(u8 *s, va_list *args) {
  u32 sw_if_index = va_arg (*args, u32);
  mmb_main_t mm = mmb_main;
  if (sw_if_index == ~0)
    return format(s, "all");
  return format(s, "%U", format_vnet_sw_if_index_name, 
                mm.vnet_main, sw_if_index);
}

static_always_inline mmb_target_t target_from_strip(mmb_rule_t *rule, 
                                                    u8 opt_kind) {
   mmb_target_t strip_target;
   if (rule->l4 == IP_PROTOCOL_TCP)
      strip_target = (mmb_target_t) {
            .keyword = MMB_TARGET_STRIP,
            .field = MMB_FIELD_TCP_OPT,
            .opt_kind = opt_kind,
            .reverse = rule->whitelist,
            .value = 0
      };

   return strip_target;
}

static_always_inline mmb_target_t target_from_add(mmb_rule_t *rule, 
                                                  uword add_index) {
   mmb_target_t add_target;
   if (rule->l4 == IP_PROTOCOL_TCP)
      add_target = (mmb_target_t) {
            .keyword = MMB_TARGET_ADD,
            .field = MMB_FIELD_TCP_OPT,
            .opt_kind = rule->opt_adds[add_index].kind,
            .reverse = 0,
            .value = rule->opt_adds[add_index].value
      };

   return add_target;
}

/** Return the next clear bit in a bitmap starting at bit i
 *    @param ai - pointer to the bitmap
 *   @param i - first bit position to test
 *   @returns first clear bit position at or after i
 *
 * corrected from vppinfra/bitmap.h
 **/
always_inline uword
clib_bitmap_next_clear_corrected(uword *ai, uword i) {
  uword i0 = i / BITS (ai[0]);
  uword i1 = i % BITS (ai[0]);
  uword t;

  if (i0 < vec_len (ai)) {
     t = (~ai[i0] >> i1) << i1;
     if (t)
	    return log2_first_set (t) + i0 * BITS (ai[0]);

     for (i0++; i0 < vec_len (ai); i0++) {
	    t = ~ai[i0];
	    if (t)
	      return log2_first_set (t) + i0 * BITS (ai[0]);
	  }
  }
  return ~0;
}

u8* mmb_format_rule(u8 *s, va_list *args) {
  mmb_rule_t *rule = va_arg(*args, mmb_rule_t*);
  s = format(s, "l3:%U l4:%U in:%U out:%U ", format_ethernet_type, rule->l3, 
             mmb_format_ip_protocol, rule->l4, mmb_format_if_sw_index, rule->in, 
             mmb_format_if_sw_index, rule->out);

  if (rule->last_match)
    s = format(s, "L ");  

  uword index=0;
  vec_foreach_index(index, rule->matches) {
    s = format(s, "%U%s", mmb_format_match, &rule->matches[index],
                        (index != vec_len(rule->matches)-1) ? " AND ":" ");
  }

  vec_foreach_index(index, rule->targets) {
    s = format(s, "%U%s", mmb_format_target, &rule->targets[index],
                      (index != vec_len(rule->targets)-1) ? ", ":"");
  }

  if (rule->has_strips) {    
   index = rule->whitelist ? clib_bitmap_first_clear(rule->opt_strips) 
                           : clib_bitmap_first_set(rule->opt_strips);
   uword (*next_func) (uword *ai, uword i) = rule->whitelist 
               ? &clib_bitmap_next_clear_corrected
               : &clib_bitmap_next_set;
    while (index != ~0) {
      mmb_target_t strip_target = target_from_strip(rule, index);
      s=format(s, "%s%U",  (vec_len(rule->targets)>0) ? ", ":"",
                  mmb_format_target, &strip_target);
      index = next_func(rule->opt_strips, index+1);
    }    
  }

  vec_foreach_index(index, rule->opt_mods) {
    s = format(s, "%s%U", (vec_len(rule->targets)>0 
                            || rule->has_strips) ? ", ":"",
                         mmb_format_target, &rule->opt_mods[index]);
  }

  vec_foreach_index(index, rule->opt_adds) {
    mmb_target_t opt_target = target_from_add(rule, index);
    s = format(s, "%s%U", 
               (rule->has_strips || vec_len(rule->targets)>0 
                   || vec_len(rule->opt_mods)>0 ) ? ", ":"",
                mmb_format_target, &opt_target);
  }

  return s;
}

static u8* mmb_format_rule_column(u8 *s, va_list *args) {
  mmb_rule_t *rule = va_arg(*args, mmb_rule_t*);

  s = format(s, "%-4U  %-8U %-16U %-16U",
                format_ethernet_type, rule->l3, 
                mmb_format_ip_protocol, rule->l4,
                mmb_format_if_sw_index, rule->in,
                mmb_format_if_sw_index, rule->out); 
  uword index, add_index=0, mod_index=0;
  uword strip_index = rule->whitelist ? clib_bitmap_first_clear(rule->opt_strips) 
                                      : clib_bitmap_first_set(rule->opt_strips);
  uword (*next_func) (uword *ai, uword i) = rule->whitelist 
                                              ? &clib_bitmap_next_clear_corrected
                                              : &clib_bitmap_next_set;
  /* count lines to print */
  uword match_count = vec_len(rule->matches);
  uword strip_count = rule->whitelist 
                       ? bitmap_size(rule->opt_strips)
                           -clib_bitmap_count_set_bits(rule->opt_strips)
                       : clib_bitmap_count_set_bits(rule->opt_strips);
  uword target_count = vec_len(rule->targets)+vec_len(rule->opt_adds)
                      +vec_len(rule->opt_mods)+strip_count;
  uword count = clib_max(match_count,target_count);
                   
  for (index=0; index<count; index++) {
    if (index < vec_len(rule->matches)) {
      /* tabulate empty line */
      if (index) 
         s = format(s, "%56s", "AND ");

      if (index==0 && rule->last_match)
         s = format(s, "L %-38U", mmb_format_match, &rule->matches[index]);
      else
         s = format(s, "%-40U", mmb_format_match, &rule->matches[index]);

    } else  
      s = format(s, "%96s", blanks);

   if (index < vec_len(rule->targets)) 
      s = format(s, "%-40U", mmb_format_target, &rule->targets[index]);
   else if (strip_index != ~0) { 
      mmb_target_t strip_target = target_from_strip(rule, strip_index);
      s = format(s, "%-40U", mmb_format_target, &strip_target);
      strip_index = next_func(rule->opt_strips, strip_index+1);
    } else if (mod_index < vec_len(rule->opt_mods)) {
      s = format(s, "%-40U", mmb_format_target, &rule->opt_mods[mod_index]);
      mod_index++;
    } else if (add_index < vec_len(rule->opt_adds)) {
      mmb_target_t opt_target = target_from_add(rule, add_index);
      s = format(s, "%-40U", mmb_format_target, &opt_target);
      add_index++;
    }
    if (index == 0) 
      s = format(s, "%u", rule->match_count);
    s = format(s, "\n");
  }

  return s;
}

static_always_inline u32 mmb_field_str_len(u8 field) {
   u32 padding = strlen(fields[field_toindex(field)]);
   if (padding % 2 == 1) 
      padding++;
   padding /= 2;
   if (field==MMB_FIELD_TCP_OPT) 
      padding += 4;

   return padding;
}

static_always_inline u8* mmb_format_ip4_address(u8 *s, va_list *args) {
   u8 *bytes = va_arg(*args, u8*);

   if (bytes[4] == 32)
      s = format(s, "%U", format_ip4_address, bytes);
   else
      s = format(s, "%U", format_ip4_address_and_length, bytes, bytes[4]);
   return s;
}

static_always_inline u8* mmb_format_ip6_address(u8 *s, va_list *args) {
   u8 *bytes = va_arg(*args, u8*);

   if (bytes[16] == 128)
      s = format(s, "%U", format_ip6_address, (ip6_address_t*) bytes);
   else
      s = format(s, "%U", format_ip6_address_and_length, 
                         (ip6_address_t*) bytes, bytes[16]);
   return s;
}

static_always_inline u8* mmb_format_value(u8 *s, va_list *args) {
  u8 *bytes = va_arg(*args, u8*);
  u8 field = va_arg(*args, u32);
  u32 index, padding=mmb_field_str_len(field);

  switch (field) {
    case MMB_FIELD_IP4_SADDR:
    case MMB_FIELD_IP4_DADDR:
      s = format(s, "%U", mmb_format_ip4_address, bytes);
      break;
    case MMB_FIELD_IP6_SADDR:
    case MMB_FIELD_IP6_DADDR:
      s = format(s, "%U", mmb_format_ip6_address, bytes);
      break;// TODO:ports in text ?

    default: /* 40 chars = 20 bytes = field (var) + cond (4) + [..] */
      vec_foreach_index(index, bytes) {
        if (index >= MMB_DISPLAY_MAX_BYTES-padding) {
          s = format(s, "[..]");
          break;
        }
        s = format(s, "%02x", bytes[index]);
      }
    break;
  }

  return s;
}

u8* mmb_format_match(u8 *s, va_list *args) {

  mmb_match_t *match = va_arg(*args, mmb_match_t*);
  return format(s, "%s%U %U %U", (match->reverse) ? "! ":"",
                          mmb_format_field, &match->field, &match->opt_kind,
                          mmb_format_condition, &match->condition,
                          mmb_format_value, match->value, match->field
                          );
} 

u8* mmb_format_target(u8 *s, va_list *args) {

  mmb_target_t *target = va_arg(*args, mmb_target_t*);
  return format(s, "%s%U %U %U", (target->reverse) ? "! ":"",
                         mmb_format_keyword, &target->keyword,
                         mmb_format_field, &target->field, &target->opt_kind,
                         mmb_format_value, target->value, target->field
                         );
}

u8* mmb_format_rules(u8 *s, va_list *args) {
  mmb_rule_t *rules = va_arg(*args, mmb_rule_t*);

  s = format(s, " Index%2sL3%4sL4%7sin%15sout%13sMatches%33sTargets%33sCount\n", 
                blanks, blanks, blanks, blanks, blanks, blanks, blanks);
  uword rule_index = 0;
  vec_foreach_index(rule_index, rules) {
    s = format(s, " %d\t%U%s", rule_index+1, mmb_format_rule_column, 
               &rules[rule_index], rule_index == vec_len(rules)-1 ? "" : "\n");
  }
  return s;
}

