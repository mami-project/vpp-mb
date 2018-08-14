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
 * @file
 * @brief MMB Plugin, format / unformat
 * @author Korian Edeline
 */

#include <ctype.h>
#include <netdb.h>

#include <vppinfra/string.h>
#include <vlib/vlib.h>

#include <mmb/mmb_format.h>

#define MMB_DISPLAY_MAX_BYTES 14
#define MMB_DISPLAY_MAX_MASK_HEX 32

#define bitmap_size(ai) vec_len(ai)*BITS(uword)

static uword mmb_unformat_field(unformat_input_t *input, va_list *args);
static uword mmb_unformat_condition(unformat_input_t *input, va_list *args);
static uword mmb_unformat_value(unformat_input_t *input, va_list *args);
static uword mmb_unformat_ip4_address (unformat_input_t *input, va_list *args);
static uword mmb_unformat_fibs(unformat_input_t *input, va_list *args);
static u8* mmb_format_match(u8 *s, va_list *args);
static u8* mmb_format_target(u8 *s, va_list *args);
static u8* mmb_format_field(u8 *s, va_list *args);
static u8* mmb_format_condition(u8 *s, va_list *args);
static u8* mmb_format_keyword(u8 *s, va_list *args);
static u8* mmb_format_rule_column(u8 *s, va_list *args);
static u8* mmb_format_table(u8 *s, va_list *args);

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
  u8 **bytes = va_arg(*args, u8**);
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

      vec_validate(*bytes, 16);
      for (i = 0; i < ARRAY_LEN(hex_quads); i++) 
         (*((u16**)bytes))[i] = clib_host_to_net_u16(hex_quads[i]); 

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

    if (vec_len(*bytes) > MMB_MAX_FIELD_LEN) 
      return 0;
    
  } else if (unformat (input, "%lu", &decimal)) {
     u64_tobytes(bytes, decimal, 8);
  } else 
    return 0;

  return 1;
}

uword mmb_unformat_fibs(unformat_input_t *input, va_list *args) {
   u8 **bytes = va_arg(*args, u8**);
   u32 fib_index;

   while (unformat(input, " %u", &fib_index)) 
     vec_add1(*bytes,(u8)fib_index);
 
   return vec_len(*bytes) > 0;
}

uword mmb_unformat_perc(unformat_input_t *input, va_list *args) {
   u8 **bytes = va_arg(*args, u8**);
   f64 perc;

   if (unformat(input, "%lf", &perc) && perc > 0.0 && perc <= 100.0) {
      vec_validate(*bytes, 4);
      (*((u32**)bytes))[0] = (u32) (perc * (MMB_MAX_DROP_RATE_VALUE/100)); /* XXX: not kosher */
      return 1;
   }

   return 0;
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
   else if (unformat(input, "drop %U", mmb_unformat_perc, &target->value))
     target->keyword=MMB_TARGET_DROP;
   else if (unformat(input, "drop"))
     target->keyword=MMB_TARGET_DROP;
   else if (unformat(input, "lb%U", mmb_unformat_fibs, &target->value)) 
     target->keyword=MMB_TARGET_LB; 
   else if (unformat(input, "shuffle %U", mmb_unformat_field, 
                      &target->field, &target->opt_kind)) 
     target->keyword=MMB_TARGET_SHUFFLE;
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
   if (!is_macro_mmb_field(field))
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
  if (is_macro_mmb_condition(condition))
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
    case MMB_TARGET_LB:
       keyword_str =  "lb";
       break;
    case MMB_TARGET_SHUFFLE:
       keyword_str =  "shuffle";
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

static_always_inline u8 *mmb_format_lb(u8 *s, va_list *args) {
   u8 *byte, *bytes = va_arg(*args, u8*);

   s = format(s, "lb");
   vec_foreach(byte, bytes) {
     s = format(s, " %u", *byte);
   }

   return s;
}

static_always_inline u8 *mmb_format_drop(u8 *s, va_list *args) {
   u8 *drop_value = va_arg(*args, u8*);
   u32 drop_rate; 

   s = format(s, "drop");
   if (vec_len(drop_value) == 0)
      return s;

   drop_rate = ((u32*)drop_value)[0];
   if (drop_rate != MMB_MAX_DROP_RATE_VALUE) {
      s = format(s, " %.2f%%", (f64)drop_rate/(MMB_MAX_DROP_RATE_VALUE/100));
   }

   return s;
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
  s = format(s, "s:%u l3:%U l4:%U in:%U out:%U ", rule->stateful, 
             format_ethernet_type, rule->l3, 
             mmb_format_ip_protocol, rule->l4, mmb_format_if_sw_index, rule->in, 
             mmb_format_if_sw_index, rule->out);  

  uword index=0;
  mmb_match_t *matches = vec_dup(rule->matches);
  vec_append(matches, rule->opt_matches);
  vec_foreach_index(index, matches) {
    s = format(s, "%U%s", mmb_format_match, &matches[index],
                        (index != vec_len(matches)-1) ? " AND ":" ");
  }
  vec_free(matches);

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

  vec_foreach_index(index, rule->shuffle_targets) {
    s = format(s, "%s%U", (vec_len(rule->targets)>0  || vec_len(rule->opt_mods)>0
                            || rule->has_strips ||  vec_len(rule->opt_adds)>0) 
                          ? ", ":"",
                         mmb_format_target, &rule->shuffle_targets[index]);
  }

  return s;
}

static u8* mmb_format_rule_column(u8 *s, va_list *args) {
  mmb_rule_t *rule = va_arg(*args, mmb_rule_t*);

  s = format(s, "%-4U  %-8U %-16U %-16U %c%6s", 
                format_ethernet_type, rule->l3, 
                mmb_format_ip_protocol, rule->l4,
                mmb_format_if_sw_index, rule->in,
                mmb_format_if_sw_index, rule->out,
                rule->stateful ? 'x' : ' ', blanks); 
  uword index, add_index=0, mod_index=0;
  uword strip_index = rule->whitelist ? clib_bitmap_first_clear(rule->opt_strips) 
                                      : clib_bitmap_first_set(rule->opt_strips);
  uword (*next_func) (uword *ai, uword i) = rule->whitelist 
                                              ? &clib_bitmap_next_clear_corrected
                                              : &clib_bitmap_next_set;

  /* merge all matches */
  mmb_match_t *matches = vec_dup(rule->matches);
  vec_append(matches, rule->opt_matches);

  /* merge shuffles and opt_mods */
  mmb_target_t *targets = vec_dup(rule->opt_mods);
  vec_append(targets,rule->shuffle_targets );

  /* count lines to print */
  uword match_count = vec_len(matches);
  uword strip_count = rule->whitelist 
                       ? bitmap_size(rule->opt_strips)
                           - clib_bitmap_count_set_bits(rule->opt_strips)
                       : clib_bitmap_count_set_bits(rule->opt_strips);
  uword target_count = vec_len(rule->targets)+vec_len(rule->opt_adds)
                       + vec_len(targets)+strip_count;
  uword count = clib_max(match_count,target_count);
                   
  for (index=0; index<count; index++) {
    if (index < match_count) {
      /* tabulate empty line */
      if (index) 
         s = format(s, "%64s", "AND ");

      s = format(s, "%-40U", mmb_format_match, &matches[index]);

    } else  
      s = format(s, "%104s", blanks);

   if (index < vec_len(rule->targets)) 
      s = format(s, "%-40U", mmb_format_target, &rule->targets[index]);
   else if (strip_index != ~0) { 
      mmb_target_t strip_target = target_from_strip(rule, strip_index);
      s = format(s, "%-40U", mmb_format_target, &strip_target);
      strip_index = next_func(rule->opt_strips, strip_index+1);
    } else if (mod_index < vec_len(targets)) {
      s = format(s, "%-40U", mmb_format_target, &targets[mod_index]);
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

  vec_free(matches);
  vec_free(targets);
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
  if (bytes == 0 && field == 0) return s;
  u32 index, padding=mmb_field_str_len(field);

  switch (field) {
    case MMB_FIELD_IP4_SADDR:
    case MMB_FIELD_IP4_DADDR:
      s = format(s, "%U", mmb_format_ip4_address, bytes);
      break;
    case MMB_FIELD_IP6_SADDR:
    case MMB_FIELD_IP6_DADDR:
      s = format(s, "%U", mmb_format_ip6_address, bytes);
      break;
    case MMB_FIELD_IP4_PROTO:
    case MMB_FIELD_IP6_NEXT:
      s = format(s, "%U", format_ip_protocol, bytes[0]);
      break;

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
  if (target->keyword == MMB_TARGET_LB)
     return format(s, "%U", mmb_format_lb, target->value);
  if (target->keyword == MMB_TARGET_DROP)
     return format(s, "%U", mmb_format_drop, target->value);  

  return format(s, "%s%U %U %U", (target->reverse) ? "! ":"",
                         mmb_format_keyword, &target->keyword,
                         mmb_format_field, &target->field, &target->opt_kind,
                         mmb_format_value, target->value, target->field
                         );
}

u8* mmb_format_rules(u8 *s, va_list *args) {
  mmb_rule_t *rules = va_arg(*args, mmb_rule_t*);

  s = format(s, " Index%2sL3%4sL4%7sin%15sout%14sS%6sMatches%33sTargets%33sCount\n", 
                blanks, blanks, blanks, blanks, blanks, blanks, blanks, blanks);
  uword rule_index = 0;
  vec_foreach_index(rule_index, rules) {
    s = format(s, " %d\t%U%s", rule_index+1, mmb_format_rule_column, 
               &rules[rule_index], rule_index == vec_len(rules)-1 ? "" : "\n");
  }

  return s;
}

static_always_inline u8* mmb_format_mask(u8 *s, va_list *args) {
  u8 *bytes = va_arg(*args, u8*);
  if (bytes == 0) 
      return s;

  u32 index;
   vec_foreach_index(index, bytes) {
     if (index % MMB_DISPLAY_MAX_MASK_HEX == 0 && index != 0) {
       s = format(s, "\n\t%5s", blanks);
     }
     s = format(s, "%02x", bytes[index]);
   }

  return s;
}

u8* mmb_format_key(u8 *s, va_list *args) {
  u8 *bytes = va_arg(*args, u8*);
  if (bytes == 0) 
      return s;

  u32 index;
   vec_foreach_index(index, bytes) {
     if (index % MMB_DISPLAY_MAX_MASK_HEX == 0 && index != 0) {
       s = format(s, "\n\t%8s", blanks);
     }
     s = format(s, "%02x", bytes[index]);
   }

  return s;
}

u8* mmb_format_u32_index(u8 *s, va_list *args) {
   u32 index = va_arg(*args, u32);
   if (index == ~0)
      return format(s, "-1");
   else
      return format(s, "%u", index); 
}

u8 *mmb_format_session(u8 *s, va_list *args) {
   mmb_session_t *session = va_arg(*args, mmb_session_t*);

   s = format(s, "lookup index %U\n", mmb_format_u32_index, session->lookup_index);
   s = format(s, "\t%5skey %U", blanks, mmb_format_key, session->key);

   return s;
}

u8* mmb_format_table(u8 *s, va_list *args) {

   mmb_table_t *table = va_arg(*args, mmb_table_t*);
   int verbose = va_arg(*args, int);

   s = format(s, "index %U next %U prev %U\n", mmb_format_u32_index, table->index, 
              mmb_format_u32_index, table->next_index, 
              mmb_format_u32_index, table->previous_index);
   s = format(s, "\tsession count %u capacity %u\n", table->entry_count, table->size);
   s = format(s, "\tskip %u match %u\n", table->skip, table->match);
   s = format(s, "\tmask %U\n", mmb_format_mask, table->mask);

   if (verbose) {
      mmb_session_t *session, *sessions = table->sessions;
      u32 session_index = 0;

      s = format(s, "\tsessions:\n");
      vec_foreach_index(session_index, sessions) {
         session = &sessions[session_index];
         s = format(s, "\t %u:%2s%U\n", session_index, blanks, 
                    mmb_format_session, session);
      }
   }

   return s;
}

u8 *mmb_format_lookup_table(u8 *s, va_list *args) {

   mmb_lookup_entry_t *lookup_pool = va_arg(*args, mmb_lookup_entry_t*);
   mmb_lookup_entry_t *lookup_entry;
   u32 *rule_index, lookup_index;

   pool_foreach_index(lookup_index, lookup_pool, ({
      s = format(s, "lookup index %d\n", lookup_index);

      lookup_entry = pool_elt_at_index(lookup_pool, lookup_index);
      vec_foreach(rule_index, lookup_entry->rule_indexes) {
         s = format(s, "  rule index %d\n", *rule_index);
      }
      s = format(s, "\n", *rule_index);
   }));

   return s;
}

u8* mmb_format_tables(u8 *s, va_list *args) {
   mmb_table_t *tables = va_arg(*args, mmb_table_t*);
   int verbose = va_arg(*args, int);
   uword table_index = 0;   

   vec_foreach_index(table_index, tables) {
      s = format(s, "[%u]:\t%U%s", table_index, mmb_format_table, 
                 &tables[table_index], verbose, 
                 table_index == vec_len(tables)-1 ? "" : "\n");
   }

   return s;
}

u8 *mmb_format_timeout_type(u8 *s, va_list *args) {
   int timeout_type = va_arg(*args, int);

   switch(timeout_type) {
      case MMB_TIMEOUT_TCP_TRANSIENT:
         s = format(s, "tcp transient");
         break;
      case MMB_TIMEOUT_TCP_IDLE:
         s = format(s, "tcp idle");
         break;
      case MMB_TIMEOUT_UDP_IDLE:
         s = format(s, "udp idle");
         break;
      default:
         break;
   }

   return s;
}

static_always_inline u8 *mmb_format_5tuple(u8 *s, va_list *args) {
   
   mmb_5tuple_t *pkt_5tuple = va_arg(*args, mmb_5tuple_t*);
   ip46_type_t type;   

   if (ip46_address_is_ip4(&pkt_5tuple->addr[0]) 
        && ip46_address_is_ip4(&pkt_5tuple->addr[1]))
      type = IP46_TYPE_IP4;
   else
      type = IP46_TYPE_IP6;

   s = format(s, "%U:%u -> %U:%u", 
         format_ip46_address, &pkt_5tuple->addr[0], type,
         pkt_5tuple->l4.port[0], 
         format_ip46_address, &pkt_5tuple->addr[1], type,
         pkt_5tuple->l4.port[1]);

   return s;
}

u8 *mmb_format_conn_table(u8 *s, va_list *args) {

   mmb_conn_table_t *mct = va_arg(*args, mmb_conn_table_t*);
   int verbose = va_arg(*args, int), count=0;
   
   mmb_main_t *mm = &mmb_main;
   f64 cps = mm->vlib_main->clib_time.clocks_per_second;
   mmb_conn_t *conn_pool = mct->conn_pool, *conn;
   u32 *rule_index, conn_index;   
   u64 now_ticks = clib_cpu_time_now();

   if (verbose)
      s = format(s, "%U\n", BV(format_bihash), &mct->conn_hash, verbose);

   s = format(s, "Connections pool");
   if (pool_elts(conn_pool) == 0)
      s = format(s, " is empty");
   s = format(s, "\n");

   pool_foreach(conn, conn_pool,({

     conn_index = conn - conn_pool;
     s = format(s, "[%u]: %U\n", conn_index+1, mmb_format_timeout_type, 
                     get_conn_timeout_type(mct, conn));
     s = format(s, " %U\n", mmb_format_5tuple, &conn->info);

     s = format(s, " rules:");
     vec_foreach(rule_index, conn->rule_indexes) {
        s = format(s, " %u", *rule_index);
        if ((count % 20) == 0 && count > 0)
          s = format(s, "\n%7s", blanks);
        count++;
     };
     s = format(s, "\n");

     if (verbose) {
        int timeout_type = get_conn_timeout_type(mct, conn);
        f64 expiring_time = (get_conn_timeout_time(mct, conn) - now_ticks) / cps;
        s = format(s, " expiring in %U\n", format_time_interval, 
                  "h:m:s", expiring_time);
        
        if (timeout_type != MMB_TIMEOUT_UDP_IDLE)
           s = format(s, " tcp-flags-seen forward %02x backward %02x\n", 
                       conn->tcp_flags_seen.as_u8[0], conn->tcp_flags_seen.as_u8[1]);
        
        if (conn->tcp_seq_offset)
           s = format(s, " tcp-seq-num shuffled by offset %08llx\n", 
                       conn->tcp_seq_offset);
        if (conn->tcp_ack_offset)
           s = format(s, " tcp-ack-num shuffled by offset %08llx\n", 
                       conn->tcp_ack_offset);
        if (conn->sport)
           s = format(s, " sport mapped to %u\n", 
                       clib_net_to_host_u16(conn->sport));
        if (conn->dport)
           s = format(s, " dport mapped to %u\n", 
                        clib_net_to_host_u16(conn->dport));
        if (conn->ip_id)
           s = format(s, " next ip-id/flow %08llx\n", 
                        conn->ip_id);
        if (conn->mapped_sack)
           s = format(s, " SACK-aware\n");

        s = format(s, "\n");
     }

   }));

   return s;
}

