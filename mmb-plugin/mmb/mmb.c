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



#define MMB_UNKNOWN             0

#define MMB_TYPE_UNKNOWN        MMB_UNKNOWN
#define MMB_TYPE_FIELD          1
#define MMB_TYPE_CONDITION      2
#define MMB_TYPE_VALUE          3
#define MMB_TYPE_TARGET         4
#define MMB_TYPE_OPT_FIELD      5

#define BEGIN_MMB_CONDITIONS    10
#define MMB_COND_EQ             11
#define MMB_COND_NEQ            12
#define MMB_COND_LEQ            13
#define MMB_COND_GEQ            14
#define MMB_COND_L              15
#define MMB_COND_G              16
#define END_MMB_CONDITIONS      17

#define BEGIN_MMB_TARGETS       20
#define MMB_TARGET_DROP         21
#define MMB_TARGET_STRIP        22
#define MMB_TARGET_STRIP_ALL    23
#define MMB_TARGET_MODIFY       24
#define END_MMB_TARGETS         25

#define BEGIN_MMB_FIELDS        30
#define MMB_FIELD_IP_PROTO      31
//...
#define BEGIN_MMB_OPT_FIELDS    200
#define MMB_FIELD_TCP_MSS       201
//...
#define END_MMB_OPT_FIELDS      202
#define END_MMB_FIELDS          203



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

u8 is_value(char * str)
{
  if (str == NULL)
    return 0;

  char* tmp = str;

  //TODO: if needed, include "-" (minus) for negatives, "." (dot) for floating numbers, "0x" for hex values
  while(*tmp != '\0')
  {
    if (*tmp < '0' || *tmp > '9')
      return 0;

    tmp++;
  }

  return 1;
}

u8 is_negate(char * str)
{
  if (str == NULL)
    return 0;

  if (*str == '!')
    return 1;

  return 0;
}

u8 get_unique_id(char* element)
{
  /* Values */
  if (is_value(element))
    return MMB_TYPE_VALUE;

  /* Conditions */
  if (!strcmp(element, "=="))
    return MMB_COND_EQ;
  if (!strcmp(element, "!="))
    return MMB_COND_NEQ;
  if (!strcmp(element, "<="))
    return MMB_COND_LEQ;
  if (!strcmp(element, ">="))
    return MMB_COND_GEQ;
  if (!strcmp(element, "<"))
    return MMB_COND_L;
  if (!strcmp(element, ">"))
    return MMB_COND_G;

  /* Targets */
  if (!strcmp(element, "drop"))
    return MMB_TARGET_DROP;
  if (!strcmp(element, "strip"))
    return MMB_TARGET_STRIP;
  if (!strcmp(element, "all"))
    return MMB_TARGET_STRIP_ALL;
  if (!strcmp(element, "mod"))
    return MMB_TARGET_MODIFY;

  /* Fields */
  if (!strcmp(element, "ip-proto"))
    return MMB_FIELD_IP_PROTO;

  /* Options */
  if (!strcmp(element, "tcp-opt-mss"))
    return MMB_FIELD_TCP_MSS;

  /* Unknown... */
  return MMB_UNKNOWN;
}

u8 get_type(u8 id)
{
  /* Element belongs to the values group */
  if (id == MMB_TYPE_VALUE)
    return MMB_TYPE_VALUE;

  /* Element belongs to the conditions group */
  if (id > BEGIN_MMB_CONDITIONS && id < END_MMB_CONDITIONS)
    return MMB_TYPE_CONDITION;

  /* Element belongs to the targets group */
  if (id > BEGIN_MMB_TARGETS && id < END_MMB_TARGETS)
    return MMB_TYPE_TARGET;

  /* Element belongs to the OPTION fields group */
  if (id > BEGIN_MMB_OPT_FIELDS && id < END_MMB_OPT_FIELDS)
    return MMB_TYPE_OPT_FIELD;

  /* Element belongs to the fields group */
  if (id > BEGIN_MMB_FIELDS && id < END_MMB_FIELDS)
    return MMB_TYPE_FIELD;

  /* Element does not belong to any known group */
  return MMB_TYPE_UNKNOWN;
}

static clib_error_t *
add_rule_command_fn (vlib_main_t * vm, unformat_input_t * input, vlib_cli_command_t * cmd)
{
  u8 next_id, next_type, negate;

  /* Read first element - must be an existing field */

  char* field;
  if (!unformat(input, "%s", &field))
    return clib_error_return(0, "Missing field: use \"list fields\" command for help");

  negate = is_negate(field);
  if (negate)
    field++;

  u8 id = get_unique_id(field);
  u8 type = get_type(id);

  if (id == MMB_UNKNOWN || type != MMB_TYPE_FIELD)
    return clib_error_return(0, "Unknown field \"%s\": use \"list fields\" command for help", field);

  vlib_cli_output(vm, "Field = %s (negate = %s)\n", field, negate == 1 ? "true" : "false");

mmb_match_field:
  /*
   * Current element is a field (matching part)
   *
   * Next element can either be:
   *   - another field
   *   - a matching condition
   *   - a value (implicit "==" condition)
   *   - a target action (when fields matching ends)
   */;

  char* field_next;
  if (!unformat(input, "%s", &field_next))
    return clib_error_return(0, "Unexpected end of command line: a field must be followed by either another field, a condition, a value or a target action");

  negate = is_negate(field_next);
  if (negate)
    field_next++;

  next_id = get_unique_id(field_next);
  next_type = get_type(next_id);

  switch(next_type)
  {
    /* next element is a field */
    case MMB_TYPE_FIELD:
      vlib_cli_output(vm, "Next is a field = %s (negate = %s)\n", field_next, negate == 1 ? "true" : "false");
      goto mmb_match_field;

    /* next element is a condition */
    case MMB_TYPE_CONDITION:
      vlib_cli_output(vm, "Next is a condition = %s\n", field_next);
      goto mmb_match_condition;

    /* next element is a value */
    case MMB_TYPE_VALUE:
      vlib_cli_output(vm, "Next is a value = %s\n", field_next);
      goto mmb_match_value;

    /* next element is a target */
    case MMB_TYPE_TARGET:
      switch(next_id)
      {
        case MMB_TARGET_DROP:
          vlib_cli_output(vm, "Next is a DROP target (%s)\n", field_next);
          goto mmb_target_drop;

        case MMB_TARGET_STRIP:
          vlib_cli_output(vm, "Next is a STRIP target (%s)\n", field_next);
          goto mmb_target_strip;

        case MMB_TARGET_MODIFY:
          vlib_cli_output(vm, "Next is a MOD target (%s)\n", field_next);
          goto mmb_target_modify;

        default:
          return clib_error_return(0, "Unexpected target element \"%s\"", field_next);
      }

    /* Something unexpected */
    default:
      return clib_error_return(0, "Unexpected element \"%s\": a field must be followed by either another field, a condition, a value or a target action", field_next);
  }

mmb_match_condition:
  /*
   * Current element is a condition (matching part)
   *
   * Next element must be a value
   */;

  char* cond_next;
  if (!unformat(input, "%s", &cond_next))
    return clib_error_return(0, "Unexpected end of command line: a condition must be followed by a value");

  next_id = get_unique_id(cond_next);
  next_type = get_type(next_id);

  /* MUST be a value next */
  if (next_type != MMB_TYPE_VALUE)
    return clib_error_return(0, "Unexpected element \"%s\": a condition must be followed by a value", cond_next);

  vlib_cli_output(vm, "Next is a value = %s\n", cond_next);

mmb_match_value:
  /*
   * Current element is a value (matching part)
   *
   * Next element can either be:
   *   - a field
   *   - a target action (when fields matching ends)
   */;

  char* value_next;
  if (!unformat(input, "%s", &value_next))
    return clib_error_return(0, "Unexpected end of command line: a value must be followed by either a field or a target action");

  negate = is_negate(value_next);
  if (negate)
    value_next++;

  next_id = get_unique_id(value_next);
  next_type = get_type(next_id);

  switch(next_type)
  {
    /* next element is a field */
    case MMB_TYPE_FIELD:
      vlib_cli_output(vm, "Next is a field = %s (negate %s)\n", value_next, negate == 1 ? "true" : "false");
      goto mmb_match_field;

    /* next element is a target */
    case MMB_TYPE_TARGET:
      switch(next_id)
      {
        case MMB_TARGET_DROP:
          vlib_cli_output(vm, "Next is a DROP target (%s)\n", value_next);
          goto mmb_target_drop;

        case MMB_TARGET_STRIP:
          vlib_cli_output(vm, "Next is a STRIP target (%s)\n", value_next);
          goto mmb_target_strip;

        case MMB_TARGET_MODIFY:
          vlib_cli_output(vm, "Next is a MOD target (%s)\n", value_next);
          goto mmb_target_modify;

        default:
          return clib_error_return(0, "Unexpected target element \"%s\"", value_next);
      }

    /* Something unexpected */
    default:
      return clib_error_return(0, "Unexpected element \"%s\": a value must be followed by either a field or a target action", value_next);
  }

mmb_target_modify:
  /*
   * Current element is a MOD target (target part)
   *
   * Next element must be a field
   */;

  char* target_mod_next;
  if (!unformat(input, "%s", &target_mod_next))
    return clib_error_return(0, "Unexpected end of command line: a \"mod\" target must be followed by a field");

  next_id = get_unique_id(target_mod_next);
  next_type = get_type(next_id);

  /* MUST be a field next */
  if (next_type != MMB_TYPE_FIELD)
    return clib_error_return(0, "Unexpected element \"%s\": a \"mod\" target must be followed by a field", target_mod_next);

  vlib_cli_output(vm, "Next is a field = %s\n", target_mod_next);

mmb_target_modify_field:
  /*
   * Current element is a field in MOD target (target part)
   *
   * Next element must be a value
   */;

  char* target_mod_field_next;
  if (!unformat(input, "%s", &target_mod_field_next))
    return clib_error_return(0, "Unexpected end of command line: a field in \"mod\" target must be followed by a value");

  next_id = get_unique_id(target_mod_field_next);
  next_type = get_type(next_id);

  /* MUST be a value next */
  if (next_type != MMB_TYPE_VALUE)
    return clib_error_return(0, "Unexpected element \"%s\": a field in \"mod\" target must be followed by a value", target_mod_field_next);

  vlib_cli_output(vm, "Next is a value = %s\n", target_mod_field_next);

mmb_target_modify_value:
  /*
   * Current element is a value in MOD target (target part)
   *
   * Next element can either be:
   *   - a MOD target
   *   - a STRIP target
   *   - NOTHING: end of command
   */;

  char* target_mod_value_next;
  if (!unformat(input, "%s", &target_mod_value_next))
  {
    // Case "NOTHING" (end of command)
    vlib_cli_output(vm, "No next element (end of command)\n");
    goto mmb_target_eof;
  }

  next_id = get_unique_id(target_mod_value_next);
  next_type = get_type(next_id);

  /* If we reach here, next element MUST be a target (MOD or STRIP) */
  if (next_type != MMB_TYPE_TARGET)
    return clib_error_return(0, "Unexpected element \"%s\": a value in \"mod\" target must be followed by either another \"mod\" target, a \"strip\" target or nothing (end of command)", target_mod_value_next);

  switch(next_id)
  {
    case MMB_TARGET_STRIP:
      vlib_cli_output(vm, "Next is a STRIP target (%s)\n", target_mod_value_next);
      goto mmb_target_strip;

    case MMB_TARGET_MODIFY:
      vlib_cli_output(vm, "Next is a MOD target (%s)\n", target_mod_value_next);
      goto mmb_target_modify;

    default:
      return clib_error_return(0, "Unexpected target element \"%s\"", target_mod_value_next);
  }

mmb_target_strip:
  /*
   * Current element is a STRIP target (target part)
   *
   * Next element can either be:
   *   - a negate ("!") character
   *   - a field (option field)
   *   - ALL (strip all options fields defined in matching part)
   */;

  char* target_strip_next;
  if (!unformat(input, "%s", &target_strip_next))
    return clib_error_return(0, "Unexpected end of command line: a \"strip\" target must be followed by a either a \"not\" (\"!\"), an opt-field or \"all\"");

  if (!strcmp(target_strip_next, "!"))
  {
    vlib_cli_output(vm, "NEGATIVE strip detected\n");
    goto mmb_target_strip_not;
  }

  next_id = get_unique_id(target_strip_next);
  next_type = get_type(next_id);

  /* next element is an opt-field */
  if (next_type == MMB_TYPE_OPT_FIELD)
  {
    vlib_cli_output(vm, "Next is an opt-field = %s\n", target_strip_next);
    goto mmb_target_strip_field;
  }

  /* next element is ALL */
  if (next_type == MMB_TYPE_TARGET && next_id == MMB_TARGET_STRIP_ALL)
  {
    vlib_cli_output(vm, "Next is ALL = %s\n", target_strip_next);
    goto mmb_target_strip_all;
  }

  /* Something unexpected */
  return clib_error_return(0, "Unexpected element \"%s\": a \"strip\" target must be followed by either a \"not\" (\"!\"), an opt-field or \"all\"", target_strip_next);

mmb_target_strip_not:
  /*
   * Current element is a NOT in STRIP target (target part)
   *
   * Next element MUST be a field (option field)
   */;

  char* target_strip_not_next;
  if (!unformat(input, "%s", &target_strip_not_next))
    return clib_error_return(0, "Unexpected end of command line: a \"not\" (\"!\") in a \"strip\" target must be followed by an opt-field");

  next_id = get_unique_id(target_strip_not_next);
  next_type = get_type(next_id);

  /* next element is an opt-field */
  if (next_type == MMB_TYPE_OPT_FIELD)
  {
    vlib_cli_output(vm, "Next is an opt-field = %s\n", target_strip_not_next);
    goto mmb_target_strip_field;
  }

  /* Something unexpected */
  return clib_error_return(0, "Unexpected element \"%s\": a \"not\" (\"!\") in a \"strip\" target must be followed by an opt-field", target_strip_not_next);

mmb_target_strip_field:
  /*
   * Current element is an opt-field in STRIP target (target part)
   *
   * Next element can either be:
   *   - another opt-field
   *   - a MOD target
   *   - NOTHING (end of command)
   */;

  char* target_strip_field_next;
  if (!unformat(input, "%s", &target_strip_field_next))
  {
    // Case "NOTHING" (end of command)
    vlib_cli_output(vm, "No next element (end of command)\n");
    goto mmb_target_eof;
  }

  next_id = get_unique_id(target_strip_field_next);
  next_type = get_type(next_id);

  /* If we reach here, next element MUST be either another opt-field or a MOD target */
  switch(next_type)
  {
    /* next element is an opt-field */
    case MMB_TYPE_OPT_FIELD:
      vlib_cli_output(vm, "Next is an opt-field = %s\n", target_strip_field_next);
      goto mmb_target_strip_field;

    /* next element is a target */
    case MMB_TYPE_TARGET:
      if (next_id != MMB_TARGET_MODIFY)
        return clib_error_return(0, "Unexpected element \"%s\": an opt-field in a \"strip\" target must be followed by either another opt-field, a \"mod\" target or nothing (end of command)", target_strip_field_next);

      /* MOD target */
      vlib_cli_output(vm, "Next is a MOD target (%s)\n", target_strip_field_next);
      goto mmb_target_modify;

    /* Something unexpected */
    default:
      return clib_error_return(0, "Unexpected element \"%s\": an opt-field in a \"strip\" target must be followed by either another opt-field, a \"mod\" target or nothing (end of command)", target_strip_field_next);
  }

mmb_target_strip_all:
  /*
   * Current element is a ALL in STRIP target (target part)
   *
   * Next element can either be:
   *   - a MOD target
   *   - NOTHING (end of command)
   */;

  char* target_strip_all_next;
  if (!unformat(input, "%s", &target_strip_all_next))
  {
    // Case "NOTHING" (end of command)
    vlib_cli_output(vm, "No next element (end of command)\n");
    goto mmb_target_eof;
  }

  next_id = get_unique_id(target_strip_all_next);
  next_type = get_type(next_id);

  /* If we reach here, next element MUST be a MOD target */
  if (next_type == MMB_TYPE_TARGET && next_id == MMB_TARGET_MODIFY)
  {
    vlib_cli_output(vm, "Next is a MOD target (%s)\n", target_strip_all_next);
    goto mmb_target_modify;
  }

  return clib_error_return(0, "Unexpected element \"%s\": \"strip all\" must be followed by either a \"mod\" target or nothing (end of command)", target_strip_all_next);

mmb_target_drop:
  /*
   * Current element is a DROP target (target part)
   *
   * Next element must be NOTHING: end of command
   */

  if (!unformat_is_eof(input))
    return clib_error_return(0, "Unexpected element after \"drop\": nothing expected, end of command\n");

  vlib_cli_output(vm, "No next element (end of command)\n");

mmb_target_eof:
  /*
   * End of the parsing
   */

  vlib_cli_output(vm, "EOF\n");
  return 0;
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
  mmb_main_t * sm = &mmb_main;
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
