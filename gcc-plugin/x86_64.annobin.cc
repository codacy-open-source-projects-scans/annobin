/* x86_64.annobin - x86_64 specific parts of the annobin plugin.
   Copyright (c) 2017 - 2024 Red Hat.
   Created by Nick Clifton.

  This is free software; you can redistribute it and/or modify it
  under the terms of the GNU General Public License as published
  by the Free Software Foundation; either version 3, or (at your
  option) any later version.

  It is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.  */

#include "annobin-global.h"
#include "annobin.h"

#ifndef GNU_PROPERTY_X86_ISA_1_USED
#define GNU_PROPERTY_X86_ISA_1_USED		0xc0000000
#define GNU_PROPERTY_X86_ISA_1_NEEDED		0xc0000001
#endif

#define GNU_PROPERTY_X86_ISA_1_486           (1U << 0)
#define GNU_PROPERTY_X86_ISA_1_586           (1U << 1)
#define GNU_PROPERTY_X86_ISA_1_686           (1U << 2)
#define GNU_PROPERTY_X86_ISA_1_SSE           (1U << 3)
#define GNU_PROPERTY_X86_ISA_1_SSE2          (1U << 4)
#define GNU_PROPERTY_X86_ISA_1_SSE3          (1U << 5)
#define GNU_PROPERTY_X86_ISA_1_SSSE3         (1U << 6)
#define GNU_PROPERTY_X86_ISA_1_SSE4_1        (1U << 7)
#define GNU_PROPERTY_X86_ISA_1_SSE4_2        (1U << 8)
#define GNU_PROPERTY_X86_ISA_1_AVX           (1U << 9)
#define GNU_PROPERTY_X86_ISA_1_AVX2          (1U << 10)
#define GNU_PROPERTY_X86_ISA_1_AVX512F       (1U << 11)
#define GNU_PROPERTY_X86_ISA_1_AVX512CD      (1U << 12)
#define GNU_PROPERTY_X86_ISA_1_AVX512ER      (1U << 13)
#define GNU_PROPERTY_X86_ISA_1_AVX512PF      (1U << 14)
#define GNU_PROPERTY_X86_ISA_1_AVX512VL      (1U << 15)
#define GNU_PROPERTY_X86_ISA_1_AVX512DQ      (1U << 16)
#define GNU_PROPERTY_X86_ISA_1_AVX512BW      (1U << 17)

static unsigned long  global_x86_isa = 0;
static unsigned long  global_stack_realign = 0;

signed int
annobin_target_start_symbol_bias (void)
{
  return 0;
}

unsigned int
annobin_get_target_pointer_size (void)
{
  // Note: testing TARGET_64BIT directly is unreliable as it ultimately uses information in global_options.
  // So instead we perform our own equivalent version of that macro.
  return GET_INT_OPTION_BY_NAME (ix86_isa_flags) & OPTION_MASK_ISA_64BIT ? 64 : 32;
}

int
annobin_save_target_specific_information (void)
{
  return 0;
}

static void
record_ABI_note (unsigned long val, annobin_function_info * info)
{
#if 0 /* Currently annocheck does nothing with x86_64 ABI note, so save space and do not generate it.  */
  annobin_inform (INFORM_VERBOSE, "x86_64: Record isa of %lx for %s",
		  global_x86_isa, get_func_name (info));

  if (use_string_format ())
    {
      static unsigned long prev_abi = -5;

      if (prev_abi == val)
	return;
      prev_abi = val;

      sprintf (annobin_note_buffer, "%s:%d", ANNOBIN_STRING_X86_64_ABI, val);
      annobin_output_string_note (annobin_note_buffer);
    }
  else
    {
      annobin_output_numeric_note (GNU_BUILD_ATTRIBUTE_ABI, val, "numeric: ABI", info);
    }
#endif
}

static void
record_stack_realign_note (unsigned int val, annobin_function_info * info)
{
  annobin_inform (INFORM_VERBOSE, "x86_64: Record stack realign setting of '%s' for %s",
		  val ? "false" : "true", get_func_name (info));

  if (use_string_format ())
    {
      static unsigned int prev_sr = -5;

      if (prev_sr == val)
	return;
      prev_sr = val;

      sprintf (annobin_note_buffer, "%s:%d", ANNOBIN_STRING_i686_STACK_REALIGN, val);
      annobin_output_string_note (annobin_note_buffer);
    }
  else
    {
      unsigned len = sprintf (annobin_note_buffer, "GA%cstack_realign", val ? BOOL_T : BOOL_F);
      
      annobin_output_note (annobin_note_buffer, len + 1, true /* The name is ASCII.  */,
			   "bool: -mstackrealign status", info);
    }
}

void
annobin_record_global_target_notes (annobin_function_info * info)
{
  /* Note - most, but not all, bits in the ix86_isa_flags variable
     are significant for purposes of ABI compatibility.  We do not
     bother to filter out any bits however, as we prefer to leave
     it to the consumer to decide what is significant.  */
  global_x86_isa = GET_INT_OPTION_BY_NAME (ix86_isa_flags);

  record_ABI_note (global_x86_isa, info);

  global_stack_realign = GET_INT_OPTION_BY_NAME (ix86_force_align_arg_pointer);
  if (in_lto () && global_stack_realign == 0)
    /* The LTO compiler determines stack realignment on a per-function basis
       unless enabled globally.  So do not record a negative global setting.  */
    annobin_inform (INFORM_VERBOSE, "x86_64: Not recording unset global stack realignment setting when in LTO mode");
  else
    record_stack_realign_note (global_stack_realign, info);
}

void
annobin_target_specific_function_notes (annobin_function_info * info, bool force)
{
  unsigned long val;

  val = GET_INT_OPTION_BY_NAME (ix86_isa_flags);
  if (force || val != global_x86_isa)
    record_ABI_note (val, info);

  val = GET_INT_OPTION_BY_NAME (ix86_force_align_arg_pointer);
  if (force || val != global_stack_realign)
    record_stack_realign_note (val, info);
}
