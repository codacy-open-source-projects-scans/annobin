/* aarch64.annobin - AArch64 specific parts of the annobin plugin.
   Copyright (c) 2017 - 2026 Red Hat.
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

signed int
annobin_target_start_symbol_bias (void)
{
  return 0;
}

int
annobin_save_target_specific_information (void)
{
  return 0;
}

unsigned int
annobin_get_target_pointer_size (void)
{
  // FIXME: We do not currently support ILP32 mode.
  return 64;
}

#ifdef aarch64_branch_protection_string
static const char * saved_branch_protection_string;

/* In GCC 11.5 they renamed many of the AArch64 specific options...  */
#if GCCPLUGIN_VERSION_MAJOR > 11 

#define ENABLE_BTI       GET_INT_OPTION_BY_NAME (aarch_enable_bti)
#define RA_SIGN_SCOPE    GET_INT_OPTION_BY_NAME (aarch_ra_sign_scope)
#define SCOPE_FUNC_NONE  AARCH_FUNCTION_NONE
#define SCOPE_FUNC_ALL   AARCH_FUNCTION_ALL
#define SCOPE_FUNC_NL    AARCH_FUNCTION_NON_LEAF

#elif GCCPLUGIN_VERSION_MAJOR < 11

#define ENABLE_BTI       GET_INT_OPTION_BY_NAME (aarch64_enable_bti)
#define RA_SIGN_SCOPE    GET_INT_OPTION_BY_NAME (aarch64_ra_sign_scope)
#define SCOPE_FUNC_NONE  AARCH64_FUNCTION_NONE
#define SCOPE_FUNC_ALL   AARCH64_FUNCTION_ALL
#define SCOPE_FUNC_NL    AARCH64_FUNCTION_NON_LEAF

#elif GCCPLUGIN_VERSION_MINOR > 5

#define ENABLE_BTI       GET_INT_OPTION_BY_NAME (aarch_enable_bti)
#define RA_SIGN_SCOPE    GET_INT_OPTION_BY_NAME (aarch_ra_sign_scope)
#define SCOPE_FUNC_NONE  AARCH_FUNCTION_NONE
#define SCOPE_FUNC_ALL   AARCH_FUNCTION_ALL
#define SCOPE_FUNC_NL    AARCH_FUNCTION_NON_LEAF

#else /* 11.0 .. 11.4 */

#define ENABLE_BTI       GET_INT_OPTION_BY_NAME (aarch64_enable_bti)
#define RA_SIGN_SCOPE    GET_INT_OPTION_BY_NAME (aarch64_ra_sign_scope)
#define SCOPE_FUNC_NONE  AARCH64_FUNCTION_NONE
#define SCOPE_FUNC_ALL   AARCH64_FUNCTION_ALL
#define SCOPE_FUNC_NL    AARCH64_FUNCTION_NON_LEAF

#endif

static void
record_branch_protection_note (annobin_function_info * info,
			       const char * optval)
{
  if (optval == NULL && is_global (info) && in_lto ())
    {
      /* The LTO compiler determines branch protections on a per-function basis
	 unless enabled globally.  So do not record a negative global setting.  */
      annobin_inform (INFORM_VERBOSE, "Not recording unset global branch protection setting when in LTO mode");
      return;
    }

  if (optval == NULL)
    {
      /* Not set by the user.  Try a bit harder to find out what settings are used.  */
      if (ENABLE_BTI == 0)
	optval = "none";
      else
	switch (RA_SIGN_SCOPE)
	  {
	  case SCOPE_FUNC_NONE :
	    optval = "bti";
	    break;
	  case SCOPE_FUNC_ALL :
	    optval = "pac-ret+leaf";
	    break;
	  case SCOPE_FUNC_NL :
	    optval = "standard";
	    break;
	  default: 
	    optval = "default";
	    break;
	  }
      annobin_inform (INFORM_VERBOSE,
		      "AArch64: branch protection set based upon enable_bti of %d and ra_sign_scope of %d",
		      ENABLE_BTI, RA_SIGN_SCOPE);
    }

  annobin_inform (INFORM_VERBOSE, "AArch64: Recording AArch64 branch protection of '%s' for '%s'",
		  optval, get_func_name (info));

  int n;
  
  if (use_string_format ())
    {
      n = snprintf (annobin_note_buffer, sizeof annobin_note_buffer - 1, "%s:%s",
		    ANNOBIN_STRING_AARCH64_BTI, optval);

      if (n >= 0 && (size_t) n < sizeof annobin_note_buffer - 1)
	annobin_output_string_note (annobin_note_buffer);
    }
  else
    {
      n = snprintf (annobin_note_buffer, sizeof annobin_note_buffer - 1, "GA%cbranch_protection:%s",
		    GNU_BUILD_ATTRIBUTE_TYPE_STRING, optval);
      if (n >= 0 && (size_t) n < sizeof annobin_note_buffer - 1)
	annobin_output_note (annobin_note_buffer, strlen (annobin_note_buffer) + 1,
			     true, "string: -mbranch-protection status", info);
    }
}
#endif

void
annobin_record_global_target_notes (annobin_function_info * info ATTRIBUTE_UNUSED)
{
#ifdef aarch64_branch_protection_string
  saved_branch_protection_string = GET_STR_OPTION_BY_INDEX (OPT_mbranch_protection_);
  record_branch_protection_note (info, saved_branch_protection_string);
#endif
}

void
annobin_target_specific_function_notes (annobin_function_info * info ATTRIBUTE_UNUSED,
					bool force ATTRIBUTE_UNUSED)
{
#ifdef aarch64_branch_protection_string
  const char * abps = GET_STR_OPTION_BY_INDEX (OPT_mbranch_protection_);
  
  if ((abps != saved_branch_protection_string
       && (abps == NULL
	   || saved_branch_protection_string == NULL
	   || strcmp (saved_branch_protection_string, abps) != 0))
      || (force && ! in_lto ())) /* In LTO mode, ignore a forced save of the same value as the global.  */
    record_branch_protection_note (info, abps);
#endif
}
