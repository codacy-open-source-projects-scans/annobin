/* annobin - Common functions used by plugins.
   Copyright (c) 2024 Red Hat.

  This is free software; you can redistribute it and/or modify it
  under the terms of the GNU General Public License as published
  by the Free Software Foundation; either version 3, or (at your
  option) any later version.

  It is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.  */

#include "annobin-common.h"

#include <stdlib.h>
#include <string.h>

bool
annobin_parse_env (arg_parser parse_argument, void * data)
{
  const char * env;

  if ((env = getenv ("ANNOBIN")) == NULL)
    return true;

  static char arg[2048];  // It is slightly safer to use a static buffer.
  bool ret = true;

  while (*env != 0)
    {
      const char * comma;
      size_t len;

      comma = strchr (env, ',');
      if (comma)
	{
	  len = comma - env;
	  if (len >= sizeof arg)
	    // FIXME: Issue an error message somehow ?
	    // FIXME: Or use a dynamically growing buffer.
	    return false;

	  strncpy (arg, env, len);
	  arg[len] = 0;
	  env = comma + 1;
        }
      else
	{
	  len = sizeof arg - 1;
	  // FIXME: Check strlen (env) against len ?
	  strncpy (arg, env, len);
	  arg[len] = 0;
	  env += strlen (env);
	}

      char * value = strchr (arg, '=');
      if (value)
	{
	  * value = 0;
	  value ++;
	}
      else
	{
	  value = (char *) "";
	}

      ret &= parse_argument (arg, value, data);
    }

  return ret;
}
