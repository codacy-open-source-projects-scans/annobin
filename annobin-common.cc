/* annobin - Common functions used by plugins.
   Copyright (c) 2024 - 2026 Red Hat.

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

/* Check the environment for a variable called ANNOBIN.
   If found, parse its contents as if it contained comma
   separated arguments, passing each in turn to the
   provided PARSE_ARGUMENT parameter.  DATA is not examined
   by this function, just passed to PARSE_ARGUMENT.  */

bool
annobin_parse_env (arg_parser parse_argument, void * data)
{
  const char * env;

  if ((env = getenv ("ANNOBIN")) == NULL)
    return true;

  bool ret = true;

  while (*env != 0)
    {
      const char * comma;
      char * arg;

      /* Look for the next argument and copy
	 it into an independent buffer.  */
      comma = strchr (env, ',');
      if (comma)
	{
	  arg = strndup (env, comma - env);
	  env = comma + 1;
        }
      else
	{
	  arg = strdup (env);
	  env += strlen (env);
	}

      if (arg == NULL)
	return false;

      /* If the argument contains a equals sign,
	 separate it into a command and value pair.  */
      char * value = strchr (arg, '=');
      if (value)
	{
	  * value = 0;
	  value ++;
	}
      else
	{
	  /* Otherwise pass an empty string as the value.  */
	  value = (char *) "";
	}

      /* Let the caller process this argument.  */
      ret &= parse_argument (arg, value, data);

      free ((void *) arg);
    }

  return ret;
}
