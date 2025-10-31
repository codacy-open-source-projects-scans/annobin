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
#ifndef ANNOBIN_COMMON_H_
#define ANNOBIN_COMMON_H_

#include <stdbool.h>

/* Checks for an ANNOBIN environment variable.
   If it exists, parses it for comma separated command line options,
    passing each in turn to PARSE_ARGUMENT.  Arguments are copied
    into a buffer before processing and can be manipulated by
    PARSE_ARGUMENT.  If an argument contains a '=' character then
    it is split into two pieces and passed to PARSE_ARGUMENT as
    (NAME, VALUE, DATA).  Otherwise it is just passed as (NAME, "", DATA).
    The return value from PARSE_ARGUMENT is recorded, but
    parsing will continue even if PARSE_ARGUMENT returns FALSE.
   Returns TRUE if the ANNOBIN environment variable does not exist.
   Returns TRUE if the ANNOBIN environment exists and PARSE_ARGUMENT
    returns TRUE for all of the arguments.
   Return FALSE otherwise.  */

typedef bool (* arg_parser)(const char * NAME, const char * VALUE, void * DATA);

extern bool annobin_parse_env (arg_parser PARSE_ARGUMENT, void * DATA);

#endif // ANNOBIN-COMMON_H_
