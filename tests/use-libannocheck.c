/* use-libannocheck.c - Test the libannocheck library.
   Copyright (c) 2021-2024 Red Hat.
   Created by Nick Clifton.

  This is free software; you can redistribute it and/or modify it
  under the terms of the GNU General Public License as published
  by the Free Software Foundation; either version 3, or (at your
  option) any later version.

  It is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.  */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include "libannocheck.h"

int
main (void)
{
  libannocheck_internals_ptr handle;
  libannocheck_error         error;

  error = libannocheck_init ((unsigned int) LIBANNOCHECK_VERSION, "use-libannocheck", NULL, & handle);
  if (error != libannocheck_error_none)
    {
      printf ("FAILED to open library\n");
      return EXIT_FAILURE;
    }

  printf ("Open library: PASS\n");

  printf ("Library version: %u (header version %u)\n",
	  libannocheck_get_version (),
	  (unsigned int) LIBANNOCHECK_VERSION);

  libannocheck_error   res;
  libannocheck_test *  tests;
  unsigned int         num_tests;

  if ((res = libannocheck_get_known_tests (handle, & tests, & num_tests)) != libannocheck_error_none)
    {
      printf ("FAILED to get_tests\n");
      (void) libannocheck_finish (handle);
      return EXIT_FAILURE;
    }

  printf ("Got test list containing %u entries\n", num_tests);

  if ((res = libannocheck_enable_all_tests (handle)) != libannocheck_error_none)
    {
      printf ("FAILED to enable all tests\n");
      (void) libannocheck_finish (handle);
      return EXIT_FAILURE;
    }

  const char ** profiles;
  unsigned int  num_profiles;

  if ((res = libannocheck_get_known_profiles (handle, & profiles, & num_profiles)) != libannocheck_error_none)
    {
      printf ("FAILED to get known profiles");
      (void) libannocheck_finish (handle);
      return EXIT_FAILURE;
    }

  if ((res = libannocheck_enable_profile (handle, "el8")) != libannocheck_error_none)
    {
      printf ("FAILED to enable el8 profilen");
      (void) libannocheck_finish (handle);
      return EXIT_FAILURE;
    }

  if ((res = libannocheck_disable_test (handle, "bind-now")) != libannocheck_error_none)
    {
      printf ("FAILED to disable bind-now");
      (void) libannocheck_finish (handle);
      return EXIT_FAILURE;
    }

  if ((res = libannocheck_disable_all_tests (handle)) != libannocheck_error_none)
    {
      printf ("FAILED to disable all tests\n");
      (void) libannocheck_finish (handle);
      return EXIT_FAILURE;
    }
  
  if ((res = libannocheck_enable_test (handle, "bind-now")) != libannocheck_error_none)
    {
      printf ("FAILED to enable bind-now");
      (void) libannocheck_finish (handle);
      return EXIT_FAILURE;
    }
  
  printf ("Enabled and disabled tests\n");

  unsigned int num_fails, num_maybs;

  if ((res = libannocheck_run_tests (handle, & num_fails, & num_maybs)) != libannocheck_error_none)
    {
      printf ("FAILED to run tests\n");
      (void) libannocheck_finish (handle);
      return EXIT_FAILURE;
    }

  printf ("Ran %d tests, %u fails, %u maybes\n", num_tests, num_fails, num_maybs);

  bool a_test_failed = false;
  int i;
  for (i = 0; i < num_tests; i++)
    {
      if (tests[i].state != libannocheck_test_state_not_run)
	{
	  printf (" test %d result %d reason: '%s' source: '%s'\n",
		  i, tests[i].state,
		  tests[i].state == libannocheck_test_state_passed ? "test ok" : tests[i].result_reason,
		  tests[i].result_source);

	  if (tests[i].state == libannocheck_test_state_failed)
	    a_test_failed = true;
	}
    }

  if (libannocheck_reinit (handle, "use-libannocheck", "use-libannocheck.debug") != libannocheck_error_none)
    {
      printf ("FAILED to reinitialise the library (2)\n");
      (void) libannocheck_finish (handle);
      return EXIT_FAILURE;
    }
  
  if ((res = libannocheck_enable_all_tests (handle)) != libannocheck_error_none)
    {
      printf ("FAILED to enable all tests (2)\n");
      (void) libannocheck_finish (handle);
      return EXIT_FAILURE;
    }
  
  libannocheck_debug (true);
  
  if ((res = libannocheck_run_tests (handle, & num_fails, & num_maybs)) != libannocheck_error_none)
    {
      printf ("FAILED to re test file, annocheck error message: %s\n", libannocheck_get_error_message (handle, res));
      (void) libannocheck_finish (handle);
      return EXIT_FAILURE;
    }

  libannocheck_debug (false);
  
  if (libannocheck_reinit (handle, "no-such-file", "fake-debug-path") != libannocheck_error_none)
    {
      printf ("FAILED to reinitialise the library (3)\n");
      (void) libannocheck_finish (handle);
      return EXIT_FAILURE;
    }
  
  if ((res = libannocheck_enable_all_tests (handle)) != libannocheck_error_none)
    {
      printf ("FAILED to enable all tests (3)\n");
      (void) libannocheck_finish (handle);
      return EXIT_FAILURE;
    }
  
  if ((res = libannocheck_run_tests (handle, & num_fails, & num_maybs)) != libannocheck_error_file_corrupt)
    {
      printf ("FAILED to test non-existant file\n");
      printf (" annocheck error message: %s\n", libannocheck_get_error_message (handle, res));
      (void) libannocheck_finish (handle);
      return EXIT_FAILURE;
    }

  if (libannocheck_finish (handle) != libannocheck_error_none)
    {
      printf ("FAILED to close library\n");
      return EXIT_FAILURE;
    }

  printf ("Close library: PASS\n");
  /* This EXIT_FAILURE is expected by libannocheck-test.  */
  return a_test_failed ? EXIT_FAILURE : EXIT_SUCCESS;
}
