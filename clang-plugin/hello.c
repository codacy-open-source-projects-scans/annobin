/* copyright : Copyright (c) 2017-2024 Red Hat */
/* license   : GNU GPL v3; see accompanying LICENSE file  */

#include <stdio.h>
#include <string.h>

char buf[128];

int 
main (int argc, char ** argv)
{
  strcpy (buf, argv[0]);
  return printf ("%s", buf);
}
