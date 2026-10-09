/*
# copyright : Copyright (c) 2026 Red Hat
# license   : GNU GFDL v1.3; see accompanying LICENSE file.
*/

#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

/* A small program to rename the provided file into one containing
   "extra" text, which if passed to the system() call would result
   in extraneous commands being executed.  */

int
main (int argc, char *argv[])
{
  if (argc < 2 || argc > 3)
    {
      fprintf (stderr, "usage: bad-rename: old-name [bad character(s)]\n");
      return -1;
    }
  
  const char * filename = argv[1];
  char * newname = NULL;

  /* We include the original filename twice, once so that whatever
     command in the system() call before the filename will still
     work (if the file still existed) and once at the end of the
     new name so that the type of the file can still be deduced by
     examining its suffix.

     Similarly if we have been provided with a bad character to use
     that is put in twice as well, both before and after the poison
     command.  */
  int res;

  if (argc > 2)
    res = asprintf (& newname, "%s%s%s%s%s", filename, argv[2], " touch ILLEGAL_TEST ", argv[2], filename);
  else
    res = asprintf (& newname, "%s%s%s", filename, "; touch ILLEGAL_TEST ; cat ", filename);
    
  if (res < 10 || newname == NULL)
    {
      fprintf (stderr, "failed to allocate new name\n");
      return -1;
    }

  if (rename (filename, newname) != 0)
    {
      fprintf (stderr, "failed to rename '%s' to '%s', error = %s\n",
	       filename, newname, strerror (errno));
      free ((void *) newname);
      return -1;
    }

  free ((void *) newname);
  
  return 0;
}
