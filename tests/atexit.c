/*
# copyright : Copyright (c) 2017-2024 Red Hat
# license   : GNU GFDL v1.3; see accompanying LICENSE file.
*/

#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
int main()
{
        /* Print the address of the functions, to force an non-inline copy
           of these functions from libc_nonshared.a into the link.  */
        printf ("%p\n", atexit);
        return 0;
}
