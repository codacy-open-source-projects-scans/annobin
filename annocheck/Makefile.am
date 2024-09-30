# copyright : Copyright (C) 2017-2024 Red Hat.
# license   : GNU GPL v3 or later; see accompanying LICENSE file

AM_CPPFLAGS = -I'$(top_builddir)' -I'$(top_srcdir)'
AUTOMAKE_OPTIONS = no-dependencies subdir-objects

tools   = hardened.c timing.c size.c notes.c built-by.c
headers = annocheck.h ../annobin-global.h ../gcc-plugin/config.h 

# A selection of files from the libiberty library maintained as part of GCC.
# Reproduced here in order to remove a dependency when building annocheck.
# NB/ These sources (and headers) are only needed by the hardened tool.

libiberty = \
  libiberty/concat.c \
  libiberty/cp-demangle.c \
  libiberty/cplus-dem.c \
  libiberty/d-demangle.c \
  libiberty/lbasename.c \
  libiberty/rust-demangle.c \
  libiberty/safe-ctype.c \
  libiberty/xexit.c \
  libiberty/xmalloc.c \
  libiberty/xstrdup.c

libiberty_headers = \
  libiberty/demangle.h \
  libiberty/environ.h \
  libiberty/cp-demangle.h \
  libiberty/filenames.h \
  libiberty/hashtab.h \
  libiberty/safe-ctype.h

bin_PROGRAMS      = annocheck
annocheck_SOURCES = annocheck.c $(libiberty) $(tools) $(headers) $(libiberty_headers)
annocheck_LDADD   = -lelf -ldw $(RPMLIBS) $(LIBDEBUGINFOD)

lib_LTLIBRARIES         = libannocheck.la
libannocheck_la_SOURCES = annocheck.c hardened.c $(libiberty)
libannocheck_la_CFLAGS  = -DLIBANNOCHECK=1

include_HEADERS   = libannocheck.h
libannocheck_DATA = libannocheck.pc
libannocheckdir   = $(libdir)/pkgconfig
