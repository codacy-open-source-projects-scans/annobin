# file      : configure.ac
# copyright : Copyright (c) 2017-2026 Red Hat
# license   : GNU GPL v3 or later; see accompanying LICENSE file

AC_PREREQ(2.64)
AC_INIT([Binary Annotations], 13.0,,[annobin-plugin])
AC_CONFIG_AUX_DIR([config])
AC_CONFIG_MACRO_DIRS([config])
AC_CONFIG_SRCDIR([annobin-global.h.in])

# NB/ When updating the ANNOBIN_VERSION below, remember to
# also update VERSION in the PROJECT section of meson.build.
# Also note that the number after the decimal point is limited
# to two digits due to various assumptions in the code.
ANNOBIN_VERSION=13.32
AC_SUBST(ANNOBIN_VERSION)

AC_CANONICAL_SYSTEM
AC_USE_SYSTEM_EXTENSIONS

# foreign: Don't require README, INSTALL, NEWS, etc.
# no-define: Don't define PACKAGE and VERSION.
# -Wall: Issue all automake warnings.
# -Wno-portability: Don't warn about constructs supported by GNU make.
#    (because GCC requires GNU make anyhow).
AM_INIT_AUTOMAKE([foreign no-dist no-define subdir-objects -Wall -Wno-portability])

if test -z "$ac_cv_prog_AWK"; then
  AC_MSG_ERROR([Could not find awk])
fi
AC_PATH_PROG(CMP, cmp)
if test -z "$ac_cv_path_CMP"; then
  AC_MSG_ERROR([Could not find cmp])
fi
AC_PATH_PROG(DIFF, diff)
if test -z "$ac_cv_path_DIFF"; then
  AC_MSG_ERROR([Could not find diff])
fi
AC_PROG_CXX
AC_LANG(C++)

LT_INIT([disable-static])
LT_OUTPUT

# Determine the target specific part of the GCC plugin.
target_plugin="dummy.annobin.lo"
case ${target} in
  aarch64*-*-*)
    target_plugin="aarch64.annobin.lo"
    ;;
  arm*-*-*)
    target_plugin="arm.annobin.lo"
    ;;
  i*86-*-*)
    target_plugin="i686.annobin.lo"
    ;;
  powerpc*-*-*)
    target_plugin="powerpc.annobin.lo"
    ;;
  riscv*-*-*)
    target_plugin="riscv.annobin.lo"
    ;;
  s390*-*-*)
    target_plugin="s390.annobin.lo"
    ;;
  x86_64-*-*)
    target_plugin="x86_64.annobin.lo"
    ;;
  *)
    target_plugin="dummy.annobin.lo"
    ;;
esac
AC_SUBST(target_plugin)

# Determine if we should build annocheck.
BUILD_ANNOCHECK
# Determine if we should build the clang-plugin
BUILD_CLANG_PLUGIN
# Determine if we should build the gcc-plugin
BUILD_GCC_PLUGIN
# Determine if we should build the llvm-plugin
BUILD_LLVM_PLUGIN
# Determine if we should build the documentation
BUILD_DOCS

AC_MSG_CHECKING([whether to enable maintainer-specific portions of Makefiles])
AC_ARG_ENABLE(maintainer-mode,
[AS_HELP_STRING([--enable-maintainer-mode],
		[enable make rules and dependencies not useful
		 (and sometimes confusing) to the casual installer])],
      USE_MAINTAINER_MODE=$enableval,
      USE_MAINTAINER_MODE=no)
AC_MSG_RESULT($USE_MAINTAINER_MODE)
AC_SUBST(MAINTAINER_MODE_TRUE)
AC_SUBST(MAINTAINER_MODE_FALSE)
if test "$USE_MAINTAINER_MODE" = yes; then
  MAINTAINER_MODE_TRUE=
  MAINTAINER_MODE_FALSE='#'
else
  MAINTAINER_MODE_TRUE='#'
  MAINTAINER_MODE_FALSE=
fi	
MAINT=$MAINTAINER_MODE_TRUE
AC_SUBST(MAINT)dnl

# Check for debuginfod availability
DEBUGINFOD

DISABLE_RPATH

ACX_LT_HOST_FLAGS
AC_SUBST(target_noncanonical)
AC_TYPE_INT64_T
AC_TYPE_UINT64_T

AM_SILENT_RULES([yes])

AC_CONFIG_FILES(Makefile)
AC_CONFIG_FILES(annobin-global.h)

#-------------------------------------------------------------------

if test "$with_annocheck" != no; then

  AC_CHECK_HEADER([dwarf.h],
                  [], [AC_MSG_ERROR([Cannot find elfutils headers])])

  AC_CONFIG_FILES(annocheck/libannocheck.h)
  AC_CONFIG_FILES([annocheck/libannocheck.pc])
  AC_CONFIG_FILES(annocheck/Makefile)
fi

AM_CONDITIONAL([COND_ANNOCHECK], [test "$with_annocheck" != no])

#-------------------------------------------------------------------

if test "$with_docs" != no; then
  AC_CONFIG_FILES(doc/Makefile)
fi

AM_CONDITIONAL([COND_DOCS], [test "$with_docs" != no])

#-------------------------------------------------------------------

if test "$with_tests" != no; then
  if test "x$with_debuginfod" != xno; then
  
    AC_PATH_PROG(DEBUGINFODPROG, debuginfod)
    if test -z "$ac_cv_path_DEBUGINFODPROG"; then
      # Not an error because other tests can still be run
      AC_MSG_WARN([Could not find debuginfod - the test will be skipped])
    fi
    
    AC_PATH_PROG(SS, ss)
    if test -z "$ac_cv_path_SS"; then
      # Not an error, because other tests can still be run.
      AC_MSG_WARN([Could not find ss - the debuginfo test will be skipped])
    fi
  fi

  AC_CONFIG_FILES(tests/Makefile)
fi

AM_CONDITIONAL([COND_TESTS], [test "$with_tests" != no])

#-------------------------------------------------------------------
# Check to see if we can build the clang plugin.

# First check to see if Clang is installed.
if test "$with_clang_plugin" != no; then

  # Paranoia: make sure that the user gave us a valid argument to the --with-clang-plugin option.
  if test "$with_clang_plugin" = yes; then
    :
  elif test "$with_clang_plugin" = auto; then
    :
  else
    AC_MSG_ERROR([Unrecognised argument to --with-clang-plugin.  Expected yes, no or auto, got '$with_clang_plugin'])
    with_clang_plugin=auto
  fi
	
  AC_CHECK_TARGET_TOOL(CLANGXX, clang++)

  if test -z "$ac_ct_CLANGXX"; then
    if test "$with_clang_plugin" = yes; then
      AC_MSG_ERROR([Could not find clang++])
    else # $with_clang_plugin = auto
      AC_MSG_WARN([Could not find clang++ - disabling clang plugin])
      with_clang_plugin=no
    fi
  fi
fi

# If that check succeeded then check to see llvm-config is installed.
# We need llvm-config in order to find the clang header files.
if test "$with_clang_plugin" != no; then

  AC_PATH_PROG(LLVM_CONFIG, llvm-config)

  if test -z "$ac_cv_path_LLVM_CONFIG"; then
    if test "$with_clang_plugin" = yes; then
      AC_MSG_ERROR([Could not find llvm-config])
    else # $with_clang_plugin = auto
      AC_MSG_WARN([Could not find llvm-config - disabling clang plugin])
      with_clang_plugin=no
    fi
  fi
fi

# Lastly, if both clang and llvm-config are installed, check
# to see if the clang development headers are available.
if test "$with_clang_plugin" != no; then

  CPPFLAGS="$CPPFLAGS -I$(llvm-config --includedir)"
  AC_CHECK_HEADER([clang/Basic/Version.h],
                  [],
                  [if test "$with_clang_plugin" = yes; then
                     AC_MSG_ERROR([Cannot find Clang development headers])
                   else # $with_clang_plugin = auto
                     AC_MSG_WARN([Cannot find Clang development headers - disabling clang plugin])
                     with_clang_plugin=no
                   fi])

fi

# Then if all is well, enable the plugin.
if test "$with_clang_plugin" != no; then
  with_clang_plugin=yes
  AC_CONFIG_FILES(clang-plugin/Makefile)
fi

AM_CONDITIONAL([COND_CLANG], [test "$with_clang_plugin" != no])

#-------------------------------------------------------------------
# Check to see if we can build the llvm plugin.

# First check to see if llvm-config is installed.
# We need it in order to find the headers.
if test "$with_llvm_plugin" != no; then

  # Paranoia: make sure that the user gave us a valid argument to the --with-llvm-plugin option.
  if test "$with_llvm_plugin" = yes; then
    :
  elif test "$with_llvm_plugin" = auto; then
    :
  else
    AC_MSG_ERROR([Unrecognised argument to --with-llvm-plugin.  Expected yes, no or auto, got '$with_llvm_plugin'])
    with_llvm_plugin=auto
  fi

  AC_PATH_PROG(LLVM_CONFIG, llvm-config)

  if test -z "$ac_cv_path_LLVM_CONFIG"; then
    if test "$with_llvm_plugin" = yes; then
      AC_MSG_ERROR([Could not find llvm-config])
    else# $with_llvm_plugin = auto
      AC_MSG_WARN([Could not find llvm-config - disabling llvm plugin])
      with_llvm_plugin=no
    fi
  fi
fi

# Next check to see if the LLVM development headers are available.
if test "$with_llvm_plugin" != no; then
  CPPFLAGS="$CPPFLAGS -I$(llvm-config --includedir)"

  AC_CHECK_HEADER([llvm/Pass.h],
                  [],
                  [if test "$with_llvm_plugin" = yes; then
                     AC_MSG_ERROR([Cannot find LLVM development headers])
                   else # $with_llvm_plugin = auto
                     AC_MSG_WARN([Cannot find LLVM development headers - disabling llvm plugin])
                     with_llvm_plugin=no
                   fi])
fi

# Finally, if all is well, enable the plugin.
if test "$with_llvm_plugin" != no; then
  with_llvm_plugin=yes
  AC_CONFIG_FILES(llvm-plugin/Makefile)
fi

AM_CONDITIONAL([COND_LLVM], [test "$with_llvm_plugin" != no])

#-------------------------------------------------------------------
# Check to see if we can build the gcc plugin.

if test "x$with_gcc_plugin" != xno; then

  # We need GCC plugin support.
  GCC_PLUGIN

  if test x$gcc_plugin_dir != xno; then
    AC_DEFINE([ANNOBIN_GCC_PLUGIN_DIR], [1], [Plugin is in GCC plugin directory.])
    plugindir=$gcc_plugin_dir
  # Otherwise, try to figure out a relative path from the driver (bindir) to
  # the plugin (libexecdir).
  else
    # Get the expanded values for bindir and libexecdir.
    if test x$exec_prefix = xNONE; then
      if test x$prefix = xNONE; then
        e_exec_prefix=$ac_default_prefix
       else
        e_exec_prefix=$prefix
      fi
    else
      e_exec_prefix=$exec_prefix
    fi

    e_pkglibexecdir=`echo "$libexecdir/$PACKAGE_NAME" | sed "s?^\\\${exec_prefix}?$e_exec_prefix?"`
    e_bindir=`echo "$bindir" | sed "s?^\\\${exec_prefix}?$e_exec_prefix?"`

    # Try to find a common prefix.
    common=$e_bindir
    rel_plugindir=$e_pkglibexecdir

    while test x$common != x/; do
      suffix=`echo "$e_pkglibexecdir" | sed "s?^$common/*??"`
      if test "x$suffix" != "x$e_pkglibexecdir"; then
        # Replace all the remaining directories in bindir with ".."
        # and append the suffix.
        rel_plugindir=`echo "$e_bindir" | sed "s?^$common/*??"`
        rel_plugindir=`echo "$rel_plugindir" | sed ['s?[^/][^/]*?..?g']`
        if test "x$rel_plugindir" != x -a "x$suffix" != x; then
          rel_plugindir="$rel_plugindir/$suffix"
        else
          rel_plugindir="$rel_plugindir$suffix"
        fi
        break
      fi
      common=`AS_DIRNAME(["$common"])`
    done
    AC_DEFINE_UNQUOTED([ANNOBIN_PLUGIN_PATH], ["$rel_plugindir"], [Plugin path.])
    plugindir='$(pkglibexecdir)'
  fi

  AC_SUBST([plugindir])
fi

if test "$with_gcc_plugin" != no; then
  AC_CONFIG_HEADERS(gcc-plugin/config.h)
  AC_CONFIG_FILES(gcc-plugin/Makefile)
fi

AM_CONDITIONAL([COND_GCC_PLUGIN], [test "$with_gcc_plugin" != no])

#-------------------------------------------------------------------

AC_OUTPUT
