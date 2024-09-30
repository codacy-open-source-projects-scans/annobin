dnl file      : config/annocheck.m4
dnl copyright : Copyright (c) 2020 Theobroma Systems Design und Consulting GmbH
dnl copyright : Copyright (c) 2021-2024 Red Hat
dnl license   : MIT; see accompanying LICENSE file
dnl
dnl ANNOCHECK
dnl
dnl

AC_DEFUN([BUILD_ANNOCHECK], [

AC_ARG_WITH(
  [annocheck],
  [AC_HELP_STRING([--without-annocheck],[do not build annocheck])],
  [with_annocheck=no],
  [:])

AS_IF([test "x$with_annocheck" != xno],

[
LIBELF

# Check for rpmlib availability.
AC_CHECK_HEADER([rpm/rpmlib.h], ,[AC_MSG_ERROR(["Required header 'rpm/rpmlib.h' not found."])])
AC_CHECK_LIB([rpm], [rpmReadPackageFile], [RPMLIBS="-lrpm"], [AC_MSG_ERROR(["Required library 'rpm' not found.])])
AC_CHECK_LIB([rpmio], [rpmConfigDir], [RPMLIBS="$RPMLIBS -lrpmio"], [AC_MSG_ERROR(["Required library 'rpmio' not found.])])
AC_SUBST(RPMLIBS)
  
],
[:])

])

AC_DEFUN([BUILD_CLANG_PLUGIN], [

AC_ARG_WITH(
  [clang-plugin],
  [AC_HELP_STRING([--without-clang-plugin],[do not build the clang plugin])],
  [with_clang_plugin=no],
  [:])

# Test suppressed because on Debian systems the Clang headers are
# installed in a non-standard location.
# AS_IF([test "x$with_clang_plugin" != xno],
# 
# [
# # Change for clang++ and clang-devel packages.
# AC_CHECK_HEADER([clang/Frontend/FrontendPluginRegistry.h], ,[AC_MSG_ERROR(["Required header 'FrontendPluginRegistry.h' not found.  Have you installed the clang-devel package ?"])])
# ],
# [:])

])

AC_DEFUN([BUILD_GCC_PLUGIN], [

AC_ARG_WITH(
  [gcc-plugin],
  [AC_HELP_STRING([--without-gcc_plugin],[do not build the gcc plugin])],
  [with_gcc_plugin=no],
  [:])
])

AC_DEFUN([BUILD_LLVM_PLUGIN], [

AC_ARG_WITH(
  [llvm-plugin],
  [AC_HELP_STRING([--without-llvm-plugin],[do not build the llvm plugin])],
  [with_llvm_plugin=no],
  [:])
])

AC_DEFUN([BUILD_DOCS], [

AC_ARG_WITH(
  [docs],
  [AC_HELP_STRING([--without-docs],[do not build the documentation])],
  [with_docs=no],
  [:])
])

AC_ARG_WITH(
  [tests],
  [AC_HELP_STRING([--without-tests],[do not run the tests])],
  [with_tests=no],
  [:])
])
