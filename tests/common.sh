
## Copyright (C) 2017-2024 Red Hat
#
# This is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published
# by the Free Software Foundation; either version 3, or (at your
# option) any later version.
#
# It is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

ANNOCHECK=${ANNOCHECK:-../../annocheck/annocheck}
CURL=${CURL:-curl}
DEBUGINFOD=${DEBUGINFOD:-debuginfod}
GAS=${GAS:-as}
GCC=${GCC:-gcc}
GO=${GO:-go}
OBJCOPY=${OBJCOPY:-objcopy}
PLUGIN=${PLUGIN:-../../gcc-plugin/.libs/annobin.so}
READELF=${READELF:-readelf}
SS=${SS:-ss}
STRIP=${STRIP:-strip}

# TEST_NAME must be set before including this
# In theory we should use ${builddir} instead of "." in the path below, but builddir is not exported.
testdir="./tmp_$TEST_NAME"

stashed_srcdir=

start_test()
{
  rm -rf $testdir
  mkdir -p $testdir

  pushd $testdir

  stashed_srcdir=$srcdir
  if test "${srcdir:0:1}" != "/";
  then
    srcdir="../$srcdir"
  fi
}

end_test()
{
  popd # Back from $testdir
  srcdir=$stashed_srcdir
}
