
## Copyright (C) 2017-2026 Red Hat
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

# Programs used by the tests.
ANNOCHECK=${ANNOCHECK:-../../annocheck/annocheck}
AR=${AR:-ar}
CLANG=${CLANG:-clang}
CURL=${CURL:-curl}
DEBUGINFOD=${DEBUGINFOD:-debuginfod}
GAS=${GAS:-as}
GCC=${GCC:-${CC:-gcc}}
GO=${GO:-go}
GPP=${GPP:-g++}
OBJCOPY=${OBJCOPY:-objcopy}
PLUGIN=${PLUGIN:-../../gcc-plugin/.libs/annobin.so}
READELF=${READELF:-readelf}
SS=${SS:-ss}
STRIP=${STRIP:-strip}
TAR=${TAR:-tar}
XZ=${XZ:-xz}
ZIP=${ZIP:-zip}

# Exit values
EXIT_TEST_PASSED=0
EXIT_TEST_FAILED=1
EXIT_TEST_SKIPPED=77

# Output file names
A_OUT=annocheck.out
G_OUT=gcc.out
EXE=test.exe

# Function start_test() creates and changes into a sub-directory before
# the test starts.  This allows multiple tests to be run in parallel
# without interference.
# Note: TEST_NAME must be set before including this.
# In theory we should use ${builddir} instead of "." in the path below,
# but builddir is not exported.
testdir="./tmp_$TEST_NAME"

stashed_srcdir=

start_test()
{
  rm -rf $testdir
  mkdir -p $testdir

  pushd $testdir > /dev/null

  stashed_srcdir=$srcdir
  if test "${srcdir:0:1}" != "/";
  then
    srcdir="../$srcdir"
  fi
}

end_test()
{
  popd > /dev/null # Back from $testdir
  srcdir=$stashed_srcdir
}
