## copyright : Copyright (C) 2017-2026 Red Hat.
## license   : GNU GPL v3; see accompanying LICENSE file

## You should have received a copy of the GNU General Public License
## along with this program; see the file COPYING3.  If not see
## <http://www.gnu.org/licenses/>.

## Process this file with automake to produce Makefile.in.

# Note: clang-test and llvm-test are used by the meson builds, not configure builds.

TESTS=\
      abi-test \
      active-checks-test \
      archive-test \
      assembler-gap-test \
      atexit-test \
      bind-now-test \
      compile-test \
      fast-test \
      fortify-test \
      function-sections-test \
      future-test \
      gaps-test \
      glibc-notes-test \
      glibcxx-test \
      gnu-stack-test \
      go-fips-test \
      hardening-fail-test \
      hardening-test \
      illegal-test \
      implicit-values-test \
      instrumentation-test \
      ldconfig-test \
      load-segments-test \
      lto-test \
      missing-notes-test \
      mixed-language-test \
      note-format-test \
      objcopy-test \
      pie-test \
      production-test \
      profile-test \
      property-note-test \
      relro-test \
      rhivos-test \
      run-path-test \
      section-size-test \
      short-enums-test \
      stack-clash-test \
      stat-test \
      static-link-test \
      strip-test \
      tar-test \
      textrel-test \
      threads-test \
      unicode-test \
      warnings-test \
      zip-test

if HAVE_DEBUGINFOD
TESTS += debuginfod-test
endif

if COND_ANNOCHECK
TESTS += libannocheck-test
endif

AM_TESTS_ENVIRONMENT = GCC=$(CC)

# FIXME: Add a test for merging notes...
# FIXME: Add a test for examining rpms...
# FIXME: Add a test for examining repositories...

clean-local:
	-rm -rf tmp_*

# The meson build system uses a target called 'test' to run the
# testuite, so for user convenience we also support that target.
test: check
