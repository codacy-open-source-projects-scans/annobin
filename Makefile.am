# copyright : Copyright (c) 2017-2024 Red Hat
# license   : GNU GPL v3 or later; see accompanying LICENSE file

## You should have received a copy of the GNU General Public License v3
## along with this program; see the file COPYING3.  If not see
## <http://www.gnu.org/licenses/>.

## Process this file with automake to produce Makefile.in.

if COND_DOCS
  MAYBE_DOCS = doc
endif

if COND_TESTS
  MAYBE_TESTS = tests
endif

if COND_ANNOCHECK
  MAYBE_ANNOCHECK = annocheck
endif

if COND_CLANG
  MAYBE_CLANG = clang-plugin
endif

if COND_GCC_PLUGIN
  MAYBE_GCC = gcc-plugin
endif

if COND_LLVM
  MAYBE_LLVM = llvm-plugin
endif

SUBDIRS = $(MAYBE_DOCS) $(MAYBE_GCC) $(MAYBE_CLANG) $(MAYBE_LLVM) $(MAYBE_ANNOCHECK) $(MAYBE_TESTS) 
dist_doc_DATA = LICENSE COPYING3
ACLOCAL_AMFLAGS = -I config

