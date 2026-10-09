## copyright : Copyright (C) 2017-2026 Red Hat.
## license   : GNU GPL v3; see accompanying LICENSE file

## You should have received a copy of the GNU General Public License
## along with this program; see the file COPYING3.  If not see
## <http://www.gnu.org/licenses/>.

tests = [
  'abi',
  'active-checks',
  'compile',
  'function-sections',
  'hardening-fail',
  'hardening',
  'instrumentation',
  'ldconfig',
  'missing-notes',
  'mixed-language',
  'property-note',
  'section-size',
]

env = {
  'srcdir' : meson.current_source_dir(),
  'PLUGIN' : gcc_plugin.full_path(),
  'TOP_BUILDDIR' : join_paths(meson.current_build_dir(), '..'),
}

if get_option('annocheck')
  env += {
    'ANNOCHECK' : annocheck.full_path(),
    'INCDIR' : '../annocheck/',
    'LIBANNOCHECKDIR' : '../annocheck/',
  }

  tests += [
    'archive',
    'assembler-gap',
    'atexit',
    'bind-now',
    'fast',
    'fortify',
    'future',
    'gaps',
    'glibc-notes',
    'glibcxx',
    'gnu-stack',
    'go-fips',
    'illegal',
    'implicit-values',
    'libannocheck',
    'load-segments',
    'lto',
    'objcopy',
    'pie',
    'production',
    'profile',
    'relro',
    'rhivos',
    'run-path',
    'short-enums',
    'stack-clash',
    'stat',
    'static-link',
    'strip',
    'tar',
    'textrel',
    'threads',
    'unicode',
    'warnings',
    'zip',
  ]

  if have_debuginfod
    awk = find_program('awk')
    debuginfod = find_program('debuginfod')
    ss = find_program('ss')
    tests += 'debuginfod'
  endif
endif

if get_option('llvm-plugin')
  env += {'LLVM_PLUGIN' : llvm_plugin.full_path()}
  tests += 'llvm'
endif

if get_option('clang-plugin')
  env += {'CLANG_PLUGIN' : clang_plugin.full_path()}
  tests += 'clang'
endif

## Running the tests in parallel often results in some
## of them timing out.  I have no idea why.
foreach testname : tests
  prog = find_program(testname + '-test')
  test(testname, prog, env: env, is_parallel : false)
endforeach
