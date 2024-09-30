# copyright : Copyright (C) 2017-2024 Red Hat.
# license   : GNU GPL v3 or later; see accompanying LICENSE file

configure_file(
  input: 'libannocheck.h.in',
  output: 'libannocheck.h',
  configuration: version_cdata,
  install: true,
  install_dir: '/usr/include' # FIXME 
)

configure_file(
  input: 'libannocheck.pc.in',
  output: 'libannocheck.pc',
  configuration: version_cdata,
  install: true,
  install_dir: '/usr/lib64/pkgconfig' # FIXME 
)

elf_lib = cxx.find_library('elf')
dw_lib = cxx.find_library('dw')
rpm_lib = cxx.find_library('rpm')
rpmio_lib = cxx.find_library('rpmio')

annocheck = executable(
  'annocheck',
  files([
    'annocheck.c',
    'notes.c',
    'hardened.c',
    'libiberty/concat.c',
    'libiberty/cp-demangle.c',
    'libiberty/cplus-dem.c',
    'libiberty/d-demangle.c',
    'libiberty/lbasename.c',
    'libiberty/rust-demangle.c',
    'libiberty/safe-ctype.c',
    'libiberty/xexit.c',
    'libiberty/xmalloc.c',
    'libiberty/xstrdup.c'
  ]),
  dependencies: [
    elf_lib,
    dw_lib,
    rpm_lib,
    rpmio_lib,
    debuginfod_lib,
  ],
  include_directories: [
    toplevel_incdir,
    gcc_plugin_incdir,
  ],
)

libannocheck = shared_library(
  'annocheck',
  files([
    'annocheck.c',
    'hardened.c',
    'libiberty/concat.c',
    'libiberty/cp-demangle.c',
    'libiberty/cplus-dem.c',
    'libiberty/d-demangle.c',
    'libiberty/lbasename.c',
    'libiberty/rust-demangle.c',
    'libiberty/safe-ctype.c',
    'libiberty/xexit.c',
    'libiberty/xmalloc.c',
    'libiberty/xstrdup.c'
  ]),
  dependencies: [
    elf_lib,
    dw_lib,
    rpm_lib,
    rpmio_lib,
    debuginfod_lib,
  ],
  c_args: [
    '-DLIBANNOCHECK=1',
  ],
  include_directories: [
    toplevel_incdir,
    gcc_plugin_incdir,
  ]
)

# Create a libannocheck.pc config file for pkgconfig

pkg = import('pkgconfig')
pkg.generate(libannocheck,
  name : 'libannocheck',
  description : 'library for checking the security hardening status of binaries',
  url : 'https://sourceware.org/annobin/',
  libraries : '-liberty',
  requires : 'binutils-devel')
