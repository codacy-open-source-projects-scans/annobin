# copyright : Copyright (c) 2017-2026 Red Hat
# license   : GNU GPL v3 or later; see accompanying LICENSE file

# Configure the config.h
cdata = configuration_data()
cdata.set_quoted('PACKAGE_VERSION', meson.project_version())
cdata.set_quoted('PACKAGE_STRING', meson.project_name() + ' ' + meson.project_version())
cdata.set_quoted('PACKAGE_TARNAME', 'annobin-plugin')

headers = [
  'memory.h',
  'limits.h',
  'stdint.h',
  'stdlib.h',
  'strings.h',
  'string.h',
  'sys/stat.h',
  'sys/types.h',
  'sys/wait.h',
  'unistd.h'
]
foreach header : headers
  cdata.set10('HAVE_' + header.underscorify().to_upper(), cxx.has_header(header))
endforeach

cdata.set10('HAVE_DEBUGINFOD', have_debuginfod)
cdata.set10('HAVE_LIBDEBUGINFOD', have_debuginfod)

# Our config.h
configure_file(output: 'config.h', configuration: cdata)


target_plugin = 'dummy.annobin.cc'
target = target_machine.cpu_family()
if target == 'aarch64'
  target_plugin = 'aarch64.annobin.cc'
elif target.startswith('arm')
  target_plugin = 'arm.annobin.cc'
elif target.startswith('ppc')
  target_plugin = 'powerpc.annobin.cc'
elif target.startswith('riscv64')
  target_plugin = 'riscv.annobin.cc'
elif target == 's390'
  target_plugin = 's390.annobin.cc'
elif target == 's390x'
  target_plugin = 's390.annobin.cc'
elif target == 'x86'
  target_plugin = 'i686.annobin.cc'
elif target == 'x86_64'
  target_plugin = 'x86_64.annobin.cc'
endif


# We can't use shared_module() here since we need to force
# using GCC, even if the environment wants another compiler.
gxx = find_program('g++')
plugin_dev_path = run_command(gxx, '-print-file-name=plugin', check: true).stdout().strip()

# Use the default c++ compiler just to find if the needed dependencies are
# installed.
plugin_inc_path = join_paths(plugin_dev_path, 'include')
fs = import('fs')
if not fs.is_dir(plugin_inc_path)
  error(
    'Could not find ',
    plugin_inc_path,
    '\nAre the development files for GCC plugins installed?',
  )
endif
inc = include_directories(plugin_inc_path)
if not cxx.has_header('plugin.h', include_directories: inc)
  error('Could not find GCC\'s plugin.h')
endif

gcc_plugin = custom_target(
  'annobin.so',
  input: ['annobin.cc', target_plugin, '../annobin-common.cc'],
  output: 'annobin.so',
  install: true,
  install_dir : plugin_dev_path,
  command: [
    gxx,
    '@INPUT@',
    '-g', '-fPIC', '-DPIC', '-shared', '-nostdlib',
    '-std=c++17', '-Wall', '-Wextra',
    '-DHAVE_CONFIG_H',
    '-I' + join_paths(meson.current_source_dir(), '..'),
    '-I' + join_paths(meson.current_build_dir(), '..'),
    '-I' + join_paths(plugin_inc_path),
    '-o', '@OUTPUT@',
  ]
)
