# Annobin - Binary Annotation and Security Checking

These are the sources for the annobin project:

  https://sourceware.org/annobin/

The project consists of two main parts:

  1. A security checker program - annocheck - which examines binaries
     and reports potential security problems.

  2. A set of plugins for GCC, Clang and LLVM that records security
     information for use by annocheck.

In addition there is a testsuite and documentation too.

## Quick Start

Annobin can be built in place, but it is recommended to build in a
separate directory tree from the sources.

### Building with Autotools
```bash
cd <somewhere>
mkdir builddir
cd builddir
<path-to-sources>/configure --quiet
make
make check
sudo make install
```

### Building with Meson
```bash
cd <somewhere>
meson setup builddir <path-to-sources>
meson compile -C builddir
meson test -C builddir
sudo meson install -C builddir
```

### Requirements

- GCC >= 9.0 (with plugin development headers)
- elfutils and libdw development libraries
- For Clang plugin: Clang >= 11, LLVM development headers
- For Meson: Meson >= 0.59, Ninja
- For Autotools: Autoconf, Automake, Libtool

## Documentation

The project includes documentation in the doc/ subdirectory.  This
compiles to both a PDF format file and a hierarchy of HTML files.  The
HTML version can be browsed from this address:

  https://sourceware.org/annobin/annobin.html/index.html

## Code of Conduct

The project does not have its own Code of Conduct, but the guidelines
found in the Binutils Code of Conduct should be considered to apply
to this project as well:

  https://sourceware.org/binutils/code-of-conduct/Code-of-Conduct.html

