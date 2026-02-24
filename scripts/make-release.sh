#!/bin/bash

# copyright : Copyright (c) 2017-2026 Red Hat
# license   : GNU GFDL v1.3; see accompanying LICENSE file.

# A script to create a release tarball from a cloned copy of the source repository.
# Expects to be run in a directory above the sources.
# Expects to find the sources inside a directory called SRCDIR,
# which defaults to 'current' if not specified in the environment.

SRCDIR=${SRCDIR:-current}

if [ -n "$(cd $SRCDIR && git status --porcelain -uno)" ]; then
    echo "There are uncommitted changes. Please commit or stash them."
    exit 1
fi

version=`grep ANNOBIN_VERSION= $SRCDIR/configure.ac | cut -f 2 -d '='`

rm -fr annobin-$version annobin-gcc-plugin-$version annobin-$version.tar.xz annobin-gcc-plugin-$version.tar.xz

cp -r $SRCDIR annobin-$version
cd annobin-$version
rm -fr .git autom4te.cache .vscode .gitignore

sleep 1
touch aclocal.m4 gcc-plugin/config.h.in
touch configure */configure Makefile.in */Makefile.in
touch doc/annobin.info

cd ..
tar cf - annobin-$version | xz -9 -c > annobin-$version.tar.xz
rm -fr annobin-$version

echo "Created: annobin-$version.tar.xz"

exit 0
