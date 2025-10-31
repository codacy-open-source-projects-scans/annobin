#!/bin/bash

# copyright : Copyright (c) 2017-2024 Red Hat
# license   : GNU GFDL v1.3; see accompanying LICENSE file.

version=`grep ANNOBIN_VERSION= current/configure.ac | cut -f 2 -d '='`

rm -fr annobin-$version annobin-gcc-plugin-$version annobin-$version.tar.xz annobin-gcc-plugin-$version.tar.xz

cp -r current annobin-$version
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
