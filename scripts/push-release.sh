#!/bin/bash

# copyright : Copyright (c) 2023-2026 Red Hat
# license   : GNU GFDL v1.3; see accompanying LICENSE file.

# A script to push the latest commit and upload it as a new source tarball.
# Expects to be run in a directory above the cloned source tree.
# Expects to find the sources inside a directory called SRCDIR,
# which defaults to 'current' if not specified in the environment.

SRCDIR=${SRCDIR:-current}

if [ -n "$(cd $SRCDIR && git status --porcelain -uno)" ]; then
    echo "There are uncommitted changes. Please commit or stash them."
    exit 1
fi

version=`grep ANNOBIN_VERSION= $SRCDIR/configure.ac | cut -f 2 -d '='`

pushd $SRCDIR
git push
git tag -a $version -m 'Version $version'
git push origin
popd

scp annobin-$version.tar.xz fedora:public_html

exit 0
