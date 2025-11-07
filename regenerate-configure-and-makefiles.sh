#!/bin/bash

# Regenerates the configure and makefiles in a consistent manner.
# Uses a CentOS-9 container for reproducibility.
# (We could probably bump this to CentOS-10 without breaking anything).
# Should be run in the top level annobin source directory.

podman run --interactive --tty --rm --security-opt label=disable \
  --mount=type=bind,source=`pwd`,destination=/src --workdir=/src \
  centos:stream9 bash -c \
  "dnf install --quiet -y autoconf automake libtool && autoreconf --force --install"

# For some reason this file is left over after autoreconf completes.
rm -f gcc-plugin/config.h.in~
