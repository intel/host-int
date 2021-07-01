#! /bin/bash

# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause

# Automatically reindent all .c and .h source files in this project,
# avoiding any changes to files in the libbpf submodule.

show_usage() {
    1>&2 echo "usage: `basename $0` [ linux-kernel-style | clang-style ] <additional parameters to pass to reindent-one.sh script>"
    1>&2 echo ""
    1>&2 echo "Examples of use:"
    1>&2 echo ""
    1>&2 echo "    `basename $0` clang-style"
    1>&2 echo "    `basename $0` linux-kernel-style ~/ubuntu-focal/"
}

if [ -d .git ]
then
    PROJ_ROOT=$PWD
    1>&2 echo "Found .git directory.  Assuming this directory is project root directory:"
    echo $PROJ_ROOT
else
    1>&2 echo "No .git directory.  This command must be run from project root directory"
    exit 1
fi

if [ $# -lt 1 ]
then
    show_usage
    exit 1
fi

for f in `find . -name '*.[ch]' | grep -v '/libbpf/'`
do
    ./scripts/reindent-one.sh "${f}" $*
done
