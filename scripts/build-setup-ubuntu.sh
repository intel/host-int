#! /bin/bash

# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause

# Install the packages required on an Ubuntu Linux system to build the
# source code in the Host INT project.

warning() {
    1>&2 echo "This software has only been tested on these systems so far:"
    1>&2 echo "    Ubuntu 20.04"
    1>&2 echo "Proceed installing manually at your own risk of"
    1>&2 echo "significant time spent figuring out how to make it all work, or"
    1>&2 echo "consider getting VirtualBox and creating a virtual machine with"
    1>&2 echo "a supported operating system."
}

lsb_release >& /dev/null
if [ $? != 0 ]
then
    1>&2 echo "No 'lsb_release' found in your command path."
    warning
    exit 1
fi

distributor_id=`lsb_release -si`
release=`lsb_release -sr`
if [ "${distributor_id}" = "Ubuntu" -a "${release}" = "20.04" ]
then
    echo "Found distributor '${distributor_id}' release '${release}'.  Continuing with installation."
else
    warning
    1>&2 echo ""
    1>&2 echo "Here is what command 'lsb_release -a' shows this OS to be:"
    lsb_release -a
    exit 1
fi

# Setup steps adapted from instructions found here on 2021-Apr-28 for
# Ubuntu systems, for compiling EBPF programs:
#
# https://github.com/xdp-project/xdp-tutorial/blob/master/setup_dependencies.org

sudo apt-get install make clang llvm libelf-dev gcc linux-headers-$(uname -r)

# flex and bison are needed if you want to do `make defconfig` in a
# Linux kernel source tree.  It is commented out in case we ever want
# to rely on cloning a Linux kernel source tree later, but at this
# time, one can build the code in this repository without this.

#sudo apt-get install flex bison
