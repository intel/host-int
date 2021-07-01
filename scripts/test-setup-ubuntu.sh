#! /bin/bash

# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause

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

# Extra packages over and above the minimum packages used to build the
# code in this repository, that can often be useful when testing the
# code.

# linux-tools-common is included because it installs the 'bpftool'
# command.

# clang-format is only for reindenting the source code, not for
# testing or building the code.

sudo apt-get install tcpdump tshark linux-tools-common clang-format \
     iperf iperf3
