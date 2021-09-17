#! /bin/bash

# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause

# Install the packages required on a Fedora Linux system to build the
# source code in the Host INT project.

warning() {
    1>&2 echo "This script has only been tested on these systems so far:"
    1>&2 echo "    Fedora 34"
    1>&2 echo "Proceed installing manually at your own risk of"
    1>&2 echo "significant time spent figuring out how to make it all work, or"
    1>&2 echo "consider getting VirtualBox and creating a virtual machine with"
    1>&2 echo "a supported operating system."
}

if [ ! -e /etc/fedora-release ]
then
    1>&2 echo "No file '/etc/fedora-release' found on your system."
    warning
    exit 1
fi

REL=`cat /etc/fedora-release`

if [ "${REL}" = "Fedora release 34 (Thirty Four)" ]
then
    echo "Found release: ${REL}.  Continuing with installation."
else
    warning
    1>&2 echo ""
    1>&2 echo "Here is what command 'cat /etc/fedora-release' shows this OS to be:"
    cat /etc/fedora-release
    exit 1
fi

# Extra packages over and above the minimum packages used to build the
# code in this repository, that can often be useful when testing the
# code.

set -x
sudo dnf install -y tcpdump wireshark-cli bpftool
