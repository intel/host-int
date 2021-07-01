#! /bin/bash

# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause

# A little script that can open multiple terminal windows in a
# particular non-overlapping arrangement, for times when you want to
# do tcpdump on a sending and receiving host/namespace and see the
# results on both, simultaneously.

# Note that some Ubuntu versions do not support the --title option for
# the gnome-terminal command.  mate-terminal is preferred here because
# it seems to be more consistent in its support of this option.
if [ `which mate-terminal` ]; then
    CMD=mate-terminal
elif [ `which gnome-terminal` ]; then
    CMD=gnome-terminal
else
    echo "Could note find gnome-terminal or mate-terminal in command path"
    exit 1
fi

# Nice to have separate terminal windows to watch what is going on.

# Top left:
# arbitrary commands run in namespace ns1, e.g. for sending packets to ns2
${CMD} --geometry=80x17-700-370 --title="ns1" &

# Bottom left:
# 'ns1 tcpdump' for running tcpdump in namespace ns1
${CMD} --geometry=80x17-700-0 --title="ns1 tcpdump" &

# Top right:
# nothing
${CMD} --geometry=80x17-0-370 --title="ns2" &

# Bottom right:
# bash running on host h2
${CMD} --geometry=80x17-0-0 --title="ns2 tcpdump" &
