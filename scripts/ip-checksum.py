#! /usr/bin/env python3

# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause


# Simple program to read groups of 4 hex digits that are contents of a
# packet, e.g. an IPv4 header, or a TCP or UDP header and payload, and
# calculate the IP checksum over its data.

# Note: This is a 'dumb' program that knows nothing about any of the
# header formats.  It _does not_ skip over any of the data you give
# it, but calculates a checksum over everything you provide as input.

# It does ignore lines beginning with a '#' character as comments,
# which you may use to cause it to ignore some of the data, if you
# edit the input file yourself.

import os, sys
import re
import fileinput

hex_words = []
for line in fileinput.input():
    line = line.strip()
    if line[0:1] == '#':
        continue
    match = re.search(r"^(\s*[0-9a-fA-F]{4})*$", line)
    if match:
        while True:
            match = re.search(r"^\s*([0-9a-fA-F]{4})(.*)$", line)
            if match:
                data_str = match.group(1)
                rest_of_line = match.group(2)
                data_int = int(data_str, 16)
                hex_words.append(data_int)
                line = rest_of_line
            else:
                break
    else:
        print("Ignoring this unrecognized input line: %s" % (line))

print("16-bit hex words parsed:")
offset = 0
sum = 0
for x in hex_words:
    if offset % 4 == 0:
        print()
        print("0x%04x:" % (offset), end='')
    print(" %04x" % (x), end='')
    offset += 2
    sum += x

print()
print()
print("Normal integer sum: 0x%04x" % (sum))
while (sum >> 16) != 0:
    a = sum & 0xffff
    b = sum >> 16
    #print("%x %x %x" % ((sum & 0xffff), a, b))
    sum = a + b

print("folded 1's complement sum: 0x%04x" % (sum))

sum = 0xffff - sum
print("Invert all bits to get...")
print("16-bit IP checksum: 0x%04x" % (sum))
