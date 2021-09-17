#!/usr/bin/env python3

# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause

import socket
import sys

def usage():
    print("usage: %s <server-address> <server-tcp-port> <data-size>" % (sys.argv[0]))

def bytes_to_hex(b):
     return ''.join(['%02x' % (x) for x in b])
if len(sys.argv) != 4:
    usage()
    sys.exit(1)

serverAddress = sys.argv[1]
serverPort = int(sys.argv[2])
dataSize = int(sys.argv[3])

serverAddressPort   = (serverAddress, serverPort)
MESSAGE = "X" * dataSize
bytesToSend = str.encode(MESSAGE)

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(serverAddressPort)
s.send(bytesToSend)
print("%s" % bytes_to_hex(bytesToSend), end='', flush=True)
s.close()
