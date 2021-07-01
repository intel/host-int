#!/usr/bin/env python3

# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause

import socket
import sys

def usage():
    print("usage: %s <server-address> <server-udp-port> <buffer-size>" % (sys.argv[0]))

if len(sys.argv) != 4:
    usage()
    sys.exit(1)

serverAddress = sys.argv[1]
serverPort = int(sys.argv[2])
bufferSize = int(sys.argv[3])

serverAddressPort   = (serverAddress, serverPort)

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(serverAddressPort)

while True:
    data, addr = sock.recvfrom(bufferSize)
    print("%s" % data, flush=True)
