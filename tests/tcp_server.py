#!/usr/bin/env python3

# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause

import socket
import sys

def usage():
    print("usage: %s <server-address> <server-tcp-port> <buffer-size>" % (sys.argv[0]))

def bytes_to_hex(b):
     return ''.join(['%02x' % (x) for x in b])

if len(sys.argv) != 4:
    usage()
    sys.exit(1)

serverAddress = sys.argv[1]
serverPort = int(sys.argv[2])
bufferSize = int(sys.argv[3])

serverAddressPort   = (serverAddress, serverPort)

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(serverAddressPort)
s.listen(1)

conn, addr = s.accept()
while 1:
    data = conn.recv(bufferSize)
    if not data: break
    print("%s" % bytes_to_hex(data), end='', flush=True)
conn.close()
