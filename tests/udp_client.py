#! /usr/bin/env python3

# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause

import socket
import sys

def usage():
    print("usage: %s <server-address> <server-udp-port> <client-address> <client-udp-port> <data_size>" % (sys.argv[0]))

if len(sys.argv) != 6:
    usage()
    sys.exit(1)

serverAddress = sys.argv[1]
serverPort = int(sys.argv[2])
clientAddress = sys.argv[3]
clientPort = int(sys.argv[4])
dataSize = int(sys.argv[5])

msgFromClient = "X" * dataSize
bytesToSend         = str.encode(msgFromClient)

serverAddressPort   = (serverAddress, serverPort)
clientAddressPort   = (clientAddress, clientPort)

# Create a UDP socket at client side
UDPClientSocket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
UDPClientSocket.bind(clientAddressPort)
print("%s" % bytesToSend, flush=True)
sent = UDPClientSocket.sendto(bytesToSend, serverAddressPort)
